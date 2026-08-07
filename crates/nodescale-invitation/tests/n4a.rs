use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, InvitationAdminIntent, JoinConstraints, Network, NetworkId,
    ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_invitation::{CreateInvitationRequest, InvitationService, InvitationServiceError};
use nodescale_provider::{
    CompatibilityStatus, MutationOutcome, MutationPolicyMode, MutationProvider, ProviderError,
    ProviderHealth, ProviderMutation, ProviderMutationCapability, ReadOnlyProvider,
    ServerInspection,
};
use nodescale_state::{
    HeadscaleImportConfig, MutationAuthorization, ProviderMutationConfiguration, StateStore,
    TlsVerificationPolicy,
};
use std::collections::BTreeSet;

fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().expect("fixed timestamp")
}

struct ImportedProvider(ProviderInstanceId);
#[async_trait::async_trait]
impl ReadOnlyProvider for ImportedProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.0
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.0,
            compatibility: CompatibilityStatus::Compatible,
            capabilities: BTreeSet::new(),
            constraints: vec![],
            mutation_allowed: false,
        })
    }

    async fn list_nodes(&self) -> Result<Vec<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(vec![])
    }

    async fn get_node(
        &self,
        _: &nodescale_domain::ProviderIdentity,
    ) -> Result<Option<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(None)
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        Ok(ProviderHealth {
            status: nodescale_provider::ProviderHealthStatus::Healthy,
            reachable: true,
            authenticated: true,
            detail: "test".into(),
        })
    }
}

struct TestProvider(ProviderInstanceId);
#[async_trait::async_trait]
impl MutationProvider for TestProvider {
    type Authorization = MutationAuthorization;

    fn instance_id(&self) -> ProviderInstanceId {
        self.0
    }

    async fn execute_mutation(
        &self,
        _: Self::Authorization,
        _: ProviderMutation,
    ) -> MutationOutcome {
        MutationOutcome::Rejected
    }
}

async fn configured_store() -> (StateStore, Network) {
    let store = StateStore::open_in_memory().expect("store opens");
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "invitation-service",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .expect("network is valid");
    store
        .import_headscale_network(
            &network,
            &HeadscaleImportConfig::new(
                "https://headscale.example.test",
                instance,
                "secret://vault/nodescale#key",
                "v0.29.3",
                TlsVerificationPolicy::Verify,
            )
            .expect("import config is valid"),
            &ImportedProvider(instance),
            now(),
            AuditActor::system(),
        )
        .await
        .expect("network imports");
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            ProviderMutationConfiguration::new(
                instance,
                Generation::initial(),
                Generation::initial(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "headscale",
                "v0.29.3",
                true,
                false,
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                MutationPolicyMode::Database,
                [
                    ProviderMutationCapability::CreateJoinCredential,
                    ProviderMutationCapability::InvalidateJoinCredential,
                ],
            )
            .expect("mutation configuration is valid"),
            AuditActor::system(),
        )
        .expect("mutation configuration persists");
    (store, network)
}

fn request(
    network: &Network,
    roles: Roles,
    admin_intent: Option<InvitationAdminIntent>,
) -> CreateInvitationRequest {
    CreateInvitationRequest {
        network_id: network.network_id,
        provider_instance_id: network.provider_instance_id,
        provider_principal_id: "principal-42".into(),
        roles,
        admin_intent,
        join_constraints: JoinConstraints::default(),
        actor: AuditActor::system(),
    }
}

#[tokio::test]
async fn create_is_fixed_single_use_listable_and_delivers_token_once() {
    let (store, network) = configured_store().await;
    let provider = TestProvider(network.provider_instance_id);
    let service = InvitationService::new(&store, &provider, &store);

    let issued = service
        .create(
            request(&network, Roles::new([Role::Worker]).unwrap(), None),
            now(),
        )
        .expect("invitation issues");
    let invitation_id = issued.view().invitation_id;
    assert_eq!(issued.view().expires_at, now() + Duration::minutes(15));
    assert_eq!(issued.view().max_uses, 1);
    assert_eq!(issued.view().used_count, 0);
    assert!(issued.view().roles.operations().is_empty());
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);

    let formatted = format!("{issued:?}");
    assert!(!formatted.contains("nsjoin_"));
    let (view, delivered) = issued.deliver_token(|token| token.to_owned());
    assert_eq!(view.invitation_id, invitation_id);
    assert!(delivered.starts_with("nsjoin_"));
    assert!(!format!("{view:?}").contains(&delivered));
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains(&delivered)
    );

    assert_eq!(
        service.list(network.network_id).unwrap(),
        vec![view.clone()]
    );
    assert_eq!(service.show(invitation_id).unwrap(), view);
}

#[tokio::test]
async fn ordinary_roles_issue_and_admin_requires_domain_intent() {
    let (store, network) = configured_store().await;
    let provider = TestProvider(network.provider_instance_id);
    let service = InvitationService::new(&store, &provider, &store);

    service
        .create(
            request(
                &network,
                Roles::new([Role::Node, Role::Observer]).unwrap(),
                None,
            ),
            now(),
        )
        .expect("ordinary roles issue");
    assert!(matches!(
        service.create(
            request(&network, Roles::new([Role::Admin]).unwrap(), None),
            now(),
        ),
        Err(InvitationServiceError::InvalidRequest)
    ));
    service
        .create(
            request(
                &network,
                Roles::new([Role::Admin]).unwrap(),
                Some(InvitationAdminIntent::explicit()),
            ),
            now(),
        )
        .expect("explicit admin intent issues");
}

#[tokio::test]
async fn invalid_role_cardinality_network_and_provider_are_rejected_without_secret_leaks() {
    let (store, network) = configured_store().await;
    let provider = TestProvider(network.provider_instance_id);
    let service = InvitationService::new(&store, &provider, &store);
    let too_many = Roles::new([
        Role::Node,
        Role::Worker,
        Role::Controller,
        Role::ProfileHost,
        Role::Observer,
    ])
    .unwrap();
    assert!(matches!(
        service.create(request(&network, too_many, None), now()),
        Err(InvitationServiceError::InvalidRequest)
    ));

    let mut wrong_network = request(&network, Roles::new([Role::Worker]).unwrap(), None);
    wrong_network.network_id = NetworkId::new();
    assert!(matches!(
        service.create(wrong_network, now()),
        Err(InvitationServiceError::NotFound)
    ));

    let mut wrong_provider = request(&network, Roles::new([Role::Worker]).unwrap(), None);
    wrong_provider.provider_instance_id = ProviderInstanceId::new();
    let error = service.create(wrong_provider, now()).unwrap_err();
    assert_eq!(error, InvitationServiceError::InvalidRequest);
    assert!(!format!("{error:?} {error}").contains("principal-42"));
    assert!(!format!("{error:?} {error}").contains("nsjoin_"));
}
