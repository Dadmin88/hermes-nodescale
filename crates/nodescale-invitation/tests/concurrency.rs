use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, InvitationToken, JoinConstraints, JoinSessionId, Network, NetworkId,
    ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_invitation::{
    CreateInvitationRequest, InvitationService, InvitationServiceError, N4AuthorizationIssuer,
    RedeemInvitationRequest,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, MutationProvider, Provider, ProviderError,
    ProviderHealth, ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_provider_fake::{AsyncFakeMutationProvider, FakeMutationAuthorization, FakeProvider};
use nodescale_state::{
    HeadscaleImportConfig, N4CleanupTarget, N4CredentialDispatch, N4PresentedMetadata,
    ProviderMutationConfiguration, StateError, StateStore, TlsVerificationPolicy,
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};
use tempfile::tempdir;

const FINGERPRINT: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FIXTURE: &str = "n4-service-cross-connection";

fn now() -> DateTime<Utc> {
    "2026-01-01T00:00:00Z".parse().expect("fixed timestamp")
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
        unreachable!("not used by concurrency fixture")
    }
}

struct FakeIssuer;
impl N4AuthorizationIssuer<AsyncFakeMutationProvider> for FakeIssuer {
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, FakeMutationAuthorization), StateError> {
        let dispatch = store.begin_n4_credential_dispatch(join_session_id, now, actor)?;
        let authorization = FakeMutationAuthorization::new(
            dispatch.network_id,
            dispatch.context.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::CreateJoinCredential],
            Utc::now() + Duration::minutes(1),
        );
        Ok((dispatch, authorization))
    }

    fn issue_invalidation(
        &self,
        _: &StateStore,
        target: &N4CleanupTarget,
        _: DateTime<Utc>,
    ) -> Result<FakeMutationAuthorization, StateError> {
        Ok(FakeMutationAuthorization::new(
            target.network_id,
            target.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::InvalidateJoinCredential],
            Utc::now() + Duration::minutes(1),
        ))
    }
}

fn fake_provider(network_id: NetworkId) -> AsyncFakeMutationProvider {
    let mut fake = FakeProvider::compatible(FIXTURE);
    Provider::ensure_network_principal(&mut fake, "principal-race").unwrap();
    AsyncFakeMutationProvider::configured(
        fake,
        network_id,
        Generation::initial(),
        true,
        MutationPolicyMode::Database,
    )
}

async fn configured_store(path: &Path) -> (StateStore, Network) {
    let store = StateStore::open(path).unwrap();
    let provider = fake_provider(NetworkId::new());
    let instance = provider.instance_id();
    let network = Network::new(
        NetworkId::new(),
        "N4 concurrency",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
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
            .unwrap(),
            &ImportedProvider(instance),
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            ProviderMutationConfiguration::new(
                instance,
                Generation::initial(),
                Generation::initial(),
                FINGERPRINT,
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
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    (store, network)
}

fn contender(
    path: PathBuf,
    network: Network,
    raw_token: String,
    barrier: Arc<Barrier>,
) -> (bool, Option<InvitationServiceError>, usize) {
    let store = StateStore::open(path).unwrap();
    let provider = fake_provider(network.network_id);
    let issuer = FakeIssuer;
    let service = InvitationService::new(&store, &provider, &issuer);
    barrier.wait();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = runtime.block_on(service.redeem(
        RedeemInvitationRequest {
            token: raw_token.parse::<InvitationToken>().unwrap(),
            presented: N4PresentedMetadata::default(),
            actor: AuditActor::system(),
        },
        now() + Duration::seconds(1),
    ));
    let (won, error) = match outcome {
        Ok(delivery) => {
            let _ = delivery.deliver_once(|_| ());
            (true, None)
        }
        Err(error) => (false, Some(error)),
    };
    (won, error, provider.mutation_dispatch_count())
}

#[tokio::test]
async fn two_connections_redeem_one_token_with_exactly_one_provider_dispatch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n4-concurrency.db");
    let (store, network) = configured_store(&path).await;
    let provider = fake_provider(network.network_id);
    let issuer = FakeIssuer;
    let service = InvitationService::new(&store, &provider, &issuer);
    let issued = service
        .create(
            CreateInvitationRequest {
                network_id: network.network_id,
                provider_instance_id: network.provider_instance_id,
                provider_principal_id: "principal-race".into(),
                roles: Roles::new([Role::Worker]).unwrap(),
                admin_intent: None,
                join_constraints: JoinConstraints::default(),
                actor: AuditActor::system(),
            },
            now(),
        )
        .unwrap();
    let invitation_id = issued.view().invitation_id;
    let (_, raw_token) = issued.deliver_token(str::to_owned);
    drop(store);

    let barrier = Arc::new(Barrier::new(3));
    let first = {
        let path = path.clone();
        let network = network.clone();
        let raw_token = raw_token.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || contender(path, network, raw_token, barrier))
    };
    let second = {
        let path = path.clone();
        let network = network.clone();
        let raw_token = raw_token.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || contender(path, network, raw_token, barrier))
    };
    barrier.wait();
    let outcomes = [first.join().unwrap(), second.join().unwrap()];

    assert_eq!(outcomes.iter().filter(|(won, _, _)| *won).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, error, _)| *error == Some(InvitationServiceError::Conflict))
            .count(),
        1
    );
    assert_eq!(outcomes.iter().map(|(_, _, count)| count).sum::<usize>(), 1);

    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened.n4_invitation_view(invitation_id).unwrap().state,
        nodescale_domain::InvitationState::Consumed
    );
    assert_eq!(reopened.device_count(network.network_id).unwrap(), 0);
    assert_eq!(reopened.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(
        reopened.fleet_projection_count(network.network_id).unwrap(),
        0
    );
}
