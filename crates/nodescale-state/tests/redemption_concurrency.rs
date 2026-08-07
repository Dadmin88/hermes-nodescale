use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, Invitation, InvitationId, InvitationToken, JoinConstraints, Network,
    NetworkId, ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, ProviderError, ProviderHealth,
    ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    HeadscaleImportConfig, N4InvitationContext, N4PresentedMetadata, ProviderMutationConfiguration,
    StateStore, TlsVerificationPolicy,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

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
        unreachable!()
    }
}
fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().unwrap()
}

#[tokio::test]
async fn separate_connections_race_one_n4_reservation_without_process_lock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("race.db");
    let admin = StateStore::open(&path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n4-race",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    admin
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
    admin
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
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    let token = InvitationToken::generate(InvitationId::new());
    let invitation = Invitation::new_n4(
        token.invitation_id(),
        network.network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now(),
        now() + Duration::minutes(20),
        1,
    )
    .unwrap();
    admin
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(instance, "principal-race").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let revision = admin
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap()
        .revision;
    let audit_before = admin.audit_event_count().unwrap();
    drop(admin);

    let barrier = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let invitation_id = invitation.invitation_id;
        joins.push(std::thread::spawn(move || {
            let store = StateStore::open(&path).unwrap();
            barrier.wait();
            store.reserve_n4_redemption(
                invitation_id,
                revision,
                nodescale_domain::JoinSessionId::new(),
                now(),
                N4PresentedMetadata::default(),
                AuditActor::system(),
            )
        }));
    }
    let outcomes = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );

    let fresh = StateStore::open(&path).unwrap();
    let view = fresh.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(view.used_count, 1);
    assert_eq!(fresh.audit_event_count().unwrap(), audit_before + 2);
    assert_eq!(fresh.device_count(network.network_id).unwrap(), 0);
    assert_eq!(fresh.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(fresh.fleet_projection_count(network.network_id).unwrap(), 0);
}
