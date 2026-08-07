use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, Invitation, InvitationId, InvitationState, InvitationToken,
    JoinConstraints, JoinSessionId, Network, NetworkId, ProviderInstanceId, ProviderKind, Role,
    Roles,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, ProviderError, ProviderHealth,
    ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    Failpoint, HeadscaleImportConfig, N4InvitationContext, N4PresentedMetadata,
    ProviderMutationConfiguration, StateError, StateStore, TlsVerificationPolicy,
};
use rusqlite::Connection;
use std::{collections::BTreeSet, path::Path};
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

#[derive(Debug, Eq, PartialEq)]
struct DatabaseSnapshot {
    audit_events: u64,
    join_sessions: u64,
    dispatches: u64,
    audit_correlations: u64,
}

#[derive(Clone, Copy)]
enum TerminalIntent {
    Revoke,
    Expire,
}

fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().unwrap()
}

async fn configured_file_store(path: &Path) -> (StateStore, Network) {
    let store = StateStore::open(path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n4-failpoint",
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
    (store, network)
}

fn invitation(network_id: NetworkId) -> Invitation {
    let token = InvitationToken::generate(InvitationId::new());
    Invitation::new_n4(
        token.invitation_id(),
        network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now(),
        now() + Duration::minutes(20),
        1,
    )
    .unwrap()
}

fn snapshot(path: &Path, invitation_id: InvitationId) -> DatabaseSnapshot {
    let connection = Connection::open(path).unwrap();
    DatabaseSnapshot {
        audit_events: connection
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap(),
        join_sessions: connection
            .query_row(
                "SELECT COUNT(*) FROM join_sessions WHERE invitation_id=?1",
                [invitation_id.to_string()],
                |row| row.get(0),
            )
            .unwrap(),
        dispatches: connection
            .query_row(
                "SELECT COUNT(*) FROM n4_join_session_dispatches WHERE invitation_id=?1",
                [invitation_id.to_string()],
                |row| row.get(0),
            )
            .unwrap(),
        audit_correlations: connection
            .query_row(
                "SELECT COUNT(*) FROM n4_audit_correlations WHERE invitation_id=?1",
                [invitation_id.to_string()],
                |row| row.get(0),
            )
            .unwrap(),
    }
}

fn assert_no_projections(store: &StateStore, network_id: NetworkId) {
    assert_eq!(store.device_count(network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network_id).unwrap(), 0);
}

fn prepare_terminal(
    store: &StateStore,
    invitation_id: InvitationId,
    at: DateTime<Utc>,
    intent: TerminalIntent,
) -> Result<(), StateError> {
    match intent {
        TerminalIntent::Revoke => {
            store.prepare_n4_revocation(invitation_id, at, AuditActor::system())
        }
        TerminalIntent::Expire => store.prepare_n4_expiry(invitation_id, at, AuditActor::system()),
    }
    .map(|_| ())
}

#[tokio::test]
async fn reserve_audit_failpoint_rolls_back_every_n4_write_on_disk() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("reserve-audit-failpoint.db");
    let (store, network) = configured_file_store(&path).await;
    let invitation = invitation(network.network_id);
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-reserve").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let baseline = snapshot(&path, invitation.invitation_id);

    store.set_failpoint(Failpoint::BeforeAuditInsert, true);
    let failed_session = JoinSessionId::new();
    assert!(
        store
            .reserve_n4_redemption(
                invitation.invitation_id,
                1,
                failed_session,
                now(),
                N4PresentedMetadata::default(),
                AuditActor::system(),
            )
            .is_err()
    );
    drop(store);

    let fresh = StateStore::open(&path).unwrap();
    let view = fresh.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(view.state, InvitationState::Issued);
    assert_eq!(view.used_count, 0);
    assert_eq!(view.revision, 1);
    assert_eq!(snapshot(&path, invitation.invitation_id), baseline);
    assert!(fresh.join_session(failed_session).is_err());
    assert_no_projections(&fresh, network.network_id);

    let successful_session = JoinSessionId::new();
    fresh
        .reserve_n4_redemption(
            invitation.invitation_id,
            1,
            successful_session,
            now(),
            N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    assert!(
        fresh
            .reserve_n4_redemption(
                invitation.invitation_id,
                1,
                JoinSessionId::new(),
                now(),
                N4PresentedMetadata::default(),
                AuditActor::system(),
            )
            .is_err()
    );
    assert_eq!(snapshot(&path, invitation.invitation_id).join_sessions, 1);
    assert_eq!(snapshot(&path, invitation.invitation_id).dispatches, 1);
    assert_eq!(
        snapshot(&path, invitation.invitation_id).audit_events,
        baseline.audit_events + 2
    );
    assert_eq!(
        snapshot(&path, invitation.invitation_id).audit_correlations,
        baseline.audit_correlations + 2
    );
    assert_no_projections(&fresh, network.network_id);
}

#[tokio::test]
async fn unused_terminal_cleanup_audit_failpoint_rolls_back_revoke_and_expiry_on_disk() {
    for (name, terminal_at, intent) in [
        ("revoke", now(), TerminalIntent::Revoke),
        (
            "expiry",
            now() + Duration::minutes(21),
            TerminalIntent::Expire,
        ),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("{name}-audit-failpoint.db"));
        let (store, network) = configured_file_store(&path).await;
        let invitation = invitation(network.network_id);
        store
            .issue_n4_invitation(
                &invitation,
                N4InvitationContext::new(network.provider_instance_id, "principal-terminal")
                    .unwrap(),
                now(),
                AuditActor::system(),
            )
            .unwrap();
        let baseline = snapshot(&path, invitation.invitation_id);

        store.set_failpoint(Failpoint::BeforeAuditInsert, true);
        assert!(prepare_terminal(&store, invitation.invitation_id, terminal_at, intent,).is_err());
        drop(store);

        let fresh = StateStore::open(&path).unwrap();
        let view = fresh.n4_invitation_view(invitation.invitation_id).unwrap();
        assert_eq!(view.state, InvitationState::Issued);
        assert_eq!(view.used_count, 0);
        assert_eq!(view.revision, 1);
        assert_eq!(view.revoked_at, None);
        assert_eq!(view.expired_at, None);
        assert_eq!(snapshot(&path, invitation.invitation_id), baseline);
        assert_no_projections(&fresh, network.network_id);

        prepare_terminal(&fresh, invitation.invitation_id, terminal_at, intent).unwrap();
        prepare_terminal(&fresh, invitation.invitation_id, terminal_at, intent).unwrap();
        let terminal_view = fresh.n4_invitation_view(invitation.invitation_id).unwrap();
        match intent {
            TerminalIntent::Revoke => {
                assert_eq!(terminal_view.state, InvitationState::Revoked);
                assert_eq!(terminal_view.revoked_at, Some(terminal_at));
                assert_eq!(terminal_view.expired_at, None);
            }
            TerminalIntent::Expire => {
                assert_eq!(terminal_view.state, InvitationState::Expired);
                assert_eq!(terminal_view.revoked_at, None);
                assert_eq!(terminal_view.expired_at, Some(terminal_at));
            }
        }
        let after_retry = snapshot(&path, invitation.invitation_id);
        assert_eq!(after_retry.audit_events, baseline.audit_events + 1);
        assert_eq!(
            after_retry.audit_correlations,
            baseline.audit_correlations + 1
        );
        assert_eq!(after_retry.join_sessions, 0);
        assert_eq!(after_retry.dispatches, 0);
        assert_no_projections(&fresh, network.network_id);
    }
}
