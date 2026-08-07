use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, Invitation, InvitationId, InvitationToken, JoinConstraints,
    JoinSessionId, Network, NetworkId, ProviderCredentialId, ProviderCredentialReference,
    ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, ProviderError, ProviderHealth,
    ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    HeadscaleImportConfig, N4CleanupIntent, N4CleanupState, N4CredentialConfirmation,
    N4DispatchFailure, N4InvalidationOutcome, N4InvitationContext, N4PresentedMetadata,
    ProviderMutationConfiguration, SanitizedMetadata, StateError, StateStore,
    TlsVerificationPolicy,
};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::Path;
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

async fn configured_file_store(path: &Path, name: &str) -> (StateStore, Network) {
    let store = StateStore::open(path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        name,
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

fn invitation(network_id: NetworkId, expires_at: DateTime<Utc>) -> Invitation {
    let token = InvitationToken::generate(InvitationId::new());
    Invitation::new_n4(
        token.invitation_id(),
        network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now(),
        expires_at,
        1,
    )
    .unwrap()
}

fn reserve(
    store: &StateStore,
    network: &Network,
    invitation: &Invitation,
    principal: &str,
) -> JoinSessionId {
    store
        .issue_n4_invitation(
            invitation,
            N4InvitationContext::new(network.provider_instance_id, principal).unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap();
    store
        .reserve_n4_redemption(
            invitation.invitation_id,
            candidate.revision,
            JoinSessionId::new(),
            now(),
            N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap()
        .join_session_id
}

fn confirmation(principal: &str, expires_at: DateTime<Utc>) -> N4CredentialConfirmation {
    N4CredentialConfirmation {
        credential_id: ProviderCredentialId::new(),
        provider_reference: ProviderCredentialReference::new("native-reference-verified").unwrap(),
        provider_principal_id: principal.into(),
        ephemeral: false,
        approved_tags: vec!["tag:nodescale-worker".into()],
        expires_at,
        confirmed_at: now(),
        safe_correlation: SanitizedMetadata::empty(),
    }
}

async fn confirmed_invitation(path: &Path, name: &str) -> (StateStore, Network, Invitation) {
    let (store, network) = configured_file_store(path, name).await;
    let invitation = invitation(network.network_id, now() + Duration::minutes(20));
    let session_id = reserve(&store, &network, &invitation, "principal-certainty");
    store
        .begin_n4_credential_dispatch(session_id, now(), AuditActor::system())
        .unwrap();
    store
        .confirm_n4_credential(
            session_id,
            confirmation("principal-certainty", now() + Duration::minutes(10)),
            AuditActor::system(),
        )
        .unwrap();
    (store, network, invitation)
}

fn dispatch_state(path: &Path, join_session_id: JoinSessionId) -> String {
    let connection = Connection::open(path).unwrap();
    connection
        .query_row(
            "SELECT dispatch_state FROM n4_join_session_dispatches WHERE join_session_id=?1",
            [join_session_id.to_string()],
            |row| row.get(0),
        )
        .unwrap()
}

fn assert_zero_projections(store: &StateStore, network: &Network) {
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
}

fn assert_conflict<T>(result: Result<T, StateError>) {
    assert!(matches!(result, Err(StateError::Conflict(_))));
}

#[tokio::test]
async fn file_backed_dispatch_failure_certainty_is_durable_nonreplayable_and_audited_once() {
    for (label, failure, begins_dispatch, expected_state) in [
        (
            "pre-dispatch",
            N4DispatchFailure::PreDispatch,
            false,
            "failed_pre_dispatch",
        ),
        (
            "definite-no-apply",
            N4DispatchFailure::DefiniteNoApply,
            true,
            "failed_no_apply",
        ),
        ("ambiguous", N4DispatchFailure::Ambiguous, true, "ambiguous"),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("{label}.db"));
        let (store, network) = configured_file_store(&path, label).await;
        let invitation = invitation(network.network_id, now() + Duration::minutes(20));
        let session_id = reserve(&store, &network, &invitation, "principal-certainty");
        let audits_after_issue = store.audit_event_count().unwrap() - 2;
        if begins_dispatch {
            store
                .begin_n4_credential_dispatch(session_id, now(), AuditActor::system())
                .unwrap();
        }
        store
            .fail_n4_credential_dispatch(session_id, failure, now(), AuditActor::system())
            .unwrap();
        assert_eq!(store.audit_event_count().unwrap(), audits_after_issue + 3);
        assert_eq!(
            store
                .n4_invitation_view(invitation.invitation_id)
                .unwrap()
                .state,
            nodescale_domain::InvitationState::Failed
        );
        assert_zero_projections(&store, &network);
        drop(store);

        assert_eq!(dispatch_state(&path, session_id), expected_state);
        let connection = Connection::open(&path).unwrap();
        let provenance: (String, String, String, String) = connection
            .query_row(
                "SELECT network_id,provider_instance_id,provider_principal_id,create_request_id FROM n4_join_session_dispatches WHERE join_session_id=?1",
                [session_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(provenance.0, network.network_id.to_string());
        assert_eq!(provenance.1, network.provider_instance_id.to_string());
        assert_eq!(provenance.2, "principal-certainty");
        assert!(!provenance.3.is_empty());
        drop(connection);

        let reopened = StateStore::open(&path).unwrap();
        assert_conflict(reopened.begin_n4_credential_dispatch(
            session_id,
            now(),
            AuditActor::system(),
        ));
        assert_conflict(
            reopened.reserve_n4_redemption(
                invitation.invitation_id,
                reopened
                    .n4_invitation_candidate(invitation.invitation_id)
                    .unwrap()
                    .revision,
                JoinSessionId::new(),
                now(),
                N4PresentedMetadata::default(),
                AuditActor::system(),
            ),
        );
        assert_eq!(
            reopened.audit_event_count().unwrap(),
            audits_after_issue + 3
        );
        assert_zero_projections(&reopened, &network);
    }
}

#[tokio::test]
async fn file_backed_cleanup_retry_ambiguity_blocks_already_satisfied_and_replay_follow_the_matrix()
{
    let dir = tempdir().unwrap();

    let retry_path = dir.path().join("retry.db");
    let (store, network, invitation) = confirmed_invitation(&retry_path, "retry").await;
    let audits_after_confirmation = store.audit_event_count().unwrap();
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    assert_eq!(target.intent, N4CleanupIntent::Revoked);
    assert!(target.provider_reference.is_some());
    assert!(!target.cleanup_uncertain);
    store
        .settle_n4_credential_invalidation(
            target.clone(),
            N4InvalidationOutcome::Retryable,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let retrying = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(retrying.state, nodescale_domain::InvitationState::Revoking);
    assert_eq!(retrying.cleanup_state, N4CleanupState::Retryable);
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation
    );
    store
        .settle_n4_credential_invalidation(
            target.clone(),
            N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let terminal = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(terminal.state, nodescale_domain::InvitationState::Revoked);
    assert_eq!(terminal.cleanup_state, N4CleanupState::Confirmed);
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    store
        .settle_n4_credential_invalidation(
            target,
            N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    assert_zero_projections(&store, &network);

    let ambiguous_path = dir.path().join("ambiguous-to-confirmed.db");
    let (store, network, invitation) =
        confirmed_invitation(&ambiguous_path, "ambiguous-to-confirmed").await;
    let audits_after_confirmation = store.audit_event_count().unwrap();
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    store
        .settle_n4_credential_invalidation(
            target.clone(),
            N4InvalidationOutcome::Ambiguous,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .cleanup_state,
        N4CleanupState::Ambiguous
    );
    store
        .settle_n4_credential_invalidation(
            target,
            N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .state,
        nodescale_domain::InvitationState::Revoked
    );
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    assert_zero_projections(&store, &network);

    for (label, outcome) in [
        (
            "authentication",
            N4InvalidationOutcome::AuthenticationFailed,
        ),
        ("compatibility", N4InvalidationOutcome::CompatibilityBlocked),
        ("blocked", N4InvalidationOutcome::Blocked),
    ] {
        let path = dir.path().join(format!("{label}.db"));
        let (store, network, invitation) = confirmed_invitation(&path, label).await;
        let audits_after_confirmation = store.audit_event_count().unwrap();
        let target = store
            .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
            .unwrap();
        store
            .settle_n4_credential_invalidation(target, outcome, now(), AuditActor::system())
            .unwrap();
        let pending = store.n4_invitation_view(invitation.invitation_id).unwrap();
        assert_eq!(pending.state, nodescale_domain::InvitationState::Revoking);
        assert_eq!(pending.cleanup_state, N4CleanupState::Blocked);
        assert_eq!(
            store.audit_event_count().unwrap(),
            audits_after_confirmation
        );
        assert_zero_projections(&store, &network);
    }

    let satisfied_path = dir.path().join("already-satisfied.db");
    let (store, network, invitation) =
        confirmed_invitation(&satisfied_path, "already-satisfied").await;
    let audits_after_confirmation = store.audit_event_count().unwrap();
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    store
        .settle_n4_credential_invalidation(
            target,
            N4InvalidationOutcome::AlreadySatisfied,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .state,
        nodescale_domain::InvitationState::Revoked
    );
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    assert_zero_projections(&store, &network);
}

#[tokio::test]
async fn invalidation_requires_exact_safe_provenance_and_rejects_opposite_terminal_intent_without_audit_replay()
 {
    let dir = tempdir().unwrap();
    let path = dir.path().join("provenance.db");
    let (store, network, invitation) = confirmed_invitation(&path, "provenance").await;
    let audits_after_confirmation = store.audit_event_count().unwrap();
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();

    let mut wrong_reference = target.clone();
    wrong_reference.provider_reference =
        Some(ProviderCredentialReference::new("native-reference-mismatch").unwrap());
    assert_conflict(store.settle_n4_credential_invalidation(
        wrong_reference,
        N4InvalidationOutcome::Confirmed,
        now(),
        AuditActor::system(),
    ));
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation
    );
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .state,
        nodescale_domain::InvitationState::Revoking
    );

    store
        .settle_n4_credential_invalidation(
            target.clone(),
            N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );

    let mut opposite_terminal_intent = target.clone();
    opposite_terminal_intent.intent = N4CleanupIntent::Expired;
    assert_conflict(store.settle_n4_credential_invalidation(
        opposite_terminal_intent,
        N4InvalidationOutcome::AlreadySatisfied,
        now(),
        AuditActor::system(),
    ));
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    store
        .settle_n4_credential_invalidation(
            target,
            N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.audit_event_count().unwrap(),
        audits_after_confirmation + 2
    );
    assert_zero_projections(&store, &network);
}

#[tokio::test]
async fn ambiguous_no_reference_revoke_stays_pending_but_expiry_terminalizes_exactly_once() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ambiguous-expiry.db");
    let (store, network) = configured_file_store(&path, "ambiguous-expiry").await;
    let expires_at = now() + Duration::minutes(1);
    let invitation = invitation(network.network_id, expires_at);
    let session_id = reserve(&store, &network, &invitation, "principal-ambiguous");
    let audits_after_issue = store.audit_event_count().unwrap() - 2;
    store
        .begin_n4_credential_dispatch(session_id, now(), AuditActor::system())
        .unwrap();
    store
        .fail_n4_credential_dispatch(
            session_id,
            N4DispatchFailure::Ambiguous,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(store.audit_event_count().unwrap(), audits_after_issue + 3);

    let revoke = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    assert!(revoke.provider_reference.is_none());
    assert!(revoke.cleanup_uncertain);
    assert_eq!(revoke.intent, N4CleanupIntent::Revoked);
    let pending = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(pending.state, nodescale_domain::InvitationState::Revoking);
    assert_eq!(pending.cleanup_state, N4CleanupState::None);
    assert_eq!(store.audit_event_count().unwrap(), audits_after_issue + 3);
    assert_eq!(dispatch_state(&path, session_id), "revocation_pending");

    let expiry = store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    assert_eq!(expiry.intent, N4CleanupIntent::Expired);
    let terminal = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(terminal.state, nodescale_domain::InvitationState::Expired);
    assert_eq!(terminal.expired_at, Some(expires_at));
    assert_eq!(store.audit_event_count().unwrap(), audits_after_issue + 4);
    assert_eq!(dispatch_state(&path, session_id), "expired");

    store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    assert_eq!(store.audit_event_count().unwrap(), audits_after_issue + 4);
    assert_zero_projections(&store, &network);
}
