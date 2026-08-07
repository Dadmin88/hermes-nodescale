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
    HeadscaleImportConfig, N4InvitationContext, ProviderMutationConfiguration, StateStore,
    TlsVerificationPolicy,
};
use std::collections::BTreeSet;

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
async fn configured_store() -> (StateStore, Network) {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n4a-lifecycle",
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
fn invitation(network_id: NetworkId, expiry: DateTime<Utc>) -> (InvitationToken, Invitation) {
    let token = InvitationToken::generate(InvitationId::new());
    let invitation = Invitation::new_n4(
        token.invitation_id(),
        network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now(),
        expiry,
        1,
    )
    .unwrap();
    (token, invitation)
}

#[tokio::test]
async fn n4_issue_persists_only_a_redacted_candidate_and_requires_configured_capabilities() {
    let (store, network) = configured_store().await;
    let (token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-42").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap();
    assert_eq!(candidate.revision, 1);
    assert_eq!(
        candidate.context.provider_instance_id,
        network.provider_instance_id
    );
    assert!(candidate.verify(&token).unwrap());
    assert!(!format!("{candidate:?}").contains("argon2"));
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
}

#[tokio::test]
async fn n4_reservation_dispatch_and_confirmation_are_fenced_and_secret_free() {
    let (store, network) = configured_store().await;
    let (token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
    let context = N4InvitationContext::new(network.provider_instance_id, "principal-42").unwrap();
    store
        .issue_n4_invitation(&invitation, context, now(), AuditActor::system())
        .unwrap();
    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap();
    assert!(candidate.verify(&token).unwrap());
    let reservation = store
        .reserve_n4_redemption(
            invitation.invitation_id,
            candidate.revision,
            nodescale_domain::JoinSessionId::new(),
            now(),
            nodescale_state::N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    let (dispatch, authorization) = store
        .begin_n4_credential_dispatch_with_authorization(
            reservation.join_session_id,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    authorization
        .validate(nodescale_state::MutationAuthorizationContext::headscale(
            network.network_id,
            network.provider_instance_id,
            dispatch.authorization_generation,
            dispatch.configuration_generation,
            dispatch.configuration_fingerprint.clone(),
            "v0.29.3",
            false,
            ProviderMutationCapability::CreateJoinCredential,
            MutationPolicyMode::Database,
            now(),
        ))
        .unwrap();
    assert!(
        store
            .begin_n4_credential_dispatch(reservation.join_session_id, now(), AuditActor::system())
            .is_err()
    );
    store
        .confirm_n4_credential(
            reservation.join_session_id,
            nodescale_state::N4CredentialConfirmation {
                credential_id: nodescale_domain::ProviderCredentialId::new(),
                provider_reference: nodescale_domain::ProviderCredentialReference::new(
                    "native-ref-42",
                )
                .unwrap(),
                provider_principal_id: dispatch.context.provider_principal_id,
                ephemeral: false,
                approved_tags: vec!["tag:nodescale-worker".into()],
                expires_at: now() + Duration::minutes(10),
                confirmed_at: now(),
                safe_correlation: nodescale_state::SanitizedMetadata::new(
                    serde_json::json!({"request": "n4"}),
                )
                .unwrap(),
            },
            AuditActor::system(),
        )
        .unwrap();
    let cleanup = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    store
        .settle_n4_credential_invalidation(
            cleanup,
            nodescale_state::N4InvalidationOutcome::Confirmed,
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
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains("nsjoin_")
    );
}

#[tokio::test]
async fn n4_unused_revocation_is_local_only_and_safe_views_exclude_legacy() {
    let (store, network) = configured_store().await;
    let (_token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-42").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let views = store.list_n4_invitations(network.network_id).unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].roles, invitation.roles);
    assert_eq!(views[0].max_uses, 1);
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    assert_eq!(target.network_id, network.network_id);
    assert_eq!(target.provider_reference, None);
    assert!(!target.cleanup_uncertain);
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
}

#[tokio::test]
async fn n4_expiry_at_equality_terminalizes_an_issued_invitation_once() {
    let (store, network) = configured_store().await;
    let expires_at = now() + Duration::minutes(1);
    let (_token, invitation) = invitation(network.network_id, expires_at);
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-equality").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.expired_n4_invitation_ids(expires_at).unwrap(),
        vec![invitation.invitation_id]
    );
    let audits_before = store.audit_event_count().unwrap();
    store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    let view = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(view.state, nodescale_domain::InvitationState::Expired);
    assert_eq!(view.expired_at, Some(expires_at));
    assert_eq!(store.audit_event_count().unwrap(), audits_before + 1);
    store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    assert_eq!(store.audit_event_count().unwrap(), audits_before + 1);
}

#[tokio::test]
async fn n4_authorization_is_exact_and_a_failed_consume_cannot_reopen_dispatch() {
    let (store, network) = configured_store().await;
    let (_token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-auth").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let reservation = store
        .reserve_n4_redemption(
            invitation.invitation_id,
            store
                .n4_invitation_candidate(invitation.invitation_id)
                .unwrap()
                .revision,
            nodescale_domain::JoinSessionId::new(),
            now(),
            nodescale_state::N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    let (dispatch, authorization) = store
        .begin_n4_credential_dispatch_with_authorization(
            reservation.join_session_id,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert!(
        authorization
            .validate(nodescale_state::MutationAuthorizationContext::headscale(
                NetworkId::new(),
                network.provider_instance_id,
                dispatch.authorization_generation,
                dispatch.configuration_generation,
                dispatch.configuration_fingerprint,
                "v0.29.3",
                false,
                ProviderMutationCapability::CreateJoinCredential,
                MutationPolicyMode::Database,
                now()
            ))
            .is_err()
    );
    assert!(
        store
            .begin_n4_credential_dispatch_with_authorization(
                reservation.join_session_id,
                now(),
                AuditActor::system()
            )
            .is_err()
    );
}

#[tokio::test]
async fn n4_pre_dispatch_no_apply_and_ambiguous_failures_are_durable_and_never_replay_create() {
    let (store, network) = configured_store().await;
    for failure in [
        nodescale_state::N4DispatchFailure::PreDispatch,
        nodescale_state::N4DispatchFailure::DefiniteNoApply,
        nodescale_state::N4DispatchFailure::Ambiguous,
    ] {
        let (_token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
        store
            .issue_n4_invitation(
                &invitation,
                N4InvitationContext::new(
                    network.provider_instance_id,
                    format!("principal-{failure:?}"),
                )
                .unwrap(),
                now(),
                AuditActor::system(),
            )
            .unwrap();
        let reservation = store
            .reserve_n4_redemption(
                invitation.invitation_id,
                store
                    .n4_invitation_candidate(invitation.invitation_id)
                    .unwrap()
                    .revision,
                nodescale_domain::JoinSessionId::new(),
                now(),
                nodescale_state::N4PresentedMetadata::default(),
                AuditActor::system(),
            )
            .unwrap();
        if failure != nodescale_state::N4DispatchFailure::PreDispatch {
            store
                .begin_n4_credential_dispatch(
                    reservation.join_session_id,
                    now(),
                    AuditActor::system(),
                )
                .unwrap();
        }
        store
            .fail_n4_credential_dispatch(
                reservation.join_session_id,
                failure,
                now(),
                AuditActor::system(),
            )
            .unwrap();
        assert!(
            store
                .begin_n4_credential_dispatch(
                    reservation.join_session_id,
                    now(),
                    AuditActor::system()
                )
                .is_err()
        );
        assert_eq!(
            store
                .n4_invitation_view(invitation.invitation_id)
                .unwrap()
                .state,
            nodescale_domain::InvitationState::Failed
        );
    }
}

#[tokio::test]
async fn n4_ambiguous_without_reference_stays_pending_until_expiry_then_terminalizes_once() {
    let (store, network) = configured_store().await;
    let expires_at = now() + Duration::minutes(1);
    let (_token, invitation) = invitation(network.network_id, expires_at);
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-ambiguous").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let reservation = store
        .reserve_n4_redemption(
            invitation.invitation_id,
            store
                .n4_invitation_candidate(invitation.invitation_id)
                .unwrap()
                .revision,
            nodescale_domain::JoinSessionId::new(),
            now(),
            nodescale_state::N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    store
        .begin_n4_credential_dispatch(reservation.join_session_id, now(), AuditActor::system())
        .unwrap();
    store
        .fail_n4_credential_dispatch(
            reservation.join_session_id,
            nodescale_state::N4DispatchFailure::Ambiguous,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert!(
        store
            .prepare_n4_expiry(invitation.invitation_id, now(), AuditActor::system())
            .is_err()
    );
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .state,
        nodescale_domain::InvitationState::Failed
    );
    let audits_before = store.audit_event_count().unwrap();
    assert_eq!(
        store.expired_n4_invitation_ids(expires_at).unwrap(),
        vec![invitation.invitation_id]
    );
    let terminal = store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    assert!(terminal.provider_reference.is_none());
    let view = store.n4_invitation_view(invitation.invitation_id).unwrap();
    assert_eq!(view.state, nodescale_domain::InvitationState::Expired);
    assert_eq!(view.expired_at, Some(expires_at));
    assert_eq!(store.audit_event_count().unwrap(), audits_before + 1);
    store
        .prepare_n4_expiry(invitation.invitation_id, expires_at, AuditActor::system())
        .unwrap();
    assert_eq!(store.audit_event_count().unwrap(), audits_before + 1);
}

#[tokio::test]
async fn n4_confirmed_cleanup_requires_exact_target_and_settles_retryable_once() {
    let (store, network) = configured_store().await;
    let (_token, invitation) = invitation(network.network_id, now() + Duration::minutes(20));
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, "principal-cleanup").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let reservation = store
        .reserve_n4_redemption(
            invitation.invitation_id,
            store
                .n4_invitation_candidate(invitation.invitation_id)
                .unwrap()
                .revision,
            nodescale_domain::JoinSessionId::new(),
            now(),
            nodescale_state::N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    let dispatch = store
        .begin_n4_credential_dispatch(reservation.join_session_id, now(), AuditActor::system())
        .unwrap();
    store
        .confirm_n4_credential(
            reservation.join_session_id,
            nodescale_state::N4CredentialConfirmation {
                credential_id: nodescale_domain::ProviderCredentialId::new(),
                provider_reference: nodescale_domain::ProviderCredentialReference::new(
                    "native-ref-cleanup",
                )
                .unwrap(),
                provider_principal_id: dispatch.context.provider_principal_id,
                ephemeral: false,
                approved_tags: vec!["tag:nodescale-worker".into()],
                expires_at: now() + Duration::minutes(10),
                confirmed_at: now(),
                safe_correlation: nodescale_state::SanitizedMetadata::empty(),
            },
            AuditActor::system(),
        )
        .unwrap();
    let target = store
        .prepare_n4_revocation(invitation.invitation_id, now(), AuditActor::system())
        .unwrap();
    let mut wrong_intent = target.clone();
    wrong_intent.intent = nodescale_state::N4CleanupIntent::Expired;
    assert!(
        store
            .settle_n4_credential_invalidation(
                wrong_intent,
                nodescale_state::N4InvalidationOutcome::Confirmed,
                now(),
                AuditActor::system()
            )
            .is_err()
    );
    let mut wrong_reference = target.clone();
    wrong_reference.provider_reference =
        Some(nodescale_domain::ProviderCredentialReference::new("other-native-ref").unwrap());
    assert!(
        store
            .settle_n4_credential_invalidation(
                wrong_reference,
                nodescale_state::N4InvalidationOutcome::Confirmed,
                now(),
                AuditActor::system()
            )
            .is_err()
    );
    store
        .settle_n4_credential_invalidation(
            target.clone(),
            nodescale_state::N4InvalidationOutcome::Retryable,
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
            .cleanup_state,
        nodescale_state::N4CleanupState::Retryable
    );
    store
        .settle_n4_credential_invalidation(
            target.clone(),
            nodescale_state::N4InvalidationOutcome::Confirmed,
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
    store
        .settle_n4_credential_invalidation(
            target,
            nodescale_state::N4InvalidationOutcome::Confirmed,
            now(),
            AuditActor::system(),
        )
        .unwrap();
}
