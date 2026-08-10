use crate::{
    HeadscaleImportConfig, N4CredentialConfirmation, N4InvitationContext, N4PresentedMetadata,
    N5IdentityConfirmationOutcome, N5TrustAuthorityConfiguration, N5TrustDecisionOutcome,
    N5TrustReason, ProviderMutationConfiguration, SanitizedMetadata, StateStore,
    TlsVerificationPolicy,
};
use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, DeviceTrustState,
    Generation, Invitation, InvitationId, InvitationToken, JoinConstraints, JoinSessionId, Network,
    NetworkId, OwnerTrustRootToken, ProviderApiKey, ProviderBindingState, ProviderCredentialId,
    ProviderCredentialReference, ProviderIdentity, ProviderInstanceId, ProviderKind,
    ProviderNodeId, Role, Roles, TrustAuthorityId, TrustRootId,
};
use nodescale_provider::{
    CompatibilityStatus, ConditionalIdentityEvidence, MutationPolicyMode,
    PreAuthAssociationStrength, PreAuthCorrelationObservation, ProviderError, ProviderHealth,
    ProviderIdentityEvidence, ProviderMutationCapability, ProviderNode, ReadOnlyProvider,
    ServerInspection,
};
use nodescale_provider_headscale::HeadscaleClientOptions;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::tempdir;

#[derive(Clone)]
struct ImportedProvider(ProviderInstanceId, Vec<ProviderNode>);
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
    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        Ok(self.1.clone())
    }
    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Ok(self
            .1
            .iter()
            .find(|node| &node.identity == identity)
            .cloned())
    }
    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        unreachable!()
    }
}

struct FailingGetProvider(ImportedProvider);

#[async_trait::async_trait]
impl ReadOnlyProvider for FailingGetProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.0.instance_id()
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        self.0.inspect_server().await
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        self.0.list_nodes().await
    }

    async fn get_node(
        &self,
        _identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Err(ProviderError::Timeout)
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        self.0.provider_health().await
    }
}

fn now() -> DateTime<Utc> {
    "2026-08-07T12:00:00Z".parse().unwrap()
}

fn provider_node(
    instance: ProviderInstanceId,
    reference: &ProviderCredentialReference,
    node_id: &str,
    machine_key: &str,
) -> ProviderNode {
    let fingerprint = format!("sha256:{:x}", Sha256::digest(machine_key.as_bytes()));
    ProviderNode {
        identity: ProviderIdentity::new(
            instance,
            ProviderNodeId::parse(node_id).unwrap(),
            fingerprint,
        )
        .unwrap(),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(ConditionalIdentityEvidence::new(machine_key).unwrap()),
            node_key: None,
            disco_key: None,
        },
        hostname: "mutable-hostname".into(),
        given_name: "mutable-name".into(),
        addresses: vec!["198.51.100.200".into()],
        user: None,
        pre_auth: Some(PreAuthCorrelationObservation {
            credential_id: reference.as_str().into(),
            association: PreAuthAssociationStrength::ProviderAuthenticatedRegistration,
        }),
        tags: BTreeSet::new(),
        registered_at: Some(now()),
        last_seen: Some(now()),
        expires_at: None,
        observed_at: now() + Duration::milliseconds(1),
        online: Some(true),
        expired: false,
    }
}

async fn add_confirmed_n4_join(
    store: &StateStore,
    network: &Network,
    reference_value: &str,
    principal: &str,
) -> (JoinSessionId, ProviderCredentialReference) {
    let token = InvitationToken::generate(InvitationId::new());
    let invitation = Invitation::new_n4(
        token.invitation_id(),
        network.network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now(),
        now() + Duration::minutes(15),
        1,
    )
    .unwrap();
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(network.provider_instance_id, principal).unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap();
    let join_session_id = JoinSessionId::new();
    store
        .reserve_n4_redemption(
            invitation.invitation_id,
            candidate.revision,
            join_session_id,
            now(),
            N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .unwrap();
    let dispatch = store
        .begin_n4_credential_dispatch(join_session_id, now(), AuditActor::system())
        .unwrap();
    let reference = ProviderCredentialReference::new(reference_value).unwrap();
    store
        .confirm_n4_credential(
            join_session_id,
            N4CredentialConfirmation {
                credential_id: ProviderCredentialId::new(),
                provider_reference: reference.clone(),
                provider_principal_id: dispatch.context.provider_principal_id,
                ephemeral: false,
                approved_tags: vec!["tag:nodescale-worker".into()],
                expires_at: now() + Duration::minutes(10),
                confirmed_at: now(),
                safe_correlation: SanitizedMetadata::new(serde_json::json!({
                    "request": "n5-test"
                }))
                .unwrap(),
            },
            AuditActor::system(),
        )
        .unwrap();
    (join_session_id, reference)
}

async fn confirmed_n4_store() -> (
    StateStore,
    Network,
    JoinSessionId,
    ProviderCredentialReference,
) {
    confirmed_n4_store_from(StateStore::open_in_memory().unwrap()).await
}

async fn confirmed_n4_store_from(
    store: StateStore,
) -> (
    StateStore,
    Network,
    JoinSessionId,
    ProviderCredentialReference,
) {
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n5-trust",
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
            &ImportedProvider(instance, vec![]),
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
    let (join_session_id, reference) =
        add_confirmed_n4_join(&store, &network, "n5-native-reference", "principal-n5").await;
    (store, network, join_session_id, reference)
}

#[tokio::test]
async fn configured_provider_snapshot_rejects_import_change_before_network_read() {
    let (store, network, join_session_id, _) = confirmed_n4_store().await;
    let configured = store
        .configured_n5_headscale_provider(
            network.network_id,
            ProviderApiKey::new("configured-provider-test-key".to_owned()).unwrap(),
            HeadscaleClientOptions::default(),
        )
        .unwrap();
    store
        .connection
        .borrow()
        .execute(
            "UPDATE provider_imports SET server_url='https://replacement.example.test' WHERE network_id=?1",
            [network.network_id.to_string()],
        )
        .unwrap();

    let error = store
        .confirm_n5_device_identity(&configured, join_session_id, now(), AuditActor::system())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        crate::StateError::Conflict(message)
            if message == "configured provider identity changed"
    ));
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
}

#[tokio::test]
async fn configured_provider_rejects_unpersisted_custom_root_before_network_read() {
    let (store, network, _, _) = confirmed_n4_store().await;
    store
        .connection
        .borrow()
        .execute(
            "UPDATE provider_imports SET custom_root_ca_sha256=?2 WHERE network_id=?1",
            rusqlite::params![
                network.network_id.to_string(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
        )
        .unwrap();

    let result = store.configured_n5_headscale_provider_with_custom_root_ca(
        network.network_id,
        ProviderApiKey::new("...".to_string()).unwrap(),
        HeadscaleClientOptions::default(),
        nodescale_provider_headscale::HeadscaleCustomRootCa::PemBytes(
            b"caller-selected-forged-root".to_vec(),
        ),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("caller-selected custom root unexpectedly became authoritative"),
    };
    assert!(matches!(
        error,
        crate::StateError::Conflict(message)
            if message == "custom root CA does not match persisted provider configuration"
    ));
}

#[tokio::test]
async fn provider_confirmation_rejects_partial_duplicate_and_expired_evidence() {
    let (store, network, join_session_id, reference) = confirmed_n4_store().await;
    let unsafe_actor_node = provider_node(
        network.provider_instance_id,
        &reference,
        "44",
        "mkey:unsafe-audit-actor",
    );
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(network.provider_instance_id, vec![unsafe_actor_node]),
                join_session_id,
                now(),
                AuditActor {
                    source: "x".repeat(65),
                    actor_id: Some("nstrust_secret_shaped_text".into()),
                },
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    let mut partial = provider_node(
        network.provider_instance_id,
        &reference,
        "45",
        "mkey:partial-registration",
    );
    partial.pre_auth.as_mut().unwrap().association = PreAuthAssociationStrength::Partial;
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(network.provider_instance_id, vec![partial]),
                join_session_id,
                now(),
                AuditActor::system(),
            )
            .await
            .is_err()
    );

    let duplicate = provider_node(
        network.provider_instance_id,
        &reference,
        "46",
        "mkey:duplicate-registration-a",
    );
    let duplicate_other = provider_node(
        network.provider_instance_id,
        &reference,
        "47",
        "mkey:duplicate-registration-b",
    );
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(
                    network.provider_instance_id,
                    vec![duplicate, duplicate_other],
                ),
                join_session_id,
                now(),
                AuditActor::system(),
            )
            .await
            .is_err()
    );

    let valid = provider_node(
        network.provider_instance_id,
        &reference,
        "48",
        "mkey:expired-registration",
    );
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(network.provider_instance_id, vec![valid]),
                join_session_id,
                now() + Duration::minutes(11),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
}

#[tokio::test]
async fn cross_session_reference_swap_and_machine_key_reuse_fail_closed() {
    let (store, network, first_session, first_reference) = confirmed_n4_store().await;
    let (second_session, second_reference) = add_confirmed_n4_join(
        &store,
        &network,
        "n5-native-reference-second",
        "principal-n5-second",
    )
    .await;

    let second_node = provider_node(
        network.provider_instance_id,
        &second_reference,
        "51",
        "mkey:cross-session-reuse",
    );
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(network.provider_instance_id, vec![second_node.clone()]),
                first_session,
                now(),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);

    let first_node = provider_node(
        network.provider_instance_id,
        &first_reference,
        "50",
        "mkey:cross-session-reuse",
    );
    store
        .confirm_n5_device_identity_from_provider(
            &ImportedProvider(network.provider_instance_id, vec![first_node]),
            first_session,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert!(
        store
            .confirm_n5_device_identity_from_provider(
                &ImportedProvider(network.provider_instance_id, vec![second_node]),
                second_session,
                now(),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 1);
}

#[tokio::test]
async fn provider_reconciliation_preserves_exact_binding_and_stales_absence() {
    let (store, network, join_session_id, reference) = confirmed_n4_store().await;
    let node = provider_node(
        network.provider_instance_id,
        &reference,
        "49",
        "mkey:reconciliation-registration",
    );
    let exact_provider = ImportedProvider(network.provider_instance_id, vec![node]);
    let confirmation = store
        .confirm_n5_device_identity_from_provider(
            &exact_provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let provider_keyed = store
        .persisted_device_trust_view_by_provider_registration(
            network.provider_instance_id,
            exact_provider.1[0].identity.node_id.clone(),
        )
        .unwrap()
        .expect("confirmed provider registration must resolve");
    assert_eq!(provider_keyed.device_id, confirmation.identity.device_id);
    assert_eq!(
        provider_keyed
            .provider_binding
            .as_ref()
            .unwrap()
            .binding_state,
        ProviderBindingState::Active
    );
    assert!(
        store
            .connection
            .borrow()
            .execute(
                "UPDATE n5_provider_bindings SET binding_state='stale',binding_revision=2,stale_at_ms=?2 WHERE device_id=?1",
                rusqlite::params![confirmation.identity.device_id.to_string(), now().timestamp_millis()],
            )
            .is_err(),
        "a lifecycle transition without an audit correlation must fail"
    );
    let exact = store
        .reconcile_n5_provider_binding_from_provider(
            &exact_provider,
            confirmation.identity.device_id,
            now() + Duration::seconds(1),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        exact.provider_binding.as_ref().unwrap().binding_state,
        ProviderBindingState::Active
    );
    let absent_provider = ImportedProvider(network.provider_instance_id, vec![]);
    let stale = store
        .reconcile_n5_provider_binding_from_provider(
            &absent_provider,
            confirmation.identity.device_id,
            now() + Duration::seconds(2),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        stale.provider_binding.as_ref().unwrap().binding_state,
        ProviderBindingState::Stale
    );
    let lifecycle_audit_links: u64 = store
        .connection
        .borrow()
        .query_row(
            "SELECT COUNT(*) FROM n5_provider_bindings b JOIN audit_events a ON a.event_id=b.last_transition_audit_event_id WHERE b.device_id=?1 AND a.event_kind='device.provider_binding_stale' AND a.generation=b.binding_revision",
            [confirmation.identity.device_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lifecycle_audit_links, 1);
    assert!(!stale.currently_trusted);
}

#[tokio::test]
async fn direct_stale_transition_rejects_unbounded_audit_actor_without_writing() {
    let (store, network, join_session_id, reference) = confirmed_n4_store().await;
    let provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "unsafe-stale-actor",
            "mkey:unsafe-stale-actor",
        )],
    );
    let confirmation = store
        .confirm_n5_device_identity_from_provider(
            &provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();

    assert!(
        store
            .mark_n5_provider_binding_stale(
                confirmation.identity.device_id,
                confirmation.identity.binding_revision,
                now() + Duration::seconds(1),
                AuditActor {
                    source: "x".repeat(65),
                    actor_id: Some("unsafe".into()),
                },
            )
            .is_err()
    );
    let unchanged = store
        .persisted_device_trust_view(confirmation.identity.device_id)
        .unwrap();
    assert_eq!(
        unchanged.provider_binding.unwrap().binding_state,
        ProviderBindingState::Active
    );
}

#[tokio::test]
async fn provider_registration_lookup_resolves_only_the_active_replacement() {
    let (store, network, first_session, first_reference) = confirmed_n4_store().await;
    let provider_node_id = "reused-provider-node";
    let first = store
        .confirm_n5_device_identity_from_provider(
            &ImportedProvider(
                network.provider_instance_id,
                vec![provider_node(
                    network.provider_instance_id,
                    &first_reference,
                    provider_node_id,
                    "mkey:first-provider-node-owner",
                )],
            ),
            first_session,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    store
        .mark_n5_provider_binding_stale(
            first.identity.device_id,
            first.identity.binding_revision,
            now() + Duration::seconds(1),
            AuditActor::system(),
        )
        .unwrap();

    let (second_session, second_reference) = add_confirmed_n4_join(
        &store,
        &network,
        "replacement-reference",
        "replacement-user",
    )
    .await;
    let second = store
        .confirm_n5_device_identity_from_provider(
            &ImportedProvider(
                network.provider_instance_id,
                vec![provider_node(
                    network.provider_instance_id,
                    &second_reference,
                    provider_node_id,
                    "mkey:replacement-provider-node-owner",
                )],
            ),
            second_session,
            now() + Duration::seconds(2),
            AuditActor::system(),
        )
        .await
        .unwrap();

    let resolved = store
        .persisted_device_trust_view_by_provider_registration(
            network.provider_instance_id,
            ProviderNodeId::parse(provider_node_id).unwrap(),
        )
        .unwrap()
        .expect("the active replacement must resolve");
    assert_eq!(resolved.device_id, second.identity.device_id);
    assert_eq!(
        resolved.provider_binding.unwrap().binding_state,
        ProviderBindingState::Active
    );
}

#[tokio::test]
async fn provider_error_stales_previously_trusted_binding() {
    let (store, network, join_session_id, reference) = confirmed_n4_store().await;
    let provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "provider-error-trusted",
            "mkey:provider-error-trusted",
        )],
    );
    let confirmation = store
        .confirm_n5_device_identity_from_provider(
            &provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let root_token = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "provider-error-owner",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root_token,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "owner",
                "provider-error-owner",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    let authorization = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            confirmation.identity.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    store
        .activate_device_trust(authorization, now(), N5TrustReason::OwnerApproved)
        .unwrap();
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        1
    );

    assert!(
        store
            .reconcile_n5_provider_binding_from_provider(
                &FailingGetProvider(provider),
                confirmation.identity.device_id,
                now() + Duration::seconds(1),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    let after = store
        .persisted_device_trust_view(confirmation.identity.device_id)
        .unwrap();
    assert_eq!(after.trust_state, DeviceTrustState::Trusted);
    assert_eq!(
        after.provider_binding.as_ref().unwrap().binding_state,
        ProviderBindingState::Stale
    );
    assert_eq!(
        after.provider_binding.as_ref().unwrap().binding_revision,
        Generation::new(2).unwrap()
    );
    assert!(!after.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn identity_is_exact_untrusted_then_explicitly_trusted_and_terminally_revoked() {
    let (store, network, join_session_id, reference) = confirmed_n4_store().await;
    let wrong_reference = ProviderCredentialReference::new("wrong-session-reference").unwrap();
    let swapped_provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &wrong_reference,
            "42",
            "mkey:wrong-reference",
        )],
    );
    let swapped = store
        .confirm_n5_device_identity_from_provider(
            &swapped_provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await;
    assert!(swapped.is_err());
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);

    let provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "42",
            "mkey:confirmed-registration",
        )],
    );
    let confirmation = store
        .confirm_n5_device_identity_from_provider(
            &provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        confirmation.outcome,
        N5IdentityConfirmationOutcome::Confirmed
    );
    let repeated = store
        .confirm_n5_device_identity_from_provider(
            &provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        repeated.outcome,
        N5IdentityConfirmationOutcome::AlreadyConfirmed
    );
    assert_eq!(repeated.identity.device_id, confirmation.identity.device_id);

    let substituted_provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "43",
            "mkey:substituted-registration",
        )],
    );
    let substituted = store
        .confirm_n5_device_identity_from_provider(
            &substituted_provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await;
    assert!(substituted.is_err());

    let before = store
        .persisted_device_trust_view(confirmation.identity.device_id)
        .unwrap();
    assert_eq!(before.trust_state, DeviceTrustState::Untrusted);
    assert!(!before.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        0
    );
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);

    let root_token = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-42",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root_token,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "owner",
                "owner-42",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [
                    DeviceTrustCapability::ActivateDeviceTrust,
                    DeviceTrustCapability::RevokeDeviceTrust,
                ],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    let wrong_capability = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            confirmation.identity.device_id,
            Generation::initial(),
            DeviceTrustCapability::RevokeDeviceTrust,
            now(),
        )
        .unwrap();
    assert!(
        store
            .activate_device_trust(wrong_capability, now(), N5TrustReason::OwnerApproved,)
            .is_err()
    );
    let expired = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            confirmation.identity.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    assert!(
        store
            .activate_device_trust(
                expired,
                now() + Duration::minutes(6),
                N5TrustReason::OwnerApproved,
            )
            .is_err()
    );
    assert_eq!(
        store
            .persisted_device_trust_view(confirmation.identity.device_id)
            .unwrap()
            .trust_state,
        DeviceTrustState::Untrusted
    );
    let activate = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            confirmation.identity.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    let activated = store
        .activate_device_trust(activate, now(), N5TrustReason::OwnerApproved)
        .unwrap();
    assert_eq!(activated.outcome, N5TrustDecisionOutcome::Applied);
    assert_eq!(activated.view.trust_state, DeviceTrustState::Trusted);
    assert!(!activated.view.currently_trusted);
    let provider_fresh = store
        .reconcile_n5_provider_binding_from_provider(
            &provider,
            confirmation.identity.device_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert!(provider_fresh.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        1
    );
    assert!(
        store
            .issue_device_trust_authorization(
                &root_token,
                authority_id,
                confirmation.identity.device_id,
                activated.view.trust_revision,
                DeviceTrustCapability::ActivateDeviceTrust,
                now() + Duration::milliseconds(100),
            )
            .is_err()
    );

    let stale = store
        .mark_n5_provider_binding_stale(
            confirmation.identity.device_id,
            confirmation.identity.binding_revision,
            now() + Duration::milliseconds(500),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(stale.trust_state, DeviceTrustState::Trusted);
    assert!(!stale.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        0
    );
    let cleanup_pending = store
        .mark_n5_provider_binding_cleanup_pending(
            confirmation.identity.device_id,
            stale.provider_binding.as_ref().unwrap().binding_revision,
            now() + Duration::milliseconds(600),
            AuditActor::system(),
        )
        .unwrap();
    assert!(!cleanup_pending.currently_trusted);
    let removed = store
        .mark_n5_provider_binding_removed(
            confirmation.identity.device_id,
            cleanup_pending
                .provider_binding
                .as_ref()
                .unwrap()
                .binding_revision,
            now() + Duration::milliseconds(700),
            AuditActor::system(),
        )
        .unwrap();
    assert!(!removed.currently_trusted);
    assert_eq!(
        removed.provider_binding.as_ref().unwrap().binding_state,
        ProviderBindingState::Removed
    );

    let revoke = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            confirmation.identity.device_id,
            activated.view.trust_revision,
            DeviceTrustCapability::RevokeDeviceTrust,
            now() + Duration::seconds(1),
        )
        .unwrap();
    let revoked = store
        .revoke_device_trust(
            revoke,
            now() + Duration::seconds(1),
            N5TrustReason::OwnerRevoked,
        )
        .unwrap();
    assert_eq!(revoked.view.trust_state, DeviceTrustState::Revoked);
    assert!(!revoked.view.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        0
    );

    assert!(
        store
            .issue_device_trust_authorization(
                &root_token,
                authority_id,
                confirmation.identity.device_id,
                revoked.view.trust_revision,
                DeviceTrustCapability::ActivateDeviceTrust,
                now() + Duration::seconds(2),
            )
            .is_err()
    );
    assert!(
        store
            .issue_device_trust_authorization(
                &root_token,
                authority_id,
                confirmation.identity.device_id,
                revoked.view.trust_revision,
                DeviceTrustCapability::RevokeDeviceTrust,
                now() + Duration::seconds(2),
            )
            .is_err()
    );
}

#[tokio::test]
async fn independent_connections_race_one_identity_and_one_trust_revision() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n5-race.db");
    let (store, network, join_session_id, reference) =
        confirmed_n4_store_from(StateStore::open(&path).unwrap()).await;
    drop(store);

    let provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "44",
            "mkey:race-registration",
        )],
    );
    let identity_barrier = Arc::new(Barrier::new(2));
    let identity_handles = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&identity_barrier);
            let provider = provider.clone();
            thread::spawn(move || {
                let store = StateStore::open(path).unwrap();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                barrier.wait();
                runtime.block_on(store.confirm_n5_device_identity_from_provider(
                    &provider,
                    join_session_id,
                    now(),
                    AuditActor::system(),
                ))
            })
        })
        .collect::<Vec<_>>();
    let identity_results = identity_handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        identity_results
            .iter()
            .filter(|result| result.outcome == N5IdentityConfirmationOutcome::Confirmed)
            .count(),
        1
    );
    assert_eq!(
        identity_results
            .iter()
            .filter(|result| result.outcome == N5IdentityConfirmationOutcome::AlreadyConfirmed)
            .count(),
        1
    );
    assert_eq!(
        identity_results[0].identity.device_id,
        identity_results[1].identity.device_id
    );
    let device_id = identity_results[0].identity.device_id;
    let persisted = std::fs::read(&path).unwrap();
    assert!(
        !persisted
            .windows("mkey:race-registration".len())
            .any(|window| window == b"mkey:race-registration")
    );

    let authority_id = TrustAuthorityId::new();
    let store = StateStore::open(&path).unwrap();
    let root_token = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-race",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    store
        .configure_n5_trust_authority(
            &root_token,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "owner",
                "owner-race",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    let first = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    let second = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    drop(store);

    let trust_barrier = Arc::new(Barrier::new(2));
    let authorizations = [first, second];
    let handles = authorizations.map(|authorization| {
        let path = path.clone();
        let barrier = Arc::clone(&trust_barrier);
        thread::spawn(move || {
            let store = StateStore::open(path).unwrap();
            barrier.wait();
            store.activate_device_trust(authorization, now(), N5TrustReason::OwnerApproved)
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

    let store = StateStore::open(&path).unwrap();
    let persisted = store.persisted_device_trust_view(device_id).unwrap();
    assert_eq!(persisted.trust_state, DeviceTrustState::Trusted);
    assert!(!persisted.currently_trusted);
    assert_eq!(
        store
            .persisted_trusted_device_count(network.network_id)
            .unwrap(),
        1
    );
    drop(store);
    let connection = rusqlite::Connection::open(path).unwrap();
    let device_count: u64 = connection
        .query_row("SELECT COUNT(*) FROM n5_device_identities", [], |row| {
            row.get(0)
        })
        .unwrap();
    let decisions: u64 = connection
        .query_row("SELECT COUNT(*) FROM n5_trust_decisions", [], |row| {
            row.get(0)
        })
        .unwrap();
    let consumed: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_trust_authorizations WHERE consumed_at_ms IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(device_count, 1);
    assert_eq!(decisions, 1);
    assert_eq!(consumed, 1);
    let decision_audit_links: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_trust_decisions d JOIN audit_events a ON a.event_id=d.audit_event_id WHERE a.event_kind='device.trust_activated' AND a.generation=d.new_revision",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(decision_audit_links, 1);
    assert!(connection
        .execute(
            "UPDATE n5_device_trust_state SET trust_state='revoked',trust_revision=trust_revision+1,revoked_at_ms=1,last_decision_id='forged'",
            [],
        )
        .is_err());
    assert!(
        connection
            .execute("DELETE FROM n5_trust_decisions", [])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM n5_device_trust_state", [])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM n5_provider_bindings", [])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM n5_device_identities", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM audit_events WHERE event_kind='device.trust_activated'",
                [],
            )
            .is_err()
    );
}

#[tokio::test]
async fn authority_revocation_race_never_leaves_usable_trust_authorization() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n5-authority-revocation-race.db");
    let (store, network, join_session_id, reference) =
        confirmed_n4_store_from(StateStore::open(&path).unwrap()).await;
    let provider = ImportedProvider(
        network.provider_instance_id,
        vec![provider_node(
            network.provider_instance_id,
            &reference,
            "52",
            "mkey:authority-revocation-race",
        )],
    );
    let device_id = store
        .confirm_n5_device_identity_from_provider(
            &provider,
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap()
        .identity
        .device_id;
    let generated = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-revocation-race",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let plaintext = generated.expose_for_delivery(str::to_owned);
    let configure_token: OwnerTrustRootToken = plaintext.parse().unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &configure_token,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "owner",
                "owner-revocation-race",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let issue_path = path.clone();
    let issue_barrier = Arc::clone(&barrier);
    let issue_plaintext = plaintext.clone();
    let issue = thread::spawn(move || {
        let token: OwnerTrustRootToken = issue_plaintext.parse().unwrap();
        let store = StateStore::open(issue_path).unwrap();
        issue_barrier.wait();
        store.issue_device_trust_authorization(
            &token,
            authority_id,
            device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
    });
    let revoke_path = path.clone();
    let revoke_barrier = Arc::clone(&barrier);
    let revoke = thread::spawn(move || {
        let token: OwnerTrustRootToken = plaintext.parse().unwrap();
        let store = StateStore::open(revoke_path).unwrap();
        revoke_barrier.wait();
        store.revoke_n5_trust_authority(&token, authority_id, now())
    });
    let issued = issue.join().unwrap().ok();
    revoke.join().unwrap().unwrap();
    let store = StateStore::open(&path).unwrap();
    if let Some(authorization) = issued {
        assert!(
            store
                .activate_device_trust(authorization, now(), N5TrustReason::OwnerApproved)
                .is_err()
        );
    }
    assert!(
        !store
            .persisted_device_trust_view(device_id)
            .unwrap()
            .currently_trusted
    );
}

#[tokio::test]
async fn owner_trust_root_is_verifier_only_and_seals_authority_and_audit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n5-owner-root.db");
    let (store, network, join_session_id, reference) =
        confirmed_n4_store_from(StateStore::open(&path).unwrap()).await;
    let device_id = store
        .confirm_n5_device_identity_from_provider(
            &ImportedProvider(
                network.provider_instance_id,
                vec![provider_node(
                    network.provider_instance_id,
                    &reference,
                    "53",
                    "mkey:owner-root-revocation",
                )],
            ),
            join_session_id,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap()
        .identity
        .device_id;
    let generated = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-root",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(format!("{generated:?}"), "OwnerTrustRootToken([REDACTED])");
    assert_eq!(generated.to_string(), "[REDACTED]");
    let plaintext = generated.expose_for_delivery(str::to_owned);
    let root_token: OwnerTrustRootToken = plaintext.parse().unwrap();

    assert!(
        store
            .bootstrap_n5_owner_trust_root(
                network.network_id,
                "local-owner",
                "second-root",
                DeviceTrustAuthorityAdminIntent::explicit(),
                now(),
                AuditActor::system(),
            )
            .is_err()
    );

    let authority_id = TrustAuthorityId::new();
    let configuration = N5TrustAuthorityConfiguration::new(
        authority_id,
        network.network_id,
        "owner",
        "owner-root",
        Generation::initial(),
        now() - Duration::minutes(1),
        now() + Duration::hours(1),
        [DeviceTrustCapability::ActivateDeviceTrust],
        now(),
    )
    .unwrap();
    let wrong_root = OwnerTrustRootToken::generate(TrustRootId::new());
    assert!(
        store
            .configure_n5_trust_authority(&wrong_root, &configuration)
            .is_err()
    );
    store
        .configure_n5_trust_authority(&root_token, &configuration)
        .unwrap();
    let authorization = store
        .issue_device_trust_authorization(
            &root_token,
            authority_id,
            device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    store
        .revoke_n5_owner_trust_root(&root_token, now() + Duration::seconds(1))
        .unwrap();
    assert!(
        store
            .activate_device_trust(
                authorization,
                now() + Duration::seconds(1),
                N5TrustReason::OwnerApproved,
            )
            .is_err()
    );
    let disabled_configuration = N5TrustAuthorityConfiguration::new(
        TrustAuthorityId::new(),
        network.network_id,
        "owner",
        "owner-root-disabled",
        Generation::initial(),
        now() - Duration::minutes(1),
        now() + Duration::hours(1),
        [DeviceTrustCapability::ActivateDeviceTrust],
        now(),
    )
    .unwrap();
    assert!(
        store
            .configure_n5_trust_authority(&root_token, &disabled_configuration)
            .is_err()
    );
    drop(store);

    let database = std::fs::read(&path).unwrap();
    assert!(
        !database
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_bytes())
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(connection
        .execute(
            "INSERT INTO n5_trust_authority_capabilities (authority_id,capability) VALUES (?1,'RevokeDeviceTrust')",
            [authority_id.to_string()],
        )
        .is_err());
    assert!(
        connection
            .execute(
                "DELETE FROM n5_trust_authorities WHERE authority_id=?1",
                [authority_id.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM n5_owner_trust_roots WHERE trust_root_id=?1",
                [root_token.trust_root_id().to_string()],
            )
            .is_err()
    );
    assert!(connection
        .execute(
            "UPDATE audit_events SET outcome='forged' WHERE event_kind='device.trust_authority_configured'",
            [],
        )
        .is_err());
    assert!(
        connection
            .execute(
                "DELETE FROM audit_events WHERE event_kind='device.trust_authority_configured'",
                [],
            )
            .is_err()
    );
}
