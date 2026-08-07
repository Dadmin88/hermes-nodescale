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
    HeadscaleImportConfig, N4CredentialConfirmation, N4InvitationContext, N4PresentedMetadata,
    ProviderMutationConfiguration, SanitizedMetadata, StateStore, TlsVerificationPolicy,
};
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

fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().unwrap()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn contains_complete_invitation_token(bytes: &[u8]) -> bool {
    const PREFIX: &[u8] = b"nsjoin_";
    bytes.windows(PREFIX.len() + 64).any(|window| {
        window.starts_with(PREFIX)
            && window[PREFIX.len()..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

fn read_database_and_existing_sidecars(path: &Path) -> Vec<Vec<u8>> {
    let mut artifacts = vec![std::fs::read(path).unwrap()];
    // StateStore does not expose a WAL-mode switch. Do not mutate its connection
    // with a test-only pragma; scan every WAL/SHM artifact it actually leaves.
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            artifacts.push(std::fs::read(sidecar).unwrap());
        }
    }
    artifacts
}

fn assert_absent_without_echoing(needle: &[u8], surfaces: &[&[u8]]) {
    for surface in surfaces {
        assert!(
            !contains_bytes(surface, needle),
            "a secret-bearing value reached an inspected persistence or diagnostic surface"
        );
    }
}

#[tokio::test]
async fn n4_raw_join_and_provider_secrets_never_reach_sqlite_audit_or_debug() {
    let source = include_str!("n4a_secret_safety.rs");
    assert!(
        !contains_complete_invitation_token(source.as_bytes()),
        "the test source must not embed a complete invitation token"
    );

    let dir = tempdir().unwrap();
    let path = dir.path().join("secret-safety.db");
    let store = StateStore::open(&path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n4-secret-safety",
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

    let token = InvitationToken::generate(InvitationId::new());
    let verifier = nodescale_domain::SecretVerifier::from_token(&token).unwrap();
    let token_prefix = ["ns", "join_"].concat();
    let raw_token = token.expose_for_delivery(|value| {
        let prefix_width = token_prefix.len();
        [
            value[..prefix_width].to_owned(),
            value[prefix_width..].to_owned(),
        ]
        .concat()
    });
    assert!(raw_token.starts_with(&token_prefix));
    let provider_secret = ["provider", "-secret", "-sentinel", "-n4a"].concat();
    assert!(
        !contains_bytes(source.as_bytes(), provider_secret.as_bytes()),
        "the test source must not embed the complete provider-secret sentinel"
    );

    // The provider secret sentinel is intentionally never supplied to StateStore.
    // Recreate the delivery token only at the service boundary from runtime fragments.
    let delivery_token: InvitationToken = raw_token.parse().unwrap();
    let invitation = Invitation::new_n4(
        delivery_token.invitation_id(),
        network.network_id,
        Roles::new([Role::Worker]).unwrap(),
        None,
        verifier,
        JoinConstraints::default(),
        now(),
        now() + Duration::minutes(20),
        1,
    )
    .unwrap();
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(instance, "principal-secret").unwrap(),
            now(),
            AuditActor::system(),
        )
        .unwrap();

    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .unwrap();
    let candidate_debug = format!("{candidate:?}");
    assert!(candidate.verify(&delivery_token).unwrap());
    let reservation = store
        .reserve_n4_redemption(
            invitation.invitation_id,
            candidate.revision,
            JoinSessionId::new(),
            now(),
            N4PresentedMetadata {
                platform: Some("linux".into()),
                hostname_hint: Some("n4-safe".into()),
                correlation: SanitizedMetadata::new(serde_json::json!({
                    "request_id": raw_token.clone(),
                }))
                .unwrap(),
            },
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
    let dispatch_debug = format!("{dispatch:?}{authorization:?}");
    store
        .confirm_n4_credential(
            reservation.join_session_id,
            N4CredentialConfirmation {
                credential_id: ProviderCredentialId::new(),
                provider_reference: ProviderCredentialReference::new("native-ref-secret-safe")
                    .unwrap(),
                provider_principal_id: dispatch.context.provider_principal_id,
                ephemeral: false,
                approved_tags: vec!["tag:nodescale-worker".into()],
                expires_at: now() + Duration::minutes(10),
                confirmed_at: now(),
                safe_correlation: SanitizedMetadata::new(serde_json::json!({
                    "request_id": provider_secret.clone(),
                }))
                .unwrap(),
            },
            AuditActor::system(),
        )
        .unwrap();

    let view_debug = format!(
        "{:?}",
        store.n4_invitation_view(invitation.invitation_id).unwrap()
    );
    let database_text_dump = store.database_text_dump_for_test().unwrap();
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);

    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    let reopened_view_debug = format!(
        "{:?}",
        reopened
            .n4_invitation_view(invitation.invitation_id)
            .unwrap()
    );
    drop(reopened);

    let raw_database_artifacts = read_database_and_existing_sidecars(&path);
    let mut surfaces = vec![
        database_text_dump.as_bytes(),
        candidate_debug.as_bytes(),
        dispatch_debug.as_bytes(),
        view_debug.as_bytes(),
        reopened_view_debug.as_bytes(),
    ];
    surfaces.extend(raw_database_artifacts.iter().map(Vec::as_slice));
    assert_absent_without_echoing(raw_token.as_bytes(), &surfaces);
    assert_absent_without_echoing(provider_secret.as_bytes(), &surfaces);
}
