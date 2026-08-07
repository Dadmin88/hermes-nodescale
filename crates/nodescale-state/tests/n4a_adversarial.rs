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
use rusqlite::{Connection, params};
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

async fn configured_file_store(path: &Path) -> (StateStore, Network) {
    let store = StateStore::open(path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n4-adversarial",
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
                "secret://synthetic-test-configuration",
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

fn n4_invitation(network_id: NetworkId) -> Invitation {
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

fn confirmation(principal: &str) -> N4CredentialConfirmation {
    let credential_id = ProviderCredentialId::new();
    N4CredentialConfirmation {
        provider_reference: ProviderCredentialReference::new(format!(
            "synthetic-provider-reference-{credential_id}"
        ))
        .unwrap(),
        credential_id,
        provider_principal_id: principal.into(),
        ephemeral: false,
        approved_tags: vec!["tag:nodescale-worker".into()],
        expires_at: now() + Duration::minutes(10),
        confirmed_at: now(),
        safe_correlation: SanitizedMetadata::empty(),
    }
}

fn reserve(
    store: &StateStore,
    invitation: &Invitation,
    network: &Network,
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

macro_rules! assert_update_rejected {
    ($connection:expr, $sql:expr, $params:expr) => {{
        assert!(
            $connection.execute($sql, $params).is_err(),
            "direct SQL mutation unexpectedly succeeded: {}",
            $sql
        );
    }};
}

#[tokio::test]
async fn n4_direct_sql_cannot_rewrite_immutable_linkage_or_bypass_dispatch_fence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n4-adversarial.db");
    let (store, network) = configured_file_store(&path).await;

    let invitation_a = n4_invitation(network.network_id);
    let session_a = reserve(&store, &invitation_a, &network, "principal-synthetic-a");
    let confirmation_a = confirmation("principal-synthetic-a");

    // The public confirmation API must reject a reserved, never-dispatched session.
    assert!(
        store
            .confirm_n4_credential(session_a, confirmation_a.clone(), AuditActor::system(),)
            .is_err()
    );
    store
        .begin_n4_credential_dispatch(session_a, now(), AuditActor::system())
        .unwrap();
    store
        .confirm_n4_credential(session_a, confirmation_a, AuditActor::system())
        .unwrap();

    // A distinct valid row makes splice attempts use durable-but-wrong identifiers.
    let invitation_b = n4_invitation(network.network_id);
    let session_b = reserve(&store, &invitation_b, &network, "principal-synthetic-b");
    let confirmation_b = confirmation("principal-synthetic-b");
    store
        .begin_n4_credential_dispatch(session_b, now(), AuditActor::system())
        .unwrap();
    store
        .confirm_n4_credential(session_b, confirmation_b, AuditActor::system())
        .unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let invitation_a_id = invitation_a.invitation_id.to_string();
    let invitation_b_id = invitation_b.invitation_id.to_string();
    let session_a_id = session_a.to_string();
    let session_b_id = session_b.to_string();
    let credential_a: String = connection
        .query_row(
            "SELECT credential_id FROM n4_join_session_dispatches WHERE join_session_id=?1",
            [&session_a_id],
            |row| row.get(0),
        )
        .unwrap();
    let credential_b: String = connection
        .query_row(
            "SELECT credential_id FROM n4_join_session_dispatches WHERE join_session_id=?1",
            [&session_b_id],
            |row| row.get(0),
        )
        .unwrap();
    let other_network = NetworkId::new().to_string();
    let other_provider = ProviderInstanceId::new().to_string();
    let rewritten_request_id = uuid::Uuid::new_v4().to_string();
    let rewritten_fingerprint =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    assert_update_rejected!(
        &connection,
        "UPDATE invitations SET max_uses=2 WHERE invitation_id=?1",
        params![invitation_a_id]
    );
    assert_update_rejected!(
        &connection,
        "UPDATE join_sessions SET invitation_id=?2 WHERE join_session_id=?1",
        params![session_a_id, invitation_b_id]
    );
    assert_update_rejected!(
        &connection,
        "UPDATE n4_invitation_details SET last_redemption_metadata_json=?2 WHERE invitation_id=?1",
        params![invitation_a_id, "{\"request_id\":\"benign-looking-value\"}"]
    );

    for (sql, value) in [
        (
            "UPDATE n4_invitation_details SET network_id=?2 WHERE invitation_id=?1",
            other_network.as_str(),
        ),
        (
            "UPDATE n4_invitation_details SET provider_instance_id=?2 WHERE invitation_id=?1",
            other_provider.as_str(),
        ),
        (
            "UPDATE n4_invitation_details SET provider_principal_id=?2 WHERE invitation_id=?1",
            "principal-synthetic-rewrite",
        ),
        (
            "UPDATE n4_invitation_details SET roles_json=?2 WHERE invitation_id=?1",
            "[\"admin\"]",
        ),
        (
            "UPDATE n4_invitation_details SET constraints_json=?2 WHERE invitation_id=?1",
            "{}",
        ),
        (
            "UPDATE n4_invitation_details SET created_by_source=?2 WHERE invitation_id=?1",
            "synthetic-rewriter",
        ),
        (
            "UPDATE n4_invitation_details SET created_by_id=?2 WHERE invitation_id=?1",
            "synthetic-actor-rewrite",
        ),
    ] {
        assert_update_rejected!(&connection, sql, params![invitation_a_id, value]);
    }

    for (sql, value) in [
        (
            "UPDATE n4_join_session_dispatches SET join_session_id=?2 WHERE join_session_id=?1",
            session_b_id.as_str(),
        ),
        (
            "UPDATE n4_join_session_dispatches SET invitation_id=?2 WHERE join_session_id=?1",
            invitation_b_id.as_str(),
        ),
        (
            "UPDATE n4_join_session_dispatches SET network_id=?2 WHERE join_session_id=?1",
            other_network.as_str(),
        ),
        (
            "UPDATE n4_join_session_dispatches SET provider_instance_id=?2 WHERE join_session_id=?1",
            other_provider.as_str(),
        ),
        (
            "UPDATE n4_join_session_dispatches SET provider_principal_id=?2 WHERE join_session_id=?1",
            "principal-synthetic-rewrite",
        ),
        (
            "UPDATE n4_join_session_dispatches SET create_request_id=?2 WHERE join_session_id=?1",
            rewritten_request_id.as_str(),
        ),
        (
            "UPDATE n4_join_session_dispatches SET authorization_generation=2 WHERE join_session_id=?1",
            "",
        ),
        (
            "UPDATE n4_join_session_dispatches SET configuration_generation=2 WHERE join_session_id=?1",
            "",
        ),
        (
            "UPDATE n4_join_session_dispatches SET configuration_fingerprint=?2 WHERE join_session_id=?1",
            rewritten_fingerprint,
        ),
        (
            "UPDATE n4_join_session_dispatches SET dispatched_at_ms=1 WHERE join_session_id=?1",
            "",
        ),
        (
            "UPDATE n4_join_session_dispatches SET credential_id=?2 WHERE join_session_id=?1",
            credential_b.as_str(),
        ),
    ] {
        if value.is_empty() {
            assert_update_rejected!(&connection, sql, params![session_a_id]);
        } else {
            assert_update_rejected!(&connection, sql, params![session_a_id, value]);
        }
    }
    assert_update_rejected!(
        &connection,
        "UPDATE n4_join_session_dispatches SET dispatch_state='dispatch_started' WHERE join_session_id=?1",
        params![session_a_id]
    );

    for (sql, value) in [
        (
            "UPDATE n4_provider_credential_metadata SET credential_id=?2 WHERE credential_id=?1",
            credential_b.as_str(),
        ),
        (
            "UPDATE n4_provider_credential_metadata SET join_session_id=?2 WHERE credential_id=?1",
            session_b_id.as_str(),
        ),
        (
            "UPDATE n4_provider_credential_metadata SET network_id=?2 WHERE credential_id=?1",
            other_network.as_str(),
        ),
        (
            "UPDATE n4_provider_credential_metadata SET provider_instance_id=?2 WHERE credential_id=?1",
            other_provider.as_str(),
        ),
        (
            "UPDATE n4_provider_credential_metadata SET provider_principal_id=?2 WHERE credential_id=?1",
            "principal-synthetic-rewrite",
        ),
        (
            "UPDATE n4_provider_credential_metadata SET approved_tags_json=?2 WHERE credential_id=?1",
            "[\"tag:synthetic-rewrite\"]",
        ),
        (
            "UPDATE n4_provider_credential_metadata SET expires_at_ms=1 WHERE credential_id=?1",
            "",
        ),
        (
            "UPDATE n4_provider_credential_metadata SET confirmed_at_ms=0 WHERE credential_id=?1",
            "",
        ),
        (
            "UPDATE n4_provider_credential_metadata SET safe_correlation_json=?2 WHERE credential_id=?1",
            "{\"synthetic\":true}",
        ),
    ] {
        if value.is_empty() {
            assert_update_rejected!(&connection, sql, params![credential_a]);
        } else {
            assert_update_rejected!(&connection, sql, params![credential_a, value]);
        }
    }
    for sql in [
        "UPDATE n4_provider_credential_metadata SET single_use=0 WHERE credential_id=?1",
        "UPDATE n4_provider_credential_metadata SET reusable=1 WHERE credential_id=?1",
        "UPDATE n4_provider_credential_metadata SET ephemeral=1 WHERE credential_id=?1",
    ] {
        assert_update_rejected!(&connection, sql, params![credential_a]);
    }

    connection
        .execute(
            "UPDATE n4_provider_credential_metadata SET invalidation_state='pending' WHERE credential_id=?1",
            params![credential_a],
        )
        .unwrap();
    assert_update_rejected!(
        &connection,
        "UPDATE n4_provider_credential_metadata SET invalidation_state='confirmed' WHERE credential_id=?1",
        params![credential_a]
    );
    connection
        .execute(
            "UPDATE n4_provider_credential_metadata SET invalidation_state='confirmed',invalidated_at_ms=1 WHERE credential_id=?1",
            params![credential_a],
        )
        .unwrap();
    assert_update_rejected!(
        &connection,
        "UPDATE n4_provider_credential_metadata SET invalidated_at_ms=NULL WHERE credential_id=?1",
        params![credential_a]
    );

    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let foreign_key_rows: u64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(foreign_key_rows, 0);
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
}
