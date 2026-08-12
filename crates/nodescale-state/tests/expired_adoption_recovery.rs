use std::{collections::BTreeSet, path::PathBuf};

use chrono::{DateTime, Duration, TimeZone, Utc};
use nodescale_domain::{
    AuditActor, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation, Network,
    OwnerTrustRootToken, ProviderIdentity, ProviderInstanceId, ProviderKind, ProviderNodeId,
    TrustAuthorityId,
};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence, MutableIdentityEvidence,
    ProviderCapability, ProviderError, ProviderHealth, ProviderHealthStatus,
    ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    Failpoint, N5TrustAuthorityConfiguration, StateStore, TailscaleImportConfig,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0).unwrap()
}

struct ProviderFixture {
    instance: ProviderInstanceId,
    node: ProviderNode,
}

#[async_trait::async_trait]
impl ReadOnlyProvider for ProviderFixture {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "tailscale".into(),
            provider_version: "api-v2".into(),
            instance_id: self.instance,
            compatibility: CompatibilityStatus::CompatibleWithConstraints,
            capabilities: [
                ProviderCapability::InspectServer,
                ProviderCapability::ListNodes,
                ProviderCapability::GetNode,
                ProviderCapability::Health,
            ]
            .into_iter()
            .collect(),
            constraints: vec!["read-only fixture".into()],
            mutation_allowed: false,
        })
    }

    async fn verify_compatibility(&self) -> Result<CompatibilityReport, ProviderError> {
        Ok(CompatibilityReport::from_inspection(
            &self.inspect_server().await?,
        ))
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        Ok(vec![self.node.clone()])
    }

    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Ok((self.node.identity == *identity).then(|| self.node.clone()))
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        Ok(ProviderHealth {
            status: ProviderHealthStatus::Healthy,
            reachable: true,
            authenticated: true,
            detail: "fixture".into(),
        })
    }
}

fn provider(instance: ProviderInstanceId) -> ProviderFixture {
    let identity = ProviderIdentity::new(
        instance,
        ProviderNodeId::parse("n292kg92CNTRL").unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    ProviderFixture {
        instance,
        node: ProviderNode {
            identity,
            identity_evidence: ProviderIdentityEvidence {
                machine_key: Some(
                    ConditionalIdentityEvidence::new("mkey:recovery-machine").unwrap(),
                ),
                node_key: Some(MutableIdentityEvidence::new("nodekey:recovery-current").unwrap()),
                disco_key: None,
            },
            hostname: "recovery-target".into(),
            given_name: "recovery-target.example.ts.net".into(),
            addresses: vec!["192.0.2.44".into()],
            user: None,
            pre_auth: None,
            tags: BTreeSet::new(),
            registered_at: Some(now()),
            last_seen: Some(now()),
            expires_at: None,
            observed_at: now(),
            online: Some(true),
            expired: false,
        },
    }
}

struct Context {
    _directory: TempDir,
    path: PathBuf,
    store: StateStore,
    root: OwnerTrustRootToken,
    authority_id: TrustAuthorityId,
    network: Network,
    action_id: String,
}

async fn context() -> Context {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let instance = ProviderInstanceId::new();
    let provider = provider(instance);
    let network = Network::new(
        nodescale_domain::NetworkId::new(),
        "V10.1 recovery",
        ProviderKind::Tailscale,
        instance,
        now(),
    )
    .unwrap();
    let store = StateStore::open(&path).unwrap();
    store
        .import_tailscale_network(
            &network,
            &TailscaleImportConfig::new("example.com", instance, "secret://systemd/provider-token")
                .unwrap(),
            &provider,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let root = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "v10.1-test",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "local-owner",
                "v10.1-test",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::AdoptExistingProviderDevice],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    let action = store
        .issue_existing_provider_adoption(
            &root,
            authority_id,
            network.network_id,
            "n292kg92CNTRL",
            "v101-first-issue",
            now(),
        )
        .unwrap();
    Context {
        _directory: directory,
        path,
        store,
        root,
        authority_id,
        network,
        action_id: action.action_id,
    }
}

fn scalar(connection: &Connection, query: &str) -> i64 {
    connection.query_row(query, [], |row| row.get(0)).unwrap()
}

#[tokio::test]
async fn expiry_before_deadline_rejects_without_mutation() {
    let context = context().await;
    let before = std::fs::read(&context.path).unwrap();
    assert!(
        context
            .store
            .expire_existing_provider_adoption(
                &context.root,
                &context.action_id,
                now() + Duration::minutes(5) - Duration::milliseconds(1),
            )
            .is_err()
    );
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT action_state FROM n5_adoption_actions WHERE action_id=?1",
                [&context.action_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "proof_pending"
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        0
    );
    assert_eq!(std::fs::read(&context.path).unwrap(), before);
}

#[tokio::test]
async fn exact_expiry_terminalizes_once_rearms_and_allows_one_fresh_issue() {
    let context = context().await;
    let expired = context
        .store
        .expire_existing_provider_adoption(
            &context.root,
            &context.action_id,
            now() + Duration::minutes(5),
        )
        .unwrap();
    assert_eq!(expired.action_id, context.action_id);
    assert_eq!(expired.action_state, "expired");
    assert_eq!(expired.provider_node_id, "n292kg92CNTRL");
    assert_eq!(expired.observation_adoption_state, "unmanaged");

    let connection = Connection::open(&context.path).unwrap();
    let action: (String, String) = connection
        .query_row(
            "SELECT action_state,terminal_reason FROM n5_adoption_actions WHERE action_id=?1",
            [&context.action_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(action, ("expired".into(), "action_expired".into()));
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM audit_events WHERE event_kind='device.adoption_action_expired'",
        ),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT adoption_state FROM provider_observations",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "unmanaged"
    );
    for table in [
        "devices",
        "n5_device_identities",
        "n5_provider_bindings",
        "n5_device_trust_state",
        "n6_binding_records",
        "n7_fleet_projection_records",
    ] {
        assert_eq!(
            scalar(&connection, &format!("SELECT COUNT(*) FROM {table}")),
            0,
            "{table} gained authority"
        );
    }
    drop(connection);

    assert!(
        context
            .store
            .expire_existing_provider_adoption(
                &context.root,
                &context.action_id,
                now() + Duration::minutes(6),
            )
            .is_err()
    );
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM audit_events WHERE event_kind='device.adoption_action_expired'",
        ),
        1
    );
    drop(connection);

    let fresh = context
        .store
        .issue_existing_provider_adoption(
            &context.root,
            context.authority_id,
            context.network.network_id,
            "n292kg92CNTRL",
            "v101-second-issue",
            now() + Duration::minutes(6),
        )
        .unwrap();
    assert_ne!(fresh.action_id, context.action_id);
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM n5_adoption_actions WHERE action_state='proof_pending'",
        ),
        1
    );
}

#[tokio::test]
async fn semantic_change_cannot_be_reset_by_expiry() {
    let context = context().await;
    let connection = Connection::open(&context.path).unwrap();
    connection
        .execute(
            "UPDATE provider_observations SET semantic_generation=semantic_generation+1,semantic_fingerprint=?1",
            ["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        )
        .unwrap();
    drop(connection);
    assert!(
        context
            .store
            .expire_existing_provider_adoption(
                &context.root,
                &context.action_id,
                now() + Duration::minutes(5),
            )
            .is_err()
    );
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT adoption_state FROM provider_observations",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "pending_device_credential_proof"
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        0
    );
}

#[tokio::test]
async fn observation_with_device_id_cannot_be_reset_by_expiry() {
    let context = context().await;
    let connection = Connection::open(&context.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "UPDATE provider_observations SET device_id=?1",
            [uuid::Uuid::new_v4().to_string()],
        )
        .unwrap();
    drop(connection);
    assert!(
        context
            .store
            .expire_existing_provider_adoption(
                &context.root,
                &context.action_id,
                now() + Duration::minutes(5),
            )
            .is_err()
    );
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT adoption_state FROM provider_observations",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "pending_device_credential_proof"
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        0
    );
}

#[tokio::test]
async fn pending_proof_operation_blocks_expiry() {
    let context = context().await;
    let connection = Connection::open(&context.path).unwrap();
    connection
        .execute(
            "INSERT INTO n5_adoption_proof_operations (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms) VALUES (?1,'v101-pending-proof',?2,'pending',NULL,NULL,NULL,NULL,?3,NULL)",
            params![
                context.action_id,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                (now() + Duration::minutes(1)).timestamp_millis(),
            ],
        )
        .unwrap();
    drop(connection);
    assert!(
        context
            .store
            .expire_existing_provider_adoption(
                &context.root,
                &context.action_id,
                now() + Duration::minutes(5),
            )
            .is_err()
    );
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT action_state FROM n5_adoption_actions WHERE action_id=?1",
                [&context.action_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "proof_pending"
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        0
    );
}

#[tokio::test]
async fn injected_failure_rolls_back_terminalization_and_observation_rearm() {
    let context = context().await;
    context
        .store
        .set_failpoint(Failpoint::BeforeAdoptionExpiryCommit, true);
    assert!(matches!(
        context.store.expire_existing_provider_adoption(
            &context.root,
            &context.action_id,
            now() + Duration::minutes(5),
        ),
        Err(nodescale_state::StateError::InjectedFailure)
    ));
    let connection = Connection::open(&context.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT action_state FROM n5_adoption_actions WHERE action_id=?1",
                [&context.action_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "proof_pending"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT adoption_state FROM provider_observations",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "pending_device_credential_proof"
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM n5_adoption_decisions"),
        0
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM audit_events WHERE event_kind='device.adoption_action_expired'",
        ),
        0
    );
}
