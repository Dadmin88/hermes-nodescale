use chrono::{DateTime, Utc};
use nodescale_domain::{AuditActor, Network, NetworkId, ProviderInstanceId, ProviderKind};
use nodescale_provider::{
    CompatibilityStatus, ConditionalIdentityEvidence, MutableIdentityEvidence, ProviderError,
    ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider, ServerInspection,
};
use nodescale_provider_fake::{FakeFailure, FakeProvider};
use nodescale_state::{
    AdoptionState, Failpoint, HeadscaleImportConfig, ObservationClassification,
    ProviderReconciliationState, ReconciliationFailure, StateStore, TlsVerificationPolicy,
};
use std::{
    collections::BTreeSet,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::Command,
    sync::{Arc, Barrier, Mutex},
};

struct ScriptProvider {
    instance: ProviderInstanceId,
    nodes: Mutex<Vec<ProviderNode>>,
    inspect: Mutex<InspectMode>,
}

#[derive(Clone, Copy)]
enum InspectMode {
    Compatible,
    AuthenticationFailed,
    Unsupported,
    Unreachable,
}

#[async_trait::async_trait]
impl ReadOnlyProvider for ScriptProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        match *self.inspect.lock().unwrap() {
            InspectMode::AuthenticationFailed => return Err(ProviderError::AuthenticationFailed),
            InspectMode::Unreachable => {
                return Err(ProviderError::Unreachable("test outage".into()));
            }
            _ => {}
        }
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.instance,
            compatibility: if matches!(*self.inspect.lock().unwrap(), InspectMode::Unsupported) {
                CompatibilityStatus::Unsupported
            } else {
                CompatibilityStatus::Compatible
            },
            capabilities: BTreeSet::new(),
            constraints: vec![],
            mutation_allowed: false,
        })
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        Ok(self.nodes.lock().unwrap().clone())
    }

    async fn get_node(
        &self,
        _identity: &nodescale_domain::ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Ok(None)
    }

    async fn provider_health(&self) -> Result<nodescale_provider::ProviderHealth, ProviderError> {
        unreachable!()
    }
}

fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().unwrap()
}

fn provider(instance: ProviderInstanceId) -> ScriptProvider {
    ScriptProvider {
        instance,
        nodes: Mutex::new(vec![node(instance, "42", "machine-one", "worker-a")]),
        inspect: Mutex::new(InspectMode::Compatible),
    }
}

fn node(instance: ProviderInstanceId, id: &str, machine: &str, hostname: &str) -> ProviderNode {
    ProviderNode {
        identity: nodescale_domain::ProviderIdentity::new(
            instance,
            nodescale_domain::ProviderNodeId::parse(id).unwrap(),
            format!("sha256:{machine}"),
        )
        .unwrap(),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(ConditionalIdentityEvidence::new(machine).unwrap()),
            node_key: Some(MutableIdentityEvidence::new("node-key").unwrap()),
            disco_key: Some(MutableIdentityEvidence::new("disco-key").unwrap()),
        },
        hostname: hostname.into(),
        given_name: hostname.into(),
        addresses: vec!["192.0.2.10".into()],
        user: None,
        pre_auth: None,
        tags: BTreeSet::new(),
        registered_at: Some(now()),
        last_seen: Some(now()),
        expires_at: None,
        observed_at: now(),
        online: Some(true),
        expired: false,
    }
}

fn config(instance: ProviderInstanceId) -> HeadscaleImportConfig {
    HeadscaleImportConfig::new(
        "https://headscale.example.test",
        instance,
        "secret://vault/nodescale#key",
        "v0.29.3",
        TlsVerificationPolicy::Verify,
    )
    .unwrap()
}

#[tokio::test]
async fn import_rejects_deserialized_plaintext_secret_before_persistence() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "plaintext-secret-import",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let bypassed_config: HeadscaleImportConfig = serde_json::from_value(serde_json::json!({
        "server_url": "https://headscale.example.test",
        "provider_instance_id": instance,
        "opaque_secret_reference": "actual-plaintext-api-key",
        "compatibility_pin": "v0.29.3",
        "tls_verification": "verify",
        "read_only": true,
        "mutation_allowed": false
    }))
    .unwrap();

    let result = store
        .import_headscale_network(
            &network,
            &bypassed_config,
            &provider(instance),
            now(),
            AuditActor::system(),
        )
        .await;

    assert!(matches!(
        result,
        Err(ReconciliationFailure::State(
            nodescale_state::StateError::Conflict(message)
        )) if message == "credential must be an opaque secret:// reference, not plaintext"
    ));
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains("actual-plaintext-api-key")
    );
}

#[tokio::test]
async fn imported_headscale_fixture_reconciles_new_nodes_as_unmanaged_without_devices() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "headscale-import",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);

    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let report = store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();

    assert_eq!(report.observed_count, 1);
    assert_eq!(report.discovered_unmanaged_count, 1);
    assert!(!report.provider_mutation_enabled);
    let observations = store.provider_observations(network.network_id).unwrap();
    assert_eq!(
        observations[0].classification,
        ObservationClassification::DiscoveredUnmanaged
    );
    assert_eq!(observations[0].semantic_generation, 1);
    assert!(observations[0].device_id.is_none());
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains("actual-plaintext-api-key")
    );
}

#[tokio::test]
async fn failures_are_typed_and_preserve_inventory() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "failure-kinds",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    let generation_before_failures =
        store.provider_observations(network.network_id).unwrap()[0].semantic_generation;
    *source.inspect.lock().unwrap() = InspectMode::AuthenticationFailed;
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::AuthenticationFailed)
    ));
    *source.inspect.lock().unwrap() = InspectMode::Unsupported;
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::Incompatible)
    ));
    *source.inspect.lock().unwrap() = InspectMode::Unreachable;
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::Unreachable)
    ));
    assert_eq!(
        store
            .provider_observations(network.network_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.provider_observations(network.network_id).unwrap()[0].semantic_generation,
        generation_before_failures
    );
}

#[tokio::test]
async fn reconciliation_is_idempotent_and_tracks_metadata_missing_expiry_and_identity_conflict() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "semantic-reconcile",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    let audit_after_first = store.audit_event_count().unwrap();
    let generation = store.network_generation(network.network_id).unwrap();
    store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(store.audit_event_count().unwrap(), audit_after_first);
    assert_eq!(
        store.network_generation(network.network_id).unwrap(),
        generation
    );
    assert_eq!(
        store.provider_observations(network.network_id).unwrap()[0].semantic_generation,
        1
    );

    source.nodes.lock().unwrap()[0].hostname = "renamed-worker".into();
    store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(
        store.provider_observations(network.network_id).unwrap()[0]
            .node
            .hostname,
        "renamed-worker"
    );
    assert_eq!(
        store.provider_observations(network.network_id).unwrap()[0].semantic_generation,
        2
    );
    *source.nodes.lock().unwrap() = vec![];
    let missing = store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(missing.provider_missing_count, 1);
    let mut expired = node(instance, "42", "machine-one", "renamed-worker");
    expired.expired = true;
    *source.nodes.lock().unwrap() = vec![expired];
    let expired_report = store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(expired_report.provider_expired_count, 1);
    let before_conflict = store.provider_observations(network.network_id).unwrap()[0]
        .stable_machine_key_fingerprint
        .clone();
    *source.nodes.lock().unwrap() = vec![node(instance, "42", "machine-two", "renamed-worker")];
    let conflict = store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(conflict.identity_conflict_count, 1);
    let preserved = store.provider_observations(network.network_id).unwrap()[0].clone();
    assert_eq!(preserved.stable_machine_key_fingerprint, before_conflict);
    assert_eq!(
        preserved.classification,
        ObservationClassification::IdentityConflict
    );
}

#[tokio::test]
async fn duplicate_snapshot_and_failpoint_fail_closed_without_partial_inventory() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "atomic-reconcile",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    *source.nodes.lock().unwrap() = vec![
        node(instance, "42", "machine-one", "one"),
        node(instance, "42", "machine-one", "two"),
    ];
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::IdentityConflict)
    ));
    assert_eq!(
        store
            .provider_observations(network.network_id)
            .unwrap()
            .len(),
        1
    );
    *source.nodes.lock().unwrap() = vec![
        node(instance, "42", "machine-one", "one"),
        node(instance, "43", "machine-three", "three"),
    ];
    store.set_failpoint(Failpoint::BeforeAuditInsert, true);
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::State(_))
    ));
    assert_eq!(
        store
            .provider_observations(network.network_id)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn invalid_network_name_and_plaintext_provider_secret_are_rejected() {
    let instance = ProviderInstanceId::new();
    assert!(
        Network::new(
            NetworkId::new(),
            "   ",
            ProviderKind::Headscale,
            instance,
            now()
        )
        .is_err()
    );
    assert!(
        HeadscaleImportConfig::new(
            "https://headscale.example.test",
            instance,
            "actual-plaintext-api-key",
            "v0.29.3",
            TlsVerificationPolicy::Verify,
        )
        .is_err()
    );
}

#[tokio::test]
async fn import_is_atomic_initial_discovery_and_duplicate_instance_is_rejected() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let first = Network::new(
        NetworkId::new(),
        "first-import",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let second = Network::new(
        NetworkId::new(),
        "second-import",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    store
        .import_headscale_network(
            &first,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        store.provider_observations(first.network_id).unwrap().len(),
        1
    );
    assert_eq!(
        store
            .reconciliation_report(first.network_id)
            .unwrap()
            .provider_state,
        ProviderReconciliationState::Healthy
    );
    assert!(matches!(
        store
            .import_headscale_network(
                &second,
                &config(instance),
                &source,
                now(),
                AuditActor::system()
            )
            .await,
        Err(ReconciliationFailure::State(_))
    ));
    assert!(matches!(
        store.network(second.network_id),
        Err(nodescale_state::StateError::NotFound(_))
    ));
}

#[tokio::test]
async fn hostname_and_address_collisions_never_merge_canonical_nodes() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "collision-proof",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    let mut second = node(instance, "7", "machine-seven", "worker-a");
    second.addresses = vec!["192.0.2.10".into()];
    *source.nodes.lock().unwrap() = vec![node(instance, "42", "machine-one", "worker-a"), second];
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let observations = store.provider_observations(network.network_id).unwrap();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].canonical_provider_node_id, "42");
    assert_eq!(observations[1].canonical_provider_node_id, "7");
    assert!(observations.iter().all(|observation| {
        observation.classification == ObservationClassification::DiscoveredUnmanaged
            && observation.adoption_state == AdoptionState::Unmanaged
            && observation.device_id.is_none()
    }));
}

#[tokio::test]
async fn outage_doctor_state_preserves_inventory_and_recovery_clears_warning() {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "outage-recovery",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    *source.inspect.lock().unwrap() = InspectMode::Unreachable;
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::Unreachable)
    ));
    let outage = store.reconciliation_report(network.network_id).unwrap();
    assert_eq!(
        outage.provider_state,
        ProviderReconciliationState::Unreachable
    );
    assert_eq!(outage.observed_count, 1);
    assert_eq!(outage.provider_missing_count, 0);
    assert!(!outage.warnings.is_empty());
    *source.inspect.lock().unwrap() = InspectMode::Compatible;
    let recovered = store
        .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(
        recovered.provider_state,
        ProviderReconciliationState::Healthy
    );
    assert!(recovered.warnings.is_empty());
}

#[tokio::test]
async fn deterministic_fake_drives_required_reconciliation_scenarios() {
    let store = StateStore::open_in_memory().unwrap();
    let mut source = FakeProvider::headscale_fixture("n2a-scenarios");
    let instance = ReadOnlyProvider::instance_id(&source);
    source.seed_read_only_snapshot(vec![]);
    let network = Network::new(
        NetworkId::new(),
        "fake-scenarios",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .reconciliation_report(network.network_id)
            .unwrap()
            .observed_count,
        0
    );

    let first = node(instance, "1", "machine-one", "same-name");
    let mut second = node(instance, "2", "machine-two", "same-name");
    second.addresses = first.addresses.clone();
    source.seed_read_only_snapshot(vec![second.clone(), first.clone()]);
    assert_eq!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await
            .unwrap()
            .discovered_unmanaged_count,
        2
    );

    let mut changed = first.clone();
    changed.hostname = "renamed".into();
    source.seed_read_only_snapshot(vec![changed.clone()]);
    assert_eq!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await
            .unwrap()
            .provider_missing_count,
        1
    );

    changed.expired = true;
    source.seed_read_only_snapshot(vec![changed.clone()]);
    assert_eq!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await
            .unwrap()
            .provider_expired_count,
        1
    );

    source.seed_read_only_snapshot(vec![changed.clone(), changed.clone()]);
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::IdentityConflict)
    ));

    let mut conflicting = changed;
    conflicting.identity_evidence.machine_key =
        Some(ConditionalIdentityEvidence::new("machine-other").unwrap());
    source.seed_read_only_snapshot(vec![conflicting]);
    assert_eq!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await
            .unwrap()
            .identity_conflict_count,
        1
    );

    source.fail_next(FakeFailure::Unavailable);
    assert!(matches!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await,
        Err(ReconciliationFailure::Unreachable)
    ));
    assert_eq!(
        store
            .provider_observations(network.network_id)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn discovery_and_adoption_staging_are_not_activation_or_fleet_authority() {
    let staged = AdoptionState::PendingDeviceCredentialProof;
    assert_ne!(staged, AdoptionState::Unmanaged);
    let store = StateStore::open_in_memory().unwrap();
    let network_id = NetworkId::new();
    assert_eq!(store.fleet_projection_count(network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network_id).unwrap(), 0);
    assert_eq!(store.device_count(network_id).unwrap(), 0);
}

#[tokio::test]
async fn incompatible_or_unauthenticated_provider_cannot_leave_partial_import() {
    for (mode, expected) in [
        (
            InspectMode::Unsupported,
            ReconciliationFailure::Incompatible,
        ),
        (
            InspectMode::AuthenticationFailed,
            ReconciliationFailure::AuthenticationFailed,
        ),
    ] {
        let store = StateStore::open_in_memory().unwrap();
        let instance = ProviderInstanceId::new();
        let network = Network::new(
            NetworkId::new(),
            "rejected-import",
            ProviderKind::Headscale,
            instance,
            now(),
        )
        .unwrap();
        let source = provider(instance);
        *source.inspect.lock().unwrap() = mode;
        let result = store
            .import_headscale_network(
                &network,
                &config(instance),
                &source,
                now(),
                AuditActor::system(),
            )
            .await;
        assert_eq!(
            std::mem::discriminant(&result.unwrap_err()),
            std::mem::discriminant(&expected),
        );
        assert!(matches!(
            store.network(network.network_id),
            Err(nodescale_state::StateError::NotFound(_))
        ));
        assert_eq!(store.audit_event_count().unwrap(), 0);
    }
}

fn abort_during_pending_adoption_terminalization(path: &Path) -> ! {
    let mut connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let action: (String, String, u64, String, String, String, u64, u64) = transaction
        .query_row(
            "SELECT action_id,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,expected_observation_generation,proof_generation
             FROM n5_adoption_actions WHERE action_state='proof_pending'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .unwrap();
    let decision_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let audit_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let observation_generation = action.6 + 1;
    transaction
        .execute(
            "UPDATE provider_observations
             SET semantic_generation=?2
             WHERE observation_id=(SELECT observation_id FROM n5_adoption_actions WHERE action_id=?1)
               AND semantic_generation=?3
               AND adoption_state='pending_device_credential_proof'",
            rusqlite::params![action.0, observation_generation, action.6],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO audit_events
             (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES (?1,'1970-01-01T00:00:00Z',?2,NULL,'system','crash-fixture','device.adoption_action_conflicted','success',?3,'{}')",
            rusqlite::params![audit_id, action.3, observation_generation],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO n5_adoption_decisions
             (decision_id,action_id,proof_operation_id,audit_event_id,decision_kind,prior_action_state,new_action_state,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,observation_generation,proof_generation,evidence_id,device_id,provider_binding_id,safe_correlation_digest,reason_code,decided_at_ms)
             VALUES (?1,?2,NULL,?3,'conflict','proof_pending','conflicted',?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL,?11,'observation_changed',1)",
            rusqlite::params![
                decision_id,
                action.0,
                audit_id,
                action.1,
                action.2,
                action.3,
                action.4,
                action.5,
                observation_generation,
                action.7,
                format!("sha256:{}", "f".repeat(64)),
            ],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE provider_observations
             SET adoption_state='unmanaged',semantic_generation=?2
             WHERE network_id=?1",
            rusqlite::params![action.3, observation_generation],
        )
        .unwrap();
    let pid = std::process::id().to_string();
    let _ = Command::new("/bin/kill").args(["-KILL", &pid]).status();
    loop {
        std::thread::park();
    }
}

#[tokio::test]
async fn semantic_reconciliation_atomically_conflicts_inert_pending_adoption() {
    if let Some(path) = std::env::var_os("NODESCALE_V8_CRASH_DB") {
        abort_during_pending_adoption_terminalization(Path::new(&path));
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pending-adoption-conflict.db");
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "pending-adoption-conflict",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let source = provider(instance);
    *source.nodes.lock().unwrap() = vec![node(instance, "42", &"a".repeat(64), "worker-a")];
    let store = StateStore::open(&path).unwrap();
    store
        .import_headscale_network(
            &network,
            &config(instance),
            &source,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let (observation_id, semantic_fingerprint, semantic_generation, provider_node_id):
        (String, String, u64, String) = connection
        .query_row(
            "SELECT observation_id,semantic_fingerprint,semantic_generation,provider_node_id FROM provider_observations WHERE network_id=?1",
            [network.network_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let digest_a = format!("sha256:{}", "a".repeat(64));
    let digest_b = format!("sha256:{}", "b".repeat(64));
    let digest_c = format!("sha256:{}", "c".repeat(64));
    let root_id = "22222222-2222-4222-8222-222222222222";
    let authority_id = "33333333-3333-4333-8333-333333333333";
    let operation_id = "adoption-authorize-1";
    let action_id = "55555555-5555-4555-8555-555555555555";
    connection
        .execute(
            "INSERT INTO n5_owner_trust_roots (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms)
             VALUES (?1,?2,'operator','owner-v8','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,NULL,0)",
            rusqlite::params![root_id, network.network_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
             VALUES (?1,?2,?3,'operator','owner-v8',1,0,9999999999999,0,0,NULL,0)",
            rusqlite::params![authority_id, root_id, network.network_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n5_trust_authority_capabilities (authority_id,capability) VALUES (?1,'AdoptExistingProviderDevice')",
            [authority_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n5_trust_authorities SET sealed=1,enabled=1 WHERE authority_id=?1",
            [authority_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n5_adoption_authorization_operations
             (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
             VALUES (?1,?2,1,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'pending',NULL,NULL,NULL,0,NULL)",
            rusqlite::params![operation_id, authority_id, network.network_id.to_string(), observation_id, instance.to_string(), provider_node_id, semantic_generation, digest_a, semantic_fingerprint, digest_b, digest_c, "d".repeat(64)],
        )
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    connection
        .execute(
            "UPDATE n5_adoption_authorization_operations
             SET operation_state='settled',outcome='issued',action_id=?2,receipt_id='66666666-6666-4666-8666-666666666666',settled_at_ms=0
             WHERE operation_id=?1",
            rusqlite::params![operation_id, action_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n5_adoption_actions
             (action_id,authorization_operation_id,authority_id,authority_generation,network_id,observation_id,provider_kind,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,proof_method,proof_generation,challenge_id,challenge_verifier,principal_source,principal_id,issued_at_ms,not_before_ms,expires_at_ms,action_state,terminal_decision_id,terminal_at_ms,terminal_reason)
             VALUES (?1,?2,?3,1,?4,?5,'headscale',?6,?7,?8,?9,?10,?11,?12,'tailscale_whois_provider_v1',1,'77777777-7777-4777-8777-777777777777','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','operator','owner-v8',0,0,9999999999999,'proof_pending',NULL,NULL,NULL)",
            rusqlite::params![action_id, operation_id, authority_id, network.network_id.to_string(), observation_id, instance.to_string(), provider_node_id, semantic_generation, digest_a, semantic_fingerprint, digest_b, digest_c],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    connection
        .execute(
            "INSERT INTO n5_adoption_proof_operations
             (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms)
             VALUES (?1,'adoption-proof-1',?2,'pending',NULL,NULL,NULL,NULL,0,NULL)",
            rusqlite::params![action_id, "e".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_observations SET adoption_state='pending_device_credential_proof' WHERE observation_id=?1",
            [&observation_id],
        )
        .unwrap();
    drop(connection);

    let crash_status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("semantic_reconciliation_atomically_conflicts_inert_pending_adoption")
        .arg("--nocapture")
        .env("NODESCALE_V8_CRASH_DB", &path)
        .status()
        .unwrap();
    assert_eq!(
        crash_status.signal(),
        Some(9),
        "crash child did not reach the post-settlement SIGKILL boundary"
    );

    let crash_reopened = rusqlite::Connection::open(&path).unwrap();
    let crash_action_state: String = crash_reopened
        .query_row(
            "SELECT action_state FROM n5_adoption_actions WHERE action_id=?1",
            [action_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(crash_action_state, "proof_pending");
    let crash_decision_count: u64 = crash_reopened
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_decisions WHERE action_id=?1",
            [action_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(crash_decision_count, 0);
    let crash_integrity: String = crash_reopened
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(crash_integrity, "ok");
    drop(crash_reopened);

    source.nodes.lock().unwrap()[0].hostname = "changed-during-proof".into();
    let store = StateStore::open(&path).unwrap();
    store.set_failpoint(Failpoint::BeforeAuditInsert, true);
    assert!(
        store
            .reconcile_read_only(network.network_id, &source, now(), AuditActor::system())
            .await
            .is_err()
    );
    drop(store);

    let rolled_back = rusqlite::Connection::open(&path).unwrap();
    let observation_after_failure: (u64, String) = rolled_back
        .query_row(
            "SELECT semantic_generation,adoption_state FROM provider_observations WHERE observation_id=?1",
            [&observation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(observation_after_failure.0, semantic_generation);
    assert_eq!(
        observation_after_failure.1,
        "pending_device_credential_proof"
    );
    let action_after_failure: (String, Option<String>) = rolled_back
        .query_row(
            "SELECT action_state,terminal_decision_id FROM n5_adoption_actions WHERE action_id=?1",
            [action_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(action_after_failure.0, "proof_pending");
    assert!(action_after_failure.1.is_none());
    let proof_after_failure: (String, Option<String>) = rolled_back
        .query_row(
            "SELECT operation_state,receipt_id FROM n5_adoption_proof_operations WHERE action_id=?1",
            [action_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(proof_after_failure.0, "pending");
    assert!(proof_after_failure.1.is_none());
    let decision_count_after_failure: u64 = rolled_back
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_decisions WHERE action_id=?1",
            [action_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(decision_count_after_failure, 0);
    let adoption_audit_count_after_failure: u64 = rolled_back
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_kind GLOB 'device.adoption_action_*'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(adoption_audit_count_after_failure, 0);
    drop(rolled_back);

    let barrier = Arc::new(Barrier::new(2));
    let mut racers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let network_id = network.network_id;
        racers.push(std::thread::spawn(move || {
            let source = provider(instance);
            *source.nodes.lock().unwrap() = vec![node(
                instance,
                "42",
                &"a".repeat(64),
                "changed-during-proof",
            )];
            let store = StateStore::open(path).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            barrier.wait();
            runtime.block_on(store.reconcile_read_only(
                network_id,
                &source,
                now(),
                AuditActor::system(),
            ))
        }));
    }
    let race_results: Vec<_> = racers
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(race_results.iter().any(Result::is_ok));
    assert!(race_results.iter().all(|result| {
        result.is_ok() || matches!(result, Err(ReconciliationFailure::State(_)))
    }));

    let connection = rusqlite::Connection::open(&path).unwrap();
    let action: (String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT action_state,terminal_decision_id,terminal_reason FROM n5_adoption_actions WHERE action_id=?1",
            [action_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(action.0, "conflicted");
    assert!(action.1.is_some());
    assert_eq!(action.2.as_deref(), Some("observation_changed"));
    let action_rewind = connection.execute(
        "UPDATE n5_adoption_actions
         SET action_state='proof_pending',terminal_decision_id=NULL,terminal_at_ms=NULL,terminal_reason=NULL
         WHERE action_id=?1",
        [action_id],
    );
    assert!(
        action_rewind.is_err(),
        "terminal adoption action was rewound to proof_pending"
    );
    let proof: (String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT operation_state,outcome,receipt_id FROM n5_adoption_proof_operations WHERE action_id=?1",
            [action_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(proof.0, "settled");
    assert_eq!(proof.1.as_deref(), Some("conflicted"));
    assert!(proof.2.is_some());
    let proof_exact_replay: (String, String) = connection
        .query_row(
            "SELECT outcome,receipt_id FROM n5_adoption_proof_operations
             WHERE action_id=?1 AND operation_id='adoption-proof-1' AND request_fingerprint=?2",
            rusqlite::params![action_id, "e".repeat(64)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(proof_exact_replay.0, "conflicted");
    assert_eq!(proof_exact_replay.1, proof.2.clone().unwrap());
    let proof_changed_replay_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_proof_operations
             WHERE action_id=?1 AND operation_id='adoption-proof-1' AND request_fingerprint=?2",
            rusqlite::params![action_id, "f".repeat(64)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(proof_changed_replay_count, 0);
    let reopened_proof = connection.execute(
        "INSERT INTO n5_adoption_proof_operations
         (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms)
         VALUES (?1,'post-terminal-proof',?2,'pending',NULL,NULL,NULL,NULL,2,NULL)",
        rusqlite::params![action_id, "1".repeat(64)],
    );
    assert!(
        reopened_proof.is_err(),
        "terminal action accepted a fresh pending proof operation"
    );
    let proof_rewind = connection.execute(
        "UPDATE n5_adoption_proof_operations
         SET operation_state='pending',outcome=NULL,receipt_id=NULL,settled_at_ms=NULL
         WHERE action_id=?1 AND operation_id='adoption-proof-1'",
        [action_id],
    );
    assert!(
        proof_rewind.is_err(),
        "settled adoption proof operation was rewound to pending"
    );
    let decision_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_decisions WHERE action_id=?1 AND decision_kind='conflict'",
            [action_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(decision_count, 1);
    let correlation_count: u64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM n5_adoption_actions AS action
             JOIN n5_adoption_decisions AS decision
               ON decision.decision_id=action.terminal_decision_id
              AND decision.action_id=action.action_id
             JOIN audit_events AS audit ON audit.event_id=decision.audit_event_id
             WHERE action.action_id=?1
               AND action.action_state='conflicted'
               AND decision.new_action_state=action.action_state
               AND decision.reason_code=action.terminal_reason
               AND decision.decided_at_ms=action.terminal_at_ms
               AND audit.network_id=action.network_id
               AND audit.device_id IS NULL
               AND audit.generation=decision.observation_generation
               AND audit.event_kind='device.adoption_action_conflicted'",
            [action_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(correlation_count, 1);
    let adoption_audit_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_kind GLOB 'device.adoption_action_*'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(adoption_audit_count, 1);
    assert!(connection
        .execute(
            "UPDATE n5_adoption_actions SET authority_generation=authority_generation+1 WHERE action_id=?1",
            [action_id],
        )
        .is_err());
    assert!(
        connection
            .execute(
                "UPDATE n5_adoption_proof_operations SET request_fingerprint=?2 WHERE action_id=?1",
                rusqlite::params![action_id, "0".repeat(64)],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE n5_adoption_decisions SET reason_code='owner_revoked' WHERE action_id=?1",
                [action_id],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM n5_adoption_decisions WHERE action_id=?1",
                [action_id],
            )
            .is_err()
    );
    assert!(connection
        .execute(
            "UPDATE audit_events SET outcome='failure' WHERE event_kind='device.adoption_action_conflicted'",
            [],
        )
        .is_err());
    assert!(
        connection
            .execute(
                "DELETE FROM audit_events WHERE event_kind='device.adoption_action_conflicted'",
                [],
            )
            .is_err()
    );
    let observation: (String, u64) = connection
        .query_row(
            "SELECT adoption_state,semantic_generation FROM provider_observations WHERE observation_id=?1",
            [&observation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(observation.0, "unmanaged");
    assert_eq!(observation.1, semantic_generation + 1);
    for table in [
        "devices",
        "n5_device_identities",
        "n5_provider_bindings",
        "n5_device_trust_state",
        "n6_binding_records",
        "n7_fleet_projection_records",
    ] {
        let count: u64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, 0,
            "pending invalidation created authority in {table}"
        );
    }
}
