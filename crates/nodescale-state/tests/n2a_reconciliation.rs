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
use std::{collections::BTreeSet, sync::Mutex};

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
            machine_key: ConditionalIdentityEvidence::new(machine).unwrap(),
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
        online: true,
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
        ConditionalIdentityEvidence::new("machine-other").unwrap();
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
