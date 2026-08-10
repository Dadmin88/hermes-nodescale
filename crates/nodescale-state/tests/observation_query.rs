use chrono::Utc;
use nodescale_domain::{
    AuditActor, Network, NetworkId, ProviderIdentity, ProviderInstanceId, ProviderKind,
    ProviderNodeId,
};
use nodescale_provider::{
    ConditionalIdentityEvidence, ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider,
};
use nodescale_provider_fake::FakeProvider;
use nodescale_state::{HeadscaleImportConfig, StateError, StateStore, TlsVerificationPolicy};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use tempfile::tempdir;

fn now() -> chrono::DateTime<Utc> {
    "2026-08-10T00:00:00Z".parse().unwrap()
}

fn node(instance: ProviderInstanceId, provider_node_id: &str) -> ProviderNode {
    let machine_key = format!("machine-key-{provider_node_id}");
    let fingerprint = format!("sha256:{:x}", Sha256::digest(machine_key.as_bytes()));
    ProviderNode {
        identity: ProviderIdentity::new(
            instance,
            ProviderNodeId::parse(provider_node_id).unwrap(),
            fingerprint,
        )
        .unwrap(),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(ConditionalIdentityEvidence::new(machine_key).unwrap()),
            node_key: None,
            disco_key: None,
        },
        hostname: format!("host-{provider_node_id}"),
        given_name: format!("given-{provider_node_id}"),
        addresses: vec![format!("192.0.2.{provider_node_id}")],
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

fn import_config(instance: ProviderInstanceId) -> HeadscaleImportConfig {
    HeadscaleImportConfig::new(
        "https://headscale.example.test",
        instance,
        "secret://vault/nodescale#key",
        "v0.29.3",
        TlsVerificationPolicy::Verify,
    )
    .unwrap()
}

async fn import_network(store: &StateStore, network: &Network, provider: &FakeProvider) {
    store
        .import_headscale_network(
            network,
            &import_config(provider.instance_id()),
            provider,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
}

fn protected_row_counts(path: &Path) -> BTreeMap<String, i64> {
    let connection = Connection::open(path).unwrap();
    let mut tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' AND (
                name IN ('provider_observations', 'audit_events', 'devices', 'keryx_bindings')
                OR name LIKE 'n5_%' OR name LIKE 'n6_%' OR name LIKE 'n7_%' OR name LIKE 'fleet_%'
            ) ORDER BY name",
        )
        .unwrap();
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                    row.get(0)
                })
                .unwrap();
            (name, count)
        })
        .collect()
}

#[tokio::test]
async fn observation_page_is_lexicographic_bounded_network_scoped_and_read_only() {
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let store = StateStore::open(&state_path).unwrap();

    let mut first_provider = FakeProvider::headscale_fixture("page-first");
    let first = Network::new(
        NetworkId::new(),
        "first network",
        ProviderKind::Headscale,
        first_provider.instance_id(),
        now(),
    )
    .unwrap();
    first_provider.seed_read_only_snapshot(vec![
        node(first_provider.instance_id(), "z-9"),
        node(first_provider.instance_id(), "a-1"),
        node(first_provider.instance_id(), "m-4"),
        node(first_provider.instance_id(), "b-2"),
    ]);
    import_network(&store, &first, &first_provider).await;

    let second_provider = FakeProvider::headscale_fixture("page-second");
    let second = Network::new(
        NetworkId::new(),
        "second network",
        ProviderKind::Headscale,
        second_provider.instance_id(),
        now(),
    )
    .unwrap();
    let mut second_provider = second_provider;
    second_provider.seed_read_only_snapshot(vec![node(second_provider.instance_id(), "a-0")]);
    import_network(&store, &second, &second_provider).await;

    let before_rows = protected_row_counts(&state_path);
    let before_audits = store.audit_event_count().unwrap();

    let first_page = store
        .provider_observation_page(first.network_id, None, 2)
        .unwrap();
    assert_eq!(
        first_page
            .iter()
            .map(|observation| observation.canonical_provider_node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-1", "b-2"]
    );
    let second_page = store
        .provider_observation_page(first.network_id, Some("b-2"), 2)
        .unwrap();
    assert_eq!(
        second_page
            .iter()
            .map(|observation| observation.canonical_provider_node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["m-4", "z-9"]
    );
    assert!(
        store
            .provider_observation_page(first.network_id, Some("z-9"), 2)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .provider_observation_page(second.network_id, None, 1000)
            .unwrap()
            .iter()
            .map(|observation| observation.canonical_provider_node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-0"]
    );
    assert_eq!(
        store
            .provider_observation_page(first.network_id, None, 0)
            .unwrap()
            .len(),
        0
    );
    assert!(
        store
            .provider_observation_page(first.network_id, None, 1000)
            .unwrap()
            .len()
            <= 100
    );

    assert_eq!(store.audit_event_count().unwrap(), before_audits);
    assert_eq!(protected_row_counts(&state_path), before_rows);
    assert_eq!(store.device_count(first.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(first.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(first.network_id).unwrap(), 0);
}

#[tokio::test]
async fn observation_page_rejects_corrupt_provider_identity_joins() {
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let store = StateStore::open(&state_path).unwrap();
    let mut provider = FakeProvider::headscale_fixture("page-integrity");
    let network = Network::new(
        NetworkId::new(),
        "integrity network",
        ProviderKind::Headscale,
        provider.instance_id(),
        now(),
    )
    .unwrap();
    provider.seed_read_only_snapshot(vec![node(provider.instance_id(), "a-1")]);
    import_network(&store, &network, &provider).await;

    let connection = Connection::open(&state_path).unwrap();
    connection
        .execute(
            "UPDATE provider_observations SET provider_node_id='tampered-node' WHERE network_id=?1",
            [network.network_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        store.provider_observation_page(network.network_id, None, 1),
        Err(StateError::Conflict(_))
    ));

    connection
        .execute(
            "UPDATE provider_observations SET provider_node_id='a-1' WHERE network_id=?1",
            [network.network_id.to_string()],
        )
        .unwrap();
    let other_provider = FakeProvider::headscale_fixture("page-integrity-other");
    let mut corrupted_network = network.clone();
    corrupted_network.provider_instance_id = other_provider.instance_id();
    connection
        .execute(
            "UPDATE networks SET provider_instance_id=?1,record_json=?2 WHERE network_id=?3",
            [
                other_provider.instance_id().to_string(),
                serde_json::to_string(&corrupted_network).unwrap(),
                network.network_id.to_string(),
            ],
        )
        .unwrap();
    assert!(matches!(
        store.provider_observation_page(network.network_id, None, 1),
        Err(StateError::Conflict(_))
    ));
}

#[tokio::test]
async fn observation_page_reads_only_its_bounded_cursor_range() {
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let store = StateStore::open(&state_path).unwrap();
    let mut provider = FakeProvider::headscale_fixture("page-sql-bound");
    let network = Network::new(
        NetworkId::new(),
        "bounded query network",
        ProviderKind::Headscale,
        provider.instance_id(),
        now(),
    )
    .unwrap();
    let first = node(provider.instance_id(), "a-1");
    let second = node(provider.instance_id(), "z-9");
    provider.seed_read_only_snapshot(vec![first, second]);
    import_network(&store, &network, &provider).await;

    let connection = Connection::open(&state_path).unwrap();
    connection
        .execute(
            "UPDATE provider_observations SET normalized_json='{' WHERE network_id=?1 AND provider_node_id='z-9'",
            [network.network_id.to_string()],
        )
        .unwrap();

    let first_page = store
        .provider_observation_page(network.network_id, None, 1)
        .unwrap();
    assert_eq!(first_page[0].canonical_provider_node_id, "a-1");
    assert!(
        store
            .provider_observation_page(network.network_id, Some("a-1"), 1)
            .is_err()
    );
}
