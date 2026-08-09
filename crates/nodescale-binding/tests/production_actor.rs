use chrono::{Duration, Utc};
use nodescale_binding::{N6BindingService, N6ProductionError};
use nodescale_domain::{
    AuditActor, Device, DeviceId, KeryxPeerId, Network, NetworkId, ProviderApiKey,
    ProviderInstanceId, ProviderKind,
};
use nodescale_state::{N5ConfiguredHeadscaleProvider, StateStore};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::const_new(());

fn configured_store() -> (
    StateStore,
    N5ConfiguredHeadscaleProvider,
    NetworkId,
    DeviceId,
    PathBuf,
) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "nodescale-n6-production-actor-{}-{unique}.sqlite",
        std::process::id()
    ));
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    let provider_instance_id = ProviderInstanceId::new();
    let now = Utc::now();

    let store = StateStore::open(&path).unwrap();
    let network = Network::new(
        network_id,
        "n6-production-actor",
        ProviderKind::Headscale,
        provider_instance_id,
        now,
    )
    .unwrap();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    store
        .create_device(
            &Device::new(device_id, network_id, "n6-actor-device", now).unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    drop(store);

    // `N5ConfiguredHeadscaleProvider` deliberately has no caller-constructible
    // fake. This minimal persisted import lets the public constructor create its
    // real Headscale client without any provider response being faked. The
    // binding package has no direct StateStore fixture API for this configuration.
    let script = r#"
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute(
    """INSERT INTO provider_imports
       (network_id, provider_instance_id, server_url, opaque_secret_reference,
        compatibility_pin, tls_verification, read_only, mutation_allowed,
        compatibility, provider_version)
       VALUES (?, ?, 'https://provider.example.test', 'secret://vault/n6',
               'v0.29.3', 'verify', 1, 0, 'compatible', 'v0.29.3')""",
    (sys.argv[2], sys.argv[3]),
)
connection.commit()
"#;
    let status = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&path)
        .arg(network_id.to_string())
        .arg(provider_instance_id.to_string())
        .status()
        .unwrap();
    assert!(status.success());

    let store = StateStore::open(&path).unwrap();
    let provider = store
        .configured_n5_headscale_provider(
            network_id,
            ProviderApiKey::new("actor-test-api-key".to_owned()).unwrap(),
            Default::default(),
        )
        .unwrap();
    (store, provider, network_id, device_id, path)
}

fn actor_thread_count() -> usize {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            fs::read_to_string(entry.path().join("comm"))
                .is_ok_and(|name| name.trim().starts_with("nodescale-n6-bi"))
        })
        .count()
}

#[tokio::test]
async fn production_actor_rejects_nonpositive_and_overlong_ttls_before_spawning() {
    let _lock = TEST_LOCK.lock().await;
    let thread_count = actor_thread_count();

    for ttl in [Duration::zero(), Duration::seconds(601)] {
        let (store, provider, _, _, path) = configured_store();
        assert!(matches!(
            N6BindingService::new(store, provider, ttl),
            Err(N6ProductionError::Rejected)
        ));
        assert_eq!(actor_thread_count(), thread_count);
        fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn production_actor_fails_closed_and_joins_its_thread_on_drop() {
    let _lock = TEST_LOCK.lock().await;
    let thread_count = actor_thread_count();
    let (store, provider, network_id, device_id, path) = configured_store();
    let service = N6BindingService::new(store, provider, Duration::seconds(600)).unwrap();

    // A configured device without N5 trust state must not be authorized. This
    // reaches the real actor and StateStore trust gate; it does not substitute
    // a successful provider implementation or provider response.
    assert!(matches!(
        service
            .authorize_peer(
                network_id,
                device_id,
                KeryxPeerId::parse("production-actor-peer").unwrap(),
            )
            .await,
        Err(N6ProductionError::Rejected)
    ));
    assert_eq!(actor_thread_count(), thread_count + 1);

    drop(service);
    assert_eq!(actor_thread_count(), thread_count);
    fs::remove_file(path).unwrap();
}
