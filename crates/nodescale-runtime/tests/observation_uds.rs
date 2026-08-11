#![cfg(unix)]

use chrono::{Duration, Utc};
use nodescale_domain::{
    AuditActor, Network, NetworkId, ProviderIdentity, ProviderKind, ProviderNodeId,
};
use nodescale_provider::{
    ConditionalIdentityEvidence, ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider,
};
use nodescale_provider_fake::{FakeFailure, FakeProvider};
use nodescale_runtime::{
    ObservationApiConfig, ObservationUdsListener, ProviderConfig, RuntimeConfig, TailscaleAuthMode,
};
use nodescale_state::{
    HeadscaleImportConfig, ReconciliationFailure, StateStore, TlsVerificationPolicy,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
};
use tempfile::tempdir;

fn now() -> chrono::DateTime<Utc> {
    "2026-08-10T00:00:00Z".parse().unwrap()
}

fn node(instance: nodescale_domain::ProviderInstanceId, provider_node_id: &str) -> ProviderNode {
    let machine_key = format!("api-machine-key-{provider_node_id}");
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
        hostname: "api-host".into(),
        given_name: "api-given".into(),
        addresses: vec!["192.0.2.1".into()],
        user: None,
        pre_auth: None,
        tags: BTreeSet::from(["tag:api".into()]),
        registered_at: Some(now()),
        last_seen: Some(now()),
        expires_at: None,
        observed_at: now(),
        online: Some(true),
        expired: false,
    }
}

async fn populated_store(path: &std::path::Path) -> (StateStore, Network) {
    let store = StateStore::open(path).unwrap();
    let mut provider = FakeProvider::headscale_fixture("uds-observation");
    let mut observed = node(provider.instance_id(), "node-1");
    observed.hostname = "é".repeat(256);
    provider.seed_read_only_snapshot(vec![observed]);
    let network = Network::new(
        NetworkId::new(),
        "uds network",
        ProviderKind::Headscale,
        provider.instance_id(),
        now(),
    )
    .unwrap();
    let import = HeadscaleImportConfig::new(
        "https://headscale.example.test",
        provider.instance_id(),
        "secret://vault/nodescale#key",
        "v0.29.3",
        TlsVerificationPolicy::Verify,
    )
    .unwrap();
    store
        .import_headscale_network(&network, &import, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    (store, network)
}

fn config(state_path: PathBuf, socket_path: PathBuf) -> RuntimeConfig {
    RuntimeConfig {
        state_path,
        poll_interval_seconds: 30,
        network_id: "11111111-1111-1111-1111-111111111111".into(),
        network_name: "observation test".into(),
        provider: ProviderConfig::Tailscale {
            provider_instance_id: "22222222-2222-2222-2222-222222222222".into(),
            tailnet: "example.test".into(),
            credential_reference: "secret://systemd/provider-token".into(),
            auth: TailscaleAuthMode::ApiAccessToken,
        },
        observation_api: Some(ObservationApiConfig {
            socket_path,
            peer_uid: nix::unistd::geteuid().as_raw(),
        }),
        operator_api: None,
    }
}

fn request(value: Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).unwrap();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend(payload);
    frame
}

fn read_response(stream: &mut UnixStream) -> Value {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut payload).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

fn exchange_at(
    listener: &ObservationUdsListener,
    store: &StateStore,
    socket_path: &std::path::Path,
    frame: &[u8],
) -> Value {
    let mut client = UnixStream::connect(socket_path).unwrap();
    client.write_all(frame).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert!(listener.serve_available(store).unwrap());
    read_response(&mut client)
}

#[tokio::test]
async fn same_uid_uds_projects_a_bounded_redacted_read_only_inventory_and_cleans_up() {
    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let socket_path = directory.path().join("obs.sock");
    let (store, network) = populated_store(&state_path).await;
    let mut unavailable_provider = FakeProvider::headscale_fixture("uds-observation");
    unavailable_provider.fail_next(FakeFailure::Unavailable);
    assert!(matches!(
        store
            .reconcile_read_only(
                network.network_id,
                &unavailable_provider,
                now() + Duration::seconds(1),
                AuditActor::system(),
            )
            .await,
        Err(ReconciliationFailure::Unreachable)
    ));
    let before_observations = store.provider_observations(network.network_id).unwrap();
    let before_audits = store.audit_event_count().unwrap();
    let runtime = config(state_path, socket_path.clone());
    let listener = ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).unwrap();
    let metadata = std::fs::metadata(&socket_path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let mut client = UnixStream::connect(&socket_path).unwrap();
    client
        .write_all(&request(serde_json::json!({
            "version":"nodescale.observations.v1",
            "kind":"list",
            "network_id":network.network_id.to_string(),
            "limit":100,
        })))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert!(listener.serve_available(&store).unwrap());
    let response = read_response(&mut client);
    assert_eq!(response["version"], "nodescale.observations.v1");
    assert_eq!(response["reconciliation"]["state"], "unreachable");
    let entries = response["observations"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let rendered = response.to_string();
    for forbidden in [
        "api-machine-key",
        "provider-user-data-must-not-leak",
        "device_id",
        "semantic_fingerprint",
        "stable_machine_key_fingerprint",
        "node_key",
        "disco_key",
        "pre_auth",
        "audit",
        "fleet",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "forbidden field leaked: {forbidden}"
        );
    }
    assert!(
        entries[0]["observed_id"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(entries[0]["hostname"].as_str().unwrap().len() <= 256);
    assert_eq!(
        store.provider_observations(network.network_id).unwrap(),
        before_observations
    );
    assert_eq!(store.audit_event_count().unwrap(), before_audits);
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);

    drop(listener);
    assert!(!socket_path.exists());
    let restarted =
        ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).unwrap();
    drop(restarted);
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn uds_rejects_wrong_uid_configuration_and_invalid_or_unframed_requests() {
    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let socket_path = directory.path().join("obs.sock");
    let (store, _network) = populated_store(&state_path).await;
    let mut runtime = config(state_path, socket_path.clone());
    runtime.observation_api.as_mut().unwrap().peer_uid += 1;
    assert!(ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).is_err());

    let runtime = config(directory.path().join("state.sqlite3"), socket_path.clone());
    let listener = ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).unwrap();
    let mut client = UnixStream::connect(&socket_path).unwrap();
    client.write_all(&[0, 0, 0, 1, b'{', b'x']).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    listener.serve_available(&store).unwrap();
    assert_eq!(read_response(&mut client)["error"], "invalid_request");
    drop(listener);
}

#[tokio::test]
async fn uds_protocol_is_closed_and_reports_unavailable_state_without_details() {
    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let socket_path = directory.path().join("obs.sock");
    let (store, network) = populated_store(&state_path).await;
    let runtime = config(state_path, socket_path.clone());
    let listener = ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).unwrap();

    let capabilities = exchange_at(
        &listener,
        &store,
        &socket_path,
        &request(serde_json::json!({
            "version":"nodescale.observations.v1",
            "kind":"capabilities"
        })),
    );
    assert_eq!(capabilities["kind"], "capabilities");
    assert_eq!(capabilities["capabilities"]["max_page_size"], 100);

    let summary = exchange_at(
        &listener,
        &store,
        &socket_path,
        &request(serde_json::json!({
            "version":"nodescale.observations.v1",
            "kind":"summary",
            "network_id":network.network_id.to_string()
        })),
    );
    assert_eq!(summary["kind"], "summary");
    assert_eq!(summary["reconciliation"]["observed_count"], 1);

    for invalid in [
        br#"{"version":"nodescale.observations.v1","version":"nodescale.observations.v1","kind":"capabilities"}"#.as_slice(),
        br#"{"version":"nodescale.observations.v1","kind":"capabilities","extra":true}"#.as_slice(),
        br#"{"version":"nodescale.observations.v1","kind":"list","network_id":"11111111-1111-1111-1111-111111111111","limit":1,"cursor":" bad"}"#.as_slice(),
    ] {
        let mut framed = (invalid.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(invalid);
        assert_eq!(
            exchange_at(&listener, &store, &socket_path, &framed)["error"],
            "invalid_request"
        );
    }

    let mut trailing = request(serde_json::json!({
        "version":"nodescale.observations.v1",
        "kind":"capabilities"
    }));
    trailing.push(b'x');
    assert_eq!(
        exchange_at(&listener, &store, &socket_path, &trailing)["error"],
        "invalid_request"
    );

    let unavailable = exchange_at(
        &listener,
        &store,
        &socket_path,
        &request(serde_json::json!({
            "version":"nodescale.observations.v1",
            "kind":"summary",
            "network_id":NetworkId::new().to_string()
        })),
    );
    assert_eq!(unavailable["kind"], "error");
    assert_eq!(unavailable["error"], "unavailable");
    assert_eq!(unavailable.as_object().unwrap().len(), 3);
}

#[test]
fn uds_bind_refuses_preexisting_paths_including_an_active_socket() {
    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let regular_path = directory.path().join("regular");
    std::fs::write(&regular_path, b"preserve").unwrap();
    let mut runtime = config(directory.path().join("state.sqlite3"), regular_path.clone());
    assert!(ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).is_err());
    assert_eq!(std::fs::read(&regular_path).unwrap(), b"preserve");

    let socket_path = directory.path().join("active.sock");
    let active = UnixListener::bind(&socket_path).unwrap();
    runtime.observation_api.as_mut().unwrap().socket_path = socket_path.clone();
    assert!(ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).is_err());
    assert!(socket_path.exists());
    drop(active);
}

#[test]
fn uds_config_requires_a_private_owned_parent_without_symlink_components() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let shared_parent = directory.path().join("shared");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o750)).unwrap();
    let runtime = config(
        directory.path().join("state.sqlite3"),
        shared_parent.join("observations.sock"),
    );
    assert!(ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).is_err());

    let real_parent = directory.path().join("real");
    let nested = real_parent.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_parent = directory.path().join("linked");
    symlink(&real_parent, &linked_parent).unwrap();
    let runtime = config(
        directory.path().join("state.sqlite3"),
        linked_parent.join("nested").join("observations.sock"),
    );
    assert!(ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).is_err());
}

#[tokio::test]
async fn uds_list_pages_worst_case_rows_within_the_advertised_response_bound() {
    let directory = tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = directory.path().join("state.sqlite3");
    let socket_path = directory.path().join("obs.sock");
    let store = StateStore::open(&state_path).unwrap();
    let mut provider = FakeProvider::headscale_fixture("uds-bounded-pages");
    let mut observed = Vec::new();
    for index in 0..10 {
        let mut entry = node(provider.instance_id(), &format!("node-{index:02}"));
        entry.hostname = "\"".repeat(256);
        entry.given_name = "\\".repeat(256);
        entry.tags = (0..32)
            .map(|tag| format!("tag:{index:02}:{tag:02}:{}", "\"".repeat(240)))
            .collect();
        observed.push(entry);
    }
    provider.seed_read_only_snapshot(observed);
    let network = Network::new(
        NetworkId::new(),
        "bounded response network",
        ProviderKind::Headscale,
        provider.instance_id(),
        now(),
    )
    .unwrap();
    let import = HeadscaleImportConfig::new(
        "https://headscale.example.test",
        provider.instance_id(),
        "secret://vault/nodescale#key",
        "v0.29.3",
        TlsVerificationPolicy::Verify,
    )
    .unwrap();
    store
        .import_headscale_network(&network, &import, &provider, now(), AuditActor::system())
        .await
        .unwrap();

    let runtime = config(state_path, socket_path.clone());
    let listener = ObservationUdsListener::bind(runtime.observation_api.as_ref().unwrap()).unwrap();
    let mut cursor: Option<String> = None;
    let mut ids = BTreeSet::new();
    for _ in 0..10 {
        let response = exchange_at(
            &listener,
            &store,
            &socket_path,
            &request(serde_json::json!({
                "version":"nodescale.observations.v1",
                "kind":"list",
                "network_id":network.network_id.to_string(),
                "limit":100,
                "cursor":cursor,
            })),
        );
        assert!(serde_json::to_vec(&response).unwrap().len() <= 64 * 1024);
        for entry in response["observations"].as_array().unwrap() {
            assert!(ids.insert(entry["observed_id"].as_str().unwrap().to_owned()));
        }
        let next = response.get("next_cursor").and_then(Value::as_str);
        if next.is_none() {
            break;
        }
        assert_ne!(next, cursor.as_deref());
        cursor = next.map(str::to_owned);
    }
    assert_eq!(ids.len(), 10);
}
