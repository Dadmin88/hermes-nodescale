#![cfg(unix)]
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::Utc;
use nodescale_domain::{
    AuditActor, Device, DeviceId, Network, NetworkId, ProviderIdentity, ProviderInstanceId,
    ProviderKind, ProviderNodeId,
};
use nodescale_runtime::{OperatorApiConfig, OperatorUdsListener};
use nodescale_state::StateStore;
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
};
use tempfile::tempdir;

struct Fixture {
    _directory: tempfile::TempDir,
    store: StateStore,
    listener: OperatorUdsListener,
    socket_path: std::path::PathBuf,
    network_id: NetworkId,
    device_ids: Vec<DeviceId>,
}

fn fixture() -> Fixture {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = directory.path().join("operator.sock");
    let store = StateStore::open(directory.path().join("state.db")).unwrap();
    let network_id = NetworkId::new();
    let network = Network::new(
        network_id,
        "network-a",
        ProviderKind::Fake,
        ProviderInstanceId::new(),
        Utc::now(),
    )
    .unwrap();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();

    let mut device_ids = Vec::new();
    for (name, provider_node_id, fingerprint) in [
        ("compute-a", "provider-node-a", "private-fingerprint-a"),
        ("compute-b", "provider-node-b", "private-fingerprint-b"),
    ] {
        let mut device = Device::new(DeviceId::new(), network_id, name, Utc::now()).unwrap();
        device.provider_identity = Some(
            ProviderIdentity::new(
                network.provider_instance_id,
                ProviderNodeId::parse(provider_node_id).unwrap(),
                fingerprint,
            )
            .unwrap(),
        );
        device_ids.push(device.device_id);
        store.create_device(&device, AuditActor::system()).unwrap();
    }
    device_ids.sort_by_key(ToString::to_string);
    let listener = OperatorUdsListener::bind(&OperatorApiConfig {
        socket_path: socket_path.clone(),
        peer_uid: nix::unistd::geteuid().as_raw(),
    })
    .unwrap();
    Fixture {
        _directory: directory,
        store,
        listener,
        socket_path,
        network_id,
        device_ids,
    }
}

fn request(fixture: &Fixture, payload: &[u8], trailing: &[u8]) -> Value {
    let mut stream = UnixStream::connect(&fixture.socket_path).unwrap();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.write_all(trailing).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert!(fixture.listener.serve_available(&fixture.store).unwrap());
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut response = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).unwrap();
    match stream.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("operator response did not close cleanly: {result:?}"),
    }
    serde_json::from_slice(&response).unwrap()
}

fn json_request(fixture: &Fixture, payload: Value) -> Value {
    request(fixture, &serde_json::to_vec(&payload).unwrap(), &[])
}

#[test]
fn operator_contract_lists_and_inspects_without_claiming_live_authority() {
    let fixture = fixture();
    let capabilities = json_request(
        &fixture,
        serde_json::json!({
            "kind": "capabilities",
            "version": "nodescale.operator.v1"
        }),
    );
    assert_eq!(capabilities["kind"], "capabilities");
    assert_eq!(
        capabilities["capabilities"]["read_operations"],
        serde_json::json!(["capabilities", "devices.list", "devices.inspect"])
    );
    assert_eq!(
        capabilities["capabilities"]["mutation_operations"],
        serde_json::json!([])
    );

    let first = json_request(
        &fixture,
        serde_json::json!({
            "kind": "devices.list",
            "version": "nodescale.operator.v1",
            "network_id": fixture.network_id.to_string(),
            "limit": 1,
            "cursor": null
        }),
    );
    assert_eq!(first["kind"], "devices.list");
    assert_eq!(first["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        first["devices"][0]["device_id"],
        fixture.device_ids[0].to_string()
    );
    assert_eq!(first["devices"][0]["durable_trust_state"], Value::Null);
    assert_eq!(
        first["devices"][0]["live_trust_evidence"],
        "not_reconciled_by_operator_read"
    );
    assert_eq!(
        first["devices"][0]["live_keryx_binding_health"],
        "not_exposed"
    );

    let second = json_request(
        &fixture,
        serde_json::json!({
            "kind": "devices.list",
            "version": "nodescale.operator.v1",
            "network_id": fixture.network_id.to_string(),
            "limit": 1,
            "cursor": first["next_cursor"]
        }),
    );
    assert_eq!(
        second["devices"][0]["device_id"],
        fixture.device_ids[1].to_string()
    );

    let inspected = json_request(
        &fixture,
        serde_json::json!({
            "kind": "devices.inspect",
            "version": "nodescale.operator.v1",
            "network_id": fixture.network_id.to_string(),
            "device_id": fixture.device_ids[0].to_string()
        }),
    );
    assert_eq!(inspected["kind"], "devices.inspect");
    assert_eq!(
        inspected["device"]["device_id"],
        fixture.device_ids[0].to_string()
    );
    let serialized = serde_json::to_string(&inspected).unwrap();
    assert!(!serialized.contains("private-fingerprint"));
    assert!(!serialized.contains("nsjoin_"));
    assert!(!serialized.contains("trust_root"));
}

#[test]
fn operator_contract_rejects_wrong_scope_unknown_fields_duplicates_and_trailing_bytes() {
    let fixture = fixture();
    let wrong_network = json_request(
        &fixture,
        serde_json::json!({
            "kind": "devices.inspect",
            "version": "nodescale.operator.v1",
            "network_id": NetworkId::new().to_string(),
            "device_id": fixture.device_ids[0].to_string()
        }),
    );
    assert_eq!(wrong_network["error"], "not_found");

    let unknown = json_request(
        &fixture,
        serde_json::json!({
            "kind": "capabilities",
            "version": "nodescale.operator.v1",
            "extra": true
        }),
    );
    assert_eq!(unknown["error"], "invalid_request");

    let duplicate = request(
        &fixture,
        br#"{"kind":"capabilities","version":"nodescale.operator.v1","version":"nodescale.operator.v1"}"#,
        &[],
    );
    assert_eq!(duplicate["error"], "invalid_request");

    let trailing = request(
        &fixture,
        br#"{"kind":"capabilities","version":"nodescale.operator.v1"}"#,
        b"unexpected",
    );
    assert_eq!(trailing["error"], "invalid_request");
}

#[test]
fn operator_contract_rejects_oversized_frames_and_unsafe_peer_configuration() {
    let fixture = fixture();
    let mut stream = UnixStream::connect(&fixture.socket_path).unwrap();
    stream.write_all(&(8193_u32).to_be_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert!(fixture.listener.serve_available(&fixture.store).unwrap());
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut response = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).unwrap();
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["error"], "invalid_request");

    let other = tempdir().unwrap();
    fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let error = OperatorUdsListener::bind(&OperatorApiConfig {
        socket_path: Path::new(other.path()).join("operator.sock"),
        peer_uid: nix::unistd::geteuid().as_raw().saturating_add(1),
    })
    .err()
    .expect("mismatched peer UID must be rejected");
    assert!(error.to_string().contains("peer_uid"));
}
