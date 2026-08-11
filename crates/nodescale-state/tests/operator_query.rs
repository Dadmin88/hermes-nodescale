// SPDX-License-Identifier: AGPL-3.0-only

use chrono::Utc;
use nodescale_domain::{
    AuditActor, Device, DeviceId, Network, NetworkId, ProviderInstanceId, ProviderKind,
};
use nodescale_state::{DEVICE_PAGE_MAX, StateStore};
use tempfile::TempDir;

fn network(id: NetworkId, provider: ProviderInstanceId, name: &str) -> Network {
    Network::new(id, name, ProviderKind::Fake, provider, Utc::now()).unwrap()
}

fn device(id: DeviceId, network_id: NetworkId, name: &str) -> Device {
    Device::new(id, network_id, name, Utc::now()).unwrap()
}

#[test]
fn operator_device_query_is_network_scoped_bounded_and_cursor_stable() {
    let directory = TempDir::new().unwrap();
    let store = StateStore::open(directory.path().join("state.db")).unwrap();
    let network_a = NetworkId::new();
    let network_b = NetworkId::new();
    store
        .create_network(
            &network(network_a, ProviderInstanceId::new(), "network-a"),
            AuditActor::system(),
        )
        .unwrap();
    store
        .create_network(
            &network(network_b, ProviderInstanceId::new(), "network-b"),
            AuditActor::system(),
        )
        .unwrap();

    let device_a = DeviceId::new();
    let device_b = DeviceId::new();
    let foreign = DeviceId::new();
    store
        .create_device(
            &device(device_a, network_a, "compute-a"),
            AuditActor::system(),
        )
        .unwrap();
    store
        .create_device(
            &device(device_b, network_a, "compute-b"),
            AuditActor::system(),
        )
        .unwrap();
    store
        .create_device(
            &device(foreign, network_b, "compute-c"),
            AuditActor::system(),
        )
        .unwrap();

    let mut expected = [device_a, device_b];
    expected.sort_by_key(ToString::to_string);
    let first = store.operator_device_page(network_a, None, 1).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].device_id, expected[0]);
    let second = store
        .operator_device_page(network_a, Some(expected[0]), 1)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].device_id, expected[1]);
    assert!(
        store
            .operator_device_page(network_a, Some(expected[1]), 1)
            .unwrap()
            .is_empty()
    );
    assert!(store.operator_device_page(network_a, None, 0).is_err());
    assert!(
        store
            .operator_device_page(network_a, None, DEVICE_PAGE_MAX + 1)
            .is_err()
    );

    assert_eq!(store.device(device_a).unwrap().device_id, device_a);
    assert!(store.device(foreign).is_ok());
    assert!(store.durable_device_trust(device_a).unwrap().is_none());
    assert!(store.latest_n6_binding(device_a).unwrap().is_none());
}
