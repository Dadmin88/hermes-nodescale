use chrono::{TimeZone, Utc};
use nodescale_domain::{ProviderApiKey, ProviderInstanceId};
use nodescale_provider::{ProviderCapability, ProviderError};
use nodescale_provider_tailscale::{
    TailscaleAuth, TailscaleClientOptions, TailscaleError, TailscaleProvider,
    parse_devices_fixture, read_only_capabilities,
};
use sha2::{Digest, Sha256};

fn fixture(devices: &str) -> String {
    format!(r#"{{"devices":[{devices}]}}"#)
}

fn device(node_id: &str, machine_key: &str, authorized: bool) -> String {
    format!(
        r#"{{
            "id":"device-api-id",
            "nodeId":"{node_id}",
            "name":"workstation.example.ts.net",
            "hostname":"workstation",
            "addresses":["192.0.2.100","fd7a:115c:a1e0::10"],
            "authorized":{authorized},
            "isExternal":false,
            "machineKey":"{machine_key}",
            "created":"2026-01-01T00:00:00Z",
            "lastSeen":"2026-01-02T00:00:00Z",
            "expires":"2027-01-01T00:00:00Z",
            "tags":["tag:worker"]
        }}"#
    )
}

#[test]
fn official_device_shape_maps_without_fabricating_missing_authority() {
    let instance = ProviderInstanceId::new();
    let observed_at = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
    let nodes = parse_devices_fixture(
        &fixture(&device("n292kg92CNTRL", "", true)),
        instance,
        observed_at,
    )
    .unwrap();

    assert_eq!(nodes.len(), 1);
    let node = &nodes[0];
    assert_eq!(node.identity.provider_instance_id, instance);
    assert_eq!(node.identity.node_id.as_str(), "n292kg92CNTRL");
    assert_eq!(
        node.identity.stable_key_fingerprint,
        format!("sha256:{:x}", Sha256::digest(b"n292kg92CNTRL"))
    );
    assert_eq!(node.identity_evidence.machine_key, None);
    assert_eq!(node.identity_evidence.node_key, None);
    assert_eq!(node.identity_evidence.disco_key, None);
    assert_eq!(node.pre_auth, None);
    assert_eq!(node.online, None);
    assert!(!node.expired);
    assert_eq!(node.hostname, "workstation");
    assert_eq!(node.given_name, "workstation.example.ts.net");
    assert_eq!(
        node.tags.iter().map(String::as_str).collect::<Vec<_>>(),
        ["tag:worker"]
    );
}

#[test]
fn machine_key_is_optional_evidence_and_deauthorization_fails_safe() {
    let instance = ProviderInstanceId::new();
    let observed_at = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
    let node = parse_devices_fixture(
        &fixture(&device(
            "node-with-machine",
            "mkey:provider-evidence",
            false,
        )),
        instance,
        observed_at,
    )
    .unwrap()
    .pop()
    .unwrap();

    assert_eq!(
        node.identity_evidence.machine_key.unwrap().as_str(),
        "mkey:provider-evidence"
    );
    assert!(node.expired);
}

#[test]
fn fields_all_node_key_is_preserved_as_mutable_adoption_evidence() {
    let instance = ProviderInstanceId::new();
    let observed_at = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
    let raw = device("node-with-keys", "mkey:provider-evidence", true).replace(
        "\"machineKey\":\"mkey:provider-evidence\"",
        "\"machineKey\":\"mkey:provider-evidence\",\"nodeKey\":\"nodekey:current-evidence\"",
    );
    let node = parse_devices_fixture(&fixture(&raw), instance, observed_at)
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(
        node.identity_evidence.node_key.unwrap().as_str(),
        "nodekey:current-evidence"
    );
}

#[test]
fn duplicate_canonical_node_ids_fail_closed() {
    let instance = ProviderInstanceId::new();
    let observed_at = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
    let duplicate = format!(
        "{},{}",
        device("same-node", "", true),
        device("same-node", "", true)
    );
    assert!(matches!(
        parse_devices_fixture(&fixture(&duplicate), instance, observed_at),
        Err(ProviderError::MalformedResponse(_))
    ));
}

#[test]
fn adapter_advertises_only_supported_read_operations_and_redacts_auth() {
    assert_eq!(
        read_only_capabilities(),
        [
            ProviderCapability::InspectServer,
            ProviderCapability::ListNodes,
            ProviderCapability::GetNode,
            ProviderCapability::Health,
        ]
        .into_iter()
        .collect()
    );

    let value = "generic-secret-value";
    let provider = TailscaleProvider::new(
        "example.com",
        ProviderInstanceId::new(),
        TailscaleAuth::ApiAccessToken(ProviderApiKey::new(value.into()).unwrap()),
        TailscaleClientOptions::default(),
    )
    .unwrap();
    let debug = format!("{provider:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(value));
}

#[test]
fn response_limit_has_a_hard_public_ceiling() {
    let result = TailscaleProvider::new(
        "example.com",
        ProviderInstanceId::new(),
        TailscaleAuth::ApiAccessToken(ProviderApiKey::new("generic-token".into()).unwrap()),
        TailscaleClientOptions {
            max_response_bytes: 8 * 1024 * 1024 + 1,
            ..TailscaleClientOptions::default()
        },
    );
    assert!(matches!(result, Err(TailscaleError::InvalidClientOptions)));
}
