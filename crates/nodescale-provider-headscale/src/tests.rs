use super::*;
use nodescale_domain::{ProviderApiKey, ProviderInstanceId};
use nodescale_provider::{IdentityEvidenceClass, PreAuthAssociationStrength, ReadOnlyProvider};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn instance() -> ProviderInstanceId {
    ProviderInstanceId::parse("123e4567-e89b-42d3-a456-426614174000").unwrap()
}

#[test]
fn selected_version_nodes_normalize_strong_identity_and_metadata() {
    let nodes = parse_nodes_fixture(
        include_str!("../fixtures/v0.29.3-nodes.json"),
        instance(),
        fixed_now(),
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    let node = &nodes[0];
    assert_eq!(node.identity.node_id.as_str(), "42");
    assert_eq!(
        node.identity_evidence.machine_key.class(),
        IdentityEvidenceClass::StableConditional
    );
    assert_eq!(
        node.identity_evidence.node_key.as_ref().unwrap().class(),
        IdentityEvidenceClass::Mutable
    );
    assert_eq!(node.hostname, "worker-1");
    assert_ne!(node.hostname, node.identity.node_id.as_str());
    assert_eq!(node.addresses[0], "192.0.2.10");
    assert_ne!(node.addresses[0], node.identity.node_id.as_str());
    assert_eq!(node.user.as_ref().unwrap().id, "7");
    assert_eq!(
        node.pre_auth.as_ref().unwrap().association,
        PreAuthAssociationStrength::Partial
    );
    assert_eq!(node.pre_auth.as_ref().unwrap().credential_id, "9");
}

#[test]
fn unknown_fields_are_tolerated_but_required_identity_is_not() {
    assert!(
        parse_nodes_fixture(
            r#"{"nodes":[{"id":"42","name":"worker-1"}]}"#,
            instance(),
            fixed_now(),
        )
        .is_err()
    );
}

#[test]
fn individual_node_fixture_matches_list_identity() {
    let listed = parse_nodes_fixture(
        include_str!("../fixtures/v0.29.3-nodes.json"),
        instance(),
        fixed_now(),
    )
    .unwrap();
    let exact = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap();
    assert_eq!(listed[0].identity, exact.identity);
}

#[test]
fn malformed_json_and_invalid_node_ids_fail_closed() {
    assert!(parse_nodes_fixture("not-json", instance(), fixed_now()).is_err());
    assert!(
        parse_nodes_fixture(
            r#"{"nodes":[{"id":"not an id","machineKey":"mkey:synthetic"}]}"#,
            instance(),
            fixed_now(),
        )
        .is_err()
    );
}

fn fixed_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-08-07T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[tokio::test]
async fn authenticated_inspection_and_listing_use_only_get_requests() {
    let (endpoint, requests) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (200, include_str!("../fixtures/v0.29.3-health.json")),
        (200, include_str!("../fixtures/v0.29.3-nodes.json")),
    ])
    .await;
    let provider = HeadscaleProvider::new_for_test(
        &endpoint,
        instance(),
        ProviderApiKey::new("synthetic-api-key".into()).unwrap(),
        HeadscaleClientOptions::default(),
    )
    .unwrap();

    let inspection = provider.inspect_server().await.unwrap();
    assert_eq!(inspection.provider_version, "v0.29.3");
    assert_eq!(inspection.compatibility, CompatibilityStatus::Compatible);
    assert!(!inspection.mutation_allowed);
    let nodes = provider.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 2);

    let requests = requests.lock().unwrap();
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
    assert!(requests[1..].iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer ")
    }));
    assert!(!format!("{provider:?}").contains("synthetic-api-key"));
}

#[tokio::test]
async fn authentication_failure_is_typed_and_secret_safe() {
    let (endpoint, _) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (401, "Unauthorized"),
    ])
    .await;
    let provider = test_provider(&endpoint, HeadscaleClientOptions::default());
    let error = provider.inspect_server().await.unwrap_err();
    assert_eq!(error, ProviderError::AuthenticationFailed);
    assert!(!format!("{error:?}").contains("synthetic-api-key"));
    let (endpoint, _) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (401, "Unauthorized"),
    ])
    .await;
    let health = test_provider(&endpoint, HeadscaleClientOptions::default())
        .provider_health()
        .await
        .unwrap();
    assert_eq!(health.status, ProviderHealthStatus::AuthenticationFailed);
    assert!(health.reachable);
    assert!(!health.authenticated);

    let (endpoint, _) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (401, "Unauthorized"),
    ])
    .await;
    let report = test_provider(&endpoint, HeadscaleClientOptions::default())
        .verify_compatibility()
        .await
        .unwrap();
    assert_eq!(report.status, CompatibilityStatus::AuthenticationFailed);
    assert!(!report.mutation_allowed);
}

#[tokio::test]
async fn malformed_version_and_node_responses_fail_closed() {
    let (endpoint, _) = start_server(vec![(200, r#"{"version":"not-a-version"}"#)]).await;
    let error = test_provider(&endpoint, HeadscaleClientOptions::default())
        .inspect_server()
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedResponse(_)));

    let (endpoint, _) = start_server(vec![(200, r#"{"nodes":[{"id":"42"}]}"#)]).await;
    let error = test_provider(&endpoint, HeadscaleClientOptions::default())
        .list_nodes()
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedResponse(_)));
}

#[tokio::test]
async fn malformed_public_version_never_claims_api_authentication() {
    let (endpoint, _) =
        start_server(vec![(200, r#"{"version":"not-a-version","dirty":false}"#)]).await;
    let health = test_provider(&endpoint, HeadscaleClientOptions::default())
        .provider_health()
        .await
        .unwrap();
    assert_eq!(health.status, ProviderHealthStatus::MalformedResponse);
    assert!(health.reachable);
    assert!(!health.authenticated);
}

#[tokio::test]
async fn dirty_pinned_build_is_compatible_only_with_constraints() {
    let (endpoint, _) = start_server(vec![
        (200, r#"{"version":"v0.29.3","dirty":true}"#),
        (200, include_str!("../fixtures/v0.29.3-health.json")),
    ])
    .await;
    let inspection = test_provider(&endpoint, HeadscaleClientOptions::default())
        .inspect_server()
        .await
        .unwrap();
    assert_eq!(
        inspection.compatibility,
        CompatibilityStatus::CompatibleWithConstraints
    );
    assert!(!inspection.mutation_allowed);
}

#[test]
fn numeric_node_ids_are_canonical_unique_and_deterministic() {
    for id in ["abc", "01", "0", "18446744073709551616"] {
        let json = format!(r#"{{"nodes":[{{"id":"{id}","machineKey":"mkey:synthetic"}}]}}"#);
        assert!(parse_nodes_fixture(&json, instance(), fixed_now()).is_err());
    }
    let duplicate = r#"{"nodes":[
        {"id":"42","machineKey":"mkey:one"},
        {"id":"42","machineKey":"mkey:two"}
    ]}"#;
    assert!(parse_nodes_fixture(duplicate, instance(), fixed_now()).is_err());

    let unordered = r#"{"nodes":[
        {"id":"10","machineKey":"mkey:ten"},
        {"id":"2","machineKey":"mkey:two"}
    ]}"#;
    let nodes = parse_nodes_fixture(unordered, instance(), fixed_now()).unwrap();
    assert_eq!(nodes[0].identity.node_id.as_str(), "2");
    assert_eq!(nodes[1].identity.node_id.as_str(), "10");
}

#[test]
fn pre_auth_secret_material_is_discarded_before_normalization() {
    const SECRET_MARKER: &str = "<synthetic-preauth-credential>";
    let raw = include_str!("../fixtures/v0.29.3-node.json");
    assert!(raw.contains(SECRET_MARKER));

    let node = parse_node_fixture(raw, instance(), fixed_now()).unwrap();
    assert_eq!(node.pre_auth.as_ref().unwrap().credential_id, "9");

    let normalized = serde_json::to_string(&node).unwrap();
    let debug = format!("{node:?}");
    assert!(!normalized.contains(SECRET_MARKER));
    assert!(!debug.contains(SECRET_MARKER));
}

#[tokio::test]
async fn exact_lookup_checks_canonical_id_and_machine_key_fingerprint() {
    let identity = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let (endpoint, requests) =
        start_server(vec![(200, include_str!("../fixtures/v0.29.3-node.json"))]).await;
    let provider = test_provider(&endpoint, HeadscaleClientOptions::default());
    let node = provider.get_node(&identity).await.unwrap().unwrap();
    assert_eq!(node.identity, identity);
    assert!(requests.lock().unwrap()[0].starts_with("GET /api/v1/node/42 "));

    let wrong = ProviderIdentity::new(
        instance(),
        ProviderNodeId::parse("42").unwrap(),
        "sha256:not-the-machine-key",
    )
    .unwrap();
    let (endpoint, _) =
        start_server(vec![(200, include_str!("../fixtures/v0.29.3-node.json"))]).await;
    let error = test_provider(&endpoint, HeadscaleClientOptions::default())
        .get_node(&wrong)
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::Conflict(_)));
}

#[tokio::test]
async fn response_bounds_and_timeouts_are_typed() {
    let (endpoint, _) =
        start_server(vec![(200, include_str!("../fixtures/v0.29.3-nodes.json"))]).await;
    let options = HeadscaleClientOptions {
        max_response_bytes: 64,
        ..HeadscaleClientOptions::default()
    };
    let error = test_provider(&endpoint, options)
        .list_nodes()
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedResponse(_)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let options = HeadscaleClientOptions {
        request_timeout: Duration::from_millis(20),
        ..HeadscaleClientOptions::default()
    };
    let error = test_provider(&endpoint, options)
        .list_nodes()
        .await
        .unwrap_err();
    assert_eq!(error, ProviderError::Timeout);
}

#[test]
fn production_configuration_requires_clean_https_origin() {
    let key = || ProviderApiKey::new("synthetic-api-key".into()).unwrap();
    assert!(matches!(
        HeadscaleProvider::new(
            "http://headscale.example.test",
            instance(),
            key(),
            HeadscaleClientOptions::default()
        ),
        Err(HeadscaleError::InvalidEndpoint("HTTPS is required"))
    ));
    assert!(
        HeadscaleProvider::new(
            "https://user@headscale.example.test/path?query=1",
            instance(),
            key(),
            HeadscaleClientOptions::default()
        )
        .is_err()
    );
}

#[tokio::test]
async fn missing_version_empty_lists_and_transport_failures_are_truthful() {
    let (endpoint, _) = start_server(vec![(200, r#"{"commit":"synthetic"}"#)]).await;
    let error = test_provider(&endpoint, HeadscaleClientOptions::default())
        .inspect_server()
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedResponse(_)));

    let (endpoint, _) = start_server(vec![(200, r#"{"nodes":[]}"#)]).await;
    let nodes = test_provider(&endpoint, HeadscaleClientOptions::default())
        .list_nodes()
        .await
        .unwrap();
    assert!(nodes.is_empty());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let provider = test_provider(
        &format!("http://{address}"),
        HeadscaleClientOptions::default(),
    );
    let error = provider.list_nodes().await.unwrap_err();
    assert!(matches!(error, ProviderError::Unreachable(_)));
    let health = health_from_error(&error, false);
    assert_eq!(health.status, ProviderHealthStatus::TransportFailure);
}

#[tokio::test]
async fn tls_handshake_failure_is_classified_without_disabling_verification() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 512];
        let _ = socket.read(&mut bytes).await;
        let _ = socket
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    let provider = HeadscaleProvider::new(
        &format!("https://{address}"),
        instance(),
        ProviderApiKey::new("synthetic-api-key".into()).unwrap(),
        HeadscaleClientOptions::default(),
    )
    .unwrap();
    let error = provider.list_nodes().await.unwrap_err();
    assert_eq!(error, ProviderError::TlsFailure);
}

#[tokio::test]
async fn future_version_is_reachable_but_unsupported() {
    let (endpoint, _) = start_server(vec![
        (200, r#"{"version":"v0.30.0","dirty":false}"#),
        (200, include_str!("../fixtures/v0.29.3-health.json")),
    ])
    .await;
    let inspection = test_provider(&endpoint, HeadscaleClientOptions::default())
        .inspect_server()
        .await
        .unwrap();
    assert_eq!(inspection.compatibility, CompatibilityStatus::Unsupported);
    assert!(!inspection.mutation_allowed);
}

#[tokio::test]
async fn doctor_report_is_sanitized_and_mutation_is_always_disabled() {
    let (endpoint, _) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (200, include_str!("../fixtures/v0.29.3-health.json")),
        (200, include_str!("../fixtures/v0.29.3-nodes.json")),
    ])
    .await;
    let provider = test_provider(&endpoint, HeadscaleClientOptions::default());
    let report = provider.doctor().await;
    assert_eq!(report.detected_version.as_deref(), Some("v0.29.3"));
    assert_eq!(report.node_count, Some(2));
    assert_eq!(report.authentication, AuthenticationState::Authenticated);
    assert!(!report.mutation_allowed);
    assert!(report.identity_fields.machine_key);
    let debug = format!("{report:?}");
    assert!(!debug.contains("synthetic-api-key"));
    assert!(!debug.contains("<synthetic-preauth-credential>"));
}

fn test_provider(endpoint: &str, options: HeadscaleClientOptions) -> HeadscaleProvider {
    HeadscaleProvider::new_for_test(
        endpoint,
        instance(),
        ProviderApiKey::new("synthetic-api-key".into()).unwrap(),
        options,
    )
    .unwrap()
}

async fn start_server(responses: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    tokio::spawn(async move {
        for (status, body) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 8192];
            let read = socket.read(&mut buffer).await.unwrap();
            captured
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let reason = if status == 200 { "OK" } else { "Unauthorized" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{address}"), requests)
}
