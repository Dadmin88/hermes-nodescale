use super::*;
use nodescale_domain::{
    Generation, NetworkId, ProviderApiKey, ProviderCredentialReference, ProviderInstanceId,
};
use nodescale_provider::{
    IdentityEvidenceClass, MutationOutcome, MutationProvider, PreAuthAssociationStrength,
    ProviderMutation, ProviderMutationCapability, ReadOnlyProvider,
};
use nodescale_state::{
    HeadscaleImportConfig, MutationAuthorization, ProviderMutationConfiguration, StateStore,
    TlsVerificationPolicy,
};
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
        node.identity_evidence.machine_key.as_ref().unwrap().class(),
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
        PreAuthAssociationStrength::ProviderAuthenticatedRegistration
    );
    assert_eq!(node.pre_auth.as_ref().unwrap().credential_id, "9");
}

#[test]
fn headscale_online_presence_is_preserved() {
    for (online_json, expected) in [
        (None, None),
        (Some("false"), Some(false)),
        (Some("true"), Some(true)),
    ] {
        let online = online_json
            .map(|value| format!(r#","online":{value}"#))
            .unwrap_or_default();
        let fixture =
            format!(r#"{{"nodes":[{{"id":"42","machineKey":"mkey:synthetic"{online}}}]}}"#);
        let nodes = parse_nodes_fixture(&fixture, instance(), fixed_now()).unwrap();
        assert!(nodes[0].identity_evidence.machine_key.is_some());
        assert_eq!(nodes[0].online, expected);
    }
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

fn node_fixture(tags: &[&str], expiry: Option<&str>, machine_key: Option<&str>) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/v0.29.3-node.json")).unwrap();
    let node = value.get_mut("node").unwrap().as_object_mut().unwrap();
    node.insert("tags".into(), serde_json::json!(tags));
    match expiry {
        Some(expiry) => {
            node.insert("expiry".into(), serde_json::json!(expiry));
        }
        None => {
            node.remove("expiry");
        }
    }
    if let Some(machine_key) = machine_key {
        node.insert("machineKey".into(), serde_json::json!(machine_key));
    }
    serde_json::to_string(&value).unwrap()
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
        test_api_key(),
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
    assert!(!requests[0].has_bearer_authorization);
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.has_bearer_authorization)
    );
    assert!(format!("{provider:?}").contains("[REDACTED]"));
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
    assert_eq!(format!("{error:?}"), "AuthenticationFailed");
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
fn pre_auth_key_metadata_is_discarded_before_normalization() {
    let raw = include_str!("../fixtures/v0.29.3-node.json");

    let node = parse_node_fixture(raw, instance(), fixed_now()).unwrap();
    assert_eq!(node.pre_auth.as_ref().unwrap().credential_id, "9");

    let normalized = serde_json::to_string(&node).unwrap();
    let debug = format!("{node:?}");
    assert!(!normalized.contains("preAuthKey"));
    assert!(!debug.contains("preAuthKey"));
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
async fn exact_lookup_rejects_non_authoritative_not_found_response() {
    let identity = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let (endpoint, _) = start_server(vec![(
        404,
        r#"{"code":5,"message":"Not Found","details":[]}"#,
    )])
    .await;

    let error = test_provider(&endpoint, HeadscaleClientOptions::default())
        .get_node(&identity)
        .await
        .expect_err("only Headscale's exact node-absence envelope is authoritative");

    assert!(matches!(error, ProviderError::MalformedResponse(_)));
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

#[tokio::test]
async fn deletion_accepts_only_the_exact_typed_node_absence_envelope() {
    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let (endpoint, requests) = start_server_cases(vec![
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-node.json")),
        TestResponse::normal(200, "{}"),
        TestResponse::normal(404, r#"{"code":5,"message":"node not found","details":[]}"#),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::DeleteNode).await,
                ProviderMutation::DeleteNode { target },
            )
            .await,
        MutationOutcome::Confirmed { .. }
    ));
    assert_eq!(requests.lock().unwrap().len(), 5);

    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let (endpoint, _) = start_server_cases(vec![
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        TestResponse::normal(404, r#"{"code":5,"message":"Not Found","details":[]}"#),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::DeleteNode).await,
                ProviderMutation::DeleteNode { target },
            )
            .await,
        MutationOutcome::Rejected
    ));
}

#[tokio::test]
async fn node_tagging_confirms_repeats_and_classifies_old_readback() {
    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let desired = node_fixture(&["tag:nodescale-worker"], None, None);
    for case in ["confirmed", "apply-close", "repeat", "old"] {
        let mut responses = vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        ];
        match case {
            "repeat" => responses.push(TestResponse::normal(200, desired.clone())),
            "confirmed" | "apply-close" | "old" => {
                responses.push(TestResponse::normal(
                    200,
                    include_str!("../fixtures/v0.29.3-node.json"),
                ));
                responses.push(if case == "apply-close" {
                    TestResponse {
                        status: 200,
                        body: String::new(),
                        mode: ResponseMode::ApplyThenClose,
                    }
                } else {
                    TestResponse::normal(200, "{}")
                });
                responses.push(TestResponse::normal(
                    200,
                    if case == "old" {
                        include_str!("../fixtures/v0.29.3-node.json").to_owned()
                    } else {
                        desired.clone()
                    },
                ));
            }
            _ => unreachable!(),
        }
        let (endpoint, requests) = start_server_cases(responses).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::ReplaceNodeTags).await,
                ProviderMutation::ReplaceNodeTags {
                    target: target.clone(),
                    tags: ["tag:nodescale-worker".to_owned()].into_iter().collect(),
                },
            )
            .await;
        match case {
            "repeat" => assert!(matches!(outcome, MutationOutcome::AlreadySatisfied { .. })),
            "confirmed" | "apply-close" => {
                assert!(matches!(outcome, MutationOutcome::Confirmed { .. }))
            }
            "old" => assert!(matches!(
                outcome,
                MutationOutcome::Failed { retryable: true }
            )),
            _ => unreachable!(),
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), if case == "repeat" { 3 } else { 5 });
        if case != "repeat" {
            assert!(requests[3].starts_with("POST /api/v1/node/42/tags "));
            assert!(requests[3].contains("tag:nodescale-worker"));
        }
    }
}

#[tokio::test]
async fn node_expiry_confirms_repeats_and_classifies_old_readback() {
    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let expired = node_fixture(&["tag:worker"], Some("2020-01-01T00:00:00Z"), None);
    for case in ["confirmed", "apply-close", "repeat", "old"] {
        let mut responses = vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        ];
        match case {
            "repeat" => responses.push(TestResponse::normal(200, expired.clone())),
            "confirmed" | "apply-close" | "old" => {
                responses.push(TestResponse::normal(
                    200,
                    include_str!("../fixtures/v0.29.3-node.json"),
                ));
                responses.push(if case == "apply-close" {
                    TestResponse {
                        status: 200,
                        body: String::new(),
                        mode: ResponseMode::ApplyThenClose,
                    }
                } else {
                    TestResponse::normal(200, "{}")
                });
                responses.push(TestResponse::normal(
                    200,
                    if case == "old" {
                        include_str!("../fixtures/v0.29.3-node.json").to_owned()
                    } else {
                        expired.clone()
                    },
                ));
            }
            _ => unreachable!(),
        }
        let (endpoint, requests) = start_server_cases(responses).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::ExpireNode).await,
                ProviderMutation::ExpireNode {
                    target: target.clone(),
                },
            )
            .await;
        match case {
            "repeat" => assert!(matches!(outcome, MutationOutcome::AlreadySatisfied { .. })),
            "confirmed" | "apply-close" => {
                assert!(matches!(outcome, MutationOutcome::Confirmed { .. }))
            }
            "old" => assert!(matches!(
                outcome,
                MutationOutcome::Failed { retryable: true }
            )),
            _ => unreachable!(),
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), if case == "repeat" { 3 } else { 5 });
        if case != "repeat" {
            assert!(requests[3].starts_with("POST /api/v1/node/42/expire "));
        }
    }
}

#[tokio::test]
async fn node_delete_apply_close_old_and_unavailable_readback_are_typed() {
    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    for case in ["apply-close", "old", "unavailable"] {
        let after = match case {
            "apply-close" => {
                TestResponse::normal(404, r#"{"code":5,"message":"node not found","details":[]}"#)
            }
            "old" => TestResponse::normal(200, include_str!("../fixtures/v0.29.3-node.json")),
            "unavailable" => {
                TestResponse::normal(500, r#"{"code":13,"message":"internal","details":[]}"#)
            }
            _ => unreachable!(),
        };
        let (endpoint, requests) = start_server_cases(vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-node.json")),
            TestResponse {
                status: 200,
                body: String::new(),
                mode: ResponseMode::ApplyThenClose,
            },
            after,
        ])
        .await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::DeleteNode).await,
                ProviderMutation::DeleteNode {
                    target: target.clone(),
                },
            )
            .await;
        match case {
            "apply-close" => assert!(matches!(outcome, MutationOutcome::Confirmed { .. })),
            "old" => assert!(matches!(
                outcome,
                MutationOutcome::Failed { retryable: true }
            )),
            "unavailable" => assert!(matches!(
                outcome,
                MutationOutcome::Ambiguous {
                    reason: MutationAmbiguity::ReadBackUnavailable
                }
            )),
            _ => unreachable!(),
        }
        assert_eq!(requests.lock().unwrap().len(), 5);
    }
}

#[tokio::test]
async fn node_identity_conflict_is_rejected_before_write() {
    let target = parse_node_fixture(
        include_str!("../fixtures/v0.29.3-node.json"),
        instance(),
        fixed_now(),
    )
    .unwrap()
    .identity;
    let conflicting = node_fixture(&["tag:worker"], None, Some("mkey:different"));
    let (endpoint, requests) = start_server_cases(vec![
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        TestResponse::normal(200, conflicting),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::ReplaceNodeTags).await,
                ProviderMutation::ReplaceNodeTags {
                    target,
                    tags: ["tag:nodescale-worker".to_owned()].into_iter().collect(),
                },
            )
            .await,
        MutationOutcome::Conflict
    ));
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn database_policy_flow_reconciles_every_potential_put_once() {
    let old = "{}";
    let desired = r#"{"acls":[]}"#;
    for case in [
        "repeat",
        "revision-conflict",
        "check-reject",
        "put-ok-match",
        "put-http-match",
        "put-auth-match",
        "put-close-match",
        "put-ok-differ",
        "put-ok-unavailable",
    ] {
        let before = if case == "repeat" { desired } else { old };
        let mut responses = vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
            TestResponse::normal(200, serde_json::json!({"policy": before}).to_string()),
        ];
        match case {
            "repeat" | "revision-conflict" => {}
            "check-reject" => responses.push(TestResponse::normal(
                400,
                r#"{"code":3,"message":"invalid policy","details":[]}"#,
            )),
            "put-ok-match" | "put-http-match" | "put-auth-match" | "put-close-match"
            | "put-ok-differ" | "put-ok-unavailable" => {
                responses.push(TestResponse::normal(200, "{}"));
                responses.push(match case {
                    "put-http-match" => TestResponse::normal(
                        500,
                        r#"{"code":13,"message":"internal","details":[]}"#,
                    ),
                    "put-auth-match" => TestResponse::normal(401, "Unauthorized"),
                    "put-close-match" => TestResponse {
                        status: 200,
                        body: String::new(),
                        mode: ResponseMode::ApplyThenClose,
                    },
                    _ => TestResponse::normal(200, "{}"),
                });
                responses.push(match case {
                    "put-ok-differ" => {
                        TestResponse::normal(200, serde_json::json!({"policy": old}).to_string())
                    }
                    "put-ok-unavailable" => TestResponse::normal(
                        500,
                        r#"{"code":13,"message":"internal","details":[]}"#,
                    ),
                    _ => TestResponse::normal(
                        200,
                        serde_json::json!({"policy": desired}).to_string(),
                    ),
                });
            }
            _ => unreachable!(),
        }
        let (endpoint, requests) = start_server_cases(responses).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let expected_revision = if case == "revision-conflict" {
            "sha256:not-current".to_owned()
        } else {
            policy_revision(before)
        };
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::ManagePolicy).await,
                ProviderMutation::ApplyPolicy {
                    expected_revision,
                    policy: desired.into(),
                },
            )
            .await;
        match case {
            "repeat" => assert!(matches!(outcome, MutationOutcome::AlreadySatisfied { .. })),
            "revision-conflict" => assert!(matches!(outcome, MutationOutcome::Conflict)),
            "check-reject" => assert!(matches!(outcome, MutationOutcome::Rejected)),
            "put-ok-match" | "put-http-match" | "put-auth-match" | "put-close-match" => {
                assert!(matches!(outcome, MutationOutcome::Confirmed { .. }))
            }
            "put-ok-differ" => assert!(matches!(
                outcome,
                MutationOutcome::Ambiguous {
                    reason: MutationAmbiguity::PotentiallyApplied
                }
            )),
            "put-ok-unavailable" => assert!(matches!(
                outcome,
                MutationOutcome::Ambiguous {
                    reason: MutationAmbiguity::ReadBackUnavailable
                }
            )),
            _ => unreachable!(),
        }
        let requests = requests.lock().unwrap();
        let expected_count = match case {
            "repeat" | "revision-conflict" => 3,
            "check-reject" => 4,
            _ => 6,
        };
        assert_eq!(requests.len(), expected_count, "{case}");
        if expected_count == 6 {
            assert!(requests[4].starts_with("PUT /api/v1/policy "));
            assert!(requests[5].starts_with("GET /api/v1/policy "));
        }
    }
}

#[tokio::test]
async fn file_and_unknown_policy_modes_are_exact_zero_traffic_unsupported() {
    assert_eq!(POLICY_MUTATION_UNSUPPORTED, "policy mutation unsupported");
    for mode in [
        nodescale_provider::MutationPolicyMode::File,
        nodescale_provider::MutationPolicyMode::Unknown,
    ] {
        let (endpoint, requests) = start_server_cases(Vec::new()).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(mode),
        )
        .unwrap();
        assert!(matches!(
            provider
                .execute_mutation(
                    mutation_authorization(ProviderMutationCapability::ManagePolicy).await,
                    ProviderMutation::ApplyPolicy {
                        expected_revision: policy_revision("{}"),
                        policy: r#"{"acls":[]}"#.into(),
                    },
                )
                .await,
            MutationOutcome::Unsupported
        ));
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn loopback_harness_exercises_chunked_oversize_and_apply_close_modes() {
    let (endpoint, _) = start_server_cases(vec![TestResponse {
        status: 200,
        body: r#"{"nodes":[]}"#.into(),
        mode: ResponseMode::Chunked,
    }])
    .await;
    assert!(
        test_provider(&endpoint, HeadscaleClientOptions::default())
            .list_nodes()
            .await
            .unwrap()
            .is_empty()
    );

    let (endpoint, _) = start_server_cases(vec![TestResponse {
        status: 200,
        body: String::new(),
        mode: ResponseMode::DeclaredOversize(65),
    }])
    .await;
    let error = test_provider(
        &endpoint,
        HeadscaleClientOptions {
            max_response_bytes: 64,
            ..HeadscaleClientOptions::default()
        },
    )
    .list_nodes()
    .await
    .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedResponse(_)));

    let (endpoint, requests) = start_server_cases(vec![TestResponse {
        status: 200,
        body: String::new(),
        mode: ResponseMode::ApplyThenClose,
    }])
    .await;
    assert!(matches!(
        test_provider(&endpoint, HeadscaleClientOptions::default())
            .list_nodes()
            .await,
        Err(ProviderError::Unreachable(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn production_configuration_requires_clean_https_origin() {
    let key = || test_api_key();
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

#[test]
fn custom_trust_root_is_additive_bounded_and_keeps_options_copy() {
    fn requires_copy<T: Copy>() {}
    requires_copy::<HeadscaleClientOptions>();

    let malformed = HeadscaleCustomRootCa::PemBytes(
        b"-----BEGIN CERTIFICATE-----\nDO_NOT_PRINT_PEM_BYTES\n-----END CERTIFICATE-----\n"
            .to_vec(),
    );
    assert!(matches!(
        HeadscaleProvider::new_with_custom_root_ca(
            "https://headscale.example.test",
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            malformed,
        ),
        Err(HeadscaleError::CustomRootCaMalformed)
    ));

    let oversized = HeadscaleCustomRootCa::PemBytes(vec![0; MAX_CUSTOM_ROOT_CA_BYTES + 1]);
    assert!(matches!(
        HeadscaleProvider::new_with_custom_root_ca(
            "https://headscale.example.test",
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            oversized,
        ),
        Err(HeadscaleError::CustomRootCaTooLarge)
    ));
}

#[test]
fn custom_trust_root_requires_exactly_one_ca_certificate() {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_pem = ca_params.self_signed(&key_pair).unwrap().pem();

    let source = HeadscaleCustomRootCa::PemBytes(ca_pem.as_bytes().to_vec());
    assert!(!format!("{source:?}").contains(&ca_pem));
    HeadscaleProvider::new_with_custom_root_ca(
        "https://headscale.example.test",
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        source,
    )
    .unwrap();

    let duplicate = format!("{ca_pem}{ca_pem}");
    assert!(matches!(
        HeadscaleProvider::new_with_custom_root_ca(
            "https://headscale.example.test",
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            HeadscaleCustomRootCa::PemBytes(duplicate.into_bytes()),
        ),
        Err(HeadscaleError::CustomRootCaMalformed)
    ));

    let leaf_key_pair = rcgen::KeyPair::generate().unwrap();
    let leaf_pem = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&leaf_key_pair)
        .unwrap()
        .pem();
    assert!(matches!(
        HeadscaleProvider::new_with_custom_root_ca(
            "https://headscale.example.test",
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            HeadscaleCustomRootCa::PemBytes(leaf_pem.into_bytes()),
        ),
        Err(HeadscaleError::CustomRootCaNotCertificateAuthority)
    ));
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
        test_api_key(),
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
    assert!(!debug.contains("runtime-join-"));
    assert!(!debug.contains("preAuthKey"));
}

fn network() -> NetworkId {
    NetworkId::parse("223e4567-e89b-42d3-a456-426614174000").unwrap()
}

fn mutation_config(mode: nodescale_provider::MutationPolicyMode) -> HeadscaleMutationTransport {
    HeadscaleMutationTransport::new(
        network(),
        Generation::initial(),
        Generation::initial(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        mode,
    )
}

struct StateImportProvider;
#[async_trait::async_trait]
impl ReadOnlyProvider for StateImportProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        instance()
    }
    async fn inspect_server(
        &self,
    ) -> Result<nodescale_provider::ServerInspection, nodescale_provider::ProviderError> {
        Ok(nodescale_provider::ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: instance(),
            compatibility: nodescale_provider::CompatibilityStatus::Compatible,
            capabilities: std::collections::BTreeSet::new(),
            constraints: vec![],
            mutation_allowed: false,
        })
    }
    async fn list_nodes(
        &self,
    ) -> Result<Vec<nodescale_provider::ProviderNode>, nodescale_provider::ProviderError> {
        Ok(vec![])
    }
    async fn get_node(
        &self,
        _: &nodescale_domain::ProviderIdentity,
    ) -> Result<Option<nodescale_provider::ProviderNode>, nodescale_provider::ProviderError> {
        Ok(None)
    }
    async fn provider_health(
        &self,
    ) -> Result<nodescale_provider::ProviderHealth, nodescale_provider::ProviderError> {
        unreachable!()
    }
}

async fn mutation_authorization(capability: ProviderMutationCapability) -> MutationAuthorization {
    let store = StateStore::open_in_memory().unwrap();
    let imported = nodescale_domain::Network::new(
        network(),
        "headscale-mutation-test",
        nodescale_domain::ProviderKind::Headscale,
        instance(),
        chrono::Utc::now(),
    )
    .unwrap();
    store
        .import_headscale_network(
            &imported,
            &HeadscaleImportConfig::new(
                "https://headscale.example.test",
                instance(),
                "secret://vault/nodescale#key",
                "v0.29.3",
                TlsVerificationPolicy::Verify,
            )
            .unwrap(),
            &StateImportProvider,
            chrono::Utc::now(),
            nodescale_domain::AuditActor::system(),
        )
        .await
        .unwrap();
    store
        .replace_provider_mutation_configuration(
            network(),
            None,
            None,
            ProviderMutationConfiguration::new(
                instance(),
                Generation::initial(),
                Generation::initial(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "headscale",
                "v0.29.3",
                true,
                false,
                chrono::Utc::now() - chrono::Duration::minutes(1),
                chrono::Utc::now() + chrono::Duration::minutes(1),
                nodescale_provider::MutationPolicyMode::Database,
                [capability],
            )
            .unwrap(),
            nodescale_domain::AuditActor::system(),
        )
        .unwrap();
    store
        .issue_mutation_authorization(network(), instance(), capability, chrono::Utc::now())
        .unwrap()
}

#[tokio::test]
async fn principal_mutation_uses_exact_order_auth_and_body_with_readback() {
    let (endpoint, requests) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (200, include_str!("../fixtures/v0.29.3-health.json")),
        (200, r#"{"users":[]}"#),
        (200, r#"{"user":{"id":"7","name":"worker"}}"#),
        (200, r#"{"users":[{"id":"7","name":"worker"}]}"#),
        (200, r#"{"users":[{"id":"7","name":"worker"}]}"#),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();

    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into(),
                },
            )
            .await,
        MutationOutcome::Confirmed { .. }
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("GET /version "));
    assert!(requests[1].starts_with("GET /api/v1/health "));
    assert!(requests[2].starts_with("GET /api/v1/user?name=worker "));
    assert_eq!(requests[3].method, "POST");
    assert_eq!(requests[3].target, "/api/v1/user");
    assert!(requests[3].has_bearer_authorization);
    assert_eq!(
        std::str::from_utf8(&requests[3].body).unwrap(),
        "{\"displayName\":\"\",\"email\":\"\",\"name\":\"worker\",\"pictureUrl\":\"\"}"
    );
    assert!(requests[4].starts_with("GET /api/v1/user?id=7 "));
}

#[tokio::test]
async fn preauth_response_secret_is_redacted_and_create_has_no_retry() {
    let secret = runtime_join_secret();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let expiration = expires_at.to_rfc3339();
    let create_response = format!(
        r#"{{"preAuthKey":{{"id":"9","key":"{secret}","user":{{"id":"7","name":"worker"}},"reusable":false,"ephemeral":false,"expiration":"{expiration}","aclTags":[]}}}}"#
    );
    let list_response = format!(
        r#"{{"preAuthKeys":[{{"id":"9","key":"{secret}","user":{{"id":"7","name":"worker"}},"reusable":false,"ephemeral":false,"expiration":"{expiration}","aclTags":[]}}]}}"#
    );
    let (endpoint, requests) = start_server_cases(vec![
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
        TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        TestResponse::normal(200, r#"{"users":[{"id":"7","name":"worker"}]}"#),
        TestResponse::normal(200, create_response),
        TestResponse::normal(200, list_response),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    let mut request = nodescale_provider::JoinCredentialRequest::single_use("7");
    request.expires_at = Some(expires_at);
    let outcome = provider
        .execute_mutation(
            mutation_authorization(ProviderMutationCapability::CreateJoinCredential).await,
            ProviderMutation::CreateJoinCredential { request },
        )
        .await;
    assert!(
        matches!(outcome, MutationOutcome::Confirmed { .. }),
        "{outcome:?}"
    );
    assert!(!format!("{outcome:?}").contains(&secret));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[2].starts_with("GET /api/v1/user?id=7 "));
    assert!(requests[3].starts_with("POST /api/v1/preauthkey "));
    assert!(requests[3].contains("\"reusable\":false"));
    assert!(requests[3].contains("\"ephemeral\":false"));
    assert!(requests[4].starts_with("GET /api/v1/preauthkey "));
}

#[tokio::test]
async fn credential_create_malformed_oversize_and_apply_close_are_secret_unavailable() {
    for mode in ["malformed", "oversize", "apply-close"] {
        let create = match mode {
            "malformed" => TestResponse::normal(200, "{"),
            "oversize" => TestResponse {
                status: 200,
                body: "{}".into(),
                mode: ResponseMode::DeclaredOversize(257),
            },
            "apply-close" => TestResponse {
                status: 200,
                body: String::new(),
                mode: ResponseMode::ApplyThenClose,
            },
            _ => unreachable!(),
        };
        let (endpoint, requests) = start_server_cases(vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
            TestResponse::normal(200, r#"{"users":[{"id":"7","name":"worker"}]}"#),
            create,
        ])
        .await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions {
                max_response_bytes: 256,
                ..HeadscaleClientOptions::default()
            },
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let mut request = nodescale_provider::JoinCredentialRequest::single_use("7");
        request.expires_at = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
        assert!(matches!(
            provider
                .execute_mutation(
                    mutation_authorization(ProviderMutationCapability::CreateJoinCredential).await,
                    ProviderMutation::CreateJoinCredential { request },
                )
                .await,
            MutationOutcome::Ambiguous {
                reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable
            }
        ));
        assert_eq!(requests.lock().unwrap().len(), 4, "{mode}");
    }
}

#[tokio::test]
async fn credential_invalidation_uses_exact_list_readback_for_certainty() {
    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
    let post_dispatch_expiration =
        (chrono::Utc::now() + chrono::Duration::milliseconds(75)).to_rfc3339();
    let active = format!(
        r#"{{"preAuthKeys":[{{"id":"9","user":{{"id":"7","name":"worker"}},"reusable":false,"ephemeral":false,"expiration":"{expiration}","aclTags":[]}}]}}"#
    );
    let duplicate = format!(
        r#"{{"preAuthKeys":[{{"id":"9","user":{{"id":"7","name":"worker"}},"expiration":"{expiration}"}},{{"id":"9","user":{{"id":"7","name":"worker"}},"expiration":"{expiration}"}}]}}"#
    );
    for case in [
        "duplicate",
        "absent",
        "apply-close",
        "post-dispatch-expired",
        "old",
        "unavailable",
    ] {
        let mut responses = vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        ];
        match case {
            "duplicate" => responses.push(TestResponse::normal(200, duplicate.clone())),
            "absent" => responses.push(TestResponse::normal(200, r#"{"preAuthKeys":[]}"#)),
            "apply-close" => {
                responses.push(TestResponse::normal(200, active.clone()));
                responses.push(TestResponse {
                    status: 200,
                    body: String::new(),
                    mode: ResponseMode::ApplyThenClose,
                });
                responses.push(TestResponse::normal(200, r#"{"preAuthKeys":[]}"#));
            }
            "post-dispatch-expired" => {
                let expired = format!(
                    r#"{{"preAuthKeys":[{{"id":"9","user":{{"id":"7","name":"worker"}},"reusable":false,"ephemeral":false,"expiration":"{post_dispatch_expiration}","aclTags":[]}}]}}"#
                );
                responses.push(TestResponse::normal(200, active.clone()));
                responses.push(TestResponse {
                    status: 200,
                    body: "{}".into(),
                    mode: ResponseMode::Delayed(Duration::from_millis(150)),
                });
                responses.push(TestResponse::normal(200, expired));
            }
            "old" => {
                responses.push(TestResponse::normal(200, active.clone()));
                responses.push(TestResponse::normal(200, "{}"));
                responses.push(TestResponse::normal(200, active.clone()));
            }
            "unavailable" => {
                responses.push(TestResponse::normal(200, active.clone()));
                responses.push(TestResponse::normal(200, "{}"));
                responses.push(TestResponse::normal(
                    500,
                    r#"{"code":13,"message":"internal","details":[]}"#,
                ));
            }
            _ => unreachable!(),
        }
        let (endpoint, requests) = start_server_cases(responses).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::InvalidateJoinCredential).await,
                ProviderMutation::RevokeJoinCredential {
                    credential: ProviderCredentialReference::new("9").unwrap(),
                },
            )
            .await;
        match case {
            "duplicate" => assert!(
                matches!(outcome, MutationOutcome::Conflict),
                "duplicate classified as {outcome:?}"
            ),
            "absent" => assert!(matches!(outcome, MutationOutcome::AlreadySatisfied { .. })),
            "apply-close" => assert!(matches!(outcome, MutationOutcome::Confirmed { .. })),
            "post-dispatch-expired" => {
                assert!(matches!(outcome, MutationOutcome::Confirmed { .. }))
            }
            "old" => assert!(matches!(
                outcome,
                MutationOutcome::Failed { retryable: true }
            )),
            "unavailable" => assert!(matches!(
                outcome,
                MutationOutcome::Ambiguous {
                    reason: MutationAmbiguity::ReadBackUnavailable
                }
            )),
            _ => unreachable!(),
        }
        let expected = if matches!(case, "duplicate" | "absent") {
            3
        } else {
            5
        };
        assert_eq!(requests.lock().unwrap().len(), expected, "{case}");
    }
}

#[tokio::test]
async fn dirty_mutation_is_denied_before_any_write() {
    let (endpoint, requests) =
        start_server(vec![(200, r#"{"version":"v0.29.3","dirty":true}"#)]).await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into()
                },
            )
            .await,
        MutationOutcome::CompatibilityBlocked
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /version "));
}

#[tokio::test]
async fn file_mode_policy_returns_the_exact_unsupported_fallback_without_write() {
    assert_eq!(POLICY_MUTATION_UNSUPPORTED, "policy mutation unsupported");
    let (endpoint, requests) = start_server(vec![]).await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::File),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::ManagePolicy).await,
                ProviderMutation::ApplyPolicy {
                    expected_revision: "sha256:ignored".into(),
                    policy: "{}".into(),
                },
            )
            .await,
        MutationOutcome::Unsupported
    ));
    let requests = requests.lock().unwrap();
    assert!(requests.is_empty());
}

#[tokio::test]
async fn mutation_local_authority_and_intent_denials_are_zero_network() {
    let (endpoint, requests) = start_server(vec![]).await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "bad name".into(),
                },
            )
            .await,
        MutationOutcome::Rejected
    ));

    let fingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cases = [
        (
            instance(),
            HeadscaleMutationTransport::new(
                NetworkId::new(),
                Generation::initial(),
                Generation::initial(),
                fingerprint,
                nodescale_provider::MutationPolicyMode::Database,
            ),
            ProviderMutationCapability::EnsureNetworkPrincipal,
        ),
        (
            ProviderInstanceId::new(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
            ProviderMutationCapability::EnsureNetworkPrincipal,
        ),
        (
            instance(),
            HeadscaleMutationTransport::new(
                network(),
                Generation::new(2).unwrap(),
                Generation::initial(),
                fingerprint,
                nodescale_provider::MutationPolicyMode::Database,
            ),
            ProviderMutationCapability::EnsureNetworkPrincipal,
        ),
        (
            instance(),
            HeadscaleMutationTransport::new(
                network(),
                Generation::initial(),
                Generation::new(2).unwrap(),
                fingerprint,
                nodescale_provider::MutationPolicyMode::Database,
            ),
            ProviderMutationCapability::EnsureNetworkPrincipal,
        ),
        (
            instance(),
            HeadscaleMutationTransport::new(
                network(),
                Generation::initial(),
                Generation::initial(),
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                nodescale_provider::MutationPolicyMode::Database,
            ),
            ProviderMutationCapability::EnsureNetworkPrincipal,
        ),
        (
            instance(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
            ProviderMutationCapability::DeleteNode,
        ),
    ];
    for (provider_instance, transport, authorization_capability) in cases {
        let denied = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            provider_instance,
            test_api_key(),
            HeadscaleClientOptions::default(),
            transport,
        )
        .unwrap();
        assert!(matches!(
            denied
                .execute_mutation(
                    mutation_authorization(authorization_capability).await,
                    ProviderMutation::EnsureNetworkPrincipal {
                        principal: "worker".into(),
                    },
                )
                .await,
            MutationOutcome::Rejected
        ));
    }
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn principal_repeat_duplicate_and_lost_response_stable_id_reconciliation_are_typed() {
    for case in ["repeat", "duplicate", "lost-confirmed"] {
        let mut responses = vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
        ];
        match case {
            "repeat" => responses.push(TestResponse::normal(
                200,
                r#"{"users":[{"id":"7","name":"worker"}]}"#,
            )),
            "duplicate" => responses.push(TestResponse::normal(
                200,
                r#"{"users":[{"id":"7","name":"worker"},{"id":"8","name":"worker"}]}"#,
            )),
            "lost-confirmed" => {
                responses.push(TestResponse::normal(200, r#"{"users":[]}"#));
                responses.push(TestResponse {
                    status: 200,
                    body: String::new(),
                    mode: ResponseMode::ApplyThenClose,
                });
                responses.push(TestResponse::normal(
                    200,
                    r#"{"users":[{"id":"7","name":"worker"}]}"#,
                ));
                responses.push(TestResponse::normal(
                    200,
                    r#"{"users":[{"id":"7","name":"worker"}]}"#,
                ));
            }
            _ => unreachable!(),
        }
        let (endpoint, requests) = start_server_cases(responses).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into(),
                },
            )
            .await;
        match case {
            "repeat" => assert!(matches!(outcome, MutationOutcome::AlreadySatisfied { .. })),
            "duplicate" => assert!(matches!(outcome, MutationOutcome::Conflict)),
            "lost-confirmed" => {
                assert!(matches!(outcome, MutationOutcome::Confirmed { .. }))
            }
            _ => unreachable!(),
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), if case == "lost-confirmed" { 5 } else { 3 });
        if case == "lost-confirmed" {
            assert!(requests[4].starts_with("GET /api/v1/user?name=worker "));
        }
    }
}

#[tokio::test]
async fn mutation_runtime_compatibility_requires_exact_clean_v0293() {
    for case in [
        "dirty",
        "prerelease",
        "build-suffixed",
        "future",
        "malformed",
        "missing-dirty",
    ] {
        let body = if case == "malformed" {
            "{".to_owned()
        } else {
            let mut value: serde_json::Value =
                serde_json::from_str(include_str!("../fixtures/v0.29.3-version.json")).unwrap();
            match case {
                "dirty" => value["dirty"] = serde_json::json!(true),
                "prerelease" => value["version"] = serde_json::json!("v0.29.3-rc.1"),
                "build-suffixed" => value["version"] = serde_json::json!("v0.29.3+local"),
                "future" => value["version"] = serde_json::json!("v0.29.4"),
                "missing-dirty" => {
                    value.as_object_mut().unwrap().remove("dirty");
                }
                _ => unreachable!(),
            }
            serde_json::to_string(&value).unwrap()
        };
        let (endpoint, requests) = start_server_cases(vec![TestResponse::normal(200, body)]).await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        assert!(matches!(
            provider
                .execute_mutation(
                    mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal)
                        .await,
                    ProviderMutation::EnsureNetworkPrincipal {
                        principal: "worker".into(),
                    },
                )
                .await,
            MutationOutcome::CompatibilityBlocked
        ));
        assert_eq!(requests.lock().unwrap().len(), 1, "{case}");
    }
}

#[tokio::test]
async fn principal_response_loss_reconciles_old_and_conflicting_readback_once() {
    for (after, expected_conflict) in [
        (r#"{"users":[]}"#, false),
        (r#"{"users":[{"id":"8","name":"other"}]}"#, true),
    ] {
        let (endpoint, requests) = start_server_cases(vec![
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-version.json")),
            TestResponse::normal(200, include_str!("../fixtures/v0.29.3-health.json")),
            TestResponse::normal(200, r#"{"users":[]}"#),
            TestResponse {
                status: 200,
                body: String::new(),
                mode: ResponseMode::ApplyThenClose,
            },
            TestResponse::normal(200, after),
        ])
        .await;
        let provider = HeadscaleMutationProvider::new_for_test(
            &endpoint,
            instance(),
            test_api_key(),
            HeadscaleClientOptions::default(),
            mutation_config(nodescale_provider::MutationPolicyMode::Database),
        )
        .unwrap();
        let outcome = provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into(),
                },
            )
            .await;
        if expected_conflict {
            assert!(matches!(outcome, MutationOutcome::Conflict), "{outcome:?}");
        } else {
            assert!(
                matches!(outcome, MutationOutcome::Failed { retryable: true }),
                "{outcome:?}"
            );
        }
        assert_eq!(requests.lock().unwrap().len(), 5);
    }
}

#[tokio::test]
async fn mutation_http_401_is_exactly_authentication_failed_without_retry() {
    let (endpoint, requests) = start_server(vec![
        (200, include_str!("../fixtures/v0.29.3-version.json")),
        (401, "Unauthorized"),
    ])
    .await;
    let provider = HeadscaleMutationProvider::new_for_test(
        &endpoint,
        instance(),
        test_api_key(),
        HeadscaleClientOptions::default(),
        mutation_config(nodescale_provider::MutationPolicyMode::Database),
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute_mutation(
                mutation_authorization(ProviderMutationCapability::EnsureNetworkPrincipal).await,
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into()
                }
            )
            .await,
        MutationOutcome::AuthenticationFailed
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

fn test_api_key() -> ProviderApiKey {
    ProviderApiKey::new(format!("test-{}", std::process::id())).unwrap()
}

fn runtime_join_secret() -> String {
    format!(
        "runtime-join-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn test_provider(endpoint: &str, options: HeadscaleClientOptions) -> HeadscaleProvider {
    HeadscaleProvider::new_for_test(endpoint, instance(), test_api_key(), options).unwrap()
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    has_bearer_authorization: bool,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn starts_with(&self, prefix: &str) -> bool {
        format!("{} {} ", self.method, self.target).starts_with(prefix)
    }

    fn contains(&self, needle: &str) -> bool {
        if needle.eq_ignore_ascii_case("authorization: Bearer ***") {
            return self.has_bearer_authorization;
        }
        let body = std::str::from_utf8(&self.body).unwrap_or("");
        format!("{} {} {body}", self.method, self.target).contains(needle)
    }
}

#[derive(Debug)]
enum ResponseMode {
    Normal,
    Chunked,
    DeclaredOversize(usize),
    ApplyThenClose,
    Delayed(Duration),
}

#[derive(Debug)]
struct TestResponse {
    status: u16,
    body: String,
    mode: ResponseMode,
}

impl TestResponse {
    fn normal(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            mode: ResponseMode::Normal,
        }
    }
}

async fn start_server(
    responses: Vec<(u16, &'static str)>,
) -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    start_server_cases(
        responses
            .into_iter()
            .map(|(status, body)| TestResponse::normal(status, body))
            .collect(),
    )
    .await
}

async fn start_server_cases(
    responses: Vec<TestResponse>,
) -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    tokio::spawn(async move {
        for response in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_complete_request(&mut socket).await.unwrap();
            captured.lock().unwrap().push(request);
            match response.mode {
                ResponseMode::ApplyThenClose => {}
                ResponseMode::Delayed(delay) => {
                    tokio::time::sleep(delay).await;
                    write_response(&mut socket, response.status, &response.body).await;
                }
                ResponseMode::Normal => {
                    write_response(&mut socket, response.status, &response.body).await;
                }
                ResponseMode::Chunked => {
                    let midpoint = response.body.len() / 2;
                    let (first, second) = response.body.split_at(midpoint);
                    let reason = if response.status == 200 {
                        "OK"
                    } else {
                        "Error"
                    };
                    let headers = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                        response.status
                    );
                    socket.write_all(headers.as_bytes()).await.unwrap();
                    for chunk in [first, second] {
                        socket
                            .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                            .await
                            .unwrap();
                        socket.write_all(chunk.as_bytes()).await.unwrap();
                        socket.write_all(b"\r\n").await.unwrap();
                    }
                    socket.write_all(b"0\r\n\r\n").await.unwrap();
                }
                ResponseMode::DeclaredOversize(length) => {
                    let reason = if response.status == 200 {
                        "OK"
                    } else {
                        "Error"
                    };
                    let headers = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
                        response.status
                    );
                    socket.write_all(headers.as_bytes()).await.unwrap();
                }
            }
        }
    });
    (format!("http://{address}"), requests)
}

async fn read_complete_request(
    socket: &mut tokio::net::TcpStream,
) -> std::io::Result<CapturedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request ended before headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request headers are not UTF-8",
        )
    })?;
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default().to_owned();
    let mut content_length = 0_usize;
    let mut has_bearer_authorization = false;
    for header in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid content length")
            })?;
        }
        if name.eq_ignore_ascii_case("authorization") {
            has_bearer_authorization = value.trim_start().starts_with("Bearer ");
        }
    }
    let mut body = bytes[header_end..].to_vec();
    while body.len() < content_length {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request ended before declared body",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(CapturedRequest {
        method,
        target,
        has_bearer_authorization,
        body,
    })
}

async fn write_response(socket: &mut tokio::net::TcpStream, status: u16, body: &str) {
    let reason = if status == 200 { "OK" } else { "Error" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
}
