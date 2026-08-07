use nodescale_provider::{
    CompatibilityStatus, JoinCredentialRequest, Provider, ProviderCapability, ProviderError,
    ProviderHealthStatus,
};
use nodescale_provider_fake::*;

#[test]
fn compatibility_never_implies_unknown_mutation_permission() {
    for status in [
        CompatibilityStatus::ReadOnlyDegraded,
        CompatibilityStatus::Unsupported,
        CompatibilityStatus::Unreachable,
        CompatibilityStatus::AuthenticationFailed,
    ] {
        assert!(!status.allows_mutation());
    }
}

#[test]
fn fake_provider_supports_deterministic_node_lifecycle() {
    let mut provider = FakeProvider::compatible("fixture-1");
    let credential = provider
        .create_join_credential(&JoinCredentialRequest::single_use("worker"))
        .unwrap();
    let node = provider.observe_join(&credential, "worker-1").unwrap();
    assert_eq!(node.identity.node_id.as_str(), "fake-node-0001");
    assert_ne!(node.identity.node_id.as_str(), node.hostname);
    provider
        .set_node_tags(&node.identity, &["role:worker".into()])
        .unwrap();
    provider.expire_node(&node.identity).unwrap();
    provider.delete_node(&node.identity).unwrap();
    assert!(provider.get_node(&node.identity).unwrap().is_none());
}

#[test]
fn fake_provider_models_degraded_unsupported_auth_and_failures() {
    assert_eq!(
        FakeProvider::degraded("d")
            .inspect_server()
            .unwrap()
            .compatibility,
        CompatibilityStatus::ReadOnlyDegraded
    );
    assert_eq!(
        FakeProvider::unsupported("u")
            .inspect_server()
            .unwrap()
            .compatibility,
        CompatibilityStatus::Unsupported
    );
    assert!(matches!(
        FakeProvider::authentication_failed("a").list_nodes(),
        Err(ProviderError::AuthenticationFailed)
    ));
    let mut provider = FakeProvider::compatible("f");
    provider.fail_next(FakeFailure::Unavailable);
    assert!(matches!(
        provider.list_nodes(),
        Err(ProviderError::Unreachable(_))
    ));
}

#[test]
fn ambiguous_mutation_does_not_claim_success() {
    let mut provider = FakeProvider::compatible("ambiguous");
    provider.fail_next(FakeFailure::AmbiguousMutation);
    assert!(matches!(
        provider.create_join_credential(&JoinCredentialRequest::single_use("worker")),
        Err(ProviderError::AmbiguousMutation(_))
    ));
}

#[test]
fn self_reported_keryx_identity_is_not_part_of_provider_model() {
    let mut provider = FakeProvider::compatible("identity");
    let credential = provider
        .create_join_credential(&JoinCredentialRequest::single_use("controller"))
        .unwrap();
    let node = provider.observe_join(&credential, "controller-1").unwrap();
    assert_eq!(node.identity.provider_instance_id, provider.instance_id());
    assert!(!format!("{node:?}").contains("keryx_peer"));
}

#[tokio::test]
async fn async_read_contract_preserves_fake_normalized_semantics() {
    let mut provider = FakeProvider::compatible("shared-contract");
    let credential = provider
        .create_join_credential(&JoinCredentialRequest::single_use("worker"))
        .unwrap();
    let identity = provider
        .observe_join(&credential, "worker-1")
        .unwrap()
        .identity;
    let inspection = nodescale_provider::ReadOnlyProvider::inspect_server(&provider)
        .await
        .unwrap();
    assert_eq!(inspection.provider_name, "nodescale-fake");
    assert!(!inspection.mutation_allowed);
    assert!(inspection.capabilities.iter().all(|capability| matches!(
        capability,
        ProviderCapability::InspectServer
            | ProviderCapability::ListNodes
            | ProviderCapability::GetNode
            | ProviderCapability::Health
    )));
    let listed = nodescale_provider::ReadOnlyProvider::list_nodes(&provider)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].identity, identity);
    assert_ne!(listed[0].hostname, listed[0].identity.node_id.as_str());
    assert_ne!(listed[0].addresses[0], listed[0].identity.node_id.as_str());
    let exact = nodescale_provider::ReadOnlyProvider::get_node(&provider, &identity)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact.identity, identity);
}

#[tokio::test]
async fn async_read_projection_matches_real_fail_closed_status_semantics() {
    for (provider, expected_compatibility, expected_health) in [
        (
            FakeProvider::compatible("compatible"),
            CompatibilityStatus::Compatible,
            ProviderHealthStatus::Healthy,
        ),
        (
            FakeProvider::degraded("degraded"),
            CompatibilityStatus::ReadOnlyDegraded,
            ProviderHealthStatus::ReachableIncompatible,
        ),
        (
            FakeProvider::unsupported("unsupported"),
            CompatibilityStatus::Unsupported,
            ProviderHealthStatus::ReachableIncompatible,
        ),
    ] {
        let inspection = nodescale_provider::ReadOnlyProvider::inspect_server(&provider)
            .await
            .unwrap();
        assert_eq!(inspection.compatibility, expected_compatibility);
        assert!(!inspection.mutation_allowed);
        let health = nodescale_provider::ReadOnlyProvider::provider_health(&provider)
            .await
            .unwrap();
        assert_eq!(health.status, expected_health);
    }

    let auth = FakeProvider::authentication_failed("auth");
    assert_eq!(
        nodescale_provider::ReadOnlyProvider::inspect_server(&auth)
            .await
            .unwrap_err(),
        ProviderError::AuthenticationFailed
    );
    let auth_health = nodescale_provider::ReadOnlyProvider::provider_health(&auth)
        .await
        .unwrap();
    assert_eq!(
        auth_health.status,
        ProviderHealthStatus::AuthenticationFailed
    );
    assert!(!auth_health.authenticated);

    let unreachable = FakeProvider::unreachable("unreachable");
    assert!(matches!(
        nodescale_provider::ReadOnlyProvider::inspect_server(&unreachable).await,
        Err(ProviderError::Unreachable(_))
    ));
    let unreachable_health = nodescale_provider::ReadOnlyProvider::provider_health(&unreachable)
        .await
        .unwrap();
    assert_eq!(
        unreachable_health.status,
        ProviderHealthStatus::TransportFailure
    );
    assert!(!unreachable_health.reachable);
}
