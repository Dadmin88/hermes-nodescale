use nodescale_provider::*;
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
