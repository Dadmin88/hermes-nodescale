use nodescale_domain::{
    DeviceTrustCapability, DeviceTrustState, ProviderBindingState, TrustDecisionKind,
};

#[test]
fn device_trust_is_explicit_and_revocation_is_terminal() {
    assert_eq!(
        DeviceTrustState::Untrusted
            .transition(DeviceTrustState::Trusted)
            .unwrap(),
        DeviceTrustState::Trusted
    );
    assert_eq!(
        DeviceTrustState::Untrusted
            .transition(DeviceTrustState::Revoked)
            .unwrap(),
        DeviceTrustState::Revoked
    );
    assert_eq!(
        DeviceTrustState::Trusted
            .transition(DeviceTrustState::Revoked)
            .unwrap(),
        DeviceTrustState::Revoked
    );
    assert!(
        DeviceTrustState::Revoked
            .transition(DeviceTrustState::Trusted)
            .is_err()
    );
    assert!(
        DeviceTrustState::Trusted
            .transition(DeviceTrustState::Untrusted)
            .is_err()
    );
}

#[test]
fn provider_binding_lifecycle_never_reactivates_stale_identity() {
    assert_eq!(
        ProviderBindingState::Active
            .transition(ProviderBindingState::Stale)
            .unwrap(),
        ProviderBindingState::Stale
    );
    assert_eq!(
        ProviderBindingState::Active
            .transition(ProviderBindingState::CleanupPending)
            .unwrap(),
        ProviderBindingState::CleanupPending
    );
    assert_eq!(
        ProviderBindingState::Stale
            .transition(ProviderBindingState::Removed)
            .unwrap(),
        ProviderBindingState::Removed
    );
    assert_eq!(
        ProviderBindingState::CleanupPending
            .transition(ProviderBindingState::Removed)
            .unwrap(),
        ProviderBindingState::Removed
    );
    assert!(
        ProviderBindingState::Stale
            .transition(ProviderBindingState::Active)
            .is_err()
    );
    assert!(
        ProviderBindingState::Removed
            .transition(ProviderBindingState::Active)
            .is_err()
    );
}

#[test]
fn trust_capabilities_and_decisions_are_not_roles_or_booleans() {
    assert_eq!(
        DeviceTrustCapability::ActivateDeviceTrust.as_str(),
        "ActivateDeviceTrust"
    );
    assert_eq!(
        DeviceTrustCapability::RevokeDeviceTrust.as_str(),
        "RevokeDeviceTrust"
    );
    assert_eq!(TrustDecisionKind::Activate.as_str(), "activate");
    assert_eq!(TrustDecisionKind::Revoke.as_str(), "revoke");
}
