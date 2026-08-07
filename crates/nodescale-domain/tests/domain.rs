use chrono::Utc;
use nodescale_domain::*;

fn id<T: TypedId>() -> T {
    T::new()
}

#[test]
fn ids_reject_blank_and_malformed_values() {
    assert!(NetworkId::parse("").is_err());
    assert!(DeviceId::parse("controller-1").is_err());
    assert!(NetworkId::parse("00000000-0000-0000-0000-000000000000").is_err());
}

#[test]
fn roles_are_descriptive_not_grants() {
    let roles = Roles::new([Role::Worker, Role::Controller]).unwrap();
    assert!(roles.contains(Role::Worker));
    assert!(roles.operations().is_empty());
}

#[test]
fn exact_operations_parse_without_role_inference() {
    assert_eq!("fleet.health".parse(), Ok(Operation::FleetHealth));
    assert_eq!("fleet.hermes.run".parse(), Ok(Operation::FleetHermesRun));
    assert!("worker".parse::<Operation>().is_err());
}

#[test]
fn membership_transitions_fail_closed() {
    assert!(
        MembershipState::Pending
            .transition(MembershipState::Active)
            .is_err()
    );
    assert!(
        MembershipState::Joining
            .transition(MembershipState::Active)
            .is_err()
    );
    assert!(
        MembershipState::Suspended
            .transition(MembershipState::Active)
            .is_err()
    );
    assert!(
        MembershipState::Revoked
            .transition(MembershipState::Active)
            .is_err()
    );
}

#[test]
fn invitation_transitions_enforce_lifecycle() {
    assert_eq!(
        InvitationState::Issued.transition(InvitationState::Exhausted),
        Ok(InvitationState::Exhausted)
    );
    assert!(
        InvitationState::Revoked
            .transition(InvitationState::Issued)
            .is_err()
    );
}

#[test]
fn join_session_transitions_follow_approved_sequence() {
    let now = Utc::now();
    let session = JoinSession::new(
        JoinSessionId::new(),
        InvitationId::new(),
        NetworkId::new(),
        now,
        now + chrono::Duration::minutes(10),
    )
    .unwrap();
    assert_eq!(session.state, JoinSessionState::Created);
    let states = [
        JoinSessionState::Created,
        JoinSessionState::InvitationValidated,
        JoinSessionState::ProviderCredentialIssued,
        JoinSessionState::MeshJoinObserved,
        JoinSessionState::AgentRegistered,
        JoinSessionState::KeryxBindingPending,
        JoinSessionState::KeryxBindingVerified,
        JoinSessionState::FleetProjectionPending,
        JoinSessionState::Active,
    ];
    for pair in states.windows(2) {
        assert_eq!(pair[0].transition(pair[1]), Ok(pair[1]));
    }
    assert!(
        JoinSessionState::Created
            .transition(JoinSessionState::Active)
            .is_err()
    );
}

#[test]
fn verified_keryx_binding_cannot_be_fabricated_by_deserialization() {
    let payload = serde_json::json!({
        "binding_id": KeryxBindingId::new(),
        "device_id": DeviceId::new(),
        "network_id": NetworkId::new(),
        "verified_peer_id": "self-reported-peer",
        "generation": 1,
        "state": "Verified",
        "verified_at": Utc::now(),
        "rotation": null
    });
    assert!(serde_json::from_value::<KeryxBindingIdentity>(payload).is_err());
}

#[test]
fn binding_revocation_and_projection_transitions_are_explicit() {
    assert!(
        KeryxBindingState::Pending
            .transition(KeryxBindingState::Verified)
            .is_ok()
    );
    assert!(
        KeryxBindingState::Disabled
            .transition(KeryxBindingState::Verified)
            .is_err()
    );
    assert!(
        RevocationState::Requested
            .transition(RevocationState::ApplicationTrustRemovalPending)
            .is_ok()
    );
    assert!(
        ProjectionStatus::Pending
            .transition(ProjectionStatus::Applied)
            .is_ok()
    );
    assert!(
        ProjectionStatus::Applied
            .transition(ProjectionStatus::Pending)
            .is_err()
    );
}

#[test]
fn secret_values_are_redacted() {
    let secret = InvitationSecret::new("invite-plaintext".to_owned()).unwrap();
    assert_eq!(format!("{secret:?}"), "InvitationSecret([REDACTED])");
    assert_eq!(format!("{secret}"), "[REDACTED]");
    assert_ne!(secret.verifier().as_str(), "invite-plaintext");
}

#[test]
fn identity_evidence_is_not_collapsed() {
    let device = Device::new(id(), id(), "controller-1", Utc::now()).unwrap();
    assert!(device.provider_identity.is_none());
    assert!(device.keryx_binding.is_none());
    assert_ne!(device.device_id.to_string(), device.network_id.to_string());
}

#[test]
fn generations_are_monotonic_and_independent() {
    let mut generations = DeviceGenerations::initial();
    generations
        .advance_credential(Generation::new(1).unwrap(), Generation::new(2).unwrap())
        .unwrap();
    assert_eq!(generations.credential.get(), 2);
    assert_eq!(generations.keryx_binding.get(), 1);
    assert!(
        generations
            .advance_credential(Generation::new(1).unwrap(), Generation::new(3).unwrap())
            .is_err()
    );
}
