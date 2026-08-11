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
    assert_eq!(
        MembershipState::Joining.transition(MembershipState::Active),
        Ok(MembershipState::Active)
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
        JoinSessionState::ProviderCredentialIssuing,
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
fn keryx_binding_identity_is_a_one_way_public_response() {
    let identity = KeryxBindingIdentity::pending(
        KeryxBindingId::new(),
        NetworkId::new(),
        DeviceId::new(),
        ProviderBindingId::new(),
        Generation::initial(),
        1,
        Utc::now(),
        AgentVersion::parse("nodescale-agent:6").unwrap(),
    )
    .unwrap();

    let serialized = serde_json::to_value(&identity).unwrap();
    assert_eq!(serialized["state"], "pending");
    assert!(serialized["verified_peer_id"].is_null());
    // There is deliberately no `Deserialize` assertion: persisted binding
    // identity is state-store-owned and not a public request contract.
}

#[test]
fn binding_revocation_and_projection_transitions_are_explicit() {
    assert!(
        KeryxBindingState::Pending
            .transition(KeryxBindingState::Active)
            .is_ok()
    );
    assert!(
        KeryxBindingState::Revoked
            .transition(KeryxBindingState::Active)
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
            .is_ok()
    );
}

#[test]
fn secret_values_are_redacted() {
    let secret = InvitationSecret::new("invite-plaintext".to_owned()).unwrap();
    let verifier = secret.verifier();
    let verifier_with_fresh_salt = secret.verifier();
    assert_eq!(format!("{secret:?}"), "InvitationSecret([REDACTED])");
    assert_eq!(format!("{secret}"), "[REDACTED]");
    assert!(verifier.as_str().starts_with("$argon2id$"));
    assert_ne!(verifier.as_str(), verifier_with_fresh_salt.as_str());
    assert_ne!(verifier.as_str(), "invite-plaintext");
}

#[test]
fn provider_native_credential_reference_is_validated_and_redacted() {
    let reference = ProviderCredentialReference::new("42").unwrap();
    assert_eq!(reference.as_str(), "42");
    assert_eq!(
        format!("{reference:?}"),
        "ProviderCredentialReference([REDACTED])"
    );
    assert_eq!(format!("{reference}"), "[REDACTED]");
    assert!(ProviderCredentialReference::new("not safe / reference").is_err());
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

#[test]
fn n4_invitation_token_uses_canonical_opaque_fixed_vector() {
    let vector = [
        "nsjoin_",
        "ABEiM0RVZneImaq7zN3u_",
        "wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
    ]
    .concat();
    let token: InvitationToken = vector.parse().unwrap();

    assert_eq!(
        token.invitation_id().to_string(),
        "00112233-4455-6677-8899-aabbccddeeff"
    );
    assert_eq!(format!("{token:?}"), "InvitationToken([REDACTED])");
    assert_eq!(format!("{token}"), "[REDACTED]");
    token.expose_for_delivery(|plaintext| assert_eq!(plaintext, vector));
    assert!(format!("{vector}=").parse::<InvitationToken>().is_err());
    assert!(
        vector[..vector.len() - 1]
            .parse::<InvitationToken>()
            .is_err()
    );
    assert!(
        format!("{}!", &vector[..vector.len() - 1])
            .parse::<InvitationToken>()
            .is_err()
    );
}

#[test]
fn n4_generated_tokens_are_distinct_and_verifiable_without_plaintext_persistence() {
    let invitation_id = InvitationId::new();
    let first = InvitationToken::generate(invitation_id);
    let second = InvitationToken::generate(invitation_id);
    let verifier = SecretVerifier::from_token(&first).unwrap();
    let verifier_with_fresh_salt = SecretVerifier::from_token(&first).unwrap();
    assert_ne!(verifier.as_str(), verifier_with_fresh_salt.as_str());
    assert!(verifier.verify(&first).unwrap());
    assert!(!verifier.verify(&second).unwrap());
    let first_delivery = first.expose_for_delivery(str::to_owned);
    let second_delivery = second.expose_for_delivery(str::to_owned);
    assert_ne!(first_delivery, second_delivery);
    assert!(first_delivery.starts_with("nsjoin_"));
    assert_eq!(first_delivery.len(), "nsjoin_".len() + 64);

    assert!(verifier.as_str().starts_with("$argon2id$"));
    assert_eq!(format!("{verifier:?}"), "SecretVerifier([REDACTED])");
    assert_eq!(format!("{verifier}"), "[REDACTED]");
    let persisted = serde_json::to_string(&verifier).unwrap();
    assert!(!persisted.contains(&first_delivery));
    assert_eq!(
        SecretVerifier::parse(serde_json::from_str::<String>(&persisted).unwrap()).unwrap(),
        verifier
    );
}

#[test]
fn n4_admin_invitation_requires_explicit_elevated_intent_and_roles_grant_nothing() {
    let now = Utc::now();
    let token = InvitationToken::generate(InvitationId::new());
    let verifier = SecretVerifier::from_token(&token).unwrap();
    let admin_roles = Roles::new([Role::Admin]).unwrap();

    assert!(
        Invitation::new_n4(
            token.invitation_id(),
            NetworkId::new(),
            admin_roles.clone(),
            None,
            verifier.clone(),
            JoinConstraints::default(),
            now,
            now + chrono::Duration::hours(1),
            1,
        )
        .is_err()
    );
    assert!(
        Invitation::new_n4(
            token.invitation_id(),
            NetworkId::new(),
            Roles::new([Role::Worker]).unwrap(),
            None,
            InvitationSecret::new("legacy-invitation-secret".into())
                .unwrap()
                .verifier(),
            JoinConstraints::default(),
            now,
            now + chrono::Duration::hours(1),
            1,
        )
        .is_err()
    );
    let bounded_token = InvitationToken::generate(InvitationId::new());
    let bounded_verifier = SecretVerifier::from_token(&bounded_token).unwrap();
    assert!(
        Invitation::new_n4(
            bounded_token.invitation_id(),
            NetworkId::new(),
            Roles::new([Role::Worker]).unwrap(),
            None,
            bounded_verifier,
            JoinConstraints::default(),
            now,
            now + chrono::Duration::hours(1),
            2,
        )
        .is_err()
    );
    assert!(
        Invitation::new_n4(
            token.invitation_id(),
            NetworkId::new(),
            admin_roles,
            Some(InvitationAdminIntent::explicit()),
            verifier,
            JoinConstraints::default(),
            now,
            now + chrono::Duration::hours(1),
            1,
        )
        .is_ok()
    );

    let ordinary = Roles::new([Role::Worker, Role::Controller]).unwrap();
    assert!(!ordinary.contains(Role::Admin));
    assert!(ordinary.operations().is_empty());
    assert_ne!(Role::Worker, Role::Controller);
    assert_ne!(Operation::FleetHermesRun.as_str(), "worker");
}

#[test]
fn n4_persisted_workflow_revalidates_and_legacy_records_fail_closed() {
    let now = Utc::now();
    let token = InvitationToken::generate(InvitationId::new());
    let invitation = Invitation::new_n4(
        token.invitation_id(),
        NetworkId::new(),
        Roles::new([Role::Worker]).unwrap(),
        None,
        SecretVerifier::from_token(&token).unwrap(),
        JoinConstraints::default(),
        now,
        now + chrono::Duration::minutes(15),
        1,
    )
    .unwrap();
    assert!(invitation.validate_n4_issuance().is_ok());

    let mut tampered = serde_json::to_value(&invitation).unwrap();
    tampered["max_uses"] = serde_json::json!(2);
    let tampered: Invitation = serde_json::from_value(tampered).unwrap();
    assert!(tampered.validate_n4_issuance().is_err());

    let legacy = Invitation::new(
        InvitationId::new(),
        NetworkId::new(),
        Roles::new([Role::Worker]).unwrap(),
        InvitationSecret::new(["legacy-invitation", "-secret"].concat())
            .unwrap()
            .verifier(),
        now,
        now + chrono::Duration::minutes(15),
        1,
    )
    .unwrap();
    let legacy: Invitation = serde_json::from_value(serde_json::to_value(legacy).unwrap()).unwrap();
    assert!(!legacy.is_n4());
    assert!(legacy.validate_n4_issuance().is_err());
}

#[test]
fn n4_constraints_are_bounded_hints_not_identity() {
    let constraints = JoinConstraints::new(Some("linux".into()), Some("worker-1".into())).unwrap();
    assert_eq!(constraints.expected_platform(), Some("linux"));
    assert_eq!(constraints.expected_hostname_hint(), Some("worker-1"));
    assert!(JoinConstraints::new(Some(" ".into()), None).is_err());
    assert!(JoinConstraints::new(None, Some("x".repeat(129))).is_err());
}

#[test]
fn legacy_invitation_constraint_sets_deserialize_as_no_n4_hints() {
    let now = Utc::now();
    let invitation = Invitation::new(
        InvitationId::new(),
        NetworkId::new(),
        Roles::new([Role::Worker]).unwrap(),
        InvitationSecret::new("legacy-invitation-secret".into())
            .unwrap()
            .verifier(),
        now,
        now + chrono::Duration::hours(1),
        1,
    )
    .unwrap();
    let mut persisted = serde_json::to_value(invitation).unwrap();
    persisted["join_constraints"] = serde_json::json!(["legacy-selector"]);
    let restored: Invitation = serde_json::from_value(persisted).unwrap();
    assert_eq!(restored.join_constraints, JoinConstraints::default());
}

#[test]
fn n4_lifecycle_is_durable_and_stops_join_progress_at_provider_credential() {
    assert_eq!(
        InvitationState::Issued.transition(InvitationState::Redeeming),
        Ok(InvitationState::Redeeming)
    );
    assert_eq!(
        InvitationState::Redeeming.transition(InvitationState::Consumed),
        Ok(InvitationState::Consumed)
    );
    assert_eq!(
        InvitationState::Redeeming.transition(InvitationState::Failed),
        Ok(InvitationState::Failed)
    );
    assert!(
        InvitationState::Issued
            .transition(InvitationState::Consumed)
            .is_err()
    );

    let now = Utc::now();
    let mut session = JoinSession::new_n4(
        JoinSessionId::new(),
        InvitationId::new(),
        NetworkId::new(),
        now,
        now + chrono::Duration::minutes(10),
    )
    .unwrap();
    session
        .advance_n4(JoinSessionState::InvitationValidated, now)
        .unwrap();
    session
        .advance_n4(JoinSessionState::ProviderCredentialIssuing, now)
        .unwrap();
    session
        .advance_n4(JoinSessionState::ProviderCredentialIssued, now)
        .unwrap();
    assert!(
        session
            .advance_n4(JoinSessionState::MeshJoinObserved, now)
            .is_err()
    );
    assert!(session.advance_n4(JoinSessionState::Active, now).is_err());
    assert!(session.transition(JoinSessionState::Revoked, now).is_err());
    assert!(session.transition(JoinSessionState::Expired, now).is_err());
    session
        .advance_n4(JoinSessionState::ProviderCredentialRevocationPending, now)
        .unwrap();
    session.advance_n4(JoinSessionState::Revoked, now).unwrap();
    assert_eq!(
        InvitationState::Consumed.transition(InvitationState::Revoking),
        Ok(InvitationState::Revoking)
    );
    assert_eq!(
        InvitationState::Revoking.transition(InvitationState::Revoked),
        Ok(InvitationState::Revoked)
    );
    assert_eq!(
        InvitationState::Failed.transition(InvitationState::Expiring),
        Ok(InvitationState::Expiring)
    );
}

#[test]
fn adoption_challenge_parser_accepts_base64url_underscores_without_widening_delimiters() {
    let value =
        "nsadopt1_11111111-1111-4111-8111-111111111111___________________________________________8";
    let parsed: AdoptionChallengeToken = value.parse().unwrap();
    assert_eq!(
        parsed.challenge_id(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(parsed.with_encoded(str::to_owned), value);
    assert!(
        format!("{value}_extra")
            .parse::<AdoptionChallengeToken>()
            .is_err()
    );
}
