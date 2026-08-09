use chrono::{Duration, Utc};
use nodescale_domain::*;
fn agent_version() -> AgentVersion {
    AgentVersion::parse("nodescale-agent:6.0.0").unwrap()
}

#[test]
fn binding_nonce_is_fixed_width_canonical_and_redacted() {
    let nonce = BindingNonce::generate();
    let encoded = nonce.with_encoded(str::to_owned);
    assert!(encoded.starts_with("nsbind_"));
    assert_eq!(encoded.len(), 50);
    assert_eq!(encoded.strip_prefix("nsbind_").unwrap().len(), 43);
    assert_eq!(format!("{nonce:?}"), "BindingNonce([REDACTED])");
    assert_eq!(format!("{nonce}"), "[REDACTED]");
    assert!(!format!("{nonce:?}").contains(&encoded));
    assert!(!format!("{nonce}").contains(&encoded));

    let parsed: BindingNonce = encoded.parse().unwrap();
    assert!(parsed.with_encoded(|actual| actual == encoded));
    assert!(
        "wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse::<BindingNonce>()
            .is_err()
    );
    assert!(format!("{encoded}=").parse::<BindingNonce>().is_err());
    assert!(
        encoded[..encoded.len() - 1]
            .parse::<BindingNonce>()
            .is_err()
    );
    assert!(
        format!("nsbind_{}!", &encoded[7..encoded.len() - 1])
            .parse::<BindingNonce>()
            .is_err()
    );
}

#[test]
fn binding_nonce_verifier_uses_only_fixed_argon2id_profile() {
    let nonce = BindingNonce::generate();
    let other = BindingNonce::generate();
    let first = BindingNonceVerifier::from_nonce(&nonce).unwrap();
    let second = BindingNonceVerifier::from_nonce(&nonce).unwrap();
    assert_ne!(first.as_str(), second.as_str());
    assert!(first.verify(&nonce).unwrap());
    assert!(!first.verify(&other).unwrap());
    assert!(
        first
            .as_str()
            .starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
    );
    assert_eq!(format!("{first:?}"), "BindingNonceVerifier([REDACTED])");
    assert_eq!(format!("{first}"), "[REDACTED]");
    assert!(BindingNonceVerifier::parse(first.as_str().replace("m=19456", "m=8192")).is_err());
    assert!(BindingNonceVerifier::parse(first.as_str().replace("argon2id", "argon2i")).is_err());
    assert!(BindingNonceVerifier::parse(first.as_str().replace("v=19", "v=16")).is_err());
    let segments = first.as_str().split('$').collect::<Vec<_>>();
    assert_eq!(segments.len(), 6);
    assert_eq!(segments[4].len(), 22, "canonical verifier salt is 16 bytes");
    assert_eq!(segments[5].len(), 43, "canonical verifier hash is 32 bytes");
    let (prefix, hash) = first.as_str().rsplit_once('$').unwrap();
    assert!(BindingNonceVerifier::parse(format!("{prefix}${}", &hash[..hash.len() - 2])).is_err());
    assert!(BindingNonceVerifier::parse(first.as_str().replace(segments[4], "c2FsdA")).is_err());
    assert!(
        BindingNonceVerifier::parse(
            first
                .as_str()
                .replace(segments[4], "MDEyMzQ1Njc4OWFiY2RlZmdo")
        )
        .is_err()
    );
    assert!(BindingNonceVerifier::parse(first.as_str().replace(segments[4], "c2FsdCE")).is_err());
    assert!(BindingNonceVerifier::parse(format!("{}x", first.as_str())).is_err());
    assert!(BindingNonceVerifier::parse("a".repeat(64)).is_err());
    assert!(BindingNonceVerifier::parse("a".repeat(1_000_000)).is_err());

    let json = serde_json::to_string(&first).unwrap();
    assert_eq!(
        serde_json::from_str::<BindingNonceVerifier>(&json).unwrap(),
        first
    );
    assert!(serde_json::from_str::<BindingNonceVerifier>("\"not a verifier\"").is_err());
}

#[test]
fn n6_binding_lifecycle_is_exact_and_terminal() {
    use KeryxBindingState::*;
    for (from, to) in [
        (Pending, Active),
        (Pending, Revoked),
        (Active, Stale),
        (Active, Rotated),
        (Active, Revoked),
        (Stale, Rotated),
        (Stale, Revoked),
    ] {
        assert_eq!(from.transition(to), Ok(to));
    }
    for (from, to) in [
        (Pending, Stale),
        (Pending, Rotated),
        (Active, Pending),
        (Stale, Active),
        (Rotated, Revoked),
        (Revoked, Rotated),
    ] {
        assert!(from.transition(to).is_err(), "{from:?} -> {to:?}");
    }
    assert!(Rotated.transition(Rotated).is_err());
    assert!(Revoked.transition(Revoked).is_err());
}

#[test]
fn n6_commands_are_bounded_secret_safe_and_fenced() {
    let now = Utc::now();
    let expiry = now + Duration::minutes(5);
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    let join_session_id = JoinSessionId::new();
    let binding_id = KeryxBindingId::new();
    let generation = Generation::initial();
    let peer = KeryxPeerId::parse("peer-1").unwrap();
    let challenge = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        join_session_id,
        peer,
        generation,
        expiry,
        now,
        agent_version(),
    )
    .unwrap();
    assert_eq!(challenge.generation(), generation);
    assert!(challenge.validate_at(expiry).is_err());
    assert!(
        N6BindingChallengeRequest::new(
            network_id,
            device_id,
            join_session_id,
            KeryxPeerId::parse("peer-1").unwrap(),
            generation,
            now,
            now,
            agent_version()
        )
        .is_err()
    );
    assert!(AgentVersion::parse("unsafe\nversion").is_err());
    assert!(serde_json::from_str::<AgentVersion>("\"unsafe\\nversion\"").is_err());
    assert!(OperationId::parse("bad operation").is_err());

    let nonce = BindingNonce::generate();
    let delivery = N6BindingChallengeDelivery::new(
        KeryxBindingChallengeId::new(),
        binding_id,
        generation,
        nonce,
        expiry,
        now,
    )
    .unwrap();
    assert_eq!(
        format!("{delivery:?}"),
        "N6BindingChallengeDelivery([REDACTED])"
    );
    let nonce = BindingNonce::generate();
    let request = N6AuthenticatedBindRequest::new(
        OperationId::parse("bind-1").unwrap(),
        network_id,
        device_id,
        join_session_id,
        nonce,
        generation,
        agent_version(),
    )
    .unwrap();
    assert_eq!(request.generation(), generation);
    let authorization = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        TrustAuthorityId::new(),
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Rotate,
        binding_id,
        generation,
        1,
        expiry,
        now,
    )
    .unwrap();
    let rotation = N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        authorization,
        binding_id,
        generation,
        1,
        Generation::new(2).unwrap(),
        expiry,
        now,
        ReasonCode::parse("routine_rotation").unwrap(),
    )
    .unwrap();
    assert_eq!(rotation.expected_next_generation().get(), 2);
    assert!(ReasonCode::parse("not safe / reason").is_err());

    let wrong_capability = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        TrustAuthorityId::new(),
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Revoke,
        binding_id,
        generation,
        1,
        expiry,
        now,
    )
    .unwrap();
    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            wrong_capability,
            binding_id,
            generation,
            1,
            Generation::new(2).unwrap(),
            expiry,
            now,
            ReasonCode::parse("routine_rotation").unwrap(),
        )
        .is_err()
    );

    let revoke_auth = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        TrustAuthorityId::new(),
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Revoke,
        binding_id,
        generation,
        1,
        expiry,
        now,
    )
    .unwrap();
    assert!(
        N6BindingRevocationIntent::new(
            KeryxBindingDecisionId::new(),
            revoke_auth,
            binding_id,
            generation,
            1,
            expiry,
            now,
            ReasonCode::parse("operator:revoke").unwrap()
        )
        .is_ok()
    );
}

#[test]
fn pending_rotation_records_predecessor_without_activation_evidence() {
    let now = Utc::now();
    let binding_id = KeryxBindingId::new();
    let predecessor = KeryxBindingId::new();
    let successor = KeryxBindingIdentity::pending_rotation(
        binding_id,
        NetworkId::new(),
        DeviceId::new(),
        JoinSessionId::new(),
        Generation::new(2).unwrap(),
        1,
        now,
        agent_version(),
        predecessor,
    )
    .unwrap();

    assert_eq!(successor.state(), KeryxBindingState::Pending);
    assert_eq!(successor.rotated_from(), Some(predecessor));
    assert!(successor.verified_peer_id().is_none());
    assert!(successor.confirmed_at().is_none());
    assert!(successor.stale_at().is_none());
    assert!(successor.rotated_at().is_none());
    assert!(successor.revoked_at().is_none());
    assert!(successor.last_verified_at().is_none());
    assert!(
        KeryxBindingIdentity::pending_rotation(
            binding_id,
            NetworkId::new(),
            DeviceId::new(),
            JoinSessionId::new(),
            Generation::new(2).unwrap(),
            1,
            now,
            agent_version(),
            binding_id,
        )
        .is_err()
    );
}

#[test]
fn rotation_generation_must_be_the_exact_non_overflowing_successor() {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(5);
    let binding_id = KeryxBindingId::new();
    let predecessor = Generation::new(2).unwrap();
    let authorization = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        TrustAuthorityId::new(),
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Rotate,
        binding_id,
        predecessor,
        1,
        expires_at,
        now,
    )
    .unwrap();
    let rotation = N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        authorization.clone(),
        binding_id,
        predecessor,
        1,
        predecessor.next_exact().unwrap(),
        expires_at,
        now,
        ReasonCode::parse("routine_rotation").unwrap(),
    )
    .unwrap();
    assert!(rotation.validate_at(now).is_ok());
    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            authorization,
            binding_id,
            predecessor,
            1,
            Generation::new(4).unwrap(),
            expires_at,
            now,
            ReasonCode::parse("routine_rotation").unwrap(),
        )
        .is_err()
    );
    assert!(Generation::new(u64::MAX).unwrap().next_exact().is_err());
}

#[test]
fn n6_safe_accessors_and_state_persistence_spellings_are_complete() {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(5);
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    let session_id = JoinSessionId::new();
    let binding_id = KeryxBindingId::new();
    let generation = Generation::initial();
    let peer = KeryxPeerId::parse("peer-1").unwrap();
    let version = agent_version();
    let challenge = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        session_id,
        peer.clone(),
        generation,
        expires_at,
        now,
        version.clone(),
    )
    .unwrap();
    assert_eq!(challenge.network_id(), network_id);
    assert_eq!(challenge.device_id(), device_id);
    assert_eq!(challenge.join_session_id(), session_id);
    assert_eq!(challenge.expected_authenticated_peer_id(), &peer);
    assert_eq!(challenge.generation(), generation);
    assert_eq!(challenge.expires_at(), expires_at);
    assert_eq!(challenge.agent_version(), &version);
    let actor = AuditActor::system();
    let authorization = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        TrustAuthorityId::new(),
        actor.clone(),
        KeryxBindingAuthorizationCapability::Rotate,
        binding_id,
        generation,
        2,
        expires_at,
        now,
    )
    .unwrap();
    assert_eq!(authorization.actor(), &actor);
    assert_eq!(
        authorization.capability(),
        KeryxBindingAuthorizationCapability::Rotate
    );
    assert_eq!(authorization.binding_id(), binding_id);
    assert_eq!(authorization.generation(), generation);
    assert_eq!(authorization.revision(), 2);
    assert_eq!(authorization.expires_at(), expires_at);
    let authorization_id = authorization.authorization_id();
    let authority_id = authorization.authority_id();

    let reason = ReasonCode::parse("routine_rotation").unwrap();
    let rotation = N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        authorization.clone(),
        binding_id,
        generation,
        2,
        generation.next_exact().unwrap(),
        expires_at,
        now,
        reason.clone(),
    )
    .unwrap();
    assert_eq!(rotation.authorization(), &authorization);
    assert_eq!(rotation.predecessor_binding_id(), binding_id);
    assert_eq!(rotation.predecessor_generation(), generation);
    assert_eq!(rotation.predecessor_revision(), 2);
    assert_eq!(
        rotation.expected_next_generation(),
        generation.next_exact().unwrap()
    );
    assert_eq!(rotation.expires_at(), expires_at);
    assert_eq!(rotation.reason_code(), &reason);
    assert_ne!(rotation.decision_id(), KeryxBindingDecisionId::new());

    let revoke_authorization = KeryxBindingAuthorization::new(
        authorization_id,
        authority_id,
        actor,
        KeryxBindingAuthorizationCapability::Revoke,
        binding_id,
        generation,
        2,
        expires_at,
        now,
    )
    .unwrap();
    let revocation = N6BindingRevocationIntent::new(
        KeryxBindingDecisionId::new(),
        revoke_authorization.clone(),
        binding_id,
        generation,
        2,
        expires_at,
        now,
        ReasonCode::parse("operator:revoke").unwrap(),
    )
    .unwrap();
    assert_eq!(revocation.authorization(), &revoke_authorization);
    assert_eq!(revocation.binding_id(), binding_id);
    assert_eq!(revocation.generation(), generation);
    assert_eq!(revocation.revision(), 2);
    assert_eq!(revocation.expires_at(), expires_at);
    assert_eq!(revocation.reason().as_str(), "operator:revoke");
    assert_ne!(revocation.decision_id(), KeryxBindingDecisionId::new());

    assert_eq!(KeryxBindingState::Pending.as_str(), "pending");
    assert_eq!(KeryxBindingState::Active.as_str(), "active");
    assert_eq!(KeryxBindingState::Stale.as_str(), "stale");
    assert_eq!(KeryxBindingState::Rotated.as_str(), "rotated");
    assert_eq!(KeryxBindingState::Revoked.as_str(), "revoked");
}

#[test]
fn commands_recheck_expiry_when_the_state_mutation_boundary_uses_them() {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(5);
    let binding_id = KeryxBindingId::new();
    let generation = Generation::initial();
    let authority_id = TrustAuthorityId::new();
    let rotate_authorization = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        authority_id,
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Rotate,
        binding_id,
        generation,
        1,
        expires_at,
        now,
    )
    .unwrap();
    let rotation = N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        rotate_authorization.clone(),
        binding_id,
        generation,
        1,
        generation.next_exact().unwrap(),
        expires_at,
        now,
        ReasonCode::parse("scheduled_rotation").unwrap(),
    )
    .unwrap();
    let revoke_authorization = KeryxBindingAuthorization::new(
        KeryxBindingAuthorizationId::new(),
        authority_id,
        AuditActor::system(),
        KeryxBindingAuthorizationCapability::Revoke,
        binding_id,
        generation,
        1,
        expires_at,
        now,
    )
    .unwrap();
    let revocation = N6BindingRevocationIntent::new(
        KeryxBindingDecisionId::new(),
        revoke_authorization.clone(),
        binding_id,
        generation,
        1,
        expires_at,
        now,
        ReasonCode::parse("operator_revoke").unwrap(),
    )
    .unwrap();

    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            revoke_authorization.clone(),
            binding_id,
            generation,
            1,
            generation.next_exact().unwrap(),
            expires_at,
            now,
            ReasonCode::parse("wrong_capability").unwrap(),
        )
        .is_err()
    );
    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            rotate_authorization.clone(),
            KeryxBindingId::new(),
            generation,
            1,
            generation.next_exact().unwrap(),
            expires_at,
            now,
            ReasonCode::parse("wrong_binding").unwrap(),
        )
        .is_err()
    );
    let different_generation = generation.next_exact().unwrap();
    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            rotate_authorization.clone(),
            binding_id,
            different_generation,
            1,
            different_generation.next_exact().unwrap(),
            expires_at,
            now,
            ReasonCode::parse("wrong_generation").unwrap(),
        )
        .is_err()
    );
    assert!(
        N6BindingRotationIntent::new(
            KeryxBindingDecisionId::new(),
            rotate_authorization.clone(),
            binding_id,
            generation,
            2,
            generation.next_exact().unwrap(),
            expires_at,
            now,
            ReasonCode::parse("wrong_revision").unwrap(),
        )
        .is_err()
    );

    let expired_now = expires_at;
    assert!(
        rotate_authorization
            .clone()
            .validate_at(expired_now)
            .is_err()
    );
    assert!(rotation.clone().validate_at(expired_now).is_err());
    assert!(
        revoke_authorization
            .clone()
            .validate_at(expired_now)
            .is_err()
    );
    assert!(revocation.clone().validate_at(expired_now).is_err());
}

#[test]
fn binding_authorization_accepts_only_bounded_n5_audit_actors() {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(1);
    let authorization = |actor| {
        KeryxBindingAuthorization::new(
            KeryxBindingAuthorizationId::new(),
            TrustAuthorityId::new(),
            actor,
            KeryxBindingAuthorizationCapability::Rotate,
            KeryxBindingId::new(),
            Generation::initial(),
            1,
            expires_at,
            now,
        )
    };

    assert!(authorization(AuditActor::system()).is_ok());
    for actor in [
        AuditActor {
            source: String::new(),
            actor_id: Some("operator".into()),
        },
        AuditActor {
            source: "x".repeat(65),
            actor_id: Some("operator".into()),
        },
        AuditActor {
            source: "operator\nsource".into(),
            actor_id: Some("operator".into()),
        },
        AuditActor {
            source: "operator".into(),
            actor_id: None,
        },
        AuditActor {
            source: "operator".into(),
            actor_id: Some("x".repeat(256)),
        },
        AuditActor {
            source: "operator".into(),
            actor_id: Some("operator\n1".into()),
        },
        AuditActor {
            source: "operator".into(),
            actor_id: Some("operator user".into()),
        },
    ] {
        assert!(authorization(actor).is_err());
    }
}

#[test]
fn challenge_delivery_rejects_expiry_at_creation_and_use() {
    let now = Utc::now();
    let expires_at = now + Duration::minutes(1);

    assert!(
        N6BindingChallengeDelivery::new(
            KeryxBindingChallengeId::new(),
            KeryxBindingId::new(),
            Generation::initial(),
            BindingNonce::generate(),
            now,
            now,
        )
        .is_err()
    );

    let delivery = N6BindingChallengeDelivery::new(
        KeryxBindingChallengeId::new(),
        KeryxBindingId::new(),
        Generation::initial(),
        BindingNonce::generate(),
        expires_at,
        now,
    )
    .unwrap();
    assert!(delivery.validate_at(now).is_ok());
    assert!(delivery.validate_at(expires_at).is_err());
}

#[test]
fn agent_version_uses_the_n6_sql_identifier_grammar() {
    let valid = AgentVersion::parse("nodescale-agent:6.0.0").unwrap();
    assert_eq!(valid.as_str(), "nodescale-agent:6.0.0");
    for forbidden in [
        "nodescale-agent/6.0.0",
        "nodescale agent",
        "agent\n6",
        "agent-é",
    ] {
        assert!(
            AgentVersion::parse(forbidden).is_err(),
            "accepted {forbidden:?}"
        );
        assert!(
            serde_json::from_value::<AgentVersion>(serde_json::json!(forbidden)).is_err(),
            "deserialized {forbidden:?}"
        );
    }
}
