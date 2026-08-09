use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AgentVersion, DeviceId, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation,
    JoinSessionId, KeryxBindingAuthorizationCapability, KeryxBindingDecisionId, KeryxPeerId,
    N6AuthenticatedBindRequest, N6BindingChallengeRequest, N6BindingRevocationIntent,
    N6BindingRotationIntent, NetworkId, OperationId, OwnerTrustRootToken, ReasonCode,
    TrustAuthorityId, TrustRootId,
};
use nodescale_state::{
    N5TrustAuthorityConfiguration, N6AuthenticatedBindOutcome, N6BindingView,
    N7AuthoritativeInspection, N7BindingProvenance, N7ProjectionAttemptOutcome,
    N7ProjectionReservationOutcome, N7ProjectionState, N7ProjectionSubmission, StateError,
    StateStore,
};
use rusqlite::Connection;
use tempfile::{TempDir, tempdir};

const NETWORK: &str = "10bdbae2-73be-46f2-8f0a-5b761fdeaf4d";
const DEVICE: &str = "f9b36c3a-e777-4e92-a4ea-14d22a234ecc";
const SESSION: &str = "cafa4427-4c17-408e-bfed-c93f34bd3756";

fn now() -> DateTime<Utc> {
    "2026-08-08T00:00:00Z".parse().unwrap()
}

fn version() -> AgentVersion {
    AgentVersion::parse("nodescale-agent:6.0.0").unwrap()
}

fn network_id() -> NetworkId {
    NetworkId::parse(NETWORK).unwrap()
}

fn seed_confirmed_n5_provenance(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n6 authority guards','active','headscale','provider-n6',1,1,'{}','2026-08-08T00:00:00Z','2026-08-08T00:00:00Z');
             INSERT INTO devices (device_id,network_id,display_name,membership_state,provider_instance_id,provider_node_id,provider_key_fingerprint,credential_generation,keryx_binding_generation,fleet_projection_generation,fleet_projection_status,record_json,created_at,updated_at,revoked_at)
             VALUES ('f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n6 device','pending',NULL,NULL,NULL,1,1,1,'none','{}','2026-08-08T00:00:00Z','2026-08-08T00:00:00Z',NULL);
             INSERT INTO device_generations (device_id,credential_generation,keryx_binding_generation,fleet_projection_generation,updated_at)
             VALUES ('f9b36c3a-e777-4e92-a4ea-14d22a234ecc',1,1,1,'2026-08-08T00:00:00Z');
             INSERT INTO invitations (invitation_id,network_id,state,secret_verifier,provider_credential_reference,max_uses,used_count,record_json,created_at,expires_at)
             VALUES ('610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','issued','$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$MDEyMzQ1Njc4OWFiY2RlZg',NULL,1,0,'{}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z');
             INSERT INTO join_sessions (join_session_id,invitation_id,network_id,device_id,state,record_json,created_at,expires_at,updated_at)
             VALUES ('cafa4427-4c17-408e-bfed-c93f34bd3756','610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','credential_issued','{}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z','2026-08-08T00:00:00Z');
             INSERT INTO provider_imports (network_id,provider_instance_id,server_url,opaque_secret_reference,compatibility_pin,tls_verification,read_only,mutation_allowed,compatibility,provider_version,last_success_at,last_attempt_at,last_failure_kind,last_failure_detail,custom_root_ca_sha256)
             VALUES ('10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','https://provider.example.test','secret://vault/n6','v0.29.3','verify',1,0,'compatible','v0.29.3',NULL,NULL,NULL,NULL,NULL);
             INSERT INTO provider_mutation_configurations (network_id,provider_instance_id,authorization_generation,configuration_generation,configuration_fingerprint,adapter,expected_version,enabled,revoked,not_before_ms,expires_at_ms,policy_mode)
             VALUES ('10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','headscale','v0.29.3',1,0,0,999999999999,'database');
             INSERT INTO confirmed_provider_credential_references (credential_id,network_id,provider_instance_id,provider_reference,authorization_generation,configuration_generation,configuration_fingerprint,confirmed_at_ms,expires_at_ms,max_uses)
             VALUES ('1647eae9-8b5a-43e8-95b0-9a2470dc440a','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','provider-ref-n6',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,999999999999,1);
             INSERT INTO n4_invitation_details (invitation_id,network_id,provider_instance_id,provider_principal_id,roles_json,constraints_json,created_by_source,created_by_id,revision,last_redemption_metadata_json)
             VALUES ('610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','principal-n6','[]','{}','nodescale',NULL,1,'{}');
             INSERT INTO n4_join_session_dispatches (join_session_id,invitation_id,network_id,provider_instance_id,provider_principal_id,create_request_id,dispatch_state,authorization_generation,configuration_generation,configuration_fingerprint,dispatched_at_ms,resolved_at_ms,credential_id)
             VALUES ('cafa4427-4c17-408e-bfed-c93f34bd3756','610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','principal-n6','00000000-0000-0000-0000-000000000006','confirmed',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,1001,'1647eae9-8b5a-43e8-95b0-9a2470dc440a');
             INSERT INTO n5_device_identities (device_id,network_id,origin_join_session_id,confirmed_at_ms,identity_revision,safe_correlation_digest)
             VALUES ('f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','cafa4427-4c17-408e-bfed-c93f34bd3756',1001,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
        )
        .unwrap();
}

struct Fixture {
    _directory: TempDir,
    store: StateStore,
    active: N6BindingView,
}

fn fixture() -> Fixture {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-authority-guards.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);

    let peer = KeryxPeerId::parse("peer-n6-authority-guards").unwrap();
    let challenge = store
        .issue_n6_binding_challenge(
            OperationId::parse("authority-guard-challenge").unwrap(),
            N6BindingChallengeRequest::new(
                network_id(),
                DeviceId::parse(DEVICE).unwrap(),
                JoinSessionId::parse(SESSION).unwrap(),
                peer.clone(),
                Generation::initial(),
                now() + Duration::minutes(5),
                now(),
                version(),
            )
            .unwrap(),
            now(),
        )
        .unwrap();
    let nonce = challenge.with_nonce(|value| value.with_encoded(str::to_owned));
    let active = match store
        .confirm_n6_authenticated_binding(
            peer,
            N6AuthenticatedBindRequest::new(
                OperationId::parse("authority-guard-bind").unwrap(),
                network_id(),
                DeviceId::parse(DEVICE).unwrap(),
                JoinSessionId::parse(SESSION).unwrap(),
                nonce.parse().unwrap(),
                Generation::initial(),
                version(),
            )
            .unwrap(),
            now(),
        )
        .unwrap()
    {
        N6AuthenticatedBindOutcome::Confirmed(view) => view,
        other => panic!("unexpected bind outcome: {other:?}"),
    };

    Fixture {
        _directory: directory,
        store,
        active,
    }
}

fn owner_authority(
    store: &StateStore,
    grants: impl IntoIterator<Item = KeryxBindingAuthorizationCapability>,
) -> (OwnerTrustRootToken, TrustAuthorityId) {
    let root = store
        .bootstrap_n5_owner_trust_root(
            network_id(),
            "local-owner",
            "owner-n6",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            nodescale_domain::AuditActor::system(),
        )
        .unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network_id(),
                "local-owner",
                "owner-n6",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    for capability in grants {
        store
            .grant_n6_binding_capability(&root, authority_id, capability, now())
            .unwrap();
    }
    (root, authority_id)
}

fn rotation_intent(
    authorization: nodescale_domain::KeryxBindingAuthorization,
    binding: &N6BindingView,
    expires_at: DateTime<Utc>,
) -> N6BindingRotationIntent {
    N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        authorization,
        binding.binding_id,
        binding.generation,
        binding.revision,
        binding.generation.next_exact().unwrap(),
        expires_at,
        now(),
        ReasonCode::parse("owner_rotation").unwrap(),
    )
    .unwrap()
}

fn revocation_intent(
    authorization: nodescale_domain::KeryxBindingAuthorization,
    binding: &N6BindingView,
    expires_at: DateTime<Utc>,
) -> N6BindingRevocationIntent {
    N6BindingRevocationIntent::new(
        KeryxBindingDecisionId::new(),
        authorization,
        binding.binding_id,
        binding.generation,
        binding.revision,
        expires_at,
        now(),
        ReasonCode::parse("owner_revocation").unwrap(),
    )
    .unwrap()
}

fn assert_binding_unchanged(store: &StateStore, binding: &N6BindingView) {
    assert_eq!(
        store.n6_binding(binding.binding_id).unwrap(),
        binding.clone()
    );
}

fn reserve_n7_projection_at(
    fixture: &Fixture,
    operation_id: &str,
    generation: Generation,
    body: &[u8],
) -> N7ProjectionSubmission {
    let binding = N7BindingProvenance::new(
        fixture.active.binding_id.to_string(),
        fixture
            .active
            .verified_peer_id
            .as_ref()
            .expect("active N6 fixture has its authenticated peer")
            .to_string(),
        fixture.active.generation,
    )
    .unwrap();
    let submission = N7ProjectionSubmission::from_canonical(
        OperationId::parse(operation_id).unwrap(),
        network_id(),
        DeviceId::parse(DEVICE).unwrap(),
        generation,
        body.to_vec(),
        binding.binding_id,
        binding.authenticated_peer_id,
        binding.binding_generation,
    )
    .unwrap();
    assert!(matches!(
        fixture
            .store
            .reserve_n7_projection(&submission, now())
            .unwrap(),
        N7ProjectionReservationOutcome::Reserved(_)
    ));
    submission
}

fn reserve_n7_projection(fixture: &Fixture, operation_id: &str) -> N7ProjectionSubmission {
    reserve_n7_projection_at(
        fixture,
        operation_id,
        Generation::initial(),
        br#"{"fleet":"desired","state":"active"}"#,
    )
}

fn mark_n7_projection_attempted(fixture: &Fixture, submission: &N7ProjectionSubmission) -> u64 {
    let attempted = fixture
        .store
        .record_n7_projection_dispatch_attempt(
            &submission.operation_id,
            DeviceId::parse(DEVICE).unwrap(),
            submission.generation,
            1,
            now(),
        )
        .unwrap();
    match attempted {
        N7ProjectionAttemptOutcome::Recorded(view)
            if view.state == N7ProjectionState::Attempted =>
        {
            view.revision
        }
        other => panic!("unexpected N7 dispatch attempt: {other:?}"),
    }
}

fn record_n7_dispatch_attempt(
    fixture: &Fixture,
    operation_id: &str,
) -> (N7ProjectionSubmission, u64) {
    let submission = reserve_n7_projection(fixture, operation_id);
    let revision = mark_n7_projection_attempted(fixture, &submission);
    (submission, revision)
}

#[test]
fn n6_rotation_and_revocation_reject_wrong_owner_root() {
    let fixture = fixture();
    let (_, authority_id) = owner_authority(
        &fixture.store,
        [
            KeryxBindingAuthorizationCapability::Rotate,
            KeryxBindingAuthorizationCapability::Revoke,
        ],
    );
    let wrong_root = OwnerTrustRootToken::generate(TrustRootId::new());

    for capability in [
        KeryxBindingAuthorizationCapability::Rotate,
        KeryxBindingAuthorizationCapability::Revoke,
    ] {
        assert!(matches!(
            fixture.store.issue_n6_binding_authorization(
                &wrong_root,
                authority_id,
                fixture.active.binding_id,
                capability,
                now() + Duration::minutes(5),
                now(),
            ),
            Err(StateError::MutationAuthorizationDenied(_))
        ));
    }
    assert_binding_unchanged(&fixture.store, &fixture.active);
}

#[test]
fn n6_rotation_and_revocation_require_exact_n6_capability_grants() {
    for capability in [
        KeryxBindingAuthorizationCapability::Rotate,
        KeryxBindingAuthorizationCapability::Revoke,
    ] {
        let fixture = fixture();
        let (root, authority_id) = owner_authority(&fixture.store, []);
        assert!(
            fixture
                .store
                .issue_n6_binding_authorization(
                    &root,
                    authority_id,
                    fixture.active.binding_id,
                    capability,
                    now() + Duration::minutes(5),
                    now(),
                )
                .is_err(),
            "missing {capability:?} grant issued an authorization"
        );
        assert_binding_unchanged(&fixture.store, &fixture.active);
    }
}

#[test]
fn n6_rotation_and_revocation_recheck_authorization_expiry_at_consumption() {
    for capability in [
        KeryxBindingAuthorizationCapability::Rotate,
        KeryxBindingAuthorizationCapability::Revoke,
    ] {
        let fixture = fixture();
        let (root, authority_id) = owner_authority(&fixture.store, [capability]);
        let expires_at = now() + Duration::minutes(1);
        let authorization = fixture
            .store
            .issue_n6_binding_authorization(
                &root,
                authority_id,
                fixture.active.binding_id,
                capability,
                expires_at,
                now(),
            )
            .unwrap();
        let result = match capability {
            KeryxBindingAuthorizationCapability::Rotate => fixture.store.rotate_n6_binding(
                &rotation_intent(authorization, &fixture.active, expires_at),
                expires_at,
            ),
            KeryxBindingAuthorizationCapability::Revoke => fixture.store.revoke_n6_binding(
                &revocation_intent(authorization, &fixture.active, expires_at),
                expires_at,
            ),
        };
        assert!(
            result.is_err(),
            "expired {capability:?} authorization was consumed"
        );
        assert_binding_unchanged(&fixture.store, &fixture.active);
    }
}

#[test]
fn n6_rotation_and_revocation_fail_closed_after_a_durable_n7_dispatch_attempt() {
    for observed_as_applied in [false, true] {
        for capability in [
            KeryxBindingAuthorizationCapability::Rotate,
            KeryxBindingAuthorizationCapability::Revoke,
        ] {
            let fixture = fixture();
            let (submission, attempted_revision) =
                record_n7_dispatch_attempt(&fixture, "n7-dispatch-before-n6-control");
            if observed_as_applied {
                assert_eq!(
                    fixture
                        .store
                        .recover_n7_projection_from_inspection(
                            &submission.operation_id,
                            DeviceId::parse(DEVICE).unwrap(),
                            submission.generation,
                            attempted_revision,
                            N7AuthoritativeInspection::observed(
                                br#"{"fleet":"desired","state":"active"}"#.to_vec(),
                            )
                            .unwrap(),
                            now(),
                        )
                        .unwrap()
                        .state,
                    N7ProjectionState::Applied
                );
            }
            let (root, authority_id) = owner_authority(&fixture.store, [capability]);
            let expires_at = now() + Duration::minutes(5);
            let authorization = fixture
                .store
                .issue_n6_binding_authorization(
                    &root,
                    authority_id,
                    fixture.active.binding_id,
                    capability,
                    expires_at,
                    now(),
                )
                .unwrap();
            let result = match capability {
                KeryxBindingAuthorizationCapability::Rotate => fixture.store.rotate_n6_binding(
                    &rotation_intent(authorization, &fixture.active, expires_at),
                    now(),
                ),
                KeryxBindingAuthorizationCapability::Revoke => fixture.store.revoke_n6_binding(
                    &revocation_intent(authorization, &fixture.active, expires_at),
                    now(),
                ),
            };
            assert!(matches!(
                result,
                Err(StateError::Conflict(message)) if message.contains("Fleet authority remains unresolved")
            ));
            assert_binding_unchanged(&fixture.store, &fixture.active);
        }
    }
}

#[test]
fn n6_revocation_succeeds_after_an_authoritative_applied_removal() {
    let fixture = fixture();
    let (active, active_revision) =
        record_n7_dispatch_attempt(&fixture, "n7-active-before-removal");
    fixture
        .store
        .recover_n7_projection_from_inspection(
            &active.operation_id,
            DeviceId::parse(DEVICE).unwrap(),
            active.generation,
            active_revision,
            N7AuthoritativeInspection::observed(active.desired_body.clone()).unwrap(),
            now(),
        )
        .unwrap();

    let removed = reserve_n7_projection_at(
        &fixture,
        "n7-removal-before-revocation",
        Generation::new(2).unwrap(),
        br#"{"fleet":"desired","state":"removed"}"#,
    );
    let removed_revision = mark_n7_projection_attempted(&fixture, &removed);
    assert_eq!(
        fixture
            .store
            .recover_n7_projection_from_inspection(
                &removed.operation_id,
                DeviceId::parse(DEVICE).unwrap(),
                removed.generation,
                removed_revision,
                N7AuthoritativeInspection::observed(removed.desired_body.clone()).unwrap(),
                now(),
            )
            .unwrap()
            .state,
        N7ProjectionState::Applied
    );

    let (root, authority_id) = owner_authority(
        &fixture.store,
        [KeryxBindingAuthorizationCapability::Revoke],
    );
    let expires_at = now() + Duration::minutes(5);
    let authorization = fixture
        .store
        .issue_n6_binding_authorization(
            &root,
            authority_id,
            fixture.active.binding_id,
            KeryxBindingAuthorizationCapability::Revoke,
            expires_at,
            now(),
        )
        .unwrap();
    let revoked = fixture
        .store
        .revoke_n6_binding(
            &revocation_intent(authorization, &fixture.active, expires_at),
            now(),
        )
        .unwrap();
    assert_eq!(revoked.state, nodescale_domain::KeryxBindingState::Revoked);
}

#[test]
fn n6_revocation_remains_valid_before_any_n7_dispatch_attempt() {
    let fixture = fixture();
    reserve_n7_projection(&fixture, "n7-desired-before-n6-revocation");
    let (root, authority_id) = owner_authority(
        &fixture.store,
        [KeryxBindingAuthorizationCapability::Revoke],
    );
    let expires_at = now() + Duration::minutes(5);
    let authorization = fixture
        .store
        .issue_n6_binding_authorization(
            &root,
            authority_id,
            fixture.active.binding_id,
            KeryxBindingAuthorizationCapability::Revoke,
            expires_at,
            now(),
        )
        .unwrap();
    let revoked = fixture
        .store
        .revoke_n6_binding(
            &revocation_intent(authorization, &fixture.active, expires_at),
            now(),
        )
        .unwrap();
    assert_eq!(revoked.state, nodescale_domain::KeryxBindingState::Revoked);
}

#[test]
fn n6_rotation_and_revocation_reject_replayed_consumed_authorizations() {
    let rotation_fixture = fixture();
    let (rotation_root, rotation_authority) = owner_authority(
        &rotation_fixture.store,
        [KeryxBindingAuthorizationCapability::Rotate],
    );
    let rotation_expiry = now() + Duration::minutes(5);
    let rotation = rotation_intent(
        rotation_fixture
            .store
            .issue_n6_binding_authorization(
                &rotation_root,
                rotation_authority,
                rotation_fixture.active.binding_id,
                KeryxBindingAuthorizationCapability::Rotate,
                rotation_expiry,
                now(),
            )
            .unwrap(),
        &rotation_fixture.active,
        rotation_expiry,
    );
    let successor = rotation_fixture
        .store
        .rotate_n6_binding(&rotation, now())
        .unwrap();
    assert!(
        rotation_fixture
            .store
            .rotate_n6_binding(&rotation, now())
            .is_err()
    );
    assert_eq!(
        rotation_fixture
            .store
            .n6_binding(successor.binding_id)
            .unwrap(),
        successor
    );

    let revocation_fixture = fixture();
    let (revocation_root, revocation_authority) = owner_authority(
        &revocation_fixture.store,
        [KeryxBindingAuthorizationCapability::Revoke],
    );
    let revocation_expiry = now() + Duration::minutes(5);
    let revocation = revocation_intent(
        revocation_fixture
            .store
            .issue_n6_binding_authorization(
                &revocation_root,
                revocation_authority,
                revocation_fixture.active.binding_id,
                KeryxBindingAuthorizationCapability::Revoke,
                revocation_expiry,
                now(),
            )
            .unwrap(),
        &revocation_fixture.active,
        revocation_expiry,
    );
    let revoked = revocation_fixture
        .store
        .revoke_n6_binding(&revocation, now())
        .unwrap();
    assert!(
        revocation_fixture
            .store
            .revoke_n6_binding(&revocation, now())
            .is_err()
    );
    assert_eq!(
        revocation_fixture
            .store
            .n6_binding(revoked.binding_id)
            .unwrap(),
        revoked
    );
}

#[test]
fn n6_rotation_and_revocation_reject_authority_revoked_after_issuance() {
    for capability in [
        KeryxBindingAuthorizationCapability::Rotate,
        KeryxBindingAuthorizationCapability::Revoke,
    ] {
        let fixture = fixture();
        let (root, authority_id) = owner_authority(&fixture.store, [capability]);
        let expires_at = now() + Duration::minutes(5);
        let authorization = fixture
            .store
            .issue_n6_binding_authorization(
                &root,
                authority_id,
                fixture.active.binding_id,
                capability,
                expires_at,
                now(),
            )
            .unwrap();
        fixture
            .store
            .revoke_n5_trust_authority(&root, authority_id, now())
            .unwrap();

        let result = match capability {
            KeryxBindingAuthorizationCapability::Rotate => fixture.store.rotate_n6_binding(
                &rotation_intent(authorization, &fixture.active, expires_at),
                now(),
            ),
            KeryxBindingAuthorizationCapability::Revoke => fixture.store.revoke_n6_binding(
                &revocation_intent(authorization, &fixture.active, expires_at),
                now(),
            ),
        };
        assert!(result.is_err(), "revoked authority consumed {capability:?}");
        assert_binding_unchanged(&fixture.store, &fixture.active);
    }
}
