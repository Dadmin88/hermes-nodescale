use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AgentVersion, BindingNonce, DeviceId, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability,
    Generation, JoinSessionId, KeryxBindingAuthorizationCapability, KeryxBindingDecisionId,
    KeryxBindingState, KeryxPeerId, N6AuthenticatedBindRequest, N6BindingChallengeRequest,
    N6BindingRevocationIntent, N6BindingRotationIntent, NetworkId, OperationId, ReasonCode,
    TrustAuthorityId,
};
use nodescale_state::{
    N5TrustAuthorityConfiguration, N6AuthenticatedBindOutcome, N6ChallengeReservationOutcome,
    StateStore,
};
use rusqlite::Connection;
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

const NETWORK: &str = "10bdbae2-73be-46f2-8f0a-5b761fdeaf4d";
const DEVICE: &str = "f9b36c3a-e777-4e92-a4ea-14d22a234ecc";
const SESSION: &str = "cafa4427-4c17-408e-bfed-c93f34bd3756";

fn now() -> DateTime<Utc> {
    "2026-08-08T00:00:00Z".parse().unwrap()
}

fn version() -> AgentVersion {
    AgentVersion::parse("nodescale-agent:6.0.0").unwrap()
}

// This is prerequisite provenance only. Every N6 transition below uses the
// public StateStore operation path.
fn seed_confirmed_n5_provenance(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n6 concurrency','active','headscale','provider-n6',1,1,'{}','2026-08-08T00:00:00Z','2026-08-08T00:00:00Z');
             INSERT INTO devices (device_id,network_id,display_name,membership_state,provider_instance_id,provider_node_id,provider_key_fingerprint,credential_generation,keryx_binding_generation,fleet_projection_generation,fleet_projection_status,record_json,created_at,updated_at,revoked_at)
             VALUES ('f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n6 device','pending',NULL,NULL,NULL,1,1,1,'none','{}','2026-08-08T00:00:00Z','2026-08-08T00:00:00Z',NULL);
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

fn network_id() -> NetworkId {
    NetworkId::parse(NETWORK).unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::parse(DEVICE).unwrap()
}

fn session_id() -> JoinSessionId {
    JoinSessionId::parse(SESSION).unwrap()
}

fn challenge(peer: KeryxPeerId) -> N6BindingChallengeRequest {
    N6BindingChallengeRequest::new(
        network_id(),
        device_id(),
        session_id(),
        peer,
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version(),
    )
    .unwrap()
}

fn bind_request(nonce: &str, operation_id: &str) -> N6AuthenticatedBindRequest {
    N6AuthenticatedBindRequest::new(
        OperationId::parse(operation_id).unwrap(),
        network_id(),
        device_id(),
        session_id(),
        nonce.parse::<BindingNonce>().unwrap(),
        Generation::initial(),
        version(),
    )
    .unwrap()
}

fn n6_counts(path: &std::path::Path) -> (i64, i64, i64, i64) {
    let connection = Connection::open(path).unwrap();
    (
        connection
            .query_row("SELECT COUNT(*) FROM n6_binding_records", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM n6_binding_challenges", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM n6_binding_decisions", [], |row| {
                row.get(0)
            })
            .unwrap(),
        connection
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE event_kind LIKE 'keryx_binding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap(),
    )
}

#[test]
fn separate_connections_race_the_same_challenge_operation_to_one_durable_reservation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-challenge-reservation-race.db");
    let setup = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    drop(setup);

    let peer = KeryxPeerId::parse("peer-n6-reservation-race").unwrap();
    let operation = OperationId::parse("challenge-operation-race").unwrap();
    let request = challenge(peer);
    let barrier = Arc::new(Barrier::new(2));
    let joins = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let operation = operation.clone();
            let request = request.clone();
            std::thread::spawn(move || {
                let store = StateStore::open(path).unwrap();
                barrier.wait();
                store.reserve_n6_binding_challenge(&operation, &request, now())
            })
        })
        .collect::<Vec<_>>();
    let outcomes = joins
        .into_iter()
        .map(|join| join.join().unwrap().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, N6ChallengeReservationOutcome::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, N6ChallengeReservationOutcome::Resumable(_)))
            .count(),
        1
    );

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n6_challenge_reservations",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(n6_counts(&path), (1, 0, 1, 1));
}

#[test]
fn separate_connections_race_the_same_bind_operation_to_one_confirmation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-bind-operation-race.db");
    let setup = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let peer = KeryxPeerId::parse("peer-n6-bind-race").unwrap();
    let delivery = setup
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-bind-race").unwrap(),
            challenge(peer.clone()),
            now(),
        )
        .unwrap();
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    drop(setup);

    let barrier = Arc::new(Barrier::new(2));
    let joins = (0..2)
        .map(|_| {
            let path = path.clone();
            let peer = peer.clone();
            let nonce = nonce.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = StateStore::open(path).unwrap();
                barrier.wait();
                store.confirm_n6_authenticated_binding(
                    peer,
                    bind_request(&nonce, "bind-operation-race"),
                    now(),
                )
            })
        })
        .collect::<Vec<_>>();
    let outcomes = joins
        .into_iter()
        .map(|join| join.join().unwrap().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, N6AuthenticatedBindOutcome::Confirmed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, N6AuthenticatedBindOutcome::Replayed(_)))
            .count(),
        1
    );

    let fresh = StateStore::open(&path).unwrap();
    assert!(fresh.n6_is_peer_active(network_id(), &peer).unwrap());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM n6_control_operations", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    assert_eq!(n6_counts(&path), (1, 1, 4, 4));
}

#[test]
fn replay_after_restart_emits_no_additional_n6_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-restart-replay.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let peer = KeryxPeerId::parse("peer-n6-restart-replay").unwrap();
    let delivery = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-restart-replay").unwrap(),
            challenge(peer.clone()),
            now(),
        )
        .unwrap();
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    assert!(matches!(
        store
            .confirm_n6_authenticated_binding(
                peer.clone(),
                bind_request(&nonce, "bind-restart-replay"),
                now(),
            )
            .unwrap(),
        N6AuthenticatedBindOutcome::Confirmed(_)
    ));
    let evidence_before = n6_counts(&path);
    drop(store);

    let reopened = StateStore::open(&path).unwrap();
    assert!(matches!(
        reopened
            .confirm_n6_authenticated_binding(
                peer,
                bind_request(&nonce, "bind-restart-replay"),
                now(),
            )
            .unwrap(),
        N6AuthenticatedBindOutcome::Replayed(_)
    ));
    drop(reopened);

    assert_eq!(n6_counts(&path), evidence_before);
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM n6_control_operations", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
}

#[test]
fn revocation_wins_before_a_stale_rotation_and_cannot_be_reactivated() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-revoke-then-rotate.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let peer = KeryxPeerId::parse("peer-n6-revoke-first").unwrap();
    let delivery = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-revoke-first").unwrap(),
            challenge(peer.clone()),
            now(),
        )
        .unwrap();
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    let active = match store
        .confirm_n6_authenticated_binding(
            peer.clone(),
            bind_request(&nonce, "bind-revoke-first"),
            now(),
        )
        .unwrap()
    {
        N6AuthenticatedBindOutcome::Confirmed(view) => view,
        outcome => panic!("unexpected initial binding outcome: {outcome:?}"),
    };

    let root = store
        .bootstrap_n5_owner_trust_root(
            network_id(),
            "local-owner",
            "owner-n6-concurrency",
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
                "owner-n6-concurrency",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    for capability in [
        KeryxBindingAuthorizationCapability::Rotate,
        KeryxBindingAuthorizationCapability::Revoke,
    ] {
        store
            .grant_n6_binding_capability(&root, authority_id, capability, now())
            .unwrap();
    }
    let rotate_authorization = store
        .issue_n6_binding_authorization(
            &root,
            authority_id,
            active.binding_id,
            KeryxBindingAuthorizationCapability::Rotate,
            now() + Duration::minutes(10),
            now(),
        )
        .unwrap();
    let revoke_authorization = store
        .issue_n6_binding_authorization(
            &root,
            authority_id,
            active.binding_id,
            KeryxBindingAuthorizationCapability::Revoke,
            now() + Duration::minutes(10),
            now(),
        )
        .unwrap();
    let rotate = N6BindingRotationIntent::new(
        KeryxBindingDecisionId::new(),
        rotate_authorization,
        active.binding_id,
        active.generation,
        active.revision,
        active.generation.next_exact().unwrap(),
        now() + Duration::minutes(5),
        now(),
        ReasonCode::parse("owner_rotation").unwrap(),
    )
    .unwrap();
    let revoke = N6BindingRevocationIntent::new(
        KeryxBindingDecisionId::new(),
        revoke_authorization,
        active.binding_id,
        active.generation,
        active.revision,
        now() + Duration::minutes(5),
        now(),
        ReasonCode::parse("owner_revocation").unwrap(),
    )
    .unwrap();
    drop(store);

    let revoker = StateStore::open(&path).unwrap();
    let revoked = revoker.revoke_n6_binding(&revoke, now()).unwrap();
    assert_eq!(revoked.state, KeryxBindingState::Revoked);
    drop(revoker);

    let rotator = StateStore::open(&path).unwrap();
    assert!(rotator.rotate_n6_binding(&rotate, now()).is_err());
    drop(rotator);

    let fresh = StateStore::open(&path).unwrap();
    assert_eq!(
        fresh.n6_binding(active.binding_id).unwrap().state,
        KeryxBindingState::Revoked
    );
    assert!(!fresh.n6_is_peer_active(network_id(), &peer).unwrap());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n6_binding_records WHERE generation = 2",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n6_binding_records WHERE binding_state = 'active'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
