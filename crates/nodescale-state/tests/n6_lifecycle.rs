use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AgentVersion, BindingNonce, DeviceId, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability,
    Generation, JoinSessionId, KeryxBindingAuthorizationCapability, KeryxBindingDecisionId,
    KeryxPeerId, N6AuthenticatedBindRequest, N6BindingChallengeRequest, N6BindingRevocationIntent,
    N6BindingRotationIntent, NetworkId, OperationId, ReasonCode, TrustAuthorityId,
};
use nodescale_state::{
    N5TrustAuthorityConfiguration, N6AuthenticatedBindOutcome, StateError, StateStore,
};
use rusqlite::Connection;
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

fn seed_confirmed_n5_provenance(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n6 network','active','headscale','provider-n6',1,1,'{}','2026-08-08T00:00:00Z','2026-08-08T00:00:00Z');
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

fn request(nonce: BindingNonce, operation_id: &str) -> N6AuthenticatedBindRequest {
    N6AuthenticatedBindRequest::new(
        OperationId::parse(operation_id).unwrap(),
        NetworkId::parse(NETWORK).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
        JoinSessionId::parse(SESSION).unwrap(),
        nonce,
        Generation::initial(),
        version(),
    )
    .unwrap()
}

#[test]
fn n6_challenge_issuance_fails_closed_without_exact_n5_join_provenance() {
    let store = StateStore::open_in_memory().unwrap();
    let request = N6BindingChallengeRequest::new(
        NetworkId::new(),
        DeviceId::new(),
        JoinSessionId::new(),
        KeryxPeerId::parse("peer-n6").unwrap(),
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version(),
    )
    .unwrap();
    assert!(matches!(
        store.issue_n6_binding_challenge(
            OperationId::parse("challenge-missing").unwrap(),
            request,
            now(),
        ),
        Err(StateError::Conflict(_)) | Err(StateError::NotFound(_))
    ));
}

#[test]
fn n6_challenge_operation_resumes_before_issuance_and_never_reissues_after_response_loss() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-operation-recovery.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let peer = KeryxPeerId::parse("peer-n6").unwrap();
    let operation = OperationId::parse("challenge-recovery-1").unwrap();
    let challenge = N6BindingChallengeRequest::new(
        NetworkId::parse(NETWORK).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
        JoinSessionId::parse(SESSION).unwrap(),
        peer,
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version(),
    )
    .unwrap();

    assert!(matches!(
        store
            .reserve_n6_binding_challenge(&operation, &challenge, now())
            .unwrap(),
        nodescale_state::N6ChallengeReservationOutcome::Acquired(_)
    ));
    drop(store);

    let reopened = StateStore::open(&path).unwrap();
    assert!(matches!(
        reopened
            .reserve_n6_binding_challenge(&operation, &challenge, now())
            .unwrap(),
        nodescale_state::N6ChallengeReservationOutcome::Resumable(_)
    ));
    let issued = reopened
        .issue_n6_binding_challenge(operation.clone(), challenge.clone(), now())
        .unwrap();
    let issued_secret = issued.with_nonce(|nonce| nonce.with_encoded(str::to_owned));
    assert!(
        reopened
            .issue_n6_binding_challenge(operation, challenge, now())
            .is_err()
    );

    drop(reopened);
    let connection = Connection::open(path).unwrap();
    let issued_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n6_challenge_reservations WHERE reservation_state='issued'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(issued_count, 1);
    assert!(
        !connection
            .query_row(
                "SELECT challenge_verifier FROM n6_binding_challenges LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .contains(&issued_secret)
    );
}

#[test]
fn n6_reserves_before_secret_generation_replaces_pending_and_replays_durably() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-lifecycle.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let peer = KeryxPeerId::parse("peer-n6").unwrap();
    let challenge = || {
        N6BindingChallengeRequest::new(
            NetworkId::parse(NETWORK).unwrap(),
            DeviceId::parse(DEVICE).unwrap(),
            JoinSessionId::parse(SESSION).unwrap(),
            peer.clone(),
            Generation::initial(),
            now() + Duration::minutes(5),
            now(),
            version(),
        )
        .unwrap()
    };

    let first = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-1").unwrap(),
            challenge(),
            now(),
        )
        .unwrap();
    let first_nonce = first.with_nonce(|nonce| nonce.with_encoded(str::to_owned));
    let binding_id = first.binding_id();
    assert!(
        !store
            .n6_is_peer_active(NetworkId::parse(NETWORK).unwrap(), &peer)
            .unwrap()
    );

    let second = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-2").unwrap(),
            challenge(),
            now(),
        )
        .unwrap();
    let second_nonce = second.with_nonce(|nonce| nonce.with_encoded(str::to_owned));
    assert_eq!(second.binding_id(), binding_id);
    assert!(
        store
            .confirm_n6_authenticated_binding(
                peer.clone(),
                request(first_nonce.parse().unwrap(), "bind-1"),
                now()
            )
            .is_err()
    );

    let confirmed = store
        .confirm_n6_authenticated_binding(
            peer.clone(),
            request(second_nonce.parse().unwrap(), "bind-1"),
            now(),
        )
        .unwrap();
    let view = match confirmed {
        N6AuthenticatedBindOutcome::Confirmed(view) => view,
        other => panic!("unexpected confirmation outcome: {other:?}"),
    };
    assert_eq!(view.binding_id, binding_id);
    assert!(
        store
            .n6_is_peer_active(NetworkId::parse(NETWORK).unwrap(), &peer)
            .unwrap()
    );

    assert!(matches!(
        store
            .confirm_n6_authenticated_binding(
                peer.clone(),
                request(second_nonce.parse().unwrap(), "bind-1"),
                now()
            )
            .unwrap(),
        N6AuthenticatedBindOutcome::Replayed(_)
    ));
    assert!(matches!(
        store
            .confirm_n6_authenticated_binding(
                peer.clone(),
                request(BindingNonce::generate(), "bind-1"),
                now()
            )
            .unwrap(),
        N6AuthenticatedBindOutcome::Conflict
    ));

    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert!(
        reopened
            .n6_is_peer_active(NetworkId::parse(NETWORK).unwrap(), &peer)
            .unwrap()
    );
    assert!(matches!(
        reopened
            .confirm_n6_authenticated_binding(
                peer,
                request(second_nonce.parse().unwrap(), "bind-1"),
                now()
            )
            .unwrap(),
        N6AuthenticatedBindOutcome::Replayed(_)
    ));

    let connection = Connection::open(path).unwrap();
    let persisted: String = connection
        .query_row(
            "SELECT challenge_verifier FROM n6_binding_challenges ORDER BY issued_at_ms DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default();
    assert!(!persisted.starts_with("nsbind_"));
}

#[test]
fn n6_rotation_and_revocation_require_live_owner_authority_and_survive_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-rotation-revocation.db");
    let store = StateStore::open(&path).unwrap();
    seed_confirmed_n5_provenance(&path);
    let initial_peer = KeryxPeerId::parse("peer-n6-initial").unwrap();
    let challenge_request = N6BindingChallengeRequest::new(
        NetworkId::parse(NETWORK).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
        JoinSessionId::parse(SESSION).unwrap(),
        initial_peer.clone(),
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version(),
    )
    .unwrap();
    let challenge = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-initial").unwrap(),
            challenge_request,
            now(),
        )
        .unwrap();
    let nonce = challenge.with_nonce(|value| value.with_encoded(str::to_owned));
    let active = match store
        .confirm_n6_authenticated_binding(
            initial_peer,
            request(nonce.parse().unwrap(), "bind-initial"),
            now(),
        )
        .unwrap()
    {
        N6AuthenticatedBindOutcome::Confirmed(view) => view,
        other => panic!("unexpected initial bind outcome: {other:?}"),
    };

    let root = store
        .bootstrap_n5_owner_trust_root(
            NetworkId::parse(NETWORK).unwrap(),
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
                NetworkId::parse(NETWORK).unwrap(),
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
    store
        .grant_n6_binding_capability(
            &root,
            authority_id,
            KeryxBindingAuthorizationCapability::Rotate,
            now(),
        )
        .unwrap();
    store
        .grant_n6_binding_capability(
            &root,
            authority_id,
            KeryxBindingAuthorizationCapability::Revoke,
            now(),
        )
        .unwrap();

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
    let successor = store
        .rotate_n6_binding(
            &N6BindingRotationIntent::new(
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
            .unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(successor.generation, Generation::new(2).unwrap());
    assert!(
        !store
            .n6_is_peer_active(
                NetworkId::parse(NETWORK).unwrap(),
                &KeryxPeerId::parse("peer-n6-initial").unwrap(),
            )
            .unwrap()
    );

    let replacement_peer = KeryxPeerId::parse("peer-n6-replacement").unwrap();
    let replacement_challenge = store
        .issue_n6_binding_challenge(
            OperationId::parse("challenge-replacement").unwrap(),
            N6BindingChallengeRequest::new(
                NetworkId::parse(NETWORK).unwrap(),
                DeviceId::parse(DEVICE).unwrap(),
                JoinSessionId::parse(SESSION).unwrap(),
                replacement_peer.clone(),
                successor.generation,
                now() + Duration::minutes(5),
                now(),
                version(),
            )
            .unwrap(),
            now(),
        )
        .unwrap();
    let replacement_nonce =
        replacement_challenge.with_nonce(|value| value.with_encoded(str::to_owned));
    let replacement_request = N6AuthenticatedBindRequest::new(
        OperationId::parse("bind-replacement").unwrap(),
        NetworkId::parse(NETWORK).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
        JoinSessionId::parse(SESSION).unwrap(),
        replacement_nonce.parse().unwrap(),
        successor.generation,
        version(),
    )
    .unwrap();
    let replacement = match store
        .confirm_n6_authenticated_binding(replacement_peer.clone(), replacement_request, now())
        .unwrap()
    {
        N6AuthenticatedBindOutcome::Confirmed(view) => view,
        other => panic!("unexpected replacement bind outcome: {other:?}"),
    };

    let revoke_authorization = store
        .issue_n6_binding_authorization(
            &root,
            authority_id,
            replacement.binding_id,
            KeryxBindingAuthorizationCapability::Revoke,
            now() + Duration::minutes(10),
            now(),
        )
        .unwrap();
    let revoked = store
        .revoke_n6_binding(
            &N6BindingRevocationIntent::new(
                KeryxBindingDecisionId::new(),
                revoke_authorization,
                replacement.binding_id,
                replacement.generation,
                replacement.revision,
                now() + Duration::minutes(5),
                now(),
                ReasonCode::parse("owner_revocation").unwrap(),
            )
            .unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(revoked.state, nodescale_domain::KeryxBindingState::Revoked);
    assert!(
        !store
            .n6_is_peer_active(NetworkId::parse(NETWORK).unwrap(), &replacement_peer)
            .unwrap()
    );

    drop(store);
    let reopened = StateStore::open(path).unwrap();
    assert_eq!(
        reopened.n6_binding(replacement.binding_id).unwrap().state,
        nodescale_domain::KeryxBindingState::Revoked
    );
}
