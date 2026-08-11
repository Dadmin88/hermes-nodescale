use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AgentVersion, AuditActor, Device, DeviceId, Generation, JoinSessionId, KeryxBindingId,
    KeryxPeerId, MembershipState, N6AuthenticatedBindRequest, N6BindingChallengeRequest, Network,
    NetworkId, Operation, OperationId, ProjectionStatus, ProviderInstanceId, ProviderKind, Role,
    Roles,
    n7::{FleetGeneratedGrants, N7FleetDesiredProjection},
};
use nodescale_state::{
    N7AuthoritativeInspection, N7BindingProvenance, N7ProjectionAttemptOutcome,
    N7ProjectionReservationOutcome, N7ProjectionState, N7ProjectionSubmission,
    SUPPORTED_SCHEMA_VERSION, StateError, StateStore,
};
use rusqlite::{Connection, params};
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

const DESIRED_BODY: &[u8] = br#"{"fleet":"desired"}"#;
const OTHER_BODY: &[u8] = br#"{"fleet":"other"}"#;
const PRE_N7_MIGRATIONS: [&str; 6] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_discovery_reconciliation.sql"),
    include_str!("../migrations/0003_mutation_authorization.sql"),
    include_str!("../migrations/0004_invitation_lifecycle.sql"),
    include_str!("../migrations/0005_device_trust.sql"),
    include_str!("../migrations/0006_keryx_identity_binding.sql"),
];

fn now() -> DateTime<Utc> {
    "2026-08-08T00:00:00Z".parse().unwrap()
}

fn seed(store: &StateStore) -> (NetworkId, DeviceId) {
    let network_id = NetworkId::new();
    let network = Network::new(
        network_id,
        "n7 durable projection",
        ProviderKind::Headscale,
        ProviderInstanceId::parse("058b9369-92c7-4fa5-a7cd-5df87513f41a").unwrap(),
        now(),
    )
    .unwrap();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let device = Device::new(DeviceId::new(), network_id, "n7-device", now()).unwrap();
    store.create_device(&device, AuditActor::system()).unwrap();
    (network_id, device.device_id)
}

/// Builds a real active N6 binding through its public challenge/confirmation
/// state machine. The raw N4/N5 rows below are only the pre-existing confirmed
/// enrollment fixture required to reach that public N6 boundary.
fn seed_active_n6(
    store: &StateStore,
    path: &std::path::Path,
    network_id: NetworkId,
    device_id: DeviceId,
) -> N7BindingProvenance {
    let invitation_id = "60000000-0000-0000-0000-000000000001";
    let session_id = JoinSessionId::parse("70000000-0000-0000-0000-000000000001").unwrap();
    let credential_id = "80000000-0000-0000-0000-000000000001";
    let network = network_id.to_string();
    let device = device_id.to_string();
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(&format!(
        "INSERT INTO invitations (invitation_id,network_id,state,secret_verifier,provider_credential_reference,max_uses,used_count,record_json,created_at,expires_at) VALUES ('{invitation_id}','{network}','issued','$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$MDEyMzQ1Njc4OWFiY2RlZg',NULL,1,0,'{{}}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z');
         INSERT INTO join_sessions (join_session_id,invitation_id,network_id,device_id,state,record_json,created_at,expires_at,updated_at) VALUES ('{session_id}','{invitation_id}','{network}','{device}','credential_issued','{{}}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z','2026-08-08T00:00:00Z');
         INSERT INTO provider_imports (network_id,provider_instance_id,server_url,opaque_secret_reference,compatibility_pin,tls_verification,read_only,mutation_allowed,compatibility,provider_version,last_success_at,last_attempt_at,last_failure_kind,last_failure_detail,custom_root_ca_sha256) VALUES ('{network}','provider-n7','https://provider.example.test','secret://vault/n7','v0.29.3','verify',1,0,'compatible','v0.29.3',NULL,NULL,NULL,NULL,NULL);
         INSERT INTO provider_mutation_configurations (network_id,provider_instance_id,authorization_generation,configuration_generation,configuration_fingerprint,adapter,expected_version,enabled,revoked,not_before_ms,expires_at_ms,policy_mode) VALUES ('{network}','provider-n7',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','headscale','v0.29.3',1,0,0,999999999999,'database');
         INSERT INTO confirmed_provider_credential_references (credential_id,network_id,provider_instance_id,provider_reference,authorization_generation,configuration_generation,configuration_fingerprint,confirmed_at_ms,expires_at_ms,max_uses) VALUES ('{credential_id}','{network}','provider-n7','provider-ref-n7',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,999999999999,1);
         INSERT INTO n4_invitation_details (invitation_id,network_id,provider_instance_id,provider_principal_id,roles_json,constraints_json,created_by_source,created_by_id,revision,last_redemption_metadata_json) VALUES ('{invitation_id}','{network}','provider-n7','principal-n7','[]','{{}}','nodescale',NULL,1,'{{}}');
         INSERT INTO n4_join_session_dispatches (join_session_id,invitation_id,network_id,provider_instance_id,provider_principal_id,create_request_id,dispatch_state,authorization_generation,configuration_generation,configuration_fingerprint,dispatched_at_ms,resolved_at_ms,credential_id) VALUES ('{session_id}','{invitation_id}','{network}','provider-n7','principal-n7','90000000-0000-0000-0000-000000000001','confirmed',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,1001,'{credential_id}');
         INSERT INTO n5_device_identities (device_id,network_id,origin_join_session_id,confirmed_at_ms,identity_revision,safe_correlation_digest) VALUES ('{device}','{network}','{session_id}',1001,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');"
    )).unwrap();
    let peer = KeryxPeerId::parse("peer-n7").unwrap();
    let version = AgentVersion::parse("nodescale-agent:7.0.0").unwrap();
    let challenge = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        session_id,
        peer.clone(),
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version.clone(),
    )
    .unwrap();
    let delivery = store
        .issue_n6_binding_challenge(
            OperationId::parse("n7-binding-challenge").unwrap(),
            challenge,
            now(),
        )
        .unwrap();
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    let confirmed = store
        .confirm_n6_authenticated_binding(
            peer.clone(),
            N6AuthenticatedBindRequest::new(
                OperationId::parse("n7-binding-confirm").unwrap(),
                network_id,
                device_id,
                session_id,
                nonce.parse().unwrap(),
                Generation::initial(),
                version,
            )
            .unwrap(),
            now(),
        )
        .unwrap();
    let binding = match confirmed {
        nodescale_state::N6AuthenticatedBindOutcome::Confirmed(binding) => binding,
        other => panic!("unexpected N6 binding outcome: {other:?}"),
    };
    N7BindingProvenance::new(
        binding.binding_id.to_string(),
        peer.to_string(),
        binding.generation,
    )
    .unwrap()
}

#[test]
fn active_n6_provenance_runtime_seam_requires_the_exact_active_durable_tuple() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-active-n6-provenance.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let binding_id = KeryxBindingId::parse(&binding.binding_id).unwrap();

    let active = store
        .n6_active_binding_provenance(
            binding_id,
            network_id,
            device_id,
            binding.binding_generation,
        )
        .expect("only the public N6 lifecycle may supply active provenance");
    let desired = N7FleetDesiredProjection::upsert_from_active_n6_provenance(
        network_id,
        device_id,
        "n7-device",
        MembershipState::Active,
        Generation::initial(),
        Generation::initial(),
        active,
        Roles::new([Role::Worker]).unwrap(),
        FleetGeneratedGrants::new([Operation::FleetHealth]).unwrap(),
    )
    .expect("opaque active provenance can construct desired N7 state");
    assert_eq!(desired.binding_provenance().binding_id(), binding_id);
    assert!(matches!(
        store.n6_active_binding_provenance(
            binding_id,
            network_id,
            DeviceId::new(),
            binding.binding_generation,
        ),
        Err(StateError::NotFound(_))
    ));
}

fn submission(
    network_id: NetworkId,
    device_id: DeviceId,
    operation_id: &str,
    body: &[u8],
    binding: &N7BindingProvenance,
) -> N7ProjectionSubmission {
    submission_at_generation(
        network_id,
        device_id,
        operation_id,
        Generation::initial(),
        body,
        binding,
    )
}

fn submission_at_generation(
    network_id: NetworkId,
    device_id: DeviceId,
    operation_id: &str,
    generation: Generation,
    body: &[u8],
    binding: &N7BindingProvenance,
) -> N7ProjectionSubmission {
    N7ProjectionSubmission::from_canonical(
        OperationId::parse(operation_id).unwrap(),
        network_id,
        device_id,
        generation,
        body.to_vec(),
        binding.binding_id.clone(),
        binding.authenticated_peer_id.clone(),
        binding.binding_generation,
    )
    .unwrap()
}

#[test]
fn canonical_submission_binds_full_body_and_n6_provenance_before_dispatch() {
    let result = N7ProjectionSubmission::from_canonical(
        OperationId::parse("n7-canonical-provenance").unwrap(),
        NetworkId::new(),
        DeviceId::new(),
        Generation::initial(),
        DESIRED_BODY.to_vec(),
        "10000000-0000-0000-0000-000000000001",
        "peer-n7",
        Generation::initial(),
    )
    .unwrap();
    assert_eq!(result.desired_body, DESIRED_BODY);
    assert!(result.desired_hash.starts_with("sha256:"));
    assert!(
        N7ProjectionSubmission::from_canonical(
            result.operation_id.clone(),
            result.network_id,
            result.device_id,
            result.generation,
            br#"{"z":1,"a":2}"#.to_vec(),
            result.binding.binding_id,
            result.binding.authenticated_peer_id,
            result.binding.binding_generation,
        )
        .is_err(),
        "unordered JSON cannot masquerade as a canonical durable body"
    );
}

#[test]
fn v6_database_upgrades_to_v7_with_n7_durable_tables() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-upgrade.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in PRE_N7_MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .pragma_update(None, "user_version", 6_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    drop(store);
    let connection = Connection::open(path).unwrap();
    for table in [
        "n7_fleet_projection_records",
        "n7_fleet_projection_operations",
        "n7_fleet_projection_attempts",
        "n7_fleet_projection_inspections",
        "n7_fleet_projection_audit",
    ] {
        assert!(
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get::<_, bool>(0)
                )
                .unwrap(),
            "missing {table}"
        );
    }
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn desired_body_and_exact_n6_provenance_are_persisted_before_dispatch_and_fence_replay() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-desired.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let first = submission(
        network_id,
        device_id,
        "n7-projection-1",
        DESIRED_BODY,
        &binding,
    );

    let view = match store.reserve_n7_projection(&first, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected initial reservation: {other:?}"),
    };
    assert_eq!(view.state, N7ProjectionState::Desired);
    assert_eq!(view.revision, 1);
    assert_eq!(view.desired_body, DESIRED_BODY);
    assert_eq!(view.binding, binding);
    assert_eq!(
        store.device(device_id).unwrap().fleet_projection_status,
        ProjectionStatus::Pending
    );

    let connection = Connection::open(&path).unwrap();
    let row: (Vec<u8>, String, String, String, i64) = connection.query_row(
        "SELECT desired_body,desired_hash,binding_id,authenticated_peer_id,revision FROM n7_fleet_projection_records", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).unwrap();
    assert_eq!(row.0, DESIRED_BODY);
    assert!(row.1.starts_with("sha256:"));
    assert_eq!(row.2, binding.binding_id);
    assert_eq!(row.3, binding.authenticated_peer_id);
    assert_eq!(row.4, 1);
    drop(connection);

    assert!(matches!(
        store.reserve_n7_projection(&first, now()).unwrap(),
        N7ProjectionReservationOutcome::Replayed(_)
    ));
    let same_body_new_operation = submission(
        network_id,
        device_id,
        "n7-projection-2",
        DESIRED_BODY,
        &binding,
    );
    assert!(matches!(
        store
            .reserve_n7_projection(&same_body_new_operation, now())
            .unwrap(),
        N7ProjectionReservationOutcome::Replayed(_)
    ));
    let conflict = submission(
        network_id,
        device_id,
        "n7-projection-3",
        OTHER_BODY,
        &binding,
    );
    assert!(matches!(
        store.reserve_n7_projection(&conflict, now()).unwrap(),
        N7ProjectionReservationOutcome::Conflict
    ));
}

#[test]
fn response_loss_restart_preserves_attempt_and_retries_missing_or_unavailable_inspection_without_terminal_conflict()
 {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-response-loss.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let request = submission(
        network_id,
        device_id,
        "n7-response-loss",
        DESIRED_BODY,
        &binding,
    );
    let reserved = match store.reserve_n7_projection(&request, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected reservation: {other:?}"),
    };
    let attempted = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            reserved.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("unexpected attempt outcome: {other:?}"),
    };
    drop(store);

    let reopened = StateStore::open(&path).unwrap();
    for inspection in [
        N7AuthoritativeInspection::unavailable(),
        N7AuthoritativeInspection::missing(),
    ] {
        let retriable = reopened
            .recover_n7_projection_from_inspection(
                &request.operation_id,
                device_id,
                request.generation,
                attempted.revision,
                inspection,
                now(),
            )
            .unwrap();
        assert_eq!(retriable.state, N7ProjectionState::Attempted);
        assert_eq!(retriable.revision, attempted.revision);
    }
    assert!(matches!(
        reopened.recover_n7_projection_from_inspection(
            &request.operation_id,
            device_id,
            request.generation,
            attempted.revision - 1,
            N7AuthoritativeInspection::observed(DESIRED_BODY.to_vec()).unwrap(),
            now()
        ),
        Err(StateError::StaleGeneration { .. })
    ));
    let applied = reopened
        .recover_n7_projection_from_inspection(
            &request.operation_id,
            device_id,
            request.generation,
            attempted.revision,
            N7AuthoritativeInspection::observed(DESIRED_BODY.to_vec()).unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(applied.state, N7ProjectionState::Applied);
    assert_eq!(
        reopened.device(device_id).unwrap().fleet_projection_status,
        ProjectionStatus::Applied
    );
    drop(reopened);

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_inspections",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        3
    );
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM n7_fleet_projection_audit WHERE event_kind='projection_applied'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
}

#[test]
fn retry_dispatch_requires_the_exact_n6_binding_to_remain_active() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-retry-active-provenance.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let request = submission(
        network_id,
        device_id,
        "n7-retry-active-provenance",
        DESIRED_BODY,
        &binding,
    );
    let reserved = match store.reserve_n7_projection(&request, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected reservation: {other:?}"),
    };
    let attempted = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            reserved.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("unexpected attempt outcome: {other:?}"),
    };

    // Model an N6 authority transition independently of the N7 dispatch API.
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER n6_binding_transition_guard;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n6_binding_records SET binding_state='stale',revision=revision+1,stale_at_ms=?1,last_decision_id='a0000000-0000-0000-0000-000000000001',last_audit_event_id='a0000000-0000-0000-0000-000000000002' WHERE binding_id=?2",
            params![now().timestamp_millis(), binding.binding_id],
        )
        .unwrap();

    assert!(matches!(
        store.record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            attempted.revision,
            now(),
        ),
        Err(StateError::Conflict(message)) if message == "N7 binding provenance is no longer active"
    ));
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_attempts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );

    connection
        .execute(
            "INSERT INTO n7_fleet_projection_attempts (attempt_id,projection_id,operation_id,attempt_number,expected_revision,attempted_at_ms) SELECT 'a0000000-0000-0000-0000-000000000003',projection_id,?1,2,2,?2 FROM n7_fleet_projection_records",
            params![request.operation_id.as_str(), now().timestamp_millis()],
        )
        .unwrap();
    let error = connection
        .execute(
            "UPDATE n7_fleet_projection_records SET current_attempt_id='a0000000-0000-0000-0000-000000000003' WHERE projection_state='attempted'",
            [],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("N7 projection transition requires exact durable identity")
    );
}

#[test]
fn a_matching_hash_without_matching_full_observed_body_never_emits_applied_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-inspect-conflict.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let request = submission(
        network_id,
        device_id,
        "n7-inspect-conflict",
        DESIRED_BODY,
        &binding,
    );
    let reserved = match store.reserve_n7_projection(&request, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected reservation: {other:?}"),
    };
    let attempted = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            reserved.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("unexpected attempt outcome: {other:?}"),
    };
    let conflicted = store
        .recover_n7_projection_from_inspection(
            &request.operation_id,
            device_id,
            request.generation,
            attempted.revision,
            N7AuthoritativeInspection::observed(OTHER_BODY.to_vec()).unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(conflicted.state, N7ProjectionState::Conflict);
    assert_eq!(
        store.device(device_id).unwrap().fleet_projection_status,
        ProjectionStatus::Conflict
    );
    drop(store);
    let connection = Connection::open(path).unwrap();
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM n7_fleet_projection_audit WHERE event_kind='projection_applied'", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM n7_fleet_projection_audit WHERE event_kind='projection_conflict'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    assert!(
        connection
            .execute(
                "UPDATE n7_fleet_projection_records SET desired_body=?1",
                [OTHER_BODY]
            )
            .is_err(),
        "desired bytes must be immutable across transitions"
    );
}

#[test]
fn separate_file_backed_connections_admit_one_desired_projection_and_one_safe_audit_chain() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-concurrency.db");
    let setup = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&setup);
    let binding = seed_active_n6(&setup, &path, network_id, device_id);
    drop(setup);
    let request = submission(
        network_id,
        device_id,
        "n7-concurrent",
        DESIRED_BODY,
        &binding,
    );
    let barrier = Arc::new(Barrier::new(2));
    let joins = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let request = request.clone();
            std::thread::spawn(move || {
                let store = StateStore::open(path).unwrap();
                barrier.wait();
                store.reserve_n7_projection(&request, now())
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
            .filter(|outcome| matches!(outcome, N7ProjectionReservationOutcome::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, N7ProjectionReservationOutcome::Replayed(_)))
            .count(),
        1
    );
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_records",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_operations",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_audit",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn accepted_successor_reservations_advance_only_fleet_projection_generation_across_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-generation-progression.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);

    let rejected = submission_at_generation(
        network_id,
        device_id,
        "n7-rejected-before-generation-advance",
        Generation::initial(),
        DESIRED_BODY,
        &N7BindingProvenance::new(
            binding.binding_id.clone(),
            "wrong-peer",
            binding.binding_generation,
        )
        .unwrap(),
    );
    assert!(matches!(
        store.reserve_n7_projection(&rejected, now()).unwrap(),
        N7ProjectionReservationOutcome::Conflict
    ));
    assert_eq!(
        store
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::initial(),
        "a rejected reservation must not consume the fleet generation"
    );

    let first = submission(
        network_id,
        device_id,
        "n7-generation-1",
        DESIRED_BODY,
        &binding,
    );
    assert!(matches!(
        store.reserve_n7_projection(&first, now()).unwrap(),
        N7ProjectionReservationOutcome::Reserved(_)
    ));
    let after_first = store.device_generations(device_id).unwrap();
    assert_eq!(after_first.fleet_projection, Generation::new(2).unwrap());
    assert_eq!(after_first.credential, Generation::initial());
    assert_eq!(after_first.keryx_binding, Generation::initial());
    assert_eq!(
        store
            .device(device_id)
            .unwrap()
            .generations
            .fleet_projection,
        Generation::new(2).unwrap(),
        "the durable device record must agree with device_generations"
    );
    assert!(matches!(
        store.reserve_n7_projection(&first, now()).unwrap(),
        N7ProjectionReservationOutcome::Replayed(_)
    ));
    assert_eq!(
        store
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::new(2).unwrap(),
        "a replay must not advance a second time"
    );
    drop(store);

    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::new(2).unwrap()
    );
    let second = submission_at_generation(
        network_id,
        device_id,
        "n7-generation-2",
        Generation::new(2).unwrap(),
        OTHER_BODY,
        &binding,
    );
    assert!(matches!(
        reopened.reserve_n7_projection(&second, now()).unwrap(),
        N7ProjectionReservationOutcome::Reserved(_)
    ));
    assert_eq!(
        reopened
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::new(3).unwrap()
    );
    assert!(matches!(
        reopened.reserve_n7_projection(&second, now()).unwrap(),
        N7ProjectionReservationOutcome::Replayed(_)
    ));
    assert_eq!(
        reopened
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::new(3).unwrap(),
        "a successor replay must preserve its already-consumed generation"
    );
}

#[test]
fn n7_generation_advance_failure_rolls_back_the_entire_reservation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-generation-rollback.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE devices SET fleet_projection_generation=2 WHERE device_id=?1",
            [device_id.to_string()],
        )
        .unwrap();
    drop(connection);

    let request = submission(
        network_id,
        device_id,
        "n7-generation-rollback",
        DESIRED_BODY,
        &binding,
    );
    assert!(matches!(
        store.reserve_n7_projection(&request, now()),
        Err(StateError::StaleGeneration {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!(
        store
            .device_generations(device_id)
            .unwrap()
            .fleet_projection,
        Generation::initial(),
        "the fleet generation update must be rolled back with the rejected reservation"
    );
    assert_eq!(
        store.device(device_id).unwrap().fleet_projection_status,
        ProjectionStatus::NotRequested,
        "the pending device status must roll back with generation advancement"
    );
    drop(store);
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_records",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_audit",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn n7_referenced_audit_events_are_immutable_and_reject_secret_like_metadata_in_sql() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-audit-immutability.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let request = submission(
        network_id,
        device_id,
        "n7-audit-immutable",
        DESIRED_BODY,
        &binding,
    );
    let reserved = match store.reserve_n7_projection(&request, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected reservation: {other:?}"),
    };
    let attempted = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            reserved.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("unexpected attempt: {other:?}"),
    };
    assert_eq!(
        store
            .recover_n7_projection_from_inspection(
                &request.operation_id,
                device_id,
                request.generation,
                attempted.revision,
                N7AuthoritativeInspection::observed(DESIRED_BODY.to_vec()).unwrap(),
                now(),
            )
            .unwrap()
            .state,
        N7ProjectionState::Applied
    );
    drop(store);

    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let event_ids = connection
        .prepare("SELECT audit_event_id FROM n7_fleet_projection_audit ORDER BY revision")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(event_ids.len(), 3, "every N7 transition must be audited");
    for event_id in event_ids {
        for sql in [
            "UPDATE audit_events SET outcome='failure' WHERE event_id=?1",
            "DELETE FROM audit_events WHERE event_id=?1",
        ] {
            let error = connection.execute(sql, [&event_id]).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("N7 audit events are append-only"),
                "direct SQL must hit the N7 immutability guard: {error}"
            );
        }
    }
    for (index, metadata_json) in [
        r#"{"secret":"redacted"}"#,
        r#"{"detail":"token opaque-value"}"#,
        r#"{"password":"redacted"}"#,
        r#"{"detail":"Bearer opaque-value"}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let error = connection
            .execute(
                "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES (?1,?2,?3,?4,'nodescale',NULL,'fleet_projection_desired','success',?5,?6)",
                params![format!("n7-unsafe-metadata-{index}"), now().to_rfc3339(), network_id.to_string(), device_id.to_string(), request.generation.get(), metadata_json],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("N7 audit metadata must be secret-free"),
            "direct SQL must reject N7 secret-like metadata: {error}"
        );
    }
    connection
        .execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES ('n7-safe-metadata',?1,?2,?3,'nodescale',NULL,'fleet_projection_desired','success',?4,'{}')",
            params![now().to_rfc3339(), network_id.to_string(), device_id.to_string(), request.generation.get()],
        )
        .unwrap();
    let error = connection
        .execute(
            "UPDATE audit_events SET metadata_json=?1 WHERE event_id='n7-safe-metadata'",
            [r#"{"authorization":"Bearer opaque-value"}"#],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("N7 audit metadata must be secret-free"),
        "direct SQL updates must reject N7 secret-like metadata: {error}"
    );
}

#[test]
fn hostile_sql_cannot_terminalize_without_the_current_attempt_inspection_or_forge_audit_state() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n7-hostile-provenance.db");
    let store = StateStore::open(&path).unwrap();
    let (network_id, device_id) = seed(&store);
    let binding = seed_active_n6(&store, &path, network_id, device_id);
    let request = submission(
        network_id,
        device_id,
        "n7-hostile-provenance",
        DESIRED_BODY,
        &binding,
    );
    let reserved = match store.reserve_n7_projection(&request, now()).unwrap() {
        N7ProjectionReservationOutcome::Reserved(view) => view,
        other => panic!("unexpected reservation: {other:?}"),
    };
    let first = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            reserved.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("unexpected first attempt: {other:?}"),
    };
    store
        .recover_n7_projection_from_inspection(
            &request.operation_id,
            device_id,
            request.generation,
            first.revision,
            N7AuthoritativeInspection::missing(),
            now(),
        )
        .unwrap();
    let retry = match store
        .record_n7_projection_dispatch_attempt(
            &request.operation_id,
            device_id,
            request.generation,
            first.revision,
            now(),
        )
        .unwrap()
    {
        N7ProjectionAttemptOutcome::Recorded(view) => view,
        other => panic!("missing recovery must append a fresh attempt: {other:?}"),
    };

    let connection = Connection::open(&path).unwrap();
    let projection_id: String = connection
        .query_row(
            "SELECT projection_id FROM n7_fleet_projection_records",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let terminal_error = connection
        .execute(
            "UPDATE n7_fleet_projection_records SET projection_state='applied',revision=3,applied_at_ms=?1 WHERE projection_id=?2",
            params![now().timestamp_millis(), projection_id],
        )
        .unwrap_err();
    assert!(
        terminal_error
            .to_string()
            .contains("N7 projection transition requires exact durable identity"),
        "a direct terminal write needs observed inspection evidence for the current retry attempt"
    );

    connection
        .execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES ('n7-forged-attempted',?1,?2,?3,'nodescale',NULL,'fleet_projection_desired','success',?4,'{}')",
            params![now().to_rfc3339(), network_id.to_string(), device_id.to_string(), request.generation.get()],
        )
        .unwrap();
    let audit_error = connection
        .execute(
            "INSERT INTO n7_fleet_projection_audit (audit_id,audit_event_id,projection_id,operation_id,event_kind,generation,revision,recorded_at_ms) VALUES ('10000000-0000-0000-0000-000000000007','n7-forged-attempted',?1,?2,'projection_desired',?3,2,?4)",
            params![projection_id, request.operation_id.as_str(), request.generation.get(), now().timestamp_millis()],
        )
        .unwrap_err();
    assert!(
        audit_error
            .to_string()
            .contains("N7 audit requires exact safe projection provenance"),
        "audit event kind and revision must describe the current projection state"
    );
    drop(connection);

    let applied = store
        .recover_n7_projection_from_inspection(
            &request.operation_id,
            device_id,
            request.generation,
            retry.revision,
            N7AuthoritativeInspection::observed(DESIRED_BODY.to_vec()).unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(applied.state, N7ProjectionState::Applied);
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_attempts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2,
        "the applied evidence binds the second, current append-only attempt"
    );
}
