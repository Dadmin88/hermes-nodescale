use nodescale_state::{SUPPORTED_SCHEMA_VERSION, StateStore};
use rusqlite::Connection;
use tempfile::tempdir;

const PRE_V8_MIGRATIONS: [&str; 7] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_discovery_reconciliation.sql"),
    include_str!("../migrations/0003_mutation_authorization.sql"),
    include_str!("../migrations/0004_invitation_lifecycle.sql"),
    include_str!("../migrations/0005_device_trust.sql"),
    include_str!("../migrations/0006_keryx_identity_binding.sql"),
    include_str!("../migrations/0007_fleet_projection.sql"),
];

#[test]
fn v7_database_upgrades_through_v9_with_inert_v8_adoption_state_without_authority() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("v8-adoption-state.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in PRE_V8_MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .pragma_update(None, "user_version", 7_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(SUPPORTED_SCHEMA_VERSION, 10);
    assert_eq!(store.schema_version().unwrap(), 10);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();

    for table in [
        "n5_adoption_authorization_operations",
        "n5_adoption_actions",
        "n5_adoption_proof_operations",
        "n5_adoption_decisions",
        "n5_existing_adoption_evidence",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing inert V8 table {table}");
    }

    let semantic_generation_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('provider_observations') WHERE name='semantic_generation' AND \"notnull\"=1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(semantic_generation_exists);

    let open_action_fence_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='n5_one_open_adoption_action_per_provider_node')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(open_action_fence_exists);

    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('11111111-1111-4111-8111-111111111111','v8-test','active','tailscale','44444444-4444-4444-8444-444444444444',1,1,'{}','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z');
             INSERT INTO n5_owner_trust_roots (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms)
             VALUES ('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','operator','owner-v8','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,NULL,0);
             INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
             VALUES ('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','operator','owner-v8',1,0,10000,0,0,NULL,0);
             INSERT INTO n5_trust_authority_capabilities (authority_id,capability)
             VALUES ('33333333-3333-4333-8333-333333333333','AdoptExistingProviderDevice');
             UPDATE n5_trust_authorities SET sealed=1,enabled=1
             WHERE authority_id='33333333-3333-4333-8333-333333333333';
             INSERT INTO provider_observations
             (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,classification,adoption_state,semantic_fingerprint,normalized_json,first_observed_at,last_observed_at,snapshot_at,semantic_generation)
             VALUES ('44444444-4444-4444-8444-444444444445','11111111-1111-4111-8111-111111111111',NULL,'44444444-4444-4444-8444-444444444444','provider-node-v8','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','discovered_unmanaged','unmanaged','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z',1);",
        )
        .unwrap();

    let forged = connection.execute(
        "INSERT INTO n5_adoption_authorization_operations
         (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
         VALUES ('forged-stale-generation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',2,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','pending',NULL,NULL,NULL,0,NULL)",
        [],
    );
    assert!(
        forged.is_err(),
        "stale caller-selected observation generation forged an adoption operation"
    );

    let orphan_issued_commit = connection.execute_batch(
        "BEGIN IMMEDIATE;
         INSERT INTO n5_adoption_authorization_operations
         (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
         VALUES ('orphan-issued-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','1111111111111111111111111111111111111111111111111111111111111111','pending',NULL,NULL,NULL,0,NULL);
         UPDATE n5_adoption_authorization_operations
         SET operation_state='settled',outcome='issued',action_id='11111111-2222-4333-8444-555555555555',receipt_id='11111111-2222-4333-8444-555555555556',settled_at_ms=0
         WHERE operation_id='orphan-issued-operation';
         COMMIT;",
    );
    if orphan_issued_commit.is_err() {
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    assert!(
        orphan_issued_commit.is_err(),
        "issued authorization committed without its exact action"
    );
    let orphan_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_authorization_operations WHERE operation_id='orphan-issued-operation'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(orphan_count, 0);

    let pre_settled_insert = connection.execute(
        "INSERT INTO n5_adoption_authorization_operations
         (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
         VALUES ('pre-settled-authorization-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','2222222222222222222222222222222222222222222222222222222222222222','settled','issued','22222222-2222-4222-8222-222222222223','22222222-2222-4222-8222-222222222224',0,0)",
        [],
    );
    assert!(
        pre_settled_insert.is_err(),
        "authorization operation bypassed pending-to-settled lifecycle"
    );

    connection
        .execute(
            "INSERT INTO n5_adoption_authorization_operations
             (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
             VALUES ('valid-authorization-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','pending',NULL,NULL,NULL,0,NULL)",
            [],
        )
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    connection
        .execute(
            "UPDATE n5_adoption_authorization_operations
             SET operation_state='settled',outcome='issued',action_id='55555555-5555-4555-8555-555555555555',receipt_id='66666666-6666-4666-8666-666666666666',settled_at_ms=0
             WHERE operation_id='valid-authorization-operation'",
            [],
        )
        .unwrap();
    let exact_replay: (String, String, String) = connection
        .query_row(
            "SELECT outcome,action_id,receipt_id
             FROM n5_adoption_authorization_operations
             WHERE operation_id='valid-authorization-operation'
               AND request_fingerprint='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(exact_replay.0, "issued");
    assert_eq!(exact_replay.1, "55555555-5555-4555-8555-555555555555");
    assert_eq!(exact_replay.2, "66666666-6666-4666-8666-666666666666");
    let changed_replay_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_adoption_authorization_operations
             WHERE operation_id='valid-authorization-operation'
               AND request_fingerprint='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(changed_replay_count, 0);
    assert!(connection
        .execute(
            "UPDATE n5_adoption_authorization_operations
             SET request_fingerprint='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
             WHERE operation_id='valid-authorization-operation'",
            [],
        )
        .is_err());
    connection
        .execute_batch("SAVEPOINT preterminal_action;")
        .unwrap();
    let preterminal_action = connection.execute(
        "INSERT INTO n5_adoption_actions
         (action_id,authorization_operation_id,authority_id,authority_generation,network_id,observation_id,provider_kind,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,proof_method,proof_generation,challenge_id,challenge_verifier,principal_source,principal_id,issued_at_ms,not_before_ms,expires_at_ms,action_state,terminal_decision_id,terminal_at_ms,terminal_reason)
         VALUES ('55555555-5555-4555-8555-555555555555','valid-authorization-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','tailscale','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','tailscale_whois_provider_v1',1,'77777777-7777-4777-8777-777777777777','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','operator','owner-v8',0,0,1000,'confirmed','77777777-7777-4777-8777-777777777778',1,'proof_confirmed')",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO preterminal_action; RELEASE preterminal_action;")
        .unwrap();
    assert!(
        preterminal_action.is_err(),
        "action insertion bypassed proof_pending and durable decision settlement"
    );
    connection
        .execute(
            "INSERT INTO n5_adoption_authorization_operations
             (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
             VALUES ('settlement-shape-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','pending',NULL,NULL,NULL,0,NULL)",
            [],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE n5_adoption_authorization_operations
             SET operation_state='settled',outcome='issued',action_id='dddddddd-dddd-4ddd-8ddd-dddddddddddd',settled_at_ms=1
             WHERE operation_id='settlement-shape-operation'",
            [],
        )
        .is_err());
    let forged_action = connection.execute(
        "INSERT INTO n5_adoption_actions
         (action_id,authorization_operation_id,authority_id,authority_generation,network_id,observation_id,provider_kind,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,proof_method,proof_generation,challenge_id,challenge_verifier,principal_source,principal_id,issued_at_ms,not_before_ms,expires_at_ms,action_state,terminal_decision_id,terminal_at_ms,terminal_reason)
         VALUES ('55555555-5555-4555-8555-555555555555','valid-authorization-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','tailscale','44444444-4444-4444-8444-444444444444','provider-node-v8',2,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','tailscale_whois_provider_v1',1,'77777777-7777-4777-8777-777777777777','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','operator','owner-v8',0,0,1000,'proof_pending',NULL,NULL,NULL)",
        [],
    );
    assert!(
        forged_action.is_err(),
        "action did not match its settled authorization operation and current observation"
    );

    connection
        .execute(
            "INSERT INTO n5_adoption_actions
             (action_id,authorization_operation_id,authority_id,authority_generation,network_id,observation_id,provider_kind,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,proof_method,proof_generation,challenge_id,challenge_verifier,principal_source,principal_id,issued_at_ms,not_before_ms,expires_at_ms,action_state,terminal_decision_id,terminal_at_ms,terminal_reason)
             VALUES ('55555555-5555-4555-8555-555555555555','valid-authorization-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','tailscale','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','tailscale_whois_provider_v1',1,'77777777-7777-4777-8777-777777777777','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','operator','owner-v8',0,0,1000,'proof_pending',NULL,NULL,NULL)",
            [],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    connection
        .execute(
            "INSERT INTO n5_adoption_proof_operations
             (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms)
             VALUES ('55555555-5555-4555-8555-555555555555','forged-confirm-proof','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','pending',NULL,NULL,NULL,NULL,0,NULL)",
            [],
        )
        .unwrap();
    let duplicate_pending_proof = connection.execute(
        "INSERT INTO n5_adoption_proof_operations
         (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms)
         VALUES ('55555555-5555-4555-8555-555555555555','second-pending-proof','1111111111111111111111111111111111111111111111111111111111111111','pending',NULL,NULL,NULL,NULL,0,NULL)",
        [],
    );
    assert!(
        duplicate_pending_proof.is_err(),
        "one action accepted two concurrent pending proof operations"
    );
    let forged_evidence = connection.execute(
        "INSERT INTO n5_existing_adoption_evidence
         (evidence_id,action_id,proof_operation_id,network_id,provider_kind,provider_instance_id,provider_node_id,observation_fingerprint,observation_semantic_fingerprint,observation_generation,machine_key_fingerprint,node_key_fingerprint,proof_generation,proof_method,provider_compatibility_pin,verified_at_ms)
         VALUES ('11111111-2222-4333-8444-555555555555','55555555-5555-4555-8555-555555555555','forged-confirm-proof','11111111-1111-4111-8111-111111111111','tailscale','44444444-4444-4444-8444-444444444444','provider-node-v8','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1,'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',1,'tailscale_whois_provider_v1','v0.0.0-forged',1)",
        [],
    );
    assert!(
        forged_evidence.is_err(),
        "V8 accepted evidence without a verified proof settlement path"
    );
    connection
        .execute_batch("SAVEPOINT forged_confirmation;")
        .unwrap();
    let forged_confirmation = connection.execute(
        "UPDATE n5_adoption_proof_operations
         SET operation_state='settled',outcome='confirmed',receipt_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',resulting_device_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',resulting_provider_binding_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc',settled_at_ms=1
         WHERE action_id='55555555-5555-4555-8555-555555555555' AND operation_id='forged-confirm-proof'",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO forged_confirmation; RELEASE forged_confirmation;")
        .unwrap();
    assert!(
        forged_confirmation.is_err(),
        "V8 proof operation fabricated confirmed DeviceId/binding results"
    );
    connection
        .execute_batch("SAVEPOINT orphan_proof_conflict;")
        .unwrap();
    let orphan_proof_conflict = connection.execute(
        "UPDATE n5_adoption_proof_operations
         SET operation_state='settled',outcome='conflicted',receipt_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab',settled_at_ms=1
         WHERE action_id='55555555-5555-4555-8555-555555555555' AND operation_id='forged-confirm-proof'",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO orphan_proof_conflict; RELEASE orphan_proof_conflict;")
        .unwrap();
    assert!(
        orphan_proof_conflict.is_err(),
        "proof operation conflicted without an exact durable decision"
    );
    connection
        .execute_batch("SAVEPOINT forged_decision;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO audit_events
             (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES ('88888888-8888-4888-8888-888888888888','1970-01-01T00:00:00Z','11111111-1111-4111-8111-111111111111',NULL,'system','reconciliation','device.adoption_action_conflicted','success',2,'{}')",
            [],
        )
        .unwrap();
    let forged_decision = connection.execute(
        "INSERT INTO n5_adoption_decisions
         (decision_id,action_id,proof_operation_id,audit_event_id,decision_kind,prior_action_state,new_action_state,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,observation_generation,proof_generation,evidence_id,device_id,provider_binding_id,safe_correlation_digest,reason_code,decided_at_ms)
         VALUES ('99999999-9999-4999-8999-999999999999','55555555-5555-4555-8555-555555555555',NULL,'88888888-8888-4888-8888-888888888888','conflict','proof_pending','conflicted','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444444','provider-node-v8',2,1,NULL,NULL,NULL,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','observation_changed',2)",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO forged_decision; RELEASE forged_decision;")
        .unwrap();
    assert!(
        forged_decision.is_err(),
        "decision escaped the exact action/authority/audit correlation boundary"
    );

    connection
        .execute_batch(
            "SAVEPOINT pending_proof_action_terminal;
             UPDATE provider_observations SET semantic_generation=2
             WHERE observation_id='44444444-4444-4444-8444-444444444445';
             INSERT INTO audit_events
             (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES ('88888888-8888-4888-8888-888888888889','1970-01-01T00:00:00Z','11111111-1111-4111-8111-111111111111',NULL,'system','reconciliation','device.adoption_action_conflicted','success',2,'{}');
             INSERT INTO n5_adoption_decisions
             (decision_id,action_id,proof_operation_id,audit_event_id,decision_kind,prior_action_state,new_action_state,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,observation_generation,proof_generation,evidence_id,device_id,provider_binding_id,safe_correlation_digest,reason_code,decided_at_ms)
             VALUES ('99999999-9999-4999-8999-999999999998','55555555-5555-4555-8555-555555555555',NULL,'88888888-8888-4888-8888-888888888889','conflict','proof_pending','conflicted','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444444','provider-node-v8',2,1,NULL,NULL,NULL,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','observation_changed',2);",
        )
        .unwrap();
    let settled_graph: (String, String, String, String) = connection
        .query_row(
            "SELECT action.action_state,action.terminal_decision_id,proof.operation_state,proof.outcome
             FROM n5_adoption_actions AS action
             JOIN n5_adoption_proof_operations AS proof ON proof.action_id=action.action_id
             WHERE action.action_id='55555555-5555-4555-8555-555555555555'
               AND proof.operation_id='forged-confirm-proof'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        settled_graph,
        (
            "conflicted".into(),
            "99999999-9999-4999-8999-999999999998".into(),
            "settled".into(),
            "conflicted".into(),
        ),
        "decision insertion committed a torn pending proof/action graph"
    );
    connection
        .execute_batch(
            "ROLLBACK TO pending_proof_action_terminal; RELEASE pending_proof_action_terminal;",
        )
        .unwrap();

    connection
        .execute_batch(
            "SAVEPOINT early_expiry;
             INSERT INTO audit_events
             (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES ('88888888-8888-4888-8888-888888888890','1970-01-01T00:00:00Z','11111111-1111-4111-8111-111111111111',NULL,'system','expiry','device.adoption_action_expired','success',1,'{}');",
        )
        .unwrap();
    let early_expiry = connection.execute(
        "INSERT INTO n5_adoption_decisions
         (decision_id,action_id,proof_operation_id,audit_event_id,decision_kind,prior_action_state,new_action_state,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,observation_generation,proof_generation,evidence_id,device_id,provider_binding_id,safe_correlation_digest,reason_code,decided_at_ms)
         VALUES ('99999999-9999-4999-8999-999999999990','55555555-5555-4555-8555-555555555555',NULL,'88888888-8888-4888-8888-888888888890','expire','proof_pending','expired','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444444','provider-node-v8',1,1,NULL,NULL,NULL,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','action_expired',2)",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO early_expiry; RELEASE early_expiry;")
        .unwrap();
    assert!(early_expiry.is_err(), "action expired before its deadline");

    connection
        .execute_batch(
            "SAVEPOINT fake_revocation;
             INSERT INTO audit_events
             (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES ('88888888-8888-4888-8888-888888888891','1970-01-01T00:00:00Z','11111111-1111-4111-8111-111111111111',NULL,'system','revocation','device.adoption_action_revoked','success',1,'{}');",
        )
        .unwrap();
    let fake_revocation = connection.execute(
        "INSERT INTO n5_adoption_decisions
         (decision_id,action_id,proof_operation_id,audit_event_id,decision_kind,prior_action_state,new_action_state,authority_id,authority_generation,network_id,provider_instance_id,provider_node_id,observation_generation,proof_generation,evidence_id,device_id,provider_binding_id,safe_correlation_digest,reason_code,decided_at_ms)
         VALUES ('99999999-9999-4999-8999-999999999991','55555555-5555-4555-8555-555555555555',NULL,'88888888-8888-4888-8888-888888888891','revoke','proof_pending','revoked','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444444','provider-node-v8',1,1,NULL,NULL,NULL,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','owner_revoked',2)",
        [],
    );
    connection
        .execute_batch("ROLLBACK TO fake_revocation; RELEASE fake_revocation;")
        .unwrap();
    assert!(
        fake_revocation.is_err(),
        "action revoked while owner root and authority remained live"
    );

    connection
        .execute_batch(
            "INSERT INTO provider_observations
             (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,classification,adoption_state,semantic_fingerprint,normalized_json,first_observed_at,last_observed_at,snapshot_at,semantic_generation)
             VALUES ('22222222-2222-4222-8222-222222222225','11111111-1111-4111-8111-111111111111',NULL,'44444444-4444-4444-8444-444444444444','provider-node-root-revoke','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','discovered_unmanaged','unmanaged','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z',1);
             INSERT INTO n5_adoption_authorization_operations
             (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
             VALUES ('pending-before-root-revoke','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222225','44444444-4444-4444-8444-444444444444','provider-node-root-revoke',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','3333333333333333333333333333333333333333333333333333333333333333','pending',NULL,NULL,NULL,0,NULL);
             INSERT INTO n5_adoption_authorization_operations
             (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
             VALUES ('issued-before-root-revoke','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222225','44444444-4444-4444-8444-444444444444','provider-node-root-revoke',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','4444444444444444444444444444444444444444444444444444444444444444','pending',NULL,NULL,NULL,0,NULL);",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n5_adoption_proof_operations
             SET operation_state='settled',outcome='unavailable',receipt_id='22222222-2222-4222-8222-222222222231',settled_at_ms=1
             WHERE action_id='55555555-5555-4555-8555-555555555555' AND operation_id='forged-confirm-proof'",
            [],
        )
        .unwrap();

    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    connection
        .execute(
            "UPDATE n5_adoption_authorization_operations
             SET operation_state='settled',outcome='issued',action_id='22222222-2222-4222-8222-222222222228',receipt_id='22222222-2222-4222-8222-222222222229',settled_at_ms=0
             WHERE operation_id='issued-before-root-revoke'",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n5_owner_trust_roots SET enabled=0,revoked_at_ms=1 WHERE trust_root_id='22222222-2222-4222-8222-222222222222'",
            [],
        )
        .unwrap();
    let revoked_root_action = connection.execute(
        "INSERT INTO n5_adoption_actions
         (action_id,authorization_operation_id,authority_id,authority_generation,network_id,observation_id,provider_kind,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,proof_method,proof_generation,challenge_id,challenge_verifier,principal_source,principal_id,issued_at_ms,not_before_ms,expires_at_ms,action_state,terminal_decision_id,terminal_at_ms,terminal_reason)
         VALUES ('22222222-2222-4222-8222-222222222228','issued-before-root-revoke','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222225','tailscale','44444444-4444-4444-8444-444444444444','provider-node-root-revoke',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','tailscale_whois_provider_v1',1,'22222222-2222-4222-8222-222222222230','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','operator','owner-v8',1,1,9999,'proof_pending',NULL,NULL,NULL)",
        [],
    );
    connection.execute_batch("ROLLBACK;").unwrap();
    assert!(
        revoked_root_action.is_err(),
        "issued authorization created an action after owner-root revocation"
    );

    connection
        .execute(
            "UPDATE n5_owner_trust_roots SET enabled=0,revoked_at_ms=1 WHERE trust_root_id='22222222-2222-4222-8222-222222222222'",
            [],
        )
        .unwrap();
    let proof_after_root_revoke = connection.execute(
        "INSERT INTO n5_adoption_proof_operations
         (action_id,operation_id,request_fingerprint,operation_state,outcome,receipt_id,resulting_device_id,resulting_provider_binding_id,created_at_ms,settled_at_ms)
         VALUES ('55555555-5555-4555-8555-555555555555','proof-after-root-revoke','5555555555555555555555555555555555555555555555555555555555555555','pending',NULL,NULL,NULL,NULL,2,NULL)",
        [],
    );
    assert!(
        proof_after_root_revoke.is_err(),
        "owner-root revocation did not stop new proof operations"
    );
    let revoked_root_settlement = connection.execute(
        "UPDATE n5_adoption_authorization_operations
         SET operation_state='settled',outcome='issued',action_id='22222222-2222-4222-8222-222222222226',receipt_id='22222222-2222-4222-8222-222222222227',settled_at_ms=1
         WHERE operation_id='pending-before-root-revoke'",
        [],
    );
    assert!(
        revoked_root_settlement.is_err(),
        "pending authorization issued after owner-root revocation"
    );
    let revoked_root_operation = connection.execute(
        "INSERT INTO n5_adoption_authorization_operations
         (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
         VALUES ('revoked-root-operation','33333333-3333-4333-8333-333333333333',1,'11111111-1111-4111-8111-111111111111','44444444-4444-4444-8444-444444444445','44444444-4444-4444-8444-444444444444','provider-node-v8',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','pending',NULL,NULL,NULL,1,NULL)",
        [],
    );
    assert!(
        revoked_root_operation.is_err(),
        "revoked owner root did not kill adoption authorization"
    );

    let terminal_rewind = connection.execute(
        "UPDATE n5_adoption_authorization_operations
         SET operation_state='pending',outcome=NULL,action_id=NULL,receipt_id=NULL,settled_at_ms=NULL
         WHERE operation_id='valid-authorization-operation'",
        [],
    );
    assert!(
        terminal_rewind.is_err(),
        "settled adoption authorization operation was rewound to pending"
    );

    for table in [
        "devices",
        "n5_device_identities",
        "n5_provider_bindings",
        "n5_device_trust_state",
        "n6_binding_records",
        "n7_fleet_projection_records",
    ] {
        let count: u64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "V8 migration created authority in {table}");
    }

    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let foreign_key_errors: u64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(foreign_key_errors, 0);
}

#[test]
fn populated_v7_reopens_as_v9_without_legacy_state_drift() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("populated-v7-to-v8.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in PRE_V8_MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('10000000-0000-4000-8000-000000000001','populated-v7','active','tailscale','20000000-0000-4000-8000-000000000001',7,9,'{\"legacy\":true}','2026-08-10T00:00:00Z','2026-08-10T00:01:00Z');
             INSERT INTO provider_observations
             (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,classification,adoption_state,semantic_fingerprint,normalized_json,first_observed_at,last_observed_at,snapshot_at)
             VALUES ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001',NULL,'20000000-0000-4000-8000-000000000001','legacy-provider-node','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','discovered_unmanaged','unmanaged','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{\"legacy_node\":true}','2026-08-10T00:00:00Z','2026-08-10T00:01:00Z','2026-08-10T00:01:00Z');
             INSERT INTO n5_owner_trust_roots
             (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms)
             VALUES ('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','operator','legacy-owner','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,NULL,10);
             INSERT INTO n5_trust_authorities
             (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
             VALUES ('50000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','operator','legacy-owner',3,10,999999,0,0,NULL,10);
             INSERT INTO n5_trust_authority_capabilities (authority_id,capability)
             VALUES ('50000000-0000-4000-8000-000000000001','ActivateDeviceTrust');
             UPDATE n5_trust_authorities SET sealed=1,enabled=1
             WHERE authority_id='50000000-0000-4000-8000-000000000001';",
        )
        .unwrap();
    connection
        .pragma_update(None, "user_version", 7_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let observation: (String, String, String, u64) = connection
        .query_row(
            "SELECT provider_node_id,classification,normalized_json,semantic_generation
             FROM provider_observations
             WHERE observation_id='30000000-0000-4000-8000-000000000001'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(observation.0, "legacy-provider-node");
    assert_eq!(observation.1, "discovered_unmanaged");
    assert_eq!(observation.2, "{\"legacy_node\":true}");
    assert_eq!(observation.3, 1);
    let authority: (u64, i64, i64) = connection
        .query_row(
            "SELECT authority_generation,sealed,enabled FROM n5_trust_authorities
             WHERE authority_id='50000000-0000-4000-8000-000000000001'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(authority, (3, 1, 1));
    let capabilities: Vec<String> = connection
        .prepare(
            "SELECT capability FROM n5_trust_authority_capabilities
             WHERE authority_id='50000000-0000-4000-8000-000000000001'
             ORDER BY capability",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(capabilities, vec!["ActivateDeviceTrust"]);
    for (table, expected) in [
        ("networks", 1_u64),
        ("provider_observations", 1),
        ("n5_owner_trust_roots", 1),
        ("n5_trust_authorities", 1),
        ("n5_trust_authority_capabilities", 1),
        ("devices", 0),
        ("n6_binding_records", 0),
        ("n7_fleet_projection_records", 0),
    ] {
        let count: u64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "migration drifted {table}");
    }
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let foreign_key_errors: u64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(foreign_key_errors, 0);
}

#[test]
fn adoption_operation_rejects_substituted_observation_fingerprint() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("v8-observation-fingerprint.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('11111111-1111-4111-8111-111111111112','fingerprint-test','active','tailscale','44444444-4444-4444-8444-444444444446',1,1,'{}','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z');
             INSERT INTO n5_owner_trust_roots (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms)
             VALUES ('22222222-2222-4222-8222-222222222223','11111111-1111-4111-8111-111111111112','operator','owner-v8','$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,NULL,0);
             INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
             VALUES ('33333333-3333-4333-8333-333333333334','22222222-2222-4222-8222-222222222223','11111111-1111-4111-8111-111111111112','operator','owner-v8',1,0,10000,0,0,NULL,0);
             INSERT INTO n5_trust_authority_capabilities (authority_id,capability)
             VALUES ('33333333-3333-4333-8333-333333333334','AdoptExistingProviderDevice');
             UPDATE n5_trust_authorities SET sealed=1,enabled=1
             WHERE authority_id='33333333-3333-4333-8333-333333333334';
             INSERT INTO provider_observations
             (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,classification,adoption_state,semantic_fingerprint,normalized_json,first_observed_at,last_observed_at,snapshot_at,semantic_generation)
             VALUES ('44444444-4444-4444-8444-444444444447','11111111-1111-4111-8111-111111111112',NULL,'44444444-4444-4444-8444-444444444446','provider-node-fingerprint','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','discovered_unmanaged','unmanaged','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z',1);",
        )
        .unwrap();

    let substituted = connection.execute(
        "INSERT INTO n5_adoption_authorization_operations
         (operation_id,authority_id,authority_generation,network_id,observation_id,provider_instance_id,provider_node_id,expected_observation_generation,expected_observation_fingerprint,expected_semantic_fingerprint,expected_machine_key_fingerprint,expected_node_key_fingerprint,request_fingerprint,operation_state,outcome,action_id,receipt_id,created_at_ms,settled_at_ms)
         VALUES ('substituted-observation-fingerprint','33333333-3333-4333-8333-333333333334',1,'11111111-1111-4111-8111-111111111112','44444444-4444-4444-8444-444444444447','44444444-4444-4444-8444-444444444446','provider-node-fingerprint',1,'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','pending',NULL,NULL,NULL,1,NULL)",
        [],
    );
    assert!(
        substituted.is_err(),
        "caller-selected observation fingerprint was not fenced to persisted discovery evidence"
    );
}
