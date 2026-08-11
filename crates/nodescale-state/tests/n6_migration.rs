use nodescale_domain::AgentVersion;
use nodescale_state::{SUPPORTED_SCHEMA_VERSION, StateStore};
use rusqlite::{Connection, params};
use tempfile::tempdir;
use uuid::Uuid;

const MIGRATIONS: [&str; 6] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_discovery_reconciliation.sql"),
    include_str!("../migrations/0003_mutation_authorization.sql"),
    include_str!("../migrations/0004_invitation_lifecycle.sql"),
    include_str!("../migrations/0005_device_trust.sql"),
    include_str!("../migrations/0006_keryx_identity_binding.sql"),
];
const MIGRATION_7: &str = include_str!("../migrations/0007_fleet_projection.sql");
const MIGRATION_8: &str = include_str!("../migrations/0008_existing_device_adoption_state.sql");
const NETWORK: &str = "10bdbae2-73be-46f2-8f0a-5b761fdeaf4d";
const DEVICE: &str = "f9b36c3a-e777-4e92-a4ea-14d22a234ecc";
const SESSION: &str = "cafa4427-4c17-408e-bfed-c93f34bd3756";
const BINDING: &str = "d494ab4f-20db-4a4f-97bf-aad97f5ac36b";
const SUCCESSOR_BINDING: &str = "c90bbb39-d044-41f9-97d9-27aae96be898";
const PEER: &str = "keryx-peer-n6";
const VERIFIER: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdC1uNi1maXhlZC0xNg$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY";

fn n6_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn assert_rejected(result: rusqlite::Result<usize>, context: &str) {
    assert!(
        result.is_err(),
        "direct SQL unexpectedly succeeded: {context}"
    );
}

fn table_exists(connection: &Connection, name: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}

fn n7_table_counts(connection: &Connection) -> Vec<(String, i64)> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'n7_%' ORDER BY name",
        )
        .unwrap();
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                    row.get(0)
                })
                .unwrap();
            (table, count)
        })
        .collect()
}

fn schema_object_exists(connection: &Connection, kind: &str, name: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2)",
            params![kind, name],
            |row| row.get(0),
        )
        .unwrap()
}

fn seed_n5_confirmed_provenance(connection: &Connection) {
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
             INSERT INTO n4_invitation_details (invitation_id,network_id,provider_instance_id,provider_principal_id,roles_json,constraints_json,created_by_source,created_by_id,revision,consumed_at_ms,revoked_at_ms,expired_at_ms,last_redemption_at_ms,last_redemption_metadata_json)
             VALUES ('610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','principal-n6','[]','{}','nodescale',NULL,1,NULL,NULL,NULL,NULL,'{}');
             INSERT INTO n4_join_session_dispatches (join_session_id,invitation_id,network_id,provider_instance_id,provider_principal_id,create_request_id,dispatch_state,authorization_generation,configuration_generation,configuration_fingerprint,dispatched_at_ms,resolved_at_ms,credential_id)
             VALUES ('cafa4427-4c17-408e-bfed-c93f34bd3756','610c7a7c-ee1b-4579-a7c1-2e5fbba13765','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','principal-n6','00000000-0000-0000-0000-000000000006','confirmed',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,1001,'1647eae9-8b5a-43e8-95b0-9a2470dc440a');
             INSERT INTO n4_provider_credential_metadata (credential_id,join_session_id,network_id,provider_instance_id,provider_principal_id,single_use,reusable,ephemeral,approved_tags_json,expires_at_ms,confirmed_at_ms,invalidation_state,invalidated_at_ms,safe_correlation_json)
             VALUES ('1647eae9-8b5a-43e8-95b0-9a2470dc440a','cafa4427-4c17-408e-bfed-c93f34bd3756','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','provider-n6','principal-n6',1,0,1,'[]',999999999999,1001,'active',NULL,'{}');
             INSERT INTO n5_owner_trust_roots (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms)
             VALUES ('55f08bb1-3cc7-42b4-ab1d-1e83d3d155df','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','operator','operator-n6','$argon2id$v=19$m=19456,t=2,p=1$c2FsdC1uNi1maXhlZC0xNg$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY',1,NULL,1000);
             INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
             VALUES ('6033e8e2-c7ba-4100-a75c-dda7de7db8a7','55f08bb1-3cc7-42b4-ab1d-1e83d3d155df','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','operator','operator-n6',1,1000,999999999999,0,0,NULL,1000);
             INSERT INTO n5_trust_authority_capabilities (authority_id,capability)
             VALUES ('6033e8e2-c7ba-4100-a75c-dda7de7db8a7','ActivateDeviceTrust');
             UPDATE n5_trust_authorities SET sealed=1,enabled=1 WHERE authority_id='6033e8e2-c7ba-4100-a75c-dda7de7db8a7';",
        )
        .unwrap();
    if table_exists(connection, "n5_n4_identity_origins") {
        connection.execute_batch(
            "BEGIN;
             PRAGMA defer_foreign_keys=ON;
             INSERT INTO n5_device_identities (device_id,network_id,identity_origin_kind,identity_origin_id,n4_origin_id,adoption_origin_id,confirmed_at_ms,identity_revision,safe_correlation_digest)
             VALUES ('f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n4_join_session','cafa4427-4c17-408e-bfed-c93f34bd3756','cafa4427-4c17-408e-bfed-c93f34bd3756',NULL,1001,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
             INSERT INTO n5_n4_identity_origins (origin_id,origin_kind,device_id,network_id,join_session_id)
             VALUES ('cafa4427-4c17-408e-bfed-c93f34bd3756','n4_join_session','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','cafa4427-4c17-408e-bfed-c93f34bd3756');
             INSERT INTO n5_provider_bindings (binding_id,device_id,network_id,provenance_kind,n4_provenance_binding_id,adoption_provenance_binding_id,provider_instance_id,provider_node_id,machine_key_fingerprint,binding_state,binding_revision,observed_at_ms)
             VALUES ('11111111-1111-4111-8111-111111111111','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n4_join_session','11111111-1111-4111-8111-111111111111',NULL,'provider-n6','provider-node-n6','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','active',1,1001);
             INSERT INTO n5_n4_provider_binding_provenance (binding_id,provenance_kind,device_id,network_id,identity_origin_kind,identity_origin_id,join_session_id,credential_id,provider_credential_reference,provider_instance_id)
             VALUES ('11111111-1111-4111-8111-111111111111','n4_join_session','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','n4_join_session','cafa4427-4c17-408e-bfed-c93f34bd3756','cafa4427-4c17-408e-bfed-c93f34bd3756','1647eae9-8b5a-43e8-95b0-9a2470dc440a','provider-ref-n6','provider-n6');
             COMMIT;",
        ).unwrap();
    } else {
        connection.execute(
            "INSERT INTO n5_device_identities (device_id,network_id,origin_join_session_id,confirmed_at_ms,identity_revision,safe_correlation_digest) VALUES (?1,?2,?3,1001,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            params![DEVICE, NETWORK, SESSION],
        ).unwrap();
    }
    if table_exists(connection, "n6_binding_authority_capabilities") {
        connection.execute_batch(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES ('dfe2b2eb-5f2f-47ba-b5b6-9e148e88f8f5','2026-08-08T00:00:00Z','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','operator','operator-n6','keryx_binding_authority_capability_granted','success',1,'{}'),
                    ('8c58f581-1384-4a2b-a9ff-90c9d4f6f042','2026-08-08T00:00:00Z','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','operator','operator-n6','keryx_binding_authority_capability_granted','success',1,'{}');
             INSERT INTO n6_binding_authority_capabilities (grant_id,authority_id,capability,issued_by_source,issued_by_id,issued_at_ms,audit_event_id)
             VALUES ('9e4c2e7a-cadf-4b41-9fc3-418b8c6072c6','6033e8e2-c7ba-4100-a75c-dda7de7db8a7','rotate','operator','operator-n6',1000,'dfe2b2eb-5f2f-47ba-b5b6-9e148e88f8f5'),
                    ('b6c52bb3-b4c1-4db2-b5bc-006c7a6ed4f2','6033e8e2-c7ba-4100-a75c-dda7de7db8a7','revoke','operator','operator-n6',1000,'8c58f581-1384-4a2b-a9ff-90c9d4f6f042');",
        ).unwrap();
    }
}

fn exact_audit_semantics(subject_kind: &str, decision_kind: &str) -> (&'static str, &'static str) {
    match (subject_kind, decision_kind) {
        ("binding", "issue") => ("keryx_binding_pending", "success"),
        ("challenge", "issue") => ("keryx_binding_nonce_issued", "success"),
        ("challenge", "confirm") => ("keryx_binding_attempted", "success"),
        ("binding", "confirm") => ("keryx_binding_confirmed", "success"),
        ("binding" | "challenge", "replay") => ("keryx_binding_replay", "idempotent"),
        ("binding" | "challenge", "conflict") => ("keryx_binding_conflict", "rejected"),
        ("binding", "stale") => ("keryx_binding_staled", "success"),
        ("binding", "rotate") => ("keryx_binding_rotated", "success"),
        ("binding", "revoke") => ("keryx_binding_revoked", "success"),
        ("challenge", "expire") => ("keryx_binding_nonce_expired", "success"),
        ("challenge", "invalidate") => ("keryx_binding_nonce_invalidated", "success"),
        ("authorization", "issue") => ("keryx_binding_authorization_issued", "success"),
        ("authorization", "expire") => ("keryx_binding_authorization_expired", "success"),
        ("authorization", "invalidate") => ("keryx_binding_authorization_invalidated", "success"),
        _ => panic!("unsupported N6 audit semantic {subject_kind}/{decision_kind}"),
    }
}

/// The audit actor is the business actor that made the decision, not the
/// recorder that appended this audit row.
fn insert_audit_for_decision(
    connection: &Connection,
    event_id: &str,
    actor_source: &str,
    actor_id: Option<&str>,
    generation: i64,
    subject_kind: &str,
    decision_kind: &str,
) {
    let (event_kind, outcome) = exact_audit_semantics(subject_kind, decision_kind);
    connection
        .execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES (?1,'2026-08-08T00:00:00Z',?2,?3,?4,?5,?6,?7,?8,'{}')",
            params![
                event_id,
                NETWORK,
                DEVICE,
                actor_source,
                actor_id,
                event_kind,
                outcome,
                generation
            ],
        )
        .unwrap();
}

fn insert_audit(connection: &Connection, event_id: &str, subject_kind: &str, decision_kind: &str) {
    insert_audit_for_decision(
        connection,
        event_id,
        "nodescale",
        None,
        1,
        subject_kind,
        decision_kind,
    );
}

#[allow(clippy::too_many_arguments)]
fn insert_binding_decision(
    connection: &Connection,
    decision_id: &str,
    audit_id: &str,
    kind: &str,
    prior_state: Option<&str>,
    new_state: &str,
    prior_revision: Option<i64>,
    new_revision: i64,
) {
    let (challenge_id, operation_id) = if kind == "confirm" {
        let (
            challenge_id,
            issue_audit_id,
            issue_decision_id,
            consume_audit_id,
            consume_decision_id,
        ) = (n6_uuid(), n6_uuid(), n6_uuid(), n6_uuid(), n6_uuid());
        connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
        insert_audit(connection, &issue_audit_id, "challenge", "issue");
        connection
            .execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
                 VALUES (?1,?2,'challenge','issue',?3,?4,NULL,?5,?6,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'challenge_issued',?7,NULL,'n6-test-agent')",
                params![issue_decision_id, issue_audit_id, BINDING, challenge_id, NETWORK, DEVICE, PEER],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id)
                 VALUES (?1,?2,?3,?4,?5,1,?6,'pending',2000,3000,'n6-test-agent',?7,?8)",
                params![challenge_id, BINDING, NETWORK, DEVICE, PEER, VERIFIER, issue_decision_id, issue_audit_id],
            )
            .unwrap();
        connection.execute_batch("COMMIT;").unwrap();
        insert_audit(connection, &consume_audit_id, "challenge", "confirm");
        connection
            .execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
                 VALUES (?1,?2,'challenge','confirm',?3,?4,NULL,?5,?6,1,'pending','consumed',1,2,2000,'nodescale',NULL,'challenge_confirmed',?7,'operation-n6','n6-test-agent')",
                params![consume_decision_id, consume_audit_id, BINDING, challenge_id, NETWORK, DEVICE, PEER],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2000,consumed_operation_id='operation-n6',consumed_authenticated_peer_id=?1,last_decision_id=?2,last_audit_event_id=?3 WHERE challenge_id=?4",
                params![PEER, consume_decision_id, consume_audit_id, challenge_id],
            )
            .unwrap();
        (Some(challenge_id), Some("operation-n6"))
    } else {
        (None, None)
    };
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES (?1,?2,'binding',?3,?4,?5,NULL,?6,?7,1,?8,?9,?10,?11,?12,'nodescale',NULL,'operator_request',?13,?14,'n6-test-agent')",
            params![decision_id, audit_id, kind, BINDING, challenge_id, NETWORK, DEVICE, prior_state, new_state, prior_revision, new_revision, 2000, PEER, operation_id],
        )
        .unwrap();
}

fn insert_pending_binding(connection: &Connection) {
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(
        connection,
        "55877447-b50c-43e8-a852-ecca2d71b955",
        "binding",
        "issue",
    );
    insert_binding_decision(
        connection,
        "d0b74ce6-d0c4-4f9d-89d7-72f0136e7a65",
        "55877447-b50c-43e8-a852-ecca2d71b955",
        "issue",
        None,
        "pending",
        None,
        1,
    );
    connection
        .execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms,last_verified_at_ms,rotated_from_binding_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES (?1,?2,?3,'11111111-1111-4111-8111-111111111111',NULL,1,1,'pending',2000,NULL,NULL,NULL,NULL,NULL,NULL,'n6-test-agent','d0b74ce6-d0c4-4f9d-89d7-72f0136e7a65','55877447-b50c-43e8-a852-ecca2d71b955')",
            params![BINDING, NETWORK, DEVICE],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
}

fn activate_seeded_binding(connection: &Connection) {
    insert_pending_binding(connection);
    insert_audit(
        connection,
        "db218817-2bde-4fa0-9697-ebba534b25e2",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        connection,
        "151c73c7-b6e8-4a07-8c7f-40f0a18e5f25",
        "db218817-2bde-4fa0-9697-ebba534b25e2",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection
        .execute(
            "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='151c73c7-b6e8-4a07-8c7f-40f0a18e5f25',last_audit_event_id='db218817-2bde-4fa0-9697-ebba534b25e2' WHERE binding_id=?2",
            params![PEER, BINDING],
        )
        .unwrap();
}

fn insert_pending_authorization(
    connection: &Connection,
    authorization_id: &str,
    action_kind: &str,
) {
    insert_pending_authorization_with_window(connection, authorization_id, action_kind, 2000, 3000);
}

fn insert_pending_authorization_with_window(
    connection: &Connection,
    authorization_id: &str,
    action_kind: &str,
    issued_at_ms: i64,
    expires_at_ms: i64,
) {
    let audit_id = n6_uuid();
    let decision_id = n6_uuid();
    let (generation, expected_revision): (i64, i64) = connection
        .query_row(
            "SELECT generation,revision FROM n6_binding_records WHERE binding_id=?1",
            [BINDING],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit_for_decision(
        connection,
        &audit_id,
        "operator",
        Some("operator-n6"),
        generation,
        "authorization",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES (?1,?2,'authorization','issue',?3,NULL,?4,?5,?6,?7,NULL,'pending',NULL,1,?8,'operator','operator-n6','authorization_issued',NULL,NULL,'n6-test-agent')",
            params![decision_id, audit_id, BINDING, authorization_id, NETWORK, DEVICE, generation, issued_at_ms],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n6_binding_authorizations (authorization_id,authority_id,binding_id,network_id,device_id,generation,expected_revision,action_kind,actor_source,actor_id,issued_at_ms,expires_at_ms,issued_decision_id,issued_audit_event_id,authorization_state)
             VALUES (?1,'6033e8e2-c7ba-4100-a75c-dda7de7db8a7',?2,?3,?4,?5,?6,?7,'operator','operator-n6',?8,?9,?10,?11,'pending')",
            params![authorization_id, BINDING, NETWORK, DEVICE, generation, expected_revision, action_kind, issued_at_ms, expires_at_ms, decision_id, audit_id],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
}

fn insert_pending_challenge(
    connection: &Connection,
    challenge_id: &str,
    audit_id: &str,
    decision_id: &str,
) {
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(connection, audit_id, "challenge", "issue");
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES (?1,?2,'challenge','issue',?3,?4,NULL,?5,?6,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'challenge_issued',?7,NULL,'n6-test-agent')",
        params![decision_id, audit_id, BINDING, challenge_id, NETWORK, DEVICE, PEER],
    ).unwrap();
    connection.execute(
        "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id)
         VALUES (?1,?2,?3,?4,?5,1,?6,'pending',2000,3000,'n6-test-agent',?7,?8)",
        params![challenge_id, BINDING, NETWORK, DEVICE, PEER, VERIFIER, decision_id, audit_id],
    ).unwrap();
    connection.execute_batch("COMMIT;").unwrap();
}

#[test]
fn fresh_schema_retains_authoritative_n6_tables() {
    let store = StateStore::open_in_memory().unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);

    let directory = tempdir().unwrap();
    let path = directory.path().join("fresh-v7.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for table in [
        "n6_binding_challenges",
        "n6_binding_records",
        "n6_binding_authorizations",
        "n6_binding_decisions",
    ] {
        assert!(table_exists(&connection, table), "missing N6 table {table}");
    }
    for index in [
        "n6_one_active_binding_per_device",
        "n6_one_active_binding_per_peer",
        "n6_binding_generation_once",
        "n6_one_pending_authorization_per_action",
    ] {
        assert!(
            schema_object_exists(&connection, "index", index),
            "missing index {index}"
        );
    }
    for trigger in [
        "n6_binding_insert_requires_issue_decision",
        "n6_binding_transition_guard",
        "n6_challenge_transition_guard",
        "n6_replay_decision_requires_consumed_challenge",
        "n6_authorization_consumption_guard",
        "n6_decision_immutable_delete",
    ] {
        assert!(
            schema_object_exists(&connection, "trigger", trigger),
            "missing trigger {trigger}"
        );
    }
    for table in [
        "n6_binding_challenges",
        "n6_binding_records",
        "n6_binding_authorizations",
    ] {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            columns
                .iter()
                .all(|column| !column.to_ascii_lowercase().contains("nonce")),
            "N6 must not persist a plaintext nonce-named column in {table}"
        );
    }
    assert!(table_exists(&connection, "keryx_bindings"));
}

#[test]
fn every_supported_predecessor_upgrades_to_v9_without_losing_n5_or_n6_state() {
    for predecessor in 1_u32..=6 {
        let directory = tempdir().unwrap();
        let path = directory.path().join(format!("v{predecessor}.db"));
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        for migration in MIGRATIONS.iter().take(predecessor as usize) {
            connection.execute_batch(migration).unwrap();
        }
        if predecessor >= 5 {
            seed_n5_confirmed_provenance(&connection);
        }
        connection
            .pragma_update(None, "user_version", predecessor)
            .unwrap();
        drop(connection);

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        drop(store);
        let connection = Connection::open(path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        for table in [
            "n7_fleet_projection_records",
            "n7_fleet_projection_operations",
            "n7_fleet_projection_attempts",
            "n7_fleet_projection_audit",
        ] {
            assert!(table_exists(&connection, table), "missing N7 table {table}");
        }
        if predecessor >= 5 {
            let preserved: i64 = connection
                .query_row("SELECT COUNT(*) FROM n5_device_identities", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(preserved, 1);
        }
        if predecessor == 6 {
            let preserved: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM n6_binding_authority_capabilities",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(preserved, 2);
        }
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let foreign_key_errors: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);
    }
}

#[test]
fn populated_v8_upgrades_to_v9_with_exact_typed_backfill_and_n7_schema_identity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("populated-v8.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    seed_n5_confirmed_provenance(&connection);
    connection.execute("INSERT INTO n5_provider_bindings (binding_id,device_id,network_id,join_session_id,credential_id,provider_instance_id,provider_node_id,machine_key_fingerprint,provider_credential_reference,binding_state,binding_revision,observed_at_ms) VALUES ('11111111-1111-4111-8111-111111111111',?1,?2,?3,'1647eae9-8b5a-43e8-95b0-9a2470dc440a','provider-n6','provider-node-n6','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','provider-ref-n6','active',1,1001)", params![DEVICE,NETWORK,SESSION]).unwrap();
    let audit = "d0d53f0b-ae6f-48de-a411-9064814350a1";
    let decision = "ffb2b178-1bf7-44f0-93e2-6137bcfffe3b";
    let reservation = "2f3ec894-cc0c-4dc8-84ee-b8eea72ab661";
    let operation = "6c4b6c3d-3251-46fd-87b7-b2b074736106";
    insert_audit(&connection, audit, "binding", "issue");
    connection
        .execute_batch("BEGIN; PRAGMA defer_foreign_keys=ON;")
        .unwrap();
    connection.execute("INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,join_session_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,'binding','issue',?3,NULL,NULL,?4,?5,?6,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'challenge_issued',?7,NULL,'n6-test-agent')",params![decision,audit,BINDING,NETWORK,DEVICE,SESSION,PEER]).unwrap();
    connection.execute("INSERT INTO n6_binding_records (binding_id,network_id,device_id,join_session_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id) VALUES (?1,?2,?3,?4,NULL,1,1,'pending',2000,'n6-test-agent',?5,?6)",params![BINDING,NETWORK,DEVICE,SESSION,decision,audit]).unwrap();
    connection.execute("INSERT INTO n6_challenge_reservations (reservation_id,binding_id,network_id,device_id,join_session_id,expected_authenticated_peer_id,operation_id,request_fingerprint,generation,expires_at_ms,agent_version,reservation_state,reserved_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',1,5000,'n6-test-agent','reserved',2100)",params![reservation,BINDING,NETWORK,DEVICE,SESSION,PEER,operation]).unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    connection.execute_batch(MIGRATION_7).unwrap();
    connection.execute_batch(MIGRATION_8).unwrap();
    connection.pragma_update(None, "user_version", 8).unwrap();
    let n7_before: Vec<(String,String,String)>=connection.prepare("SELECT type,name,sql FROM sqlite_schema WHERE (name LIKE 'n7_%' OR tbl_name LIKE 'n7_%') AND sql IS NOT NULL ORDER BY type,name").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
    let n7_counts_before = n7_table_counts(&connection);
    drop(connection);
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        10
    );
    let typed:(String,String,String,String,String,i64,String,String)=connection.query_row("SELECT i.identity_origin_kind,io.join_session_id,b.provenance_kind,bp.join_session_id,r.n5_provider_binding_id,r.generation,r.binding_state,z.operation_id FROM n5_device_identities i JOIN n5_n4_identity_origins io ON io.origin_id=i.n4_origin_id AND io.device_id=i.device_id AND io.network_id=i.network_id JOIN n5_provider_bindings b ON b.device_id=i.device_id AND b.network_id=i.network_id JOIN n5_n4_provider_binding_provenance bp ON bp.binding_id=b.n4_provenance_binding_id AND bp.device_id=b.device_id AND bp.network_id=b.network_id JOIN n6_binding_records r ON r.n5_provider_binding_id=b.binding_id AND r.device_id=b.device_id AND r.network_id=b.network_id JOIN n6_challenge_reservations z ON z.binding_id=r.binding_id AND z.device_id=r.device_id AND z.network_id=r.network_id AND z.generation=r.generation WHERE r.binding_id=?1",[BINDING],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).unwrap();
    assert_eq!(
        typed,
        (
            "n4_join_session".into(),
            SESSION.into(),
            "n4_join_session".into(),
            SESSION.into(),
            "11111111-1111-4111-8111-111111111111".into(),
            1,
            "pending".into(),
            operation.into()
        )
    );
    let preserved:(String,String,String,String)=connection.query_row("SELECT d.decision_id,d.audit_event_id,z.reservation_id,z.request_fingerprint FROM n6_binding_decisions d JOIN n6_challenge_reservations z ON z.binding_id=d.binding_id AND z.network_id=d.network_id AND z.device_id=d.device_id AND z.generation=d.generation WHERE d.decision_id=?1",[decision],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        preserved,
        (
            decision.into(),
            audit.into(),
            reservation.into(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into()
        )
    );
    let n7_after:Vec<(String,String,String)>=connection.prepare("SELECT type,name,sql FROM sqlite_schema WHERE (name LIKE 'n7_%' OR tbl_name LIKE 'n7_%') AND sql IS NOT NULL ORDER BY type,name").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
    assert_eq!(n7_after, n7_before);
    assert_eq!(n7_table_counts(&connection), n7_counts_before);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE 'stage_%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn direct_sql_requires_exact_provenance_decisions_and_immutable_lifecycle() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-guards.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);

    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('33fd5328-3139-43a6-96b2-77fba9df4c4c','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111','keryx-peer-n6',1,1,'active',2000,'n6-test-agent','missing','missing')",
            [],
        ),
        "direct active binding insert",
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('36dc3932-a6fe-4283-b181-37ad190d015e','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111',NULL,1,1,'pending',2000,'n6-test-agent','missing','missing')",
            [],
        ),
        "binding without exact N5/N4 provenance",
    );

    insert_pending_binding(&connection);
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET binding_state='active',verified_peer_id='keryx-peer-n6',revision=2,confirmed_at_ms=2100 WHERE binding_id='d494ab4f-20db-4a4f-97bf-aad97f5ac36b'",
            [],
        ),
        "binding transition without decision and audit",
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET generation=2 WHERE binding_id='d494ab4f-20db-4a4f-97bf-aad97f5ac36b'",
            [],
        ),
        "binding identity/generation mutation",
    );
    assert_rejected(
        connection.execute(
            "DELETE FROM n6_binding_records WHERE binding_id='d494ab4f-20db-4a4f-97bf-aad97f5ac36b'",
            [],
        ),
        "binding delete",
    );

    insert_audit(
        &connection,
        "c8847df8-b560-4368-9be6-5d0831b6b4a9",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "7bc1868c-8eb6-431a-8d7a-38312127060a",
        "c8847df8-b560-4368-9be6-5d0831b6b4a9",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection
        .execute(
            "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_decision_id='7bc1868c-8eb6-431a-8d7a-38312127060a',last_audit_event_id='c8847df8-b560-4368-9be6-5d0831b6b4a9',last_verified_at_ms=2000 WHERE binding_id=?2",
            params![PEER, BINDING],
        )
        .unwrap();
    insert_pending_authorization(
        &connection,
        "7411f6fd-c907-49c1-9d96-84e9e4b1c3be",
        "rotate",
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2100 WHERE authorization_id='7411f6fd-c907-49c1-9d96-84e9e4b1c3be'",
            [],
        ),
        "authorization consumption without an exact unexpired decision",
    );
    assert_rejected(
        connection.execute(
            "DELETE FROM n6_binding_authorizations WHERE authorization_id='7411f6fd-c907-49c1-9d96-84e9e4b1c3be'",
            [],
        ),
        "authorization delete",
    );
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit_for_decision(
        &connection,
        "8e041ede-2f48-4348-81d5-03b22ab9243f",
        "nodescale",
        None,
        3,
        "binding",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('82ebd534-9d72-421e-a732-605a30fabf9a','8e041ede-2f48-4348-81d5-03b22ab9243f','binding','issue','a4b5bf76-1eb1-4ecb-bef7-a6292fc7692d',NULL,NULL,'10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc',3,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request','keryx-peer-n6',NULL,'n6-test-agent')",
            [],
        )
        .unwrap();
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms,last_verified_at_ms,rotated_from_binding_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('a4b5bf76-1eb1-4ecb-bef7-a6292fc7692d','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111',NULL,3,1,'pending',2000,NULL,NULL,NULL,NULL,NULL,'d494ab4f-20db-4a4f-97bf-aad97f5ac36b','n6-test-agent','82ebd534-9d72-421e-a732-605a30fabf9a','8e041ede-2f48-4348-81d5-03b22ab9243f')",
            [],
        ),
        "generation skip or fake predecessor",
    );
    connection.execute_batch("ROLLBACK;").unwrap();
    insert_audit(
        &connection,
        "7971f947-2d59-44d9-9f0a-3f19069bd933",
        "binding",
        "stale",
    );
    insert_binding_decision(
        &connection,
        "8cbc6645-b6c4-46ac-aaa3-655546415630",
        "7971f947-2d59-44d9-9f0a-3f19069bd933",
        "stale",
        Some("active"),
        "stale",
        Some(2),
        3,
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET binding_state='stale',verified_peer_id='keryx-peer-swapped',revision=3,stale_at_ms=2000,last_decision_id='8cbc6645-b6c4-46ac-aaa3-655546415630',last_audit_event_id='7971f947-2d59-44d9-9f0a-3f19069bd933' WHERE binding_id='d494ab4f-20db-4a4f-97bf-aad97f5ac36b'",
            [],
        ),
        "verified peer rewrite during binding lifecycle transition",
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('6e8cc954-2ca4-43d8-ad47-5497ae9bd757','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111','keryx-peer-other',2,1,'active',2100,'n6-test-agent','missing','missing')",
            [],
        ),
        "duplicate active binding",
    );
}

#[test]
fn challenges_authorizations_and_decisions_are_append_only_and_one_shot() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-challenge.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(
        &connection,
        "26a28b7e-2de9-4ff7-8c6b-60b766160831",
        "challenge",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('d14eb9f2-c231-44b3-93ed-4a29c0539df9','26a28b7e-2de9-4ff7-8c6b-60b766160831','challenge','issue','d494ab4f-20db-4a4f-97bf-aad97f5ac36b','6a0e1b0e-3aa3-4092-b8cc-632e83347063',NULL,'10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc',1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request','keryx-peer-n6',NULL,'n6-test-agent')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,consumed_at_ms,invalidated_at_ms,expired_at_ms,consumed_operation_id,consumed_authenticated_peer_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('6a0e1b0e-3aa3-4092-b8cc-632e83347063','d494ab4f-20db-4a4f-97bf-aad97f5ac36b','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','keryx-peer-n6',1,?1,'pending',2000,3000,NULL,NULL,NULL,NULL,NULL,'n6-test-agent','d14eb9f2-c231-44b3-93ed-4a29c0539df9','26a28b7e-2de9-4ff7-8c6b-60b766160831')",
            [VERIFIER],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_challenges SET join_session_id='other-session' WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        ),
        "challenge tuple swap",
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_challenges SET challenge_verifier='$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$MDEyMzQ1Njc4OWFiY2RlZg' WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        ),
        "challenge verifier mutation",
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2100,consumed_operation_id='operation-n6',consumed_authenticated_peer_id='keryx-peer-n6' WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        ),
        "challenge consume without decision",
    );
    assert_rejected(
        connection.execute(
            "DELETE FROM n6_binding_challenges WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        ),
        "challenge delete",
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('92e08ad3-443d-48b4-914c-4a0121a46b7c','d494ab4f-20db-4a4f-97bf-aad97f5ac36b','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','keryx-peer-n6',1,'not-an-argon2id-verifier','pending',2000,3000,'n6-test-agent','d14eb9f2-c231-44b3-93ed-4a29c0539df9','26a28b7e-2de9-4ff7-8c6b-60b766160831')",
            [],
        ),
        "strict Argon2id verifier",
    );

    insert_audit(
        &connection,
        "a7494b27-d3e5-4905-bd9c-4aa9d94be38d",
        "challenge",
        "confirm",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('9d276e27-eec7-4e4f-a2a9-3a6cec9153f4','a7494b27-d3e5-4905-bd9c-4aa9d94be38d','challenge','confirm','d494ab4f-20db-4a4f-97bf-aad97f5ac36b','6a0e1b0e-3aa3-4092-b8cc-632e83347063',NULL,'10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc',1,'pending','consumed',1,2,2100,'nodescale',NULL,'operator_request','keryx-peer-n6','operation-n6','n6-test-agent')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2100,consumed_operation_id='operation-n6',consumed_authenticated_peer_id='keryx-peer-n6',last_decision_id='9d276e27-eec7-4e4f-a2a9-3a6cec9153f4',last_audit_event_id='a7494b27-d3e5-4905-bd9c-4aa9d94be38d' WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        )
        .unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2200 WHERE challenge_id='6a0e1b0e-3aa3-4092-b8cc-632e83347063'",
            [],
        ),
        "consumed challenge replay",
    );
    assert_rejected(
        connection.execute(
            "DELETE FROM n6_binding_decisions WHERE decision_id='9d276e27-eec7-4e4f-a2a9-3a6cec9153f4'",
            [],
        ),
        "decision delete",
    );
    assert_rejected(
        connection.execute(
            "DELETE FROM audit_events WHERE event_id='a7494b27-d3e5-4905-bd9c-4aa9d94be38d'",
            [],
        ),
        "audit linked to N6 decision delete",
    );
}

#[test]
fn replay_decisions_require_exact_consumed_challenge_provenance_and_are_audit_only() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-replay-provenance.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(
        &connection,
        "848f97c0-52fe-4078-9895-5c5948371aa8",
        "challenge",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('25a6bd87-6dd4-4daa-aa0c-59596fc342cb','848f97c0-52fe-4078-9895-5c5948371aa8','challenge','issue',?1,'8f2daa38-de99-4db2-9cd0-94074c7c8b98',NULL,?2,?3,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request',?4,NULL,'n6-test-agent')",
            params![BINDING, NETWORK, DEVICE, PEER],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,consumed_at_ms,invalidated_at_ms,expired_at_ms,consumed_operation_id,consumed_authenticated_peer_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('8f2daa38-de99-4db2-9cd0-94074c7c8b98',?1,?2,?3,?4,1,?5,'pending',2000,3000,NULL,NULL,NULL,NULL,NULL,'n6-test-agent','25a6bd87-6dd4-4daa-aa0c-59596fc342cb','848f97c0-52fe-4078-9895-5c5948371aa8')",
            params![BINDING, NETWORK, DEVICE, PEER, VERIFIER],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    insert_audit(
        &connection,
        "d9d97dba-ac7c-4fef-84e4-7a7889dbeccd",
        "challenge",
        "confirm",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('215b7c5e-737b-42a2-858c-13c7c8d79c78','d9d97dba-ac7c-4fef-84e4-7a7889dbeccd','challenge','confirm',?1,'8f2daa38-de99-4db2-9cd0-94074c7c8b98',NULL,?2,?3,1,'pending','consumed',1,2,2100,'nodescale',NULL,'operator_request',?4,'operation-replay','n6-test-agent')",
            params![BINDING, NETWORK, DEVICE, PEER],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2100,consumed_operation_id='operation-replay',consumed_authenticated_peer_id=?1,last_decision_id='215b7c5e-737b-42a2-858c-13c7c8d79c78',last_audit_event_id='d9d97dba-ac7c-4fef-84e4-7a7889dbeccd' WHERE challenge_id='8f2daa38-de99-4db2-9cd0-94074c7c8b98'",
            [PEER],
        )
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(
        &connection,
        "355de2f8-c343-43c9-ae6f-4337f6f7f3ef",
        "challenge",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('5f86266d-78b0-4edb-b106-b59f1c6a5a2d','355de2f8-c343-43c9-ae6f-4337f6f7f3ef','challenge','issue',?1,'88914a67-1f7b-4373-adcf-ef9f6d01ca74',NULL,?2,?3,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request',?4,NULL,'n6-test-agent')",
            params![BINDING, NETWORK, DEVICE, PEER],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,consumed_at_ms,invalidated_at_ms,expired_at_ms,consumed_operation_id,consumed_authenticated_peer_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('88914a67-1f7b-4373-adcf-ef9f6d01ca74',?1,?2,?3,?4,1,?5,'pending',2000,3000,NULL,NULL,NULL,NULL,NULL,'n6-test-agent','5f86266d-78b0-4edb-b106-b59f1c6a5a2d','355de2f8-c343-43c9-ae6f-4337f6f7f3ef')",
            params![BINDING, NETWORK, DEVICE, PEER, VERIFIER],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();

    let insert_replay = |decision_id: &str,
                         audit_event_id: &str,
                         challenge_id: &str,
                         binding_id: &str,
                         device_id: &str,
                         _join_session_id: &str,
                         generation: i64,
                         authenticated_peer_id: &str,
                         operation_id: &str,
                         agent_version: &str,
                         decided_at_ms: i64,
                         prior_state: &str,
                         new_state: &str,
                         prior_revision: i64,
                         new_revision: i64| {
        insert_audit(&connection, audit_event_id, "challenge", "replay");
        connection.execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES (?1,?2,'challenge','replay',?3,?4,NULL,?5,?6,?7,?8,?9,?10,?11,?12,'nodescale',NULL,'challenge_replay',?13,?14,?15)",
            params![decision_id, audit_event_id, binding_id, challenge_id, NETWORK, device_id, generation, prior_state, new_state, prior_revision, new_revision, decided_at_ms, authenticated_peer_id, operation_id, agent_version],
        )
    };

    assert_rejected(
        insert_replay(
            "7dd1d3ca-d948-4a11-aa1e-453562014361",
            "f72d8ea0-2545-4387-a1a9-f8315fa69742",
            "88914a67-1f7b-4373-adcf-ef9f6d01ca74",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay for non-consumed challenge",
    );
    assert_rejected(
        insert_replay(
            "4e8221b0-badc-4cb4-90a4-222bb011f883",
            "6ab2ca1d-6040-4525-af49-e7a1ca12d4c8",
            "b565e82e-4bc0-478e-8f62-1254f3ae484a",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay for nonexistent challenge",
    );
    assert_rejected(
        insert_replay(
            "c630fc8d-65c3-46d3-977e-90b402fb4cea",
            "6856217c-5386-4fc3-a4cb-57dd7b91e2dd",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            "907ae7a4-ea8a-4aa2-8115-df4bc2e6d654",
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong binding tuple",
    );
    assert_rejected(
        insert_replay(
            "206e334c-7386-43ea-9af3-39772bc1edc3",
            "76701d8d-85a0-4360-a317-f64f2a022d2d",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            "25042b49-2d90-47e9-934d-ca68cf029d39",
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong device",
    );
    assert_rejected(
        insert_replay(
            "8b54b187-4c02-44a2-8de7-23688fc98053",
            "efed2a1f-c5e5-41f6-ba01-04e05ec1b07b",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            "session-wrong",
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong join session",
    );
    assert_rejected(
        insert_replay(
            "892f42d3-0c3e-4045-9a92-69a3ab2521b4",
            "91f841df-82f4-4858-8867-e5880e288e96",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            2,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong generation",
    );
    assert_rejected(
        insert_replay(
            "bc7fd3c5-a6c8-4ab7-8eea-a3ae2aa827be",
            "44aad34b-03c4-4bcc-9f6a-59d9fecbf0d3",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            1,
            "peer-wrong",
            "operation-replay",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong authenticated peer",
    );
    assert_rejected(
        insert_replay(
            "9a6d9d92-1c0b-4d12-b453-6208e2047d5a",
            "d620dc6d-6320-4128-82eb-7d9836ef9499",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-wrong",
            "n6-test-agent",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong operation",
    );
    assert_rejected(
        insert_replay(
            "0d800609-db7e-4837-b4a1-b99a23c5e337",
            "f94a68c9-eab7-430e-906a-c1e9584d928c",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "agent-wrong",
            2100,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay with wrong agent version",
    );
    assert_rejected(
        insert_replay(
            "1804e9c8-c8ef-4c80-a7a3-b1ad4dd801a7",
            "20a4ee35-8a22-4d37-90ca-3c244f09e4d8",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2099,
            "consumed",
            "consumed",
            2,
            3,
        ),
        "replay before challenge consumption",
    );
    assert_rejected(
        insert_replay(
            "f4591332-74d1-441e-abe3-0b84418168ca",
            "fc1d9393-7324-4c8b-83ab-e20482a9595b",
            "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
            BINDING,
            DEVICE,
            SESSION,
            1,
            PEER,
            "operation-replay",
            "n6-test-agent",
            2100,
            "pending",
            "consumed",
            1,
            2,
        ),
        "replay reconsumption state and revision evidence",
    );

    let before: (String, i64, String, String, String, String) = connection
        .query_row(
            "SELECT challenge_state,consumed_at_ms,consumed_operation_id,consumed_authenticated_peer_id,last_decision_id,last_audit_event_id FROM n6_binding_challenges WHERE challenge_id='8f2daa38-de99-4db2-9cd0-94074c7c8b98'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .unwrap();
    insert_replay(
        "4fb8296c-9b44-4004-b345-4c931a57f4b4",
        "4fbeb70c-ceeb-41c0-9588-dc4420900e8d",
        "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
        BINDING,
        DEVICE,
        SESSION,
        1,
        PEER,
        "operation-replay",
        "n6-test-agent",
        2100,
        "consumed",
        "consumed",
        2,
        2,
    )
    .unwrap();
    insert_replay(
        "00b2a332-c7f7-4efc-91af-97743d85e164",
        "3e815e79-5300-40d4-9af0-f11d4fe04527",
        "8f2daa38-de99-4db2-9cd0-94074c7c8b98",
        BINDING,
        DEVICE,
        SESSION,
        1,
        PEER,
        "operation-replay",
        "n6-test-agent",
        2100,
        "consumed",
        "consumed",
        2,
        2,
    )
    .unwrap();
    let replay_audit: (String, String) = connection
        .query_row(
            "SELECT event_kind,outcome FROM audit_events WHERE event_id='4fbeb70c-ceeb-41c0-9588-dc4420900e8d'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        replay_audit,
        ("keryx_binding_replay".into(), "idempotent".into()),
        "replay decisions require the exact idempotent semantic audit"
    );
    let after: (String, i64, String, String, String, String) = connection
        .query_row(
            "SELECT challenge_state,consumed_at_ms,consumed_operation_id,consumed_authenticated_peer_id,last_decision_id,last_audit_event_id FROM n6_binding_challenges WHERE challenge_id='8f2daa38-de99-4db2-9cd0-94074c7c8b98'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "replay decisions must not reconsume or mutate challenge"
    );
}

#[test]
fn rotation_successor_can_be_pending_while_predecessor_is_active() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-rotation-pending.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "72d1b026-ecd5-4e6c-a26f-317fa4a2b526",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "47c0986d-4137-4c70-adac-9b33c9a8be99",
        "72d1b026-ecd5-4e6c-a26f-317fa4a2b526",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection
        .execute(
            "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='47c0986d-4137-4c70-adac-9b33c9a8be99',last_audit_event_id='72d1b026-ecd5-4e6c-a26f-317fa4a2b526' WHERE binding_id=?2",
            params![PEER, BINDING],
        )
        .unwrap();
    insert_pending_authorization(
        &connection,
        "2363759c-3fd8-4305-ac97-1558e98b9192",
        "rotate",
    );
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit_for_decision(
        &connection,
        "eb8e1e6a-7704-434e-994c-ff9d2f2b1ce1",
        "nodescale",
        None,
        2,
        "binding",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('10ecd26e-e4c8-4a8b-9d4a-f8d0a9da7048','eb8e1e6a-7704-434e-994c-ff9d2f2b1ce1','binding','issue',?1,NULL,NULL,?2,?3,2,NULL,'pending',NULL,1,2100,'nodescale',NULL,'operator_request',NULL,NULL,'n6-test-agent')",
            params![SUCCESSOR_BINDING, NETWORK, DEVICE],
        )
        .unwrap();

    connection
        .execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms,last_verified_at_ms,rotated_from_binding_id,rotation_authorization_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES (?1,?2,?3,'11111111-1111-4111-8111-111111111111',NULL,2,1,'pending',2100,NULL,NULL,NULL,NULL,NULL,?4,'2363759c-3fd8-4305-ac97-1558e98b9192','n6-test-agent','10ecd26e-e4c8-4a8b-9d4a-f8d0a9da7048','eb8e1e6a-7704-434e-994c-ff9d2f2b1ce1')",
            params![SUCCESSOR_BINDING, NETWORK, DEVICE, BINDING],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();

    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit_for_decision(
        &connection,
        "41bb206b-5f89-4eff-b3f7-263895452351",
        "nodescale",
        None,
        2,
        "challenge",
        "issue",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('1ee7b97d-9680-4178-b712-7702831f58a0','41bb206b-5f89-4eff-b3f7-263895452351','challenge','issue',?1,'99d6b73c-728e-41c9-826f-17768d9b7d94',NULL,?2,?3,2,NULL,'pending',NULL,1,2150,'nodescale',NULL,'challenge_issued',?4,NULL,'n6-test-agent')",
        params![SUCCESSOR_BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    connection.execute(
        "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id) VALUES ('99d6b73c-728e-41c9-826f-17768d9b7d94',?1,?2,?3,?4,2,?5,'pending',2150,3000,'n6-test-agent','1ee7b97d-9680-4178-b712-7702831f58a0','41bb206b-5f89-4eff-b3f7-263895452351')",
        params![SUCCESSOR_BINDING, NETWORK, DEVICE, PEER, VERIFIER],
    ).unwrap();
    connection.execute_batch("COMMIT;").unwrap();
    insert_audit_for_decision(
        &connection,
        "80a45975-81dd-4590-ab55-ee7a7166e4b2",
        "nodescale",
        None,
        2,
        "challenge",
        "confirm",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('474e161f-dd89-42e3-9aa6-cfaa2b7efeea','80a45975-81dd-4590-ab55-ee7a7166e4b2','challenge','confirm',?1,'99d6b73c-728e-41c9-826f-17768d9b7d94',NULL,?2,?3,2,'pending','consumed',1,2,2200,'nodescale',NULL,'challenge_confirmed',?4,'operation-rotation-g2','n6-test-agent')",
        params![SUCCESSOR_BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2200,consumed_operation_id='operation-rotation-g2',consumed_authenticated_peer_id=?1,last_decision_id='474e161f-dd89-42e3-9aa6-cfaa2b7efeea',last_audit_event_id='80a45975-81dd-4590-ab55-ee7a7166e4b2' WHERE challenge_id='99d6b73c-728e-41c9-826f-17768d9b7d94'",
        [PEER],
    ).unwrap();
    insert_audit_for_decision(
        &connection,
        "0a6911f2-41dc-4178-9b66-cb3d8bab0623",
        "nodescale",
        None,
        2,
        "binding",
        "confirm",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('2163e01e-ebe6-46fd-a961-655439fc190d','0a6911f2-41dc-4178-9b66-cb3d8bab0623','binding','confirm',?1,'99d6b73c-728e-41c9-826f-17768d9b7d94',NULL,?2,?3,2,'pending','active',1,2,2200,'nodescale',NULL,'challenge_confirmed',?4,'operation-rotation-g2','n6-test-agent')",
        params![SUCCESSOR_BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute("UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2200,last_verified_at_ms=2200,last_decision_id='2163e01e-ebe6-46fd-a961-655439fc190d',last_audit_event_id='0a6911f2-41dc-4178-9b66-cb3d8bab0623' WHERE binding_id=?2", params![PEER, SUCCESSOR_BINDING]),
        "successor activation before predecessor rotation",
    );

    insert_pending_authorization(
        &connection,
        "d202edf9-2617-4e30-827a-3065a0b03589",
        "revoke",
    );
    insert_audit(
        &connection,
        "f1a2b719-f9d4-4aa2-a8b5-887f554282df",
        "binding",
        "revoke",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('6b4c06cd-e0fc-4e33-9608-a02746c739e4','f1a2b719-f9d4-4aa2-a8b5-887f554282df','binding','revoke',?1,NULL,'d202edf9-2617-4e30-827a-3065a0b03589',?2,?3,1,'active','revoked',2,3,2200,'nodescale',NULL,'operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='6b4c06cd-e0fc-4e33-9608-a02746c739e4',consumed_audit_event_id='f1a2b719-f9d4-4aa2-a8b5-887f554282df' WHERE authorization_id='d202edf9-2617-4e30-827a-3065a0b03589'",
            [],
        ),
        "unauthenticated audit and decision cannot consume revoke authorization",
    );

    insert_audit(
        &connection,
        "d35f0441-e761-4531-b622-c8f2f0f4fcc9",
        "binding",
        "rotate",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('6d99df6b-cbbe-4e04-be4d-be85f5d7e3ab','d35f0441-e761-4531-b622-c8f2f0f4fcc9','binding','rotate',?1,NULL,'2363759c-3fd8-4305-ac97-1558e98b9192',?2,?3,1,'active','rotated',2,3,2200,'nodescale',NULL,'operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='6d99df6b-cbbe-4e04-be4d-be85f5d7e3ab',consumed_audit_event_id='d35f0441-e761-4531-b622-c8f2f0f4fcc9' WHERE authorization_id='2363759c-3fd8-4305-ac97-1558e98b9192'",
            [],
        ),
        "unauthenticated audit and decision cannot consume rotation authorization",
    );

    insert_audit_for_decision(
        &connection,
        "3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69",
        "operator",
        Some("operator-n6"),
        1,
        "binding",
        "rotate",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('5c281d45-5e40-4b63-8746-dc5f6e0a7270','3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69','binding','rotate',?1,NULL,'2363759c-3fd8-4305-ac97-1558e98b9192',?2,?3,1,'active','rotated',2,3,2200,'operator','operator-n6','operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute("UPDATE n6_binding_records SET binding_state='rotated',revision=3,rotated_at_ms=2200,last_decision_id='5c281d45-5e40-4b63-8746-dc5f6e0a7270',last_audit_event_id='3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69' WHERE binding_id=?1", [BINDING]),
        "rotation decision without consumed exact authorization",
    );
    connection.execute(
        "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='5c281d45-5e40-4b63-8746-dc5f6e0a7270',consumed_audit_event_id='3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69' WHERE authorization_id='2363759c-3fd8-4305-ac97-1558e98b9192'",
        [],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET binding_state='rotated',revision=3,stale_at_ms=2200,rotated_at_ms=2200,last_decision_id='5c281d45-5e40-4b63-8746-dc5f6e0a7270',last_audit_event_id='3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69' WHERE binding_id=?1",
            [BINDING],
        ),
        "active to rotated cannot fabricate stale history",
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='rotated',revision=3,rotated_at_ms=2200,last_decision_id='5c281d45-5e40-4b63-8746-dc5f6e0a7270',last_audit_event_id='3c3536b6-0d7c-4c02-a6cc-2c6c4137ee69' WHERE binding_id=?1",
        [BINDING],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2200,last_verified_at_ms=2200,last_decision_id='2163e01e-ebe6-46fd-a961-655439fc190d',last_audit_event_id='0a6911f2-41dc-4178-9b66-cb3d8bab0623' WHERE binding_id=?2",
        params![PEER, SUCCESSOR_BINDING],
    ).unwrap();
    assert_rejected(
        connection.execute("UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2201 WHERE authorization_id='2363759c-3fd8-4305-ac97-1558e98b9192'", []),
        "consumed rotation authorization replay",
    );
}

#[test]
fn stale_to_rotated_preserves_durable_history_and_rejects_rewrites() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-stale-to-rotated.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "9d7ad1da-2802-42ba-8d0e-fcf146f5d646",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "58ec2c30-6275-48ba-b0b4-269b03fb0be0",
        "9d7ad1da-2802-42ba-8d0e-fcf146f5d646",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='58ec2c30-6275-48ba-b0b4-269b03fb0be0',last_audit_event_id='9d7ad1da-2802-42ba-8d0e-fcf146f5d646' WHERE binding_id=?2",
        params![PEER, BINDING],
    ).unwrap();

    insert_audit(
        &connection,
        "c9c8c11e-ac2a-46ca-ba19-848e74c9b8e7",
        "binding",
        "stale",
    );
    insert_binding_decision(
        &connection,
        "fc0c07de-8095-425f-8d5e-4380bc3ef48b",
        "c9c8c11e-ac2a-46ca-ba19-848e74c9b8e7",
        "stale",
        Some("active"),
        "stale",
        Some(2),
        3,
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='stale',revision=3,stale_at_ms=2000,last_decision_id='fc0c07de-8095-425f-8d5e-4380bc3ef48b',last_audit_event_id='c9c8c11e-ac2a-46ca-ba19-848e74c9b8e7' WHERE binding_id=?1",
        [BINDING],
    ).unwrap();
    insert_pending_authorization(
        &connection,
        "6c765b78-b26b-4e66-96e3-634318b2fd64",
        "rotate",
    );
    insert_audit_for_decision(
        &connection,
        "e5613d89-ae3a-4535-b9ec-7a64b7f9e852",
        "operator",
        Some("operator-n6"),
        1,
        "binding",
        "rotate",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('0e64bc13-c37a-499b-85ca-5cf0a5b28247','e5613d89-ae3a-4535-b9ec-7a64b7f9e852','binding','rotate',?1,NULL,'6c765b78-b26b-4e66-96e3-634318b2fd64',?2,?3,1,'stale','rotated',3,4,2200,'operator','operator-n6','operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='0e64bc13-c37a-499b-85ca-5cf0a5b28247',consumed_audit_event_id='e5613d89-ae3a-4535-b9ec-7a64b7f9e852' WHERE authorization_id='6c765b78-b26b-4e66-96e3-634318b2fd64'",
        [],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET binding_state='rotated',revision=4,rotated_at_ms=2200,last_verified_at_ms=2100,last_decision_id='0e64bc13-c37a-499b-85ca-5cf0a5b28247',last_audit_event_id='e5613d89-ae3a-4535-b9ec-7a64b7f9e852' WHERE binding_id=?1",
            [BINDING],
        ),
        "stale to rotated cannot rewrite last verification after stale evidence",
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='rotated',revision=4,rotated_at_ms=2200,last_decision_id='0e64bc13-c37a-499b-85ca-5cf0a5b28247',last_audit_event_id='e5613d89-ae3a-4535-b9ec-7a64b7f9e852' WHERE binding_id=?1",
        [BINDING],
    ).unwrap();

    let history: (String, i64, i64, i64) = connection.query_row(
        "SELECT verified_peer_id,confirmed_at_ms,last_verified_at_ms,stale_at_ms FROM n6_binding_records WHERE binding_id=?1",
        [BINDING],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    assert_eq!(history, (PEER.into(), 2000, 2000, 2000));
    for (column, value) in [
        ("verified_peer_id", "peer-rewritten"),
        ("confirmed_at_ms", "2101"),
        ("last_verified_at_ms", "2101"),
        ("stale_at_ms", "2101"),
    ] {
        assert_rejected(
            connection.execute(
                &format!("UPDATE n6_binding_records SET {column}={value} WHERE binding_id='d494ab4f-20db-4a4f-97bf-aad97f5ac36b'"),
                [],
            ),
            column,
        );
    }
}

#[test]
fn consumed_authorization_requires_a_live_matching_n5_authority() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-live-authority.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "d2611e1e-4422-4de2-890a-75ef66f124f6",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "83eda197-ee34-46c9-8e19-b62afae588aa",
        "d2611e1e-4422-4de2-890a-75ef66f124f6",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='83eda197-ee34-46c9-8e19-b62afae588aa',last_audit_event_id='d2611e1e-4422-4de2-890a-75ef66f124f6' WHERE binding_id=?2",
        params![PEER, BINDING],
    ).unwrap();
    insert_pending_authorization(
        &connection,
        "16995c82-f15e-4033-8406-915fe16469b6",
        "revoke",
    );
    connection.execute(
        "UPDATE n5_trust_authorities SET enabled=0,revoked_at_ms=2100 WHERE authority_id='6033e8e2-c7ba-4100-a75c-dda7de7db8a7'",
        [],
    ).unwrap();
    insert_audit_for_decision(
        &connection,
        "e6c564a4-d052-421e-b92d-7ddcf96c5461",
        "operator",
        Some("operator-n6"),
        1,
        "binding",
        "revoke",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('95d17a27-b94e-4d7c-9d69-3e2b29cd1804','e6c564a4-d052-421e-b92d-7ddcf96c5461','binding','revoke',?1,NULL,'16995c82-f15e-4033-8406-915fe16469b6',?2,?3,1,'active','revoked',2,3,2200,'operator','operator-n6','operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='95d17a27-b94e-4d7c-9d69-3e2b29cd1804',consumed_audit_event_id='e6c564a4-d052-421e-b92d-7ddcf96c5461' WHERE authorization_id='16995c82-f15e-4033-8406-915fe16469b6'",
            [],
        ),
        "disabled or revoked N5 authority cannot consume authorization",
    );
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_records SET binding_state='revoked',revision=3,revoked_at_ms=2200,last_decision_id='95d17a27-b94e-4d7c-9d69-3e2b29cd1804',last_audit_event_id='e6c564a4-d052-421e-b92d-7ddcf96c5461' WHERE binding_id=?1",
            [BINDING],
        ),
        "binding lifecycle mutation requires successful authorization consumption",
    );
}

#[test]
fn decision_rejects_audit_business_actor_or_generation_mismatch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-audit-correlation.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);

    for (audit_id, decision_id, audit_source, audit_actor, audit_generation) in [
        (
            "4c79d88b-d06c-40a4-865b-9a3a19a9e65c",
            "94166758-ec44-4fc3-b90c-a7fbeb212c82",
            "operator",
            Some("operator-n6"),
            1,
        ),
        (
            "d8b7ed27-febf-401f-99d2-1c7851244a9c",
            "458563fe-4e13-47be-b1f8-fed61268ff28",
            "nodescale",
            None,
            2,
        ),
    ] {
        insert_audit_for_decision(
            &connection,
            audit_id,
            audit_source,
            audit_actor,
            audit_generation,
            "binding",
            "issue",
        );
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
                 VALUES (?1,?2,'binding','issue','392a2b6b-47bd-4adb-83cc-ee8555ddb9f7',NULL,NULL,?3,?4,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request',NULL,NULL,'n6-test-agent')",
                params![decision_id, audit_id, NETWORK, DEVICE],
            ),
            "decision and audit business actor/generation mismatch",
        );
    }
}

#[test]
fn sql_agent_version_grammar_matches_the_n6_domain_boundary() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-agent-version-grammar.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);

    let valid = AgentVersion::parse("nodescale-agent:6.0.0").unwrap();
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    insert_audit(
        &connection,
        "10620696-72fb-488f-86cb-8d24e1dba8f7",
        "binding",
        "issue",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('989ddfc9-6a82-46ff-a30c-dea08f53c3d5','10620696-72fb-488f-86cb-8d24e1dba8f7','binding','issue','050ff538-1607-4d5a-87e4-71abd5aebab0',NULL,NULL,?1,?2,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request',NULL,NULL,?3)",
            params![NETWORK, DEVICE, valid.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('050ff538-1607-4d5a-87e4-71abd5aebab0',?1,?2,'11111111-1111-4111-8111-111111111111',NULL,1,1,'pending',2000,?3,'989ddfc9-6a82-46ff-a30c-dea08f53c3d5','10620696-72fb-488f-86cb-8d24e1dba8f7')",
            params![NETWORK, DEVICE, valid.as_str()],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();

    for (index, forbidden) in [
        "agent/version",
        "agent version",
        "agent\nversion",
        "agent-é",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            AgentVersion::parse(forbidden).is_err(),
            "domain accepted {forbidden:?}"
        );
        let audit_id = format!("audit-invalid-agent-version-{index}");
        let decision_id = format!("decision-invalid-agent-version-{index}");
        insert_audit(&connection, &audit_id, "binding", "issue");
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
                 VALUES (?1,?2,'binding','issue',?3,NULL,NULL,?4,?5,1,NULL,'pending',NULL,1,2000,'nodescale',NULL,'operator_request',NULL,NULL,?6)",
                params![decision_id, audit_id, format!("binding-invalid-agent-version-{index}"), NETWORK, DEVICE, forbidden],
            ),
            forbidden,
        );
    }
}

#[test]
fn binding_activation_requires_one_exact_consumed_challenge() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-binding-consumed-challenge.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "7081d445-6304-4bb0-aba2-675a144b588e",
        "binding",
        "confirm",
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES ('d6639c69-f764-4659-82cf-1711f6c39808','7081d445-6304-4bb0-aba2-675a144b588e','binding','confirm',?1,NULL,NULL,?2,?3,1,'pending','active',1,2,2100,'nodescale',NULL,'challenge_confirmed',?4,'operation-n6','n6-test-agent')",
            params![BINDING, NETWORK, DEVICE, PEER],
        ),
        "binding confirmation decision without a consumed challenge",
    );
}

#[test]
fn sql_n6_uuid_and_argon2_phc_shapes_are_exact() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-shape-checks.db");
    drop(StateStore::open(&path).unwrap());
    let source = Connection::open(path).unwrap();
    let schema: String = source
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='n6_binding_challenges'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let connection = Connection::open_in_memory().unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection.execute_batch(&schema).unwrap();

    let insert = |challenge_id: String, verifier: &str| {
        connection.execute(
            "INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id) VALUES (?1,?2,?3,?4,'keryx-peer-n6',1,?5,'pending',1000,2000,'n6-test-agent',?6,?7)",
            params![challenge_id, n6_uuid(), n6_uuid(), n6_uuid(), verifier, n6_uuid(), n6_uuid()],
        )
    };
    insert(n6_uuid(), VERIFIER).unwrap();
    let mut noncanonical_salt = VERIFIER.as_bytes().to_vec();
    noncanonical_salt[52] = b'h';
    let noncanonical_salt = String::from_utf8(noncanonical_salt).unwrap();
    assert_rejected(
        insert(n6_uuid(), &noncanonical_salt),
        "noncanonical salt trailing bits",
    );
    let mut noncanonical_hash = VERIFIER.as_bytes().to_vec();
    noncanonical_hash[96] = b'Z';
    let noncanonical_hash = String::from_utf8(noncanonical_hash).unwrap();
    assert_rejected(
        insert(n6_uuid(), &noncanonical_hash),
        "noncanonical hash trailing bits",
    );
    for invalid in [
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVG",
        "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZmdo$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVG",
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdCE$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVG",
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdC1uNi1maXhlZC0xNg$MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY$extra",
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdC1uNi1maXhlZA$MDEyMzQ1Njc4OWFiY2RlZg",
    ] {
        assert_rejected(insert(n6_uuid(), invalid), invalid);
    }
    for invalid_id in [
        "00000000-0000-0000-0000-000000000000".to_owned(),
        n6_uuid().to_uppercase(),
        n6_uuid().replace('-', ""),
    ] {
        assert_rejected(insert(invalid_id, VERIFIER), "noncanonical N6 UUID");
    }
}

#[test]
fn sql_binding_state_check_requires_verification_for_confirmed_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-state-check.db");
    drop(StateStore::open(&path).unwrap());
    let source = Connection::open(path).unwrap();
    let schema: String = source
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='n6_binding_records'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let connection = Connection::open_in_memory().unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection.execute_batch(&schema).unwrap();

    for (index, state, stale_at_ms, rotated_at_ms, revoked_at_ms) in [
        (0, "active", None, None, None),
        (1, "stale", Some(2000), None, None),
        (2, "rotated", None, Some(2000), None),
        (3, "revoked", None, None, Some(2000)),
    ] {
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms,last_verified_at_ms,rotated_from_binding_id,rotation_authorization_id,agent_version,last_decision_id,last_audit_event_id)
                 VALUES (?1,'10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111','peer-n6',1,1,?2,1000,1500,?3,?4,?5,NULL,NULL,NULL,'nodescale-agent:6.0.0',?6,?7)",
                params![format!("binding-missing-verification-{index}"), state, stale_at_ms, rotated_at_ms, revoked_at_ms, format!("decision-missing-verification-{index}"), format!("audit-missing-verification-{index}")],
            ),
            state,
        );
    }

    connection
        .execute(
            "INSERT INTO n6_binding_records (binding_id,network_id,device_id,n5_provider_binding_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms,last_verified_at_ms,rotated_from_binding_id,rotation_authorization_id,agent_version,last_decision_id,last_audit_event_id)
             VALUES ('885ded61-1e2b-4b98-b861-2a2b27c3a533','10bdbae2-73be-46f2-8f0a-5b761fdeaf4d','f9b36c3a-e777-4e92-a4ea-14d22a234ecc','11111111-1111-4111-8111-111111111111',NULL,1,2,'revoked',1000,NULL,NULL,NULL,2000,NULL,NULL,NULL,'nodescale-agent:6.0.0','406143dc-598d-49d0-8b49-3e8bc8817846','39da141a-e7a6-424d-ba7f-60c2aebb6d0d')",
            [],
        )
        .unwrap();
}

#[test]
fn n5_activate_device_trust_alone_cannot_issue_n6_rotate_authorization() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-capability-issuance.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "bda26502-c6de-4bc4-84a3-f27f1f86cd10",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "242a4ac8-aad2-40b1-bfeb-56be7c1f8b8f",
        "bda26502-c6de-4bc4-84a3-f27f1f86cd10",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection
        .execute(
            "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='242a4ac8-aad2-40b1-bfeb-56be7c1f8b8f',last_audit_event_id='bda26502-c6de-4bc4-84a3-f27f1f86cd10' WHERE binding_id=?2",
            params![PEER, BINDING],
        )
        .unwrap();
    connection.execute(
        "INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
         VALUES ('71e08e3f-0cd5-4f12-b21e-ec343b332a71','55f08bb1-3cc7-42b4-ab1d-1e83d3d155df',?1,'operator','operator-n6',2,1000,999999999999,1,1,NULL,1000)",
        [NETWORK],
    ).unwrap();

    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_authorizations (authorization_id,authority_id,binding_id,network_id,device_id,generation,expected_revision,action_kind,actor_source,actor_id,issued_at_ms,expires_at_ms,authorization_state,consumed_at_ms,consumed_decision_id,consumed_audit_event_id)
             VALUES ('b1dfdc16-26b0-4401-a8b0-138a0d19f037','71e08e3f-0cd5-4f12-b21e-ec343b332a71',?1,?2,?3,1,2,'rotate','operator','operator-n6',2000,3000,'pending',NULL,NULL,NULL)",
            params![BINDING, NETWORK, DEVICE],
        ),
        "N5 ActivateDeviceTrust alone must not issue N6 rotate authorization",
    );
}

#[test]
fn authorization_lifecycle_requires_settlement_evidence_and_releases_only_settled_rows() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-authorization-lifecycle.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);

    insert_audit(
        &connection,
        "bcd64ee1-edcd-4921-a6e3-d6cea444c4c8",
        "binding",
        "confirm",
    );
    insert_binding_decision(
        &connection,
        "ae0501ea-55a3-4e14-b28e-6c5128fbb1cd",
        "bcd64ee1-edcd-4921-a6e3-d6cea444c4c8",
        "confirm",
        Some("pending"),
        "active",
        Some(1),
        2,
    );
    connection.execute(
        "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=2,confirmed_at_ms=2000,last_verified_at_ms=2000,last_decision_id='ae0501ea-55a3-4e14-b28e-6c5128fbb1cd',last_audit_event_id='bcd64ee1-edcd-4921-a6e3-d6cea444c4c8' WHERE binding_id=?2",
        params![PEER, BINDING],
    ).unwrap();

    insert_pending_authorization_with_window(
        &connection,
        "0281770a-2c38-40c0-b714-c95e36937311",
        "rotate",
        2000,
        2100,
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_authorizations (authorization_id,authority_id,binding_id,network_id,device_id,generation,expected_revision,action_kind,actor_source,actor_id,issued_at_ms,expires_at_ms,authorization_state) VALUES ('d3677d34-dbe6-4342-9d88-97f6bd957e1b','6033e8e2-c7ba-4100-a75c-dda7de7db8a7',?1,?2,?3,1,2,'rotate','operator','operator-n6',2000,2200,'pending')",
            params![BINDING, NETWORK, DEVICE],
        ),
        "expired but unsettled pending authorization blocks replacement",
    );

    insert_audit_for_decision(
        &connection,
        "65b4d5c6-644a-4487-b850-4cceea2d144e",
        "operator",
        Some("operator-n6"),
        1,
        "authorization",
        "expire",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('f63075d3-a96b-4fcf-ab72-eb06a3e2a927','65b4d5c6-644a-4487-b850-4cceea2d144e','authorization','expire',?1,NULL,'0281770a-2c38-40c0-b714-c95e36937311',?2,?3,1,'pending','expired',2,3,2100,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_authorizations SET authorization_state='expired',expired_at_ms=2100,expired_decision_id='f63075d3-a96b-4fcf-ab72-eb06a3e2a927',expired_audit_event_id='65b4d5c6-644a-4487-b850-4cceea2d144e' WHERE authorization_id='0281770a-2c38-40c0-b714-c95e36937311'",
        [],
    ).unwrap();
    insert_pending_authorization_with_window(
        &connection,
        "d3677d34-dbe6-4342-9d88-97f6bd957e1b",
        "rotate",
        2000,
        2200,
    );

    for statement in [
        "UPDATE n6_binding_authorizations SET authorization_state='consumed' WHERE authorization_id='0281770a-2c38-40c0-b714-c95e36937311'",
        "UPDATE n6_binding_authorizations SET expired_at_ms=2101 WHERE authorization_id='0281770a-2c38-40c0-b714-c95e36937311'",
        "UPDATE n6_binding_authorizations SET authorization_state='expired' WHERE authorization_id='0281770a-2c38-40c0-b714-c95e36937311'",
        "DELETE FROM n6_binding_authorizations WHERE authorization_id='0281770a-2c38-40c0-b714-c95e36937311'",
    ] {
        assert_rejected(connection.execute(statement, []), statement);
    }

    insert_audit_for_decision(
        &connection,
        "7a903c15-8c37-4301-bc42-9ed07a0b0964",
        "operator",
        Some("operator-n6"),
        1,
        "authorization",
        "invalidate",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('eecbd34b-5a11-4e2e-a311-ad2364802811','7a903c15-8c37-4301-bc42-9ed07a0b0964','authorization','invalidate',?1,NULL,'d3677d34-dbe6-4342-9d88-97f6bd957e1b',?2,?3,1,'pending','invalidated',2,3,2050,'operator','operator-n6','authorization_invalidated',NULL,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE],
    ).unwrap();
    connection
        .execute(
            "UPDATE n6_binding_authorizations SET authorization_state='invalidated',invalidated_at_ms=2050,invalidated_decision_id='eecbd34b-5a11-4e2e-a311-ad2364802811',invalidated_audit_event_id='7a903c15-8c37-4301-bc42-9ed07a0b0964' WHERE authorization_id='d3677d34-dbe6-4342-9d88-97f6bd957e1b'",
            [],
        )
        .unwrap();
    for (audit_id, expected_kind) in [
        (
            "65b4d5c6-644a-4487-b850-4cceea2d144e",
            "keryx_binding_authorization_expired",
        ),
        (
            "7a903c15-8c37-4301-bc42-9ed07a0b0964",
            "keryx_binding_authorization_invalidated",
        ),
    ] {
        let settlement_audit: (String, String) = connection
            .query_row(
                "SELECT event_kind,outcome FROM audit_events WHERE event_id=?1",
                [audit_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            settlement_audit,
            (expected_kind.into(), "success".into()),
            "authorization settlement audit must be exact"
        );
    }
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed' WHERE authorization_id='d3677d34-dbe6-4342-9d88-97f6bd957e1b'",
            [],
        ),
        "invalidated authorization cannot consume",
    );

    insert_pending_authorization_with_window(
        &connection,
        "b31a88cf-30d7-4c8b-b5c3-87fb6516b020",
        "revoke",
        2000,
        2300,
    );
    connection.execute(
        "UPDATE n5_trust_authorities SET enabled=0,revoked_at_ms=2200 WHERE authority_id='6033e8e2-c7ba-4100-a75c-dda7de7db8a7'",
        [],
    ).unwrap();
    insert_audit_for_decision(
        &connection,
        "fdcdcaef-dd49-4c09-9830-d8e7c1393382",
        "operator",
        Some("operator-n6"),
        1,
        "authorization",
        "expire",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('3b0b24d6-5401-4e09-b9ef-84e24c6acb18','fdcdcaef-dd49-4c09-9830-d8e7c1393382','authorization','expire',?1,NULL,'b31a88cf-30d7-4c8b-b5c3-87fb6516b020',?2,?3,1,'pending','expired',2,3,2300,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_authorizations SET authorization_state='expired',expired_at_ms=2300,expired_decision_id='3b0b24d6-5401-4e09-b9ef-84e24c6acb18',expired_audit_event_id='fdcdcaef-dd49-4c09-9830-d8e7c1393382' WHERE authorization_id='b31a88cf-30d7-4c8b-b5c3-87fb6516b020'",
        [],
    ).unwrap();
}

#[test]
fn decisions_require_closed_subject_grammar_exact_semantic_audits_and_public_metadata() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-semantic-decision-audits.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);

    let insert_audit = |event_id: &str, event_kind: &str, outcome: &str, metadata_json: &str| {
        connection.execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
             VALUES (?1,'2026-08-08T00:00:00Z',?2,?3,'nodescale',NULL,?4,?5,1,?6)",
            params![event_id, NETWORK, DEVICE, event_kind, outcome, metadata_json],
        )
    };
    let insert_decision = |decision_id: &str,
                           audit_event_id: &str,
                           subject_kind: &str,
                           decision_kind: &str,
                           challenge_id: Option<&str>,
                           authorization_id: Option<&str>| {
        let (prior_state, new_state, prior_revision, new_revision) = match decision_kind {
            "issue" => (None, "pending", None, 1),
            "replay" | "conflict" => (Some("pending"), "pending", Some(1), 1),
            _ => (Some("pending"), "pending", Some(1), 2),
        };
        connection.execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10,?11,?12,?13,2000,'nodescale',NULL,'semantic_audit_test',NULL,NULL,'n6-test-agent')",
            params![decision_id, audit_event_id, subject_kind, decision_kind, BINDING, challenge_id, authorization_id, NETWORK, DEVICE, prior_state, new_state, prior_revision, new_revision],
        )
    };

    insert_audit(
        "0669b041-4566-45c8-bac4-8d7b58afe614",
        "keryx_binding_nonce_issued",
        "success",
        "{}",
    )
    .unwrap();
    assert_rejected(
        insert_decision(
            "a1826bd0-65e8-4fd1-a4d7-9bcc4872a1e1",
            "0669b041-4566-45c8-bac4-8d7b58afe614",
            "binding",
            "issue",
            None,
            None,
        ),
        "cross-subject semantic audit event",
    );

    insert_audit(
        "e86c1d12-d745-44dc-b6cf-efbd8f8a9922",
        "keryx_binding_pending",
        "failed",
        "{}",
    )
    .unwrap();
    assert_rejected(
        insert_decision(
            "bd9cc3c9-d303-446d-a778-41bf50ef0337",
            "e86c1d12-d745-44dc-b6cf-efbd8f8a9922",
            "binding",
            "issue",
            None,
            None,
        ),
        "failed audit cannot be linked to successful issue transition",
    );

    for (audit_id, decision_id, metadata_json) in [
        (
            "46fc83cc-b32b-4081-b02d-c049f719fbfc",
            "fa8096d9-fa0a-44dc-8f69-6447a86609ed",
            "{\"nonce\":\"never-persist\"}",
        ),
        (
            "4b211d2c-8e0e-4f4e-9c7a-42ee671adc1d",
            "96ee80ad-7e5b-457e-bffc-6bbf9afdbbfc",
            "{\"verifier\":\"never-persist\"}",
        ),
        (
            "7489f3ad-af40-446a-ab15-64cc1e5f44aa",
            "ed2a6c18-723e-4f56-ac6a-9c23c4255d60",
            "{\"secret\":\"never-persist\"}",
        ),
    ] {
        insert_audit(audit_id, "keryx_binding_pending", "success", metadata_json).unwrap();
        assert_rejected(
            insert_decision(decision_id, audit_id, "binding", "issue", None, None),
            "semantic audit metadata must not contain nonce, verifier, or secret material",
        );
    }

    for (index, subject_kind, decision_kind, challenge_id, authorization_id) in [
        (0, "binding", "expire", None, None),
        (
            1,
            "challenge",
            "rotate",
            Some("eea44ffd-577c-4322-9d53-d034a4d3a539"),
            None,
        ),
        (
            2,
            "authorization",
            "confirm",
            None,
            Some("9b4ae5bf-5a7f-42e5-b232-fad3e2919675"),
        ),
    ] {
        let audit_id = n6_uuid();
        let decision_id = n6_uuid();
        insert_audit(&audit_id, "keryx_binding_pending", "success", "{}").unwrap();
        assert_rejected(
            insert_decision(
                &decision_id,
                &audit_id,
                subject_kind,
                decision_kind,
                challenge_id,
                authorization_id,
            ),
            &format!("invalid subject/decision combination {index}"),
        );
    }

    insert_audit(
        "5c942af8-e004-458d-90b3-8782edb34bb8",
        "keryx_binding_replay",
        "idempotent",
        "{}",
    )
    .unwrap();
    assert_rejected(
        insert_decision(
            "3d045e2b-cfd4-4bf1-b5a8-9314f5917d4d",
            "5c942af8-e004-458d-90b3-8782edb34bb8",
            "binding",
            "replay",
            None,
            None,
        ),
        "binding replay requires the exact existing binding",
    );
    let binding_replay_audit: (String, String) = connection
        .query_row(
            "SELECT event_kind,outcome FROM audit_events WHERE event_id='5c942af8-e004-458d-90b3-8782edb34bb8'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        binding_replay_audit,
        ("keryx_binding_replay".into(), "idempotent".into()),
        "binding replay decisions require the exact idempotent semantic audit"
    );

    insert_audit(
        "b1ca68cb-2b03-40cf-ae43-849b59f5a925",
        "keryx_binding_conflict",
        "rejected",
        "{}",
    )
    .unwrap();
    assert_rejected(
        insert_decision(
            "008df2fb-1a3f-4e1d-b8c9-bfb23d1996ef",
            "b1ca68cb-2b03-40cf-ae43-849b59f5a925",
            "binding",
            "conflict",
            None,
            None,
        ),
        "binding conflict requires the exact existing binding",
    );
    let conflict_audit: (String, String) = connection
        .query_row(
            "SELECT event_kind,outcome FROM audit_events WHERE event_id='b1ca68cb-2b03-40cf-ae43-849b59f5a925'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        conflict_audit,
        ("keryx_binding_conflict".into(), "rejected".into()),
        "conflict decisions require the exact rejected semantic audit"
    );
    let state_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM n6_binding_records", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state_rows, 0, "conflicts must remain audit-only");

    for (audit_id, event_kind, outcome) in [
        (
            "52fc0bac-5949-41c9-9c20-569f282e95d8",
            "keryx_binding_pending",
            "success",
        ),
        (
            "4eeb20e8-2ceb-4592-93d1-329fc7b63c19",
            "keryx_binding_capability_granted",
            "failed",
        ),
    ] {
        insert_audit(audit_id, event_kind, outcome, "{}").unwrap();
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_authority_capabilities (grant_id,authority_id,capability,issued_by_source,issued_by_id,issued_at_ms,audit_event_id)
                 VALUES (?1,'6033e8e2-c7ba-4100-a75c-dda7de7db8a7','rotate','operator','operator-n6',1000,?2)",
                params![n6_uuid(), audit_id],
            ),
            "capability grant requires exact event kind and success outcome",
        );
    }
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authority_capabilities SET issued_at_ms=1001 WHERE grant_id='9e4c2e7a-cadf-4b41-9fc3-418b8c6072c6'",
            [],
        ),
        "capability grant remains immutable",
    );
}

#[test]
fn n6_authority_use_requires_a_live_matching_owner_root_at_each_boundary() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-owner-root-live.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    seed_n5_confirmed_provenance(&connection);
    activate_seeded_binding(&connection);

    connection.execute(
        "INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
         VALUES ('8fa7cc7d-8c95-4639-91a4-5695c234c7af','55f08bb1-3cc7-42b4-ab1d-1e83d3d155df',?1,'operator','operator-other',2,1000,999999999999,0,0,NULL,1000)",
        [NETWORK],
    ).unwrap();
    connection.execute(
        "UPDATE n5_trust_authorities SET sealed=1,enabled=1 WHERE authority_id='8fa7cc7d-8c95-4639-91a4-5695c234c7af'",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
         VALUES ('1ec78e53-36d3-4bfd-9d7b-2e89c7d8e967','2026-08-08T00:00:00Z',?1,?2,'operator','operator-other','keryx_binding_authority_capability_granted','success',1,'{}')",
        params![NETWORK, DEVICE],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_authority_capabilities (grant_id,authority_id,capability,issued_by_source,issued_by_id,issued_at_ms,audit_event_id)
             VALUES ('2b28e77f-69b1-4b7d-92d7-fd75f3678452','8fa7cc7d-8c95-4639-91a4-5695c234c7af','rotate','operator','operator-other',2000,'1ec78e53-36d3-4bfd-9d7b-2e89c7d8e967')",
            [],
        ),
        "N6 capability grant cannot swap the owner root's principal scope",
    );

    connection.execute(
        "INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms)
         VALUES ('c2f8337c-a7f4-446c-9b01-a9bc8f25021e','55f08bb1-3cc7-42b4-ab1d-1e83d3d155df',?1,'operator','operator-n6',3,1000,999999999999,0,0,NULL,1000)",
        [NETWORK],
    ).unwrap();
    connection.execute(
        "UPDATE n5_trust_authorities SET sealed=1,enabled=1 WHERE authority_id='c2f8337c-a7f4-446c-9b01-a9bc8f25021e'",
        [],
    ).unwrap();
    insert_pending_authorization(
        &connection,
        "a11f1b80-99e3-446c-953d-5480b1eeb7ac",
        "rotate",
    );
    connection.execute(
        "UPDATE n5_owner_trust_roots SET enabled=0,revoked_at_ms=2100 WHERE trust_root_id='55f08bb1-3cc7-42b4-ab1d-1e83d3d155df'",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json)
         VALUES ('6f1f849f-2741-432c-ae34-29b77a34d771','2026-08-08T00:00:00Z',?1,?2,'operator','operator-n6','keryx_binding_authority_capability_granted','success',1,'{}')",
        params![NETWORK, DEVICE],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_authority_capabilities (grant_id,authority_id,capability,issued_by_source,issued_by_id,issued_at_ms,audit_event_id)
             VALUES ('7f070e21-5dc0-43fa-87d4-e630c0d06261','c2f8337c-a7f4-446c-9b01-a9bc8f25021e','rotate','operator','operator-n6',2200,'6f1f849f-2741-432c-ae34-29b77a34d771')",
            [],
        ),
        "revoked owner root cannot grant a new N6 capability through its still-live child authority",
    );
    assert_rejected(
        connection.execute(
            "INSERT INTO n6_binding_authorizations (authorization_id,authority_id,binding_id,network_id,device_id,generation,expected_revision,action_kind,actor_source,actor_id,issued_at_ms,expires_at_ms,authorization_state)
             VALUES ('9f5215b0-ca83-44e9-a47e-89f0bda2c8e9','6033e8e2-c7ba-4100-a75c-dda7de7db8a7',?1,?2,?3,1,2,'revoke','operator','operator-n6',2200,3000,'pending')",
            params![BINDING, NETWORK, DEVICE],
        ),
        "revoked owner root cannot issue an N6 authorization through its still-live child authority",
    );

    insert_audit_for_decision(
        &connection,
        "5eb926da-4ea6-493a-8a12-a98d8cddfe2c",
        "operator",
        Some("operator-n6"),
        1,
        "binding",
        "rotate",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('b04e0b60-518a-44c5-b525-7a69a0bf556a','5eb926da-4ea6-493a-8a12-a98d8cddfe2c','binding','rotate',?1,NULL,'a11f1b80-99e3-446c-953d-5480b1eeb7ac',?2,?3,1,'active','rotated',2,3,2200,'operator','operator-n6','operator_request',?4,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE, PEER],
    ).unwrap();
    assert_rejected(
        connection.execute(
            "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='b04e0b60-518a-44c5-b525-7a69a0bf556a',consumed_audit_event_id='5eb926da-4ea6-493a-8a12-a98d8cddfe2c' WHERE authorization_id='a11f1b80-99e3-446c-953d-5480b1eeb7ac'",
            [],
        ),
        "owner root revoked after issuance cannot consume an N6 authorization",
    );

    insert_audit_for_decision(
        &connection,
        "37b5a02e-72b6-43a1-9e52-2b4acb6e3e3a",
        "operator",
        Some("operator-n6"),
        1,
        "authorization",
        "expire",
    );
    connection.execute(
        "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version)
         VALUES ('3b114bf1-58e1-44f1-bd86-ca77b9f707a2','37b5a02e-72b6-43a1-9e52-2b4acb6e3e3a','authorization','expire',?1,NULL,'a11f1b80-99e3-446c-953d-5480b1eeb7ac',?2,?3,1,'pending','expired',2,3,3000,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent')",
        params![BINDING, NETWORK, DEVICE],
    ).unwrap();
    connection.execute(
        "UPDATE n6_binding_authorizations SET authorization_state='expired',expired_at_ms=3000,expired_decision_id='3b114bf1-58e1-44f1-bd86-ca77b9f707a2',expired_audit_event_id='37b5a02e-72b6-43a1-9e52-2b4acb6e3e3a' WHERE authorization_id='a11f1b80-99e3-446c-953d-5480b1eeb7ac'",
        [],
    ).unwrap();
}

#[test]
fn two_connection_begin_immediate_duplicate_challenge_confirmation_leaves_no_loser_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-two-connection-challenge.db");
    drop(StateStore::open(&path).unwrap());
    let seed = Connection::open(&path).unwrap();
    seed.pragma_update(None, "foreign_keys", true).unwrap();
    seed_n5_confirmed_provenance(&seed);
    insert_pending_binding(&seed);
    let challenge_id = n6_uuid();
    insert_pending_challenge(&seed, &challenge_id, &n6_uuid(), &n6_uuid());
    drop(seed);
    let (winner_audit, winner_decision, loser_audit, loser_decision) =
        (n6_uuid(), n6_uuid(), n6_uuid(), n6_uuid());
    let winner = Connection::open(&path).unwrap();
    let loser = Connection::open(&path).unwrap();
    for connection in [&winner, &loser] {
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
    }
    winner.execute_batch(&format!("BEGIN IMMEDIATE;
        INSERT INTO audit_events VALUES ('{winner_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','nodescale',NULL,'keryx_binding_attempted','success',1,'{{}}');
        INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{winner_decision}','{winner_audit}','challenge','confirm','{BINDING}','{challenge_id}',NULL,'{NETWORK}','{DEVICE}',1,'pending','consumed',1,2,2100,'nodescale',NULL,'challenge_confirmed','{PEER}','race-confirm','n6-test-agent');
        UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=2100,consumed_operation_id='race-confirm',consumed_authenticated_peer_id='{PEER}',last_decision_id='{winner_decision}',last_audit_event_id='{winner_audit}' WHERE challenge_id='{challenge_id}'; COMMIT;")).unwrap();
    assert!(loser.execute_batch(&format!("BEGIN IMMEDIATE;
        INSERT INTO audit_events VALUES ('{loser_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','nodescale',NULL,'keryx_binding_attempted','success',1,'{{}}');
        INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{loser_decision}','{loser_audit}','challenge','confirm','{BINDING}','{challenge_id}',NULL,'{NETWORK}','{DEVICE}',1,'pending','consumed',1,2,2200,'nodescale',NULL,'challenge_confirmed','{PEER}','race-confirm','n6-test-agent');")).is_err());
    loser.execute_batch("ROLLBACK").unwrap();
    let inspect = Connection::open(path).unwrap();
    let loser_evidence: i64 = inspect
        .query_row(
            "SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1",
            [loser_decision],
            |row| row.get(0),
        )
        .unwrap();
    let audit_rows: i64 = inspect
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_id=?1",
            [loser_audit],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((loser_evidence, audit_rows), (0, 0));
    let state: (String, String) = inspect.query_row("SELECT challenge_state,consumed_operation_id FROM n6_binding_challenges WHERE challenge_id=?1", [challenge_id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(state, ("consumed".into(), "race-confirm".into()));
}

#[test]
fn two_connection_begin_immediate_rotate_revoke_loser_leaves_no_success_or_consumption() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-two-connection-rotate-revoke.db");
    drop(StateStore::open(&path).unwrap());
    let seed = Connection::open(&path).unwrap();
    seed.pragma_update(None, "foreign_keys", true).unwrap();
    seed_n5_confirmed_provenance(&seed);
    activate_seeded_binding(&seed);
    let (rotate_auth, revoke_auth) = (n6_uuid(), n6_uuid());
    insert_pending_authorization(&seed, &rotate_auth, "rotate");
    insert_pending_authorization(&seed, &revoke_auth, "revoke");
    drop(seed);
    let (rotate_audit, rotate_decision, revoke_audit, revoke_decision) =
        (n6_uuid(), n6_uuid(), n6_uuid(), n6_uuid());
    let winner = Connection::open(&path).unwrap();
    let loser = Connection::open(&path).unwrap();
    for connection in [&winner, &loser] {
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
    }
    winner.execute_batch(&format!("BEGIN IMMEDIATE;
        INSERT INTO audit_events VALUES ('{rotate_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','operator','operator-n6','keryx_binding_rotated','success',1,'{{}}');
        INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{rotate_decision}','{rotate_audit}','binding','rotate','{BINDING}',NULL,'{rotate_auth}','{NETWORK}','{DEVICE}',1,'active','rotated',2,3,2200,'operator','operator-n6','race_rotate','{PEER}',NULL,'n6-test-agent');
        UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=2200,consumed_decision_id='{rotate_decision}',consumed_audit_event_id='{rotate_audit}' WHERE authorization_id='{rotate_auth}';
        UPDATE n6_binding_records SET binding_state='rotated',revision=3,rotated_at_ms=2200,last_decision_id='{rotate_decision}',last_audit_event_id='{rotate_audit}' WHERE binding_id='{BINDING}'; COMMIT;")).unwrap();
    assert!(loser.execute_batch(&format!("BEGIN IMMEDIATE;
        INSERT INTO audit_events VALUES ('{revoke_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','operator','operator-n6','keryx_binding_revoked','success',1,'{{}}');
        INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{revoke_decision}','{revoke_audit}','binding','revoke','{BINDING}',NULL,'{revoke_auth}','{NETWORK}','{DEVICE}',1,'active','revoked',2,3,2201,'operator','operator-n6','race_revoke','{PEER}',NULL,'n6-test-agent');")).is_err());
    loser.execute_batch("ROLLBACK").unwrap();
    let inspect = Connection::open(path).unwrap();
    let loser_evidence: i64 = inspect
        .query_row(
            "SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1",
            [revoke_decision],
            |row| row.get(0),
        )
        .unwrap();
    let audit_rows: i64 = inspect
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_id=?1",
            [revoke_audit],
            |row| row.get(0),
        )
        .unwrap();
    let revoke_state: String = inspect
        .query_row(
            "SELECT authorization_state FROM n6_binding_authorizations WHERE authorization_id=?1",
            [revoke_auth],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        (loser_evidence, audit_rows, revoke_state),
        (0, 0, "pending".into())
    );
}

#[test]
fn cleanup_decisions_require_exact_live_pending_subjects_and_rollback_loser_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-cleanup-decision-fence.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);
    let challenge_id = n6_uuid();
    insert_pending_challenge(&connection, &challenge_id, &n6_uuid(), &n6_uuid());

    let (premature_audit, premature_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{premature_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','nodescale',NULL,'keryx_binding_nonce_expired','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{premature_decision}','{premature_audit}','challenge','expire','{BINDING}','{challenge_id}',NULL,'{NETWORK}','{DEVICE}',1,'pending','expired',1,2,2999,'nodescale',NULL,'challenge_expired',NULL,NULL,'n6-test-agent');"
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let premature_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![premature_decision, premature_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(premature_evidence, (0, 0));

    let (grammar_audit, grammar_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{grammar_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','nodescale',NULL,'keryx_binding_attempted','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{grammar_decision}','{grammar_audit}','challenge','confirm','{BINDING}','{challenge_id}',NULL,'{NETWORK}','{DEVICE}',1,'pending','active',1,2,2100,'nodescale',NULL,'challenge_confirmed','{PEER}','wrong-confirm-state','n6-test-agent');"
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let grammar_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![grammar_decision, grammar_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(grammar_evidence, (0, 0));

    let (nonexistent_audit, nonexistent_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{nonexistent_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','nodescale',NULL,'keryx_binding_nonce_invalidated','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{nonexistent_decision}','{nonexistent_audit}','challenge','invalidate','{BINDING}','{}',NULL,'{NETWORK}','{DEVICE}',1,'pending','invalidated',1,2,2100,'nodescale',NULL,'challenge_invalidated',NULL,NULL,'n6-test-agent');",
            n6_uuid()
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let nonexistent_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![nonexistent_decision, nonexistent_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(nonexistent_evidence, (0, 0));
}

#[test]
fn authorization_cleanup_requires_live_pending_authorization_and_accepted_actor() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-authorization-cleanup-fence.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    seed_n5_confirmed_provenance(&connection);
    activate_seeded_binding(&connection);
    let authorization_id = n6_uuid();
    insert_pending_authorization(&connection, &authorization_id, "rotate");

    let (premature_audit, premature_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{premature_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','operator','operator-n6','keryx_binding_authorization_expired','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{premature_decision}','{premature_audit}','authorization','expire','{BINDING}',NULL,'{authorization_id}','{NETWORK}','{DEVICE}',1,'pending','expired',2,3,2999,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent');"
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let premature_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![premature_decision, premature_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(premature_evidence, (0, 0));

    let (expiry_audit, expiry_decision) = (n6_uuid(), n6_uuid());
    insert_audit_for_decision(
        &connection,
        &expiry_audit,
        "operator",
        Some("operator-n6"),
        1,
        "authorization",
        "expire",
    );
    connection
        .execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,'authorization','expire',?3,NULL,?4,?5,?6,1,'pending','expired',2,3,3000,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent')",
            params![expiry_decision, expiry_audit, BINDING, authorization_id, NETWORK, DEVICE],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE n6_binding_authorizations SET authorization_state='expired',expired_at_ms=3000,expired_decision_id=?1,expired_audit_event_id=?2 WHERE authorization_id=?3",
            params![expiry_decision, expiry_audit, authorization_id],
        )
        .unwrap();

    let (terminal_audit, terminal_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{terminal_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','operator','operator-n6','keryx_binding_authorization_expired','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{terminal_decision}','{terminal_audit}','authorization','expire','{BINDING}',NULL,'{authorization_id}','{NETWORK}','{DEVICE}',1,'pending','expired',2,3,3001,'operator','operator-n6','authorization_expired',NULL,NULL,'n6-test-agent');"
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let terminal_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![terminal_decision, terminal_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(terminal_evidence, (0, 0));

    let invalidated_authorization = n6_uuid();
    insert_pending_authorization(&connection, &invalidated_authorization, "rotate");
    let (invalid_audit, invalid_decision) = (n6_uuid(), n6_uuid());
    assert!(connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{invalid_audit}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','operator','operator-other','keryx_binding_authorization_invalidated','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{invalid_decision}','{invalid_audit}','authorization','invalidate','{BINDING}',NULL,'{invalidated_authorization}','{NETWORK}','{DEVICE}',1,'pending','invalidated',2,3,2500,'operator','operator-other','authorization_invalidated',NULL,NULL,'n6-test-agent');"
        ))
        .is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let invalid_evidence: (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM n6_binding_decisions WHERE decision_id=?1), (SELECT COUNT(*) FROM audit_events WHERE event_id=?2)",
            params![invalid_decision, invalid_audit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(invalid_evidence, (0, 0));
}

#[test]
fn deferred_decision_subject_cycles_reject_orphans_and_binding_idempotency_phantoms() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-deferred-subject-cycles.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    seed_n5_confirmed_provenance(&connection);

    for (
        subject_kind,
        binding_id,
        challenge_id,
        authorization_id,
        event_kind,
        actor_source,
        actor_id,
        reason,
    ) in [
        (
            "binding",
            n6_uuid(),
            "NULL".to_owned(),
            "NULL".to_owned(),
            "keryx_binding_pending",
            "nodescale",
            "NULL",
            "binding_issued",
        ),
        (
            "challenge",
            BINDING.to_owned(),
            n6_uuid(),
            "NULL".to_owned(),
            "keryx_binding_nonce_issued",
            "nodescale",
            "NULL",
            "challenge_issued",
        ),
        (
            "authorization",
            BINDING.to_owned(),
            "NULL".to_owned(),
            n6_uuid(),
            "keryx_binding_authorization_issued",
            "operator",
            "'operator-n6'",
            "authorization_issued",
        ),
    ] {
        let (audit_id, decision_id) = (n6_uuid(), n6_uuid());
        assert!(connection.execute_batch(&format!(
            "BEGIN IMMEDIATE;
             INSERT INTO audit_events VALUES ('{audit_id}','2026-08-08T00:00:00Z','{NETWORK}','{DEVICE}','{actor_source}',{actor_id},'{event_kind}','success',1,'{{}}');
             INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES ('{decision_id}','{audit_id}','{subject_kind}','issue','{binding_id}',{challenge_id},{authorization_id},'{NETWORK}','{DEVICE}',1,NULL,'pending',NULL,1,2000,'{actor_source}',{actor_id},'{reason}',NULL,NULL,'n6-test-agent');
             COMMIT;"
        )).is_err(), "orphan {subject_kind} issue decision must fail at commit");
        connection.execute_batch("ROLLBACK").unwrap();
    }

    insert_pending_binding(&connection);
    for decision_kind in ["replay", "conflict"] {
        let (audit_id, decision_id) = (n6_uuid(), n6_uuid());
        insert_audit(&connection, &audit_id, "binding", decision_kind);
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,'binding',?3,?4,NULL,NULL,?5,?6,1,'pending','pending',1,1,2001,'nodescale',NULL,'binding_idempotency',NULL,NULL,'n6-test-agent')",
                params![decision_id, audit_id, decision_kind, n6_uuid(), NETWORK, DEVICE, SESSION],
            ),
            "phantom binding replay/conflict",
        );
        let (mismatch_audit, mismatch_decision) = (n6_uuid(), n6_uuid());
        insert_audit_for_decision(
            &connection,
            &mismatch_audit,
            "nodescale",
            None,
            2,
            "binding",
            decision_kind,
        );
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,'binding',?3,?4,NULL,NULL,?5,?6,2,'pending','pending',1,1,2001,'nodescale',NULL,'binding_idempotency',NULL,NULL,'n6-test-agent')",
                params![mismatch_decision, mismatch_audit, decision_kind, BINDING, NETWORK, DEVICE, SESSION],
            ),
            "mismatched binding replay/conflict",
        );
    }
}

#[test]
fn n6_decision_audit_metadata_rejects_decoded_secret_values_under_any_key() {
    const NONCE: &str = "nsbind_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let directory = tempdir().unwrap();
    let path = directory.path().join("n6-audit-secret-values.db");
    drop(StateStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    seed_n5_confirmed_provenance(&connection);
    insert_pending_binding(&connection);
    for metadata_json in [
        serde_json::json!({"correlation": NONCE}).to_string(),
        serde_json::json!({"context": {"items": [VERIFIER]}}).to_string(),
        format!(r#"{{"{NONCE}":"public"}}"#),
        format!(r#"{{"{VERIFIER}":"public"}}"#),
        r#"{"escaped":"nsbind_\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_owned(),
        r#"{"nsbind_\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA":"public"}"#.to_owned(),
    ] {
        let (audit_id, decision_id) = (n6_uuid(), n6_uuid());
        connection.execute(
            "INSERT INTO audit_events VALUES (?1,'2026-08-08T00:00:00Z',?2,?3,'nodescale',NULL,'keryx_binding_replay','idempotent',1,?4)",
            params![audit_id, NETWORK, DEVICE, metadata_json],
        ).unwrap();
        assert_rejected(
            connection.execute(
                "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,'binding','replay',?3,NULL,NULL,?4,?5,1,'pending','pending',1,1,2001,'nodescale',NULL,'binding_replay',NULL,NULL,'n6-test-agent')",
                params![decision_id, audit_id, BINDING, NETWORK, DEVICE, SESSION],
            ),
            "decoded N6 audit secret value",
        );
    }
}
