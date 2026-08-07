use nodescale_domain::{InvitationId, NetworkId};
use nodescale_state::{SUPPORTED_SCHEMA_VERSION, StateError, StateStore};
use tempfile::tempdir;

#[test]
fn v3_legacy_invitation_survives_upgrade_but_is_not_n4_visible_or_redeemable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy-v3.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../migrations/0002_discovery_reconciliation.sql"
        ))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../migrations/0003_mutation_authorization.sql"
        ))
        .unwrap();
    let invitation_id = InvitationId::new();
    let network_id = NetworkId::new();
    let provider_instance_id = nodescale_domain::ProviderInstanceId::new();
    connection.execute(
        "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at) VALUES (?1,'legacy','creating','headscale',?2,1,1,'{}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        rusqlite::params![network_id.to_string(), provider_instance_id.to_string()],
    ).unwrap();
    connection
        .execute(
            "INSERT INTO invitations (invitation_id,network_id,state,secret_verifier,provider_credential_reference,max_uses,used_count,record_json,created_at,expires_at) VALUES (?1,?2,'issued','legacy-verifier',NULL,1,0,'{}','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')",
            rusqlite::params![invitation_id.to_string(), network_id.to_string()],
        )
        .unwrap();
    connection
        .pragma_update(None, "user_version", 3_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    assert!(store.list_n4_invitations(network_id).unwrap().is_empty());
    assert!(matches!(
        store.n4_invitation_candidate(invitation_id),
        Err(StateError::NotFound(_))
    ));
    assert_eq!(store.device_count(network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network_id).unwrap(), 0);
}

#[test]
fn future_schema_is_rejected_without_mutating_the_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("future.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", SUPPORTED_SCHEMA_VERSION + 1)
        .unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&path),
        Err(StateError::UnsupportedSchema { .. })
    ));
}

#[test]
fn every_predecessor_schema_reaches_v4_with_integrity_intact() {
    for predecessor in 1_u32..=3 {
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("v{predecessor}.db"));
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        if predecessor >= 2 {
            connection
                .execute_batch(include_str!(
                    "../migrations/0002_discovery_reconciliation.sql"
                ))
                .unwrap();
        }
        if predecessor >= 3 {
            connection
                .execute_batch(include_str!(
                    "../migrations/0003_mutation_authorization.sql"
                ))
                .unwrap();
        }
        connection
            .pragma_update(None, "user_version", predecessor)
            .unwrap();
        drop(connection);
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        drop(store);
        let check = rusqlite::Connection::open(path).unwrap();
        let integrity: String = check
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let foreign_key_rows: u64 = check
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_rows, 0);
    }
}
