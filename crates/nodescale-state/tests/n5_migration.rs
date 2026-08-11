use nodescale_state::{SUPPORTED_SCHEMA_VERSION, StateStore};
use tempfile::tempdir;

const MIGRATIONS: [&str; 4] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_discovery_reconciliation.sql"),
    include_str!("../migrations/0003_mutation_authorization.sql"),
    include_str!("../migrations/0004_invitation_lifecycle.sql"),
];

#[test]
fn fresh_schema_has_n5_tables_and_no_implicit_trust() {
    let store = StateStore::open_in_memory().unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);

    let directory = tempdir().unwrap();
    let path = directory.path().join("fresh.db");
    drop(StateStore::open(&path).unwrap());
    let connection = rusqlite::Connection::open(path).unwrap();
    for table in [
        "n5_device_identities",
        "n5_provider_bindings",
        "n5_trust_authorities",
        "n5_trust_authority_capabilities",
        "n5_device_trust_state",
        "n5_trust_authorizations",
        "n5_trust_decisions",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing N5 table {table}");
    }
    let trusted: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM n5_device_trust_state WHERE trust_state='trusted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(trusted, 0);
}

#[test]
fn every_supported_predecessor_upgrades_to_v7_atomically() {
    for predecessor in 1_u32..=4 {
        let directory = tempdir().unwrap();
        let path = directory.path().join(format!("v{predecessor}.db"));
        let connection = rusqlite::Connection::open(&path).unwrap();
        for migration in MIGRATIONS.iter().take(predecessor as usize) {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .pragma_update(None, "user_version", predecessor)
            .unwrap();
        drop(connection);

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
        drop(store);

        let connection = rusqlite::Connection::open(path).unwrap();
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let foreign_key_errors: u64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);
    }
}
