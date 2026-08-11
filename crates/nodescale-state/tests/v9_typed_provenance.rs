use nodescale_state::{SUPPORTED_SCHEMA_VERSION, StateStore};
use rusqlite::{Connection, params};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

const V8_MIGRATIONS: [&str; 8] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_discovery_reconciliation.sql"),
    include_str!("../migrations/0003_mutation_authorization.sql"),
    include_str!("../migrations/0004_invitation_lifecycle.sql"),
    include_str!("../migrations/0005_device_trust.sql"),
    include_str!("../migrations/0006_keryx_identity_binding.sql"),
    include_str!("../migrations/0007_fleet_projection.sql"),
    include_str!("../migrations/0008_existing_device_adoption_state.sql"),
];
const V9_MIGRATION: &str = include_str!("../migrations/0009_typed_n5_provenance.sql");

fn column_names(connection: &Connection, table: &str) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
        ))
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn n7_schema(connection: &Connection) -> Vec<(String, String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,sql FROM sqlite_schema
             WHERE (name LIKE 'n7_%' OR tbl_name LIKE 'n7_%')
               AND sql IS NOT NULL
             ORDER BY type,name",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn v8_opens_through_v10_without_rewriting_n7_schema_or_allowing_partial_adoption_rows() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("v9-typed-provenance.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in V8_MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .pragma_update(None, "user_version", 8_u32)
        .unwrap();
    let n7_before = n7_schema(&connection);
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(SUPPORTED_SCHEMA_VERSION, 10);
    assert_eq!(store.schema_version().unwrap(), 10);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    assert_eq!(n7_schema(&connection), n7_before);

    let identities = column_names(&connection, "n5_device_identities");
    for column in [
        "identity_origin_kind",
        "identity_origin_id",
        "n4_origin_id",
        "adoption_origin_id",
    ] {
        assert!(identities.iter().any(|value| value == column));
    }
    assert!(
        !identities
            .iter()
            .any(|value| value == "origin_join_session_id")
    );

    for table in [
        "n5_n4_identity_origins",
        "n5_existing_adoption_identity_origins",
        "n5_n4_provider_binding_provenance",
        "n5_existing_adoption_provider_binding_provenance",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing typed provenance subtype {table}");
    }

    let bindings = column_names(&connection, "n5_provider_bindings");
    for column in [
        "provenance_kind",
        "n4_provenance_binding_id",
        "adoption_provenance_binding_id",
    ] {
        assert!(bindings.iter().any(|value| value == column));
    }
    for removed in [
        "join_session_id",
        "credential_id",
        "provider_credential_reference",
    ] {
        assert!(!bindings.iter().any(|value| value == removed));
    }

    let records = column_names(&connection, "n6_binding_records");
    assert!(
        records
            .iter()
            .any(|value| value == "n5_provider_binding_id")
    );
    assert!(!records.iter().any(|value| value == "join_session_id"));
    for table in [
        "n6_binding_decisions",
        "n6_binding_challenges",
        "n6_binding_authorizations",
        "n6_challenge_reservations",
    ] {
        assert!(
            !column_names(&connection, table)
                .iter()
                .any(|value| value == "join_session_id")
        );
    }

    assert!(
        connection
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    for (table, required_column) in [
        ("n5_existing_adoption_identity_origins", "origin_kind"),
        (
            "n5_existing_adoption_provider_binding_provenance",
            "provenance_kind",
        ),
    ] {
        let error = connection
            .execute(&format!("INSERT INTO {table} DEFAULT VALUES"), [])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("NOT NULL constraint failed") && error.contains(required_column),
            "partial adoption provenance was not rejected by typed requirements: {error}"
        );
    }
}

fn create_v8(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for migration in V8_MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .pragma_update(None, "user_version", 8_u32)
        .unwrap();
}

#[test]
fn two_v8_openers_serialize_one_v9_migration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("two-openers.db");
    create_v8(&path);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let store = StateStore::open(path).unwrap();
            assert_eq!(store.schema_version().unwrap(), 10);
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }
    let connection = Connection::open(path).unwrap();
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
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn v9_transaction_rollback_and_failed_open_leave_exact_v8_and_no_temp_residue() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rollback.db");
    create_v8(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA defer_foreign_keys=ON;")
        .unwrap();
    connection.execute_batch(V9_MIGRATION).unwrap();
    connection.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        8
    );
    assert!(
        column_names(&connection, "n5_device_identities")
            .contains(&"origin_join_session_id".into())
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='n5_n4_identity_origins')",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
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
    connection
        .execute_batch("CREATE TABLE n5_n4_identity_origins(blocker INTEGER);")
        .unwrap();
    drop(connection);
    assert!(StateStore::open(&path).is_err());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        8
    );
    assert!(
        column_names(&connection, "n5_device_identities")
            .contains(&"origin_join_session_id".into())
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
    connection
        .execute_batch("DROP TABLE n5_n4_identity_origins;")
        .unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), 10);
}

#[test]
fn v9_crash_child_aborts_after_rebuild_before_marker() {
    let Ok(path) = std::env::var("NODESCALE_V9_CRASH_DATABASE") else {
        return;
    };
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA defer_foreign_keys=ON;")
        .unwrap();
    connection.execute_batch(V9_MIGRATION).unwrap();
    std::process::abort();
}

#[test]
fn process_crash_before_v9_marker_restores_exact_v8_and_retry_succeeds() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("crash.db");
    create_v8(&path);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v9_crash_child_aborts_after_rebuild_before_marker",
            "--nocapture",
        ])
        .env("NODESCALE_V9_CRASH_DATABASE", &path)
        .output()
        .unwrap();
    assert!(!output.status.success());

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .unwrap(),
        8
    );
    assert!(
        column_names(&connection, "n5_device_identities")
            .contains(&"origin_join_session_id".into())
    );
    assert!(column_names(&connection, "n6_binding_records").contains(&"join_session_id".into()));
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), 10);
    drop(store);
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE 'stage_%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}
