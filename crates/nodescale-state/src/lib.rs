//! Nodescale-owned SQLite durable state and transactional audit foundation.

use chrono::Utc;
use nodescale_domain::{
    AuditActor, AuditEventId, Device, DeviceGenerations, DeviceId, Generation, Invitation,
    JoinSession, JoinSessionId, JoinSessionState, MembershipState, Network, NetworkId, Revocation,
    RevocationState,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, Transaction, params};
use serde_json::{Map, Value};
use std::{
    cell::{Cell, RefCell},
    path::Path,
};
use thiserror::Error;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;
const INITIAL_MIGRATION: &str = include_str!("../migrations/0001_initial.sql");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failpoint {
    BeforeAuditInsert,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("SQLite state error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("state conflict: {0}")]
    Conflict(String),
    #[error("stale generation: expected {expected}, actual {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("unsupported schema version {found}; maximum supported is {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("audit metadata is unsafe: {0}")]
    UnsafeAuditMetadata(String),
    #[error("injected transaction failure")]
    InjectedFailure,
    #[error("trusted activation remains gated in N0C")]
    ActivationGated,
    #[error("record not found: {0}")]
    NotFound(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedMetadata(Value);
impl SanitizedMetadata {
    pub fn new(value: Value) -> Result<Self, StateError> {
        validate_metadata(&value)?;
        Ok(Self(value))
    }
    #[must_use]
    pub fn empty() -> Self {
        Self(Value::Object(Map::new()))
    }
    fn json(&self) -> Result<String, StateError> {
        Ok(serde_json::to_string(&self.0)?)
    }
}

pub struct StateStore {
    connection: RefCell<Connection>,
    fail_before_audit: Cell<bool>,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, StateError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(connection: Connection) -> Result<Self, StateError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let found =
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?;
        if found > SUPPORTED_SCHEMA_VERSION {
            return Err(StateError::UnsupportedSchema {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        if found == 0 {
            connection.execute_batch("BEGIN IMMEDIATE;")?;
            let migration_result = connection.execute_batch(INITIAL_MIGRATION).and_then(|()| {
                connection.pragma_update(None, "user_version", SUPPORTED_SCHEMA_VERSION)
            });
            match migration_result {
                Ok(()) => connection.execute_batch("COMMIT;")?,
                Err(error) => {
                    let _ = connection.execute_batch("ROLLBACK;");
                    return Err(StateError::Sqlite(error));
                }
            }
        }
        Ok(Self {
            connection: RefCell::new(connection),
            fail_before_audit: Cell::new(false),
        })
    }

    pub fn schema_version(&self) -> Result<u32, StateError> {
        Ok(self
            .connection
            .borrow()
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn audit_event_count(&self) -> Result<u64, StateError> {
        Ok(self
            .connection
            .borrow()
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?)
    }

    pub fn set_failpoint(&self, failpoint: Failpoint, enabled: bool) {
        match failpoint {
            Failpoint::BeforeAuditInsert => self.fail_before_audit.set(enabled),
        }
    }

    pub fn create_network(&self, network: &Network, actor: AuditActor) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let record = serde_json::to_string(network)?;
            tx.execute("INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![network.network_id.to_string(), network.name, lower(network.state.as_str()), format!("{:?}", network.provider_kind).to_lowercase(), network.provider_instance_id.to_string(), to_i64(network.membership_generation)?, to_i64(network.policy_generation)?, record, network.created_at.to_rfc3339(), network.updated_at.to_rfc3339()]).map_err(map_constraint)?;
            tx.execute("INSERT INTO membership_generations (network_id,generation,updated_at) VALUES (?1,?2,?3)", params![network.network_id.to_string(), to_i64(network.membership_generation)?, network.updated_at.to_rfc3339()]).map_err(map_constraint)?;
            store.append_audit(tx, Some(network.network_id), None, actor, "network.created", "success", Some(network.membership_generation), &SanitizedMetadata::empty())
        })
    }

    pub fn create_device(&self, device: &Device, actor: AuditActor) -> Result<(), StateError> {
        if matches!(
            device.membership_state,
            MembershipState::Active | MembershipState::Suspended
        ) {
            return Err(StateError::ActivationGated);
        }
        self.transactional(|tx, store| {
            let (provider_instance, provider_node, provider_key) = device.provider_identity.as_ref().map_or((None,None,None), |identity| (Some(identity.provider_instance_id.to_string()), Some(identity.node_id.to_string()), Some(identity.stable_key_fingerprint.clone())));
            tx.execute("INSERT INTO devices (device_id,network_id,display_name,membership_state,provider_instance_id,provider_node_id,provider_key_fingerprint,credential_generation,keryx_binding_generation,fleet_projection_generation,fleet_projection_status,record_json,created_at,updated_at,revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)", params![device.device_id.to_string(), device.network_id.to_string(), device.display_name, lower(device.membership_state.as_str()), provider_instance, provider_node, provider_key, to_i64(device.generations.credential)?, to_i64(device.generations.keryx_binding)?, to_i64(device.generations.fleet_projection)?, lower(device.fleet_projection_status.as_str()), serde_json::to_string(device)?, device.created_at.to_rfc3339(), device.updated_at.to_rfc3339(), device.revoked_at.map(|value| value.to_rfc3339())]).map_err(map_constraint)?;
            tx.execute("INSERT INTO device_generations (device_id,credential_generation,keryx_binding_generation,fleet_projection_generation,updated_at) VALUES (?1,?2,?3,?4,?5)", params![device.device_id.to_string(), to_i64(device.generations.credential)?, to_i64(device.generations.keryx_binding)?, to_i64(device.generations.fleet_projection)?, device.updated_at.to_rfc3339()]).map_err(map_constraint)?;
            store.append_audit(tx, Some(device.network_id), Some(device.device_id), actor, "device.created", "success", Some(device.generations.credential), &SanitizedMetadata::empty())
        })
    }

    pub fn issue_invitation(
        &self,
        invitation: &Invitation,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            tx.execute("INSERT INTO invitations (invitation_id,network_id,state,secret_verifier,provider_credential_reference,max_uses,used_count,record_json,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![invitation.invitation_id.to_string(), invitation.network_id.to_string(), lower(invitation.state.as_str()), invitation.secret_verifier.as_str(), invitation.provider_credential_reference.map(|id| id.to_string()), i64::from(invitation.max_uses), i64::from(invitation.used_count), serde_json::to_string(invitation)?, invitation.created_at.to_rfc3339(), invitation.expires_at.to_rfc3339()]).map_err(map_constraint)?;
            store.append_audit(tx, Some(invitation.network_id), None, actor, "invitation.issued", "success", None, &SanitizedMetadata::empty())
        })
    }

    pub fn create_join_session(
        &self,
        session: &JoinSession,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            tx.execute("INSERT INTO join_sessions (join_session_id,invitation_id,network_id,device_id,state,record_json,created_at,expires_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![session.join_session_id.to_string(), session.invitation_id.to_string(), session.network_id.to_string(), session.device_id.map(|id| id.to_string()), lower(session.state.as_str()), serde_json::to_string(session)?, session.created_at.to_rfc3339(), session.expires_at.to_rfc3339(), session.updated_at.to_rfc3339()]).map_err(map_constraint)?;
            store.append_audit(tx, Some(session.network_id), session.device_id, actor, "join_session.created", "success", None, &SanitizedMetadata::empty())
        })
    }

    pub fn join_session(&self, join_session_id: JoinSessionId) -> Result<JoinSession, StateError> {
        let record = self
            .connection
            .borrow()
            .query_row(
                "SELECT record_json FROM join_sessions WHERE join_session_id=?1",
                [join_session_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(join_session_id.to_string()))?;
        Ok(serde_json::from_str(&record)?)
    }

    pub fn transition_join_session(
        &self,
        join_session_id: JoinSessionId,
        expected: JoinSessionState,
        next: JoinSessionState,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let record = tx.query_row(
                "SELECT record_json FROM join_sessions WHERE join_session_id=?1",
                [join_session_id.to_string()],
                |row| row.get::<_, String>(0),
            ).optional()?.ok_or_else(|| StateError::NotFound(join_session_id.to_string()))?;
            let mut session: JoinSession = serde_json::from_str(&record)?;
            if session.state != expected {
                return Err(StateError::Conflict("join session state changed concurrently".into()));
            }
            session.transition(next, Utc::now()).map_err(|error| StateError::Conflict(error.to_string()))?;
            let changed = tx.execute(
                "UPDATE join_sessions SET state=?3,record_json=?4,updated_at=?5 WHERE join_session_id=?1 AND state=?2",
                params![join_session_id.to_string(), lower(expected.as_str()), lower(next.as_str()), serde_json::to_string(&session)?, session.updated_at.to_rfc3339()],
            )?;
            if changed == 0 { return Err(StateError::Conflict("join session state changed concurrently".into())); }
            store.append_audit(tx, Some(session.network_id), session.device_id, actor, "join_session.state_changed", "success", None, &SanitizedMetadata::empty())
        })
    }

    pub fn record_revocation(
        &self,
        revocation: &Revocation,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let record = tx
                .query_row(
                    "SELECT record_json FROM devices WHERE device_id=?1 AND network_id=?2",
                    params![revocation.device_id.to_string(), revocation.network_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(revocation.device_id.to_string()))?;
            let mut device: Device = serde_json::from_str(&record)?;
            device.membership_state = device
                .membership_state
                .transition(nodescale_domain::MembershipState::Revoking)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            device.updated_at = revocation.updated_at;
            tx.execute("INSERT INTO revocations (revocation_id,network_id,device_id,state,record_json,requested_at,updated_at,application_trust_removed_at,provider_cleanup_completed_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![revocation.revocation_id.to_string(), revocation.network_id.to_string(), revocation.device_id.to_string(), lower(revocation.state.as_str()), serde_json::to_string(revocation)?, revocation.requested_at.to_rfc3339(), revocation.updated_at.to_rfc3339(), revocation.application_trust_removed_at.map(|value| value.to_rfc3339()), revocation.provider_cleanup_completed_at.map(|value| value.to_rfc3339())]).map_err(map_constraint)?;
            tx.execute("UPDATE devices SET membership_state='revoking', record_json=?2, updated_at=?3 WHERE device_id=?1", params![revocation.device_id.to_string(), serde_json::to_string(&device)?, revocation.updated_at.to_rfc3339()])?;
            store.append_audit(tx, Some(revocation.network_id), Some(revocation.device_id), actor, "revocation.requested", "success", None, &SanitizedMetadata::empty())
        })
    }

    pub fn network(&self, network_id: NetworkId) -> Result<Network, StateError> {
        let record = self
            .connection
            .borrow()
            .query_row(
                "SELECT record_json FROM networks WHERE network_id=?1",
                [network_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(network_id.to_string()))?;
        Ok(serde_json::from_str(&record)?)
    }

    pub fn network_generation(&self, network_id: NetworkId) -> Result<Generation, StateError> {
        let value = self
            .connection
            .borrow()
            .query_row(
                "SELECT generation FROM membership_generations WHERE network_id=?1",
                [network_id.to_string()],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(network_id.to_string()))?;
        Generation::new(value).map_err(|error| StateError::Conflict(error.to_string()))
    }

    pub fn device(&self, device_id: DeviceId) -> Result<Device, StateError> {
        let record = self
            .connection
            .borrow()
            .query_row(
                "SELECT record_json FROM devices WHERE device_id=?1",
                [device_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
        Ok(serde_json::from_str(&record)?)
    }

    pub fn device_generations(&self, device_id: DeviceId) -> Result<DeviceGenerations, StateError> {
        let values = self.connection.borrow().query_row("SELECT credential_generation,keryx_binding_generation,fleet_projection_generation FROM device_generations WHERE device_id=?1", [device_id.to_string()], |row| Ok((row.get::<_,u64>(0)?, row.get::<_,u64>(1)?, row.get::<_,u64>(2)?))).optional()?.ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
        Ok(DeviceGenerations {
            credential: generation(values.0)?,
            keryx_binding: generation(values.1)?,
            fleet_projection: generation(values.2)?,
        })
    }

    pub fn revocation_state(&self, device_id: DeviceId) -> Result<RevocationState, StateError> {
        let value = self
            .connection
            .borrow()
            .query_row(
                "SELECT state FROM revocations WHERE device_id=?1",
                [device_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
        match value.as_str() {
            "requested" => Ok(RevocationState::Requested),
            "applicationtrustremovalpending" => Ok(RevocationState::ApplicationTrustRemovalPending),
            "credentialrevocationpending" => Ok(RevocationState::CredentialRevocationPending),
            "keryxbindingdisablepending" => Ok(RevocationState::KeryxBindingDisablePending),
            "providercleanuppending" => Ok(RevocationState::ProviderCleanupPending),
            "revoked" => Ok(RevocationState::Revoked),
            _ => Err(StateError::Conflict("unknown revocation state".into())),
        }
    }

    pub fn advance_membership_generation(
        &self,
        network_id: NetworkId,
        expected: Generation,
        next: Generation,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        validate_next(expected, next)?;
        self.transactional(|tx, store| {
            let record = tx
                .query_row(
                    "SELECT record_json FROM networks WHERE network_id=?1",
                    [network_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(network_id.to_string()))?;
            let mut network: Network = serde_json::from_str(&record)?;
            if network.membership_generation != expected {
                return Err(StateError::StaleGeneration {
                    expected: expected.get(),
                    actual: network.membership_generation.get(),
                });
            }
            let now = Utc::now();
            network.membership_generation = next;
            network.updated_at = now;
            let changed = tx.execute("UPDATE membership_generations SET generation=?3,updated_at=?4 WHERE network_id=?1 AND generation=?2", params![network_id.to_string(), to_i64(expected)?, to_i64(next)?, now.to_rfc3339()])?;
            if changed == 0 { return Err(stale_network_generation(tx, network_id, expected)?); }
            tx.execute("UPDATE networks SET membership_generation=?2,record_json=?3,updated_at=?4 WHERE network_id=?1", params![network_id.to_string(), to_i64(next)?, serde_json::to_string(&network)?, now.to_rfc3339()])?;
            store.append_audit(tx, Some(network_id), None, actor, "membership.generation.advanced", "success", Some(next), &SanitizedMetadata::empty())
        })
    }

    pub fn advance_device_credential_generation(
        &self,
        device_id: DeviceId,
        expected: Generation,
        next: Generation,
        actor: AuditActor,
    ) -> Result<(), StateError> {
        validate_next(expected, next)?;
        self.transactional(|tx, store| {
            let record = tx
                .query_row(
                    "SELECT record_json FROM devices WHERE device_id=?1",
                    [device_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
            let mut device: Device = serde_json::from_str(&record)?;
            if device.generations.credential != expected {
                return Err(StateError::StaleGeneration {
                    expected: expected.get(),
                    actual: device.generations.credential.get(),
                });
            }
            let network_id = device.network_id;
            let now = Utc::now();
            device.generations.credential = next;
            device.updated_at = now;
            let changed = tx.execute("UPDATE device_generations SET credential_generation=?3,updated_at=?4 WHERE device_id=?1 AND credential_generation=?2", params![device_id.to_string(), to_i64(expected)?, to_i64(next)?, now.to_rfc3339()])?;
            if changed == 0 {
                let actual = tx.query_row("SELECT credential_generation FROM device_generations WHERE device_id=?1", [device_id.to_string()], |row| row.get::<_,u64>(0)).optional()?.ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
                return Err(StateError::StaleGeneration { expected: expected.get(), actual });
            }
            tx.execute("UPDATE devices SET credential_generation=?2,record_json=?3,updated_at=?4 WHERE device_id=?1", params![device_id.to_string(), to_i64(next)?, serde_json::to_string(&device)?, now.to_rfc3339()])?;
            store.append_audit(tx, Some(network_id), Some(device_id), actor, "device.credential_generation.advanced", "success", Some(next), &SanitizedMetadata::empty())
        })
    }

    pub fn database_text_dump_for_test(&self) -> Result<String, StateError> {
        let connection = self.connection.borrow();
        let mut output = String::new();
        for query in [
            "SELECT record_json || secret_verifier FROM invitations",
            "SELECT record_json || display_name || COALESCE(provider_key_fingerprint,'') FROM devices",
            "SELECT metadata_json || event_kind || actor_source || COALESCE(actor_id,'') FROM audit_events",
        ] {
            let mut statement = connection.prepare(query)?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                output.push_str(&row?);
            }
        }
        Ok(output)
    }

    fn transactional<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>, &Self) -> Result<T, StateError>,
    ) -> Result<T, StateError> {
        let mut connection = self.connection.borrow_mut();
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        match operation(&tx, self) {
            Ok(value) => {
                tx.commit()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn append_audit(
        &self,
        tx: &Transaction<'_>,
        network_id: Option<NetworkId>,
        device_id: Option<DeviceId>,
        actor: AuditActor,
        kind: &str,
        outcome: &str,
        generation: Option<Generation>,
        metadata: &SanitizedMetadata,
    ) -> Result<(), StateError> {
        if self.fail_before_audit.get() {
            return Err(StateError::InjectedFailure);
        }
        tx.execute("INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![AuditEventId::new().to_string(), Utc::now().to_rfc3339(), network_id.map(|id| id.to_string()), device_id.map(|id| id.to_string()), actor.source, actor.actor_id, kind, outcome, generation.map(to_i64).transpose()?, metadata.json()?])?;
        Ok(())
    }
}

fn validate_next(expected: Generation, next: Generation) -> Result<(), StateError> {
    if next.get() <= expected.get() {
        return Err(StateError::Conflict(
            "generation must advance monotonically".into(),
        ));
    }
    Ok(())
}

fn stale_network_generation(
    tx: &Transaction<'_>,
    network_id: NetworkId,
    expected: Generation,
) -> Result<StateError, StateError> {
    let actual = tx
        .query_row(
            "SELECT generation FROM membership_generations WHERE network_id=?1",
            [network_id.to_string()],
            |row| row.get::<_, u64>(0),
        )
        .optional()?
        .ok_or_else(|| StateError::NotFound(network_id.to_string()))?;
    Ok(StateError::StaleGeneration {
        expected: expected.get(),
        actual,
    })
}

fn generation(value: u64) -> Result<Generation, StateError> {
    Generation::new(value).map_err(|error| StateError::Conflict(error.to_string()))
}
fn to_i64(value: Generation) -> Result<i64, StateError> {
    i64::try_from(value.get())
        .map_err(|_| StateError::Conflict("generation exceeds SQLite integer range".into()))
}
fn lower(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn map_constraint(error: rusqlite::Error) -> StateError {
    if matches!(&error, rusqlite::Error::SqliteFailure(details, _) if details.code == ErrorCode::ConstraintViolation)
    {
        StateError::Conflict(error.to_string())
    } else {
        StateError::Sqlite(error)
    }
}

fn validate_metadata(value: &Value) -> Result<(), StateError> {
    const BANNED_KEYS: &[&str] = &[
        "secret",
        "token",
        "password",
        "credential",
        "api_key",
        "private_key",
        "nonce",
    ];
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let normalized = key.to_ascii_lowercase();
                if BANNED_KEYS.iter().any(|banned| normalized.contains(banned)) {
                    return Err(StateError::UnsafeAuditMetadata(key.clone()));
                }
                validate_metadata(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                validate_metadata(nested)?;
            }
        }
        Value::String(value) if value.len() > 1024 => {
            return Err(StateError::UnsafeAuditMetadata("oversized string".into()));
        }
        _ => {}
    }
    Ok(())
}
