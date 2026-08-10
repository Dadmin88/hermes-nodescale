use super::*;
use nodescale_domain::{
    Generation, KeryxBindingId, KeryxPeerId, OperationId, ProjectionStatus,
    n7::{FleetGeneratedGrants, N6ActiveBindingProvenance, N7FleetDesiredProjection},
};
use rusqlite::{OptionalExtension, Transaction, params};

/// Exact authenticated N6 evidence that authorizes one Fleet projection.
/// It is persisted with the projection rather than looked up later by peer alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N7BindingProvenance {
    pub binding_id: String,
    pub authenticated_peer_id: String,
    pub binding_generation: Generation,
}
impl N7BindingProvenance {
    pub fn new(
        binding_id: impl Into<String>,
        authenticated_peer_id: impl Into<String>,
        binding_generation: Generation,
    ) -> Result<Self, StateError> {
        let binding_id = binding_id.into();
        let authenticated_peer_id = authenticated_peer_id.into();
        if !safe_identifier(&binding_id) || !safe_identifier(&authenticated_peer_id) {
            return Err(StateError::Conflict(
                "N7 binding provenance identifiers are invalid".into(),
            ));
        }
        Ok(Self {
            binding_id,
            authenticated_peer_id,
            binding_generation,
        })
    }
}

/// A durable N7 submission. The complete JSON body, its SHA-256 fingerprint,
/// and the exact active N6 binding are atomically recorded before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N7ProjectionSubmission {
    pub operation_id: OperationId,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub generation: Generation,
    pub desired_body: Vec<u8>,
    pub desired_hash: String,
    pub binding: N7BindingProvenance,
}
impl N7ProjectionSubmission {
    #[allow(clippy::too_many_arguments)]
    pub fn from_canonical(
        operation_id: OperationId,
        network_id: NetworkId,
        device_id: DeviceId,
        generation: Generation,
        desired_body: Vec<u8>,
        binding_id: impl Into<String>,
        authenticated_peer_id: impl Into<String>,
        binding_generation: Generation,
    ) -> Result<Self, StateError> {
        let canonical = canonical_json_bytes(&desired_body)?;
        if canonical != desired_body {
            return Err(StateError::Conflict(
                "N7 desired projection body must be canonical JSON bytes".into(),
            ));
        }
        let binding =
            N7BindingProvenance::new(binding_id, authenticated_peer_id, binding_generation)?;
        Ok(Self {
            operation_id,
            network_id,
            device_id,
            generation,
            desired_hash: sha256_fingerprint(&desired_body),
            desired_body,
            binding,
        })
    }
}

/// An authoritative inspection is deliberately three-valued. A missing record
/// or unavailable authority is not evidence that a previously attempted apply
/// conflicted, so recovery remains retriable and non-terminal in either case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N7AuthoritativeInspection {
    Observed { body: Vec<u8>, hash: String },
    Missing,
    Unavailable,
}
impl N7AuthoritativeInspection {
    pub fn observed(body: Vec<u8>) -> Result<Self, StateError> {
        let canonical = canonical_json_bytes(&body)?;
        if canonical != body {
            return Err(StateError::Conflict(
                "N7 authoritative inspection body must be canonical JSON bytes".into(),
            ));
        }
        Ok(Self::Observed {
            hash: sha256_fingerprint(&body),
            body,
        })
    }

    #[must_use]
    pub const fn missing() -> Self {
        Self::Missing
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum N7ProjectionState {
    Desired,
    Attempted,
    Applied,
    Conflict,
}
impl N7ProjectionState {
    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "desired" => Ok(Self::Desired),
            "attempted" => Ok(Self::Attempted),
            "applied" => Ok(Self::Applied),
            "conflict" => Ok(Self::Conflict),
            _ => Err(StateError::Conflict("unknown N7 projection state".into())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N7ProjectionView {
    pub projection_id: String,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub generation: Generation,
    pub desired_body: Vec<u8>,
    pub desired_hash: String,
    pub binding: N7BindingProvenance,
    pub revision: u64,
    pub state: N7ProjectionState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N7ProjectionReservationOutcome {
    Reserved(N7ProjectionView),
    Replayed(N7ProjectionView),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N7ProjectionAttemptOutcome {
    Recorded(N7ProjectionView),
    Replayed(N7ProjectionView),
}

impl StateStore {
    /// Reconstruct bounded canonical N7 desired projections exclusively from
    /// state-owned active device and authenticated N6 binding rows.
    pub fn n7_runtime_desired_projections(
        &self,
        network_id: NetworkId,
    ) -> Result<Vec<N7FleetDesiredProjection>, StateError> {
        let connection = self.connection.borrow();
        let network_record = connection
            .query_row(
                "SELECT record_json FROM networks WHERE network_id=?1",
                [network_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(network_id.to_string()))?;
        let network: Network = serde_json::from_str(&network_record)?;
        let mut statement = connection.prepare(
            "SELECT d.record_json,b.binding_id,b.verified_peer_id,b.generation
             FROM devices d
             JOIN n6_binding_records b
               ON b.network_id=d.network_id AND b.device_id=d.device_id
             WHERE d.network_id=?1
               AND d.membership_state='active'
               AND d.revoked_at IS NULL
               AND b.binding_state='active'
               AND b.verified_peer_id IS NOT NULL
             ORDER BY d.device_id
             LIMIT 257",
        )?;
        let rows = statement.query_map([network_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        let mut desired = Vec::new();
        for row in rows {
            let (device_record, binding_id, peer_id, binding_generation) = row?;
            if desired.len() == 256 {
                return Err(StateError::Conflict(
                    "N7 runtime desired projection bound exceeded".into(),
                ));
            }
            let device: Device = serde_json::from_str(&device_record)?;
            let binding_id = KeryxBindingId::parse(&binding_id)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let peer_id = KeryxPeerId::parse(peer_id)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let binding_generation = Generation::new(binding_generation)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let provenance = N6ActiveBindingProvenance::from_verified_active_runtime_row(
                network_id,
                device.device_id,
                binding_id,
                peer_id,
                binding_generation,
            )
            .map_err(|error| StateError::Conflict(error.to_string()))?;
            let grants = FleetGeneratedGrants::new(network.baseline_operations.iter().copied())
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            desired.push(
                N7FleetDesiredProjection::upsert_from_active_n6_provenance(
                    network_id,
                    device.device_id,
                    device.display_name,
                    device.membership_state,
                    network.membership_generation,
                    device.generations.fleet_projection,
                    provenance,
                    device.roles,
                    grants,
                )
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            );
        }
        Ok(desired)
    }

    /// Persists desired bytes and exact N6 binding provenance before any adapter
    /// dispatch. Reuse of an operation ID is valid only for the exact full tuple.
    pub fn reserve_n7_projection(
        &self,
        submission: &N7ProjectionSubmission,
        now: DateTime<Utc>,
    ) -> Result<N7ProjectionReservationOutcome, StateError> {
        self.transactional(|tx, store| {
            if let Some(projection_id) = store.n7_matching_operation_tx(tx, submission)? {
                return Ok(N7ProjectionReservationOutcome::Replayed(
                    store.n7_projection_view_tx(tx, &projection_id)?,
                ));
            }
            if store.n7_operation_exists_tx(tx, &submission.operation_id)? {
                return Ok(N7ProjectionReservationOutcome::Conflict);
            }

            if let Some(projection_id) = tx
                .query_row(
                    "SELECT projection_id FROM n7_fleet_projection_records WHERE device_id=?1 AND generation=?2",
                    params![submission.device_id.to_string(), submission.generation.get()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                let view = store.n7_projection_view_tx(tx, &projection_id)?;
                if view.network_id != submission.network_id
                    || view.desired_hash != submission.desired_hash
                    || view.desired_body != submission.desired_body
                    || view.binding != submission.binding
                {
                    return Ok(N7ProjectionReservationOutcome::Conflict);
                }
                store.n7_insert_operation_tx(tx, &projection_id, submission, now)?;
                return Ok(N7ProjectionReservationOutcome::Replayed(view));
            }

            let actual_generation = tx
                .query_row(
                    "SELECT fleet_projection_generation FROM device_generations WHERE device_id=?1",
                    [submission.device_id.to_string()],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(submission.device_id.to_string()))?;
            if actual_generation != submission.generation.get() {
                return Err(StateError::StaleGeneration {
                    expected: submission.generation.get(),
                    actual: actual_generation,
                });
            }
            let device_network = tx.query_row(
                "SELECT network_id FROM devices WHERE device_id=?1",
                [submission.device_id.to_string()],
                |row| row.get::<_, String>(0),
            )?;
            if device_network != submission.network_id.to_string()
                || !store.n7_binding_is_active_tx(tx, submission.network_id, submission.device_id, &submission.binding)?
            {
                return Ok(N7ProjectionReservationOutcome::Conflict);
            }

            let projection_id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO n7_fleet_projection_records (projection_id,network_id,device_id,generation,desired_body,desired_hash,binding_id,authenticated_peer_id,binding_generation,projection_state,revision,persisted_at_ms,attempted_at_ms,applied_at_ms,conflict_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'desired',1,?10,NULL,NULL,NULL)",
                params![projection_id, submission.network_id.to_string(), submission.device_id.to_string(), submission.generation.get(), submission.desired_body, submission.desired_hash, submission.binding.binding_id, submission.binding.authenticated_peer_id, submission.binding.binding_generation.get(), now.timestamp_millis()],
            )?;
            store.n7_insert_operation_tx(tx, &projection_id, submission, now)?;
            store.n7_set_device_status(tx, submission.device_id, ProjectionStatus::Pending, now)?;
            store.append_n7_projection_audit(tx, &projection_id, submission.operation_id.as_str(), submission.network_id, submission.device_id, submission.generation, 1, "projection_desired", now)?;
            store.n7_advance_fleet_projection_generation_tx(
                tx,
                submission.device_id,
                submission.generation,
                now,
            )?;
            Ok(N7ProjectionReservationOutcome::Reserved(store.n7_projection_view_tx(tx, &projection_id)?))
        })
    }

    /// Records local attempted evidence immediately before dispatch. It rechecks
    /// that the *same* N6 binding remains active, rather than accepting a peer-only lookup.
    pub fn record_n7_projection_dispatch_attempt(
        &self,
        operation_id: &OperationId,
        device_id: DeviceId,
        generation: Generation,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<N7ProjectionAttemptOutcome, StateError> {
        self.transactional(|tx, store| {
            let projection_id = store.n7_operation_projection_tx(tx, operation_id, device_id, generation)?;
            let view = store.n7_projection_view_tx(tx, &projection_id)?;
            if view.revision != expected_revision {
                return Err(stale_revision(expected_revision, view.revision));
            }
            match view.state {
                N7ProjectionState::Desired => {
                    if !store.n7_binding_is_active_tx(tx, view.network_id, device_id, &view.binding)? {
                        return Err(StateError::Conflict("N7 binding provenance is no longer active".into()));
                    }
                    let attempt_id = uuid::Uuid::new_v4().to_string();
                    if tx.execute(
                        "INSERT INTO n7_fleet_projection_attempts (attempt_id,projection_id,operation_id,attempt_number,expected_revision,attempted_at_ms) VALUES (?1,?2,?3,1,?4,?5)",
                        params![attempt_id, projection_id, operation_id.as_str(), expected_revision, now.timestamp_millis()],
                    )? != 1 {
                        return Err(stale_revision(expected_revision, store.n7_projection_view_tx(tx, &projection_id)?.revision));
                    }
                    tx.execute(
                        "UPDATE n7_fleet_projection_records SET projection_state='attempted',revision=2,current_attempt_id=?1,attempted_at_ms=?2 WHERE projection_id=?3 AND projection_state='desired' AND revision=?4",
                        params![attempt_id, now.timestamp_millis(), projection_id, expected_revision],
                    )?;
                    store.append_n7_projection_audit(tx, &projection_id, operation_id.as_str(), view.network_id, device_id, generation, 2, "projection_attempted", now)?;
                    Ok(N7ProjectionAttemptOutcome::Recorded(store.n7_projection_view_tx(tx, &projection_id)?))
                }
                N7ProjectionState::Attempted => {
                    let next_attempt = store.n7_next_attempt_number_tx(tx, &projection_id)?;
                    let attempt_id = uuid::Uuid::new_v4().to_string();
                    tx.execute(
                        "INSERT INTO n7_fleet_projection_attempts (attempt_id,projection_id,operation_id,attempt_number,expected_revision,attempted_at_ms) VALUES (?1,?2,?3,?4,?5,?6)",
                        params![attempt_id, projection_id, operation_id.as_str(), next_attempt, expected_revision, now.timestamp_millis()],
                    )?;
                    if tx.execute(
                        "UPDATE n7_fleet_projection_records SET current_attempt_id=?1 WHERE projection_id=?2 AND projection_state='attempted' AND revision=?3",
                        params![attempt_id, projection_id, expected_revision],
                    )? != 1 {
                        return Err(stale_revision(expected_revision, store.n7_projection_view_tx(tx, &projection_id)?.revision));
                    }
                    store.append_n7_projection_audit(tx, &projection_id, operation_id.as_str(), view.network_id, device_id, generation, 2, "projection_attempted", now)?;
                    Ok(N7ProjectionAttemptOutcome::Recorded(store.n7_projection_view_tx(tx, &projection_id)?))
                }
                _ => Ok(N7ProjectionAttemptOutcome::Replayed(view)),
            }
        })
    }

    /// Recover only from an authoritative inspection. Missing or unavailable is
    /// recorded as immutable inspection evidence but intentionally leaves the
    /// desired/attempted state non-terminal, so a later authority read may retry.
    pub fn recover_n7_projection_from_inspection(
        &self,
        operation_id: &OperationId,
        device_id: DeviceId,
        generation: Generation,
        expected_revision: u64,
        inspection: N7AuthoritativeInspection,
        now: DateTime<Utc>,
    ) -> Result<N7ProjectionView, StateError> {
        self.transactional(|tx, store| {
            let projection_id = store.n7_operation_projection_tx(tx, operation_id, device_id, generation)?;
            let view = store.n7_projection_view_tx(tx, &projection_id)?;
            if view.revision != expected_revision {
                return Err(stale_revision(expected_revision, view.revision));
            }
            if matches!(view.state, N7ProjectionState::Applied | N7ProjectionState::Conflict) {
                return Ok(view);
            }
            if view.state != N7ProjectionState::Attempted {
                return Err(StateError::Conflict("N7 inspection recovery requires a persisted dispatch attempt".into()));
            }
            let attempt_id = store.n7_current_attempt_id_tx(tx, &projection_id)?;

            let (kind, observed_body, observed_hash) = match inspection {
                N7AuthoritativeInspection::Unavailable => ("unavailable", None, None),
                N7AuthoritativeInspection::Missing => ("missing", None, None),
                N7AuthoritativeInspection::Observed { body, hash } => ("observed", Some(body), Some(hash)),
            };
            tx.execute(
                "INSERT INTO n7_fleet_projection_inspections (inspection_id,projection_id,operation_id,attempt_id,expected_revision,inspection_kind,observed_body,observed_hash,inspected_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![uuid::Uuid::new_v4().to_string(), projection_id, operation_id.as_str(), attempt_id, expected_revision, kind, observed_body, observed_hash, now.timestamp_millis()],
            )?;
            if kind != "observed" {
                return Ok(view);
            }
            let observed_body = tx.query_row(
                "SELECT observed_body FROM n7_fleet_projection_inspections WHERE projection_id=?1 AND attempt_id=?2 ORDER BY inspected_at_ms DESC, rowid DESC LIMIT 1",
                params![projection_id, attempt_id],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            let observed_hash = sha256_fingerprint(&observed_body);
            let (next_state, next_status, event_kind, timestamp_column) = if observed_hash == view.desired_hash && observed_body == view.desired_body {
                ("applied", ProjectionStatus::Applied, "projection_applied", "applied_at_ms")
            } else {
                ("conflict", ProjectionStatus::Conflict, "projection_conflict", "conflict_at_ms")
            };
            let sql = format!("UPDATE n7_fleet_projection_records SET projection_state=?1,revision=3,{timestamp_column}=?2 WHERE projection_id=?3 AND projection_state='attempted' AND revision=?4");
            if tx.execute(&sql, params![next_state, now.timestamp_millis(), projection_id, expected_revision])? != 1 {
                return Err(stale_revision(expected_revision, store.n7_projection_view_tx(tx, &projection_id)?.revision));
            }
            store.n7_set_device_status(tx, device_id, next_status, now)?;
            store.append_n7_projection_audit(tx, &projection_id, operation_id.as_str(), view.network_id, device_id, generation, 3, event_kind, now)?;
            store.n7_projection_view_tx(tx, &projection_id)
        })
    }

    fn n7_matching_operation_tx(
        &self,
        tx: &Transaction<'_>,
        submission: &N7ProjectionSubmission,
    ) -> Result<Option<String>, StateError> {
        tx.query_row(
            "SELECT projection_id FROM n7_fleet_projection_operations WHERE operation_id=?1 AND network_id=?2 AND device_id=?3 AND generation=?4 AND desired_body=?5 AND desired_hash=?6 AND binding_id=?7 AND authenticated_peer_id=?8 AND binding_generation=?9",
            params![submission.operation_id.as_str(), submission.network_id.to_string(), submission.device_id.to_string(), submission.generation.get(), submission.desired_body, submission.desired_hash, submission.binding.binding_id, submission.binding.authenticated_peer_id, submission.binding.binding_generation.get()],
            |row| row.get(0),
        ).optional().map_err(StateError::from)
    }

    fn n7_operation_exists_tx(
        &self,
        tx: &Transaction<'_>,
        operation_id: &OperationId,
    ) -> Result<bool, StateError> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM n7_fleet_projection_operations WHERE operation_id=?1)",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(StateError::from)
    }

    fn n7_insert_operation_tx(
        &self,
        tx: &Transaction<'_>,
        projection_id: &str,
        submission: &N7ProjectionSubmission,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        tx.execute(
            "INSERT INTO n7_fleet_projection_operations (operation_id,projection_id,network_id,device_id,generation,desired_body,desired_hash,binding_id,authenticated_peer_id,binding_generation,recorded_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![submission.operation_id.as_str(), projection_id, submission.network_id.to_string(), submission.device_id.to_string(), submission.generation.get(), submission.desired_body, submission.desired_hash, submission.binding.binding_id, submission.binding.authenticated_peer_id, submission.binding.binding_generation.get(), now.timestamp_millis()],
        )?;
        Ok(())
    }

    fn n7_binding_is_active_tx(
        &self,
        tx: &Transaction<'_>,
        network_id: NetworkId,
        device_id: DeviceId,
        binding: &N7BindingProvenance,
    ) -> Result<bool, StateError> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM n6_binding_records WHERE binding_id=?1 AND network_id=?2 AND device_id=?3 AND verified_peer_id=?4 AND generation=?5 AND binding_state='active')",
            params![binding.binding_id, network_id.to_string(), device_id.to_string(), binding.authenticated_peer_id, binding.binding_generation.get()],
            |row| row.get(0),
        ).map_err(StateError::from)
    }

    fn n7_operation_projection_tx(
        &self,
        tx: &Transaction<'_>,
        operation_id: &OperationId,
        device_id: DeviceId,
        generation: Generation,
    ) -> Result<String, StateError> {
        let (projection_id, stored_device, stored_generation) = tx.query_row(
            "SELECT projection_id,device_id,generation FROM n7_fleet_projection_operations WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?)),
        ).optional()?.ok_or_else(|| StateError::NotFound(format!("N7 operation {}", operation_id.as_str())))?;
        if stored_device != device_id.to_string() || stored_generation != generation.get() {
            return Err(StateError::Conflict(
                "N7 operation provenance does not match projection".into(),
            ));
        }
        Ok(projection_id)
    }

    fn n7_current_attempt_id_tx(
        &self,
        tx: &Transaction<'_>,
        projection_id: &str,
    ) -> Result<String, StateError> {
        tx.query_row(
            "SELECT current_attempt_id FROM n7_fleet_projection_records WHERE projection_id=?1 AND current_attempt_id IS NOT NULL",
            [projection_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| StateError::Conflict("N7 attempted projection has no current durable attempt".into()))
    }

    fn n7_next_attempt_number_tx(
        &self,
        tx: &Transaction<'_>,
        projection_id: &str,
    ) -> Result<u64, StateError> {
        tx.query_row(
            "SELECT COALESCE(MAX(attempt_number),0)+1 FROM n7_fleet_projection_attempts WHERE projection_id=?1",
            [projection_id],
            |row| row.get(0),
        )
        .map_err(StateError::from)
    }

    fn n7_projection_view_tx(
        &self,
        tx: &Transaction<'_>,
        projection_id: &str,
    ) -> Result<N7ProjectionView, StateError> {
        let row = tx.query_row(
            "SELECT network_id,device_id,generation,desired_body,desired_hash,binding_id,authenticated_peer_id,binding_generation,revision,projection_state FROM n7_fleet_projection_records WHERE projection_id=?1",
            [projection_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?, row.get::<_, u64>(7)?, row.get::<_, u64>(8)?, row.get::<_, String>(9)?)),
        ).optional()?.ok_or_else(|| StateError::NotFound(format!("N7 projection {projection_id}")))?;
        Ok(N7ProjectionView {
            projection_id: projection_id.to_owned(),
            network_id: NetworkId::parse(&row.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            device_id: DeviceId::parse(&row.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            generation: generation(row.2)?,
            desired_body: row.3,
            desired_hash: row.4,
            binding: N7BindingProvenance::new(row.5, row.6, generation(row.7)?)?,
            revision: row.8,
            state: N7ProjectionState::parse(&row.9)?,
        })
    }

    fn n7_advance_fleet_projection_generation_tx(
        &self,
        tx: &Transaction<'_>,
        device_id: DeviceId,
        expected: Generation,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        let next = expected
            .next_exact()
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        let stored = tx
            .query_row(
                "SELECT record_json FROM devices WHERE device_id=?1",
                [device_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
        let mut device: Device = serde_json::from_str(&stored)?;
        device
            .generations
            .advance_fleet_projection(expected, next)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        device.updated_at = now;

        let changed = tx.execute(
            "UPDATE device_generations SET fleet_projection_generation=?3,updated_at=?4 WHERE device_id=?1 AND fleet_projection_generation=?2",
            params![device_id.to_string(), expected.get(), next.get(), now.to_rfc3339()],
        )?;
        if changed == 0 {
            let actual = tx
                .query_row(
                    "SELECT fleet_projection_generation FROM device_generations WHERE device_id=?1",
                    [device_id.to_string()],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
            return Err(StateError::StaleGeneration {
                expected: expected.get(),
                actual,
            });
        }
        let changed = tx.execute(
            "UPDATE devices SET fleet_projection_generation=?2,record_json=?3,updated_at=?4 WHERE device_id=?1 AND fleet_projection_generation=?5",
            params![device_id.to_string(), next.get(), serde_json::to_string(&device)?, now.to_rfc3339(), expected.get()],
        )?;
        if changed == 0 {
            let actual = tx
                .query_row(
                    "SELECT fleet_projection_generation FROM devices WHERE device_id=?1",
                    [device_id.to_string()],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
            return Err(StateError::StaleGeneration {
                expected: expected.get(),
                actual,
            });
        }
        Ok(())
    }

    fn n7_set_device_status(
        &self,
        tx: &Transaction<'_>,
        device_id: DeviceId,
        next: ProjectionStatus,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        let stored = tx.query_row(
            "SELECT record_json FROM devices WHERE device_id=?1",
            [device_id.to_string()],
            |row| row.get::<_, String>(0),
        )?;
        let mut device: Device = serde_json::from_str(&stored)?;
        if device.fleet_projection_status != next {
            device
                .fleet_projection_status
                .transition(next)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            device.fleet_projection_status = next;
        }
        device.updated_at = now;
        tx.execute("UPDATE devices SET fleet_projection_status=?2,record_json=?3,updated_at=?4 WHERE device_id=?1", params![device_id.to_string(), lower(next.as_str()), serde_json::to_string(&device)?, now.to_rfc3339()])?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_n7_projection_audit(
        &self,
        tx: &Transaction<'_>,
        projection_id: &str,
        operation_id: &str,
        network_id: NetworkId,
        device_id: DeviceId,
        generation: Generation,
        revision: u64,
        event_kind: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        let event_id = AuditEventId::new();
        tx.execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES (?1,?2,?3,?4,'nodescale',NULL,?5,'success',?6,'{}')",
            params![event_id.to_string(), now.to_rfc3339(), network_id.to_string(), device_id.to_string(), format!("fleet_{event_kind}"), generation.get()],
        )?;
        tx.execute(
            "INSERT INTO n7_fleet_projection_audit (audit_id,audit_event_id,projection_id,operation_id,event_kind,generation,revision,recorded_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![uuid::Uuid::new_v4().to_string(), event_id.to_string(), projection_id, operation_id, event_kind, generation.get(), revision, now.timestamp_millis()],
        )?;
        Ok(())
    }
}

fn canonical_json_bytes(bytes: &[u8]) -> Result<Vec<u8>, StateError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if !value.is_object() {
        return Err(StateError::Conflict(
            "N7 desired projection body must be a JSON object".into(),
        ));
    }
    Ok(serde_json::to_vec(&value)?)
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn stale_revision(expected: u64, actual: u64) -> StateError {
    StateError::StaleGeneration { expected, actual }
}
