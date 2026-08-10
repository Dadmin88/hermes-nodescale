PRAGMA foreign_keys = ON;

-- N7 owns immutable desired Fleet projection evidence. The complete canonical
-- body and exact active N6 binding tuple are persisted before dispatch.
CREATE TABLE n7_fleet_projection_records (
    projection_id TEXT PRIMARY KEY CHECK (length(projection_id)=36 AND projection_id=lower(projection_id) AND substr(projection_id,9,1)='-' AND substr(projection_id,14,1)='-' AND substr(projection_id,19,1)='-' AND substr(projection_id,24,1)='-' AND replace(projection_id,'-','') NOT GLOB '*[^0-9a-f]*'),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    generation INTEGER NOT NULL CHECK (typeof(generation)='integer' AND generation>=1),
    desired_body BLOB NOT NULL CHECK (typeof(desired_body)='blob' AND length(desired_body)>1),
    desired_hash TEXT NOT NULL CHECK (length(desired_hash)=71 AND substr(desired_hash,1,7)='sha256:' AND substr(desired_hash,8) NOT GLOB '*[^0-9a-f]*'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT CHECK (length(binding_id) BETWEEN 1 AND 64 AND binding_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    authenticated_peer_id TEXT NOT NULL CHECK (length(authenticated_peer_id) BETWEEN 1 AND 255 AND authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    binding_generation INTEGER NOT NULL CHECK (typeof(binding_generation)='integer' AND binding_generation>=1),
    projection_state TEXT NOT NULL CHECK (projection_state IN ('desired','attempted','applied','conflict')),
    revision INTEGER NOT NULL CHECK (typeof(revision)='integer' AND revision>=1),
    current_attempt_id TEXT REFERENCES n7_fleet_projection_attempts(attempt_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    persisted_at_ms INTEGER NOT NULL CHECK (typeof(persisted_at_ms)='integer' AND persisted_at_ms>=0),
    attempted_at_ms INTEGER CHECK (attempted_at_ms IS NULL OR (typeof(attempted_at_ms)='integer' AND attempted_at_ms>=persisted_at_ms)),
    applied_at_ms INTEGER CHECK (applied_at_ms IS NULL OR (typeof(applied_at_ms)='integer' AND applied_at_ms>=persisted_at_ms)),
    conflict_at_ms INTEGER CHECK (conflict_at_ms IS NULL OR (typeof(conflict_at_ms)='integer' AND conflict_at_ms>=persisted_at_ms)),
    CHECK ((projection_state='desired' AND revision=1 AND current_attempt_id IS NULL AND attempted_at_ms IS NULL AND applied_at_ms IS NULL AND conflict_at_ms IS NULL)
        OR (projection_state='attempted' AND revision=2 AND current_attempt_id IS NOT NULL AND attempted_at_ms IS NOT NULL AND applied_at_ms IS NULL AND conflict_at_ms IS NULL)
        OR (projection_state='applied' AND revision=3 AND current_attempt_id IS NOT NULL AND attempted_at_ms IS NOT NULL AND applied_at_ms IS NOT NULL AND conflict_at_ms IS NULL)
        OR (projection_state='conflict' AND revision=3 AND current_attempt_id IS NOT NULL AND attempted_at_ms IS NOT NULL AND applied_at_ms IS NULL AND conflict_at_ms IS NOT NULL)),
    UNIQUE(device_id,generation)
);

CREATE TABLE n7_fleet_projection_operations (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    projection_id TEXT NOT NULL REFERENCES n7_fleet_projection_records(projection_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    generation INTEGER NOT NULL CHECK (typeof(generation)='integer' AND generation>=1),
    desired_body BLOB NOT NULL CHECK (typeof(desired_body)='blob' AND length(desired_body)>1),
    desired_hash TEXT NOT NULL CHECK (length(desired_hash)=71 AND substr(desired_hash,1,7)='sha256:' AND substr(desired_hash,8) NOT GLOB '*[^0-9a-f]*'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authenticated_peer_id TEXT NOT NULL CHECK (length(authenticated_peer_id) BETWEEN 1 AND 255 AND authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    binding_generation INTEGER NOT NULL CHECK (typeof(binding_generation)='integer' AND binding_generation>=1),
    recorded_at_ms INTEGER NOT NULL CHECK (typeof(recorded_at_ms)='integer' AND recorded_at_ms>=0),
    UNIQUE(projection_id,operation_id)
);

CREATE TABLE n7_fleet_projection_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id)=36 AND attempt_id=lower(attempt_id) AND substr(attempt_id,9,1)='-' AND substr(attempt_id,14,1)='-' AND substr(attempt_id,19,1)='-' AND substr(attempt_id,24,1)='-' AND replace(attempt_id,'-','') NOT GLOB '*[^0-9a-f]*'),
    projection_id TEXT NOT NULL REFERENCES n7_fleet_projection_records(projection_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES n7_fleet_projection_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK (typeof(attempt_number)='integer' AND attempt_number>=1),
    expected_revision INTEGER NOT NULL CHECK (expected_revision IN (1,2)),
    attempted_at_ms INTEGER NOT NULL CHECK (typeof(attempted_at_ms)='integer' AND attempted_at_ms>=0),
    UNIQUE(projection_id,attempt_number)
);

CREATE TABLE n7_fleet_projection_inspections (
    inspection_id TEXT PRIMARY KEY CHECK (length(inspection_id)=36 AND inspection_id=lower(inspection_id) AND substr(inspection_id,9,1)='-' AND substr(inspection_id,14,1)='-' AND substr(inspection_id,19,1)='-' AND substr(inspection_id,24,1)='-' AND replace(inspection_id,'-','') NOT GLOB '*[^0-9a-f]*'),
    projection_id TEXT NOT NULL REFERENCES n7_fleet_projection_records(projection_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES n7_fleet_projection_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    attempt_id TEXT NOT NULL REFERENCES n7_fleet_projection_attempts(attempt_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    expected_revision INTEGER NOT NULL CHECK (expected_revision=2),
    inspection_kind TEXT NOT NULL CHECK (inspection_kind IN ('observed','missing','unavailable')),
    observed_body BLOB CHECK (observed_body IS NULL OR (typeof(observed_body)='blob' AND length(observed_body)>1)),
    observed_hash TEXT CHECK (observed_hash IS NULL OR (length(observed_hash)=71 AND substr(observed_hash,1,7)='sha256:' AND substr(observed_hash,8) NOT GLOB '*[^0-9a-f]*')),
    inspected_at_ms INTEGER NOT NULL CHECK (typeof(inspected_at_ms)='integer' AND inspected_at_ms>=0),
    CHECK ((inspection_kind='observed' AND observed_body IS NOT NULL AND observed_hash IS NOT NULL)
        OR (inspection_kind IN ('missing','unavailable') AND observed_body IS NULL AND observed_hash IS NULL))
);

CREATE TABLE n7_fleet_projection_audit (
    audit_id TEXT PRIMARY KEY CHECK (length(audit_id)=36 AND audit_id=lower(audit_id) AND substr(audit_id,9,1)='-' AND substr(audit_id,14,1)='-' AND substr(audit_id,19,1)='-' AND substr(audit_id,24,1)='-' AND replace(audit_id,'-','') NOT GLOB '*[^0-9a-f]*'),
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    projection_id TEXT NOT NULL REFERENCES n7_fleet_projection_records(projection_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    operation_id TEXT NOT NULL REFERENCES n7_fleet_projection_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('projection_desired','projection_attempted','projection_applied','projection_conflict')),
    generation INTEGER NOT NULL CHECK (typeof(generation)='integer' AND generation>=1),
    revision INTEGER NOT NULL CHECK (typeof(revision)='integer' AND revision>=1),
    recorded_at_ms INTEGER NOT NULL CHECK (typeof(recorded_at_ms)='integer' AND recorded_at_ms>=0)
);

CREATE TRIGGER n7_projection_exact_active_n6
BEFORE INSERT ON n7_fleet_projection_records
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n6_binding_records b
    WHERE b.binding_id=NEW.binding_id AND b.network_id=NEW.network_id AND b.device_id=NEW.device_id
      AND b.verified_peer_id=NEW.authenticated_peer_id AND b.generation=NEW.binding_generation
      AND b.binding_state='active'
)
BEGIN SELECT RAISE(ABORT,'N7 desired projection requires exact active N6 provenance'); END;

CREATE TRIGGER n7_projection_record_transition_guard
BEFORE UPDATE ON n7_fleet_projection_records
FOR EACH ROW WHEN NOT (
    (OLD.projection_state='desired' AND OLD.revision=1 AND NEW.projection_state='attempted' AND NEW.revision=2
        AND EXISTS (SELECT 1 FROM n6_binding_records b WHERE b.binding_id=NEW.binding_id AND b.network_id=NEW.network_id AND b.device_id=NEW.device_id AND b.verified_peer_id=NEW.authenticated_peer_id AND b.generation=NEW.binding_generation AND b.binding_state='active')
        AND EXISTS (SELECT 1 FROM n7_fleet_projection_attempts a WHERE a.attempt_id=NEW.current_attempt_id AND a.projection_id=NEW.projection_id AND a.operation_id IN (SELECT operation_id FROM n7_fleet_projection_operations WHERE projection_id=NEW.projection_id)))
    OR (OLD.projection_state='attempted' AND OLD.revision=2 AND NEW.projection_state='attempted' AND NEW.revision=2
        AND NEW.current_attempt_id<>OLD.current_attempt_id
        AND EXISTS (SELECT 1 FROM n6_binding_records b WHERE b.binding_id=NEW.binding_id AND b.network_id=NEW.network_id AND b.device_id=NEW.device_id AND b.verified_peer_id=NEW.authenticated_peer_id AND b.generation=NEW.binding_generation AND b.binding_state='active')
        AND EXISTS (SELECT 1 FROM n7_fleet_projection_attempts a WHERE a.attempt_id=NEW.current_attempt_id AND a.projection_id=NEW.projection_id AND a.attempt_number=(SELECT MAX(attempt_number) FROM n7_fleet_projection_attempts WHERE projection_id=NEW.projection_id)))
    OR (OLD.projection_state='attempted' AND OLD.revision=2 AND NEW.projection_state IN ('applied','conflict') AND NEW.revision=3 AND NEW.current_attempt_id=OLD.current_attempt_id
        AND EXISTS (SELECT 1 FROM n7_fleet_projection_inspections i JOIN n7_fleet_projection_attempts a ON a.attempt_id=i.attempt_id WHERE i.projection_id=NEW.projection_id AND i.attempt_id=NEW.current_attempt_id AND i.operation_id=a.operation_id AND i.expected_revision=OLD.revision AND i.inspection_kind='observed'
            AND ((NEW.projection_state='applied' AND i.observed_body=NEW.desired_body AND i.observed_hash=NEW.desired_hash)
              OR (NEW.projection_state='conflict' AND (i.observed_body<>NEW.desired_body OR i.observed_hash<>NEW.desired_hash)))))
) OR NEW.network_id<>OLD.network_id OR NEW.device_id<>OLD.device_id OR NEW.generation<>OLD.generation
   OR NEW.desired_body<>OLD.desired_body OR NEW.desired_hash<>OLD.desired_hash OR NEW.binding_id<>OLD.binding_id
   OR NEW.authenticated_peer_id<>OLD.authenticated_peer_id OR NEW.binding_generation<>OLD.binding_generation
BEGIN SELECT RAISE(ABORT,'N7 projection transition requires exact durable identity, body, N6 provenance, and revision fence'); END;

CREATE TRIGGER n7_projection_attempt_exact_subject
BEFORE INSERT ON n7_fleet_projection_attempts
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n7_fleet_projection_records p
    JOIN n7_fleet_projection_operations o ON o.operation_id=NEW.operation_id AND o.projection_id=p.projection_id
    WHERE p.projection_id=NEW.projection_id
      AND ((p.projection_state='desired' AND p.revision=1 AND NEW.attempt_number=1 AND NEW.expected_revision=1)
        OR (p.projection_state='attempted' AND p.revision=2 AND NEW.attempt_number=(SELECT COALESCE(MAX(attempt_number),0)+1 FROM n7_fleet_projection_attempts WHERE projection_id=p.projection_id) AND NEW.expected_revision=p.revision))
)
BEGIN SELECT RAISE(ABORT,'N7 attempt requires the exact durable operation and current revision'); END;

CREATE TRIGGER n7_projection_operation_exact_subject
BEFORE INSERT ON n7_fleet_projection_operations
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n7_fleet_projection_records p
    WHERE p.projection_id=NEW.projection_id AND p.network_id=NEW.network_id AND p.device_id=NEW.device_id
      AND p.generation=NEW.generation AND p.desired_body=NEW.desired_body AND p.desired_hash=NEW.desired_hash
      AND p.binding_id=NEW.binding_id AND p.authenticated_peer_id=NEW.authenticated_peer_id AND p.binding_generation=NEW.binding_generation
)
BEGIN SELECT RAISE(ABORT,'N7 operation must bind the exact durable identity, body, hash, and N6 provenance'); END;

CREATE TRIGGER n7_projection_inspection_exact_subject
BEFORE INSERT ON n7_fleet_projection_inspections
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n7_fleet_projection_records p JOIN n7_fleet_projection_operations o ON o.operation_id=NEW.operation_id
    JOIN n7_fleet_projection_attempts a ON a.attempt_id=NEW.attempt_id
    WHERE p.projection_id=NEW.projection_id AND o.projection_id=p.projection_id
      AND a.projection_id=p.projection_id AND a.operation_id=NEW.operation_id
      AND p.projection_state='attempted' AND p.revision=NEW.expected_revision AND p.current_attempt_id=NEW.attempt_id
)
BEGIN SELECT RAISE(ABORT,'N7 inspection requires the exact attempted operation and revision'); END;

CREATE TRIGGER n7_projection_audit_exact_subject
BEFORE INSERT ON n7_fleet_projection_audit
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n7_fleet_projection_records p
    JOIN n7_fleet_projection_operations o ON o.operation_id=NEW.operation_id AND o.projection_id=p.projection_id
    JOIN audit_events e ON e.event_id=NEW.audit_event_id
    WHERE p.projection_id=NEW.projection_id AND p.generation=NEW.generation
      AND e.network_id=p.network_id AND e.device_id=p.device_id AND e.generation=NEW.generation
      AND e.actor_source='nodescale' AND e.actor_id IS NULL AND e.event_kind='fleet_' || NEW.event_kind
      AND e.outcome='success' AND e.metadata_json='{}'
      AND ((NEW.event_kind='projection_desired' AND p.projection_state='desired' AND p.revision=1)
        OR (NEW.event_kind='projection_attempted' AND p.projection_state='attempted' AND p.revision=2)
        OR (NEW.event_kind='projection_applied' AND p.projection_state='applied' AND p.revision=3)
        OR (NEW.event_kind='projection_conflict' AND p.projection_state='conflict' AND p.revision=3))
      AND NEW.revision=p.revision
)
BEGIN SELECT RAISE(ABORT,'N7 audit requires exact safe projection provenance'); END;

CREATE TRIGGER n7_projection_record_immutable_delete BEFORE DELETE ON n7_fleet_projection_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection records are durable'); END;
CREATE TRIGGER n7_projection_operation_immutable_update BEFORE UPDATE ON n7_fleet_projection_operations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection operations are immutable'); END;
CREATE TRIGGER n7_projection_operation_immutable_delete BEFORE DELETE ON n7_fleet_projection_operations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection operations are immutable'); END;
CREATE TRIGGER n7_projection_attempt_immutable_update BEFORE UPDATE ON n7_fleet_projection_attempts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection attempts are append-only'); END;
CREATE TRIGGER n7_projection_attempt_immutable_delete BEFORE DELETE ON n7_fleet_projection_attempts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection attempts are append-only'); END;
CREATE TRIGGER n7_projection_inspection_immutable_update BEFORE UPDATE ON n7_fleet_projection_inspections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection inspections are append-only'); END;
CREATE TRIGGER n7_projection_inspection_immutable_delete BEFORE DELETE ON n7_fleet_projection_inspections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection inspections are append-only'); END;
CREATE TRIGGER n7_projection_audit_immutable_update BEFORE UPDATE ON n7_fleet_projection_audit FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection audit is append-only'); END;
CREATE TRIGGER n7_projection_audit_immutable_delete BEFORE DELETE ON n7_fleet_projection_audit FOR EACH ROW BEGIN SELECT RAISE(ABORT,'N7 projection audit is append-only'); END;

-- Every audit event linked into the N7 provenance chain is immutable, not only
-- the link row. N7 event metadata is also secret-free at the SQL boundary so
-- direct writes cannot persist bearer or credential material before linkage.
CREATE TRIGGER n7_audit_event_immutable_update
BEFORE UPDATE ON audit_events
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM n7_fleet_projection_audit a WHERE a.audit_event_id=OLD.event_id
)
BEGIN SELECT RAISE(ABORT,'N7 audit events are append-only'); END;
CREATE TRIGGER n7_audit_event_immutable_delete
BEFORE DELETE ON audit_events
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM n7_fleet_projection_audit a WHERE a.audit_event_id=OLD.event_id
)
BEGIN SELECT RAISE(ABORT,'N7 audit events are append-only'); END;

CREATE TRIGGER n7_audit_metadata_secret_free_insert
BEFORE INSERT ON audit_events
FOR EACH ROW WHEN NEW.event_kind IN ('fleet_projection_desired','fleet_projection_attempted','fleet_projection_applied','fleet_projection_conflict')
  AND (lower(NEW.metadata_json) LIKE '%secret%'
       OR lower(NEW.metadata_json) LIKE '%token%'
       OR lower(NEW.metadata_json) LIKE '%password%'
       OR lower(NEW.metadata_json) LIKE '%bearer%'
       OR lower(NEW.metadata_json) LIKE '%authorization%'
       OR lower(NEW.metadata_json) LIKE '%api_key%'
       OR lower(NEW.metadata_json) LIKE '%apikey%'
       OR lower(NEW.metadata_json) LIKE '%access_key%'
       OR lower(NEW.metadata_json) LIKE '%private_key%')
BEGIN SELECT RAISE(ABORT,'N7 audit metadata must be secret-free'); END;
CREATE TRIGGER n7_audit_metadata_secret_free_update
BEFORE UPDATE OF event_kind, metadata_json ON audit_events
FOR EACH ROW WHEN NEW.event_kind IN ('fleet_projection_desired','fleet_projection_attempted','fleet_projection_applied','fleet_projection_conflict')
  AND (lower(NEW.metadata_json) LIKE '%secret%'
       OR lower(NEW.metadata_json) LIKE '%token%'
       OR lower(NEW.metadata_json) LIKE '%password%'
       OR lower(NEW.metadata_json) LIKE '%bearer%'
       OR lower(NEW.metadata_json) LIKE '%authorization%'
       OR lower(NEW.metadata_json) LIKE '%api_key%'
       OR lower(NEW.metadata_json) LIKE '%apikey%'
       OR lower(NEW.metadata_json) LIKE '%access_key%'
       OR lower(NEW.metadata_json) LIKE '%private_key%')
BEGIN SELECT RAISE(ABORT,'N7 audit metadata must be secret-free'); END;
