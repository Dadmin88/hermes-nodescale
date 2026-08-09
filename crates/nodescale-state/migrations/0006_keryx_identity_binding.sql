PRAGMA foreign_keys = ON;

-- N6 is the sole authoritative Keryx binding plane.  The legacy
-- `keryx_bindings` projection remains deliberately untouched for compatibility.
CREATE TABLE n6_binding_decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(decision_id) BETWEEN 1 AND 64 AND decision_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(audit_event_id) BETWEEN 1 AND 64 AND audit_event_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('binding','challenge','authorization')),
    decision_kind TEXT NOT NULL CHECK (decision_kind IN ('issue','confirm','replay','conflict','stale','rotate','revoke','expire','invalidate')),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
        CHECK (length(binding_id) BETWEEN 1 AND 64 AND binding_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    challenge_id TEXT REFERENCES n6_binding_challenges(challenge_id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
        CHECK (challenge_id IS NULL OR (length(challenge_id) BETWEEN 1 AND 64 AND challenge_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    authorization_id TEXT REFERENCES n6_binding_authorizations(authorization_id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
        CHECK (authorization_id IS NULL OR (length(authorization_id) BETWEEN 1 AND 64 AND authorization_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(network_id) BETWEEN 1 AND 64 AND network_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(device_id) BETWEEN 1 AND 64 AND device_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    join_session_id TEXT NOT NULL REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(join_session_id) BETWEEN 1 AND 64 AND join_session_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    prior_state TEXT CHECK (prior_state IS NULL OR prior_state IN ('pending','active','stale','rotated','revoked','consumed','invalidated','expired')),
    new_state TEXT NOT NULL CHECK (new_state IN ('pending','active','stale','rotated','revoked','consumed','invalidated','expired')),
    prior_revision INTEGER CHECK (prior_revision IS NULL OR (typeof(prior_revision) = 'integer' AND prior_revision >= 1)),
    new_revision INTEGER NOT NULL CHECK (typeof(new_revision) = 'integer' AND new_revision >= 1),
    decided_at_ms INTEGER NOT NULL CHECK (typeof(decided_at_ms) = 'integer' AND decided_at_ms >= 0),
    actor_source TEXT NOT NULL CHECK (length(actor_source) BETWEEN 1 AND 64 AND actor_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    actor_id TEXT CHECK (actor_id IS NULL OR (length(actor_id) BETWEEN 1 AND 255 AND actor_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 64 AND reason_code NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    authenticated_peer_id TEXT CHECK (authenticated_peer_id IS NULL OR (length(authenticated_peer_id) BETWEEN 1 AND 255 AND authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    operation_id TEXT CHECK (operation_id IS NULL OR (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 128 AND agent_version NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    CHECK ((subject_kind = 'binding' AND decision_kind IN ('issue','confirm','replay','conflict','stale','rotate','revoke'))
        OR (subject_kind = 'challenge' AND decision_kind IN ('issue','confirm','replay','conflict','expire','invalidate'))
        OR (subject_kind = 'authorization' AND decision_kind IN ('issue','expire','invalidate'))),
    CHECK ((actor_source = 'nodescale' AND actor_id IS NULL) OR (actor_source <> 'nodescale' AND actor_id IS NOT NULL)),
    CHECK ((subject_kind = 'binding'
            AND ((decision_kind = 'confirm' AND challenge_id IS NOT NULL)
                OR (decision_kind <> 'confirm' AND challenge_id IS NULL))
            AND (authorization_id IS NULL OR decision_kind IN ('rotate','revoke')))
        OR (subject_kind = 'challenge' AND challenge_id IS NOT NULL AND authorization_id IS NULL)
        OR (subject_kind = 'authorization' AND challenge_id IS NULL AND authorization_id IS NOT NULL)),
    CHECK ((decision_kind = 'issue'
            AND prior_state IS NULL AND prior_revision IS NULL
            AND new_state = 'pending' AND new_revision = 1)
        OR (decision_kind IN ('replay','conflict')
            AND prior_state IS NOT NULL AND prior_revision IS NOT NULL
            AND new_state = prior_state AND new_revision = prior_revision)
        OR (decision_kind NOT IN ('issue','replay','conflict')
            AND prior_state IS NOT NULL AND prior_revision IS NOT NULL
            AND new_revision = prior_revision + 1)),
    CHECK ((subject_kind = 'binding' AND (
            (decision_kind = 'issue' AND new_state = 'pending')
            OR (decision_kind = 'confirm' AND prior_state = 'pending' AND new_state = 'active' AND prior_revision = 1 AND new_revision = 2)
            OR (decision_kind = 'stale' AND prior_state = 'active' AND new_state = 'stale')
            OR (decision_kind = 'rotate' AND prior_state IN ('active','stale') AND new_state = 'rotated')
            OR (decision_kind = 'revoke' AND prior_state IN ('pending','active','stale') AND new_state = 'revoked')
            OR (decision_kind IN ('replay','conflict') AND prior_state IN ('pending','active','stale','rotated','revoked'))
        ))
        OR (subject_kind = 'challenge' AND (
            (decision_kind = 'issue' AND new_state = 'pending')
            OR (decision_kind = 'confirm' AND prior_state = 'pending' AND new_state = 'consumed' AND prior_revision = 1 AND new_revision = 2)
            OR (decision_kind = 'expire' AND prior_state = 'pending' AND new_state = 'expired' AND prior_revision = 1 AND new_revision = 2)
            OR (decision_kind = 'invalidate' AND prior_state = 'pending' AND new_state = 'invalidated' AND prior_revision = 1 AND new_revision = 2)
            OR (decision_kind IN ('replay','conflict') AND prior_state IN ('pending','consumed','invalidated','expired'))
        ))
        OR (subject_kind = 'authorization' AND (
            (decision_kind = 'issue' AND new_state = 'pending')
            OR (decision_kind = 'expire' AND prior_state = 'pending' AND new_state = 'expired')
            OR (decision_kind = 'invalidate' AND prior_state = 'pending' AND new_state = 'invalidated')
        )))
,
    CHECK ((length(decision_id) = 36 AND decision_id = lower(decision_id) AND substr(decision_id,9,1) = '-' AND substr(decision_id,14,1) = '-' AND substr(decision_id,19,1) = '-' AND substr(decision_id,24,1) = '-' AND replace(decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND decision_id <> '00000000-0000-0000-0000-000000000000') AND (length(audit_event_id) = 36 AND audit_event_id = lower(audit_event_id) AND substr(audit_event_id,9,1) = '-' AND substr(audit_event_id,14,1) = '-' AND substr(audit_event_id,19,1) = '-' AND substr(audit_event_id,24,1) = '-' AND replace(audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND audit_event_id <> '00000000-0000-0000-0000-000000000000') AND (length(binding_id) = 36 AND binding_id = lower(binding_id) AND substr(binding_id,9,1) = '-' AND substr(binding_id,14,1) = '-' AND substr(binding_id,19,1) = '-' AND substr(binding_id,24,1) = '-' AND replace(binding_id,'-','') NOT GLOB '*[^0-9a-f]*' AND binding_id <> '00000000-0000-0000-0000-000000000000') AND (challenge_id IS NULL OR (length(challenge_id) = 36 AND challenge_id = lower(challenge_id) AND substr(challenge_id,9,1) = '-' AND substr(challenge_id,14,1) = '-' AND substr(challenge_id,19,1) = '-' AND substr(challenge_id,24,1) = '-' AND replace(challenge_id,'-','') NOT GLOB '*[^0-9a-f]*' AND challenge_id <> '00000000-0000-0000-0000-000000000000')) AND (authorization_id IS NULL OR (length(authorization_id) = 36 AND authorization_id = lower(authorization_id) AND substr(authorization_id,9,1) = '-' AND substr(authorization_id,14,1) = '-' AND substr(authorization_id,19,1) = '-' AND substr(authorization_id,24,1) = '-' AND replace(authorization_id,'-','') NOT GLOB '*[^0-9a-f]*' AND authorization_id <> '00000000-0000-0000-0000-000000000000')) AND (length(network_id) = 36 AND network_id = lower(network_id) AND substr(network_id,9,1) = '-' AND substr(network_id,14,1) = '-' AND substr(network_id,19,1) = '-' AND substr(network_id,24,1) = '-' AND replace(network_id,'-','') NOT GLOB '*[^0-9a-f]*' AND network_id <> '00000000-0000-0000-0000-000000000000') AND (length(device_id) = 36 AND device_id = lower(device_id) AND substr(device_id,9,1) = '-' AND substr(device_id,14,1) = '-' AND substr(device_id,19,1) = '-' AND substr(device_id,24,1) = '-' AND replace(device_id,'-','') NOT GLOB '*[^0-9a-f]*' AND device_id <> '00000000-0000-0000-0000-000000000000') AND (length(join_session_id) = 36 AND join_session_id = lower(join_session_id) AND substr(join_session_id,9,1) = '-' AND substr(join_session_id,14,1) = '-' AND substr(join_session_id,19,1) = '-' AND substr(join_session_id,24,1) = '-' AND replace(join_session_id,'-','') NOT GLOB '*[^0-9a-f]*' AND join_session_id <> '00000000-0000-0000-0000-000000000000')));

CREATE TABLE n6_binding_authority_capabilities (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36 AND grant_id = lower(grant_id) AND substr(grant_id,9,1) = '-' AND substr(grant_id,14,1) = '-' AND substr(grant_id,19,1) = '-' AND substr(grant_id,24,1) = '-' AND replace(grant_id,'-','') NOT GLOB '*[^0-9a-f]*' AND grant_id <> '00000000-0000-0000-0000-000000000000'),
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(authority_id) = 36 AND authority_id = lower(authority_id) AND substr(authority_id,9,1) = '-' AND substr(authority_id,14,1) = '-' AND substr(authority_id,19,1) = '-' AND substr(authority_id,24,1) = '-' AND replace(authority_id,'-','') NOT GLOB '*[^0-9a-f]*' AND authority_id <> '00000000-0000-0000-0000-000000000000'),
    capability TEXT NOT NULL CHECK (capability IN ('rotate','revoke')),
    issued_by_source TEXT NOT NULL CHECK (length(issued_by_source) BETWEEN 1 AND 64 AND issued_by_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    issued_by_id TEXT CHECK (issued_by_id IS NULL OR (length(issued_by_id) BETWEEN 1 AND 255 AND issued_by_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    issued_at_ms INTEGER NOT NULL CHECK (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= 0),
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(audit_event_id) = 36 AND audit_event_id = lower(audit_event_id) AND substr(audit_event_id,9,1) = '-' AND substr(audit_event_id,14,1) = '-' AND substr(audit_event_id,19,1) = '-' AND substr(audit_event_id,24,1) = '-' AND replace(audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND audit_event_id <> '00000000-0000-0000-0000-000000000000'),
    UNIQUE(authority_id, capability),
    CHECK ((issued_by_source = 'nodescale' AND issued_by_id IS NULL) OR (issued_by_source <> 'nodescale' AND issued_by_id IS NOT NULL))
);

CREATE TRIGGER n6_binding_authority_capability_insert_guard
BEFORE INSERT ON n6_binding_authority_capabilities
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_trust_authorities a
    JOIN n5_owner_trust_roots r ON r.trust_root_id = a.trust_root_id
    JOIN audit_events e ON e.event_id = NEW.audit_event_id
    WHERE a.authority_id = NEW.authority_id
      AND e.network_id = a.network_id
      AND e.actor_source = NEW.issued_by_source
      AND e.actor_id IS NEW.issued_by_id
      AND e.event_kind = 'keryx_binding_authority_capability_granted'
      AND e.outcome = 'success'
      AND a.principal_source = NEW.issued_by_source
      AND a.principal_id IS NEW.issued_by_id
      AND a.sealed = 1
      AND a.enabled = 1
      AND a.revoked_at_ms IS NULL
      AND r.network_id = a.network_id
      AND r.principal_source = a.principal_source
      AND r.principal_id = a.principal_id
      AND r.enabled = 1
      AND r.revoked_at_ms IS NULL
      AND NEW.issued_at_ms >= a.not_before_ms
      AND NEW.issued_at_ms < a.expires_at_ms
)
BEGIN SELECT RAISE(ABORT, 'N6 authority capability grant requires an exact live owner-root authority and successful audit provenance'); END;
CREATE TRIGGER n6_binding_authority_capability_immutable_update
BEFORE UPDATE ON n6_binding_authority_capabilities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 authority capability grants are immutable'); END;
CREATE TRIGGER n6_binding_authority_capability_immutable_delete
BEFORE DELETE ON n6_binding_authority_capabilities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 authority capability grants are immutable'); END;

CREATE TABLE n6_binding_records (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 64 AND binding_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(network_id) BETWEEN 1 AND 64 AND network_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(device_id) BETWEEN 1 AND 64 AND device_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    join_session_id TEXT NOT NULL REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(join_session_id) BETWEEN 1 AND 64 AND join_session_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    verified_peer_id TEXT CHECK (verified_peer_id IS NULL OR (length(verified_peer_id) BETWEEN 1 AND 255 AND verified_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 1),
    binding_state TEXT NOT NULL CHECK (binding_state IN ('pending','active','stale','rotated','revoked')),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    confirmed_at_ms INTEGER CHECK (confirmed_at_ms IS NULL OR (typeof(confirmed_at_ms) = 'integer' AND confirmed_at_ms >= created_at_ms)),
    stale_at_ms INTEGER CHECK (stale_at_ms IS NULL OR (typeof(stale_at_ms) = 'integer' AND stale_at_ms >= created_at_ms)),
    rotated_at_ms INTEGER CHECK (rotated_at_ms IS NULL OR (typeof(rotated_at_ms) = 'integer' AND rotated_at_ms >= created_at_ms)),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (typeof(revoked_at_ms) = 'integer' AND revoked_at_ms >= created_at_ms)),
    last_verified_at_ms INTEGER CHECK (last_verified_at_ms IS NULL OR (typeof(last_verified_at_ms) = 'integer' AND last_verified_at_ms >= created_at_ms)),
    rotated_from_binding_id TEXT REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (rotated_from_binding_id IS NULL OR (length(rotated_from_binding_id) BETWEEN 1 AND 64 AND rotated_from_binding_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    rotation_authorization_id TEXT REFERENCES n6_binding_authorizations(authorization_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (rotation_authorization_id IS NULL OR (length(rotation_authorization_id) BETWEEN 1 AND 64 AND rotation_authorization_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 128 AND agent_version NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    last_decision_id TEXT NOT NULL UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    last_audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    UNIQUE(network_id, device_id, generation),
    CHECK ((generation = 1 AND rotated_from_binding_id IS NULL AND rotation_authorization_id IS NULL)
        OR (generation > 1 AND rotated_from_binding_id IS NOT NULL AND rotation_authorization_id IS NOT NULL)),
    CHECK (
        (binding_state = 'pending' AND verified_peer_id IS NULL AND confirmed_at_ms IS NULL AND stale_at_ms IS NULL AND rotated_at_ms IS NULL AND revoked_at_ms IS NULL AND last_verified_at_ms IS NULL)
        OR (binding_state = 'active' AND verified_peer_id IS NOT NULL AND confirmed_at_ms IS NOT NULL AND stale_at_ms IS NULL AND rotated_at_ms IS NULL AND revoked_at_ms IS NULL AND last_verified_at_ms IS NOT NULL AND confirmed_at_ms <= last_verified_at_ms)
        OR (binding_state = 'stale' AND verified_peer_id IS NOT NULL AND confirmed_at_ms IS NOT NULL AND stale_at_ms IS NOT NULL AND rotated_at_ms IS NULL AND revoked_at_ms IS NULL AND last_verified_at_ms IS NOT NULL AND confirmed_at_ms <= last_verified_at_ms AND last_verified_at_ms <= stale_at_ms)
        OR (binding_state = 'rotated' AND verified_peer_id IS NOT NULL AND confirmed_at_ms IS NOT NULL AND rotated_at_ms IS NOT NULL AND revoked_at_ms IS NULL AND last_verified_at_ms IS NOT NULL
            AND confirmed_at_ms <= last_verified_at_ms
            AND last_verified_at_ms <= CASE WHEN stale_at_ms IS NULL THEN rotated_at_ms ELSE stale_at_ms END
            AND (stale_at_ms IS NULL OR stale_at_ms <= rotated_at_ms))
        OR (
            binding_state = 'revoked'
            AND rotated_at_ms IS NULL
            AND revoked_at_ms IS NOT NULL
            AND (
                (verified_peer_id IS NULL AND confirmed_at_ms IS NULL AND last_verified_at_ms IS NULL AND stale_at_ms IS NULL)
                OR (
                    verified_peer_id IS NOT NULL
                    AND confirmed_at_ms IS NOT NULL
                    AND last_verified_at_ms IS NOT NULL
                    AND confirmed_at_ms <= last_verified_at_ms
                    AND last_verified_at_ms <= CASE WHEN stale_at_ms IS NULL THEN revoked_at_ms ELSE stale_at_ms END
                    AND (stale_at_ms IS NULL OR stale_at_ms <= revoked_at_ms)
                )
            )
        )
    )
,
    CHECK ((length(binding_id) = 36 AND binding_id = lower(binding_id) AND substr(binding_id,9,1) = '-' AND substr(binding_id,14,1) = '-' AND substr(binding_id,19,1) = '-' AND substr(binding_id,24,1) = '-' AND replace(binding_id,'-','') NOT GLOB '*[^0-9a-f]*' AND binding_id <> '00000000-0000-0000-0000-000000000000') AND (length(network_id) = 36 AND network_id = lower(network_id) AND substr(network_id,9,1) = '-' AND substr(network_id,14,1) = '-' AND substr(network_id,19,1) = '-' AND substr(network_id,24,1) = '-' AND replace(network_id,'-','') NOT GLOB '*[^0-9a-f]*' AND network_id <> '00000000-0000-0000-0000-000000000000') AND (length(device_id) = 36 AND device_id = lower(device_id) AND substr(device_id,9,1) = '-' AND substr(device_id,14,1) = '-' AND substr(device_id,19,1) = '-' AND substr(device_id,24,1) = '-' AND replace(device_id,'-','') NOT GLOB '*[^0-9a-f]*' AND device_id <> '00000000-0000-0000-0000-000000000000') AND (length(join_session_id) = 36 AND join_session_id = lower(join_session_id) AND substr(join_session_id,9,1) = '-' AND substr(join_session_id,14,1) = '-' AND substr(join_session_id,19,1) = '-' AND substr(join_session_id,24,1) = '-' AND replace(join_session_id,'-','') NOT GLOB '*[^0-9a-f]*' AND join_session_id <> '00000000-0000-0000-0000-000000000000') AND (rotated_from_binding_id IS NULL OR (length(rotated_from_binding_id) = 36 AND rotated_from_binding_id = lower(rotated_from_binding_id) AND substr(rotated_from_binding_id,9,1) = '-' AND substr(rotated_from_binding_id,14,1) = '-' AND substr(rotated_from_binding_id,19,1) = '-' AND substr(rotated_from_binding_id,24,1) = '-' AND replace(rotated_from_binding_id,'-','') NOT GLOB '*[^0-9a-f]*' AND rotated_from_binding_id <> '00000000-0000-0000-0000-000000000000')) AND (rotation_authorization_id IS NULL OR (length(rotation_authorization_id) = 36 AND rotation_authorization_id = lower(rotation_authorization_id) AND substr(rotation_authorization_id,9,1) = '-' AND substr(rotation_authorization_id,14,1) = '-' AND substr(rotation_authorization_id,19,1) = '-' AND substr(rotation_authorization_id,24,1) = '-' AND replace(rotation_authorization_id,'-','') NOT GLOB '*[^0-9a-f]*' AND rotation_authorization_id <> '00000000-0000-0000-0000-000000000000')) AND (length(last_decision_id) = 36 AND last_decision_id = lower(last_decision_id) AND substr(last_decision_id,9,1) = '-' AND substr(last_decision_id,14,1) = '-' AND substr(last_decision_id,19,1) = '-' AND substr(last_decision_id,24,1) = '-' AND replace(last_decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND last_decision_id <> '00000000-0000-0000-0000-000000000000') AND (length(last_audit_event_id) = 36 AND last_audit_event_id = lower(last_audit_event_id) AND substr(last_audit_event_id,9,1) = '-' AND substr(last_audit_event_id,14,1) = '-' AND substr(last_audit_event_id,19,1) = '-' AND substr(last_audit_event_id,24,1) = '-' AND replace(last_audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND last_audit_event_id <> '00000000-0000-0000-0000-000000000000')));
CREATE UNIQUE INDEX n6_binding_generation_once ON n6_binding_records(network_id, device_id, generation);
CREATE UNIQUE INDEX n6_one_active_binding_per_device ON n6_binding_records(device_id) WHERE binding_state = 'active';
CREATE UNIQUE INDEX n6_one_active_binding_per_peer ON n6_binding_records(network_id, verified_peer_id) WHERE binding_state = 'active';

CREATE TABLE n6_binding_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 1 AND 64 AND challenge_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(network_id) BETWEEN 1 AND 64 AND network_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(device_id) BETWEEN 1 AND 64 AND device_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    join_session_id TEXT NOT NULL REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(join_session_id) BETWEEN 1 AND 64 AND join_session_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    expected_authenticated_peer_id TEXT NOT NULL CHECK (length(expected_authenticated_peer_id) BETWEEN 1 AND 255 AND expected_authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    challenge_verifier TEXT NOT NULL CHECK (
        length(challenge_verifier) = length('$argon2id$v=19$m=19456,t=2,p=1$') + 22 + 1 + 43
        AND substr(challenge_verifier, 1, length('$argon2id$v=19$m=19456,t=2,p=1$')) = '$argon2id$v=19$m=19456,t=2,p=1$'
        AND substr(challenge_verifier, length('$argon2id$v=19$m=19456,t=2,p=1$') + 23, 1) = '$'
        AND substr(challenge_verifier, length('$argon2id$v=19$m=19456,t=2,p=1$') + 1, 22) NOT GLOB '*[^A-Za-z0-9+/]*'
        AND substr(challenge_verifier, length('$argon2id$v=19$m=19456,t=2,p=1$') + 22, 1) GLOB '[AQgw]'
        AND substr(challenge_verifier, length('$argon2id$v=19$m=19456,t=2,p=1$') + 24, 43) NOT GLOB '*[^A-Za-z0-9+/]*'
        AND substr(challenge_verifier, length('$argon2id$v=19$m=19456,t=2,p=1$') + 66, 1) GLOB '[AEIMQUYcgkosw048]'
    ),
    challenge_state TEXT NOT NULL CHECK (challenge_state IN ('pending','consumed','invalidated','expired')),
    issued_at_ms INTEGER NOT NULL CHECK (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > issued_at_ms),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR (typeof(consumed_at_ms) = 'integer' AND consumed_at_ms >= issued_at_ms AND consumed_at_ms < expires_at_ms)),
    invalidated_at_ms INTEGER CHECK (invalidated_at_ms IS NULL OR (typeof(invalidated_at_ms) = 'integer' AND invalidated_at_ms >= issued_at_ms)),
    expired_at_ms INTEGER CHECK (expired_at_ms IS NULL OR (typeof(expired_at_ms) = 'integer' AND expired_at_ms >= expires_at_ms)),
    consumed_operation_id TEXT CHECK (consumed_operation_id IS NULL OR (length(consumed_operation_id) BETWEEN 1 AND 128 AND consumed_operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    consumed_authenticated_peer_id TEXT CHECK (consumed_authenticated_peer_id IS NULL OR (length(consumed_authenticated_peer_id) BETWEEN 1 AND 255 AND consumed_authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 128 AND agent_version NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    last_decision_id TEXT NOT NULL UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    last_audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((challenge_state = 'pending' AND consumed_at_ms IS NULL AND invalidated_at_ms IS NULL AND expired_at_ms IS NULL AND consumed_operation_id IS NULL AND consumed_authenticated_peer_id IS NULL)
        OR (challenge_state = 'consumed' AND consumed_at_ms IS NOT NULL AND invalidated_at_ms IS NULL AND expired_at_ms IS NULL AND consumed_operation_id IS NOT NULL AND consumed_authenticated_peer_id IS NOT NULL)
        OR (challenge_state = 'invalidated' AND consumed_at_ms IS NULL AND invalidated_at_ms IS NOT NULL AND expired_at_ms IS NULL AND consumed_operation_id IS NULL AND consumed_authenticated_peer_id IS NULL)
        OR (challenge_state = 'expired' AND consumed_at_ms IS NULL AND invalidated_at_ms IS NULL AND expired_at_ms IS NOT NULL AND consumed_operation_id IS NULL AND consumed_authenticated_peer_id IS NULL))
,
    CHECK ((length(challenge_id) = 36 AND challenge_id = lower(challenge_id) AND substr(challenge_id,9,1) = '-' AND substr(challenge_id,14,1) = '-' AND substr(challenge_id,19,1) = '-' AND substr(challenge_id,24,1) = '-' AND replace(challenge_id,'-','') NOT GLOB '*[^0-9a-f]*' AND challenge_id <> '00000000-0000-0000-0000-000000000000') AND (length(binding_id) = 36 AND binding_id = lower(binding_id) AND substr(binding_id,9,1) = '-' AND substr(binding_id,14,1) = '-' AND substr(binding_id,19,1) = '-' AND substr(binding_id,24,1) = '-' AND replace(binding_id,'-','') NOT GLOB '*[^0-9a-f]*' AND binding_id <> '00000000-0000-0000-0000-000000000000') AND (length(network_id) = 36 AND network_id = lower(network_id) AND substr(network_id,9,1) = '-' AND substr(network_id,14,1) = '-' AND substr(network_id,19,1) = '-' AND substr(network_id,24,1) = '-' AND replace(network_id,'-','') NOT GLOB '*[^0-9a-f]*' AND network_id <> '00000000-0000-0000-0000-000000000000') AND (length(device_id) = 36 AND device_id = lower(device_id) AND substr(device_id,9,1) = '-' AND substr(device_id,14,1) = '-' AND substr(device_id,19,1) = '-' AND substr(device_id,24,1) = '-' AND replace(device_id,'-','') NOT GLOB '*[^0-9a-f]*' AND device_id <> '00000000-0000-0000-0000-000000000000') AND (length(join_session_id) = 36 AND join_session_id = lower(join_session_id) AND substr(join_session_id,9,1) = '-' AND substr(join_session_id,14,1) = '-' AND substr(join_session_id,19,1) = '-' AND substr(join_session_id,24,1) = '-' AND replace(join_session_id,'-','') NOT GLOB '*[^0-9a-f]*' AND join_session_id <> '00000000-0000-0000-0000-000000000000') AND (length(last_decision_id) = 36 AND last_decision_id = lower(last_decision_id) AND substr(last_decision_id,9,1) = '-' AND substr(last_decision_id,14,1) = '-' AND substr(last_decision_id,19,1) = '-' AND substr(last_decision_id,24,1) = '-' AND replace(last_decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND last_decision_id <> '00000000-0000-0000-0000-000000000000') AND (length(last_audit_event_id) = 36 AND last_audit_event_id = lower(last_audit_event_id) AND substr(last_audit_event_id,9,1) = '-' AND substr(last_audit_event_id,14,1) = '-' AND substr(last_audit_event_id,19,1) = '-' AND substr(last_audit_event_id,24,1) = '-' AND replace(last_audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND last_audit_event_id <> '00000000-0000-0000-0000-000000000000')));
CREATE UNIQUE INDEX n6_one_pending_challenge_per_binding ON n6_binding_challenges(binding_id) WHERE challenge_state = 'pending';

CREATE TABLE n6_binding_authorizations (
    authorization_id TEXT PRIMARY KEY CHECK (length(authorization_id) = 36 AND authorization_id = lower(authorization_id) AND substr(authorization_id,9,1) = '-' AND substr(authorization_id,14,1) = '-' AND substr(authorization_id,19,1) = '-' AND substr(authorization_id,24,1) = '-' AND replace(authorization_id,'-','') NOT GLOB '*[^0-9a-f]*' AND authorization_id <> '00000000-0000-0000-0000-000000000000'),
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(authority_id) = 36 AND authority_id = lower(authority_id) AND substr(authority_id,9,1) = '-' AND substr(authority_id,14,1) = '-' AND substr(authority_id,19,1) = '-' AND substr(authority_id,24,1) = '-' AND replace(authority_id,'-','') NOT GLOB '*[^0-9a-f]*' AND authority_id <> '00000000-0000-0000-0000-000000000000'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(network_id) = 36 AND network_id = lower(network_id) AND substr(network_id,9,1) = '-' AND substr(network_id,14,1) = '-' AND substr(network_id,19,1) = '-' AND substr(network_id,24,1) = '-' AND replace(network_id,'-','') NOT GLOB '*[^0-9a-f]*' AND network_id <> '00000000-0000-0000-0000-000000000000'),
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(device_id) = 36 AND device_id = lower(device_id) AND substr(device_id,9,1) = '-' AND substr(device_id,14,1) = '-' AND substr(device_id,19,1) = '-' AND substr(device_id,24,1) = '-' AND replace(device_id,'-','') NOT GLOB '*[^0-9a-f]*' AND device_id <> '00000000-0000-0000-0000-000000000000'),
    join_session_id TEXT NOT NULL REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
        CHECK (length(join_session_id) = 36 AND join_session_id = lower(join_session_id) AND substr(join_session_id,9,1) = '-' AND substr(join_session_id,14,1) = '-' AND substr(join_session_id,19,1) = '-' AND substr(join_session_id,24,1) = '-' AND replace(join_session_id,'-','') NOT GLOB '*[^0-9a-f]*' AND join_session_id <> '00000000-0000-0000-0000-000000000000'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    expected_revision INTEGER NOT NULL CHECK (typeof(expected_revision) = 'integer' AND expected_revision >= 1),
    action_kind TEXT NOT NULL CHECK (action_kind IN ('rotate','revoke')),
    actor_source TEXT NOT NULL CHECK (length(actor_source) BETWEEN 1 AND 64 AND actor_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    actor_id TEXT CHECK (actor_id IS NULL OR (length(actor_id) BETWEEN 1 AND 255 AND actor_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    issued_at_ms INTEGER NOT NULL CHECK (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > issued_at_ms),
    -- Every authorization has immutable issuance provenance. Inserts are
    -- deliberately acyclic: audit -> authorization/issue decision -> grant.
    issued_decision_id TEXT NOT NULL UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    issued_audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authorization_state TEXT NOT NULL CHECK (authorization_state IN ('pending','consumed','expired','invalidated')),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR (typeof(consumed_at_ms) = 'integer' AND consumed_at_ms >= issued_at_ms AND consumed_at_ms < expires_at_ms)),
    expired_at_ms INTEGER CHECK (expired_at_ms IS NULL OR (typeof(expired_at_ms) = 'integer' AND expired_at_ms >= expires_at_ms)),
    invalidated_at_ms INTEGER CHECK (invalidated_at_ms IS NULL OR (typeof(invalidated_at_ms) = 'integer' AND invalidated_at_ms >= issued_at_ms)),
    consumed_decision_id TEXT UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    consumed_audit_event_id TEXT UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    expired_decision_id TEXT UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    expired_audit_event_id TEXT UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    invalidated_decision_id TEXT UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    invalidated_audit_event_id TEXT UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((actor_source = 'nodescale' AND actor_id IS NULL) OR (actor_source <> 'nodescale' AND actor_id IS NOT NULL)),
    CHECK ((authorization_state = 'pending'
            AND consumed_at_ms IS NULL AND expired_at_ms IS NULL AND invalidated_at_ms IS NULL
            AND consumed_decision_id IS NULL AND consumed_audit_event_id IS NULL
            AND expired_decision_id IS NULL AND expired_audit_event_id IS NULL
            AND invalidated_decision_id IS NULL AND invalidated_audit_event_id IS NULL)
        OR (authorization_state = 'consumed'
            AND consumed_at_ms IS NOT NULL AND consumed_decision_id IS NOT NULL AND consumed_audit_event_id IS NOT NULL
            AND expired_at_ms IS NULL AND invalidated_at_ms IS NULL
            AND expired_decision_id IS NULL AND expired_audit_event_id IS NULL
            AND invalidated_decision_id IS NULL AND invalidated_audit_event_id IS NULL)
        OR (authorization_state = 'expired'
            AND expired_at_ms IS NOT NULL AND expired_decision_id IS NOT NULL AND expired_audit_event_id IS NOT NULL
            AND consumed_at_ms IS NULL AND invalidated_at_ms IS NULL
            AND consumed_decision_id IS NULL AND consumed_audit_event_id IS NULL
            AND invalidated_decision_id IS NULL AND invalidated_audit_event_id IS NULL)
        OR (authorization_state = 'invalidated'
            AND invalidated_at_ms IS NOT NULL AND invalidated_decision_id IS NOT NULL AND invalidated_audit_event_id IS NOT NULL
            AND consumed_at_ms IS NULL AND expired_at_ms IS NULL
            AND consumed_decision_id IS NULL AND consumed_audit_event_id IS NULL
            AND expired_decision_id IS NULL AND expired_audit_event_id IS NULL)),
    CHECK ((consumed_decision_id IS NULL OR (length(consumed_decision_id) = 36 AND consumed_decision_id = lower(consumed_decision_id) AND substr(consumed_decision_id,9,1) = '-' AND substr(consumed_decision_id,14,1) = '-' AND substr(consumed_decision_id,19,1) = '-' AND substr(consumed_decision_id,24,1) = '-' AND replace(consumed_decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND consumed_decision_id <> '00000000-0000-0000-0000-000000000000'))
        AND (consumed_audit_event_id IS NULL OR (length(consumed_audit_event_id) = 36 AND consumed_audit_event_id = lower(consumed_audit_event_id) AND substr(consumed_audit_event_id,9,1) = '-' AND substr(consumed_audit_event_id,14,1) = '-' AND substr(consumed_audit_event_id,19,1) = '-' AND substr(consumed_audit_event_id,24,1) = '-' AND replace(consumed_audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND consumed_audit_event_id <> '00000000-0000-0000-0000-000000000000'))
        AND (expired_decision_id IS NULL OR (length(expired_decision_id) = 36 AND expired_decision_id = lower(expired_decision_id) AND substr(expired_decision_id,9,1) = '-' AND substr(expired_decision_id,14,1) = '-' AND substr(expired_decision_id,19,1) = '-' AND substr(expired_decision_id,24,1) = '-' AND replace(expired_decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND expired_decision_id <> '00000000-0000-0000-0000-000000000000'))
        AND (expired_audit_event_id IS NULL OR (length(expired_audit_event_id) = 36 AND expired_audit_event_id = lower(expired_audit_event_id) AND substr(expired_audit_event_id,9,1) = '-' AND substr(expired_audit_event_id,14,1) = '-' AND substr(expired_audit_event_id,19,1) = '-' AND substr(expired_audit_event_id,24,1) = '-' AND replace(expired_audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND expired_audit_event_id <> '00000000-0000-0000-0000-000000000000'))
        AND (invalidated_decision_id IS NULL OR (length(invalidated_decision_id) = 36 AND invalidated_decision_id = lower(invalidated_decision_id) AND substr(invalidated_decision_id,9,1) = '-' AND substr(invalidated_decision_id,14,1) = '-' AND substr(invalidated_decision_id,19,1) = '-' AND substr(invalidated_decision_id,24,1) = '-' AND replace(invalidated_decision_id,'-','') NOT GLOB '*[^0-9a-f]*' AND invalidated_decision_id <> '00000000-0000-0000-0000-000000000000'))
        AND (invalidated_audit_event_id IS NULL OR (length(invalidated_audit_event_id) = 36 AND invalidated_audit_event_id = lower(invalidated_audit_event_id) AND substr(invalidated_audit_event_id,9,1) = '-' AND substr(invalidated_audit_event_id,14,1) = '-' AND substr(invalidated_audit_event_id,19,1) = '-' AND substr(invalidated_audit_event_id,24,1) = '-' AND replace(invalidated_audit_event_id,'-','') NOT GLOB '*[^0-9a-f]*' AND invalidated_audit_event_id <> '00000000-0000-0000-0000-000000000000'))));
CREATE UNIQUE INDEX n6_one_pending_authorization_per_action ON n6_binding_authorizations(binding_id, action_kind) WHERE authorization_state = 'pending';

CREATE TRIGGER n6_decision_exact_provenance
BEFORE INSERT ON n6_binding_decisions
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_device_identities i
    JOIN n4_join_session_dispatches s ON s.join_session_id = NEW.join_session_id
    JOIN audit_events a ON a.event_id = NEW.audit_event_id
    WHERE i.device_id = NEW.device_id
      AND i.network_id = NEW.network_id
      AND i.origin_join_session_id = NEW.join_session_id
      AND s.network_id = NEW.network_id
      AND s.dispatch_state = 'confirmed'
      AND a.network_id = NEW.network_id
      AND a.device_id = NEW.device_id
      -- Audit actor is the business actor that made the decision, not the recorder.
      AND a.actor_source = NEW.actor_source
      AND a.actor_id IS NEW.actor_id
      AND a.generation = NEW.generation
      AND ((NEW.subject_kind = 'binding' AND NEW.decision_kind = 'issue' AND a.event_kind = 'keryx_binding_pending' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'issue' AND a.event_kind = 'keryx_binding_nonce_issued' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'confirm' AND a.event_kind = 'keryx_binding_attempted' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'binding' AND NEW.decision_kind = 'confirm' AND a.event_kind = 'keryx_binding_confirmed' AND a.outcome = 'success')
        OR (NEW.subject_kind IN ('binding','challenge') AND NEW.decision_kind = 'replay' AND a.event_kind = 'keryx_binding_replay' AND a.outcome = 'idempotent')
        OR (NEW.subject_kind IN ('binding','challenge') AND NEW.decision_kind = 'conflict' AND a.event_kind = 'keryx_binding_conflict' AND a.outcome = 'rejected')
        OR (NEW.subject_kind = 'binding' AND NEW.decision_kind = 'stale' AND a.event_kind = 'keryx_binding_staled' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'binding' AND NEW.decision_kind = 'rotate' AND a.event_kind = 'keryx_binding_rotated' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'binding' AND NEW.decision_kind = 'revoke' AND a.event_kind = 'keryx_binding_revoked' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'expire' AND a.event_kind = 'keryx_binding_nonce_expired' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'invalidate' AND a.event_kind = 'keryx_binding_nonce_invalidated' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'authorization' AND NEW.decision_kind = 'issue' AND a.event_kind = 'keryx_binding_authorization_issued' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'authorization' AND NEW.decision_kind = 'expire' AND a.event_kind = 'keryx_binding_authorization_expired' AND a.outcome = 'success')
        OR (NEW.subject_kind = 'authorization' AND NEW.decision_kind = 'invalidate' AND a.event_kind = 'keryx_binding_authorization_invalidated' AND a.outcome = 'success'))
      AND NOT EXISTS (
          SELECT 1
          FROM json_tree(a.metadata_json) AS metadata
          WHERE (metadata.type = 'text' AND (
                    (length(metadata.value) = 50
                        AND substr(metadata.value, 1, 7) = 'nsbind_'
                        AND substr(metadata.value, 8, 43) NOT GLOB '*[^A-Za-z0-9_-]*'
                        AND substr(metadata.value, 50, 1) GLOB '[AEIMQUYcgkosw048]')
                    OR substr(metadata.value, 1, length('$argon2id$v=19$m=19456,t=2,p=1$')) = '$argon2id$v=19$m=19456,t=2,p=1$'
                ))
             OR (typeof(metadata.key) = 'text' AND (
                    (length(metadata.key) = 50
                        AND substr(metadata.key, 1, 7) = 'nsbind_'
                        AND substr(metadata.key, 8, 43) NOT GLOB '*[^A-Za-z0-9_-]*'
                        AND substr(metadata.key, 50, 1) GLOB '[AEIMQUYcgkosw048]')
                    OR substr(metadata.key, 1, length('$argon2id$v=19$m=19456,t=2,p=1$')) = '$argon2id$v=19$m=19456,t=2,p=1$'
                ))
      )
)
BEGIN SELECT RAISE(ABORT, 'N6 decision requires exact N5 identity, confirmed N4 session, semantic audit, and public metadata'); END;

-- A success decision may be written only while the exact subject snapshot is
-- still live. This makes a transaction that lost a competing transition fail
-- before it can retain success evidence.
CREATE TRIGGER n6_decision_live_subject_fence
BEFORE INSERT ON n6_binding_decisions
FOR EACH ROW WHEN (
    (NEW.subject_kind = 'challenge' AND NEW.decision_kind IN ('confirm','expire','invalidate') AND NOT EXISTS (
        SELECT 1 FROM n6_binding_challenges c
        WHERE c.challenge_id = NEW.challenge_id AND c.binding_id = NEW.binding_id
          AND c.network_id = NEW.network_id AND c.device_id = NEW.device_id
          AND c.join_session_id = NEW.join_session_id AND c.generation = NEW.generation
          AND c.challenge_state = 'pending'
          AND NEW.prior_state = 'pending' AND NEW.prior_revision = 1
          AND ((NEW.decision_kind = 'confirm' AND NEW.decided_at_ms >= c.issued_at_ms AND NEW.decided_at_ms < c.expires_at_ms)
            OR (NEW.decision_kind = 'expire' AND NEW.decided_at_ms >= c.expires_at_ms)
            OR (NEW.decision_kind = 'invalidate' AND NEW.decided_at_ms >= c.issued_at_ms
                AND NEW.actor_source = 'nodescale' AND NEW.actor_id IS NULL))
    ))
    OR (NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'conflict' AND NOT EXISTS (
        SELECT 1 FROM n6_binding_challenges c
        WHERE c.challenge_id = NEW.challenge_id AND c.binding_id = NEW.binding_id
          AND c.network_id = NEW.network_id AND c.device_id = NEW.device_id
          AND c.join_session_id = NEW.join_session_id AND c.generation = NEW.generation
          AND c.challenge_state = NEW.prior_state
          AND NEW.new_state = NEW.prior_state
          AND NEW.prior_revision = CASE WHEN c.challenge_state = 'pending' THEN 1 ELSE 2 END
          AND NEW.new_revision = NEW.prior_revision
    ))
    OR (NEW.subject_kind = 'authorization' AND NEW.decision_kind IN ('expire','invalidate') AND NOT EXISTS (
        SELECT 1 FROM n6_binding_authorizations z
        WHERE z.authorization_id = NEW.authorization_id AND z.binding_id = NEW.binding_id
          AND z.network_id = NEW.network_id AND z.device_id = NEW.device_id
          AND z.join_session_id = NEW.join_session_id AND z.generation = NEW.generation
          AND z.authorization_state = 'pending'
          AND NEW.prior_state = 'pending' AND NEW.prior_revision = z.expected_revision
          AND ((NEW.decision_kind = 'expire' AND NEW.decided_at_ms >= z.expires_at_ms
                AND NEW.actor_source = z.actor_source AND NEW.actor_id IS z.actor_id)
            OR (NEW.decision_kind = 'invalidate' AND NEW.decided_at_ms >= z.issued_at_ms
                AND ((NEW.actor_source = z.actor_source AND NEW.actor_id IS z.actor_id)
                  OR (NEW.actor_source = 'nodescale' AND NEW.actor_id IS NULL))))
    ))
    OR (NEW.subject_kind = 'binding' AND NEW.decision_kind IN ('confirm','replay','conflict','stale','rotate','revoke') AND NOT EXISTS (
        SELECT 1 FROM n6_binding_records b
        WHERE b.binding_id = NEW.binding_id AND b.network_id = NEW.network_id
          AND b.device_id = NEW.device_id AND b.join_session_id = NEW.join_session_id
          AND b.generation = NEW.generation AND b.binding_state = NEW.prior_state
          AND b.revision = NEW.prior_revision
    ))
)
BEGIN SELECT RAISE(ABORT, 'N6 success decision requires an exact live subject state and revision'); END;

CREATE TRIGGER n6_binding_confirm_requires_consumed_challenge
BEFORE INSERT ON n6_binding_decisions
FOR EACH ROW WHEN NEW.subject_kind = 'binding' AND NEW.decision_kind = 'confirm' AND NOT EXISTS (
    SELECT 1
    FROM n6_binding_challenges c
    JOIN n6_binding_decisions consumed ON consumed.decision_id = c.last_decision_id
    JOIN audit_events consumed_audit ON consumed_audit.event_id = c.last_audit_event_id
    WHERE c.challenge_id = NEW.challenge_id
      AND c.binding_id = NEW.binding_id
      AND c.network_id = NEW.network_id
      AND c.device_id = NEW.device_id
      AND c.join_session_id = NEW.join_session_id
      AND c.generation = NEW.generation
      AND c.challenge_state = 'consumed'
      AND c.consumed_authenticated_peer_id = NEW.authenticated_peer_id
      AND c.consumed_operation_id = NEW.operation_id
      AND c.consumed_at_ms <= NEW.decided_at_ms
      AND consumed.audit_event_id = c.last_audit_event_id
      AND consumed.subject_kind = 'challenge'
      AND consumed.decision_kind = 'confirm'
      AND consumed.binding_id = c.binding_id
      AND consumed.challenge_id = c.challenge_id
      AND consumed.network_id = c.network_id
      AND consumed.device_id = c.device_id
      AND consumed.join_session_id = c.join_session_id
      AND consumed.generation = c.generation
      AND consumed.prior_state = 'pending'
      AND consumed.new_state = 'consumed'
      AND consumed.prior_revision = 1
      AND consumed.new_revision = 2
      AND consumed.decided_at_ms = c.consumed_at_ms
      AND consumed.authenticated_peer_id = c.consumed_authenticated_peer_id
      AND consumed.operation_id = c.consumed_operation_id
      AND consumed.agent_version = c.agent_version
      AND consumed_audit.network_id = c.network_id
      AND consumed_audit.device_id = c.device_id
      AND consumed_audit.generation = c.generation
)
BEGIN SELECT RAISE(ABORT, 'N6 binding confirmation requires one exact consumed challenge provenance'); END;

CREATE TRIGGER n6_replay_decision_requires_consumed_challenge
BEFORE INSERT ON n6_binding_decisions
FOR EACH ROW WHEN NEW.subject_kind = 'challenge' AND NEW.decision_kind = 'replay' AND NOT EXISTS (
    SELECT 1
    FROM n6_binding_challenges c
    JOIN n6_binding_decisions consumed ON consumed.decision_id = c.last_decision_id
    WHERE NEW.subject_kind = 'challenge'
      AND NEW.challenge_id IS NOT NULL
      AND c.challenge_id = NEW.challenge_id
      AND c.binding_id = NEW.binding_id
      AND c.network_id = NEW.network_id
      AND c.device_id = NEW.device_id
      AND c.join_session_id = NEW.join_session_id
      AND c.generation = NEW.generation
      AND c.challenge_state = 'consumed'
      AND c.consumed_authenticated_peer_id = NEW.authenticated_peer_id
      AND c.consumed_operation_id = NEW.operation_id
      AND c.agent_version = NEW.agent_version
      AND NEW.decided_at_ms >= c.consumed_at_ms
      AND consumed.audit_event_id = c.last_audit_event_id
      AND consumed.subject_kind = 'challenge'
      AND consumed.decision_kind = 'confirm'
      AND consumed.binding_id = c.binding_id
      AND consumed.challenge_id = c.challenge_id
      AND consumed.network_id = c.network_id
      AND consumed.device_id = c.device_id
      AND consumed.join_session_id = c.join_session_id
      AND consumed.generation = c.generation
      AND consumed.prior_state = 'pending'
      AND consumed.new_state = 'consumed'
      AND consumed.prior_revision = 1
      AND consumed.new_revision = 2
      AND consumed.decided_at_ms = c.consumed_at_ms
      AND consumed.authenticated_peer_id = c.consumed_authenticated_peer_id
      AND consumed.operation_id = c.consumed_operation_id
      AND consumed.agent_version = c.agent_version
      AND NEW.prior_state = consumed.new_state
      AND NEW.new_state = consumed.new_state
      AND NEW.prior_revision = consumed.new_revision
      AND NEW.new_revision = consumed.new_revision
)
BEGIN SELECT RAISE(ABORT, 'N6 replay decision requires one exact consumed challenge provenance'); END;

CREATE TRIGGER n6_binding_insert_requires_issue_decision
BEFORE INSERT ON n6_binding_records
FOR EACH ROW WHEN NEW.binding_state <> 'pending'
    OR NEW.revision <> 1
    OR NOT EXISTS (
        SELECT 1 FROM n5_device_identities i
        JOIN n4_join_session_dispatches s ON s.join_session_id = NEW.join_session_id
        JOIN n6_binding_decisions d ON d.decision_id = NEW.last_decision_id
        WHERE i.device_id = NEW.device_id
          AND i.network_id = NEW.network_id
          AND i.origin_join_session_id = NEW.join_session_id
          AND s.network_id = NEW.network_id
          AND s.dispatch_state = 'confirmed'
          AND d.audit_event_id = NEW.last_audit_event_id
          AND d.subject_kind = 'binding'
          AND d.decision_kind = 'issue'
          AND d.binding_id = NEW.binding_id
          AND d.network_id = NEW.network_id
          AND d.device_id = NEW.device_id
          AND d.join_session_id = NEW.join_session_id
          AND d.generation = NEW.generation
          AND d.new_state = 'pending'
          AND d.new_revision = NEW.revision
          AND d.decided_at_ms = NEW.created_at_ms
          AND d.agent_version = NEW.agent_version
    )
    OR (NEW.generation > 1 AND NOT EXISTS (
        SELECT 1
        FROM n6_binding_records p
        JOIN n6_binding_authorizations z ON z.authorization_id = NEW.rotation_authorization_id
        JOIN n5_trust_authorities a ON a.authority_id = z.authority_id
        WHERE p.binding_id = NEW.rotated_from_binding_id
          AND p.network_id = NEW.network_id
          AND p.device_id = NEW.device_id
          AND p.join_session_id = NEW.join_session_id
          AND p.generation = NEW.generation - 1
          AND p.binding_state IN ('active','stale')
          AND z.binding_id = p.binding_id
          AND z.network_id = p.network_id
          AND z.device_id = p.device_id
          AND z.join_session_id = p.join_session_id
          AND z.generation = p.generation
          AND z.expected_revision = p.revision
          AND z.action_kind = 'rotate'
          AND z.authorization_state = 'pending'
          AND z.consumed_at_ms IS NULL
          AND z.consumed_decision_id IS NULL
          AND z.consumed_audit_event_id IS NULL
          AND a.network_id = NEW.network_id
          AND a.sealed = 1
          AND a.enabled = 1
          AND a.revoked_at_ms IS NULL
    ))
BEGIN SELECT RAISE(ABORT, 'N6 successor binding requires one exact open rotate authorization'); END;

CREATE TRIGGER n6_binding_transition_guard
BEFORE UPDATE ON n6_binding_records
FOR EACH ROW WHEN NEW.binding_id <> OLD.binding_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.device_id <> OLD.device_id
    OR NEW.join_session_id <> OLD.join_session_id
    OR NEW.generation <> OLD.generation
    OR (OLD.verified_peer_id IS NOT NULL AND NEW.verified_peer_id IS NOT OLD.verified_peer_id)
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR (OLD.confirmed_at_ms IS NOT NULL AND NEW.confirmed_at_ms IS NOT OLD.confirmed_at_ms)
    OR (OLD.last_verified_at_ms IS NOT NULL AND NEW.last_verified_at_ms IS NOT OLD.last_verified_at_ms)
    OR (OLD.stale_at_ms IS NOT NULL AND NEW.stale_at_ms IS NOT OLD.stale_at_ms)
    OR (OLD.stale_at_ms IS NULL AND NEW.stale_at_ms IS NOT NULL
        AND NOT (OLD.binding_state = 'active' AND NEW.binding_state = 'stale'))
    OR (OLD.rotated_at_ms IS NOT NULL AND NEW.rotated_at_ms IS NOT OLD.rotated_at_ms)
    OR (OLD.revoked_at_ms IS NOT NULL AND NEW.revoked_at_ms IS NOT OLD.revoked_at_ms)
    OR NEW.rotated_from_binding_id IS NOT OLD.rotated_from_binding_id
    OR NEW.rotation_authorization_id IS NOT OLD.rotation_authorization_id
    OR NEW.revision <> OLD.revision + 1
    OR NEW.last_decision_id = OLD.last_decision_id
    OR NEW.last_audit_event_id = OLD.last_audit_event_id
    OR NOT ((OLD.binding_state = 'pending' AND NEW.binding_state IN ('active','revoked'))
        OR (OLD.binding_state = 'active' AND NEW.binding_state IN ('stale','rotated','revoked'))
        OR (OLD.binding_state = 'stale' AND NEW.binding_state IN ('rotated','revoked')))
    OR NOT EXISTS (
        SELECT 1 FROM n6_binding_decisions d
        WHERE d.decision_id = NEW.last_decision_id
          AND d.audit_event_id = NEW.last_audit_event_id
          AND d.subject_kind = 'binding'
          AND d.binding_id = OLD.binding_id
          AND d.network_id = OLD.network_id
          AND d.device_id = OLD.device_id
          AND d.join_session_id = OLD.join_session_id
          AND d.generation = OLD.generation
          AND d.prior_state = OLD.binding_state
          AND d.new_state = NEW.binding_state
          AND d.prior_revision = OLD.revision
          AND d.new_revision = NEW.revision
          AND d.agent_version = NEW.agent_version
          AND ((NEW.binding_state = 'active' AND d.decision_kind = 'confirm' AND d.authorization_id IS NULL
                AND d.decided_at_ms = NEW.confirmed_at_ms AND d.authenticated_peer_id = NEW.verified_peer_id
                AND (NEW.generation = 1 OR EXISTS (
                    SELECT 1
                    FROM n6_binding_records p
                    JOIN n6_binding_authorizations z ON z.authorization_id = NEW.rotation_authorization_id
                    JOIN n6_binding_decisions r ON r.decision_id = z.consumed_decision_id
                    WHERE p.binding_id = NEW.rotated_from_binding_id
                      AND p.binding_state = 'rotated'
                      AND p.last_decision_id = z.consumed_decision_id
                      AND p.last_audit_event_id = z.consumed_audit_event_id
                      AND z.binding_id = p.binding_id
                      AND z.network_id = OLD.network_id
                      AND z.device_id = OLD.device_id
                      AND z.join_session_id = OLD.join_session_id
                      AND z.generation = OLD.generation - 1
                      AND z.action_kind = 'rotate'
                      AND r.decision_kind = 'rotate'
                      AND r.authorization_id = z.authorization_id
                )))
            OR (NEW.binding_state = 'stale' AND d.decision_kind = 'stale' AND d.authorization_id IS NULL AND d.decided_at_ms = NEW.stale_at_ms)
            OR (NEW.binding_state IN ('rotated','revoked')
                AND d.decision_kind = CASE NEW.binding_state WHEN 'rotated' THEN 'rotate' ELSE 'revoke' END
                AND d.authorization_id IS NOT NULL
                AND d.decided_at_ms = CASE NEW.binding_state WHEN 'rotated' THEN NEW.rotated_at_ms ELSE NEW.revoked_at_ms END
                AND EXISTS (
                    SELECT 1 FROM n6_binding_authorizations z
                    WHERE z.authorization_id = d.authorization_id
                      AND z.binding_id = OLD.binding_id
                      AND z.network_id = OLD.network_id
                      AND z.device_id = OLD.device_id
                      AND z.join_session_id = OLD.join_session_id
                      AND z.generation = OLD.generation
                      AND z.expected_revision = OLD.revision
                      AND z.action_kind = d.decision_kind
                      AND z.consumed_at_ms = d.decided_at_ms
                      AND z.consumed_decision_id = d.decision_id
                      AND z.consumed_audit_event_id = d.audit_event_id
                )))
    )
BEGIN SELECT RAISE(ABORT, 'N6 binding transition requires a fresh exact decision'); END;
CREATE TRIGGER n6_binding_immutable_delete
BEFORE DELETE ON n6_binding_records
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 binding records are append-only'); END;

CREATE TRIGGER n6_challenge_insert_guard
BEFORE INSERT ON n6_binding_challenges
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n6_binding_records b
    JOIN n6_binding_decisions d ON d.decision_id = NEW.last_decision_id
    WHERE b.binding_id = NEW.binding_id
      AND b.network_id = NEW.network_id
      AND b.device_id = NEW.device_id
      AND b.join_session_id = NEW.join_session_id
      AND b.generation = NEW.generation
      AND b.binding_state = 'pending'
      AND d.audit_event_id = NEW.last_audit_event_id
      AND d.subject_kind = 'challenge'
      AND d.decision_kind = 'issue'
      AND d.binding_id = NEW.binding_id
      AND d.challenge_id = NEW.challenge_id
      AND d.network_id = NEW.network_id
      AND d.device_id = NEW.device_id
      AND d.join_session_id = NEW.join_session_id
      AND d.generation = NEW.generation
      AND d.new_state = 'pending'
      AND d.decided_at_ms = NEW.issued_at_ms
      AND d.agent_version = NEW.agent_version
)
BEGIN SELECT RAISE(ABORT, 'N6 challenge requires matching pending binding and issue decision'); END;

CREATE TRIGGER n6_challenge_transition_guard
BEFORE UPDATE ON n6_binding_challenges
FOR EACH ROW WHEN NEW.challenge_id <> OLD.challenge_id
    OR NEW.binding_id <> OLD.binding_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.device_id <> OLD.device_id
    OR NEW.join_session_id <> OLD.join_session_id
    OR NEW.expected_authenticated_peer_id <> OLD.expected_authenticated_peer_id
    OR NEW.generation <> OLD.generation
    OR NEW.challenge_verifier <> OLD.challenge_verifier
    OR NEW.issued_at_ms <> OLD.issued_at_ms
    OR NEW.expires_at_ms <> OLD.expires_at_ms
    OR NEW.agent_version <> OLD.agent_version
    OR OLD.challenge_state <> 'pending'
    OR NEW.last_decision_id = OLD.last_decision_id
    OR NEW.last_audit_event_id = OLD.last_audit_event_id
    OR NOT ((NEW.challenge_state = 'consumed' AND NEW.consumed_authenticated_peer_id = OLD.expected_authenticated_peer_id)
        OR NEW.challenge_state IN ('invalidated','expired'))
    OR NOT EXISTS (
        SELECT 1 FROM n6_binding_decisions d
        WHERE d.decision_id = NEW.last_decision_id
          AND d.audit_event_id = NEW.last_audit_event_id
          AND d.subject_kind = 'challenge'
          AND d.binding_id = OLD.binding_id
          AND d.challenge_id = OLD.challenge_id
          AND d.network_id = OLD.network_id
          AND d.device_id = OLD.device_id
          AND d.join_session_id = OLD.join_session_id
          AND d.generation = OLD.generation
          AND d.prior_state = OLD.challenge_state
          AND d.new_state = NEW.challenge_state
          AND d.prior_revision = 1
          AND d.new_revision = 2
          AND ((NEW.challenge_state = 'consumed' AND d.decision_kind = 'confirm' AND d.decided_at_ms = NEW.consumed_at_ms AND d.operation_id = NEW.consumed_operation_id AND d.authenticated_peer_id = NEW.consumed_authenticated_peer_id)
            OR (NEW.challenge_state = 'invalidated' AND d.decision_kind = 'invalidate' AND d.decided_at_ms = NEW.invalidated_at_ms)
            OR (NEW.challenge_state = 'expired' AND d.decision_kind = 'expire' AND d.decided_at_ms = NEW.expired_at_ms))
    )
BEGIN SELECT RAISE(ABORT, 'N6 challenge transition requires one exact settlement decision'); END;
CREATE TRIGGER n6_challenge_immutable_delete
BEFORE DELETE ON n6_binding_challenges
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 challenges are append-only'); END;

CREATE TRIGGER n6_authorization_insert_guard
BEFORE INSERT ON n6_binding_authorizations
FOR EACH ROW WHEN NEW.authorization_state <> 'pending'
    OR NEW.issued_decision_id IS NULL OR NEW.issued_audit_event_id IS NULL
    OR NEW.consumed_at_ms IS NOT NULL OR NEW.expired_at_ms IS NOT NULL OR NEW.invalidated_at_ms IS NOT NULL
    OR NEW.consumed_decision_id IS NOT NULL OR NEW.consumed_audit_event_id IS NOT NULL
    OR NEW.expired_decision_id IS NOT NULL OR NEW.expired_audit_event_id IS NOT NULL
    OR NEW.invalidated_decision_id IS NOT NULL OR NEW.invalidated_audit_event_id IS NOT NULL
    OR NOT EXISTS (
        SELECT 1
        FROM n6_binding_records b
        JOIN n5_trust_authorities a ON a.authority_id = NEW.authority_id
        JOIN n5_owner_trust_roots r ON r.trust_root_id = a.trust_root_id
        JOIN n6_binding_authority_capabilities c
          ON c.authority_id = NEW.authority_id AND c.capability = NEW.action_kind
        WHERE b.binding_id = NEW.binding_id
          AND b.network_id = NEW.network_id
          AND b.device_id = NEW.device_id
          AND b.join_session_id = NEW.join_session_id
          AND b.generation = NEW.generation
          AND b.revision = NEW.expected_revision
          AND ((NEW.action_kind = 'rotate' AND b.binding_state IN ('active','stale'))
            OR (NEW.action_kind = 'revoke' AND b.binding_state IN ('pending','active','stale')))
          AND a.network_id = NEW.network_id
          AND a.principal_source = NEW.actor_source
          AND a.principal_id = NEW.actor_id
          AND a.sealed = 1
          AND a.enabled = 1
          AND a.revoked_at_ms IS NULL
          AND r.network_id = a.network_id
          AND r.principal_source = a.principal_source
          AND r.principal_id = a.principal_id
          AND r.enabled = 1
          AND r.revoked_at_ms IS NULL
          AND NEW.issued_at_ms >= a.not_before_ms
          AND NEW.issued_at_ms < a.expires_at_ms
          AND NEW.expires_at_ms <= a.expires_at_ms
          AND EXISTS (
              SELECT 1 FROM n6_binding_decisions d
              JOIN audit_events e ON e.event_id = NEW.issued_audit_event_id
              WHERE d.decision_id = NEW.issued_decision_id
                AND d.audit_event_id = NEW.issued_audit_event_id
                AND d.subject_kind = 'authorization' AND d.decision_kind = 'issue'
                AND d.authorization_id = NEW.authorization_id
                AND d.prior_state IS NULL AND d.prior_revision IS NULL
                AND d.new_state = 'pending' AND d.new_revision = 1
                AND d.binding_id = NEW.binding_id AND d.network_id = NEW.network_id
                AND d.device_id = NEW.device_id AND d.join_session_id = NEW.join_session_id
                AND d.generation = NEW.generation AND d.decided_at_ms = NEW.issued_at_ms
                AND d.actor_source = NEW.actor_source AND d.actor_id IS NEW.actor_id
                AND e.network_id = NEW.network_id AND e.device_id = NEW.device_id
                AND e.generation = NEW.generation AND e.actor_source = NEW.actor_source
                AND e.actor_id IS NEW.actor_id
                AND e.event_kind = 'keryx_binding_authorization_issued' AND e.outcome = 'success'
          )
    )
BEGIN SELECT RAISE(ABORT, 'N6 authorization requires a pending exact current binding, dedicated capability, and live N5 authority'); END;

CREATE TRIGGER n6_authorization_consumption_guard
BEFORE UPDATE ON n6_binding_authorizations
FOR EACH ROW WHEN NEW.authorization_id <> OLD.authorization_id
    OR NEW.authority_id <> OLD.authority_id
    OR NEW.binding_id <> OLD.binding_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.device_id <> OLD.device_id
    OR NEW.join_session_id <> OLD.join_session_id
    OR NEW.generation <> OLD.generation
    OR NEW.expected_revision <> OLD.expected_revision
    OR NEW.action_kind <> OLD.action_kind
    OR NEW.actor_source <> OLD.actor_source
    OR NEW.actor_id IS NOT OLD.actor_id
    OR NEW.issued_at_ms <> OLD.issued_at_ms
    OR NEW.expires_at_ms <> OLD.expires_at_ms
    OR NEW.issued_decision_id <> OLD.issued_decision_id
    OR NEW.issued_audit_event_id <> OLD.issued_audit_event_id
    OR OLD.authorization_state <> 'pending'
    OR NOT (
        (NEW.authorization_state = 'consumed'
            AND NEW.expired_at_ms IS NULL AND NEW.invalidated_at_ms IS NULL
            AND NEW.expired_decision_id IS NULL AND NEW.expired_audit_event_id IS NULL
            AND NEW.invalidated_decision_id IS NULL AND NEW.invalidated_audit_event_id IS NULL
            AND EXISTS (
                SELECT 1 FROM n6_binding_decisions d
                JOIN n5_trust_authorities a ON a.authority_id = OLD.authority_id
                JOIN n5_owner_trust_roots r ON r.trust_root_id = a.trust_root_id
                JOIN n6_binding_authority_capabilities c
                  ON c.authority_id = OLD.authority_id AND c.capability = OLD.action_kind
                WHERE d.decision_id = NEW.consumed_decision_id
                  AND d.audit_event_id = NEW.consumed_audit_event_id
                  AND d.subject_kind = 'binding'
                  AND d.decision_kind = OLD.action_kind
                  AND d.binding_id = OLD.binding_id
                  AND d.authorization_id = OLD.authorization_id
                  AND d.network_id = OLD.network_id
                  AND d.device_id = OLD.device_id
                  AND d.join_session_id = OLD.join_session_id
                  AND d.generation = OLD.generation
                  AND d.prior_state IN ('pending','active','stale')
                  AND d.prior_revision = OLD.expected_revision
                  AND d.new_revision = OLD.expected_revision + 1
                  AND d.actor_source = OLD.actor_source
                  AND d.actor_id IS OLD.actor_id
                  AND d.decided_at_ms = NEW.consumed_at_ms
                  AND d.decided_at_ms >= OLD.issued_at_ms
                  AND d.decided_at_ms < OLD.expires_at_ms
                  AND EXISTS (
                      SELECT 1 FROM n6_binding_records b
                      WHERE b.binding_id = OLD.binding_id AND b.network_id = OLD.network_id
                        AND b.device_id = OLD.device_id AND b.join_session_id = OLD.join_session_id
                        AND b.generation = OLD.generation AND b.revision = OLD.expected_revision
                        AND b.binding_state = d.prior_state
                        AND ((OLD.action_kind = 'rotate' AND b.binding_state IN ('active','stale'))
                          OR (OLD.action_kind = 'revoke' AND b.binding_state IN ('pending','active','stale')))
                  )
                  AND a.network_id = OLD.network_id
                  AND a.sealed = 1 AND a.enabled = 1 AND a.revoked_at_ms IS NULL
                  AND r.network_id = a.network_id
                  AND r.principal_source = a.principal_source
                  AND r.principal_id = a.principal_id
                  AND r.enabled = 1 AND r.revoked_at_ms IS NULL
                  AND d.decided_at_ms >= a.not_before_ms AND d.decided_at_ms < a.expires_at_ms
            ))
        OR (NEW.authorization_state = 'expired'
            AND NEW.consumed_at_ms IS NULL AND NEW.invalidated_at_ms IS NULL
            AND NEW.consumed_decision_id IS NULL AND NEW.consumed_audit_event_id IS NULL
            AND NEW.invalidated_decision_id IS NULL AND NEW.invalidated_audit_event_id IS NULL
            AND EXISTS (
                SELECT 1 FROM n6_binding_decisions d
                WHERE d.decision_id = NEW.expired_decision_id
                  AND d.audit_event_id = NEW.expired_audit_event_id
                  AND d.subject_kind = 'authorization'
                  AND d.decision_kind = 'expire'
                  AND d.binding_id = OLD.binding_id
                  AND d.authorization_id = OLD.authorization_id
                  AND d.network_id = OLD.network_id
                  AND d.device_id = OLD.device_id
                  AND d.join_session_id = OLD.join_session_id
                  AND d.generation = OLD.generation
                  AND d.prior_state = 'pending' AND d.new_state = 'expired'
                  AND d.prior_revision = OLD.expected_revision AND d.new_revision = OLD.expected_revision + 1
                  AND d.actor_source = OLD.actor_source AND d.actor_id IS OLD.actor_id
                  AND d.decided_at_ms = NEW.expired_at_ms AND d.decided_at_ms >= OLD.expires_at_ms
            ))
        OR (NEW.authorization_state = 'invalidated'
            AND NEW.consumed_at_ms IS NULL AND NEW.expired_at_ms IS NULL
            AND NEW.consumed_decision_id IS NULL AND NEW.consumed_audit_event_id IS NULL
            AND NEW.expired_decision_id IS NULL AND NEW.expired_audit_event_id IS NULL
            AND EXISTS (
                SELECT 1 FROM n6_binding_decisions d
                WHERE d.decision_id = NEW.invalidated_decision_id
                  AND d.audit_event_id = NEW.invalidated_audit_event_id
                  AND d.subject_kind = 'authorization'
                  AND d.decision_kind = 'invalidate'
                  AND d.binding_id = OLD.binding_id
                  AND d.authorization_id = OLD.authorization_id
                  AND d.network_id = OLD.network_id
                  AND d.device_id = OLD.device_id
                  AND d.join_session_id = OLD.join_session_id
                  AND d.generation = OLD.generation
                  AND d.prior_state = 'pending' AND d.new_state = 'invalidated'
                  AND d.prior_revision = OLD.expected_revision AND d.new_revision = OLD.expected_revision + 1
                  AND d.decided_at_ms = NEW.invalidated_at_ms AND d.decided_at_ms >= OLD.issued_at_ms
                  AND ((d.actor_source = OLD.actor_source AND d.actor_id IS OLD.actor_id)
                    OR (d.actor_source = 'nodescale' AND d.actor_id IS NULL))
            ))
    )
BEGIN SELECT RAISE(ABORT, 'N6 authorization transition requires one exact pending settlement decision'); END;
CREATE TRIGGER n6_authorization_immutable_delete
BEFORE DELETE ON n6_binding_authorizations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 authorizations are append-only'); END;

CREATE TRIGGER n6_decision_immutable_update
BEFORE UPDATE ON n6_binding_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 decisions are append-only'); END;
CREATE TRIGGER n6_decision_immutable_delete
BEFORE DELETE ON n6_binding_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 decisions are append-only'); END;

CREATE TRIGGER n6_audit_immutable_update
BEFORE UPDATE ON audit_events
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM n6_binding_decisions d WHERE d.audit_event_id = OLD.event_id)
    OR EXISTS (SELECT 1 FROM n6_binding_authority_capabilities c WHERE c.audit_event_id = OLD.event_id)
    OR EXISTS (SELECT 1 FROM n6_binding_authorizations z WHERE z.issued_audit_event_id = OLD.event_id OR z.consumed_audit_event_id = OLD.event_id OR z.expired_audit_event_id = OLD.event_id OR z.invalidated_audit_event_id = OLD.event_id)
BEGIN SELECT RAISE(ABORT, 'N6 audit events are append-only'); END;
CREATE TRIGGER n6_audit_immutable_delete
BEFORE DELETE ON audit_events
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM n6_binding_decisions d WHERE d.audit_event_id = OLD.event_id)
    OR EXISTS (SELECT 1 FROM n6_binding_authority_capabilities c WHERE c.audit_event_id = OLD.event_id)
    OR EXISTS (SELECT 1 FROM n6_binding_authorizations z WHERE z.issued_audit_event_id = OLD.event_id OR z.consumed_audit_event_id = OLD.event_id OR z.expired_audit_event_id = OLD.event_id OR z.invalidated_audit_event_id = OLD.event_id)
BEGIN SELECT RAISE(ABORT, 'N6 audit events are append-only'); END;

-- A reservation is committed before nonce generation. It deliberately contains
-- no nonce bytes or derived plaintext: completion may persist only the fixed
-- profile verifier in n6_binding_challenges.
CREATE TABLE n6_challenge_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (length(reservation_id) = 36 AND reservation_id = lower(reservation_id) AND substr(reservation_id,9,1) = '-' AND substr(reservation_id,14,1) = '-' AND substr(reservation_id,19,1) = '-' AND substr(reservation_id,24,1) = '-' AND replace(reservation_id,'-','') NOT GLOB '*[^0-9a-f]*' AND reservation_id <> '00000000-0000-0000-0000-000000000000'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    join_session_id TEXT NOT NULL REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    expected_authenticated_peer_id TEXT NOT NULL CHECK (length(expected_authenticated_peer_id) BETWEEN 1 AND 255 AND expected_authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64 AND request_fingerprint = lower(request_fingerprint) AND request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms >= 0),
    agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 128 AND agent_version NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    reservation_state TEXT NOT NULL CHECK (reservation_state IN ('reserved','issued','abandoned')),
    reserved_at_ms INTEGER NOT NULL CHECK (typeof(reserved_at_ms) = 'integer' AND reserved_at_ms >= 0),
    issued_at_ms INTEGER CHECK (issued_at_ms IS NULL OR (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= reserved_at_ms)),
    abandoned_at_ms INTEGER CHECK (abandoned_at_ms IS NULL OR (typeof(abandoned_at_ms) = 'integer' AND abandoned_at_ms >= reserved_at_ms)),
    challenge_id TEXT UNIQUE REFERENCES n6_binding_challenges(challenge_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((reservation_state = 'reserved' AND issued_at_ms IS NULL AND abandoned_at_ms IS NULL AND challenge_id IS NULL)
        OR (reservation_state = 'issued' AND issued_at_ms IS NOT NULL AND abandoned_at_ms IS NULL AND challenge_id IS NOT NULL)
        OR (reservation_state = 'abandoned' AND issued_at_ms IS NULL AND abandoned_at_ms IS NOT NULL AND challenge_id IS NULL))
);
CREATE UNIQUE INDEX n6_one_reserved_challenge_per_binding ON n6_challenge_reservations(binding_id) WHERE reservation_state = 'reserved';
CREATE UNIQUE INDEX n6_challenge_operation_once ON n6_challenge_reservations(expected_authenticated_peer_id, operation_id);

-- First completion wins by authenticated peer + operation ID. Its request
-- fingerprint is a SHA-256 digest only; no nonce transport spelling is retained.
CREATE TABLE n6_control_operations (
    authenticated_peer_id TEXT NOT NULL CHECK (length(authenticated_peer_id) BETWEEN 1 AND 255 AND authenticated_peer_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64 AND request_fingerprint = lower(request_fingerprint) AND request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    binding_id TEXT NOT NULL REFERENCES n6_binding_records(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    challenge_id TEXT NOT NULL REFERENCES n6_binding_challenges(challenge_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    result_kind TEXT NOT NULL CHECK (result_kind = 'confirmed'),
    completed_at_ms INTEGER NOT NULL CHECK (typeof(completed_at_ms) = 'integer' AND completed_at_ms >= 0),
    completion_decision_id TEXT NOT NULL UNIQUE REFERENCES n6_binding_decisions(decision_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    completion_audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    PRIMARY KEY(authenticated_peer_id, operation_id)
);

CREATE TRIGGER n6_challenge_reservation_completion_exact
BEFORE UPDATE ON n6_challenge_reservations
FOR EACH ROW
BEGIN
    SELECT CASE WHEN OLD.reservation_state <> 'reserved'
        THEN RAISE(ABORT, 'N6 challenge reservation is terminal') END;
    SELECT CASE WHEN OLD.reservation_id <> NEW.reservation_id
        OR OLD.binding_id <> NEW.binding_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.device_id <> NEW.device_id
        OR OLD.join_session_id <> NEW.join_session_id
        OR OLD.expected_authenticated_peer_id <> NEW.expected_authenticated_peer_id
        OR OLD.operation_id <> NEW.operation_id
        OR OLD.request_fingerprint <> NEW.request_fingerprint
        OR OLD.generation <> NEW.generation
        OR OLD.expires_at_ms <> NEW.expires_at_ms
        OR OLD.agent_version <> NEW.agent_version
        OR OLD.reserved_at_ms <> NEW.reserved_at_ms
        THEN RAISE(ABORT, 'N6 challenge reservation provenance is immutable') END;
    SELECT CASE WHEN NEW.reservation_state = 'issued' AND NOT EXISTS (
        SELECT 1 FROM n6_binding_challenges c
        WHERE c.challenge_id = NEW.challenge_id
          AND c.binding_id = NEW.binding_id
          AND c.network_id = NEW.network_id
          AND c.device_id = NEW.device_id
          AND c.join_session_id = NEW.join_session_id
          AND c.expected_authenticated_peer_id = NEW.expected_authenticated_peer_id
          AND c.generation = NEW.generation
          AND c.expires_at_ms = NEW.expires_at_ms
          AND c.agent_version = NEW.agent_version
          AND c.challenge_state = 'pending'
    ) THEN RAISE(ABORT, 'N6 issued reservation does not match challenge') END;
END;

CREATE TRIGGER n6_challenge_reservations_append_only_delete
BEFORE DELETE ON n6_challenge_reservations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 challenge reservations are append-only'); END;

CREATE TRIGGER n6_control_operation_exact_confirmation
BEFORE INSERT ON n6_control_operations
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM n6_binding_decisions d
        JOIN n6_binding_challenges c ON c.challenge_id = NEW.challenge_id
        JOIN n6_binding_records b ON b.binding_id = NEW.binding_id
        WHERE d.decision_id = NEW.completion_decision_id
          AND d.audit_event_id = NEW.completion_audit_event_id
          AND d.subject_kind = 'binding'
          AND d.decision_kind = 'confirm'
          AND d.binding_id = NEW.binding_id
          AND d.authenticated_peer_id = NEW.authenticated_peer_id
          AND d.operation_id = NEW.operation_id
          AND c.binding_id = NEW.binding_id
          AND c.challenge_state = 'consumed'
          AND c.consumed_authenticated_peer_id = NEW.authenticated_peer_id
          AND c.consumed_operation_id = NEW.operation_id
          AND b.binding_state = 'active'
          AND b.verified_peer_id = NEW.authenticated_peer_id
    ) THEN RAISE(ABORT, 'N6 control operation lacks exact confirmation evidence') END;
END;

CREATE TRIGGER n6_control_operations_append_only_update
BEFORE UPDATE ON n6_control_operations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 control operations are append-only'); END;
CREATE TRIGGER n6_control_operations_append_only_delete
BEFORE DELETE ON n6_control_operations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N6 control operations are append-only'); END;
