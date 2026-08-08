PRAGMA foreign_keys = ON;

ALTER TABLE provider_imports ADD COLUMN custom_root_ca_sha256 TEXT
CHECK (
    custom_root_ca_sha256 IS NULL
    OR (
        length(custom_root_ca_sha256) = 71
        AND custom_root_ca_sha256 GLOB 'sha256:*'
        AND substr(custom_root_ca_sha256, 8) NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE UNIQUE INDEX n5_n4_credential_exact_provenance
ON n4_provider_credential_metadata (
    join_session_id,
    credential_id,
    network_id,
    provider_instance_id
);
CREATE UNIQUE INDEX n5_confirmed_provider_reference_exact_provenance
ON confirmed_provider_credential_references (
    credential_id,
    network_id,
    provider_instance_id,
    provider_reference
);

CREATE TABLE n5_device_identities (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    origin_join_session_id TEXT NOT NULL UNIQUE REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT,
    confirmed_at_ms INTEGER NOT NULL CHECK (typeof(confirmed_at_ms) = 'integer' AND confirmed_at_ms >= 0),
    identity_revision INTEGER NOT NULL CHECK (typeof(identity_revision) = 'integer' AND identity_revision = 1),
    safe_correlation_digest TEXT NOT NULL CHECK (
        length(safe_correlation_digest) = 71
        AND safe_correlation_digest GLOB 'sha256:*'
        AND substr(safe_correlation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE TABLE n5_provider_bindings (
    binding_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    join_session_id TEXT NOT NULL UNIQUE,
    credential_id TEXT NOT NULL,
    provider_credential_reference TEXT NOT NULL CHECK (length(provider_credential_reference) BETWEEN 1 AND 255),
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL CHECK (length(provider_node_id) BETWEEN 1 AND 255),
    machine_key_fingerprint TEXT NOT NULL CHECK (
        length(machine_key_fingerprint) = 71
        AND machine_key_fingerprint GLOB 'sha256:*'
        AND substr(machine_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    binding_state TEXT NOT NULL CHECK (binding_state IN ('active','stale','cleanup_pending','removed')),
    binding_revision INTEGER NOT NULL CHECK (typeof(binding_revision) = 'integer' AND binding_revision >= 1),
    observed_at_ms INTEGER NOT NULL CHECK (typeof(observed_at_ms) = 'integer' AND observed_at_ms >= 0),
    stale_at_ms INTEGER CHECK (stale_at_ms IS NULL OR (typeof(stale_at_ms) = 'integer' AND stale_at_ms >= observed_at_ms)),
    cleanup_pending_at_ms INTEGER CHECK (cleanup_pending_at_ms IS NULL OR (typeof(cleanup_pending_at_ms) = 'integer' AND cleanup_pending_at_ms >= observed_at_ms)),
    removed_at_ms INTEGER CHECK (removed_at_ms IS NULL OR (typeof(removed_at_ms) = 'integer' AND removed_at_ms >= observed_at_ms)),
    last_transition_audit_event_id TEXT UNIQUE CHECK (last_transition_audit_event_id IS NULL OR length(last_transition_audit_event_id) = 36),
    transition_actor_source TEXT CHECK (transition_actor_source IS NULL OR (length(transition_actor_source) BETWEEN 1 AND 64 AND transition_actor_source NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    transition_actor_id TEXT CHECK (transition_actor_id IS NULL OR (length(transition_actor_id) BETWEEN 1 AND 255 AND transition_actor_id NOT GLOB '*[^A-Za-z0-9_.:-]*')),
    FOREIGN KEY (join_session_id, credential_id, network_id, provider_instance_id)
        REFERENCES n4_provider_credential_metadata(join_session_id, credential_id, network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (credential_id, network_id, provider_instance_id, provider_credential_reference)
        REFERENCES confirmed_provider_credential_references(credential_id, network_id, provider_instance_id, provider_reference)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (
        (binding_state = 'active' AND stale_at_ms IS NULL AND cleanup_pending_at_ms IS NULL AND removed_at_ms IS NULL)
        OR (binding_state = 'stale' AND stale_at_ms IS NOT NULL AND cleanup_pending_at_ms IS NULL AND removed_at_ms IS NULL)
        OR (binding_state = 'cleanup_pending' AND cleanup_pending_at_ms IS NOT NULL AND removed_at_ms IS NULL)
        OR (binding_state = 'removed' AND removed_at_ms IS NOT NULL)
    ),
    CHECK (
        (binding_revision = 1 AND last_transition_audit_event_id IS NULL AND transition_actor_source IS NULL AND transition_actor_id IS NULL)
        OR
        (binding_revision > 1 AND last_transition_audit_event_id IS NOT NULL AND transition_actor_source IS NOT NULL
         AND ((transition_actor_source = 'nodescale' AND transition_actor_id IS NULL)
              OR (transition_actor_source <> 'nodescale' AND transition_actor_id IS NOT NULL)))
    )
);

CREATE UNIQUE INDEX n5_one_active_binding_per_device
ON n5_provider_bindings(device_id) WHERE binding_state = 'active';
CREATE UNIQUE INDEX n5_one_active_binding_per_provider_node
ON n5_provider_bindings(provider_instance_id, provider_node_id) WHERE binding_state = 'active';
CREATE UNIQUE INDEX n5_one_active_binding_per_machine_key
ON n5_provider_bindings(provider_instance_id, machine_key_fingerprint) WHERE binding_state = 'active';

CREATE TABLE n5_owner_trust_roots (
    trust_root_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL UNIQUE REFERENCES networks(network_id) ON DELETE RESTRICT,
    principal_source TEXT NOT NULL CHECK (length(principal_source) BETWEEN 1 AND 64 AND principal_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255 AND principal_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    secret_verifier TEXT NOT NULL CHECK (
        length(secret_verifier) BETWEEN 90 AND 255
        AND secret_verifier GLOB '$argon2id$v=19$m=19456,t=2,p=1$*'
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (typeof(revoked_at_ms) = 'integer' AND revoked_at_ms >= created_at_ms)),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    CHECK ((enabled = 1 AND revoked_at_ms IS NULL) OR enabled = 0)
);

CREATE TABLE n5_trust_authorities (
    authority_id TEXT PRIMARY KEY,
    trust_root_id TEXT NOT NULL REFERENCES n5_owner_trust_roots(trust_root_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    principal_source TEXT NOT NULL CHECK (length(principal_source) BETWEEN 1 AND 64 AND principal_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255 AND principal_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    not_before_ms INTEGER NOT NULL CHECK (typeof(not_before_ms) = 'integer' AND not_before_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > not_before_ms),
    sealed INTEGER NOT NULL CHECK (sealed IN (0, 1)),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (typeof(revoked_at_ms) = 'integer' AND revoked_at_ms >= not_before_ms)),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    UNIQUE(network_id, principal_source, principal_id, authority_generation),
    CHECK ((sealed = 0 AND enabled = 0 AND revoked_at_ms IS NULL) OR sealed = 1),
    CHECK ((enabled = 1 AND revoked_at_ms IS NULL) OR (enabled = 0))
);

CREATE TABLE n5_trust_authority_capabilities (
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT,
    capability TEXT NOT NULL CHECK (capability IN ('ActivateDeviceTrust','RevokeDeviceTrust')),
    PRIMARY KEY (authority_id, capability)
);

CREATE TABLE n5_device_trust_state (
    device_id TEXT PRIMARY KEY REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    trust_state TEXT NOT NULL CHECK (trust_state IN ('untrusted','trusted','revoked')),
    trust_revision INTEGER NOT NULL CHECK (typeof(trust_revision) = 'integer' AND trust_revision >= 1),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    activated_at_ms INTEGER CHECK (activated_at_ms IS NULL OR (typeof(activated_at_ms) = 'integer' AND activated_at_ms >= created_at_ms)),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (typeof(revoked_at_ms) = 'integer' AND revoked_at_ms >= created_at_ms)),
    last_decision_id TEXT,
    CHECK (
        (trust_state = 'untrusted' AND activated_at_ms IS NULL AND revoked_at_ms IS NULL AND last_decision_id IS NULL)
        OR (trust_state = 'trusted' AND activated_at_ms IS NOT NULL AND revoked_at_ms IS NULL AND last_decision_id IS NOT NULL)
        OR (trust_state = 'revoked' AND revoked_at_ms IS NOT NULL AND last_decision_id IS NOT NULL)
    )
);

CREATE TABLE n5_trust_authorizations (
    action_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    expected_trust_state TEXT NOT NULL CHECK (expected_trust_state IN ('untrusted','trusted','revoked')),
    expected_revision INTEGER NOT NULL CHECK (typeof(expected_revision) = 'integer' AND expected_revision >= 1),
    capability TEXT NOT NULL CHECK (capability IN ('ActivateDeviceTrust','RevokeDeviceTrust')),
    principal_source TEXT NOT NULL CHECK (length(principal_source) BETWEEN 1 AND 64),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255),
    issued_at_ms INTEGER NOT NULL CHECK (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > issued_at_ms),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR (typeof(consumed_at_ms) = 'integer' AND consumed_at_ms >= issued_at_ms AND consumed_at_ms < expires_at_ms)),
    decision_id TEXT,
    CHECK ((consumed_at_ms IS NULL AND decision_id IS NULL) OR (consumed_at_ms IS NOT NULL AND decision_id IS NOT NULL))
);

CREATE TABLE n5_trust_decisions (
    decision_id TEXT PRIMARY KEY,
    audit_event_id TEXT NOT NULL UNIQUE CHECK (length(audit_event_id) = 36),
    action_id TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL REFERENCES n5_device_identities(device_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    prior_trust_state TEXT NOT NULL CHECK (prior_trust_state IN ('untrusted','trusted')),
    new_trust_state TEXT NOT NULL CHECK (new_trust_state IN ('trusted','revoked')),
    decision_kind TEXT NOT NULL CHECK (decision_kind IN ('activate','revoke')),
    decided_at_ms INTEGER NOT NULL CHECK (typeof(decided_at_ms) = 'integer' AND decided_at_ms >= 0),
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    authorized_principal_source TEXT NOT NULL CHECK (length(authorized_principal_source) BETWEEN 1 AND 64 AND authorized_principal_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    authorized_principal_id TEXT NOT NULL CHECK (length(authorized_principal_id) BETWEEN 1 AND 255 AND authorized_principal_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    prior_revision INTEGER NOT NULL CHECK (typeof(prior_revision) = 'integer' AND prior_revision >= 1),
    new_revision INTEGER NOT NULL CHECK (typeof(new_revision) = 'integer' AND new_revision = prior_revision + 1),
    safe_correlation_digest TEXT NOT NULL CHECK (
        length(safe_correlation_digest) = 71
        AND safe_correlation_digest GLOB 'sha256:*'
        AND substr(safe_correlation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('owner_approved','owner_revoked','security_response','provider_binding_stale')),
    CHECK (
        (decision_kind = 'activate' AND prior_trust_state = 'untrusted' AND new_trust_state = 'trusted')
        OR (decision_kind = 'revoke' AND prior_trust_state IN ('untrusted','trusted') AND new_trust_state = 'revoked')
    ),
    UNIQUE(device_id, new_revision)
);

CREATE TRIGGER n5_identity_links_exact_n4_session
BEFORE INSERT ON n5_device_identities
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM devices d
    JOIN n4_join_session_dispatches s ON s.join_session_id = NEW.origin_join_session_id
    WHERE d.device_id = NEW.device_id
      AND d.network_id = NEW.network_id
      AND s.network_id = NEW.network_id
      AND s.dispatch_state = 'confirmed'
)
BEGIN SELECT RAISE(ABORT, 'N5 identity requires exact confirmed N4 session provenance'); END;

CREATE TRIGGER n5_identity_immutable
BEFORE UPDATE ON n5_device_identities
FOR EACH ROW
BEGIN SELECT RAISE(ABORT, 'N5 device identity is immutable'); END;
CREATE TRIGGER n5_identity_immutable_delete
BEFORE DELETE ON n5_device_identities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 device identity is immutable'); END;

CREATE TRIGGER n5_binding_links_exact_identity
BEFORE INSERT ON n5_provider_bindings
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_device_identities i
    WHERE i.device_id = NEW.device_id
      AND i.network_id = NEW.network_id
      AND i.origin_join_session_id = NEW.join_session_id
)
BEGIN SELECT RAISE(ABORT, 'N5 provider binding must match logical device identity'); END;

CREATE TRIGGER n5_binding_identity_immutable
BEFORE UPDATE ON n5_provider_bindings
FOR EACH ROW WHEN NEW.binding_id <> OLD.binding_id
    OR NEW.device_id <> OLD.device_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.join_session_id <> OLD.join_session_id
    OR NEW.credential_id <> OLD.credential_id
    OR NEW.provider_credential_reference <> OLD.provider_credential_reference
    OR NEW.provider_instance_id <> OLD.provider_instance_id
    OR NEW.provider_node_id <> OLD.provider_node_id
    OR NEW.machine_key_fingerprint <> OLD.machine_key_fingerprint
    OR NEW.observed_at_ms <> OLD.observed_at_ms
BEGIN SELECT RAISE(ABORT, 'N5 provider binding identity is immutable'); END;
CREATE TRIGGER n5_binding_immutable_delete
BEFORE DELETE ON n5_provider_bindings
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 provider bindings are immutable'); END;

CREATE TRIGGER n5_binding_state_transitions
BEFORE UPDATE OF binding_state, binding_revision, stale_at_ms, cleanup_pending_at_ms, removed_at_ms, last_transition_audit_event_id, transition_actor_source, transition_actor_id
ON n5_provider_bindings
FOR EACH ROW WHEN NEW.binding_revision <> OLD.binding_revision + 1
    OR NEW.last_transition_audit_event_id IS OLD.last_transition_audit_event_id
    OR NEW.transition_actor_source IS NULL
    OR NOT (
    (OLD.binding_state = 'active' AND NEW.binding_state IN ('stale','cleanup_pending'))
    OR (OLD.binding_state = 'stale' AND NEW.binding_state IN ('cleanup_pending','removed'))
    OR (OLD.binding_state = 'cleanup_pending' AND NEW.binding_state = 'removed')
)
BEGIN SELECT RAISE(ABORT, 'unsafe N5 provider binding transition'); END;

CREATE TRIGGER n5_binding_audit_fields_require_transition
BEFORE UPDATE OF last_transition_audit_event_id, transition_actor_source, transition_actor_id
ON n5_provider_bindings
FOR EACH ROW WHEN NEW.binding_state = OLD.binding_state OR NEW.binding_revision = OLD.binding_revision
BEGIN SELECT RAISE(ABORT, 'N5 binding audit correlation requires lifecycle transition'); END;

CREATE TRIGGER n5_binding_transition_emits_audit
AFTER UPDATE OF binding_state, binding_revision ON n5_provider_bindings
FOR EACH ROW
BEGIN
    INSERT INTO audit_events (
        event_id,timestamp,network_id,device_id,actor_source,actor_id,
        event_kind,outcome,generation,metadata_json
    ) VALUES (
        NEW.last_transition_audit_event_id,
        strftime(
            '%Y-%m-%dT%H:%M:%fZ',
            (CASE NEW.binding_state
                WHEN 'stale' THEN NEW.stale_at_ms
                WHEN 'cleanup_pending' THEN NEW.cleanup_pending_at_ms
                ELSE NEW.removed_at_ms
             END) / 1000.0,
            'unixepoch'
        ),
        NEW.network_id,
        NEW.device_id,
        NEW.transition_actor_source,
        NEW.transition_actor_id,
        CASE NEW.binding_state
            WHEN 'stale' THEN 'device.provider_binding_stale'
            WHEN 'cleanup_pending' THEN 'device.provider_binding_cleanup_pending'
            ELSE 'device.provider_binding_removed'
        END,
        'success',
        NEW.binding_revision,
        '{}'
    );
END;

CREATE TRIGGER n5_owner_trust_root_immutable
BEFORE UPDATE ON n5_owner_trust_roots
FOR EACH ROW WHEN NEW.trust_root_id <> OLD.trust_root_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.principal_source <> OLD.principal_source
    OR NEW.principal_id <> OLD.principal_id
    OR NEW.secret_verifier <> OLD.secret_verifier
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR OLD.enabled = 0
    OR (OLD.revoked_at_ms IS NOT NULL AND NEW.revoked_at_ms IS NOT OLD.revoked_at_ms)
BEGIN SELECT RAISE(ABORT, 'N5 owner trust root provenance is immutable'); END;
CREATE TRIGGER n5_owner_trust_root_immutable_delete
BEFORE DELETE ON n5_owner_trust_roots
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 owner trust roots are immutable'); END;

CREATE TRIGGER n5_authority_links_exact_trust_root
BEFORE INSERT ON n5_trust_authorities
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n5_owner_trust_roots r
    WHERE r.trust_root_id = NEW.trust_root_id
      AND r.network_id = NEW.network_id
      AND r.enabled = 1
      AND r.revoked_at_ms IS NULL
)
BEGIN SELECT RAISE(ABORT, 'N5 trust authority requires exact active owner root'); END;

CREATE TRIGGER n5_authority_identity_immutable
BEFORE UPDATE ON n5_trust_authorities
FOR EACH ROW WHEN NEW.authority_id <> OLD.authority_id
    OR NEW.trust_root_id <> OLD.trust_root_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.principal_source <> OLD.principal_source
    OR NEW.principal_id <> OLD.principal_id
    OR NEW.authority_generation <> OLD.authority_generation
    OR NEW.not_before_ms <> OLD.not_before_ms
    OR NEW.expires_at_ms <> OLD.expires_at_ms
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NOT (
        (OLD.sealed = 0 AND OLD.enabled = 0 AND OLD.revoked_at_ms IS NULL
         AND NEW.sealed = 1 AND NEW.enabled = 1 AND NEW.revoked_at_ms IS NULL)
        OR
        (OLD.sealed = 1 AND OLD.enabled = 1 AND OLD.revoked_at_ms IS NULL
         AND NEW.sealed = 1 AND NEW.enabled = 0 AND NEW.revoked_at_ms IS NOT NULL)
    )
BEGIN SELECT RAISE(ABORT, 'N5 trust authority provenance is immutable'); END;
CREATE TRIGGER n5_authority_immutable_delete
BEFORE DELETE ON n5_trust_authorities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust authorities are immutable'); END;

CREATE TRIGGER n5_authority_capability_insert_only_before_seal
BEFORE INSERT ON n5_trust_authority_capabilities
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n5_trust_authorities a
    WHERE a.authority_id = NEW.authority_id AND a.sealed = 0 AND a.enabled = 0
)
BEGIN SELECT RAISE(ABORT, 'N5 trust authority capabilities require unsealed authority'); END;
CREATE TRIGGER n5_authority_capability_immutable_update
BEFORE UPDATE ON n5_trust_authority_capabilities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust authority capabilities are immutable'); END;
CREATE TRIGGER n5_authority_capability_immutable_delete
BEFORE DELETE ON n5_trust_authority_capabilities
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust authority capabilities are immutable'); END;

CREATE TRIGGER n5_trust_authorization_valid
BEFORE INSERT ON n5_trust_authorizations
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_device_trust_state s
    JOIN n5_trust_authorities a ON a.authority_id = NEW.authority_id
    JOIN n5_owner_trust_roots r ON r.trust_root_id = a.trust_root_id
    JOIN n5_trust_authority_capabilities c ON c.authority_id = a.authority_id
    WHERE s.device_id = NEW.device_id
      AND s.network_id = NEW.network_id
      AND s.trust_state = NEW.expected_trust_state
      AND s.trust_revision = NEW.expected_revision
      AND a.network_id = NEW.network_id
      AND a.authority_generation = NEW.authority_generation
      AND a.principal_source = NEW.principal_source
      AND a.principal_id = NEW.principal_id
      AND a.enabled = 1
      AND a.sealed = 1
      AND a.revoked_at_ms IS NULL
      AND r.network_id = a.network_id
      AND r.enabled = 1
      AND r.revoked_at_ms IS NULL
      AND NEW.issued_at_ms >= a.not_before_ms
      AND NEW.issued_at_ms < a.expires_at_ms
      AND NEW.expires_at_ms <= a.expires_at_ms
      AND c.capability = NEW.capability
)
BEGIN SELECT RAISE(ABORT, 'N5 trust authorization lacks current exact authority'); END;

CREATE TRIGGER n5_trust_authorization_consumption_bound
BEFORE UPDATE ON n5_trust_authorizations
FOR EACH ROW WHEN NEW.action_id <> OLD.action_id
    OR NEW.authority_id <> OLD.authority_id
    OR NEW.authority_generation <> OLD.authority_generation
    OR NEW.device_id <> OLD.device_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.expected_trust_state <> OLD.expected_trust_state
    OR NEW.expected_revision <> OLD.expected_revision
    OR NEW.capability <> OLD.capability
    OR NEW.principal_source <> OLD.principal_source
    OR NEW.principal_id <> OLD.principal_id
    OR NEW.issued_at_ms <> OLD.issued_at_ms
    OR NEW.expires_at_ms <> OLD.expires_at_ms
    OR OLD.consumed_at_ms IS NOT NULL
    OR OLD.decision_id IS NOT NULL
    OR NOT EXISTS (
        SELECT 1 FROM n5_trust_decisions d
        WHERE d.decision_id = NEW.decision_id
          AND d.action_id = OLD.action_id
          AND d.decided_at_ms = NEW.consumed_at_ms
    )
BEGIN SELECT RAISE(ABORT, 'N5 trust authorization consumption requires exact decision'); END;
CREATE TRIGGER n5_trust_authorization_immutable_delete
BEFORE DELETE ON n5_trust_authorizations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust authorizations are immutable'); END;

CREATE TRIGGER n5_trust_decision_valid
BEFORE INSERT ON n5_trust_decisions
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_device_trust_state s
    JOIN n5_trust_authorities a ON a.authority_id = NEW.authority_id
    JOIN n5_owner_trust_roots r ON r.trust_root_id = a.trust_root_id
    JOIN n5_trust_authority_capabilities c ON c.authority_id = a.authority_id
    JOIN n5_trust_authorizations z ON z.action_id = NEW.action_id
    WHERE s.device_id = NEW.device_id
      AND s.network_id = NEW.network_id
      AND s.trust_state = NEW.prior_trust_state
      AND s.trust_revision = NEW.prior_revision
      AND a.network_id = NEW.network_id
      AND a.authority_generation = NEW.authority_generation
      AND a.principal_source = NEW.authorized_principal_source
      AND a.principal_id = NEW.authorized_principal_id
      AND a.enabled = 1
      AND a.sealed = 1
      AND a.revoked_at_ms IS NULL
      AND r.network_id = a.network_id
      AND r.enabled = 1
      AND r.revoked_at_ms IS NULL
      AND NEW.decided_at_ms >= a.not_before_ms
      AND NEW.decided_at_ms < a.expires_at_ms
      AND c.capability = CASE NEW.decision_kind
          WHEN 'activate' THEN 'ActivateDeviceTrust'
          WHEN 'revoke' THEN 'RevokeDeviceTrust'
      END
      AND z.authority_id = NEW.authority_id
      AND z.authority_generation = NEW.authority_generation
      AND z.device_id = NEW.device_id
      AND z.network_id = NEW.network_id
      AND z.expected_trust_state = NEW.prior_trust_state
      AND z.expected_revision = NEW.prior_revision
      AND z.capability = c.capability
      AND z.principal_source = NEW.authorized_principal_source
      AND z.principal_id = NEW.authorized_principal_id
      AND z.consumed_at_ms IS NULL
      AND z.decision_id IS NULL
      AND NEW.decided_at_ms >= z.issued_at_ms
      AND NEW.decided_at_ms < z.expires_at_ms
      AND (
          NEW.decision_kind = 'revoke'
          OR EXISTS (
              SELECT 1 FROM n5_provider_bindings b
              WHERE b.device_id = NEW.device_id
                AND b.network_id = NEW.network_id
                AND b.binding_state = 'active'
          )
      )
)
BEGIN SELECT RAISE(ABORT, 'N5 trust decision lacks current exact authority or identity'); END;

CREATE TRIGGER n5_trust_state_decision_bound
BEFORE UPDATE ON n5_device_trust_state
FOR EACH ROW WHEN NEW.device_id <> OLD.device_id
    OR NEW.network_id <> OLD.network_id
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NOT EXISTS (
        SELECT 1 FROM n5_trust_decisions d
        WHERE d.decision_id = NEW.last_decision_id
          AND d.device_id = OLD.device_id
          AND d.network_id = OLD.network_id
          AND d.prior_trust_state = OLD.trust_state
          AND d.new_trust_state = NEW.trust_state
          AND d.prior_revision = OLD.trust_revision
          AND d.new_revision = NEW.trust_revision
          AND ((d.decision_kind = 'activate' AND NEW.activated_at_ms = d.decided_at_ms AND NEW.revoked_at_ms IS NULL)
            OR (d.decision_kind = 'revoke' AND NEW.revoked_at_ms = d.decided_at_ms))
    )
BEGIN SELECT RAISE(ABORT, 'N5 trust state requires its exact append-only decision'); END;
CREATE TRIGGER n5_trust_state_immutable_delete
BEFORE DELETE ON n5_device_trust_state
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust state cannot be deleted'); END;

CREATE TRIGGER n5_apply_trust_decision
AFTER INSERT ON n5_trust_decisions
FOR EACH ROW
BEGIN
    INSERT INTO audit_events (
        event_id,timestamp,network_id,device_id,actor_source,actor_id,
        event_kind,outcome,generation,metadata_json
    ) VALUES (
        NEW.audit_event_id,
        strftime('%Y-%m-%dT%H:%M:%fZ', NEW.decided_at_ms / 1000.0, 'unixepoch'),
        NEW.network_id,
        NEW.device_id,
        NEW.authorized_principal_source,
        NEW.authorized_principal_id,
        CASE NEW.decision_kind
            WHEN 'activate' THEN 'device.trust_activated'
            ELSE 'device.trust_revoked'
        END,
        'success',
        NEW.new_revision,
        '{}'
    );
    UPDATE n5_trust_authorizations
    SET consumed_at_ms = NEW.decided_at_ms,
        decision_id = NEW.decision_id
    WHERE action_id = NEW.action_id
      AND consumed_at_ms IS NULL
      AND decision_id IS NULL;
    UPDATE n5_device_trust_state
    SET trust_state = NEW.new_trust_state,
        trust_revision = NEW.new_revision,
        activated_at_ms = CASE WHEN NEW.decision_kind = 'activate' THEN NEW.decided_at_ms ELSE activated_at_ms END,
        revoked_at_ms = CASE WHEN NEW.decision_kind = 'revoke' THEN NEW.decided_at_ms ELSE revoked_at_ms END,
        last_decision_id = NEW.decision_id
    WHERE device_id = NEW.device_id
      AND network_id = NEW.network_id
      AND trust_state = NEW.prior_trust_state
      AND trust_revision = NEW.prior_revision;
END;

CREATE TRIGGER n5_trust_decision_immutable_update
BEFORE UPDATE ON n5_trust_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust decisions are append-only'); END;
CREATE TRIGGER n5_trust_decision_immutable_delete
BEFORE DELETE ON n5_trust_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 trust decisions are append-only'); END;

CREATE TRIGGER n5_audit_immutable_update
BEFORE UPDATE ON audit_events
FOR EACH ROW WHEN OLD.event_kind GLOB 'device.*'
BEGIN SELECT RAISE(ABORT, 'N5 audit events are append-only'); END;
CREATE TRIGGER n5_audit_immutable_delete
BEFORE DELETE ON audit_events
FOR EACH ROW WHEN OLD.event_kind GLOB 'device.*'
BEGIN SELECT RAISE(ABORT, 'N5 audit events are append-only'); END;
