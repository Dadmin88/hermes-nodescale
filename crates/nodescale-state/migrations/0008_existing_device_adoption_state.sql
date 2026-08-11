PRAGMA foreign_keys = ON;

ALTER TABLE provider_observations
ADD COLUMN semantic_generation INTEGER NOT NULL DEFAULT 1
CHECK (typeof(semantic_generation) = 'integer' AND semantic_generation >= 1);

DROP TRIGGER n5_trust_authorization_valid;
DROP TRIGGER n5_trust_decision_valid;

ALTER TABLE n5_trust_authority_capabilities RENAME TO n5_trust_authority_capabilities_v7;

CREATE TABLE n5_trust_authority_capabilities (
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT,
    capability TEXT NOT NULL CHECK (
        capability IN (
            'ActivateDeviceTrust',
            'RevokeDeviceTrust',
            'AdoptExistingProviderDevice'
        )
    ),
    PRIMARY KEY (authority_id, capability)
);

INSERT INTO n5_trust_authority_capabilities (authority_id, capability)
SELECT authority_id, capability
FROM n5_trust_authority_capabilities_v7;

DROP TABLE n5_trust_authority_capabilities_v7;

CREATE TRIGGER n5_authority_capability_insert_only_before_seal
BEFORE INSERT ON n5_trust_authority_capabilities
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n5_trust_authorities
    WHERE authority_id = NEW.authority_id AND sealed = 0 AND enabled = 0
)
BEGIN SELECT RAISE(ABORT, 'N5 capabilities must be configured before authority sealing'); END;

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

CREATE TABLE n5_adoption_authorization_operations (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    observation_id TEXT NOT NULL REFERENCES provider_observations(observation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    expected_observation_generation INTEGER NOT NULL CHECK (typeof(expected_observation_generation) = 'integer' AND expected_observation_generation >= 1),
    expected_observation_fingerprint TEXT NOT NULL CHECK (length(expected_observation_fingerprint) = 71 AND expected_observation_fingerprint GLOB 'sha256:*' AND substr(expected_observation_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_semantic_fingerprint TEXT NOT NULL CHECK (length(expected_semantic_fingerprint) = 71 AND expected_semantic_fingerprint GLOB 'sha256:*' AND substr(expected_semantic_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_machine_key_fingerprint TEXT NOT NULL CHECK (length(expected_machine_key_fingerprint) = 71 AND expected_machine_key_fingerprint GLOB 'sha256:*' AND substr(expected_machine_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_node_key_fingerprint TEXT NOT NULL CHECK (length(expected_node_key_fingerprint) = 71 AND expected_node_key_fingerprint GLOB 'sha256:*' AND substr(expected_node_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64 AND request_fingerprint = lower(request_fingerprint) AND request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    operation_state TEXT NOT NULL CHECK (operation_state IN ('pending','settled')),
    outcome TEXT CHECK (outcome IS NULL OR outcome IN ('issued','rejected','conflicted')),
    action_id TEXT UNIQUE,
    receipt_id TEXT UNIQUE,
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    settled_at_ms INTEGER CHECK (settled_at_ms IS NULL OR (typeof(settled_at_ms) = 'integer' AND settled_at_ms >= created_at_ms)),
    CHECK (
        (operation_state = 'pending' AND outcome IS NULL AND action_id IS NULL AND receipt_id IS NULL AND settled_at_ms IS NULL)
        OR
        (operation_state = 'settled' AND outcome IS NOT NULL AND receipt_id IS NOT NULL AND settled_at_ms IS NOT NULL
         AND ((outcome = 'issued' AND action_id IS NOT NULL) OR (outcome <> 'issued' AND action_id IS NULL)))
    ),
    FOREIGN KEY (action_id)
        REFERENCES n5_adoption_actions(action_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE n5_adoption_actions (
    action_id TEXT PRIMARY KEY,
    authorization_operation_id TEXT NOT NULL UNIQUE REFERENCES n5_adoption_authorization_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    observation_id TEXT NOT NULL REFERENCES provider_observations(observation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    provider_kind TEXT NOT NULL CHECK (length(provider_kind) BETWEEN 1 AND 64 AND provider_kind NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    expected_observation_generation INTEGER NOT NULL CHECK (typeof(expected_observation_generation) = 'integer' AND expected_observation_generation >= 1),
    expected_observation_fingerprint TEXT NOT NULL CHECK (length(expected_observation_fingerprint) = 71 AND expected_observation_fingerprint GLOB 'sha256:*' AND substr(expected_observation_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_semantic_fingerprint TEXT NOT NULL CHECK (length(expected_semantic_fingerprint) = 71 AND expected_semantic_fingerprint GLOB 'sha256:*' AND substr(expected_semantic_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_machine_key_fingerprint TEXT NOT NULL CHECK (length(expected_machine_key_fingerprint) = 71 AND expected_machine_key_fingerprint GLOB 'sha256:*' AND substr(expected_machine_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    expected_node_key_fingerprint TEXT NOT NULL CHECK (length(expected_node_key_fingerprint) = 71 AND expected_node_key_fingerprint GLOB 'sha256:*' AND substr(expected_node_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    proof_method TEXT NOT NULL CHECK (proof_method = 'tailscale_whois_provider_v1'),
    proof_generation INTEGER NOT NULL CHECK (typeof(proof_generation) = 'integer' AND proof_generation >= 1),
    challenge_id TEXT NOT NULL UNIQUE,
    challenge_verifier TEXT NOT NULL CHECK (length(challenge_verifier) BETWEEN 90 AND 255 AND challenge_verifier GLOB '$argon2id$v=19$m=19456,t=2,p=1$*'),
    principal_source TEXT NOT NULL CHECK (length(principal_source) BETWEEN 1 AND 64 AND principal_source NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255 AND principal_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    issued_at_ms INTEGER NOT NULL CHECK (typeof(issued_at_ms) = 'integer' AND issued_at_ms >= 0),
    not_before_ms INTEGER NOT NULL CHECK (typeof(not_before_ms) = 'integer' AND not_before_ms >= issued_at_ms),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > not_before_ms),
    action_state TEXT NOT NULL CHECK (action_state IN ('proof_pending','confirmed','conflicted','expired','revoked')),
    terminal_decision_id TEXT UNIQUE,
    terminal_at_ms INTEGER CHECK (terminal_at_ms IS NULL OR (typeof(terminal_at_ms) = 'integer' AND terminal_at_ms >= issued_at_ms)),
    terminal_reason TEXT,
    CHECK (
        (action_state = 'proof_pending' AND terminal_decision_id IS NULL AND terminal_at_ms IS NULL AND terminal_reason IS NULL)
        OR
        (action_state <> 'proof_pending' AND terminal_decision_id IS NOT NULL AND terminal_at_ms IS NOT NULL AND terminal_reason IS NOT NULL)
    )
);

CREATE UNIQUE INDEX n5_one_open_adoption_action_per_provider_node
ON n5_adoption_actions(network_id, provider_instance_id, provider_node_id)
WHERE action_state = 'proof_pending';

CREATE TABLE n5_adoption_proof_operations (
    action_id TEXT NOT NULL REFERENCES n5_adoption_actions(action_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128 AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64 AND request_fingerprint = lower(request_fingerprint) AND request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    operation_state TEXT NOT NULL CHECK (operation_state IN ('pending','settled')),
    outcome TEXT CHECK (outcome IS NULL OR outcome IN ('confirmed','replay','rejected','conflicted','unavailable')),
    receipt_id TEXT UNIQUE,
    resulting_device_id TEXT,
    resulting_provider_binding_id TEXT,
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    settled_at_ms INTEGER CHECK (settled_at_ms IS NULL OR (typeof(settled_at_ms) = 'integer' AND settled_at_ms >= created_at_ms)),
    PRIMARY KEY (action_id, operation_id),
    CHECK (
        (operation_state = 'pending' AND outcome IS NULL AND receipt_id IS NULL AND resulting_device_id IS NULL AND resulting_provider_binding_id IS NULL AND settled_at_ms IS NULL)
        OR
        (operation_state = 'settled' AND outcome IS NOT NULL AND receipt_id IS NOT NULL AND settled_at_ms IS NOT NULL
         AND ((outcome IN ('confirmed','replay') AND resulting_device_id IS NOT NULL AND resulting_provider_binding_id IS NOT NULL)
              OR (outcome NOT IN ('confirmed','replay') AND resulting_device_id IS NULL AND resulting_provider_binding_id IS NULL)))
    )
);

CREATE UNIQUE INDEX n5_one_pending_adoption_proof_operation_per_action
ON n5_adoption_proof_operations(action_id)
WHERE operation_state = 'pending';

CREATE TABLE n5_adoption_decisions (
    decision_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE REFERENCES n5_adoption_actions(action_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    proof_operation_id TEXT,
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    decision_kind TEXT NOT NULL CHECK (decision_kind IN ('confirm','conflict','expire','revoke')),
    prior_action_state TEXT NOT NULL CHECK (prior_action_state = 'proof_pending'),
    new_action_state TEXT NOT NULL CHECK (new_action_state IN ('confirmed','conflicted','expired','revoked')),
    authority_id TEXT NOT NULL REFERENCES n5_trust_authorities(authority_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (typeof(authority_generation) = 'integer' AND authority_generation >= 1),
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    observation_generation INTEGER NOT NULL CHECK (typeof(observation_generation) = 'integer' AND observation_generation >= 1),
    proof_generation INTEGER NOT NULL CHECK (typeof(proof_generation) = 'integer' AND proof_generation >= 1),
    evidence_id TEXT UNIQUE,
    device_id TEXT,
    provider_binding_id TEXT,
    safe_correlation_digest TEXT NOT NULL CHECK (length(safe_correlation_digest) = 71 AND safe_correlation_digest GLOB 'sha256:*' AND substr(safe_correlation_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('proof_confirmed','observation_changed','provider_missing','provider_expired','identity_conflict','owner_revoked','action_expired')),
    decided_at_ms INTEGER NOT NULL CHECK (typeof(decided_at_ms) = 'integer' AND decided_at_ms >= 0),
    CHECK (
        (decision_kind = 'confirm' AND new_action_state = 'confirmed' AND proof_operation_id IS NOT NULL AND evidence_id IS NOT NULL AND device_id IS NOT NULL AND provider_binding_id IS NOT NULL)
        OR
        (decision_kind <> 'confirm' AND proof_operation_id IS NULL AND evidence_id IS NULL AND device_id IS NULL AND provider_binding_id IS NULL)
    )
);

CREATE TABLE n5_existing_adoption_evidence (
    evidence_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE REFERENCES n5_adoption_actions(action_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    proof_operation_id TEXT NOT NULL,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    provider_kind TEXT NOT NULL CHECK (length(provider_kind) BETWEEN 1 AND 64 AND provider_kind NOT GLOB '*[^A-Za-z0-9_.:-]*'),
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL CHECK (length(observation_fingerprint) = 71 AND observation_fingerprint GLOB 'sha256:*' AND substr(observation_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    observation_semantic_fingerprint TEXT NOT NULL CHECK (length(observation_semantic_fingerprint) = 71 AND observation_semantic_fingerprint GLOB 'sha256:*' AND substr(observation_semantic_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    observation_generation INTEGER NOT NULL CHECK (typeof(observation_generation) = 'integer' AND observation_generation >= 1),
    machine_key_fingerprint TEXT NOT NULL CHECK (length(machine_key_fingerprint) = 71 AND machine_key_fingerprint GLOB 'sha256:*' AND substr(machine_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    node_key_fingerprint TEXT NOT NULL CHECK (length(node_key_fingerprint) = 71 AND node_key_fingerprint GLOB 'sha256:*' AND substr(node_key_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    proof_generation INTEGER NOT NULL CHECK (typeof(proof_generation) = 'integer' AND proof_generation >= 1),
    proof_method TEXT NOT NULL CHECK (proof_method = 'tailscale_whois_provider_v1'),
    provider_compatibility_pin TEXT NOT NULL CHECK (length(provider_compatibility_pin) BETWEEN 1 AND 128),
    verified_at_ms INTEGER NOT NULL CHECK (typeof(verified_at_ms) = 'integer' AND verified_at_ms >= 0),
    FOREIGN KEY (action_id, proof_operation_id)
        REFERENCES n5_adoption_proof_operations(action_id, operation_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    UNIQUE(network_id, provider_instance_id, provider_node_id, machine_key_fingerprint, proof_generation)
);

CREATE TRIGGER n5_adoption_authorization_operation_insert_guard
BEFORE INSERT ON n5_adoption_authorization_operations
FOR EACH ROW WHEN NEW.operation_state <> 'pending'
    OR NOT EXISTS (
    SELECT 1
    FROM n5_trust_authorities AS authority
    JOIN n5_owner_trust_roots AS root
      ON root.trust_root_id = authority.trust_root_id
     AND root.network_id = authority.network_id
     AND root.enabled = 1
     AND root.revoked_at_ms IS NULL
    JOIN n5_trust_authority_capabilities AS capability
      ON capability.authority_id = authority.authority_id
     AND capability.capability = 'AdoptExistingProviderDevice'
    JOIN provider_observations AS observation
      ON observation.observation_id = NEW.observation_id
     AND observation.network_id = NEW.network_id
     AND observation.provider_instance_id = NEW.provider_instance_id
     AND observation.provider_node_id = NEW.provider_node_id
     AND observation.semantic_generation = NEW.expected_observation_generation
     AND observation.stable_key_fingerprint = NEW.expected_observation_fingerprint
     AND observation.semantic_fingerprint = NEW.expected_semantic_fingerprint
     AND observation.classification = 'discovered_unmanaged'
     AND observation.adoption_state = 'unmanaged'
     AND observation.device_id IS NULL
    WHERE authority.authority_id = NEW.authority_id
      AND authority.network_id = NEW.network_id
      AND authority.authority_generation = NEW.authority_generation
      AND authority.sealed = 1
      AND authority.enabled = 1
      AND authority.revoked_at_ms IS NULL
      AND NEW.created_at_ms >= authority.not_before_ms
      AND NEW.created_at_ms < authority.expires_at_ms
)
BEGIN SELECT RAISE(ABORT, 'N5 adoption authorization requires exact current owner authority and observation'); END;

CREATE TRIGGER n5_adoption_authorization_operation_immutable_identity
BEFORE UPDATE ON n5_adoption_authorization_operations
FOR EACH ROW WHEN OLD.operation_id <> NEW.operation_id
    OR OLD.authority_id <> NEW.authority_id
    OR OLD.authority_generation <> NEW.authority_generation
    OR OLD.network_id <> NEW.network_id
    OR OLD.observation_id <> NEW.observation_id
    OR OLD.provider_instance_id <> NEW.provider_instance_id
    OR OLD.provider_node_id <> NEW.provider_node_id
    OR OLD.expected_observation_generation <> NEW.expected_observation_generation
    OR OLD.expected_observation_fingerprint <> NEW.expected_observation_fingerprint
    OR OLD.expected_semantic_fingerprint <> NEW.expected_semantic_fingerprint
    OR OLD.expected_machine_key_fingerprint <> NEW.expected_machine_key_fingerprint
    OR OLD.expected_node_key_fingerprint <> NEW.expected_node_key_fingerprint
    OR OLD.request_fingerprint <> NEW.request_fingerprint
    OR OLD.created_at_ms <> NEW.created_at_ms
BEGIN SELECT RAISE(ABORT, 'N5 adoption authorization operation identity is immutable'); END;

CREATE TRIGGER n5_adoption_authorization_operation_issue_guard
BEFORE UPDATE ON n5_adoption_authorization_operations
FOR EACH ROW WHEN OLD.operation_state = 'pending'
    AND NEW.operation_state = 'settled'
    AND NEW.outcome = 'issued'
    AND NOT EXISTS (
        SELECT 1
        FROM n5_trust_authorities AS authority
        JOIN n5_owner_trust_roots AS root
          ON root.trust_root_id = authority.trust_root_id
         AND root.network_id = authority.network_id
         AND root.enabled = 1
         AND root.revoked_at_ms IS NULL
        JOIN n5_trust_authority_capabilities AS capability
          ON capability.authority_id = authority.authority_id
         AND capability.capability = 'AdoptExistingProviderDevice'
        JOIN provider_observations AS observation
          ON observation.observation_id = NEW.observation_id
         AND observation.network_id = NEW.network_id
         AND observation.provider_instance_id = NEW.provider_instance_id
         AND observation.provider_node_id = NEW.provider_node_id
         AND observation.semantic_generation = NEW.expected_observation_generation
         AND observation.stable_key_fingerprint = NEW.expected_observation_fingerprint
         AND observation.semantic_fingerprint = NEW.expected_semantic_fingerprint
         AND observation.classification = 'discovered_unmanaged'
         AND observation.adoption_state = 'unmanaged'
         AND observation.device_id IS NULL
        WHERE authority.authority_id = NEW.authority_id
          AND authority.network_id = NEW.network_id
          AND authority.authority_generation = NEW.authority_generation
          AND authority.sealed = 1
          AND authority.enabled = 1
          AND authority.revoked_at_ms IS NULL
          AND NEW.settled_at_ms >= authority.not_before_ms
          AND NEW.settled_at_ms < authority.expires_at_ms
    )
BEGIN SELECT RAISE(ABORT, 'N5 adoption authorization issuance requires exact current owner authority and observation'); END;

CREATE TRIGGER n5_adoption_authorization_operation_lifecycle
BEFORE UPDATE ON n5_adoption_authorization_operations
FOR EACH ROW WHEN OLD.operation_state <> 'pending' OR NEW.operation_state <> 'settled'
BEGIN SELECT RAISE(ABORT, 'N5 adoption authorization operation is terminal or transition is invalid'); END;

CREATE TRIGGER n5_adoption_authorization_operation_no_delete
BEFORE DELETE ON n5_adoption_authorization_operations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption authorization operations are durable'); END;

CREATE TRIGGER n5_adoption_action_insert_guard
BEFORE INSERT ON n5_adoption_actions
FOR EACH ROW WHEN NEW.action_state <> 'proof_pending'
    OR NOT EXISTS (
    SELECT 1
    FROM n5_adoption_authorization_operations AS operation
    JOIN n5_trust_authorities AS authority
      ON authority.authority_id = NEW.authority_id
     AND authority.network_id = NEW.network_id
     AND authority.authority_generation = NEW.authority_generation
     AND authority.sealed = 1
     AND authority.enabled = 1
     AND authority.revoked_at_ms IS NULL
    JOIN n5_owner_trust_roots AS root
      ON root.trust_root_id = authority.trust_root_id
     AND root.network_id = authority.network_id
     AND root.enabled = 1
     AND root.revoked_at_ms IS NULL
    JOIN n5_trust_authority_capabilities AS capability
      ON capability.authority_id = authority.authority_id
     AND capability.capability = 'AdoptExistingProviderDevice'
    JOIN provider_observations AS observation
      ON observation.observation_id = NEW.observation_id
     AND observation.network_id = NEW.network_id
     AND observation.provider_instance_id = NEW.provider_instance_id
     AND observation.provider_node_id = NEW.provider_node_id
     AND observation.semantic_generation = NEW.expected_observation_generation
     AND observation.stable_key_fingerprint = NEW.expected_observation_fingerprint
     AND observation.semantic_fingerprint = NEW.expected_semantic_fingerprint
     AND observation.classification = 'discovered_unmanaged'
     AND observation.adoption_state = 'unmanaged'
     AND observation.device_id IS NULL
    JOIN networks AS network
      ON network.network_id = NEW.network_id
     AND network.provider_kind = NEW.provider_kind
    WHERE operation.operation_id = NEW.authorization_operation_id
      AND operation.operation_state = 'settled'
      AND operation.outcome = 'issued'
      AND operation.action_id = NEW.action_id
      AND operation.authority_id = NEW.authority_id
      AND operation.authority_generation = NEW.authority_generation
      AND operation.network_id = NEW.network_id
      AND operation.observation_id = NEW.observation_id
      AND operation.provider_instance_id = NEW.provider_instance_id
      AND operation.provider_node_id = NEW.provider_node_id
      AND operation.expected_observation_generation = NEW.expected_observation_generation
      AND operation.expected_observation_fingerprint = NEW.expected_observation_fingerprint
      AND operation.expected_semantic_fingerprint = NEW.expected_semantic_fingerprint
      AND operation.expected_machine_key_fingerprint = NEW.expected_machine_key_fingerprint
      AND operation.expected_node_key_fingerprint = NEW.expected_node_key_fingerprint
      AND NEW.issued_at_ms >= operation.settled_at_ms
      AND NEW.issued_at_ms >= authority.not_before_ms
      AND NEW.issued_at_ms < authority.expires_at_ms
      AND NEW.expires_at_ms <= authority.expires_at_ms
)
BEGIN SELECT RAISE(ABORT, 'N5 adoption action requires exact settled authorization operation and observation'); END;

CREATE TRIGGER n5_adoption_action_sets_observation_pending
AFTER INSERT ON n5_adoption_actions
FOR EACH ROW
BEGIN
    UPDATE provider_observations
    SET adoption_state = 'pending_device_credential_proof'
    WHERE observation_id = NEW.observation_id
      AND network_id = NEW.network_id
      AND provider_instance_id = NEW.provider_instance_id
      AND provider_node_id = NEW.provider_node_id
      AND semantic_generation = NEW.expected_observation_generation
      AND adoption_state = 'unmanaged';
    SELECT CASE WHEN changes() <> 1
        THEN RAISE(ABORT, 'N5 adoption action lost observation pending transition') END;
END;

CREATE TRIGGER n5_adoption_action_immutable_identity
BEFORE UPDATE ON n5_adoption_actions
FOR EACH ROW WHEN OLD.action_id <> NEW.action_id
    OR OLD.authorization_operation_id <> NEW.authorization_operation_id
    OR OLD.authority_id <> NEW.authority_id
    OR OLD.authority_generation <> NEW.authority_generation
    OR OLD.network_id <> NEW.network_id
    OR OLD.observation_id <> NEW.observation_id
    OR OLD.provider_kind <> NEW.provider_kind
    OR OLD.provider_instance_id <> NEW.provider_instance_id
    OR OLD.provider_node_id <> NEW.provider_node_id
    OR OLD.expected_observation_generation <> NEW.expected_observation_generation
    OR OLD.expected_observation_fingerprint <> NEW.expected_observation_fingerprint
    OR OLD.expected_semantic_fingerprint <> NEW.expected_semantic_fingerprint
    OR OLD.expected_machine_key_fingerprint <> NEW.expected_machine_key_fingerprint
    OR OLD.expected_node_key_fingerprint <> NEW.expected_node_key_fingerprint
    OR OLD.proof_method <> NEW.proof_method
    OR OLD.proof_generation <> NEW.proof_generation
    OR OLD.challenge_id <> NEW.challenge_id
    OR OLD.challenge_verifier <> NEW.challenge_verifier
    OR OLD.principal_source <> NEW.principal_source
    OR OLD.principal_id <> NEW.principal_id
    OR OLD.issued_at_ms <> NEW.issued_at_ms
    OR OLD.not_before_ms <> NEW.not_before_ms
    OR OLD.expires_at_ms <> NEW.expires_at_ms
BEGIN SELECT RAISE(ABORT, 'N5 adoption action identity is immutable'); END;

CREATE TRIGGER n5_adoption_action_lifecycle
BEFORE UPDATE ON n5_adoption_actions
FOR EACH ROW WHEN OLD.action_state <> 'proof_pending'
    OR NEW.action_state NOT IN ('confirmed','rejected','expired','revoked','conflicted')
    OR EXISTS (
        SELECT 1 FROM n5_adoption_proof_operations AS proof
        WHERE proof.action_id = OLD.action_id
          AND proof.operation_state = 'pending'
    )
    OR NOT EXISTS (
        SELECT 1 FROM n5_adoption_decisions AS decision
        WHERE decision.decision_id = NEW.terminal_decision_id
          AND decision.action_id = OLD.action_id
          AND decision.new_action_state = NEW.action_state
          AND decision.decided_at_ms = NEW.terminal_at_ms
          AND decision.reason_code = NEW.terminal_reason
    )
BEGIN SELECT RAISE(ABORT, 'N5 adoption action transition requires exact durable decision'); END;

CREATE TRIGGER n5_adoption_action_no_delete
BEFORE DELETE ON n5_adoption_actions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption actions are durable'); END;

CREATE TRIGGER n5_adoption_proof_operation_insert_guard
BEFORE INSERT ON n5_adoption_proof_operations
FOR EACH ROW WHEN NEW.operation_state <> 'pending'
    OR NOT EXISTS (
        SELECT 1
        FROM n5_adoption_actions AS action
        JOIN n5_trust_authorities AS authority
          ON authority.authority_id = action.authority_id
         AND authority.network_id = action.network_id
         AND authority.authority_generation = action.authority_generation
         AND authority.sealed = 1
         AND authority.enabled = 1
         AND authority.revoked_at_ms IS NULL
        JOIN n5_owner_trust_roots AS root
          ON root.trust_root_id = authority.trust_root_id
         AND root.network_id = authority.network_id
         AND root.enabled = 1
         AND root.revoked_at_ms IS NULL
        JOIN n5_trust_authority_capabilities AS capability
          ON capability.authority_id = authority.authority_id
         AND capability.capability = 'AdoptExistingProviderDevice'
        JOIN provider_observations AS observation
          ON observation.observation_id = action.observation_id
         AND observation.network_id = action.network_id
         AND observation.provider_instance_id = action.provider_instance_id
         AND observation.provider_node_id = action.provider_node_id
        WHERE action.action_id = NEW.action_id
          AND action.action_state = 'proof_pending'
          AND observation.adoption_state = 'pending_device_credential_proof'
          AND NEW.created_at_ms >= action.not_before_ms
          AND NEW.created_at_ms < action.expires_at_ms
          AND NEW.created_at_ms >= authority.not_before_ms
          AND NEW.created_at_ms < authority.expires_at_ms
    )
BEGIN SELECT RAISE(ABORT, 'N5 adoption proof operation requires exact pending action'); END;

CREATE TRIGGER n5_adoption_proof_operation_immutable_identity
BEFORE UPDATE ON n5_adoption_proof_operations
FOR EACH ROW WHEN OLD.action_id <> NEW.action_id
    OR OLD.operation_id <> NEW.operation_id
    OR OLD.request_fingerprint <> NEW.request_fingerprint
    OR OLD.created_at_ms <> NEW.created_at_ms
BEGIN SELECT RAISE(ABORT, 'N5 adoption proof operation identity is immutable'); END;

CREATE TRIGGER n5_adoption_proof_operation_lifecycle
BEFORE UPDATE ON n5_adoption_proof_operations
FOR EACH ROW WHEN OLD.operation_state <> 'pending'
    OR NEW.operation_state <> 'settled'
    OR NEW.outcome NOT IN ('rejected','conflicted','unavailable')
    OR NEW.resulting_device_id IS NOT NULL
    OR NEW.resulting_provider_binding_id IS NOT NULL
    OR (
        NEW.outcome = 'conflicted'
        AND NOT EXISTS (
            SELECT 1 FROM n5_adoption_decisions AS decision
            WHERE decision.action_id = OLD.action_id
              AND decision.decision_kind = 'conflict'
              AND decision.new_action_state = 'conflicted'
        )
    )
BEGIN SELECT RAISE(ABORT, 'N5 adoption proof operation is terminal or transition is invalid for V8'); END;

CREATE TRIGGER n5_adoption_proof_operation_no_delete
BEFORE DELETE ON n5_adoption_proof_operations
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption proof operations are durable'); END;

CREATE TRIGGER n5_adoption_decision_insert_guard
BEFORE INSERT ON n5_adoption_decisions
FOR EACH ROW WHEN NEW.decision_kind = 'confirm'
    OR NOT EXISTS (
        SELECT 1
        FROM n5_adoption_actions AS action
        JOIN audit_events AS audit ON audit.event_id = NEW.audit_event_id
        JOIN provider_observations AS observation
          ON observation.observation_id = action.observation_id
         AND observation.network_id = NEW.network_id
         AND observation.provider_instance_id = NEW.provider_instance_id
         AND observation.provider_node_id = NEW.provider_node_id
         AND observation.semantic_generation = NEW.observation_generation
         AND observation.adoption_state = 'pending_device_credential_proof'
        WHERE action.action_id = NEW.action_id
          AND action.action_state = 'proof_pending'
          AND action.authority_id = NEW.authority_id
          AND action.authority_generation = NEW.authority_generation
          AND action.network_id = NEW.network_id
          AND action.provider_instance_id = NEW.provider_instance_id
          AND action.provider_node_id = NEW.provider_node_id
          AND action.proof_generation = NEW.proof_generation
          AND NEW.prior_action_state = 'proof_pending'
          AND (
              (NEW.decision_kind = 'conflict'
               AND NEW.new_action_state = 'conflicted'
               AND NEW.reason_code IN ('observation_changed','provider_missing','provider_expired','identity_conflict')
               AND NEW.observation_generation > action.expected_observation_generation
               AND (
                   NEW.reason_code = 'observation_changed'
                   OR (NEW.reason_code = 'provider_missing' AND observation.classification = 'provider_missing')
                   OR (NEW.reason_code = 'provider_expired' AND observation.classification = 'provider_expired')
                   OR (NEW.reason_code = 'identity_conflict' AND observation.classification = 'identity_conflict')
               ))
              OR
              (NEW.decision_kind = 'expire'
               AND NEW.new_action_state = 'expired'
               AND NEW.reason_code = 'action_expired'
               AND NEW.observation_generation = action.expected_observation_generation
               AND NEW.decided_at_ms >= action.expires_at_ms)
              OR
              (NEW.decision_kind = 'revoke'
               AND NEW.new_action_state = 'revoked'
               AND NEW.reason_code = 'owner_revoked'
               AND NEW.observation_generation = action.expected_observation_generation
               AND EXISTS (
                   SELECT 1
                   FROM n5_trust_authorities AS authority
                   JOIN n5_owner_trust_roots AS root
                     ON root.trust_root_id = authority.trust_root_id
                    AND root.network_id = authority.network_id
                   WHERE authority.authority_id = action.authority_id
                     AND authority.authority_generation = action.authority_generation
                     AND (
                         authority.enabled = 0
                         OR authority.revoked_at_ms IS NOT NULL
                         OR root.enabled = 0
                         OR root.revoked_at_ms IS NOT NULL
                     )
               ))
          )
          AND audit.network_id = NEW.network_id
          AND audit.device_id IS NULL
          AND audit.generation = NEW.observation_generation
          AND audit.outcome = 'success'
          AND audit.event_kind = 'device.adoption_action_' || NEW.new_action_state
    )
BEGIN SELECT RAISE(ABORT, 'N5 adoption decision is not exactly correlated'); END;

CREATE TRIGGER n5_adoption_decision_terminalize_graph
AFTER INSERT ON n5_adoption_decisions
FOR EACH ROW BEGIN
    UPDATE n5_adoption_proof_operations
    SET operation_state = 'settled',
        outcome = CASE NEW.decision_kind
            WHEN 'conflict' THEN 'conflicted'
            ELSE 'unavailable'
        END,
        receipt_id = NEW.decision_id || ':' || operation_id,
        settled_at_ms = NEW.decided_at_ms
    WHERE action_id = NEW.action_id
      AND operation_state = 'pending';

    UPDATE n5_adoption_actions
    SET action_state = NEW.new_action_state,
        terminal_decision_id = NEW.decision_id,
        terminal_at_ms = NEW.decided_at_ms,
        terminal_reason = NEW.reason_code
    WHERE action_id = NEW.action_id
      AND action_state = 'proof_pending';
    SELECT CASE WHEN changes() <> 1
        THEN RAISE(ABORT, 'N5 adoption decision did not terminalize exactly one action') END;
END;

CREATE TRIGGER n5_adoption_decision_immutable_update
BEFORE UPDATE ON n5_adoption_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption decisions are append-only'); END;
CREATE TRIGGER n5_adoption_decision_immutable_delete
BEFORE DELETE ON n5_adoption_decisions
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption decisions are append-only'); END;

CREATE TRIGGER n5_adoption_evidence_v8_insert_blocked
BEFORE INSERT ON n5_existing_adoption_evidence
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption evidence insertion is unavailable before a reviewed later slice'); END;

CREATE TRIGGER n5_adoption_evidence_immutable_update
BEFORE UPDATE ON n5_existing_adoption_evidence
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption evidence is append-only'); END;
CREATE TRIGGER n5_adoption_evidence_immutable_delete
BEFORE DELETE ON n5_existing_adoption_evidence
FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'N5 adoption evidence is append-only'); END;
