PRAGMA foreign_keys = ON;

-- Keep provider_imports immutable as the read-only identity plane. Mutation
-- authority is additive and default-deny in a separate configuration plane.
CREATE UNIQUE INDEX idx_provider_import_identity_v3
    ON provider_imports(network_id, provider_instance_id);

CREATE TABLE provider_mutation_configurations (
    network_id TEXT PRIMARY KEY REFERENCES networks(network_id) ON DELETE RESTRICT,
    provider_instance_id TEXT NOT NULL UNIQUE,
    authorization_generation INTEGER NOT NULL
        CHECK (typeof(authorization_generation) = 'integer' AND authorization_generation > 0),
    configuration_generation INTEGER NOT NULL
        CHECK (typeof(configuration_generation) = 'integer' AND configuration_generation > 0),
    configuration_fingerprint TEXT NOT NULL
        CHECK (length(configuration_fingerprint) = 71 AND configuration_fingerprint GLOB 'sha256:*' AND substr(configuration_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    adapter TEXT NOT NULL CHECK (adapter = 'headscale'),
    expected_version TEXT NOT NULL CHECK (expected_version = 'v0.29.3'),
    enabled INTEGER NOT NULL CHECK (typeof(enabled) = 'integer' AND enabled IN (0, 1)),
    revoked INTEGER NOT NULL CHECK (typeof(revoked) = 'integer' AND revoked IN (0, 1)),
    not_before_ms INTEGER NOT NULL
        CHECK (typeof(not_before_ms) = 'integer' AND not_before_ms >= 0),
    expires_at_ms INTEGER NOT NULL
        CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms >= 0 AND not_before_ms < expires_at_ms),
    policy_mode TEXT NOT NULL CHECK (policy_mode IN ('database', 'file', 'unknown')),
    UNIQUE (network_id, provider_instance_id),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_imports(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE provider_mutation_capabilities (
    network_id TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    capability TEXT NOT NULL CHECK (capability IN (
        'EnsureNetworkPrincipal', 'CreateJoinCredential', 'InvalidateJoinCredential',
        'ReplaceNodeTags', 'ExpireNode', 'DeleteNode', 'ManagePolicy'
    )),
    PRIMARY KEY (network_id, provider_instance_id, capability),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_mutation_configurations(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE confirmed_provider_credential_references (
    credential_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    provider_reference TEXT NOT NULL
        CHECK (length(provider_reference) BETWEEN 1 AND 255),
    authorization_generation INTEGER NOT NULL
        CHECK (typeof(authorization_generation) = 'integer' AND authorization_generation > 0),
    configuration_generation INTEGER NOT NULL
        CHECK (typeof(configuration_generation) = 'integer' AND configuration_generation > 0),
    configuration_fingerprint TEXT NOT NULL
        CHECK (length(configuration_fingerprint) = 71 AND configuration_fingerprint GLOB 'sha256:*' AND substr(configuration_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'),
    confirmed_at_ms INTEGER NOT NULL
        CHECK (typeof(confirmed_at_ms) = 'integer' AND confirmed_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL
        CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms > confirmed_at_ms),
    max_uses INTEGER NOT NULL
        CHECK (typeof(max_uses) = 'integer' AND max_uses = 1),
    UNIQUE (network_id, provider_instance_id, provider_reference),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_mutation_configurations(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TRIGGER provider_mutation_configuration_requires_read_only_import_insert
BEFORE INSERT ON provider_mutation_configurations
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM provider_imports
    WHERE network_id = NEW.network_id
      AND provider_instance_id = NEW.provider_instance_id
      AND read_only = 1 AND mutation_allowed = 0
)
BEGIN SELECT RAISE(ABORT, 'mutation configuration requires exact read-only import'); END;

CREATE TRIGGER provider_mutation_configuration_requires_read_only_import_update
BEFORE UPDATE OF network_id, provider_instance_id ON provider_mutation_configurations
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM provider_imports
    WHERE network_id = NEW.network_id
      AND provider_instance_id = NEW.provider_instance_id
      AND read_only = 1 AND mutation_allowed = 0
)
BEGIN SELECT RAISE(ABORT, 'mutation configuration requires exact read-only import'); END;

CREATE TRIGGER provider_mutation_capability_manage_policy_database_insert
BEFORE INSERT ON provider_mutation_capabilities
FOR EACH ROW WHEN NEW.capability = 'ManagePolicy' AND NOT EXISTS (
    SELECT 1 FROM provider_mutation_configurations
    WHERE network_id = NEW.network_id AND policy_mode = 'database'
)
BEGIN SELECT RAISE(ABORT, 'manage_policy requires database policy mode'); END;

CREATE TRIGGER provider_mutation_capability_manage_policy_database_update
BEFORE UPDATE OF capability, network_id, provider_instance_id ON provider_mutation_capabilities
FOR EACH ROW WHEN NEW.capability = 'ManagePolicy' AND NOT EXISTS (
    SELECT 1 FROM provider_mutation_configurations
    WHERE network_id = NEW.network_id AND policy_mode = 'database'
)
BEGIN SELECT RAISE(ABORT, 'manage_policy requires database policy mode'); END;

CREATE TRIGGER provider_mutation_configuration_manage_policy_database_update
BEFORE UPDATE OF policy_mode ON provider_mutation_configurations
FOR EACH ROW WHEN NEW.policy_mode <> 'database' AND EXISTS (
    SELECT 1 FROM provider_mutation_capabilities
    WHERE network_id = NEW.network_id
      AND provider_instance_id = NEW.provider_instance_id
      AND capability = 'ManagePolicy'
)
BEGIN SELECT RAISE(ABORT, 'manage_policy requires database policy mode'); END;

CREATE TRIGGER provider_mutation_authorization_generation_must_advance
BEFORE UPDATE OF authorization_generation ON provider_mutation_configurations
FOR EACH ROW WHEN NEW.authorization_generation <= OLD.authorization_generation
BEGIN SELECT RAISE(ABORT, 'authorization generation must advance'); END;

CREATE TRIGGER provider_mutation_configuration_generation_must_advance
BEFORE UPDATE OF configuration_generation ON provider_mutation_configurations
FOR EACH ROW WHEN NEW.configuration_generation <= OLD.configuration_generation
BEGIN SELECT RAISE(ABORT, 'configuration generation must advance'); END;
