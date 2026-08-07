PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS networks (
    network_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    provider_kind TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL UNIQUE,
    membership_generation INTEGER NOT NULL CHECK (membership_generation > 0),
    policy_generation INTEGER NOT NULL CHECK (policy_generation > 0),
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    membership_state TEXT NOT NULL,
    provider_instance_id TEXT,
    provider_node_id TEXT,
    provider_key_fingerprint TEXT,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    keryx_binding_generation INTEGER NOT NULL CHECK (keryx_binding_generation > 0),
    fleet_projection_generation INTEGER NOT NULL CHECK (fleet_projection_generation > 0),
    fleet_projection_status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(network_id, display_name),
    UNIQUE(provider_instance_id, provider_node_id, provider_key_fingerprint)
);

CREATE TABLE IF NOT EXISTS invitations (
    invitation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    state TEXT NOT NULL,
    secret_verifier TEXT NOT NULL UNIQUE,
    provider_credential_reference TEXT,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    used_count INTEGER NOT NULL CHECK (used_count >= 0 AND used_count <= max_uses),
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS join_sessions (
    join_session_id TEXT PRIMARY KEY,
    invitation_id TEXT NOT NULL REFERENCES invitations(invitation_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keryx_bindings (
    binding_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    verified_peer_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL,
    verified_at TEXT,
    record_json TEXT NOT NULL,
    UNIQUE(network_id, device_id, generation),
    UNIQUE(network_id, verified_peer_id, generation)
);

CREATE TABLE IF NOT EXISTS provider_observations (
    observation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    stable_key_fingerprint TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    UNIQUE(provider_instance_id, provider_node_id, stable_key_fingerprint, observed_at)
);

CREATE TABLE IF NOT EXISTS membership_generations (
    network_id TEXT PRIMARY KEY REFERENCES networks(network_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation > 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_generations (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE RESTRICT,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    keryx_binding_generation INTEGER NOT NULL CHECK (keryx_binding_generation > 0),
    fleet_projection_generation INTEGER NOT NULL CHECK (fleet_projection_generation > 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL UNIQUE REFERENCES devices(device_id) ON DELETE RESTRICT,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    application_trust_removed_at TEXT,
    provider_cleanup_completed_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    network_id TEXT REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    actor_source TEXT NOT NULL,
    actor_id TEXT,
    event_kind TEXT NOT NULL,
    outcome TEXT NOT NULL,
    generation INTEGER,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json))
);

CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id);
CREATE INDEX IF NOT EXISTS idx_audit_network_time ON audit_events(network_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_device_time ON audit_events(device_id, timestamp);
