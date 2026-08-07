PRAGMA foreign_keys = ON;

ALTER TABLE provider_observations RENAME TO provider_observations_n1a;

CREATE TABLE provider_observations (
    observation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    provider_instance_id TEXT NOT NULL,
    provider_node_id TEXT NOT NULL,
    stable_key_fingerprint TEXT NOT NULL,
    classification TEXT NOT NULL,
    adoption_state TEXT NOT NULL,
    semantic_fingerprint TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    UNIQUE(provider_instance_id, provider_node_id)
);

INSERT INTO provider_observations (
    observation_id,
    network_id,
    device_id,
    provider_instance_id,
    provider_node_id,
    stable_key_fingerprint,
    classification,
    adoption_state,
    semantic_fingerprint,
    normalized_json,
    first_observed_at,
    last_observed_at,
    snapshot_at
)
SELECT
    latest.observation_id,
    latest.network_id,
    latest.device_id,
    latest.provider_instance_id,
    latest.provider_node_id,
    latest.stable_key_fingerprint,
    'discovered_unmanaged',
    'unmanaged',
    '',
    latest.normalized_json,
    first_seen.first_observed_at,
    latest.observed_at,
    latest.observed_at
FROM provider_observations_n1a AS latest
JOIN (
    SELECT provider_instance_id, provider_node_id, MIN(observed_at) AS first_observed_at
    FROM provider_observations_n1a
    GROUP BY provider_instance_id, provider_node_id
) AS first_seen
    ON first_seen.provider_instance_id = latest.provider_instance_id
   AND first_seen.provider_node_id = latest.provider_node_id
WHERE latest.rowid = (
    SELECT candidate.rowid
    FROM provider_observations_n1a AS candidate
    WHERE candidate.provider_instance_id = latest.provider_instance_id
      AND candidate.provider_node_id = latest.provider_node_id
    ORDER BY candidate.observed_at DESC, candidate.rowid DESC
    LIMIT 1
);

DROP TABLE provider_observations_n1a;

CREATE TABLE provider_imports (
    network_id TEXT PRIMARY KEY REFERENCES networks(network_id) ON DELETE RESTRICT,
    provider_instance_id TEXT NOT NULL UNIQUE,
    server_url TEXT NOT NULL,
    opaque_secret_reference TEXT NOT NULL,
    compatibility_pin TEXT NOT NULL,
    tls_verification TEXT NOT NULL CHECK (tls_verification = 'verify'),
    read_only INTEGER NOT NULL CHECK (read_only = 1),
    mutation_allowed INTEGER NOT NULL CHECK (mutation_allowed = 0),
    compatibility TEXT NOT NULL,
    provider_version TEXT NOT NULL,
    last_success_at TEXT,
    last_attempt_at TEXT,
    last_failure_kind TEXT,
    last_failure_detail TEXT
);

CREATE INDEX idx_provider_observations_network
    ON provider_observations(network_id, classification);
