PRAGMA foreign_keys = ON;

-- N4A deliberately extends rather than rebuilds the legacy invitation/session
-- projections. Rows without an extension row are legacy and cannot use N4 APIs.
CREATE TABLE n4_invitation_details (
    invitation_id TEXT PRIMARY KEY REFERENCES invitations(invitation_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    provider_principal_id TEXT NOT NULL CHECK (length(provider_principal_id) BETWEEN 1 AND 255),
    roles_json TEXT NOT NULL CHECK (json_valid(roles_json) AND json_type(roles_json) = 'array'),
    constraints_json TEXT NOT NULL CHECK (json_valid(constraints_json) AND json_type(constraints_json) = 'object'),
    created_by_source TEXT NOT NULL CHECK (length(created_by_source) BETWEEN 1 AND 255),
    created_by_id TEXT,
    revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 1),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR (typeof(consumed_at_ms) = 'integer' AND consumed_at_ms >= 0)),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (typeof(revoked_at_ms) = 'integer' AND revoked_at_ms >= 0)),
    expired_at_ms INTEGER CHECK (expired_at_ms IS NULL OR (typeof(expired_at_ms) = 'integer' AND expired_at_ms >= 0)),
    last_redemption_at_ms INTEGER CHECK (last_redemption_at_ms IS NULL OR (typeof(last_redemption_at_ms) = 'integer' AND last_redemption_at_ms >= 0)),
    last_redemption_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(last_redemption_metadata_json) AND json_type(last_redemption_metadata_json) = 'object'
        AND (last_redemption_metadata_json = '{}' OR (
            json_type(last_redemption_metadata_json, '$.sha256') = 'text'
            AND length(json_extract(last_redemption_metadata_json, '$.sha256')) = 64
            AND json_extract(last_redemption_metadata_json, '$.sha256') NOT GLOB '*[^0-9a-f]*'
            AND json_remove(last_redemption_metadata_json, '$.sha256') = '{}'
        ))
    ),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_mutation_configurations(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE n4_join_session_dispatches (
    join_session_id TEXT PRIMARY KEY REFERENCES join_sessions(join_session_id) ON DELETE RESTRICT,
    invitation_id TEXT NOT NULL REFERENCES n4_invitation_details(invitation_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    provider_principal_id TEXT NOT NULL CHECK (length(provider_principal_id) BETWEEN 1 AND 255),
    create_request_id TEXT NOT NULL UNIQUE CHECK (length(create_request_id) = 36 AND create_request_id GLOB '????????-????-????-????-????????????'),
    dispatch_state TEXT NOT NULL CHECK (dispatch_state IN ('reserved','dispatch_started','confirmed','ambiguous','failed_pre_dispatch','failed_no_apply','revocation_pending','revoked','expired')),
    authorization_generation INTEGER CHECK (authorization_generation IS NULL OR (typeof(authorization_generation) = 'integer' AND authorization_generation > 0)),
    configuration_generation INTEGER CHECK (configuration_generation IS NULL OR (typeof(configuration_generation) = 'integer' AND configuration_generation > 0)),
    configuration_fingerprint TEXT CHECK (configuration_fingerprint IS NULL OR (length(configuration_fingerprint) = 71 AND configuration_fingerprint GLOB 'sha256:*' AND substr(configuration_fingerprint, 8) NOT GLOB '*[^0-9a-f]*')),
    dispatched_at_ms INTEGER CHECK (dispatched_at_ms IS NULL OR (typeof(dispatched_at_ms) = 'integer' AND dispatched_at_ms >= 0)),
    resolved_at_ms INTEGER CHECK (resolved_at_ms IS NULL OR (typeof(resolved_at_ms) = 'integer' AND resolved_at_ms >= 0)),
    credential_id TEXT REFERENCES confirmed_provider_credential_references(credential_id) ON DELETE RESTRICT,
    UNIQUE (invitation_id),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_mutation_configurations(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((dispatch_state IN ('reserved','failed_pre_dispatch') AND authorization_generation IS NULL AND configuration_generation IS NULL AND configuration_fingerprint IS NULL AND dispatched_at_ms IS NULL)
        OR (dispatch_state NOT IN ('reserved','failed_pre_dispatch') AND authorization_generation IS NOT NULL AND configuration_generation IS NOT NULL AND configuration_fingerprint IS NOT NULL AND dispatched_at_ms IS NOT NULL)),
    CHECK ((dispatch_state = 'confirmed' AND credential_id IS NOT NULL) OR (dispatch_state <> 'confirmed'))
);

CREATE TABLE n4_provider_credential_metadata (
    credential_id TEXT PRIMARY KEY REFERENCES confirmed_provider_credential_references(credential_id) ON DELETE RESTRICT,
    join_session_id TEXT NOT NULL UNIQUE REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT,
    network_id TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    provider_principal_id TEXT NOT NULL CHECK (length(provider_principal_id) BETWEEN 1 AND 255),
    single_use INTEGER NOT NULL CHECK (single_use = 1),
    reusable INTEGER NOT NULL CHECK (reusable = 0),
    ephemeral INTEGER NOT NULL CHECK (ephemeral IN (0, 1)),
    approved_tags_json TEXT NOT NULL CHECK (json_valid(approved_tags_json) AND json_type(approved_tags_json) = 'array'),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms >= 0),
    confirmed_at_ms INTEGER NOT NULL CHECK (typeof(confirmed_at_ms) = 'integer' AND confirmed_at_ms >= 0 AND expires_at_ms > confirmed_at_ms),
    invalidation_state TEXT NOT NULL CHECK (invalidation_state IN ('active','pending','confirmed','retryable','ambiguous','blocked')),
    invalidated_at_ms INTEGER CHECK (invalidated_at_ms IS NULL OR (typeof(invalidated_at_ms) = 'integer' AND invalidated_at_ms >= 0)),
    safe_correlation_json TEXT NOT NULL CHECK (
        json_valid(safe_correlation_json) AND json_type(safe_correlation_json) = 'object'
        AND (safe_correlation_json = '{}' OR (
            json_type(safe_correlation_json, '$.sha256') = 'text'
            AND length(json_extract(safe_correlation_json, '$.sha256')) = 64
            AND json_extract(safe_correlation_json, '$.sha256') NOT GLOB '*[^0-9a-f]*'
            AND json_remove(safe_correlation_json, '$.sha256') = '{}'
        ))
    ),
    CHECK ((invalidation_state = 'confirmed') = (invalidated_at_ms IS NOT NULL)),
    FOREIGN KEY (network_id, provider_instance_id)
        REFERENCES provider_mutation_configurations(network_id, provider_instance_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE n4_audit_correlations (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    invitation_id TEXT REFERENCES n4_invitation_details(invitation_id) ON DELETE RESTRICT,
    join_session_id TEXT REFERENCES n4_join_session_dispatches(join_session_id) ON DELETE RESTRICT,
    action_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    UNIQUE(action_id, event_kind)
);

CREATE TRIGGER n4_invitation_requires_single_use
BEFORE INSERT ON n4_invitation_details
FOR EACH ROW WHEN NOT EXISTS (SELECT 1 FROM invitations WHERE invitation_id = NEW.invitation_id AND network_id = NEW.network_id AND max_uses = 1)
BEGIN SELECT RAISE(ABORT, 'N4 invitation requires matching single-use base invitation'); END;

CREATE TRIGGER n4_invitation_verifier_immutable
BEFORE UPDATE OF secret_verifier ON invitations
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM n4_invitation_details WHERE invitation_id = OLD.invitation_id)
BEGIN SELECT RAISE(ABORT, 'N4 invitation verifier is immutable'); END;

CREATE TRIGGER n4_base_invitation_linkage_immutable
BEFORE UPDATE OF network_id, max_uses ON invitations
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM n4_invitation_details WHERE invitation_id = OLD.invitation_id)
    AND (NEW.network_id <> OLD.network_id OR NEW.max_uses <> 1)
BEGIN SELECT RAISE(ABORT, 'N4 base invitation linkage and single-use limit are immutable'); END;

CREATE TRIGGER n4_details_safe_metadata_insert
BEFORE INSERT ON n4_invitation_details
FOR EACH ROW WHEN lower(NEW.last_redemption_metadata_json) LIKE '%secret%' OR lower(NEW.last_redemption_metadata_json) LIKE '%token%' OR lower(NEW.last_redemption_metadata_json) LIKE '%password%'
BEGIN SELECT RAISE(ABORT, 'N4 redemption metadata must be secret-free'); END;
CREATE TRIGGER n4_details_safe_metadata_update
BEFORE UPDATE OF last_redemption_metadata_json ON n4_invitation_details
FOR EACH ROW WHEN lower(NEW.last_redemption_metadata_json) LIKE '%secret%' OR lower(NEW.last_redemption_metadata_json) LIKE '%token%' OR lower(NEW.last_redemption_metadata_json) LIKE '%password%'
BEGIN SELECT RAISE(ABORT, 'N4 redemption metadata must be secret-free'); END;

CREATE TRIGGER n4_dispatch_links_match_session_insert
BEFORE INSERT ON n4_join_session_dispatches
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM join_sessions s JOIN n4_invitation_details d ON d.invitation_id = NEW.invitation_id
    WHERE s.join_session_id = NEW.join_session_id AND s.invitation_id = NEW.invitation_id
      AND s.network_id = NEW.network_id AND d.network_id = NEW.network_id
      AND d.provider_instance_id = NEW.provider_instance_id
      AND d.provider_principal_id = NEW.provider_principal_id
)
BEGIN SELECT RAISE(ABORT, 'N4 dispatch must match session, invitation, network, and provider'); END;
CREATE TRIGGER n4_dispatch_links_match_update
BEFORE UPDATE OF join_session_id, invitation_id, network_id, provider_instance_id, provider_principal_id ON n4_join_session_dispatches
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM join_sessions s JOIN n4_invitation_details d ON d.invitation_id = NEW.invitation_id
    WHERE s.join_session_id = NEW.join_session_id AND s.invitation_id = NEW.invitation_id
      AND s.network_id = NEW.network_id AND d.network_id = NEW.network_id
      AND d.provider_instance_id = NEW.provider_instance_id
      AND d.provider_principal_id = NEW.provider_principal_id
)
BEGIN SELECT RAISE(ABORT, 'N4 dispatch must match session, invitation, network, and provider'); END;

CREATE TRIGGER n4_base_join_session_linkage_immutable
BEFORE UPDATE OF invitation_id, network_id ON join_sessions
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM n4_join_session_dispatches WHERE join_session_id = OLD.join_session_id)
    AND (NEW.invitation_id <> OLD.invitation_id OR NEW.network_id <> OLD.network_id)
BEGIN SELECT RAISE(ABORT, 'N4 base join-session linkage is immutable'); END;

CREATE TRIGGER n4_dispatch_state_transitions
BEFORE UPDATE OF dispatch_state ON n4_join_session_dispatches
FOR EACH ROW WHEN NOT (
    (OLD.dispatch_state = 'reserved' AND NEW.dispatch_state IN ('dispatch_started','failed_pre_dispatch','revoked','expired')) OR
    (OLD.dispatch_state = 'dispatch_started' AND NEW.dispatch_state IN ('confirmed','ambiguous','failed_no_apply','revocation_pending')) OR
    (OLD.dispatch_state = 'confirmed' AND NEW.dispatch_state IN ('revocation_pending','revoked','expired')) OR
    (OLD.dispatch_state = 'ambiguous' AND NEW.dispatch_state IN ('revocation_pending','revoked','expired')) OR
    (OLD.dispatch_state = 'revocation_pending' AND NEW.dispatch_state IN ('revoked','expired')) OR
    OLD.dispatch_state = NEW.dispatch_state
)
BEGIN SELECT RAISE(ABORT, 'unsafe N4 dispatch state transition'); END;

CREATE TRIGGER n4_credential_links_match
BEFORE INSERT ON n4_provider_credential_metadata
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n4_join_session_dispatches d JOIN confirmed_provider_credential_references r ON r.credential_id = NEW.credential_id
    WHERE d.join_session_id = NEW.join_session_id AND d.credential_id = NEW.credential_id
      AND d.network_id = NEW.network_id AND d.provider_instance_id = NEW.provider_instance_id
      AND d.provider_principal_id = NEW.provider_principal_id
      AND r.network_id = NEW.network_id AND r.provider_instance_id = NEW.provider_instance_id
)
BEGIN SELECT RAISE(ABORT, 'N4 credential metadata must match confirmed dispatch provenance'); END;
CREATE TRIGGER n4_credential_safe_correlation
BEFORE INSERT ON n4_provider_credential_metadata
FOR EACH ROW WHEN lower(NEW.safe_correlation_json) LIKE '%secret%' OR lower(NEW.safe_correlation_json) LIKE '%token%' OR lower(NEW.safe_correlation_json) LIKE '%password%'
BEGIN SELECT RAISE(ABORT, 'N4 credential correlation must be secret-free'); END;

-- Exact provider identity/reference linkage is immutable after confirmation.
CREATE TRIGGER n4_dispatch_linkage_immutable
BEFORE UPDATE ON n4_join_session_dispatches
FOR EACH ROW WHEN NEW.join_session_id <> OLD.join_session_id OR NEW.invitation_id <> OLD.invitation_id
    OR NEW.network_id <> OLD.network_id OR NEW.provider_instance_id <> OLD.provider_instance_id
    OR NEW.provider_principal_id <> OLD.provider_principal_id OR NEW.create_request_id <> OLD.create_request_id
    OR (OLD.credential_id IS NOT NULL AND COALESCE(NEW.credential_id, '') <> OLD.credential_id)
    OR (OLD.dispatch_state <> 'reserved' AND (COALESCE(NEW.authorization_generation, 0) <> COALESCE(OLD.authorization_generation, 0)
        OR COALESCE(NEW.configuration_generation, 0) <> COALESCE(OLD.configuration_generation, 0)
        OR COALESCE(NEW.configuration_fingerprint, '') <> COALESCE(OLD.configuration_fingerprint, '')
        OR COALESCE(NEW.dispatched_at_ms, 0) <> COALESCE(OLD.dispatched_at_ms, 0)))
    OR (OLD.resolved_at_ms IS NOT NULL AND COALESCE(NEW.resolved_at_ms, -1) <> OLD.resolved_at_ms)
BEGIN SELECT RAISE(ABORT, 'N4 dispatch provenance is immutable'); END;

CREATE TRIGGER n4_audit_correlation_immutable
BEFORE UPDATE ON n4_audit_correlations
FOR EACH ROW
BEGIN SELECT RAISE(ABORT, 'N4 audit correlation is immutable'); END;

CREATE TRIGGER n4_details_provenance_immutable
BEFORE UPDATE ON n4_invitation_details
FOR EACH ROW WHEN NEW.network_id <> OLD.network_id
    OR NEW.provider_instance_id <> OLD.provider_instance_id
    OR NEW.provider_principal_id <> OLD.provider_principal_id
    OR NEW.roles_json <> OLD.roles_json
    OR NEW.constraints_json <> OLD.constraints_json
    OR NEW.created_by_source <> OLD.created_by_source
    OR COALESCE(NEW.created_by_id, '') <> COALESCE(OLD.created_by_id, '')
BEGIN SELECT RAISE(ABORT, 'N4 invitation provenance is immutable'); END;

CREATE TRIGGER n4_credential_metadata_immutable
BEFORE UPDATE ON n4_provider_credential_metadata
FOR EACH ROW WHEN NEW.credential_id <> OLD.credential_id OR NEW.join_session_id <> OLD.join_session_id
    OR NEW.network_id <> OLD.network_id OR NEW.provider_instance_id <> OLD.provider_instance_id
    OR NEW.provider_principal_id <> OLD.provider_principal_id OR NEW.single_use <> OLD.single_use
    OR NEW.reusable <> OLD.reusable OR NEW.ephemeral <> OLD.ephemeral
    OR NEW.approved_tags_json <> OLD.approved_tags_json OR NEW.expires_at_ms <> OLD.expires_at_ms
    OR NEW.confirmed_at_ms <> OLD.confirmed_at_ms OR NEW.safe_correlation_json <> OLD.safe_correlation_json
BEGIN SELECT RAISE(ABORT, 'N4 credential metadata provenance is immutable'); END;

CREATE TRIGGER n4_credential_links_match_update
BEFORE UPDATE ON n4_provider_credential_metadata
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM n4_join_session_dispatches d JOIN confirmed_provider_credential_references r ON r.credential_id = NEW.credential_id
    WHERE d.join_session_id = NEW.join_session_id AND d.credential_id = NEW.credential_id
      AND d.network_id = NEW.network_id AND d.provider_instance_id = NEW.provider_instance_id
      AND d.provider_principal_id = NEW.provider_principal_id
      AND r.network_id = NEW.network_id AND r.provider_instance_id = NEW.provider_instance_id
)
BEGIN SELECT RAISE(ABORT, 'N4 credential metadata must match confirmed dispatch provenance'); END;

CREATE TRIGGER n4_credential_invalidation_transitions
BEFORE UPDATE OF invalidation_state, invalidated_at_ms ON n4_provider_credential_metadata
FOR EACH ROW WHEN NOT (
    (OLD.invalidation_state = 'active' AND NEW.invalidation_state = 'pending') OR
    (OLD.invalidation_state = 'pending' AND NEW.invalidation_state IN ('pending','confirmed','retryable','ambiguous','blocked')) OR
    (OLD.invalidation_state IN ('retryable','ambiguous','blocked') AND NEW.invalidation_state IN ('retryable','ambiguous','blocked','confirmed')) OR
    (OLD.invalidation_state = 'confirmed' AND NEW.invalidation_state = 'confirmed')
) OR (OLD.invalidated_at_ms IS NOT NULL AND NEW.invalidated_at_ms IS NOT OLD.invalidated_at_ms)
BEGIN SELECT RAISE(ABORT, 'unsafe N4 invalidation state transition'); END;
