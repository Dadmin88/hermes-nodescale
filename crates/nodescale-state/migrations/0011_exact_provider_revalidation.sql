DROP TRIGGER n5_binding_state_transitions;
DROP TRIGGER n5_binding_transition_emits_audit;

CREATE TRIGGER n5_binding_state_transitions
BEFORE UPDATE OF binding_state, binding_revision, stale_at_ms, cleanup_pending_at_ms, removed_at_ms, last_transition_audit_event_id, transition_actor_source, transition_actor_id
ON n5_provider_bindings
FOR EACH ROW WHEN NEW.binding_revision <> OLD.binding_revision + 1
    OR NEW.last_transition_audit_event_id IS OLD.last_transition_audit_event_id
    OR NEW.transition_actor_source IS NULL
    OR NOT (
        (OLD.binding_state = 'active' AND NEW.binding_state IN ('stale','cleanup_pending'))
        OR (OLD.binding_state = 'stale' AND NEW.binding_state IN ('active','cleanup_pending','removed'))
        OR (OLD.binding_state = 'cleanup_pending' AND NEW.binding_state = 'removed')
    )
BEGIN SELECT RAISE(ABORT, 'unsafe N5 provider binding transition'); END;

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
                WHEN 'active' THEN NEW.observed_at_ms
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
            WHEN 'active' THEN 'device.provider_binding_revalidated'
            WHEN 'stale' THEN 'device.provider_binding_stale'
            WHEN 'cleanup_pending' THEN 'device.provider_binding_cleanup_pending'
            ELSE 'device.provider_binding_removed'
        END,
        'success',
        NEW.binding_revision,
        '{}'
    );
END;
