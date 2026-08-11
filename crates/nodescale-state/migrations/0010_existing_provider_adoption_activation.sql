DROP TRIGGER n5_adoption_evidence_v8_insert_blocked;
DROP TRIGGER n5_adoption_proof_operation_lifecycle;
DROP TRIGGER n5_adoption_decision_insert_guard;
DROP TRIGGER n5_adoption_decision_terminalize_graph;
DROP TRIGGER n5_existing_adoption_identity_origin_v9_block;
DROP TRIGGER n5_existing_adoption_provider_binding_v9_block;

CREATE TRIGGER n5_adoption_evidence_v10_insert_guard
BEFORE INSERT ON n5_existing_adoption_evidence
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM n5_adoption_actions action
    JOIN n5_adoption_proof_operations proof
      ON proof.action_id=action.action_id
     AND proof.operation_id=NEW.proof_operation_id
     AND proof.operation_state='pending'
    JOIN provider_observations observation
      ON observation.observation_id=action.observation_id
     AND observation.network_id=NEW.network_id
     AND observation.provider_instance_id=NEW.provider_instance_id
     AND observation.provider_node_id=NEW.provider_node_id
     AND observation.semantic_generation=NEW.observation_generation
     AND observation.stable_key_fingerprint=NEW.observation_fingerprint
     AND observation.semantic_fingerprint=NEW.observation_semantic_fingerprint
     AND observation.classification='discovered_unmanaged'
     AND observation.adoption_state='pending_device_credential_proof'
     AND observation.device_id IS NULL
    JOIN provider_imports import
      ON import.network_id=NEW.network_id
     AND import.provider_instance_id=NEW.provider_instance_id
     AND import.compatibility_pin=NEW.provider_compatibility_pin
    JOIN n5_trust_authorities authority
      ON authority.authority_id=action.authority_id
     AND authority.network_id=action.network_id
     AND authority.authority_generation=action.authority_generation
     AND authority.sealed=1 AND authority.enabled=1 AND authority.revoked_at_ms IS NULL
    JOIN n5_owner_trust_roots root
      ON root.trust_root_id=authority.trust_root_id
     AND root.network_id=authority.network_id
     AND root.enabled=1 AND root.revoked_at_ms IS NULL
    JOIN n5_trust_authority_capabilities capability
      ON capability.authority_id=authority.authority_id
     AND capability.capability='AdoptExistingProviderDevice'
    WHERE action.action_id=NEW.action_id
      AND action.action_state='proof_pending'
      AND action.network_id=NEW.network_id
      AND action.provider_kind=NEW.provider_kind
      AND action.provider_instance_id=NEW.provider_instance_id
      AND action.provider_node_id=NEW.provider_node_id
      AND action.expected_observation_generation=NEW.observation_generation
      AND action.expected_observation_fingerprint=NEW.observation_fingerprint
      AND action.expected_semantic_fingerprint=NEW.observation_semantic_fingerprint
      AND action.expected_machine_key_fingerprint=NEW.machine_key_fingerprint
      AND action.expected_node_key_fingerprint=NEW.node_key_fingerprint
      AND action.proof_generation=NEW.proof_generation
      AND action.proof_method=NEW.proof_method
      AND NEW.verified_at_ms>=action.not_before_ms
      AND NEW.verified_at_ms<action.expires_at_ms
      AND NEW.verified_at_ms>=authority.not_before_ms
      AND NEW.verified_at_ms<authority.expires_at_ms
)
BEGIN SELECT RAISE(ABORT,'N5 adoption evidence requires exact current action, authority, observation, and proof'); END;

CREATE TRIGGER n5_adoption_proof_operation_v10_lifecycle
BEFORE UPDATE ON n5_adoption_proof_operations
FOR EACH ROW WHEN OLD.operation_state<>'pending'
 OR NEW.operation_state<>'settled'
 OR NEW.settled_at_ms IS NULL
 OR (
   NEW.outcome='confirmed' AND (
     NEW.resulting_device_id IS NULL OR NEW.resulting_provider_binding_id IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM n5_adoption_decisions decision
       JOIN n5_existing_adoption_evidence evidence
         ON evidence.evidence_id=decision.evidence_id
        AND evidence.action_id=OLD.action_id
        AND evidence.proof_operation_id=OLD.operation_id
       WHERE decision.action_id=OLD.action_id
         AND decision.decision_kind='confirm'
         AND decision.device_id=NEW.resulting_device_id
         AND decision.provider_binding_id=NEW.resulting_provider_binding_id
     )
   )
 )
 OR (
   NEW.outcome='conflicted' AND NOT EXISTS (
     SELECT 1 FROM n5_adoption_decisions decision
     WHERE decision.action_id=OLD.action_id
       AND decision.decision_kind='conflict'
       AND decision.new_action_state='conflicted'
   )
 )
 OR (
   NEW.outcome IN ('rejected','conflicted','unavailable')
   AND (NEW.resulting_device_id IS NOT NULL OR NEW.resulting_provider_binding_id IS NOT NULL)
 )
 OR NEW.outcome NOT IN ('confirmed','rejected','conflicted','unavailable')
BEGIN SELECT RAISE(ABORT,'N5 adoption proof operation transition is invalid'); END;

CREATE TRIGGER n5_adoption_decision_v10_insert_guard
BEFORE INSERT ON n5_adoption_decisions
FOR EACH ROW WHEN
  (NEW.decision_kind='confirm' AND NOT EXISTS (
    SELECT 1
    FROM n5_adoption_actions action
    JOIN n5_adoption_proof_operations proof
      ON proof.action_id=action.action_id
     AND proof.operation_id=NEW.proof_operation_id
     AND proof.operation_state='pending'
    JOIN n5_existing_adoption_evidence evidence
      ON evidence.evidence_id=NEW.evidence_id
     AND evidence.action_id=action.action_id
     AND evidence.proof_operation_id=proof.operation_id
     AND evidence.network_id=NEW.network_id
     AND evidence.provider_instance_id=NEW.provider_instance_id
     AND evidence.provider_node_id=NEW.provider_node_id
     AND evidence.observation_generation=NEW.observation_generation
     AND evidence.proof_generation=NEW.proof_generation
    JOIN provider_observations observation
      ON observation.observation_id=action.observation_id
     AND observation.network_id=NEW.network_id
     AND observation.provider_instance_id=NEW.provider_instance_id
     AND observation.provider_node_id=NEW.provider_node_id
     AND observation.semantic_generation=NEW.observation_generation
     AND observation.adoption_state='pending_device_credential_proof'
     AND observation.device_id IS NULL
    JOIN n5_trust_authorities authority
      ON authority.authority_id=NEW.authority_id
     AND authority.network_id=NEW.network_id
     AND authority.authority_generation=NEW.authority_generation
     AND authority.sealed=1 AND authority.enabled=1 AND authority.revoked_at_ms IS NULL
    JOIN n5_owner_trust_roots root
      ON root.trust_root_id=authority.trust_root_id
     AND root.enabled=1 AND root.revoked_at_ms IS NULL
    JOIN audit_events audit
      ON audit.event_id=NEW.audit_event_id
     AND audit.network_id=NEW.network_id
     AND audit.device_id=NEW.device_id
     AND audit.event_kind='device.adoption_confirmed'
     AND audit.outcome='success'
    WHERE action.action_id=NEW.action_id
      AND action.action_state='proof_pending'
      AND action.authority_id=NEW.authority_id
      AND action.authority_generation=NEW.authority_generation
      AND action.network_id=NEW.network_id
      AND action.provider_instance_id=NEW.provider_instance_id
      AND action.provider_node_id=NEW.provider_node_id
      AND action.proof_generation=NEW.proof_generation
      AND NEW.prior_action_state='proof_pending'
      AND NEW.new_action_state='confirmed'
      AND NEW.reason_code='proof_confirmed'
  ))
  OR (NEW.decision_kind<>'confirm' AND NOT EXISTS (
    SELECT 1
    FROM n5_adoption_actions action
    JOIN audit_events audit ON audit.event_id=NEW.audit_event_id
    JOIN provider_observations observation
      ON observation.observation_id=action.observation_id
     AND observation.network_id=NEW.network_id
     AND observation.provider_instance_id=NEW.provider_instance_id
     AND observation.provider_node_id=NEW.provider_node_id
     AND observation.semantic_generation=NEW.observation_generation
     AND observation.adoption_state='pending_device_credential_proof'
    WHERE action.action_id=NEW.action_id
      AND action.action_state='proof_pending'
      AND action.authority_id=NEW.authority_id
      AND action.authority_generation=NEW.authority_generation
      AND action.network_id=NEW.network_id
      AND action.provider_instance_id=NEW.provider_instance_id
      AND action.provider_node_id=NEW.provider_node_id
      AND action.proof_generation=NEW.proof_generation
      AND NEW.prior_action_state='proof_pending'
      AND ((NEW.decision_kind='conflict' AND NEW.new_action_state='conflicted'
             AND NEW.reason_code IN ('observation_changed','provider_missing','provider_expired','identity_conflict')
             AND NEW.observation_generation>action.expected_observation_generation
             AND (NEW.reason_code='observation_changed'
               OR (NEW.reason_code='provider_missing' AND observation.classification='provider_missing')
               OR (NEW.reason_code='provider_expired' AND observation.classification='provider_expired')
               OR (NEW.reason_code='identity_conflict' AND observation.classification='identity_conflict')))
        OR (NEW.decision_kind='expire' AND NEW.new_action_state='expired'
             AND NEW.reason_code='action_expired'
             AND NEW.observation_generation=action.expected_observation_generation
             AND NEW.decided_at_ms>=action.expires_at_ms)
        OR (NEW.decision_kind='revoke' AND NEW.new_action_state='revoked'
             AND NEW.reason_code='owner_revoked'
             AND NEW.observation_generation=action.expected_observation_generation
             AND EXISTS (
               SELECT 1 FROM n5_trust_authorities authority
               JOIN n5_owner_trust_roots root
                 ON root.trust_root_id=authority.trust_root_id
                AND root.network_id=authority.network_id
               WHERE authority.authority_id=action.authority_id
                 AND authority.authority_generation=action.authority_generation
                 AND (authority.enabled=0 OR authority.revoked_at_ms IS NOT NULL
                      OR root.enabled=0 OR root.revoked_at_ms IS NOT NULL)
             )))
      AND audit.network_id=NEW.network_id
      AND audit.device_id IS NULL
      AND audit.generation=NEW.observation_generation
      AND audit.outcome='success'
      AND audit.event_kind='device.adoption_action_' || NEW.new_action_state
  ))
BEGIN SELECT RAISE(ABORT,'N5 adoption decision is not exactly correlated'); END;

CREATE TRIGGER n5_adoption_decision_v10_terminalize_graph
AFTER INSERT ON n5_adoption_decisions
FOR EACH ROW BEGIN
  UPDATE n5_adoption_proof_operations
  SET operation_state='settled',
      outcome=CASE NEW.decision_kind WHEN 'confirm' THEN 'confirmed' WHEN 'conflict' THEN 'conflicted' ELSE 'unavailable' END,
      receipt_id=NEW.decision_id || ':' || operation_id,
      resulting_device_id=CASE NEW.decision_kind WHEN 'confirm' THEN NEW.device_id ELSE NULL END,
      resulting_provider_binding_id=CASE NEW.decision_kind WHEN 'confirm' THEN NEW.provider_binding_id ELSE NULL END,
      settled_at_ms=NEW.decided_at_ms
  WHERE action_id=NEW.action_id AND operation_state='pending';

  UPDATE n5_adoption_actions
  SET action_state=NEW.new_action_state,
      terminal_decision_id=NEW.decision_id,
      terminal_at_ms=NEW.decided_at_ms,
      terminal_reason=NEW.reason_code
  WHERE action_id=NEW.action_id AND action_state='proof_pending';
  SELECT CASE WHEN changes()<>1 THEN RAISE(ABORT,'N5 adoption decision did not terminalize exactly one action') END;
END;
