use super::*;
use nodescale_domain::{
    AgentVersion, BindingNonce, BindingNonceVerifier, Generation, KeryxBindingAuthorization,
    KeryxBindingAuthorizationCapability, KeryxBindingAuthorizationId, KeryxBindingChallengeId,
    KeryxBindingDecisionId, KeryxBindingId, KeryxBindingState, KeryxPeerId,
    N6AuthenticatedBindRequest, N6BindingChallengeDelivery, N6BindingChallengeRequest,
    N6BindingRevocationIntent, N6BindingRotationIntent, OperationId, OwnerTrustRootToken,
    TrustAuthorityId, n7::N6ActiveBindingProvenance,
};
use rusqlite::{OptionalExtension, Transaction, params};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N6BindingView {
    pub binding_id: KeryxBindingId,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub join_session_id: JoinSessionId,
    pub verified_peer_id: Option<KeryxPeerId>,
    pub generation: Generation,
    pub revision: u64,
    pub state: KeryxBindingState,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub stale_at: Option<DateTime<Utc>>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N6AuthenticatedBindOutcome {
    Confirmed(N6BindingView),
    Replayed(N6BindingView),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N6ChallengeReservation {
    reservation_id: String,
    binding_id: KeryxBindingId,
    generation: Generation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N6ChallengeReservationOutcome {
    Acquired(N6ChallengeReservation),
    Resumable(N6ChallengeReservation),
    AlreadyIssued,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum N6ChallengeCompletion {
    Recorded {
        challenge_id: KeryxBindingChallengeId,
        binding_id: KeryxBindingId,
        generation: Generation,
        expires_at: DateTime<Utc>,
        issued_at: DateTime<Utc>,
    },
    AlreadyIssued,
}

impl StateStore {
    /// Reserves durable state before generating the nonce, then persists only its verifier.
    pub fn issue_n6_binding_challenge(
        &self,
        operation_id: OperationId,
        request: N6BindingChallengeRequest,
        now: DateTime<Utc>,
    ) -> Result<N6BindingChallengeDelivery, StateError> {
        let reservation = match self.reserve_n6_binding_challenge(&operation_id, &request, now)? {
            N6ChallengeReservationOutcome::Acquired(value)
            | N6ChallengeReservationOutcome::Resumable(value) => value,
            N6ChallengeReservationOutcome::AlreadyIssued => {
                return Err(StateError::Conflict(
                    "N6 challenge operation already issued; use a new operation ID".into(),
                ));
            }
            N6ChallengeReservationOutcome::Conflict => {
                return Err(StateError::Conflict(
                    "N6 challenge operation conflicts with durable state".into(),
                ));
            }
        };
        let nonce = BindingNonce::generate();
        let verifier = BindingNonceVerifier::from_nonce(&nonce)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        let completion = self.complete_n6_binding_challenge(&reservation, verifier, now)?;
        let N6ChallengeCompletion::Recorded {
            challenge_id,
            binding_id,
            generation,
            expires_at,
            issued_at,
        } = completion
        else {
            return Err(StateError::Conflict(
                "N6 challenge operation already completed".into(),
            ));
        };
        N6BindingChallengeDelivery::new(
            challenge_id,
            binding_id,
            generation,
            nonce,
            expires_at,
            issued_at,
        )
        .map_err(|error| StateError::Conflict(error.to_string()))
    }

    pub fn confirm_n6_authenticated_binding(
        &self,
        authenticated_peer_id: KeryxPeerId,
        request: N6AuthenticatedBindRequest,
        now: DateTime<Utc>,
    ) -> Result<N6AuthenticatedBindOutcome, StateError> {
        let fingerprint = n6_request_fingerprint(&authenticated_peer_id, &request);
        self.transactional(|tx, store| {
            if let Some((stored_fingerprint, binding_id)) = tx
                .query_row(
                    "SELECT request_fingerprint,binding_id FROM n6_control_operations WHERE authenticated_peer_id=?1 AND operation_id=?2",
                    params![authenticated_peer_id.as_str(), request.operation_id().as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
            {
                if stored_fingerprint != fingerprint {
                    return Ok(N6AuthenticatedBindOutcome::Conflict);
                }
                let binding_id = KeryxBindingId::parse(&binding_id)
                    .map_err(|error| StateError::Conflict(error.to_string()))?;
                return Ok(N6AuthenticatedBindOutcome::Replayed(store.n6_binding_view_tx(tx, binding_id)?));
            }

            let challenge = tx
                .query_row(
                    "SELECT challenge_id,binding_id,challenge_verifier,expires_at_ms,agent_version \
                     FROM n6_binding_challenges WHERE network_id=?1 AND device_id=?2 AND join_session_id=?3 \
                       AND generation=?4 AND expected_authenticated_peer_id=?5 AND challenge_state='pending'",
                    params![request.network_id().to_string(), request.device_id().to_string(), request.join_session_id().to_string(), request.generation().get(), authenticated_peer_id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?)),
                )
                .optional()?
                .ok_or_else(|| StateError::Conflict("no pending N6 challenge for authenticated peer".into()))?;
            if now.timestamp_millis() >= challenge.3 || challenge.4 != request.agent_version().as_str() {
                return Err(StateError::Conflict("N6 challenge is expired or agent-mismatched".into()));
            }
            let verifier = BindingNonceVerifier::parse(challenge.2)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            if !request
                .with_nonce(|nonce| verifier.verify(nonce))
                .map_err(|error| StateError::Conflict(error.to_string()))?
            {
                return Err(StateError::Conflict("N6 nonce verification failed".into()));
            }
            let binding_id = KeryxBindingId::parse(&challenge.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let challenge_id = KeryxBindingChallengeId::parse(&challenge.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let binding = store.n6_binding_view_tx(tx, binding_id)?;
            if binding.network_id != request.network_id()
                || binding.device_id != request.device_id()
                || binding.join_session_id != request.join_session_id()
                || binding.generation != request.generation()
                || binding.state != KeryxBindingState::Pending
            {
                return Err(StateError::Conflict("N6 binding challenge provenance changed".into()));
            }

            let challenge_audit = store.append_n6_audit(
                tx,
                binding.network_id,
                binding.device_id,
                AuditActor::system(),
                "keryx_binding_attempted",
                "success",
                binding.generation,
                now,
            )?;
            let challenge_decision = KeryxBindingDecisionId::new();
            store.insert_n6_decision(
                tx, challenge_decision, challenge_audit, "challenge", "confirm", binding_id,
                Some(challenge_id), None, &binding, "pending", "consumed", 1, 2, now,
                AuditActor::system(), "challenge_confirmed", Some(&authenticated_peer_id),
                Some(request.operation_id()), request.agent_version(),
            )?;
            if tx.execute(
                "UPDATE n6_binding_challenges SET challenge_state='consumed',consumed_at_ms=?1,consumed_operation_id=?2,consumed_authenticated_peer_id=?3,last_decision_id=?4,last_audit_event_id=?5 WHERE challenge_id=?6 AND challenge_state='pending'",
                params![now.timestamp_millis(), request.operation_id().as_str(), authenticated_peer_id.as_str(), challenge_decision.to_string(), challenge_audit.to_string(), challenge_id.to_string()],
            )? != 1 { return Err(StateError::Conflict("N6 challenge consumption lost".into())); }

            let binding_audit = store.append_n6_audit(
                tx, binding.network_id, binding.device_id, AuditActor::system(),
                "keryx_binding_confirmed", "success", binding.generation, now,
            )?;
            let binding_decision = KeryxBindingDecisionId::new();
            store.insert_n6_decision(
                tx, binding_decision, binding_audit, "binding", "confirm", binding_id,
                Some(challenge_id), None, &binding, "pending", "active", binding.revision,
                binding.revision + 1, now, AuditActor::system(), "binding_confirmed",
                Some(&authenticated_peer_id), Some(request.operation_id()), request.agent_version(),
            )?;
            if tx.execute(
                "UPDATE n6_binding_records SET binding_state='active',verified_peer_id=?1,revision=revision+1,confirmed_at_ms=?2,last_verified_at_ms=?2,last_decision_id=?3,last_audit_event_id=?4 WHERE binding_id=?5 AND binding_state='pending' AND revision=?6",
                params![authenticated_peer_id.as_str(), now.timestamp_millis(), binding_decision.to_string(), binding_audit.to_string(), binding_id.to_string(), binding.revision],
            )? != 1 { return Err(StateError::Conflict("N6 binding confirmation lost".into())); }
            tx.execute(
                "INSERT INTO n6_control_operations (authenticated_peer_id,operation_id,request_fingerprint,binding_id,challenge_id,result_kind,completed_at_ms,completion_decision_id,completion_audit_event_id) VALUES (?1,?2,?3,?4,?5,'confirmed',?6,?7,?8)",
                params![authenticated_peer_id.as_str(), request.operation_id().as_str(), fingerprint, binding_id.to_string(), challenge_id.to_string(), now.timestamp_millis(), binding_decision.to_string(), binding_audit.to_string()],
            ).map_err(map_constraint)?;
            Ok(N6AuthenticatedBindOutcome::Confirmed(store.n6_binding_view_tx(tx, binding_id)?))
        })
    }

    pub fn n6_is_peer_active(
        &self,
        network_id: NetworkId,
        authenticated_peer_id: &KeryxPeerId,
    ) -> Result<bool, StateError> {
        Ok(self.connection.borrow().query_row(
            "SELECT EXISTS(SELECT 1 FROM n6_binding_records WHERE network_id=?1 AND verified_peer_id=?2 AND binding_state='active')",
            params![network_id.to_string(), authenticated_peer_id.as_str()], |row| row.get(0),
        )?)
    }

    pub fn n6_binding(&self, binding_id: KeryxBindingId) -> Result<N6BindingView, StateError> {
        self.transactional(|tx, store| store.n6_binding_view_tx(tx, binding_id))
    }

    /// Reads the sole production bridge from N6 durable state into N7 domain
    /// provenance. It succeeds only for this exact active binding tuple; a
    /// pending, stale, rotated, revoked, peerless, or mismatched row is not
    /// evidence and fails closed.
    ///
    /// The result is opaque domain evidence, not a request DTO: callers cannot
    /// deserialize or seed it outside the authenticated N6 lifecycle.
    pub fn n6_active_binding_provenance(
        &self,
        binding_id: KeryxBindingId,
        network_id: NetworkId,
        device_id: DeviceId,
        binding_generation: Generation,
    ) -> Result<N6ActiveBindingProvenance, StateError> {
        self.transactional(|tx, _store| {
            let verified_peer_id = tx
                .query_row(
                    "SELECT verified_peer_id FROM n6_binding_records \
                     WHERE binding_id=?1 AND network_id=?2 AND device_id=?3 \
                       AND generation=?4 AND binding_state='active' \
                       AND verified_peer_id IS NOT NULL",
                    params![
                        binding_id.to_string(),
                        network_id.to_string(),
                        device_id.to_string(),
                        binding_generation.get(),
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound("exact active N6 binding provenance".into()))?;
            let verified_peer_id = KeryxPeerId::parse(verified_peer_id)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            N6ActiveBindingProvenance::from_verified_active_runtime_row(
                network_id,
                device_id,
                binding_id,
                verified_peer_id,
                binding_generation,
            )
            .map_err(|error| StateError::Conflict(error.to_string()))
        })
    }

    pub fn n6_active_binding(
        &self,
        network_id: NetworkId,
        authenticated_peer_id: &KeryxPeerId,
    ) -> Result<N6BindingView, StateError> {
        self.transactional(|tx, store| {
            let binding_id = tx
                .query_row(
                    "SELECT binding_id FROM n6_binding_records WHERE network_id=?1 AND verified_peer_id=?2 AND binding_state='active'",
                    params![network_id.to_string(), authenticated_peer_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound("active N6 peer binding".into()))?;
            store.n6_binding_view_tx(
                tx,
                KeryxBindingId::parse(&binding_id)
                    .map_err(|error| StateError::Conflict(error.to_string()))?,
            )
        })
    }

    pub fn grant_n6_binding_capability(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        capability: KeryxBindingAuthorizationCapability,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        self.transactional(|tx, _store| {
            let (network, generation, principal_source, principal_id) = tx.query_row(
                "SELECT network_id,authority_generation,principal_source,principal_id FROM n5_trust_authorities WHERE authority_id=?1",
                [authority_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
            )?;
            let network_id = NetworkId::parse(&network)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let actor = super::n5::verify_n5_owner_root(tx, root_token, network_id)?;
            if actor.source != principal_source || actor.actor_id.as_deref() != Some(&principal_id) {
                return Err(StateError::MutationAuthorizationDenied(
                    "N6 capability grant principal does not match authority",
                ));
            }
            let audit = AuditEventId::new();
            tx.execute(
                "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES (?1,?2,?3,NULL,?4,?5,'keryx_binding_authority_capability_granted','success',?6,'{}')",
                params![audit.to_string(), now.to_rfc3339(), network_id.to_string(), actor.source, actor.actor_id, generation],
            )?;
            let capability = match capability {
                KeryxBindingAuthorizationCapability::Rotate => "rotate",
                KeryxBindingAuthorizationCapability::Revoke => "revoke",
            };
            tx.execute(
                "INSERT INTO n6_binding_authority_capabilities (grant_id,authority_id,capability,issued_by_source,issued_by_id,issued_at_ms,audit_event_id) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![uuid::Uuid::new_v4().to_string(), authority_id.to_string(), capability, actor.source, actor.actor_id, now.timestamp_millis(), audit.to_string()],
            )?;
            Ok(())
        })
    }

    pub fn issue_n6_binding_authorization(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        binding_id: KeryxBindingId,
        capability: KeryxBindingAuthorizationCapability,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<KeryxBindingAuthorization, StateError> {
        self.transactional(|tx, store| {
            let binding = store.n6_binding_view_tx(tx, binding_id)?;
            let actor = super::n5::verify_n5_owner_root(tx, root_token, binding.network_id)?;
            let authorization = KeryxBindingAuthorization::new(
                KeryxBindingAuthorizationId::new(),
                authority_id,
                actor.clone(),
                capability,
                binding_id,
                binding.generation,
                binding.revision,
                expires_at,
                now,
            )
            .map_err(|error| StateError::Conflict(error.to_string()))?;
            let audit = store.append_n6_audit(tx, binding.network_id, binding.device_id, actor.clone(), "keryx_binding_authorization_issued", "success", binding.generation, now)?;
            let decision = KeryxBindingDecisionId::new();
            let agent_version = AgentVersion::parse(tx.query_row(
                "SELECT agent_version FROM n6_binding_records WHERE binding_id=?1",
                [binding_id.to_string()],
                |row| row.get::<_, String>(0),
            )?).map_err(|error| StateError::Conflict(error.to_string()))?;
            store.insert_n6_decision(tx, decision, audit, "authorization", "issue", binding_id, None, Some(authorization.authorization_id()), &binding, "", "pending", 0, 1, now, actor.clone(), "authorization_issued", None, None, &agent_version)?;
            let action = match capability {
                KeryxBindingAuthorizationCapability::Rotate => "rotate",
                KeryxBindingAuthorizationCapability::Revoke => "revoke",
            };
            tx.execute(
                "INSERT INTO n6_binding_authorizations (authorization_id,authority_id,binding_id,network_id,device_id,join_session_id,generation,expected_revision,action_kind,actor_source,actor_id,issued_at_ms,expires_at_ms,issued_decision_id,issued_audit_event_id,authorization_state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'pending')",
                params![authorization.authorization_id().to_string(), authority_id.to_string(), binding_id.to_string(), binding.network_id.to_string(), binding.device_id.to_string(), binding.join_session_id.to_string(), binding.generation.get(), binding.revision, action, actor.source, actor.actor_id, now.timestamp_millis(), expires_at.timestamp_millis(), decision.to_string(), audit.to_string()],
            )?;
            Ok(authorization)
        })
    }

    pub fn rotate_n6_binding(
        &self,
        intent: &N6BindingRotationIntent,
        now: DateTime<Utc>,
    ) -> Result<N6BindingView, StateError> {
        intent
            .validate_at(now)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        self.transactional(|tx, store| {
            let predecessor = store.n6_binding_view_tx(tx, intent.predecessor_binding_id())?;
            if predecessor.generation != intent.predecessor_generation()
                || predecessor.revision != intent.predecessor_revision()
                || !matches!(predecessor.state, KeryxBindingState::Active | KeryxBindingState::Stale)
            {
                return Err(StateError::StaleGeneration {
                    expected: intent.predecessor_revision(),
                    actual: predecessor.revision,
                });
            }
            let agent_version = AgentVersion::parse(tx.query_row(
                "SELECT agent_version FROM n6_binding_records WHERE binding_id=?1",
                [predecessor.binding_id.to_string()],
                |row| row.get::<_, String>(0),
            )?).map_err(|error| StateError::Conflict(error.to_string()))?;

            let successor_id = KeryxBindingId::new();
            let successor_audit = store.append_n6_audit(tx, predecessor.network_id, predecessor.device_id, intent.authorization().actor().clone(), "keryx_binding_pending", "success", intent.expected_next_generation(), now)?;
            let successor_decision = KeryxBindingDecisionId::new();
            let successor = N6BindingView {
                binding_id: successor_id,
                network_id: predecessor.network_id,
                device_id: predecessor.device_id,
                join_session_id: predecessor.join_session_id,
                verified_peer_id: None,
                generation: intent.expected_next_generation(),
                revision: 1,
                state: KeryxBindingState::Pending,
                created_at: now,
                confirmed_at: None,
                stale_at: None,
                rotated_at: None,
                revoked_at: None,
            };
            store.insert_n6_decision(tx, successor_decision, successor_audit, "binding", "issue", successor_id, None, None, &successor, "", "pending", 0, 1, now, intent.authorization().actor().clone(), "binding_issued", None, None, &agent_version)?;
            tx.execute(
                "INSERT INTO n6_binding_records (binding_id,network_id,device_id,join_session_id,verified_peer_id,generation,revision,binding_state,created_at_ms,rotated_from_binding_id,rotation_authorization_id,agent_version,last_decision_id,last_audit_event_id) VALUES (?1,?2,?3,?4,NULL,?5,1,'pending',?6,?7,?8,?9,?10,?11)",
                params![successor_id.to_string(), predecessor.network_id.to_string(), predecessor.device_id.to_string(), predecessor.join_session_id.to_string(), successor.generation.get(), now.timestamp_millis(), predecessor.binding_id.to_string(), intent.authorization().authorization_id().to_string(), agent_version.as_str(), successor_decision.to_string(), successor_audit.to_string()],
            )?;

            let rotation_audit = store.append_n6_audit(tx, predecessor.network_id, predecessor.device_id, intent.authorization().actor().clone(), "keryx_binding_rotated", "success", predecessor.generation, now)?;
            store.insert_n6_decision(tx, intent.decision_id(), rotation_audit, "binding", "rotate", predecessor.binding_id, None, Some(intent.authorization().authorization_id()), &predecessor, predecessor.state.as_str(), "rotated", predecessor.revision, predecessor.revision + 1, now, intent.authorization().actor().clone(), intent.reason_code().as_str(), None, None, &agent_version)?;
            tx.execute(
                "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=?1,consumed_decision_id=?2,consumed_audit_event_id=?3 WHERE authorization_id=?4 AND authorization_state='pending'",
                params![now.timestamp_millis(), intent.decision_id().to_string(), rotation_audit.to_string(), intent.authorization().authorization_id().to_string()],
            )?;
            let changed = tx.execute(
                "UPDATE n6_binding_records SET binding_state='rotated',revision=revision+1,rotated_at_ms=?1,last_decision_id=?2,last_audit_event_id=?3 WHERE binding_id=?4 AND revision=?5 AND binding_state IN ('active','stale')",
                params![now.timestamp_millis(), intent.decision_id().to_string(), rotation_audit.to_string(), predecessor.binding_id.to_string(), predecessor.revision],
            )?;
            if changed != 1 {
                return Err(StateError::StaleGeneration { expected: predecessor.revision, actual: predecessor.revision + 1 });
            }
            store.n6_binding_view_tx(tx, successor_id)
        })
    }

    pub fn revoke_n6_binding(
        &self,
        intent: &N6BindingRevocationIntent,
        now: DateTime<Utc>,
    ) -> Result<N6BindingView, StateError> {
        intent
            .validate_at(now)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        self.transactional(|tx, store| {
            let binding = store.n6_binding_view_tx(tx, intent.binding_id())?;
            if binding.generation != intent.generation()
                || binding.revision != intent.revision()
                || !matches!(binding.state, KeryxBindingState::Pending | KeryxBindingState::Active | KeryxBindingState::Stale)
            {
                return Err(StateError::StaleGeneration {
                    expected: intent.revision(),
                    actual: binding.revision,
                });
            }
            let agent_version = AgentVersion::parse(tx.query_row(
                "SELECT agent_version FROM n6_binding_records WHERE binding_id=?1",
                [binding.binding_id.to_string()],
                |row| row.get::<_, String>(0),
            )?).map_err(|error| StateError::Conflict(error.to_string()))?;
            store.invalidate_n6_pending_challenge(tx, binding.binding_id, now)?;
            let audit = store.append_n6_audit(tx, binding.network_id, binding.device_id, intent.authorization().actor().clone(), "keryx_binding_revoked", "success", binding.generation, now)?;
            store.insert_n6_decision(tx, intent.decision_id(), audit, "binding", "revoke", binding.binding_id, None, Some(intent.authorization().authorization_id()), &binding, binding.state.as_str(), "revoked", binding.revision, binding.revision + 1, now, intent.authorization().actor().clone(), intent.reason_code().as_str(), None, None, &agent_version)?;
            tx.execute(
                "UPDATE n6_binding_authorizations SET authorization_state='consumed',consumed_at_ms=?1,consumed_decision_id=?2,consumed_audit_event_id=?3 WHERE authorization_id=?4 AND authorization_state='pending'",
                params![now.timestamp_millis(), intent.decision_id().to_string(), audit.to_string(), intent.authorization().authorization_id().to_string()],
            )?;
            let changed = tx.execute(
                "UPDATE n6_binding_records SET binding_state='revoked',revision=revision+1,revoked_at_ms=?1,last_decision_id=?2,last_audit_event_id=?3 WHERE binding_id=?4 AND revision=?5 AND binding_state IN ('pending','active','stale')",
                params![now.timestamp_millis(), intent.decision_id().to_string(), audit.to_string(), binding.binding_id.to_string(), binding.revision],
            )?;
            if changed != 1 {
                return Err(StateError::StaleGeneration { expected: binding.revision, actual: binding.revision + 1 });
            }
            store.n6_binding_view_tx(tx, binding.binding_id)
        })
    }

    pub fn n6_challenge_generation(
        &self,
        network_id: NetworkId,
        device_id: DeviceId,
    ) -> Result<Generation, StateError> {
        let connection = self.connection.borrow();
        let pending = connection
            .query_row(
                "SELECT generation FROM n6_binding_records WHERE network_id=?1 AND device_id=?2 AND binding_state='pending' ORDER BY generation DESC LIMIT 1",
                params![network_id.to_string(), device_id.to_string()],
                |row| row.get::<_, u64>(0),
            )
            .optional()?;
        if let Some(generation) = pending {
            return Generation::new(generation)
                .map_err(|error| StateError::Conflict(error.to_string()));
        }
        let existing: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM n6_binding_records WHERE network_id=?1 AND device_id=?2)",
            params![network_id.to_string(), device_id.to_string()],
            |row| row.get(0),
        )?;
        if existing {
            return Err(StateError::Conflict(
                "N6 binding has no pending generation; rotation authorization is required".into(),
            ));
        }
        Ok(Generation::initial())
    }

    pub fn reserve_n6_binding_challenge(
        &self,
        operation_id: &OperationId,
        request: &N6BindingChallengeRequest,
        now: DateTime<Utc>,
    ) -> Result<N6ChallengeReservationOutcome, StateError> {
        request
            .validate_at(now)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        let fingerprint = n6_challenge_fingerprint(request);
        self.transactional(|tx, store| {
            if let Some((stored_fingerprint, state, reservation_id, binding_id, generation)) = tx
                .query_row(
                    "SELECT request_fingerprint,reservation_state,reservation_id,binding_id,generation FROM n6_challenge_reservations WHERE expected_authenticated_peer_id=?1 AND operation_id=?2",
                    params![request.expected_authenticated_peer_id().as_str(), operation_id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, u64>(4)?)),
                )
                .optional()?
            {
                if stored_fingerprint != fingerprint || state == "abandoned" {
                    return Ok(N6ChallengeReservationOutcome::Conflict);
                }
                if state == "issued" {
                    return Ok(N6ChallengeReservationOutcome::AlreadyIssued);
                }
                return Ok(N6ChallengeReservationOutcome::Resumable(N6ChallengeReservation {
                    reservation_id,
                    binding_id: KeryxBindingId::parse(&binding_id)
                        .map_err(|error| StateError::Conflict(error.to_string()))?,
                    generation: Generation::new(generation)
                        .map_err(|error| StateError::Conflict(error.to_string()))?,
                }));
            }
            let exact_n5: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM n5_device_identities WHERE device_id=?1 AND network_id=?2 AND origin_join_session_id=?3)",
                params![request.device_id().to_string(), request.network_id().to_string(), request.join_session_id().to_string()], |row| row.get(0),
            )?;
            if !exact_n5 { return Err(StateError::Conflict("N6 challenge requires exact confirmed N5 join provenance".into())); }
            let existing = tx.query_row(
                "SELECT binding_id,binding_state FROM n6_binding_records WHERE network_id=?1 AND device_id=?2 AND generation=?3",
                params![request.network_id().to_string(), request.device_id().to_string(), request.generation().get()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).optional()?;
            let binding_id = match existing {
                Some((id, state)) if state == "pending" => KeryxBindingId::parse(&id).map_err(|e| StateError::Conflict(e.to_string()))?,
                Some(_) => return Err(StateError::Conflict("N6 binding generation is no longer challengeable".into())),
                None => {
                    let binding_id = KeryxBindingId::new();
                    let audit = store.append_n6_audit(tx, request.network_id(), request.device_id(), AuditActor::system(), "keryx_binding_pending", "success", request.generation(), now)?;
                    let decision = KeryxBindingDecisionId::new();
                    let pending = N6BindingView { binding_id, network_id: request.network_id(), device_id: request.device_id(), join_session_id: request.join_session_id(), verified_peer_id: None, generation: request.generation(), revision: 1, state: KeryxBindingState::Pending, created_at: now, confirmed_at: None, stale_at: None, rotated_at: None, revoked_at: None };
                    store.insert_n6_decision(tx, decision, audit, "binding", "issue", binding_id, None, None, &pending, "", "pending", 0, 1, now, AuditActor::system(), "binding_issued", Some(request.expected_authenticated_peer_id()), None, request.agent_version())?;
                    tx.execute("INSERT INTO n6_binding_records (binding_id,network_id,device_id,join_session_id,verified_peer_id,generation,revision,binding_state,created_at_ms,agent_version,last_decision_id,last_audit_event_id) VALUES (?1,?2,?3,?4,NULL,?5,1,'pending',?6,?7,?8,?9)", params![binding_id.to_string(), request.network_id().to_string(), request.device_id().to_string(), request.join_session_id().to_string(), request.generation().get(), now.timestamp_millis(), request.agent_version().as_str(), decision.to_string(), audit.to_string()])?;
                    binding_id
                }
            };
            store.invalidate_n6_pending_challenge(tx, binding_id, now)?;
            tx.execute("UPDATE n6_challenge_reservations SET reservation_state='abandoned',abandoned_at_ms=?2 WHERE binding_id=?1 AND reservation_state='reserved'", params![binding_id.to_string(), now.timestamp_millis()])?;
            let reservation_id = uuid::Uuid::new_v4().to_string();
            tx.execute("INSERT INTO n6_challenge_reservations (reservation_id,binding_id,network_id,device_id,join_session_id,expected_authenticated_peer_id,operation_id,request_fingerprint,generation,expires_at_ms,agent_version,reservation_state,reserved_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'reserved',?12)", params![reservation_id, binding_id.to_string(), request.network_id().to_string(), request.device_id().to_string(), request.join_session_id().to_string(), request.expected_authenticated_peer_id().as_str(), operation_id.as_str(), fingerprint, request.generation().get(), request.expires_at().timestamp_millis(), request.agent_version().as_str(), now.timestamp_millis()])?;
            Ok(N6ChallengeReservationOutcome::Acquired(N6ChallengeReservation {
                reservation_id,
                binding_id,
                generation: request.generation(),
            }))
        })
    }

    pub fn complete_n6_binding_challenge(
        &self,
        reservation: &N6ChallengeReservation,
        verifier: BindingNonceVerifier,
        now: DateTime<Utc>,
    ) -> Result<N6ChallengeCompletion, StateError> {
        self.transactional(|tx, store| {
            let row = tx.query_row(
                "SELECT reservation_state,expected_authenticated_peer_id,operation_id,agent_version,expires_at_ms FROM n6_challenge_reservations WHERE reservation_id=?1 AND binding_id=?2 AND generation=?3",
                params![reservation.reservation_id, reservation.binding_id.to_string(), reservation.generation.get()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?)),
            ).optional()?.ok_or_else(|| StateError::Conflict("N6 challenge reservation is absent".into()))?;
            if row.0 == "issued" {
                return Ok(N6ChallengeCompletion::AlreadyIssued);
            }
            if row.0 != "reserved" {
                return Err(StateError::Conflict("N6 challenge reservation is no longer live".into()));
            }
            let binding = store.n6_binding_view_tx(tx, reservation.binding_id)?;
            let challenge_id = KeryxBindingChallengeId::new();
            let peer = KeryxPeerId::parse(&row.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let operation_id = OperationId::parse(&row.2)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let agent_version = AgentVersion::parse(row.3)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let expires_at = DateTime::from_timestamp_millis(row.4)
                .ok_or_else(|| StateError::Conflict("invalid N6 reservation expiry".into()))?;
            let audit = store.append_n6_audit(tx, binding.network_id, binding.device_id, AuditActor::system(), "keryx_binding_nonce_issued", "success", binding.generation, now)?;
            let decision = KeryxBindingDecisionId::new();
            store.insert_n6_decision(tx, decision, audit, "challenge", "issue", reservation.binding_id, Some(challenge_id), None, &binding, "", "pending", 0, 1, now, AuditActor::system(), "challenge_issued", Some(&peer), Some(&operation_id), &agent_version)?;
            tx.execute("INSERT INTO n6_binding_challenges (challenge_id,binding_id,network_id,device_id,join_session_id,expected_authenticated_peer_id,generation,challenge_verifier,challenge_state,issued_at_ms,expires_at_ms,agent_version,last_decision_id,last_audit_event_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9,?10,?11,?12,?13)", params![challenge_id.to_string(), reservation.binding_id.to_string(), binding.network_id.to_string(), binding.device_id.to_string(), binding.join_session_id.to_string(), peer.as_str(), binding.generation.get(), verifier.as_str(), now.timestamp_millis(), expires_at.timestamp_millis(), agent_version.as_str(), decision.to_string(), audit.to_string()])?;
            if tx.execute("UPDATE n6_challenge_reservations SET reservation_state='issued',issued_at_ms=?1,challenge_id=?2 WHERE reservation_id=?3 AND reservation_state='reserved'", params![now.timestamp_millis(), challenge_id.to_string(), reservation.reservation_id])? != 1 {
                return Err(StateError::Conflict("N6 challenge reservation completion lost".into()));
            }
            Ok(N6ChallengeCompletion::Recorded {
                challenge_id,
                binding_id: reservation.binding_id,
                generation: reservation.generation,
                expires_at,
                issued_at: now,
            })
        })
    }

    fn invalidate_n6_pending_challenge(
        &self,
        tx: &Transaction<'_>,
        binding_id: KeryxBindingId,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        let Some((challenge, network, device, session, generation, agent)) = tx.query_row("SELECT challenge_id,network_id,device_id,join_session_id,generation,agent_version FROM n6_binding_challenges WHERE binding_id=?1 AND challenge_state='pending'", [binding_id.to_string()], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?,r.get::<_, String>(2)?,r.get::<_, String>(3)?,r.get::<_, u64>(4)?,r.get::<_, String>(5)?))).optional()? else { return Ok(()); };
        let view = self.n6_binding_view_tx(tx, binding_id)?;
        let audit = self.append_n6_audit(
            tx,
            NetworkId::parse(&network).map_err(|e| StateError::Conflict(e.to_string()))?,
            DeviceId::parse(&device).map_err(|e| StateError::Conflict(e.to_string()))?,
            AuditActor::system(),
            "keryx_binding_nonce_invalidated",
            "success",
            Generation::new(generation).map_err(|e| StateError::Conflict(e.to_string()))?,
            now,
        )?;
        let decision = KeryxBindingDecisionId::new();
        let agent_version =
            AgentVersion::parse(agent).map_err(|error| StateError::Conflict(error.to_string()))?;
        self.insert_n6_decision(
            tx,
            decision,
            audit,
            "challenge",
            "invalidate",
            binding_id,
            Some(
                KeryxBindingChallengeId::parse(&challenge)
                    .map_err(|e| StateError::Conflict(e.to_string()))?,
            ),
            None,
            &view,
            "pending",
            "invalidated",
            1,
            2,
            now,
            AuditActor::system(),
            "challenge_replaced",
            None,
            None,
            &agent_version,
        )?;
        let _ = session;
        tx.execute("UPDATE n6_binding_challenges SET challenge_state='invalidated',invalidated_at_ms=?1,last_decision_id=?2,last_audit_event_id=?3 WHERE challenge_id=?4 AND challenge_state='pending'", params![now.timestamp_millis(), decision.to_string(), audit.to_string(), challenge])?;
        Ok(())
    }

    fn n6_binding_view_tx(
        &self,
        tx: &Transaction<'_>,
        binding_id: KeryxBindingId,
    ) -> Result<N6BindingView, StateError> {
        let row = tx.query_row(
            "SELECT network_id,device_id,join_session_id,verified_peer_id,generation,revision,binding_state,created_at_ms,confirmed_at_ms,stale_at_ms,rotated_at_ms,revoked_at_ms FROM n6_binding_records WHERE binding_id=?1",
            [binding_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, u64>(4)?, row.get::<_, u64>(5)?, row.get::<_, String>(6)?, row.get::<_, i64>(7)?, row.get::<_, Option<i64>>(8)?, row.get::<_, Option<i64>>(9)?, row.get::<_, Option<i64>>(10)?, row.get::<_, Option<i64>>(11)?)),
        ).optional()?.ok_or_else(|| StateError::NotFound(binding_id.to_string()))?;
        let time = |value: i64| {
            DateTime::from_timestamp_millis(value)
                .ok_or_else(|| StateError::Conflict("invalid N6 timestamp".into()))
        };
        let optional_time = |value: Option<i64>| value.map(time).transpose();
        let state = match row.6.as_str() {
            "pending" => KeryxBindingState::Pending,
            "active" => KeryxBindingState::Active,
            "stale" => KeryxBindingState::Stale,
            "rotated" => KeryxBindingState::Rotated,
            "revoked" => KeryxBindingState::Revoked,
            _ => return Err(StateError::Conflict("invalid N6 binding state".into())),
        };
        Ok(N6BindingView {
            binding_id,
            network_id: NetworkId::parse(&row.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            device_id: DeviceId::parse(&row.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            join_session_id: JoinSessionId::parse(&row.2)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            verified_peer_id: row
                .3
                .map(KeryxPeerId::parse)
                .transpose()
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            generation: Generation::new(row.4)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            revision: row.5,
            state,
            created_at: time(row.7)?,
            confirmed_at: optional_time(row.8)?,
            stale_at: optional_time(row.9)?,
            rotated_at: optional_time(row.10)?,
            revoked_at: optional_time(row.11)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn append_n6_audit(
        &self,
        tx: &Transaction<'_>,
        network_id: NetworkId,
        device_id: DeviceId,
        actor: AuditActor,
        kind: &str,
        outcome: &str,
        generation: Generation,
        now: DateTime<Utc>,
    ) -> Result<AuditEventId, StateError> {
        let event_id = AuditEventId::new();
        tx.execute(
            "INSERT INTO audit_events (event_id,timestamp,network_id,device_id,actor_source,actor_id,event_kind,outcome,generation,metadata_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'{}')",
            params![event_id.to_string(), now.to_rfc3339(), network_id.to_string(), device_id.to_string(), actor.source, actor.actor_id, kind, outcome, generation.get()],
        )?;
        Ok(event_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_n6_decision(
        &self,
        tx: &Transaction<'_>,
        decision_id: KeryxBindingDecisionId,
        audit_id: AuditEventId,
        subject: &str,
        kind: &str,
        binding_id: KeryxBindingId,
        challenge_id: Option<KeryxBindingChallengeId>,
        authorization_id: Option<nodescale_domain::KeryxBindingAuthorizationId>,
        binding: &N6BindingView,
        prior_state: &str,
        new_state: &str,
        prior_revision: u64,
        new_revision: u64,
        now: DateTime<Utc>,
        actor: AuditActor,
        reason: &str,
        peer: Option<&KeryxPeerId>,
        operation_id: Option<&OperationId>,
        agent_version: &AgentVersion,
    ) -> Result<(), StateError> {
        let issue = kind == "issue";
        tx.execute(
            "INSERT INTO n6_binding_decisions (decision_id,audit_event_id,subject_kind,decision_kind,binding_id,challenge_id,authorization_id,network_id,device_id,join_session_id,generation,prior_state,new_state,prior_revision,new_revision,decided_at_ms,actor_source,actor_id,reason_code,authenticated_peer_id,operation_id,agent_version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![decision_id.to_string(), audit_id.to_string(), subject, kind, binding_id.to_string(), challenge_id.map(|id| id.to_string()), authorization_id.map(|id| id.to_string()), binding.network_id.to_string(), binding.device_id.to_string(), binding.join_session_id.to_string(), binding.generation.get(), if issue { None } else { Some(prior_state) }, new_state, if issue { None } else { Some(prior_revision) }, new_revision, now.timestamp_millis(), actor.source, actor.actor_id, reason, peer.map(KeryxPeerId::as_str), operation_id.map(OperationId::as_str), agent_version.as_str()],
        ).map_err(map_constraint)?;
        Ok(())
    }
}

fn n6_challenge_fingerprint(request: &N6BindingChallengeRequest) -> String {
    let mut hasher = Sha256::new();
    for value in [
        request.expected_authenticated_peer_id().as_str(),
        &request.network_id().to_string(),
        &request.device_id().to_string(),
        &request.join_session_id().to_string(),
        &request.generation().get().to_string(),
        &request.expires_at().timestamp_millis().to_string(),
        request.agent_version().as_str(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn n6_request_fingerprint(peer: &KeryxPeerId, request: &N6AuthenticatedBindRequest) -> String {
    let mut hasher = Sha256::new();
    for value in [
        peer.as_str(),
        request.operation_id().as_str(),
        &request.network_id().to_string(),
        &request.device_id().to_string(),
        &request.join_session_id().to_string(),
        &request.generation().get().to_string(),
        request.agent_version().as_str(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    request.with_nonce(|nonce| nonce.with_encoded(|encoded| hasher.update(encoded.as_bytes())));
    format!("{:x}", hasher.finalize())
}
