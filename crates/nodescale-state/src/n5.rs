use super::*;
use chrono::Duration;
use nodescale_domain::{
    DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, DeviceTrustState, OwnerTrustRootToken,
    ProviderApiKey, ProviderBindingId, ProviderBindingState, SecretVerifier, TrustActionId,
    TrustAuthorityId, TrustDecisionId, TrustDecisionKind, TrustRootId,
};
use nodescale_provider_headscale::{
    HeadscaleClientOptions, HeadscaleCustomRootCa, HeadscaleProvider,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
struct N5IdentityEvidence {
    join_session_id: JoinSessionId,
    provider_reference: ProviderCredentialReference,
    provider_identity: nodescale_domain::ProviderIdentity,
    observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N5JoinCorrelationContext {
    pub join_session_id: JoinSessionId,
    pub network_id: NetworkId,
    pub provider_instance_id: ProviderInstanceId,
    pub provider_reference: ProviderCredentialReference,
    pub confirmed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Opaque authorizing provider created from the current state-owned import.
/// Raw caller-constructed adapters cannot be converted into this type.
pub struct N5ConfiguredHeadscaleProvider {
    network_id: NetworkId,
    import_config: HeadscaleImportConfig,
    provider: HeadscaleProvider,
}

impl N5ConfiguredHeadscaleProvider {
    #[must_use]
    pub fn instance_id(&self) -> ProviderInstanceId {
        self.import_config.provider_instance_id
    }

    fn provider(&self) -> &HeadscaleProvider {
        &self.provider
    }

    fn validate_current(&self, store: &StateStore) -> Result<(), StateError> {
        let (_, current) = store.import_config(self.network_id)?;
        if current != self.import_config {
            return Err(StateError::Conflict(
                "configured provider identity changed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N5DeviceIdentity {
    pub device_id: DeviceId,
    pub network_id: NetworkId,
    pub origin_join_session_id: JoinSessionId,
    pub binding_id: ProviderBindingId,
    pub provider_reference: ProviderCredentialReference,
    pub provider_identity: nodescale_domain::ProviderIdentity,
    pub binding_state: ProviderBindingState,
    pub binding_revision: Generation,
    pub confirmed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum N5IdentityConfirmationOutcome {
    Confirmed,
    AlreadyConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N5IdentityConfirmation {
    pub outcome: N5IdentityConfirmationOutcome,
    pub identity: N5DeviceIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N5TrustAuthorityConfiguration {
    pub authority_id: TrustAuthorityId,
    pub network_id: NetworkId,
    pub principal_source: String,
    pub principal_id: String,
    pub generation: Generation,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub capabilities: BTreeSet<DeviceTrustCapability>,
    pub created_at: DateTime<Utc>,
}
impl N5TrustAuthorityConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: TrustAuthorityId,
        network_id: NetworkId,
        principal_source: impl Into<String>,
        principal_id: impl Into<String>,
        generation: Generation,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        capabilities: impl IntoIterator<Item = DeviceTrustCapability>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, StateError> {
        let principal_source = principal_source.into();
        let principal_id = principal_id.into();
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if !safe_identifier(&principal_source)
            || principal_source.len() > 64
            || !safe_identifier(&principal_id)
            || expires_at <= not_before
            || created_at > expires_at
            || capabilities.is_empty()
        {
            return Err(StateError::Conflict(
                "invalid N5 trust authority configuration".into(),
            ));
        }
        Ok(Self {
            authority_id,
            network_id,
            principal_source,
            principal_id,
            generation,
            not_before,
            expires_at,
            capabilities,
            created_at,
        })
    }
}

pub struct DeviceTrustAuthorization {
    action_id: TrustActionId,
    authority_id: TrustAuthorityId,
    authority_generation: Generation,
    device_id: DeviceId,
    network_id: NetworkId,
    expected_state: DeviceTrustState,
    expected_revision: Generation,
    capability: DeviceTrustCapability,
    principal_source: String,
    principal_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
impl std::fmt::Debug for DeviceTrustAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceTrustAuthorization")
            .field("action_id", &self.action_id)
            .field("device_id", &self.device_id)
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum N5TrustReason {
    OwnerApproved,
    OwnerRevoked,
    SecurityResponse,
    ProviderBindingStale,
}
impl N5TrustReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerApproved => "owner_approved",
            Self::OwnerRevoked => "owner_revoked",
            Self::SecurityResponse => "security_response",
            Self::ProviderBindingStale => "provider_binding_stale",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceTrustView {
    pub device_id: DeviceId,
    pub network_id: NetworkId,
    pub trust_state: DeviceTrustState,
    pub trust_revision: Generation,
    /// The durable provider binding in its current lifecycle state.
    ///
    /// `None` means no N5 provider binding exists. Stale, cleanup-pending, and
    /// removed bindings remain visible so callers can use the returned revision
    /// for the next fenced transition.
    pub provider_binding: Option<N5DeviceIdentity>,
    /// Whether a provider-fresh reconciliation confirmed effective trust for
    /// this returned view. Durable state and mutation results always set this
    /// false; only the exact provider reconciliation path may set it true.
    pub currently_trusted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum N5TrustDecisionOutcome {
    Applied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct N5TrustDecisionResult {
    pub outcome: N5TrustDecisionOutcome,
    pub view: DeviceTrustView,
}

impl StateStore {
    pub fn configured_n5_headscale_provider(
        &self,
        network_id: NetworkId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
    ) -> Result<N5ConfiguredHeadscaleProvider, StateError> {
        self.build_configured_n5_headscale_provider(network_id, api_key, options, None)
    }

    pub fn configured_n5_headscale_provider_with_custom_root_ca(
        &self,
        network_id: NetworkId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        custom_root_ca: HeadscaleCustomRootCa,
    ) -> Result<N5ConfiguredHeadscaleProvider, StateError> {
        self.build_configured_n5_headscale_provider(
            network_id,
            api_key,
            options,
            Some(custom_root_ca),
        )
    }

    fn build_configured_n5_headscale_provider(
        &self,
        network_id: NetworkId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        custom_root_ca: Option<HeadscaleCustomRootCa>,
    ) -> Result<N5ConfiguredHeadscaleProvider, StateError> {
        let (_, import_config) = self.import_config(network_id)?;
        let custom_root_ca = match custom_root_ca {
            Some(root) => {
                let (bytes, fingerprint) = root.into_pem_bytes_and_sha256().map_err(|_| {
                    StateError::Conflict("configured provider construction failed".into())
                })?;
                if import_config.custom_root_ca_sha256.as_deref() != Some(&fingerprint) {
                    return Err(StateError::Conflict(
                        "custom root CA does not match persisted provider configuration".into(),
                    ));
                }
                Some(HeadscaleCustomRootCa::PemBytes(bytes))
            }
            None if import_config.custom_root_ca_sha256.is_some() => {
                return Err(StateError::Conflict(
                    "persisted provider configuration requires its custom root CA".into(),
                ));
            }
            None => None,
        };
        let provider = match custom_root_ca {
            Some(root) => HeadscaleProvider::new_with_custom_root_ca(
                &import_config.server_url,
                import_config.provider_instance_id,
                api_key,
                options,
                root,
            ),
            None => HeadscaleProvider::new(
                &import_config.server_url,
                import_config.provider_instance_id,
                api_key,
                options,
            ),
        }
        .map_err(|_| StateError::Conflict("configured provider construction failed".into()))?;
        Ok(N5ConfiguredHeadscaleProvider {
            network_id,
            import_config,
            provider,
        })
    }

    pub fn n5_join_correlation_context(
        &self,
        join_session_id: JoinSessionId,
    ) -> Result<N5JoinCorrelationContext, StateError> {
        let row = self
            .connection
            .borrow()
            .query_row(
                "SELECT m.network_id,m.provider_instance_id,r.provider_reference,m.confirmed_at_ms,m.expires_at_ms \
                 FROM n4_provider_credential_metadata m \
                 JOIN n4_join_session_dispatches d ON d.join_session_id=m.join_session_id AND d.credential_id=m.credential_id \
                 JOIN confirmed_provider_credential_references r ON r.credential_id=m.credential_id \
                 WHERE m.join_session_id=?1 AND d.dispatch_state='confirmed' AND m.invalidation_state='active' AND m.single_use=1 AND m.reusable=0",
                [join_session_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                StateError::Conflict(
                    "N5 correlation requires one active confirmed single-use N4 credential".into(),
                )
            })?;
        Ok(N5JoinCorrelationContext {
            join_session_id,
            network_id: NetworkId::parse(&row.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            provider_instance_id: ProviderInstanceId::parse(&row.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            provider_reference: ProviderCredentialReference::new(row.2)
                .map_err(|error| StateError::Conflict(error.to_string()))?,
            confirmed_at: DateTime::from_timestamp_millis(row.3)
                .ok_or_else(|| StateError::Conflict("invalid N4 confirmation time".into()))?,
            expires_at: DateTime::from_timestamp_millis(row.4)
                .ok_or_else(|| StateError::Conflict("invalid N4 expiry time".into()))?,
        })
    }

    pub async fn confirm_n5_device_identity(
        &self,
        provider: &N5ConfiguredHeadscaleProvider,
        join_session_id: JoinSessionId,
        confirmed_at: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N5IdentityConfirmation, StateError> {
        provider.validate_current(self)?;
        let context = self.n5_join_correlation_context(join_session_id)?;
        if context.network_id != provider.network_id {
            return Err(StateError::Conflict(
                "configured provider network does not match join session".into(),
            ));
        }
        self.confirm_n5_device_identity_from_provider(
            provider.provider(),
            join_session_id,
            confirmed_at,
            actor,
        )
        .await
    }

    pub(crate) async fn confirm_n5_device_identity_from_provider<P: ReadOnlyProvider>(
        &self,
        provider: &P,
        join_session_id: JoinSessionId,
        confirmed_at: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N5IdentityConfirmation, StateError> {
        let context = self.n5_join_correlation_context(join_session_id)?;
        if provider.instance_id() != context.provider_instance_id {
            return Err(StateError::Conflict(
                "configured provider does not match N5 join provenance".into(),
            ));
        }
        if confirmed_at >= context.expires_at {
            return Err(StateError::Conflict(
                "N5 join correlation credential has expired".into(),
            ));
        }
        let nodes = provider.list_nodes().await.map_err(|error| {
            StateError::Conflict(format!("provider observation failed: {error}"))
        })?;
        let selected = select_n5_provider_registration(&context, &nodes, confirmed_at)?;
        let reread = provider
            .get_node(&selected.identity)
            .await
            .map_err(|error| StateError::Conflict(format!("provider re-read failed: {error}")))?
            .ok_or_else(|| {
                StateError::Conflict("provider registration disappeared before confirmation".into())
            })?;
        validate_n5_provider_registration(&context, &reread, confirmed_at)?;
        if reread.identity != selected.identity {
            return Err(StateError::Conflict(
                "provider registration changed before confirmation".into(),
            ));
        }
        self.persist_verified_n5_device_identity(
            N5IdentityEvidence {
                join_session_id,
                provider_reference: context.provider_reference,
                provider_identity: reread.identity,
                observed_at: reread.observed_at,
            },
            confirmed_at,
            actor,
        )
    }

    fn persist_verified_n5_device_identity(
        &self,
        evidence: N5IdentityEvidence,
        confirmed_at: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N5IdentityConfirmation, StateError> {
        validate_n5_audit_actor(&actor)?;
        if !valid_sha256_fingerprint(&evidence.provider_identity.stable_key_fingerprint) {
            return Err(StateError::Conflict("invalid N5 identity evidence".into()));
        }
        self.transactional(|tx, store| {
            if let Some(existing) = load_n5_identity_by_session(tx, evidence.join_session_id)? {
                if existing.provider_reference != evidence.provider_reference
                    || existing.provider_identity != evidence.provider_identity
                {
                    return Err(StateError::Conflict(
                        "join session is already bound to different device evidence".into(),
                    ));
                }
                return Ok(N5IdentityConfirmation {
                    outcome: N5IdentityConfirmationOutcome::AlreadyConfirmed,
                    identity: existing,
                });
            }

            let provenance = tx
                .query_row(
                    "SELECT m.network_id,m.provider_instance_id,m.credential_id,r.provider_reference,m.invalidation_state,s.record_json,m.expires_at_ms \
                     FROM n4_provider_credential_metadata m \
                     JOIN n4_join_session_dispatches d ON d.join_session_id=m.join_session_id AND d.credential_id=m.credential_id \
                     JOIN confirmed_provider_credential_references r ON r.credential_id=m.credential_id \
                     JOIN join_sessions s ON s.join_session_id=m.join_session_id \
                     WHERE m.join_session_id=?1 AND d.dispatch_state='confirmed' AND m.single_use=1 AND m.reusable=0",
                    [evidence.join_session_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    StateError::Conflict(
                        "N5 identity requires a confirmed N4 credential dispatch".into(),
                    )
                })?;
            let network_id = NetworkId::parse(&provenance.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let provider_instance_id = ProviderInstanceId::parse(&provenance.1)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            if provider_instance_id != evidence.provider_identity.provider_instance_id
                || provenance.3 != evidence.provider_reference.as_str()
                || provenance.4 != "active"
                || confirmed_at.timestamp_millis() >= provenance.6
            {
                return Err(StateError::Conflict(
                    "provider evidence does not match the active N4 credential".into(),
                ));
            }

            let device_id = DeviceId::new();
            let binding_id = ProviderBindingId::new();
            let device = Device::new(device_id, network_id, device_id.to_string(), confirmed_at)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let mut session: JoinSession = serde_json::from_str(&provenance.5)?;
            if session.device_id.is_some() {
                return Err(StateError::Conflict(
                    "join session already names a logical device".into(),
                ));
            }
            session.device_id = Some(device_id);
            session.updated_at = confirmed_at;
            let correlation = safe_n5_digest(&[
                &evidence.join_session_id.to_string(),
                evidence.provider_reference.as_str(),
                &provider_instance_id.to_string(),
                evidence.provider_identity.node_id.as_str(),
                &evidence.provider_identity.stable_key_fingerprint,
            ]);

            tx.execute(
                "INSERT INTO devices (device_id,network_id,display_name,membership_state,provider_instance_id,provider_node_id,provider_key_fingerprint,credential_generation,keryx_binding_generation,fleet_projection_generation,fleet_projection_status,record_json,created_at,updated_at,revoked_at) VALUES (?1,?2,?3,'pending',NULL,NULL,NULL,1,1,1,'notrequested',?4,?5,?5,NULL)",
                params![device_id.to_string(), network_id.to_string(), device.display_name, serde_json::to_string(&device)?, confirmed_at.to_rfc3339()],
            )
            .map_err(map_constraint)?;
            tx.execute(
                "INSERT INTO device_generations (device_id,credential_generation,keryx_binding_generation,fleet_projection_generation,updated_at) VALUES (?1,1,1,1,?2)",
                params![device_id.to_string(), confirmed_at.to_rfc3339()],
            )?;
            tx.execute(
                "UPDATE join_sessions SET device_id=?2,record_json=?3,updated_at=?4 WHERE join_session_id=?1 AND device_id IS NULL",
                params![evidence.join_session_id.to_string(), device_id.to_string(), serde_json::to_string(&session)?, confirmed_at.to_rfc3339()],
            )?;
            tx.execute(
                "INSERT INTO n5_device_identities (device_id,network_id,origin_join_session_id,confirmed_at_ms,identity_revision,safe_correlation_digest) VALUES (?1,?2,?3,?4,1,?5)",
                params![device_id.to_string(), network_id.to_string(), evidence.join_session_id.to_string(), confirmed_at.timestamp_millis(), correlation],
            )?;
            tx.execute(
                "INSERT INTO n5_provider_bindings (binding_id,device_id,network_id,join_session_id,credential_id,provider_credential_reference,provider_instance_id,provider_node_id,machine_key_fingerprint,binding_state,binding_revision,observed_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'active',1,?10)",
                params![binding_id.to_string(), device_id.to_string(), network_id.to_string(), evidence.join_session_id.to_string(), provenance.2, evidence.provider_reference.as_str(), provider_instance_id.to_string(), evidence.provider_identity.node_id.as_str(), evidence.provider_identity.stable_key_fingerprint, evidence.observed_at.timestamp_millis()],
            )?;
            tx.execute(
                "INSERT INTO n5_device_trust_state (device_id,network_id,trust_state,trust_revision,created_at_ms,activated_at_ms,revoked_at_ms,last_decision_id) VALUES (?1,?2,'untrusted',1,?3,NULL,NULL,NULL)",
                params![device_id.to_string(), network_id.to_string(), confirmed_at.timestamp_millis()],
            )?;
            store.append_audit(
                tx,
                Some(network_id),
                Some(device_id),
                actor,
                "device.identity_confirmed",
                "success",
                Some(Generation::initial()),
                &SanitizedMetadata::empty(),
            )?;
            Ok(N5IdentityConfirmation {
                outcome: N5IdentityConfirmationOutcome::Confirmed,
                identity: load_n5_identity_by_session(tx, evidence.join_session_id)?
                    .ok_or_else(|| StateError::Conflict("N5 identity write was lost".into()))?,
            })
        })
    }

    pub fn bootstrap_n5_owner_trust_root(
        &self,
        network_id: NetworkId,
        principal_source: &str,
        principal_id: &str,
        _intent: DeviceTrustAuthorityAdminIntent,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<OwnerTrustRootToken, StateError> {
        validate_n5_principal(principal_source, principal_id)?;
        validate_n5_audit_actor(&actor)?;
        let token = OwnerTrustRootToken::generate(TrustRootId::new());
        let verifier = SecretVerifier::from_trust_root_token(&token)
            .map_err(|error| StateError::Conflict(error.to_string()))?;
        self.transactional(|tx, store| {
            tx.execute(
                "INSERT INTO n5_owner_trust_roots (trust_root_id,network_id,principal_source,principal_id,secret_verifier,enabled,revoked_at_ms,created_at_ms) VALUES (?1,?2,?3,?4,?5,1,NULL,?6)",
                params![token.trust_root_id().to_string(), network_id.to_string(), principal_source, principal_id, verifier.as_str(), now.timestamp_millis()],
            )
            .map_err(map_constraint)?;
            store.append_audit(
                tx,
                Some(network_id),
                None,
                actor,
                "device.owner_trust_root_bootstrapped",
                "success",
                Some(Generation::initial()),
                &SanitizedMetadata::empty(),
            )
        })?;
        Ok(token)
    }

    pub fn revoke_n5_owner_trust_root(
        &self,
        root_token: &OwnerTrustRootToken,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let network_id = tx
                .query_row(
                    "SELECT network_id FROM n5_owner_trust_roots WHERE trust_root_id=?1",
                    [root_token.trust_root_id().to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    StateError::MutationAuthorizationDenied("N5 owner trust root was not found")
                })
                .and_then(|value| {
                    NetworkId::parse(&value)
                        .map_err(|error| StateError::Conflict(error.to_string()))
                })?;
            let root = verify_n5_owner_root(tx, root_token, network_id)?;
            tx.execute(
                "UPDATE n5_trust_authorities SET enabled=0,revoked_at_ms=?2 \
                 WHERE trust_root_id=?1 AND sealed=1 AND enabled=1 AND revoked_at_ms IS NULL",
                params![
                    root_token.trust_root_id().to_string(),
                    now.timestamp_millis()
                ],
            )?;
            if tx.execute(
                "UPDATE n5_owner_trust_roots SET enabled=0,revoked_at_ms=?2 \
                 WHERE trust_root_id=?1 AND enabled=1 AND revoked_at_ms IS NULL",
                params![
                    root_token.trust_root_id().to_string(),
                    now.timestamp_millis()
                ],
            )? != 1
            {
                return Err(StateError::MutationAuthorizationDenied(
                    "N5 owner trust root revocation was stale",
                ));
            }
            store.append_audit(
                tx,
                Some(network_id),
                None,
                root,
                "device.owner_trust_root_revoked",
                "success",
                None,
                &SanitizedMetadata::empty(),
            )?;
            Ok(())
        })
    }

    pub fn configure_n5_trust_authority(
        &self,
        root_token: &OwnerTrustRootToken,
        configuration: &N5TrustAuthorityConfiguration,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let root = verify_n5_owner_root(tx, root_token, configuration.network_id)?;
            tx.execute(
                "INSERT INTO n5_trust_authorities (authority_id,trust_root_id,network_id,principal_source,principal_id,authority_generation,not_before_ms,expires_at_ms,sealed,enabled,revoked_at_ms,created_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,0,NULL,?9)",
                params![configuration.authority_id.to_string(), root_token.trust_root_id().to_string(), configuration.network_id.to_string(), configuration.principal_source, configuration.principal_id, to_i64(configuration.generation)?, configuration.not_before.timestamp_millis(), configuration.expires_at.timestamp_millis(), configuration.created_at.timestamp_millis()],
            )
            .map_err(map_constraint)?;
            for capability in &configuration.capabilities {
                tx.execute(
                    "INSERT INTO n5_trust_authority_capabilities (authority_id,capability) VALUES (?1,?2)",
                    params![configuration.authority_id.to_string(), capability.as_str()],
                )?;
            }
            let sealed = tx.execute(
                "UPDATE n5_trust_authorities SET sealed=1,enabled=1 WHERE authority_id=?1 AND sealed=0 AND enabled=0",
                [configuration.authority_id.to_string()],
            )?;
            if sealed != 1 {
                return Err(StateError::Conflict(
                    "N5 trust authority sealing was lost".into(),
                ));
            }
            store.append_audit(
                tx,
                Some(configuration.network_id),
                None,
                root,
                "device.trust_authority_configured",
                "success",
                Some(configuration.generation),
                &SanitizedMetadata::empty(),
            )
        })
    }

    pub fn revoke_n5_trust_authority(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        now: DateTime<Utc>,
    ) -> Result<(), StateError> {
        self.transactional(|tx, store| {
            let network: String = tx
                .query_row(
                    "SELECT network_id FROM n5_trust_authorities WHERE authority_id=?1 AND trust_root_id=?2",
                    params![authority_id.to_string(), root_token.trust_root_id().to_string()],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(authority_id.to_string()))?;
            let network_id = NetworkId::parse(&network)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let root = verify_n5_owner_root(tx, root_token, network_id)?;
            let changed = tx.execute(
                "UPDATE n5_trust_authorities SET enabled=0,revoked_at_ms=?2 WHERE authority_id=?1 AND enabled=1 AND revoked_at_ms IS NULL",
                params![authority_id.to_string(), now.timestamp_millis()],
            )?;
            if changed == 1 {
                store.append_audit(
                    tx,
                    Some(network_id),
                    None,
                    root,
                    "device.trust_authority_revoked",
                    "success",
                    None,
                    &SanitizedMetadata::empty(),
                )?;
            }
            Ok(())
        })
    }

    pub fn issue_device_trust_authorization(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        device_id: DeviceId,
        expected_revision: Generation,
        capability: DeviceTrustCapability,
        now: DateTime<Utc>,
    ) -> Result<DeviceTrustAuthorization, StateError> {
        self.transactional(|tx, store| {
            let row = tx
                .query_row(
                    "SELECT a.network_id,a.authority_generation,a.principal_source,a.principal_id,a.expires_at_ms,s.trust_state,s.trust_revision \
                     FROM n5_trust_authorities a \
                     JOIN n5_trust_authority_capabilities c ON c.authority_id=a.authority_id \
                     JOIN n5_device_trust_state s ON s.network_id=a.network_id \
                     WHERE a.authority_id=?1 AND s.device_id=?2 AND c.capability=?3 \
                       AND a.trust_root_id=?5 \
                       AND a.sealed=1 AND a.enabled=1 AND a.revoked_at_ms IS NULL \
                       AND ?4>=a.not_before_ms AND ?4<a.expires_at_ms",
                    params![authority_id.to_string(), device_id.to_string(), capability.as_str(), now.timestamp_millis(), root_token.trust_root_id().to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, u64>(6)?,
                        ))
                    },
                )
                .optional()?
                .ok_or(StateError::MutationAuthorizationDenied(
                    "N5 trust authority is absent, stale, or lacks the exact capability",
                ))?;
            let actual_revision = generation(row.6)?;
            if actual_revision != expected_revision {
                return Err(StateError::StaleGeneration {
                    expected: expected_revision.get(),
                    actual: actual_revision.get(),
                });
            }
            let expected_state = parse_trust_state(&row.5)?;
            match (capability, expected_state) {
                (
                    DeviceTrustCapability::ActivateDeviceTrust,
                    DeviceTrustState::Untrusted,
                )
                | (
                    DeviceTrustCapability::RevokeDeviceTrust,
                    DeviceTrustState::Untrusted | DeviceTrustState::Trusted,
                ) => {}
                _ => {
                    return Err(StateError::MutationAuthorizationDenied(
                        "N5 trust action is already satisfied or terminal",
                    ));
                }
            }
            let authority_generation = generation(row.1)?;
            let network_id = NetworkId::parse(&row.0)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let root = verify_n5_owner_root(tx, root_token, network_id)?;
            let authority_expiry = DateTime::from_timestamp_millis(row.4)
                .ok_or_else(|| StateError::Conflict("invalid trust authority expiry".into()))?;
            let expires_at = std::cmp::min(authority_expiry, now + Duration::minutes(5));
            let action_id = TrustActionId::new();
            tx.execute(
                "INSERT INTO n5_trust_authorizations (action_id,authority_id,authority_generation,device_id,network_id,expected_trust_state,expected_revision,capability,principal_source,principal_id,issued_at_ms,expires_at_ms,consumed_at_ms,decision_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,NULL)",
                params![action_id.to_string(), authority_id.to_string(), to_i64(authority_generation)?, device_id.to_string(), network_id.to_string(), trust_state_name(expected_state), expected_revision.get(), capability.as_str(), row.2, row.3, now.timestamp_millis(), expires_at.timestamp_millis()],
            )
            .map_err(map_constraint)?;
            store.append_audit(
                tx,
                Some(network_id),
                Some(device_id),
                root,
                "device.trust_authorization_issued",
                "success",
                Some(expected_revision),
                &SanitizedMetadata::empty(),
            )?;
            Ok(DeviceTrustAuthorization {
                action_id,
                authority_id,
                authority_generation,
                device_id,
                network_id,
                expected_state,
                expected_revision,
                capability,
                principal_source: row.2,
                principal_id: row.3,
                issued_at: now,
                expires_at,
            })
        })
    }

    pub fn activate_device_trust(
        &self,
        authorization: DeviceTrustAuthorization,
        now: DateTime<Utc>,
        reason: N5TrustReason,
    ) -> Result<N5TrustDecisionResult, StateError> {
        self.apply_n5_trust_decision(
            authorization,
            now,
            DeviceTrustCapability::ActivateDeviceTrust,
            TrustDecisionKind::Activate,
            reason,
        )
    }

    pub fn revoke_device_trust(
        &self,
        authorization: DeviceTrustAuthorization,
        now: DateTime<Utc>,
        reason: N5TrustReason,
    ) -> Result<N5TrustDecisionResult, StateError> {
        self.apply_n5_trust_decision(
            authorization,
            now,
            DeviceTrustCapability::RevokeDeviceTrust,
            TrustDecisionKind::Revoke,
            reason,
        )
    }

    fn apply_n5_trust_decision(
        &self,
        authorization: DeviceTrustAuthorization,
        now: DateTime<Utc>,
        required_capability: DeviceTrustCapability,
        kind: TrustDecisionKind,
        reason: N5TrustReason,
    ) -> Result<N5TrustDecisionResult, StateError> {
        if authorization.capability != required_capability
            || now < authorization.issued_at
            || now >= authorization.expires_at
        {
            return Err(StateError::MutationAuthorizationDenied(
                "N5 trust authorization is wrong-purpose or expired",
            ));
        }
        self.transactional(|tx, store| {
            let (state_name, revision): (String, u64) = tx
                .query_row(
                    "SELECT trust_state,trust_revision FROM n5_device_trust_state WHERE device_id=?1 AND network_id=?2",
                    params![authorization.device_id.to_string(), authorization.network_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| StateError::NotFound(authorization.device_id.to_string()))?;
            let current = parse_trust_state(&state_name)?;
            if revision != authorization.expected_revision.get()
                || current != authorization.expected_state
            {
                return Err(StateError::StaleGeneration {
                    expected: authorization.expected_revision.get(),
                    actual: revision,
                });
            }
            let target = match kind {
                TrustDecisionKind::Activate => DeviceTrustState::Trusted,
                TrustDecisionKind::Revoke => DeviceTrustState::Revoked,
            };
            current
                .transition(target)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            let decision_id = TrustDecisionId::new();
            let audit_event_id = AuditEventId::new();
            if store.fail_before_audit.get() {
                return Err(StateError::InjectedFailure);
            }
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| StateError::Conflict("trust revision overflow".into()))?;
            let correlation = safe_n5_digest(&[
                &authorization.action_id.to_string(),
                &authorization.device_id.to_string(),
                kind.as_str(),
            ]);
            tx.execute(
                "INSERT INTO n5_trust_decisions (decision_id,audit_event_id,action_id,device_id,network_id,prior_trust_state,new_trust_state,decision_kind,decided_at_ms,authority_id,authority_generation,authorized_principal_source,authorized_principal_id,prior_revision,new_revision,safe_correlation_digest,reason_code) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![decision_id.to_string(), audit_event_id.to_string(), authorization.action_id.to_string(), authorization.device_id.to_string(), authorization.network_id.to_string(), trust_state_name(current), trust_state_name(target), kind.as_str(), now.timestamp_millis(), authorization.authority_id.to_string(), to_i64(authorization.authority_generation)?, authorization.principal_source, authorization.principal_id, revision, next_revision, correlation, reason.as_str()],
            )
            .map_err(map_constraint)?;
            Ok(N5TrustDecisionResult {
                outcome: N5TrustDecisionOutcome::Applied,
                view: load_device_trust_view(tx, authorization.device_id)?,
            })
        })
    }

    pub(crate) fn persisted_device_trust_view(
        &self,
        device_id: DeviceId,
    ) -> Result<DeviceTrustView, StateError> {
        load_device_trust_view(&self.connection.borrow(), device_id)
    }

    pub fn device_id_by_provider_registration(
        &self,
        provider_instance_id: ProviderInstanceId,
        provider_node_id: nodescale_domain::ProviderNodeId,
    ) -> Result<Option<DeviceId>, StateError> {
        self.connection
            .borrow()
            .query_row(
                "SELECT device_id FROM n5_provider_bindings WHERE provider_instance_id=?1 AND provider_node_id=?2 AND binding_state='active'",
                params![provider_instance_id.to_string(), provider_node_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|device_id| {
                DeviceId::parse(&device_id)
                    .map_err(|error| StateError::Conflict(error.to_string()))
            })
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn persisted_device_trust_view_by_provider_registration(
        &self,
        provider_instance_id: ProviderInstanceId,
        provider_node_id: nodescale_domain::ProviderNodeId,
    ) -> Result<Option<DeviceTrustView>, StateError> {
        let connection = self.connection.borrow();
        let device_id = connection
            .query_row(
                "SELECT device_id FROM n5_provider_bindings WHERE provider_instance_id=?1 AND provider_node_id=?2 AND binding_state='active'",
                params![provider_instance_id.to_string(), provider_node_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        device_id
            .map(|device_id| {
                DeviceId::parse(&device_id)
                    .map_err(|error| StateError::Conflict(error.to_string()))
                    .and_then(|device_id| load_device_trust_view(&connection, device_id))
            })
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn persisted_trusted_device_count(
        &self,
        network_id: NetworkId,
    ) -> Result<u64, StateError> {
        Ok(self.connection.borrow().query_row(
            "SELECT COUNT(*) FROM n5_device_trust_state s WHERE s.network_id=?1 AND s.trust_state='trusted' AND EXISTS (SELECT 1 FROM n5_provider_bindings b WHERE b.device_id=s.device_id AND b.binding_state='active')",
            [network_id.to_string()],
            |row| row.get(0),
        )?)
    }

    pub fn mark_n5_provider_binding_stale(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        validate_n5_audit_actor(&actor)?;
        self.transactional(|tx, store| {
            if store.fail_before_audit.get() {
                return Err(StateError::InjectedFailure);
            }
            let changed = tx.execute(
                "UPDATE n5_provider_bindings SET binding_state='stale',binding_revision=binding_revision+1,stale_at_ms=?3,last_transition_audit_event_id=?4,transition_actor_source=?5,transition_actor_id=?6 WHERE device_id=?1 AND binding_state='active' AND binding_revision=?2",
                params![device_id.to_string(), expected_revision.get(), now.timestamp_millis(), AuditEventId::new().to_string(), actor.source, actor.actor_id],
            )?;
            if changed != 1 {
                return Err(StateError::StaleGeneration {
                    expected: expected_revision.get(),
                    actual: tx.query_row(
                        "SELECT binding_revision FROM n5_provider_bindings WHERE device_id=?1 ORDER BY binding_revision DESC LIMIT 1",
                        [device_id.to_string()],
                        |row| row.get(0),
                    )?,
                });
            }
            load_device_trust_view(tx, device_id)
        })
    }

    pub fn mark_n5_provider_binding_cleanup_pending(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        self.transition_n5_provider_binding(
            device_id,
            expected_revision,
            &["active", "stale"],
            "cleanup_pending",
            "cleanup_pending_at_ms",
            now,
            actor,
        )
    }

    pub fn mark_n5_provider_binding_removed(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        self.transition_n5_provider_binding(
            device_id,
            expected_revision,
            &["stale", "cleanup_pending"],
            "removed",
            "removed_at_ms",
            now,
            actor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition_n5_provider_binding(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        allowed_states: &[&str],
        target_state: &str,
        timestamp_column: &str,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        validate_n5_audit_actor(&actor)?;
        let allowed = match allowed_states {
            ["active", "stale"] => "binding_state IN ('active','stale')",
            ["stale", "cleanup_pending"] => "binding_state IN ('stale','cleanup_pending')",
            _ => {
                return Err(StateError::Conflict(
                    "unsupported N5 provider binding transition".into(),
                ));
            }
        };
        let query = format!(
            "UPDATE n5_provider_bindings SET binding_state=?3,binding_revision=binding_revision+1,{timestamp_column}=?4,last_transition_audit_event_id=?5,transition_actor_source=?6,transition_actor_id=?7 WHERE device_id=?1 AND {allowed} AND binding_revision=?2"
        );
        self.transactional(|tx, store| {
            if store.fail_before_audit.get() {
                return Err(StateError::InjectedFailure);
            }
            let changed = tx.execute(
                &query,
                params![
                    device_id.to_string(),
                    expected_revision.get(),
                    target_state,
                    now.timestamp_millis(),
                    AuditEventId::new().to_string(),
                    actor.source,
                    actor.actor_id,
                ],
            )?;
            if changed != 1 {
                let actual = tx.query_row(
                    "SELECT binding_revision FROM n5_provider_bindings WHERE device_id=?1 ORDER BY binding_revision DESC LIMIT 1",
                    [device_id.to_string()],
                    |row| row.get(0),
                )?;
                return Err(StateError::StaleGeneration {
                    expected: expected_revision.get(),
                    actual,
                });
            }
            load_device_trust_view(tx, device_id)
        })
    }

    pub async fn reconcile_n5_provider_binding(
        &self,
        provider: &N5ConfiguredHeadscaleProvider,
        device_id: DeviceId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        provider.validate_current(self)?;
        let view = self.persisted_device_trust_view(device_id)?;
        if view.network_id != provider.network_id {
            return Err(StateError::Conflict(
                "configured provider network does not match device".into(),
            ));
        }
        self.reconcile_n5_provider_binding_from_provider(provider.provider(), device_id, now, actor)
            .await
    }

    pub(crate) async fn reconcile_n5_provider_binding_from_provider<P: ReadOnlyProvider>(
        &self,
        provider: &P,
        device_id: DeviceId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, StateError> {
        validate_n5_audit_actor(&actor)?;
        let view = self.persisted_device_trust_view(device_id)?;
        let Some(binding) = view
            .provider_binding
            .as_ref()
            .filter(|binding| binding.binding_state == ProviderBindingState::Active)
        else {
            return Ok(view);
        };
        if provider.instance_id() != binding.provider_identity.provider_instance_id {
            return Err(StateError::Conflict(
                "N5 provider reconciliation used the wrong provider instance".into(),
            ));
        }
        let observed = match provider.get_node(&binding.provider_identity).await {
            Ok(observed) => observed,
            Err(error) => {
                self.mark_n5_provider_binding_stale(
                    device_id,
                    binding.binding_revision,
                    now,
                    actor,
                )?;
                return Err(StateError::Conflict(format!(
                    "N5 provider reconciliation failed and binding was staled: {error}"
                )));
            }
        };
        let remains_exact = observed.as_ref().is_some_and(|node| {
            node.identity == binding.provider_identity
                && node.pre_auth.as_ref().is_some_and(|association| {
                    association.credential_id == binding.provider_reference.as_str()
                        && association.association
                            == PreAuthAssociationStrength::ProviderAuthenticatedRegistration
                })
                && node.expires_at.is_none_or(|expires_at| expires_at > now)
                && !node.expired
                && node
                    .identity_evidence
                    .machine_key
                    .as_ref()
                    .is_some_and(|machine_key| {
                        format!(
                            "sha256:{:x}",
                            Sha256::digest(machine_key.as_str().as_bytes())
                        ) == binding.provider_identity.stable_key_fingerprint
                    })
        });
        if remains_exact {
            let mut provider_fresh_view = view;
            provider_fresh_view.currently_trusted =
                provider_fresh_view.trust_state == DeviceTrustState::Trusted;
            return Ok(provider_fresh_view);
        }
        self.mark_n5_provider_binding_stale(device_id, binding.binding_revision, now, actor)
    }
}

fn validate_n5_principal(source: &str, principal_id: &str) -> Result<(), StateError> {
    let valid = |value: &str, max: usize| {
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    };
    if !valid(source, 64) || !valid(principal_id, 255) {
        return Err(StateError::Conflict(
            "N5 trust principal contains unsafe metadata".into(),
        ));
    }
    Ok(())
}

fn validate_n5_audit_actor(actor: &AuditActor) -> Result<(), StateError> {
    match actor.actor_id.as_deref() {
        Some(actor_id) => validate_n5_principal(&actor.source, actor_id),
        None if actor.source == "nodescale" => Ok(()),
        None => Err(StateError::MutationAuthorizationDenied(
            "N5 audit actor requires bounded provenance",
        )),
    }
}

pub(super) fn verify_n5_owner_root(
    tx: &Transaction<'_>,
    token: &OwnerTrustRootToken,
    network_id: NetworkId,
) -> Result<AuditActor, StateError> {
    let row = tx
        .query_row(
            "SELECT principal_source,principal_id,secret_verifier FROM n5_owner_trust_roots WHERE trust_root_id=?1 AND network_id=?2 AND enabled=1 AND revoked_at_ms IS NULL",
            params![token.trust_root_id().to_string(), network_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()?
        .ok_or(StateError::MutationAuthorizationDenied(
            "N5 owner trust root is absent or revoked",
        ))?;
    let verifier =
        SecretVerifier::parse(row.2).map_err(|error| StateError::Conflict(error.to_string()))?;
    if !verifier
        .verify_trust_root(token)
        .map_err(|error| StateError::Conflict(error.to_string()))?
    {
        return Err(StateError::MutationAuthorizationDenied(
            "N5 owner trust root capability is invalid",
        ));
    }
    Ok(AuditActor {
        source: row.0,
        actor_id: Some(row.1),
    })
}

fn select_n5_provider_registration<'a>(
    context: &N5JoinCorrelationContext,
    nodes: &'a [ProviderNode],
    now: DateTime<Utc>,
) -> Result<&'a ProviderNode, StateError> {
    let matches = nodes
        .iter()
        .filter(|node| {
            node.pre_auth.as_ref().is_some_and(|association| {
                association.credential_id == context.provider_reference.as_str()
                    && association.association
                        == PreAuthAssociationStrength::ProviderAuthenticatedRegistration
            })
        })
        .collect::<Vec<_>>();
    let node = match matches.as_slice() {
        [] => {
            return Err(StateError::Conflict(
                "no authenticated provider registration matches the N5 join".into(),
            ));
        }
        [node] => *node,
        _ => {
            return Err(StateError::Conflict(
                "multiple provider registrations match one N5 join".into(),
            ));
        }
    };
    validate_n5_provider_registration(context, node, now)?;
    Ok(node)
}

fn validate_n5_provider_registration(
    context: &N5JoinCorrelationContext,
    node: &ProviderNode,
    now: DateTime<Utc>,
) -> Result<(), StateError> {
    let association_matches = node.pre_auth.as_ref().is_some_and(|association| {
        association.credential_id == context.provider_reference.as_str()
            && association.association
                == PreAuthAssociationStrength::ProviderAuthenticatedRegistration
    });
    let machine_key_matches =
        node.identity_evidence
            .machine_key
            .as_ref()
            .is_some_and(|machine_key| {
                format!(
                    "sha256:{:x}",
                    Sha256::digest(machine_key.as_str().as_bytes())
                ) == node.identity.stable_key_fingerprint
            });
    if !association_matches
        || node.identity.provider_instance_id != context.provider_instance_id
        || !machine_key_matches
        || node.expired
        || node.expires_at.is_some_and(|expiry| now >= expiry)
    {
        return Err(StateError::Conflict(
            "provider registration does not satisfy N5 identity evidence".into(),
        ));
    }
    Ok(())
}

fn load_n5_identity_by_session(
    connection: &Connection,
    join_session_id: JoinSessionId,
) -> Result<Option<N5DeviceIdentity>, StateError> {
    connection
        .query_row(
            "SELECT i.device_id,i.network_id,i.confirmed_at_ms,b.binding_id,b.provider_credential_reference,b.provider_instance_id,b.provider_node_id,b.machine_key_fingerprint,b.binding_state,b.binding_revision \
             FROM n5_device_identities i JOIN n5_provider_bindings b ON b.device_id=i.device_id AND b.join_session_id=i.origin_join_session_id \
             WHERE i.origin_join_session_id=?1",
            [join_session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?, row.get::<_, String>(7)?, row.get::<_, String>(8)?,
                    row.get::<_, u64>(9)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            let provider_instance_id = ProviderInstanceId::parse(&row.5)
                .map_err(|error| StateError::Conflict(error.to_string()))?;
            Ok(N5DeviceIdentity {
                device_id: DeviceId::parse(&row.0)
                    .map_err(|error| StateError::Conflict(error.to_string()))?,
                network_id: NetworkId::parse(&row.1)
                    .map_err(|error| StateError::Conflict(error.to_string()))?,
                origin_join_session_id: join_session_id,
                binding_id: ProviderBindingId::parse(&row.3)
                    .map_err(|error| StateError::Conflict(error.to_string()))?,
                provider_reference: ProviderCredentialReference::new(row.4)
                    .map_err(|error| StateError::Conflict(error.to_string()))?,
                provider_identity: nodescale_domain::ProviderIdentity::new(
                    provider_instance_id,
                    nodescale_domain::ProviderNodeId::parse(row.6)
                        .map_err(|error| StateError::Conflict(error.to_string()))?,
                    row.7,
                )
                .map_err(|error| StateError::Conflict(error.to_string()))?,
                binding_state: parse_binding_state(&row.8)?,
                binding_revision: generation(row.9)?,
                confirmed_at: DateTime::from_timestamp_millis(row.2)
                    .ok_or_else(|| StateError::Conflict("invalid N5 confirmation time".into()))?,
            })
        })
        .transpose()
}

fn load_device_trust_view(
    connection: &Connection,
    device_id: DeviceId,
) -> Result<DeviceTrustView, StateError> {
    let row = connection
        .query_row(
            "SELECT network_id,trust_state,trust_revision FROM n5_device_trust_state WHERE device_id=?1",
            [device_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?)),
        )
        .optional()?
        .ok_or_else(|| StateError::NotFound(device_id.to_string()))?;
    let network_id =
        NetworkId::parse(&row.0).map_err(|error| StateError::Conflict(error.to_string()))?;
    let trust_state = parse_trust_state(&row.1)?;
    let binding_join = connection
        .query_row(
            "SELECT join_session_id FROM n5_provider_bindings WHERE device_id=?1",
            [device_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let provider_binding = binding_join
        .map(|join| {
            JoinSessionId::parse(&join)
                .map_err(|error| StateError::Conflict(error.to_string()))
                .and_then(|join_session_id| {
                    load_n5_identity_by_session(connection, join_session_id)?.ok_or_else(|| {
                        StateError::Conflict("provider binding has no N5 identity".into())
                    })
                })
        })
        .transpose()?;
    Ok(DeviceTrustView {
        device_id,
        network_id,
        trust_state,
        trust_revision: generation(row.2)?,
        currently_trusted: false,
        provider_binding,
    })
}

fn parse_trust_state(value: &str) -> Result<DeviceTrustState, StateError> {
    match value {
        "untrusted" => Ok(DeviceTrustState::Untrusted),
        "trusted" => Ok(DeviceTrustState::Trusted),
        "revoked" => Ok(DeviceTrustState::Revoked),
        _ => Err(StateError::Conflict("invalid N5 trust state".into())),
    }
}

fn trust_state_name(value: DeviceTrustState) -> &'static str {
    match value {
        DeviceTrustState::Untrusted => "untrusted",
        DeviceTrustState::Trusted => "trusted",
        DeviceTrustState::Revoked => "revoked",
    }
}

fn parse_binding_state(value: &str) -> Result<ProviderBindingState, StateError> {
    match value {
        "active" => Ok(ProviderBindingState::Active),
        "stale" => Ok(ProviderBindingState::Stale),
        "cleanup_pending" => Ok(ProviderBindingState::CleanupPending),
        "removed" => Ok(ProviderBindingState::Removed),
        _ => Err(StateError::Conflict(
            "invalid N5 provider binding state".into(),
        )),
    }
}

fn safe_n5_digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}
