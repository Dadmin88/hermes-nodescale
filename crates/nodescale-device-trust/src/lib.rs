//! Authoritative N5 device identity correlation and explicit trust service.
//!
//! A logical Nodescale device is created only after one exact provider node is
//! linked to the confirmed, active, single-use N4 provider credential. Provider
//! registration is evidence for a binding; it is never the logical device ID or
//! a trust decision.

use chrono::{DateTime, Utc};
use nodescale_domain::{
    AuditActor, DeviceId, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation,
    JoinSessionId, NetworkId, OwnerTrustRootToken, TrustAuthorityId,
};
use nodescale_provider::{ProviderError, ReadOnlyProvider};
use nodescale_state::{
    DeviceTrustAuthorization, DeviceTrustView, N5DeviceIdentity, N5IdentityConfirmation,
    N5TrustAuthorityConfiguration, N5TrustDecisionResult, N5TrustReason, StateError, StateStore,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceIdentityError {
    #[error("device identity state is unavailable")]
    State(#[source] StateError),
    #[error("provider observation is unavailable")]
    Provider(#[source] ProviderError),
    #[error("configured provider does not match the join session")]
    ProviderMismatch,
    #[error("join-session identity evidence has expired")]
    CorrelationExpired,
    #[error("no authoritative provider registration matches the join session")]
    RegistrationNotObserved,
    #[error("multiple provider registrations match one join session")]
    AmbiguousRegistration,
    #[error("provider registration identity evidence is invalid")]
    InvalidProviderEvidence,
}

pub struct DeviceIdentityService<'a, P> {
    store: &'a StateStore,
    provider: &'a P,
}
impl<'a, P: ReadOnlyProvider> DeviceIdentityService<'a, P> {
    #[must_use]
    pub const fn new(store: &'a StateStore, provider: &'a P) -> Self {
        Self { store, provider }
    }

    pub async fn confirm_join_identity(
        &self,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N5IdentityConfirmation, DeviceIdentityError> {
        self.store
            .confirm_n5_device_identity(self.provider, join_session_id, now, actor)
            .await
            .map_err(DeviceIdentityError::State)
    }

    pub async fn reconcile_active_binding(
        &self,
        device_id: DeviceId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, DeviceIdentityError> {
        self.store
            .reconcile_n5_provider_binding(self.provider, device_id, now, actor)
            .await
            .map_err(DeviceIdentityError::State)
    }

    pub fn mark_binding_cleanup_pending(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, DeviceIdentityError> {
        self.store
            .mark_n5_provider_binding_cleanup_pending(device_id, expected_revision, now, actor)
            .map_err(DeviceIdentityError::State)
    }

    pub fn mark_binding_removed(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, DeviceIdentityError> {
        self.store
            .mark_n5_provider_binding_removed(device_id, expected_revision, now, actor)
            .map_err(DeviceIdentityError::State)
    }

    pub fn trust_view(&self, device_id: DeviceId) -> Result<DeviceTrustView, DeviceIdentityError> {
        self.store
            .device_trust_view(device_id)
            .map_err(DeviceIdentityError::State)
    }

    pub fn trusted_device_count(&self, network_id: NetworkId) -> Result<u64, DeviceIdentityError> {
        self.store
            .trusted_device_count(network_id)
            .map_err(DeviceIdentityError::State)
    }

    pub fn revoke_owner_trust_root(
        &self,
        root_token: &OwnerTrustRootToken,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceIdentityError> {
        self.store
            .revoke_n5_owner_trust_root(root_token, now)
            .map_err(DeviceIdentityError::State)
    }

    pub fn configure_trust_authority(
        &self,
        root_token: &OwnerTrustRootToken,
        configuration: &N5TrustAuthorityConfiguration,
    ) -> Result<(), DeviceIdentityError> {
        self.store
            .configure_n5_trust_authority(root_token, configuration)
            .map_err(DeviceIdentityError::State)
    }

    pub fn bootstrap_owner_trust_root(
        &self,
        network_id: NetworkId,
        principal_source: &str,
        principal_id: &str,
        intent: DeviceTrustAuthorityAdminIntent,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<OwnerTrustRootToken, DeviceIdentityError> {
        self.store
            .bootstrap_n5_owner_trust_root(
                network_id,
                principal_source,
                principal_id,
                intent,
                now,
                actor,
            )
            .map_err(DeviceIdentityError::State)
    }

    pub fn revoke_trust_authority(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceIdentityError> {
        self.store
            .revoke_n5_trust_authority(root_token, authority_id, now)
            .map_err(DeviceIdentityError::State)
    }

    pub fn issue_trust_authorization(
        &self,
        root_token: &OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        device_id: DeviceId,
        expected_revision: Generation,
        capability: DeviceTrustCapability,
        now: DateTime<Utc>,
    ) -> Result<DeviceTrustAuthorization, DeviceIdentityError> {
        self.store
            .issue_device_trust_authorization(
                root_token,
                authority_id,
                device_id,
                expected_revision,
                capability,
                now,
            )
            .map_err(DeviceIdentityError::State)
    }

    pub fn activate_trust(
        &self,
        authorization: DeviceTrustAuthorization,
        now: DateTime<Utc>,
        reason: N5TrustReason,
    ) -> Result<N5TrustDecisionResult, DeviceIdentityError> {
        self.store
            .activate_device_trust(authorization, now, reason)
            .map_err(DeviceIdentityError::State)
    }

    pub fn revoke_trust(
        &self,
        authorization: DeviceTrustAuthorization,
        now: DateTime<Utc>,
        reason: N5TrustReason,
    ) -> Result<N5TrustDecisionResult, DeviceIdentityError> {
        self.store
            .revoke_device_trust(authorization, now, reason)
            .map_err(DeviceIdentityError::State)
    }

    pub fn mark_active_binding_stale(
        &self,
        device_id: DeviceId,
        expected_revision: Generation,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<DeviceTrustView, DeviceIdentityError> {
        self.store
            .mark_n5_provider_binding_stale(device_id, expected_revision, now, actor)
            .map_err(DeviceIdentityError::State)
    }
}

#[must_use]
pub fn confirmed_device_identity(confirmation: &N5IdentityConfirmation) -> &N5DeviceIdentity {
    &confirmation.identity
}
