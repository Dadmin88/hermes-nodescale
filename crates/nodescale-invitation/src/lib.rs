//! N4 invitation issuance orchestration over the fenced state boundary.
//!
//! This slice deliberately creates and presents invitations only. Redemption and
//! cleanup remain separate lifecycle slices so no provider mutation is reachable
//! from this public API yet.

use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Invitation, InvitationAdminIntent, InvitationId, InvitationToken, JoinConstraints,
    JoinSessionId, NetworkId, ProviderCredentialId, ProviderInstanceId, ProviderJoinCredential,
    Role, Roles,
};
use nodescale_provider::{
    JoinCredentialRequest, MutationEvidence, MutationOutcome, MutationProvider, ProviderMutation,
    ProviderMutationCapability,
};
use nodescale_state::{
    MutationAuthorization, N4CleanupIntent, N4CleanupTarget, N4CredentialConfirmation,
    N4CredentialDispatch, N4DispatchFailure, N4InvalidationOutcome, N4InvitationContext,
    N4InvitationView, N4PresentedMetadata, SanitizedMetadata, StateError, StateStore,
};
use std::{collections::BTreeSet, fmt};

const INVITATION_LIFETIME: Duration = Duration::minutes(15);
const MAX_N4_ROLES: usize = 4;

/// Issues provider-specific single-use authority without erasing the provider's
/// associated authorization type. Future redemption and cleanup slices consume
/// this authority after state has installed their durable dispatch fences.
pub trait N4AuthorizationIssuer<P>
where
    P: MutationProvider,
{
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, P::Authorization), StateError>;

    fn issue_invalidation(
        &self,
        store: &StateStore,
        target: &N4CleanupTarget,
        now: DateTime<Utc>,
    ) -> Result<P::Authorization, StateError>;
}

/// Production authority comes only from the state-owned authorization issuer.
impl<P> N4AuthorizationIssuer<P> for StateStore
where
    P: MutationProvider<Authorization = MutationAuthorization>,
{
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, P::Authorization), StateError> {
        debug_assert!(std::ptr::eq(self, store));
        store.begin_n4_credential_dispatch_with_authorization(join_session_id, now, actor)
    }

    fn issue_invalidation(
        &self,
        store: &StateStore,
        target: &N4CleanupTarget,
        now: DateTime<Utc>,
    ) -> Result<P::Authorization, StateError> {
        debug_assert!(std::ptr::eq(self, store));
        store.issue_mutation_authorization(
            target.network_id,
            target.provider_instance_id,
            ProviderMutationCapability::InvalidateJoinCredential,
            now,
        )
    }
}

/// The only N4 creation inputs accepted by this service. Lifetime and use count
/// are fixed by the service and cannot be supplied by a caller.
pub struct CreateInvitationRequest {
    pub network_id: NetworkId,
    pub provider_instance_id: ProviderInstanceId,
    pub provider_principal_id: String,
    pub roles: Roles,
    pub admin_intent: Option<InvitationAdminIntent>,
    pub join_constraints: JoinConstraints,
    pub actor: AuditActor,
}
impl fmt::Debug for CreateInvitationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateInvitationRequest")
            .field("network_id", &self.network_id)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("provider_principal_id", &"[REDACTED]")
            .field("roles", &self.roles)
            .field("admin_intent", &self.admin_intent.is_some())
            .field("join_constraints", &self.join_constraints)
            .field("actor", &self.actor)
            .finish()
    }
}

/// Owned one-time invitation delivery. Formatting never reveals the token.
pub struct IssuedInvitation {
    view: N4InvitationView,
    token: InvitationToken,
}
impl IssuedInvitation {
    #[must_use]
    pub fn view(&self) -> &N4InvitationView {
        &self.view
    }

    /// Consumes delivery material so it can only be exposed for one immediate
    /// caller-controlled handoff.
    pub fn deliver_token<R>(
        self,
        deliver: impl for<'token> FnOnce(&'token str) -> R,
    ) -> (N4InvitationView, R) {
        let view = self.view;
        let delivered = self.token.expose_for_delivery(deliver);
        (view, delivered)
    }
}
impl fmt::Debug for IssuedInvitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedInvitation")
            .field("view", &self.view)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

pub struct RedeemInvitationRequest {
    pub token: InvitationToken,
    pub presented: N4PresentedMetadata,
    pub actor: AuditActor,
}
impl fmt::Debug for RedeemInvitationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedeemInvitationRequest")
            .field("token", &"[REDACTED]")
            .field("presented", &self.presented)
            .field("actor", &self.actor)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedemptionReceipt {
    pub invitation_id: InvitationId,
    pub join_session_id: JoinSessionId,
    pub credential_id: ProviderCredentialId,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
}

pub struct ProviderCredentialDelivery {
    receipt: RedemptionReceipt,
    secret: ProviderJoinCredential,
}
impl fmt::Debug for ProviderCredentialDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderCredentialDelivery")
            .field("receipt", &self.receipt)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl ProviderCredentialDelivery {
    #[must_use]
    pub const fn receipt(&self) -> &RedemptionReceipt {
        &self.receipt
    }

    pub fn deliver_once<R>(
        self,
        deliver: impl for<'credential> FnOnce(&'credential str) -> R,
    ) -> (RedemptionReceipt, R) {
        let Self { receipt, secret } = self;
        let delivered = secret.expose(deliver);
        (receipt, delivered)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryReconciliationFailure {
    pub invitation_id: InvitationId,
    pub error: InvitationServiceError,
}

#[derive(Debug, Default)]
pub struct ExpiryReconciliationReport {
    pub settled: Vec<N4InvitationView>,
    pub pending: Vec<ExpiryReconciliationFailure>,
}

/// Stable redacted service categories. Raw state errors can carry database or
/// provider material, so they never cross this boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InvitationServiceError {
    InvalidRequest,
    NotFound,
    Conflict,
    Unavailable,
    ProviderRejected,
    ProviderUnavailable,
    AuthenticationFailed,
    CompatibilityBlocked,
    Ambiguous,
}
impl InvitationServiceError {
    const fn label(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid invitation request",
            Self::NotFound => "invitation resource was not found",
            Self::Conflict => "invitation state conflict",
            Self::Unavailable => "invitation state is unavailable",
            Self::ProviderRejected => "provider mutation was rejected",
            Self::ProviderUnavailable => "provider is unavailable",
            Self::AuthenticationFailed => "provider authentication failed",
            Self::CompatibilityBlocked => "provider compatibility blocks mutation",
            Self::Ambiguous => "provider credential mutation outcome is ambiguous",
        }
    }
}
impl fmt::Debug for InvitationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
impl fmt::Display for InvitationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
impl std::error::Error for InvitationServiceError {}

/// Single-threaded N4 creation coordinator. `StateStore` intentionally does not
/// promise `Sync`, so this service makes no Send/Sync claim.
pub struct InvitationService<'a, P, I>
where
    P: MutationProvider,
    I: N4AuthorizationIssuer<P>,
{
    store: &'a StateStore,
    provider: &'a P,
    issuer: &'a I,
}
impl<'a, P, I> InvitationService<'a, P, I>
where
    P: MutationProvider,
    I: N4AuthorizationIssuer<P>,
{
    #[must_use]
    pub const fn new(store: &'a StateStore, provider: &'a P, issuer: &'a I) -> Self {
        Self {
            store,
            provider,
            issuer,
        }
    }

    /// Creates a fixed fifteen-minute, single-use N4 invitation and returns its
    /// safe view plus one owned delivery opportunity for the plaintext token.
    pub fn create(
        &self,
        request: CreateInvitationRequest,
        now: DateTime<Utc>,
    ) -> Result<IssuedInvitation, InvitationServiceError> {
        if request.roles.iter().count() > MAX_N4_ROLES {
            return Err(InvitationServiceError::InvalidRequest);
        }
        // Validate the typed role vocabulary at issuance; future provider dispatch
        // reuses the same closed mapping rather than accepting tag strings.
        let _ = closed_tags(&request.roles)?;

        let network = self.store.network(request.network_id).map_err(map_state)?;
        if network.provider_instance_id != request.provider_instance_id
            || self.provider.instance_id() != request.provider_instance_id
        {
            return Err(InvitationServiceError::InvalidRequest);
        }

        // The issuer is retained for the next lifecycle slice. Keep its generic
        // association live here without minting authority during plain issuance.
        let _ = self.issuer;
        let invitation_id = InvitationId::new();
        let token = InvitationToken::generate(invitation_id);
        let verifier = nodescale_domain::SecretVerifier::from_token(&token)
            .map_err(|_| InvitationServiceError::Unavailable)?;
        let invitation = Invitation::new_n4(
            invitation_id,
            request.network_id,
            request.roles,
            request.admin_intent,
            verifier,
            request.join_constraints,
            now,
            now + INVITATION_LIFETIME,
            1,
        )
        .map_err(|_| InvitationServiceError::InvalidRequest)?;
        let context =
            N4InvitationContext::new(request.provider_instance_id, request.provider_principal_id)
                .map_err(|_| InvitationServiceError::InvalidRequest)?;
        self.store
            .issue_n4_invitation(&invitation, context, now, request.actor)
            .map_err(map_state)?;
        let view = self
            .store
            .n4_invitation_view(invitation_id)
            .map_err(map_state)?;
        Ok(IssuedInvitation { view, token })
    }

    pub fn list(
        &self,
        network_id: NetworkId,
    ) -> Result<Vec<N4InvitationView>, InvitationServiceError> {
        self.store
            .list_n4_invitations(network_id)
            .map_err(map_state)
    }

    pub fn show(
        &self,
        invitation_id: InvitationId,
    ) -> Result<N4InvitationView, InvitationServiceError> {
        self.store
            .n4_invitation_view(invitation_id)
            .map_err(map_state)
    }

    pub async fn redeem(
        &self,
        request: RedeemInvitationRequest,
        now: DateTime<Utc>,
    ) -> Result<ProviderCredentialDelivery, InvitationServiceError> {
        let invitation_id = request.token.invitation_id();
        let candidate = self
            .store
            .n4_invitation_candidate(invitation_id)
            .map_err(map_state)?;
        if !candidate.verify(&request.token).map_err(map_state)? {
            return Err(InvitationServiceError::Conflict);
        }
        let view = self.show(invitation_id)?;
        let tags = closed_tags(&view.roles)?;
        let join_session_id = JoinSessionId::new();
        let reservation = self
            .store
            .reserve_n4_redemption(
                invitation_id,
                candidate.revision,
                join_session_id,
                now,
                request.presented,
                request.actor.clone(),
            )
            .map_err(map_state)?;
        let (dispatch, authorization) = self
            .issuer
            .begin_create(self.store, join_session_id, now, request.actor.clone())
            .map_err(map_state)?;
        if dispatch.invitation_id != reservation.invitation_id
            || dispatch.network_id != reservation.network_id
            || dispatch.context != reservation.context
        {
            self.record_dispatch_failure(
                join_session_id,
                N4DispatchFailure::Ambiguous,
                now,
                request.actor,
            )?;
            return Err(InvitationServiceError::Ambiguous);
        }

        let outcome = self
            .provider
            .execute_mutation(
                authorization,
                ProviderMutation::CreateJoinCredential {
                    request: JoinCredentialRequest {
                        principal: reservation.context.provider_principal_id.clone(),
                        reusable: false,
                        max_uses: 1,
                        expires_at: Some(reservation.expires_at),
                        tags: tags.clone(),
                    },
                },
            )
            .await;
        match outcome {
            MutationOutcome::Confirmed {
                evidence: MutationEvidence::JoinCredentialIssued(issued),
            } if issued.max_uses == 1
                && issued.expires_at > now
                && issued.expires_at <= reservation.expires_at =>
            {
                let credential_id = ProviderCredentialId::new();
                let provider_reference = issued.provider_reference.clone();
                let receipt = RedemptionReceipt {
                    invitation_id,
                    join_session_id,
                    credential_id,
                    expires_at: issued.expires_at,
                    max_uses: issued.max_uses,
                };
                let confirmed = self.store.confirm_n4_credential(
                    join_session_id,
                    N4CredentialConfirmation {
                        credential_id,
                        provider_reference: provider_reference.clone(),
                        provider_principal_id: reservation.context.provider_principal_id,
                        ephemeral: false,
                        approved_tags: tags.into_iter().collect(),
                        expires_at: issued.expires_at,
                        confirmed_at: now,
                        safe_correlation: SanitizedMetadata::empty(),
                    },
                    request.actor.clone(),
                );
                if confirmed.is_err() {
                    let containment_target = N4CleanupTarget {
                        invitation_id,
                        join_session_id: Some(join_session_id),
                        credential_id: Some(credential_id),
                        provider_reference: Some(provider_reference.clone()),
                        network_id: reservation.network_id,
                        provider_instance_id: reservation.context.provider_instance_id,
                        intent: N4CleanupIntent::Revoked,
                        cleanup_uncertain: true,
                    };
                    if let Ok(authorization) =
                        self.issuer
                            .issue_invalidation(self.store, &containment_target, now)
                    {
                        let _ = self
                            .provider
                            .execute_mutation(
                                authorization,
                                ProviderMutation::RevokeJoinCredential {
                                    credential: provider_reference,
                                },
                            )
                            .await;
                    }
                    let _ = self.record_dispatch_failure(
                        join_session_id,
                        N4DispatchFailure::Ambiguous,
                        now,
                        request.actor,
                    );
                    return Err(InvitationServiceError::Ambiguous);
                }
                Ok(ProviderCredentialDelivery {
                    receipt,
                    secret: issued.secret,
                })
            }
            MutationOutcome::Unavailable => {
                self.record_dispatch_failure(
                    join_session_id,
                    N4DispatchFailure::DefiniteNoApply,
                    now,
                    request.actor,
                )?;
                Err(InvitationServiceError::ProviderUnavailable)
            }
            MutationOutcome::Rejected
            | MutationOutcome::Conflict
            | MutationOutcome::Unsupported => {
                self.record_dispatch_failure(
                    join_session_id,
                    N4DispatchFailure::DefiniteNoApply,
                    now,
                    request.actor,
                )?;
                Err(InvitationServiceError::ProviderRejected)
            }
            MutationOutcome::AuthenticationFailed => {
                self.record_dispatch_failure(
                    join_session_id,
                    N4DispatchFailure::DefiniteNoApply,
                    now,
                    request.actor,
                )?;
                Err(InvitationServiceError::AuthenticationFailed)
            }
            MutationOutcome::CompatibilityBlocked => {
                self.record_dispatch_failure(
                    join_session_id,
                    N4DispatchFailure::DefiniteNoApply,
                    now,
                    request.actor,
                )?;
                Err(InvitationServiceError::CompatibilityBlocked)
            }
            MutationOutcome::Ambiguous { .. }
            | MutationOutcome::AlreadySatisfied { .. }
            | MutationOutcome::Failed { .. }
            | MutationOutcome::Confirmed { .. } => {
                self.record_dispatch_failure(
                    join_session_id,
                    N4DispatchFailure::Ambiguous,
                    now,
                    request.actor,
                )?;
                Err(InvitationServiceError::Ambiguous)
            }
        }
    }

    pub async fn revoke(
        &self,
        invitation_id: InvitationId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N4InvitationView, InvitationServiceError> {
        let target = self
            .store
            .prepare_n4_revocation(invitation_id, now, actor.clone())
            .map_err(map_state)?;
        self.complete_cleanup(target, now, actor).await
    }

    pub async fn expire(
        &self,
        invitation_id: InvitationId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N4InvitationView, InvitationServiceError> {
        let current = self.show(invitation_id)?;
        if now < current.expires_at {
            return Err(InvitationServiceError::Conflict);
        }
        let target = self
            .store
            .prepare_n4_expiry(invitation_id, now, actor.clone())
            .map_err(map_state)?;
        self.complete_cleanup(target, now, actor).await
    }

    pub async fn expire_due(
        &self,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<ExpiryReconciliationReport, InvitationServiceError> {
        let invitation_ids = self
            .store
            .expired_n4_invitation_ids(now)
            .map_err(map_state)?;
        let mut report = ExpiryReconciliationReport::default();
        for invitation_id in invitation_ids {
            match self.expire(invitation_id, now, actor.clone()).await {
                Ok(view) => report.settled.push(view),
                Err(error) => report.pending.push(ExpiryReconciliationFailure {
                    invitation_id,
                    error,
                }),
            }
        }
        Ok(report)
    }

    async fn complete_cleanup(
        &self,
        target: N4CleanupTarget,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<N4InvitationView, InvitationServiceError> {
        let invitation_id = target.invitation_id;
        let Some(provider_reference) = target.provider_reference.clone() else {
            return if target.cleanup_uncertain {
                Err(InvitationServiceError::Ambiguous)
            } else {
                self.show(invitation_id)
            };
        };
        let authorization = match self.issuer.issue_invalidation(self.store, &target, now) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.store
                    .settle_n4_credential_invalidation(
                        target,
                        N4InvalidationOutcome::Blocked,
                        now,
                        actor,
                    )
                    .map_err(map_state)?;
                return Err(map_state(error));
            }
        };
        let outcome = self
            .provider
            .execute_mutation(
                authorization,
                ProviderMutation::RevokeJoinCredential {
                    credential: provider_reference.clone(),
                },
            )
            .await;
        let (settlement, service_error) = match outcome {
            MutationOutcome::Confirmed {
                evidence: MutationEvidence::CredentialRevoked { credential },
            } if credential == provider_reference => (N4InvalidationOutcome::Confirmed, None),
            MutationOutcome::AlreadySatisfied {
                evidence: MutationEvidence::CredentialRevoked { credential },
            } if credential == provider_reference => {
                (N4InvalidationOutcome::AlreadySatisfied, None)
            }
            MutationOutcome::Unavailable | MutationOutcome::Failed { retryable: true } => (
                N4InvalidationOutcome::Retryable,
                Some(InvitationServiceError::ProviderUnavailable),
            ),
            MutationOutcome::Ambiguous { .. } => (
                N4InvalidationOutcome::Ambiguous,
                Some(InvitationServiceError::Ambiguous),
            ),
            MutationOutcome::AuthenticationFailed => (
                N4InvalidationOutcome::AuthenticationFailed,
                Some(InvitationServiceError::AuthenticationFailed),
            ),
            MutationOutcome::CompatibilityBlocked => (
                N4InvalidationOutcome::CompatibilityBlocked,
                Some(InvitationServiceError::CompatibilityBlocked),
            ),
            MutationOutcome::Rejected
            | MutationOutcome::Conflict
            | MutationOutcome::Unsupported
            | MutationOutcome::Failed { retryable: false }
            | MutationOutcome::Confirmed { .. }
            | MutationOutcome::AlreadySatisfied { .. } => (
                N4InvalidationOutcome::Blocked,
                Some(InvitationServiceError::ProviderRejected),
            ),
        };
        self.store
            .settle_n4_credential_invalidation(target, settlement, now, actor)
            .map_err(map_state)?;
        match service_error {
            Some(error) => Err(error),
            None => self.show(invitation_id),
        }
    }

    fn record_dispatch_failure(
        &self,
        join_session_id: JoinSessionId,
        failure: N4DispatchFailure,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(), InvitationServiceError> {
        self.store
            .fail_n4_credential_dispatch(join_session_id, failure, now, actor)
            .map_err(map_state)
    }
}

/// Maps a closed set of typed domain roles to the only provider tags N4 may use.
/// The absence of a string parameter prevents arbitrary caller-supplied tags.
fn closed_tags(roles: &Roles) -> Result<BTreeSet<String>, InvitationServiceError> {
    let tags = roles
        .iter()
        .map(|role| match role {
            Role::Node => "tag:nodescale-node",
            Role::Worker => "tag:nodescale-worker",
            Role::Controller => "tag:nodescale-controller",
            Role::ProfileHost => "tag:nodescale-profile-host",
            Role::Observer => "tag:nodescale-observer",
            Role::Admin => "tag:nodescale-admin",
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if tags.len() > MAX_N4_ROLES {
        return Err(InvitationServiceError::InvalidRequest);
    }
    Ok(tags)
}

fn map_state(error: StateError) -> InvitationServiceError {
    match error {
        StateError::NotFound(_) => InvitationServiceError::NotFound,
        StateError::Conflict(_)
        | StateError::StaleGeneration { .. }
        | StateError::MutationAuthorizationDenied(_) => InvitationServiceError::Conflict,
        StateError::Sqlite(_)
        | StateError::Serialization(_)
        | StateError::UnsafeAuditMetadata(_)
        | StateError::InjectedFailure
        | StateError::ActivationGated
        | StateError::UnsupportedSchema { .. } => InvitationServiceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_tags_are_exact_and_bounded() {
        let tags = closed_tags(&Roles::new([Role::Node, Role::Admin]).unwrap()).unwrap();
        assert_eq!(
            tags,
            [
                "tag:nodescale-admin".to_owned(),
                "tag:nodescale-node".to_owned()
            ]
            .into_iter()
            .collect()
        );
        let roles = Roles::new([
            Role::Node,
            Role::Worker,
            Role::Controller,
            Role::ProfileHost,
            Role::Observer,
        ])
        .unwrap();
        assert_eq!(
            closed_tags(&roles),
            Err(InvitationServiceError::InvalidRequest)
        );
    }
}
