use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AgentVersion, AuditActor, BindingNonce, BindingNonceVerifier, DeviceId, JoinSessionId,
    KeryxBindingAuthorization, KeryxBindingAuthorizationCapability, KeryxBindingId, KeryxPeerId,
    N6AuthenticatedBindRequest, N6BindingChallengeDelivery, N6BindingChallengeRequest,
    N6BindingRevocationIntent, N6BindingRotationIntent, NetworkId, OperationId,
    OwnerTrustRootToken, TrustAuthorityId,
};
use nodescale_keryx_adapter::{
    AuthenticatedBindRequest, BindOutcome, ChallengeOutcome, ChallengeRequest, ControlPlaneError,
    NodescaleIdentityControlPlane, RejectionCode,
};
use nodescale_state::{
    N5ConfiguredHeadscaleProvider, N6AuthenticatedBindOutcome, N6BindingView,
    N6ChallengeCompletion, N6ChallengeReservationOutcome, StateError, StateStore,
};
use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

const MAX_CHALLENGE_TTL_SECONDS: i64 = 600;
const ACTOR_MAILBOX_CAPACITY: usize = 128;

pub trait N6Clock: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemN6Clock;

impl N6Clock for SystemN6Clock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Error)]
pub enum N6ProductionError {
    #[error("N6 request was rejected")]
    Rejected,
    #[error("N6 operation already completed")]
    Duplicate,
    #[error("N6 control plane is unavailable")]
    Internal,
}

pub enum N6ChallengeIssueOutcome {
    Issued(N6BindingChallengeDelivery),
    Duplicate,
}

struct StateN6Runtime {
    store: StateStore,
    provider: N5ConfiguredHeadscaleProvider,
}

enum ActorCommand {
    Issue {
        authenticated_peer: KeryxPeerId,
        operation_id: OperationId,
        network_id: NetworkId,
        device_id: DeviceId,
        join_session_id: JoinSessionId,
        agent_version: AgentVersion,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        reply: oneshot::Sender<Result<N6ChallengeIssueOutcome, N6ProductionError>>,
    },
    Confirm {
        authenticated_peer: KeryxPeerId,
        request: N6AuthenticatedBindRequest,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<N6AuthenticatedBindOutcome, N6ProductionError>>,
    },
    Authorize {
        network_id: NetworkId,
        device_id: DeviceId,
        authenticated_peer: KeryxPeerId,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<N6BindingView, N6ProductionError>>,
    },
    GrantCapability {
        root: OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        capability: KeryxBindingAuthorizationCapability,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<(), N6ProductionError>>,
    },
    IssueAuthorization {
        root: OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        binding_id: KeryxBindingId,
        capability: KeryxBindingAuthorizationCapability,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<KeryxBindingAuthorization, N6ProductionError>>,
    },
    Rotate {
        intent: N6BindingRotationIntent,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<N6BindingView, N6ProductionError>>,
    },
    Revoke {
        intent: N6BindingRevocationIntent,
        now: DateTime<Utc>,
        reply: oneshot::Sender<Result<N6BindingView, N6ProductionError>>,
    },
}

struct ActorClient {
    sender: Option<mpsc::Sender<ActorCommand>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for ActorClient {
    fn drop(&mut self) {
        self.sender.take();
        if let Ok(thread) = self.thread.get_mut()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

/// Production N6 service. A dedicated current-thread actor owns StateStore's
/// intentionally non-Sync SQLite connection and performs provider I/O without
/// exposing a forgeable or cross-thread state reference.
pub struct N6BindingService<C = SystemN6Clock> {
    actor: Arc<ActorClient>,
    clock: Arc<C>,
    challenge_ttl: Duration,
}

impl N6BindingService<SystemN6Clock> {
    pub fn new(
        store: StateStore,
        provider: N5ConfiguredHeadscaleProvider,
        challenge_ttl: Duration,
    ) -> Result<Self, N6ProductionError> {
        Self::with_clock(store, provider, challenge_ttl, Arc::new(SystemN6Clock))
    }
}

impl<C: N6Clock> N6BindingService<C> {
    pub fn with_clock(
        store: StateStore,
        provider: N5ConfiguredHeadscaleProvider,
        challenge_ttl: Duration,
        clock: Arc<C>,
    ) -> Result<Self, N6ProductionError> {
        if challenge_ttl <= Duration::zero()
            || challenge_ttl > Duration::seconds(MAX_CHALLENGE_TTL_SECONDS)
        {
            return Err(N6ProductionError::Rejected);
        }
        let (sender, mut receiver) = mpsc::channel(ACTOR_MAILBOX_CAPACITY);
        let thread = std::thread::Builder::new()
            .name("nodescale-n6-binding".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let runtime = StateN6Runtime { store, provider };
                    while let Some(command) = receiver.recv().await {
                        match command {
                            ActorCommand::Issue {
                                authenticated_peer,
                                operation_id,
                                network_id,
                                device_id,
                                join_session_id,
                                agent_version,
                                now,
                                expires_at,
                                reply,
                            } => {
                                let result = issue_on_actor(
                                    &runtime,
                                    authenticated_peer,
                                    operation_id,
                                    network_id,
                                    device_id,
                                    join_session_id,
                                    agent_version,
                                    now,
                                    expires_at,
                                )
                                .await;
                                let _ = reply.send(result);
                            }
                            ActorCommand::Confirm {
                                authenticated_peer,
                                request,
                                now,
                                reply,
                            } => {
                                let result =
                                    confirm_on_actor(&runtime, authenticated_peer, request, now)
                                        .await;
                                let _ = reply.send(result);
                            }
                            ActorCommand::Authorize {
                                network_id,
                                device_id,
                                authenticated_peer,
                                now,
                                reply,
                            } => {
                                let result = authorize_on_actor(
                                    &runtime,
                                    network_id,
                                    device_id,
                                    authenticated_peer,
                                    now,
                                )
                                .await;
                                let _ = reply.send(result);
                            }
                            ActorCommand::GrantCapability {
                                root,
                                authority_id,
                                capability,
                                now,
                                reply,
                            } => {
                                let result = runtime
                                    .store
                                    .grant_n6_binding_capability(
                                        &root,
                                        authority_id,
                                        capability,
                                        now,
                                    )
                                    .map_err(classify_state_error);
                                let _ = reply.send(result);
                            }
                            ActorCommand::IssueAuthorization {
                                root,
                                authority_id,
                                binding_id,
                                capability,
                                expires_at,
                                now,
                                reply,
                            } => {
                                let result = runtime
                                    .store
                                    .issue_n6_binding_authorization(
                                        &root,
                                        authority_id,
                                        binding_id,
                                        capability,
                                        expires_at,
                                        now,
                                    )
                                    .map_err(classify_state_error);
                                let _ = reply.send(result);
                            }
                            ActorCommand::Rotate { intent, now, reply } => {
                                let result = rotate_on_actor(&runtime, &intent, now).await;
                                let _ = reply.send(result);
                            }
                            ActorCommand::Revoke { intent, now, reply } => {
                                let result = runtime
                                    .store
                                    .revoke_n6_binding(&intent, now)
                                    .map_err(classify_state_error);
                                let _ = reply.send(result);
                            }
                        }
                    }
                });
            })
            .map_err(|_| N6ProductionError::Internal)?;
        Ok(Self {
            actor: Arc::new(ActorClient {
                sender: Some(sender),
                thread: Mutex::new(Some(thread)),
            }),
            clock,
            challenge_ttl,
        })
    }

    pub async fn issue_challenge(
        &self,
        authenticated_peer: KeryxPeerId,
        operation_id: OperationId,
        network_id: NetworkId,
        device_id: DeviceId,
        join_session_id: JoinSessionId,
        agent_version: AgentVersion,
    ) -> Result<N6ChallengeIssueOutcome, N6ProductionError> {
        let now = self.clock.now();
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::Issue {
                authenticated_peer,
                operation_id,
                network_id,
                device_id,
                join_session_id,
                agent_version,
                now,
                expires_at: now + self.challenge_ttl,
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn confirm_binding(
        &self,
        authenticated_peer: KeryxPeerId,
        request: N6AuthenticatedBindRequest,
    ) -> Result<N6AuthenticatedBindOutcome, N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::Confirm {
                authenticated_peer,
                request,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn authorize_peer(
        &self,
        network_id: NetworkId,
        device_id: DeviceId,
        authenticated_peer: KeryxPeerId,
    ) -> Result<N6BindingView, N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::Authorize {
                network_id,
                device_id,
                authenticated_peer,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn grant_binding_capability(
        &self,
        root: OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        capability: KeryxBindingAuthorizationCapability,
    ) -> Result<(), N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::GrantCapability {
                root,
                authority_id,
                capability,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn issue_binding_authorization(
        &self,
        root: OwnerTrustRootToken,
        authority_id: TrustAuthorityId,
        binding_id: KeryxBindingId,
        capability: KeryxBindingAuthorizationCapability,
        expires_at: DateTime<Utc>,
    ) -> Result<KeryxBindingAuthorization, N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::IssueAuthorization {
                root,
                authority_id,
                binding_id,
                capability,
                expires_at,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn rotate_binding(
        &self,
        intent: N6BindingRotationIntent,
    ) -> Result<N6BindingView, N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::Rotate {
                intent,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }

    pub async fn revoke_binding(
        &self,
        intent: N6BindingRevocationIntent,
    ) -> Result<N6BindingView, N6ProductionError> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .as_ref()
            .ok_or(N6ProductionError::Internal)?
            .send(ActorCommand::Revoke {
                intent,
                now: self.clock.now(),
                reply,
            })
            .await
            .map_err(|_| N6ProductionError::Internal)?;
        response.await.map_err(|_| N6ProductionError::Internal)?
    }
}

#[allow(clippy::too_many_arguments)]
async fn issue_on_actor(
    runtime: &StateN6Runtime,
    authenticated_peer: KeryxPeerId,
    operation_id: OperationId,
    network_id: NetworkId,
    device_id: DeviceId,
    join_session_id: JoinSessionId,
    agent_version: AgentVersion,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<N6ChallengeIssueOutcome, N6ProductionError> {
    let fresh = runtime
        .store
        .reconcile_n5_provider_binding(&runtime.provider, device_id, now, AuditActor::system())
        .await
        .map_err(classify_state_error)?;
    if !fresh.currently_trusted || fresh.network_id != network_id {
        return Err(N6ProductionError::Rejected);
    }
    let generation = runtime
        .store
        .n6_challenge_generation(network_id, device_id)
        .map_err(classify_state_error)?;
    let request = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        join_session_id,
        authenticated_peer,
        generation,
        expires_at,
        now,
        agent_version,
    )
    .map_err(|_| N6ProductionError::Rejected)?;
    let reservation = match runtime
        .store
        .reserve_n6_binding_challenge(&operation_id, &request, now)
        .map_err(classify_state_error)?
    {
        N6ChallengeReservationOutcome::Acquired(value)
        | N6ChallengeReservationOutcome::Resumable(value) => value,
        N6ChallengeReservationOutcome::AlreadyIssued => {
            return Ok(N6ChallengeIssueOutcome::Duplicate);
        }
        N6ChallengeReservationOutcome::Conflict => {
            return Err(N6ProductionError::Rejected);
        }
    };
    let nonce = BindingNonce::generate();
    let verifier =
        BindingNonceVerifier::from_nonce(&nonce).map_err(|_| N6ProductionError::Internal)?;
    let completion = runtime
        .store
        .complete_n6_binding_challenge(&reservation, verifier, now)
        .map_err(classify_state_error)?;
    let N6ChallengeCompletion::Recorded {
        challenge_id,
        binding_id,
        generation,
        expires_at,
        issued_at,
    } = completion
    else {
        return Ok(N6ChallengeIssueOutcome::Duplicate);
    };
    let delivery = N6BindingChallengeDelivery::new(
        challenge_id,
        binding_id,
        generation,
        nonce,
        expires_at,
        issued_at,
    )
    .map_err(|_| N6ProductionError::Internal)?;
    Ok(N6ChallengeIssueOutcome::Issued(delivery))
}

async fn confirm_on_actor(
    runtime: &StateN6Runtime,
    authenticated_peer: KeryxPeerId,
    request: N6AuthenticatedBindRequest,
    now: DateTime<Utc>,
) -> Result<N6AuthenticatedBindOutcome, N6ProductionError> {
    let fresh = runtime
        .store
        .reconcile_n5_provider_binding(
            &runtime.provider,
            request.device_id(),
            now,
            AuditActor::system(),
        )
        .await
        .map_err(classify_state_error)?;
    if !fresh.currently_trusted || fresh.network_id != request.network_id() {
        return Err(N6ProductionError::Rejected);
    }
    runtime
        .store
        .confirm_n6_authenticated_binding(authenticated_peer, request, now)
        .map_err(classify_state_error)
}

async fn rotate_on_actor(
    runtime: &StateN6Runtime,
    intent: &N6BindingRotationIntent,
    now: DateTime<Utc>,
) -> Result<N6BindingView, N6ProductionError> {
    let predecessor = runtime
        .store
        .n6_binding(intent.predecessor_binding_id())
        .map_err(classify_state_error)?;
    let fresh = runtime
        .store
        .reconcile_n5_provider_binding(
            &runtime.provider,
            predecessor.device_id,
            now,
            AuditActor::system(),
        )
        .await
        .map_err(classify_state_error)?;
    if !fresh.currently_trusted || fresh.network_id != predecessor.network_id {
        return Err(N6ProductionError::Rejected);
    }
    runtime
        .store
        .rotate_n6_binding(intent, now)
        .map_err(classify_state_error)
}

async fn authorize_on_actor(
    runtime: &StateN6Runtime,
    network_id: NetworkId,
    device_id: DeviceId,
    authenticated_peer: KeryxPeerId,
    now: DateTime<Utc>,
) -> Result<N6BindingView, N6ProductionError> {
    let fresh = runtime
        .store
        .reconcile_n5_provider_binding(&runtime.provider, device_id, now, AuditActor::system())
        .await
        .map_err(classify_state_error)?;
    if !fresh.currently_trusted || fresh.network_id != network_id {
        return Err(N6ProductionError::Rejected);
    }
    let binding = runtime
        .store
        .n6_active_binding(network_id, &authenticated_peer)
        .map_err(classify_state_error)?;
    if binding.device_id != device_id {
        return Err(N6ProductionError::Rejected);
    }
    Ok(binding)
}

#[async_trait]
impl<C: N6Clock> NodescaleIdentityControlPlane for N6BindingService<C> {
    async fn issue_challenge(
        &self,
        request: ChallengeRequest,
    ) -> Result<ChallengeOutcome, ControlPlaneError> {
        match self
            .issue_challenge(
                request.provenance().authenticated_peer_id().clone(),
                request.operation_id().clone(),
                request.network_id(),
                request.device_id(),
                request.join_session_id(),
                request.agent_version().clone(),
            )
            .await
        {
            Ok(N6ChallengeIssueOutcome::Issued(delivery)) => Ok(ChallengeOutcome::issued(delivery)),
            Ok(N6ChallengeIssueOutcome::Duplicate) | Err(N6ProductionError::Duplicate) => {
                Ok(ChallengeOutcome::rejected(RejectionCode::Duplicate))
            }
            Err(N6ProductionError::Rejected) => {
                Ok(ChallengeOutcome::rejected(RejectionCode::Rejected))
            }
            Err(N6ProductionError::Internal) => Err(ControlPlaneError::new()),
        }
    }

    async fn bind_authenticated_peer(
        &self,
        request: AuthenticatedBindRequest,
    ) -> Result<BindOutcome, ControlPlaneError> {
        let (provenance, request) = request.into_parts();
        match self
            .confirm_binding(provenance.authenticated_peer_id().clone(), request)
            .await
        {
            Ok(N6AuthenticatedBindOutcome::Confirmed(view)) => Ok(BindOutcome::active(
                view.binding_id,
                view.generation,
                view.revision,
            )),
            Ok(N6AuthenticatedBindOutcome::Replayed(view)) => Ok(BindOutcome::already_confirmed(
                view.binding_id,
                view.generation,
                view.revision,
            )),
            Ok(N6AuthenticatedBindOutcome::Conflict) | Err(N6ProductionError::Rejected) => {
                Ok(BindOutcome::rejected(RejectionCode::Rejected))
            }
            Err(N6ProductionError::Duplicate) => {
                Ok(BindOutcome::rejected(RejectionCode::Duplicate))
            }
            Err(N6ProductionError::Internal) => Err(ControlPlaneError::new()),
        }
    }
}

fn classify_state_error(error: StateError) -> N6ProductionError {
    match error {
        StateError::Conflict(_)
        | StateError::StaleGeneration { .. }
        | StateError::NotFound(_)
        | StateError::MutationAuthorizationDenied(_) => N6ProductionError::Rejected,
        StateError::Sqlite(_)
        | StateError::Serialization(_)
        | StateError::UnsupportedSchema { .. }
        | StateError::UnsafeAuditMetadata(_)
        | StateError::InjectedFailure
        | StateError::ActivationGated => N6ProductionError::Internal,
    }
}
