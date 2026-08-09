//! Authenticated, typed bridge from Keryx direct-control frames to Nodescale.
//!
//! This crate deliberately owns no StateStore or application-service dependency.
//! An application composition root supplies the narrow [`NodescaleIdentityControlPlane`]
//! seam only after it has installed its durable state-backed implementation.

#[cfg(test)]
mod tests;

use std::{fmt, str::FromStr, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use keryx_proto::v1::{
    NodescaleIdentityBindDisposition, NodescaleIdentityBindResult, NodescaleIdentityBindV1,
    NodescaleIdentityChallengeDisposition, NodescaleIdentityChallengeResult,
    NodescaleIdentityChallengeV1,
};
use keryx_relay::{
    AuthenticatedDirectContext, DirectControlHandlers, NodescaleIdentityBindHandler,
    NodescaleIdentityChallengeHandler,
};
use nodescale_domain::{
    AgentVersion, BindingNonce, DeviceId, Generation, JoinSessionId, KeryxBindingId, KeryxPeerId,
    N6AuthenticatedBindRequest, N6BindingChallengeDelivery, NetworkId, OperationId,
};

const INVALID_REQUEST_REASON: &str = "invalid request";
const REJECTED_REASON: &str = "request rejected";
const CONTROL_PLANE_ERROR_REASON: &str = "request could not be completed";

/// The only externally visible, fixed rejection codes the adapter emits.
///
/// Keryx results have string `code` fields, so this closed enum prevents caller
/// input or control-plane error text from becoming a response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionCode {
    Duplicate,
    Rejected,
}

impl RejectionCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
        }
    }
}

/// Opaque control-plane failure. Its display text is fixed so failures cannot
/// leak database errors, secret material, or raw transport input to Keryx.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneError(());

impl ControlPlaneError {
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

impl fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(CONTROL_PLANE_ERROR_REASON)
    }
}

impl std::error::Error for ControlPlaneError {}

/// Construction can fail before handler installation when a composition root
/// has not supplied a usable control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterConstructionError(());

impl AdapterConstructionError {
    #[must_use]
    pub const fn invalid_configuration() -> Self {
        Self(())
    }
}

impl fmt::Display for AdapterConstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid control-plane configuration")
    }
}

impl std::error::Error for AdapterConstructionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProvenance {
    authenticated_peer_id: KeryxPeerId,
    destination_node_id: BoundedTransportId,
    relay_frame_id: BoundedTransportId,
}

impl AuthenticatedProvenance {
    fn parse(source: &str, destination: &str, frame: &str) -> Result<Self, InputError> {
        Ok(Self {
            authenticated_peer_id: KeryxPeerId::parse(source).map_err(|_| InputError)?,
            destination_node_id: BoundedTransportId::parse(destination)?,
            relay_frame_id: BoundedTransportId::parse(frame)?,
        })
    }

    #[must_use]
    pub fn authenticated_peer_id(&self) -> &KeryxPeerId {
        &self.authenticated_peer_id
    }

    #[must_use]
    pub fn destination_node_id(&self) -> &str {
        self.destination_node_id.as_str()
    }

    #[must_use]
    pub fn relay_frame_id(&self) -> &str {
        self.relay_frame_id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundedTransportId(String);

impl BoundedTransportId {
    fn parse(value: &str) -> Result<Self, InputError> {
        let is_safe = !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            });
        if is_safe {
            Ok(Self(value.to_owned()))
        } else {
            Err(InputError)
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parsed challenge issuance request. The authenticated peer is exclusively
/// transport provenance, never a field accepted from the protobuf message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeRequest {
    provenance: AuthenticatedProvenance,
    operation_id: OperationId,
    network_id: NetworkId,
    device_id: DeviceId,
    join_session_id: JoinSessionId,
    agent_version: AgentVersion,
}

impl ChallengeRequest {
    #[must_use]
    pub fn provenance(&self) -> &AuthenticatedProvenance {
        &self.provenance
    }
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    #[must_use]
    pub fn join_session_id(&self) -> JoinSessionId {
        self.join_session_id
    }
    #[must_use]
    pub fn agent_version(&self) -> &AgentVersion {
        &self.agent_version
    }
}

/// Parsed bind confirmation request. `request` owns the nonce and deliberately
/// has redacted debug formatting; the peer remains separate authenticated provenance.
pub struct AuthenticatedBindRequest {
    provenance: AuthenticatedProvenance,
    request: N6AuthenticatedBindRequest,
}

impl AuthenticatedBindRequest {
    #[must_use]
    pub fn provenance(&self) -> &AuthenticatedProvenance {
        &self.provenance
    }
    #[must_use]
    pub fn request(&self) -> &N6AuthenticatedBindRequest {
        &self.request
    }

    #[must_use]
    pub fn into_parts(self) -> (AuthenticatedProvenance, N6AuthenticatedBindRequest) {
        (self.provenance, self.request)
    }
}

impl fmt::Debug for AuthenticatedBindRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedBindRequest")
            .field("provenance", &self.provenance)
            .field("request", &self.request)
            .finish()
    }
}

/// Application-owned outcomes; secrets only exist in the `Issued` delivery value.
pub enum ChallengeOutcome {
    Issued(N6BindingChallengeDelivery),
    Rejected(RejectionCode),
}

impl ChallengeOutcome {
    #[must_use]
    pub fn issued(delivery: N6BindingChallengeDelivery) -> Self {
        Self::Issued(delivery)
    }
    #[must_use]
    pub const fn rejected(code: RejectionCode) -> Self {
        Self::Rejected(code)
    }
}

impl fmt::Debug for ChallengeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issued(_) => f.write_str("ChallengeOutcome::Issued([REDACTED])"),
            Self::Rejected(code) => f
                .debug_tuple("ChallengeOutcome::Rejected")
                .field(code)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindOutcome {
    Active {
        binding_id: KeryxBindingId,
        generation: Generation,
        revision: u64,
    },
    AlreadyConfirmed {
        binding_id: KeryxBindingId,
        generation: Generation,
        revision: u64,
    },
    Rejected(RejectionCode),
}

impl BindOutcome {
    #[must_use]
    pub fn active(binding_id: KeryxBindingId, generation: Generation, revision: u64) -> Self {
        Self::Active {
            binding_id,
            generation,
            revision,
        }
    }
    #[must_use]
    pub fn already_confirmed(
        binding_id: KeryxBindingId,
        generation: Generation,
        revision: u64,
    ) -> Self {
        Self::AlreadyConfirmed {
            binding_id,
            generation,
            revision,
        }
    }
    #[must_use]
    pub const fn rejected(code: RejectionCode) -> Self {
        Self::Rejected(code)
    }
}

/// The adapter-local contract an application bridge must implement.
///
/// A production `nodescale-binding` bridge should: validate its durable store
/// and clock in `validate_configuration`; deduplicate challenge issue by
/// `(authenticated_peer_id, operation_id)`; return `Rejected(Duplicate)` with
/// no delivery for replays; create an `N6BindingChallengeDelivery` only for a
/// newly issued nonce; and bind using the provenance peer plus the owned
/// `N6AuthenticatedBindRequest` in one durable transaction.
#[async_trait]
pub trait NodescaleIdentityControlPlane: Send + Sync + 'static {
    fn validate_configuration(&self) -> Result<(), AdapterConstructionError> {
        Ok(())
    }

    async fn issue_challenge(
        &self,
        request: ChallengeRequest,
    ) -> Result<ChallengeOutcome, ControlPlaneError>;

    async fn bind_authenticated_peer(
        &self,
        request: AuthenticatedBindRequest,
    ) -> Result<BindOutcome, ControlPlaneError>;
}

/// A successfully constructed adapter. It installs Keryx handlers only after
/// the control plane accepts its configuration.
pub struct TryNodescaleKeryxAdapter<C> {
    control_plane: Arc<C>,
}

impl<C> Clone for TryNodescaleKeryxAdapter<C> {
    fn clone(&self) -> Self {
        Self {
            control_plane: Arc::clone(&self.control_plane),
        }
    }
}

impl<C: NodescaleIdentityControlPlane> TryNodescaleKeryxAdapter<C> {
    pub fn new(control_plane: Arc<C>) -> Result<Self, AdapterConstructionError> {
        control_plane.validate_configuration()?;
        Ok(Self { control_plane })
    }

    #[must_use]
    pub fn direct_control_handlers(&self) -> DirectControlHandlers {
        let handler: Arc<Self> = Arc::new(self.clone());
        DirectControlHandlers {
            nodescale_identity_bind_v1: Some(handler.clone()),
            nodescale_identity_challenge_v1: Some(handler),
        }
    }

    async fn handle_challenge(
        &self,
        context: &AuthenticatedDirectContext,
        operation: NodescaleIdentityChallengeV1,
    ) -> NodescaleIdentityChallengeResult {
        let request = match parse_challenge_request(context, operation) {
            Ok(request) => request,
            Err(_) => return rejected_challenge("invalid_request", INVALID_REQUEST_REASON),
        };
        match self.control_plane.issue_challenge(request).await {
            Ok(ChallengeOutcome::Issued(delivery)) => issued_challenge(delivery),
            Ok(ChallengeOutcome::Rejected(code)) => {
                rejected_challenge(code.as_str(), REJECTED_REASON)
            }
            Err(_) => rejected_challenge("control_plane_error", CONTROL_PLANE_ERROR_REASON),
        }
    }

    async fn handle_bind(
        &self,
        context: &AuthenticatedDirectContext,
        operation: NodescaleIdentityBindV1,
    ) -> NodescaleIdentityBindResult {
        let request = match parse_bind_request(context, operation) {
            Ok(request) => request,
            Err(_) => return rejected_bind("invalid_request", INVALID_REQUEST_REASON),
        };
        match self.control_plane.bind_authenticated_peer(request).await {
            Ok(BindOutcome::Active {
                binding_id,
                generation,
                revision,
            }) => active_bind(binding_id, generation, revision),
            Ok(BindOutcome::AlreadyConfirmed {
                binding_id,
                generation,
                revision,
            }) => already_confirmed_bind(binding_id, generation, revision),
            Ok(BindOutcome::Rejected(code)) => rejected_bind(code.as_str(), REJECTED_REASON),
            Err(_) => rejected_bind("control_plane_error", CONTROL_PLANE_ERROR_REASON),
        }
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub async fn handle_challenge_for_test(
        &self,
        context: RawAuthenticatedDirectContext,
        operation: NodescaleIdentityChallengeV1,
    ) -> NodescaleIdentityChallengeResult {
        let request = match parse_challenge_request_fields(
            &context.source,
            &context.destination,
            &context.frame,
            operation,
        ) {
            Ok(request) => request,
            Err(_) => return rejected_challenge("invalid_request", INVALID_REQUEST_REASON),
        };
        match self.control_plane.issue_challenge(request).await {
            Ok(ChallengeOutcome::Issued(delivery)) => issued_challenge(delivery),
            Ok(ChallengeOutcome::Rejected(code)) => {
                rejected_challenge(code.as_str(), REJECTED_REASON)
            }
            Err(_) => rejected_challenge("control_plane_error", CONTROL_PLANE_ERROR_REASON),
        }
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub async fn handle_bind_for_test(
        &self,
        context: RawAuthenticatedDirectContext,
        operation: NodescaleIdentityBindV1,
    ) -> NodescaleIdentityBindResult {
        let request = match parse_bind_request_fields(
            &context.source,
            &context.destination,
            &context.frame,
            operation,
        ) {
            Ok(request) => request,
            Err(_) => return rejected_bind("invalid_request", INVALID_REQUEST_REASON),
        };
        match self.control_plane.bind_authenticated_peer(request).await {
            Ok(BindOutcome::Active {
                binding_id,
                generation,
                revision,
            }) => active_bind(binding_id, generation, revision),
            Ok(BindOutcome::AlreadyConfirmed {
                binding_id,
                generation,
                revision,
            }) => already_confirmed_bind(binding_id, generation, revision),
            Ok(BindOutcome::Rejected(code)) => rejected_bind(code.as_str(), REJECTED_REASON),
            Err(_) => rejected_bind("control_plane_error", CONTROL_PLANE_ERROR_REASON),
        }
    }
}

#[tonic::async_trait]
impl<C: NodescaleIdentityControlPlane> NodescaleIdentityChallengeHandler
    for TryNodescaleKeryxAdapter<C>
{
    async fn handle_nodescale_identity_challenge(
        &self,
        context: AuthenticatedDirectContext,
        operation: NodescaleIdentityChallengeV1,
    ) -> anyhow::Result<NodescaleIdentityChallengeResult> {
        Ok(self.handle_challenge(&context, operation).await)
    }
}

#[tonic::async_trait]
impl<C: NodescaleIdentityControlPlane> NodescaleIdentityBindHandler
    for TryNodescaleKeryxAdapter<C>
{
    async fn handle_nodescale_identity_bind(
        &self,
        context: AuthenticatedDirectContext,
        operation: NodescaleIdentityBindV1,
    ) -> anyhow::Result<NodescaleIdentityBindResult> {
        Ok(self.handle_bind(&context, operation).await)
    }
}

fn parse_challenge_request(
    context: &AuthenticatedDirectContext,
    operation: NodescaleIdentityChallengeV1,
) -> Result<ChallengeRequest, InputError> {
    parse_challenge_request_fields(
        context.authenticated_source_node_id(),
        context.destination_node_id(),
        context.relay_frame_id(),
        operation,
    )
}

fn parse_challenge_request_fields(
    source: &str,
    destination: &str,
    frame: &str,
    operation: NodescaleIdentityChallengeV1,
) -> Result<ChallengeRequest, InputError> {
    Ok(ChallengeRequest {
        provenance: AuthenticatedProvenance::parse(source, destination, frame)?,
        operation_id: OperationId::parse(operation.operation_id).map_err(|_| InputError)?,
        network_id: NetworkId::parse(&operation.network_id).map_err(|_| InputError)?,
        device_id: DeviceId::parse(&operation.device_id).map_err(|_| InputError)?,
        join_session_id: JoinSessionId::parse(&operation.join_session_id)
            .map_err(|_| InputError)?,
        agent_version: AgentVersion::parse(operation.agent_version).map_err(|_| InputError)?,
    })
}

fn parse_bind_request(
    context: &AuthenticatedDirectContext,
    operation: NodescaleIdentityBindV1,
) -> Result<AuthenticatedBindRequest, InputError> {
    parse_bind_request_fields(
        context.authenticated_source_node_id(),
        context.destination_node_id(),
        context.relay_frame_id(),
        operation,
    )
}

fn parse_bind_request_fields(
    source: &str,
    destination: &str,
    frame: &str,
    operation: NodescaleIdentityBindV1,
) -> Result<AuthenticatedBindRequest, InputError> {
    let provenance = AuthenticatedProvenance::parse(source, destination, frame)?;
    let request = N6AuthenticatedBindRequest::new(
        OperationId::parse(operation.operation_id).map_err(|_| InputError)?,
        NetworkId::parse(&operation.network_id).map_err(|_| InputError)?,
        DeviceId::parse(&operation.device_id).map_err(|_| InputError)?,
        JoinSessionId::parse(&operation.join_session_id).map_err(|_| InputError)?,
        BindingNonce::from_str(&operation.binding_nonce).map_err(|_| InputError)?,
        Generation::new(operation.binding_generation).map_err(|_| InputError)?,
        AgentVersion::parse(operation.agent_version).map_err(|_| InputError)?,
    )
    .map_err(|_| InputError)?;
    Ok(AuthenticatedBindRequest {
        provenance,
        request,
    })
}

fn issued_challenge(delivery: N6BindingChallengeDelivery) -> NodescaleIdentityChallengeResult {
    if delivery.validate_at(Utc::now()).is_err() {
        return rejected_challenge("control_plane_error", CONTROL_PLANE_ERROR_REASON);
    }
    let challenge_secret = delivery.with_nonce(|nonce| nonce.with_encoded(str::to_owned));
    NodescaleIdentityChallengeResult {
        disposition: NodescaleIdentityChallengeDisposition::Issued as i32,
        accepted: true,
        challenge_id: delivery.challenge_id().to_string(),
        challenge_secret,
        binding_generation: delivery.generation().get(),
        expires_at_unix_ms: delivery
            .expires_at()
            .timestamp_millis()
            .try_into()
            .unwrap_or(0),
        reason: String::new(),
        code: String::new(),
    }
}

fn rejected_challenge(code: &str, reason: &str) -> NodescaleIdentityChallengeResult {
    NodescaleIdentityChallengeResult {
        disposition: NodescaleIdentityChallengeDisposition::Rejected as i32,
        accepted: false,
        challenge_id: String::new(),
        challenge_secret: String::new(),
        binding_generation: 0,
        expires_at_unix_ms: 0,
        reason: reason.to_owned(),
        code: code.to_owned(),
    }
}

fn active_bind(
    binding_id: KeryxBindingId,
    generation: Generation,
    revision: u64,
) -> NodescaleIdentityBindResult {
    if revision == 0 {
        return rejected_bind("invalid_revision", "binding revision must be positive");
    }
    NodescaleIdentityBindResult {
        disposition: NodescaleIdentityBindDisposition::Active as i32,
        accepted: true,
        binding_id: binding_id.to_string(),
        generation: generation.get(),
        revision,
        reason: String::new(),
        code: String::new(),
    }
}

fn already_confirmed_bind(
    binding_id: KeryxBindingId,
    generation: Generation,
    revision: u64,
) -> NodescaleIdentityBindResult {
    if revision == 0 {
        return rejected_bind("invalid_revision", "binding revision must be positive");
    }
    NodescaleIdentityBindResult {
        disposition: NodescaleIdentityBindDisposition::AlreadyConfirmed as i32,
        accepted: true,
        binding_id: binding_id.to_string(),
        generation: generation.get(),
        revision,
        reason: String::new(),
        code: String::new(),
    }
}

fn rejected_bind(code: &str, reason: &str) -> NodescaleIdentityBindResult {
    NodescaleIdentityBindResult {
        disposition: NodescaleIdentityBindDisposition::Rejected as i32,
        accepted: false,
        binding_id: String::new(),
        generation: 0,
        revision: 0,
        reason: reason.to_owned(),
        code: code.to_owned(),
    }
}

#[derive(Clone, Copy, Debug)]
struct InputError;

#[cfg(test)]
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawAuthenticatedDirectContext {
    source: String,
    destination: String,
    frame: String,
}

#[cfg(test)]
impl RawAuthenticatedDirectContext {
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        destination: impl Into<String>,
        frame: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            frame: frame.into(),
        }
    }
}
