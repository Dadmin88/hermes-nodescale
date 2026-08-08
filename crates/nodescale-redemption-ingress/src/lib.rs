#![forbid(unsafe_code)]

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::post,
};
use chrono::Utc;
use nodescale_domain::{AuditActor, InvitationId, InvitationToken, JoinSessionId, SecretVerifier};
use nodescale_invitation::{
    InvitationService, InvitationServiceError, N4AuthorizationIssuer, ProviderCredentialDelivery,
    RedeemInvitationRequest, RedemptionReceipt,
};
use nodescale_provider::{MutationProvider, ProviderMutationCapability};
use nodescale_state::{
    MutationAuthorization, N4CleanupTarget, N4CredentialDispatch, N4PresentedMetadata,
    SanitizedMetadata, StateError, StateStore,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc as std_mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_REQUEST_BODY_BYTES: usize = 256;
const DEFAULT_SOURCE_BURST: u32 = 4;
const DEFAULT_GLOBAL_BURST: u32 = 16;
const DEFAULT_MAXIMUM_TRACKED_SOURCES: usize = 1_024;
const DEFAULT_WORKER_QUEUE_CAPACITY: usize = 2;
const DEFAULT_ARGON_CONCURRENCY: usize = 1;
const DEFAULT_PROVIDER_CREATE_CONCURRENCY: usize = 1;
const DEFAULT_SOURCE_REFILL: Duration = Duration::from_secs(30);
const DEFAULT_GLOBAL_REFILL: Duration = Duration::from_secs(1);
const MAX_ROOT_CA_PEM_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    request_body_bytes: NonZeroUsize,
    source_burst: NonZeroU32,
    global_burst: NonZeroU32,
    source_refill_interval: Duration,
    global_refill_interval: Duration,
    maximum_tracked_sources: NonZeroUsize,
    worker_queue_capacity: NonZeroUsize,
    source_initial_tokens: NonZeroU32,
    global_initial_tokens: NonZeroU32,
    argon_concurrency: NonZeroUsize,
    provider_create_concurrency: NonZeroUsize,
}

impl AdmissionLimits {
    #[must_use]
    pub fn safe_defaults() -> Self {
        Self::bounded(
            DEFAULT_REQUEST_BODY_BYTES,
            DEFAULT_SOURCE_BURST,
            DEFAULT_SOURCE_REFILL,
            DEFAULT_GLOBAL_BURST,
            DEFAULT_GLOBAL_REFILL,
            DEFAULT_MAXIMUM_TRACKED_SOURCES,
            DEFAULT_WORKER_QUEUE_CAPACITY,
        )
        .expect("built-in admission limits satisfy hard ceilings")
    }

    pub fn bounded(
        request_body_bytes: usize,
        source_burst: u32,
        source_refill_interval: Duration,
        global_burst: u32,
        global_refill_interval: Duration,
        maximum_tracked_sources: usize,
        worker_queue_capacity: usize,
    ) -> Result<Self, AdmissionLimitError> {
        if !(1..=4_096).contains(&request_body_bytes) {
            return Err(AdmissionLimitError::OutOfRange("request_body_bytes"));
        }
        if !(1..=64).contains(&source_burst) {
            return Err(AdmissionLimitError::OutOfRange("source_burst"));
        }
        if !(1..=1_024).contains(&global_burst) {
            return Err(AdmissionLimitError::OutOfRange("global_burst"));
        }
        if !(1..=65_536).contains(&maximum_tracked_sources) {
            return Err(AdmissionLimitError::OutOfRange("maximum_tracked_sources"));
        }
        if !(1..=64).contains(&worker_queue_capacity) {
            return Err(AdmissionLimitError::OutOfRange("worker_queue_capacity"));
        }
        for (name, interval) in [
            ("source_refill_interval", source_refill_interval),
            ("global_refill_interval", global_refill_interval),
        ] {
            if !(Duration::from_millis(10)..=Duration::from_secs(3_600)).contains(&interval) {
                return Err(AdmissionLimitError::OutOfRange(name));
            }
        }
        Ok(Self {
            request_body_bytes: NonZeroUsize::new(request_body_bytes).unwrap(),
            source_burst: NonZeroU32::new(source_burst).unwrap(),
            global_burst: NonZeroU32::new(global_burst).unwrap(),
            source_refill_interval,
            global_refill_interval,
            maximum_tracked_sources: NonZeroUsize::new(maximum_tracked_sources).unwrap(),
            worker_queue_capacity: NonZeroUsize::new(worker_queue_capacity).unwrap(),
            source_initial_tokens: NonZeroU32::new(1).unwrap(),
            global_initial_tokens: NonZeroU32::new(1).unwrap(),
            argon_concurrency: NonZeroUsize::new(DEFAULT_ARGON_CONCURRENCY).unwrap(),
            provider_create_concurrency: NonZeroUsize::new(DEFAULT_PROVIDER_CREATE_CONCURRENCY)
                .unwrap(),
        })
    }

    pub fn with_initial_tokens(
        mut self,
        source_initial_tokens: u32,
        global_initial_tokens: u32,
    ) -> Result<Self, AdmissionLimitError> {
        if source_initial_tokens == 0 || source_initial_tokens > self.source_burst.get() {
            return Err(AdmissionLimitError::OutOfRange("source_initial_tokens"));
        }
        if global_initial_tokens == 0 || global_initial_tokens > self.global_burst.get() {
            return Err(AdmissionLimitError::OutOfRange("global_initial_tokens"));
        }
        self.source_initial_tokens = NonZeroU32::new(source_initial_tokens).unwrap();
        self.global_initial_tokens = NonZeroU32::new(global_initial_tokens).unwrap();
        Ok(self)
    }

    #[must_use]
    pub const fn request_body_bytes(self) -> usize {
        self.request_body_bytes.get()
    }

    #[must_use]
    pub const fn source_refill_interval(self) -> Duration {
        self.source_refill_interval
    }

    #[must_use]
    pub const fn maximum_tracked_sources(self) -> usize {
        self.maximum_tracked_sources.get()
    }

    #[must_use]
    pub const fn worker_queue_capacity(self) -> usize {
        self.worker_queue_capacity.get()
    }

    #[must_use]
    pub const fn argon_concurrency(self) -> usize {
        self.argon_concurrency.get()
    }

    #[must_use]
    pub const fn provider_create_concurrency(self) -> usize {
        self.provider_create_concurrency.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdmissionLimitError {
    #[error("admission setting is outside its hard safety range: {0}")]
    OutOfRange(&'static str),
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self::safe_defaults()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Allowed,
    Limited { retry_after: Duration },
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AdmissionConfigurationError {
    #[error("admission clock predates controller initialization")]
    ClockBeforeInitialization,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: u32,
    burst: u32,
    refill_interval: Duration,
    last_refill: Instant,
}

impl Bucket {
    fn new(
        burst: NonZeroU32,
        refill_interval: Duration,
        initial_tokens: NonZeroU32,
        now: Instant,
    ) -> Self {
        Self {
            tokens: initial_tokens.get(),
            burst: burst.get(),
            refill_interval,
            last_refill: now,
        }
    }

    fn availability(&mut self, now: Instant) -> AdmissionDecision {
        self.refill(now);
        if self.tokens > 0 {
            AdmissionDecision::Allowed
        } else {
            let elapsed = now.saturating_duration_since(self.last_refill);
            let retry_after = self.refill_interval.saturating_sub(elapsed);
            AdmissionDecision::Limited {
                retry_after: retry_after.max(Duration::from_millis(1)),
            }
        }
    }

    fn debit(&mut self) {
        debug_assert!(self.tokens > 0);
        self.tokens -= 1;
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let interval_nanos = self.refill_interval.as_nanos();
        if interval_nanos == 0 {
            return;
        }
        let intervals = elapsed.as_nanos() / interval_nanos;
        if intervals == 0 {
            return;
        }
        let added = u32::try_from(intervals).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(added).min(self.burst);
        let advanced_intervals = intervals.min(u32::MAX.into()) as u32;
        self.last_refill += self.refill_interval.saturating_mul(advanced_intervals);
    }
}

#[derive(Debug)]
pub struct InMemoryAdmissionController {
    limits: AdmissionLimits,
    initialized_at: Instant,
    global: Bucket,
    overflow: Bucket,
    sources: HashMap<IpAddr, Bucket>,
}

impl InMemoryAdmissionController {
    pub fn new(limits: AdmissionLimits, now: Instant) -> Result<Self, AdmissionConfigurationError> {
        Ok(Self {
            limits,
            initialized_at: now,
            global: Bucket::new(
                limits.global_burst,
                limits.global_refill_interval,
                limits.global_initial_tokens,
                now,
            ),
            overflow: Bucket::new(
                limits.source_burst,
                limits.source_refill_interval,
                NonZeroU32::new(1).unwrap(),
                now,
            ),
            sources: HashMap::with_capacity(limits.maximum_tracked_sources()),
        })
    }

    #[must_use]
    pub fn admit(&mut self, source: IpAddr, now: Instant) -> AdmissionDecision {
        if now < self.initialized_at {
            return AdmissionDecision::Limited {
                retry_after: self.limits.global_refill_interval,
            };
        }
        let source = normalize_ip(source);
        enum SelectedBucket {
            Tracked,
            Overflow,
            New,
        }

        let (selected, source_decision, mut new_bucket) =
            if let Some(bucket) = self.sources.get_mut(&source) {
                (SelectedBucket::Tracked, bucket.availability(now), None)
            } else if self.sources.len() >= self.limits.maximum_tracked_sources() {
                (
                    SelectedBucket::Overflow,
                    self.overflow.availability(now),
                    None,
                )
            } else {
                let mut bucket = Bucket::new(
                    self.limits.source_burst,
                    self.limits.source_refill_interval,
                    self.limits.source_initial_tokens,
                    now,
                );
                let decision = bucket.availability(now);
                (SelectedBucket::New, decision, Some(bucket))
            };

        if let AdmissionDecision::Limited { retry_after } = source_decision {
            return AdmissionDecision::Limited { retry_after };
        }
        if let AdmissionDecision::Limited { retry_after } = self.global.availability(now) {
            return AdmissionDecision::Limited { retry_after };
        }

        match selected {
            SelectedBucket::Tracked => self.sources.get_mut(&source).unwrap().debit(),
            SelectedBucket::Overflow => self.overflow.debit(),
            SelectedBucket::New => {
                let mut bucket = new_bucket.take().unwrap();
                bucket.debit();
                self.sources.insert(source, bucket);
            }
        }
        self.global.debit();
        AdmissionDecision::Allowed
    }

    #[must_use]
    pub fn tracked_source_count(&self) -> usize {
        self.sources.len()
    }
}

fn normalize_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinBootstrapConfig {
    login_server: String,
    root_ca_pem: Option<String>,
}

impl JoinBootstrapConfig {
    pub fn new(
        login_server: impl AsRef<str>,
        root_ca_pem: Option<String>,
    ) -> Result<Self, IngressConfigurationError> {
        let parsed = Url::parse(login_server.as_ref())
            .map_err(|_| IngressConfigurationError::InvalidLoginServer)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(IngressConfigurationError::InvalidLoginServer);
        }
        if root_ca_pem.as_ref().is_some_and(|pem| {
            pem.is_empty()
                || pem.len() > MAX_ROOT_CA_PEM_BYTES
                || !pem.contains("-----BEGIN CERTIFICATE-----")
                || !pem.contains("-----END CERTIFICATE-----")
        }) {
            return Err(IngressConfigurationError::InvalidRootCa);
        }
        Ok(Self {
            login_server: parsed.to_string(),
            root_ca_pem,
        })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IngressConfigurationError {
    #[error("join login server must be a clean verified HTTPS origin")]
    InvalidLoginServer,
    #[error("join root CA must be a bounded PEM certificate chain")]
    InvalidRootCa,
}

pub struct RedemptionAttempt {
    source: IpAddr,
    token: InvitationToken,
    timing_token: InvitationToken,
}

impl RedemptionAttempt {
    #[must_use]
    pub const fn source(&self) -> IpAddr {
        self.source
    }

    #[must_use]
    pub fn into_parts(self) -> (IpAddr, InvitationToken, InvitationToken) {
        (self.source, self.token, self.timing_token)
    }
}

impl fmt::Debug for RedemptionAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedemptionAttempt")
            .field("source", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionFailure {
    NotRedeemable,
    Unavailable,
}

pub struct RedemptionHandoff {
    delivery: Option<ProviderCredentialDelivery>,
    accepted: Option<oneshot::Sender<()>>,
}

impl RedemptionHandoff {
    #[must_use]
    pub fn receipt(&self) -> &RedemptionReceipt {
        self.delivery
            .as_ref()
            .expect("redemption handoff always owns delivery before consumption")
            .receipt()
    }

    #[must_use]
    pub fn untracked(delivery: ProviderCredentialDelivery) -> Self {
        Self {
            delivery: Some(delivery),
            accepted: None,
        }
    }

    fn tracked(delivery: ProviderCredentialDelivery, accepted: oneshot::Sender<()>) -> Self {
        Self {
            delivery: Some(delivery),
            accepted: Some(accepted),
        }
    }

    fn serialize(mut self, bootstrap: &JoinBootstrapConfig) -> Result<Vec<u8>, ()> {
        let delivery = self.delivery.take().ok_or(())?;
        let (_, serialized) = delivery.deliver_once(|auth_key| {
            serde_json::to_vec(&WireSuccess {
                login_server: &bootstrap.login_server,
                root_ca_pem: bootstrap.root_ca_pem.as_deref(),
                auth_key,
            })
        });
        let body = serialized.map_err(|_| ())?;
        if let Some(accepted) = self.accepted.take() {
            accepted.send(()).map_err(|_| ())?;
        }
        Ok(body)
    }
}

impl fmt::Debug for RedemptionHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedemptionHandoff")
            .field("delivery", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait RedemptionBackend: Send + Sync {
    async fn redeem(
        &self,
        attempt: RedemptionAttempt,
    ) -> Result<RedemptionHandoff, RedemptionFailure>;
}

struct IngressState {
    backend: Arc<dyn RedemptionBackend>,
    admission: Mutex<InMemoryAdmissionController>,
    limits: AdmissionLimits,
    bootstrap: JoinBootstrapConfig,
}

pub fn redemption_router<B>(
    backend: Arc<B>,
    limits: AdmissionLimits,
    bootstrap: JoinBootstrapConfig,
) -> Result<Router, AdmissionConfigurationError>
where
    B: RedemptionBackend + 'static,
{
    let state = Arc::new(IngressState {
        backend,
        admission: Mutex::new(InMemoryAdmissionController::new(limits, Instant::now())?),
        limits,
        bootstrap,
    });
    Ok(Router::new()
        .route("/v1/redemptions", post(redeem_http))
        .with_state(state))
}

async fn redeem_http(
    State(state): State<Arc<IngressState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let source = normalize_ip(peer.ip());
    let decision = match state.admission.lock() {
        Ok(mut admission) => admission.admit(source, Instant::now()),
        Err(_) => return unavailable_response(None),
    };
    if let AdmissionDecision::Limited { retry_after } = decision {
        return unavailable_response(Some(retry_after));
    }

    if !is_json_content_type(request.headers()) {
        return invalid_request_response();
    }

    let mut body = match to_bytes(request.into_body(), state.limits.request_body_bytes()).await {
        Ok(body) => body.to_vec(),
        Err(_) => return invalid_request_response(),
    };
    let wire = match serde_json::from_slice::<WireRedemptionRequest>(&body) {
        Ok(wire) => wire,
        Err(_) => {
            body.zeroize();
            return invalid_request_response();
        }
    };
    body.zeroize();
    let token = match InvitationToken::from_str(wire.invitation_token.as_str()) {
        Ok(token) => token,
        Err(_) => return invalid_request_response(),
    };
    let timing_token = match InvitationToken::from_str(wire.invitation_token.as_str()) {
        Ok(token) => token,
        Err(_) => return invalid_request_response(),
    };
    drop(wire);

    match state
        .backend
        .redeem(RedemptionAttempt {
            source,
            token,
            timing_token,
        })
        .await
    {
        Ok(delivery) => success_response(delivery, &state.bootstrap),
        Err(RedemptionFailure::NotRedeemable) => not_redeemable_response(),
        Err(RedemptionFailure::Unavailable) => unavailable_response(None),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRedemptionRequest {
    invitation_token: SecretInput,
}

struct SecretInput(Zeroizing<String>);

impl SecretInput {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Zeroizing::new(String::deserialize(deserializer)?)))
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

#[derive(Serialize)]
struct WireSuccess<'a> {
    login_server: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_ca_pem: Option<&'a str>,
    auth_key: &'a str,
}

fn success_response(handoff: RedemptionHandoff, bootstrap: &JoinBootstrapConfig) -> Response {
    match handoff.serialize(bootstrap) {
        Ok(body) => fixed_response(StatusCode::OK, Body::from(body), None),
        Err(()) => unavailable_response(None),
    }
}

fn invalid_request_response() -> Response {
    fixed_response(
        StatusCode::BAD_REQUEST,
        Body::from(r#"{"error":"invalid_request"}"#),
        None,
    )
}

fn not_redeemable_response() -> Response {
    fixed_response(
        StatusCode::CONFLICT,
        Body::from(r#"{"error":"not_redeemable"}"#),
        None,
    )
}

fn unavailable_response(retry_after: Option<Duration>) -> Response {
    let status = if retry_after.is_some() {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    fixed_response(
        status,
        Body::from(r#"{"error":"temporarily_unavailable"}"#),
        retry_after,
    )
}

fn fixed_response(status: StatusCode, body: Body, retry_after: Option<Duration>) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    if let Some(retry_after) = retry_after {
        let seconds = retry_after.as_secs().max(1).to_string();
        if let Ok(value) = HeaderValue::from_str(&seconds) {
            headers.insert(header::RETRY_AFTER, value);
        }
    }
    response
}

struct WorkerCommand {
    attempt: RedemptionAttempt,
    enqueued_at: Instant,
    reply: oneshot::Sender<Result<RedemptionHandoff, RedemptionFailure>>,
}

struct WorkerControl {
    shutdown: oneshot::Receiver<()>,
    pending_handoffs: Arc<AtomicUsize>,
}

pub struct RedemptionWorkerClient {
    sender: mpsc::Sender<WorkerCommand>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    completion: Mutex<std_mpsc::Receiver<()>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    terminated: AtomicBool,
    pending_handoffs: Arc<AtomicUsize>,
}

impl fmt::Debug for RedemptionWorkerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedemptionWorkerClient")
            .field("capacity", &self.sender.capacity())
            .field("pending_handoffs", &self.pending_handoffs())
            .finish()
    }
}

impl RedemptionWorkerClient {
    #[must_use]
    pub fn pending_handoffs(&self) -> usize {
        self.pending_handoffs.load(Ordering::Acquire)
    }

    pub fn shutdown_timeout(&self, timeout: Duration) -> Result<(), WorkerShutdownError> {
        if self.terminated.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(shutdown) = self
            .shutdown
            .lock()
            .map_err(|_| WorkerShutdownError::Poisoned)?
            .take()
        {
            let _ = shutdown.send(());
        }
        match self
            .completion
            .lock()
            .map_err(|_| WorkerShutdownError::Poisoned)?
            .recv_timeout(timeout)
        {
            Ok(()) => {
                let thread = self
                    .thread
                    .lock()
                    .map_err(|_| WorkerShutdownError::Poisoned)?
                    .take();
                if thread.is_some_and(|thread| thread.join().is_err()) {
                    return Err(WorkerShutdownError::WorkerPanicked);
                }
                self.terminated.store(true, Ordering::Release);
                Ok(())
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => Err(WorkerShutdownError::TimedOut),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                Err(WorkerShutdownError::WorkerPanicked)
            }
        }
    }
}

impl Drop for RedemptionWorkerClient {
    fn drop(&mut self) {
        if let Ok(shutdown) = self.shutdown.get_mut() {
            if let Some(shutdown) = shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }
}

#[async_trait]
impl RedemptionBackend for RedemptionWorkerClient {
    async fn redeem(
        &self,
        attempt: RedemptionAttempt,
    ) -> Result<RedemptionHandoff, RedemptionFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(WorkerCommand {
                attempt,
                enqueued_at: Instant::now(),
                reply,
            })
            .map_err(|_| RedemptionFailure::Unavailable)?;
        response
            .await
            .unwrap_or(Err(RedemptionFailure::Unavailable))
    }
}

#[derive(Debug, Error)]
pub enum WorkerSpawnError {
    #[error("failed to initialize the dummy invitation verifier")]
    DummyVerifier,
    #[error("failed to spawn the redemption worker thread")]
    Thread(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WorkerShutdownError {
    #[error("redemption worker did not stop before the shutdown deadline")]
    TimedOut,
    #[error("redemption worker synchronization was poisoned")]
    Poisoned,
    #[error("redemption worker thread panicked")]
    WorkerPanicked,
}

pub fn spawn_redemption_worker_with_issuer<P, I>(
    store: StateStore,
    provider: P,
    issuer: I,
    limits: AdmissionLimits,
) -> Result<Arc<RedemptionWorkerClient>, WorkerSpawnError>
where
    P: MutationProvider + 'static,
    I: N4AuthorizationIssuer<P> + Send + 'static,
{
    spawn_worker(store, provider, issuer, limits, Arc::new(Utc::now))
}

#[doc(hidden)]
pub fn spawn_redemption_worker_with_issuer_and_clock<P, I>(
    store: StateStore,
    provider: P,
    issuer: I,
    limits: AdmissionLimits,
    clock: Arc<dyn Fn() -> chrono::DateTime<Utc> + Send + Sync>,
) -> Result<Arc<RedemptionWorkerClient>, WorkerSpawnError>
where
    P: MutationProvider + 'static,
    I: N4AuthorizationIssuer<P> + Send + 'static,
{
    spawn_worker(store, provider, issuer, limits, clock)
}

pub fn spawn_state_authorized_redemption_worker<P>(
    store: StateStore,
    provider: P,
    limits: AdmissionLimits,
) -> Result<Arc<RedemptionWorkerClient>, WorkerSpawnError>
where
    P: MutationProvider<Authorization = MutationAuthorization> + 'static,
{
    spawn_worker(
        store,
        provider,
        StateAuthorizationIssuer,
        limits,
        Arc::new(Utc::now),
    )
}

fn spawn_worker<P, I>(
    store: StateStore,
    provider: P,
    issuer: I,
    limits: AdmissionLimits,
    clock: Arc<dyn Fn() -> chrono::DateTime<Utc> + Send + Sync>,
) -> Result<Arc<RedemptionWorkerClient>, WorkerSpawnError>
where
    P: MutationProvider + 'static,
    I: N4AuthorizationIssuer<P> + Send + 'static,
{
    let dummy_token = InvitationToken::generate(InvitationId::new());
    let dummy_verifier =
        SecretVerifier::from_token(&dummy_token).map_err(|_| WorkerSpawnError::DummyVerifier)?;
    drop(dummy_token);
    let (sender, receiver) = mpsc::channel(limits.worker_queue_capacity());
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let (completion, completion_receiver) = std_mpsc::channel();
    let pending_handoffs = Arc::new(AtomicUsize::new(0));
    let worker_pending_handoffs = Arc::clone(&pending_handoffs);
    let thread = thread::Builder::new()
        .name("nodescale-redemption".into())
        .spawn(move || {
            run_worker(
                store,
                provider,
                issuer,
                dummy_verifier,
                receiver,
                WorkerControl {
                    shutdown: shutdown_receiver,
                    pending_handoffs: worker_pending_handoffs,
                },
                clock,
            );
            let _ = completion.send(());
        })?;
    Ok(Arc::new(RedemptionWorkerClient {
        sender,
        shutdown: Mutex::new(Some(shutdown)),
        completion: Mutex::new(completion_receiver),
        thread: Mutex::new(Some(thread)),
        terminated: AtomicBool::new(false),
        pending_handoffs,
    }))
}

fn run_worker<P, I>(
    store: StateStore,
    provider: P,
    issuer: I,
    dummy_verifier: SecretVerifier,
    receiver: mpsc::Receiver<WorkerCommand>,
    control: WorkerControl,
    clock: Arc<dyn Fn() -> chrono::DateTime<Utc> + Send + Sync>,
) where
    P: MutationProvider + 'static,
    I: N4AuthorizationIssuer<P> + Send + 'static,
{
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    runtime.block_on(async move {
        worker_loop(
            &store,
            &provider,
            &issuer,
            &dummy_verifier,
            receiver,
            control,
            &clock,
        )
        .await;
    });
}

async fn worker_loop<P, I>(
    store: &StateStore,
    provider: &P,
    issuer: &I,
    dummy_verifier: &SecretVerifier,
    mut receiver: mpsc::Receiver<WorkerCommand>,
    mut control: WorkerControl,
    clock: &Arc<dyn Fn() -> chrono::DateTime<Utc> + Send + Sync>,
) where
    P: MutationProvider,
    I: N4AuthorizationIssuer<P>,
{
    loop {
        let command = tokio::select! {
            biased;
            _ = &mut control.shutdown => break,
            command = receiver.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        if command.enqueued_at.elapsed() > Duration::from_secs(5) {
            let _ = command.reply.send(Err(RedemptionFailure::Unavailable));
            continue;
        }
        let (source, token, timing_token) = command.attempt.into_parts();
        let presented = match source_metadata(source) {
            Ok(presented) => presented,
            Err(_) => {
                let _ = command.reply.send(Err(RedemptionFailure::Unavailable));
                continue;
            }
        };
        let service = InvitationService::new(store, provider, issuer);
        let now = clock();
        let result = service
            .redeem(
                RedeemInvitationRequest {
                    token,
                    presented,
                    actor: ingress_actor(),
                },
                now,
            )
            .await;
        let public_result = match result {
            Ok(delivery) => {
                let invitation_id = delivery.receipt().invitation_id;
                let (accepted, acceptance) = oneshot::channel();
                let handoff = RedemptionHandoff::tracked(delivery, accepted);
                control.pending_handoffs.fetch_add(1, Ordering::AcqRel);
                if command.reply.send(Ok(handoff)).is_err() {
                    control.pending_handoffs.fetch_sub(1, Ordering::AcqRel);
                    let _ = service
                        .revoke(invitation_id, clock(), ingress_actor())
                        .await;
                    continue;
                }
                let accepted = acceptance.await.is_ok();
                control.pending_handoffs.fetch_sub(1, Ordering::AcqRel);
                if !accepted {
                    let _ = service
                        .revoke(invitation_id, clock(), ingress_actor())
                        .await;
                }
                continue;
            }
            Err(InvitationServiceError::NotFound) => {
                let _ = dummy_verifier.verify(&timing_token);
                Err(RedemptionFailure::NotRedeemable)
            }
            Err(InvitationServiceError::Unavailable) => Err(RedemptionFailure::Unavailable),
            Err(_) => Err(RedemptionFailure::NotRedeemable),
        };
        let _ = command.reply.send(public_result);
    }
}

fn source_metadata(source: IpAddr) -> Result<N4PresentedMetadata, StateError> {
    Ok(N4PresentedMetadata {
        platform: None,
        hostname_hint: None,
        correlation: SanitizedMetadata::new(serde_json::json!({
            "source": source.to_string()
        }))?,
    })
}

fn ingress_actor() -> AuditActor {
    AuditActor {
        source: "nodescale_redemption_ingress".into(),
        actor_id: None,
    }
}

struct StateAuthorizationIssuer;

impl<P> N4AuthorizationIssuer<P> for StateAuthorizationIssuer
where
    P: MutationProvider<Authorization = MutationAuthorization>,
{
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: chrono::DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, MutationAuthorization), StateError> {
        store.begin_n4_credential_dispatch_with_authorization(join_session_id, now, actor)
    }

    fn issue_invalidation(
        &self,
        store: &StateStore,
        target: &N4CleanupTarget,
        now: chrono::DateTime<Utc>,
    ) -> Result<MutationAuthorization, StateError> {
        store.issue_mutation_authorization(
            target.network_id,
            target.provider_instance_id,
            ProviderMutationCapability::InvalidateJoinCredential,
            now,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsServeConfig {
    bind: SocketAddr,
    certificate_chain_path: PathBuf,
    private_key_path: PathBuf,
}

impl TlsServeConfig {
    pub fn private_bind(
        bind: SocketAddr,
        certificate_chain_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
    ) -> Result<Self, TlsServeConfigError> {
        if !is_private_bind(bind.ip()) {
            return Err(TlsServeConfigError::PublicBindRequiresExplicitOptIn);
        }
        Self::build(bind, certificate_chain_path, private_key_path)
    }

    pub fn explicitly_public_bind(
        bind: SocketAddr,
        certificate_chain_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
    ) -> Result<Self, TlsServeConfigError> {
        Self::build(bind, certificate_chain_path, private_key_path)
    }

    fn build(
        bind: SocketAddr,
        certificate_chain_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
    ) -> Result<Self, TlsServeConfigError> {
        let certificate_chain_path = certificate_chain_path.into();
        let private_key_path = private_key_path.into();
        if certificate_chain_path.as_os_str().is_empty() || private_key_path.as_os_str().is_empty()
        {
            return Err(TlsServeConfigError::EmptyCredentialPath);
        }
        Ok(Self {
            bind,
            certificate_chain_path,
            private_key_path,
        })
    }

    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    #[must_use]
    pub fn certificate_chain_path(&self) -> &Path {
        &self.certificate_chain_path
    }

    #[must_use]
    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TlsServeConfigError {
    #[error("public or wildcard bind requires explicit opt-in")]
    PublicBindRequiresExplicitOptIn,
    #[error("TLS certificate and private-key paths must be non-empty")]
    EmptyCredentialPath,
}

#[derive(Debug, Error)]
pub enum TlsServeError {
    #[error("failed to load TLS certificate or private key")]
    LoadCredentials(#[source] std::io::Error),
    #[error("TLS server failed")]
    Serve(#[source] std::io::Error),
}

pub async fn serve_tls(config: TlsServeConfig, router: Router) -> Result<(), TlsServeError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        config.certificate_chain_path,
        config.private_key_path,
    )
    .await
    .map_err(TlsServeError::LoadCredentials)?;
    axum_server::bind_rustls(config.bind, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(TlsServeError::Serve)
}

fn is_private_bind(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    }
}
