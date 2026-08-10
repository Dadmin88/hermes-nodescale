use crate::RuntimeError;
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};
use nodescale_domain::{NetworkId, ProviderKind, ProviderNodeId};
use nodescale_state::{
    ObservationClassification, PROVIDER_OBSERVATION_PAGE_MAX, ProviderObservation,
    ProviderReconciliationState, StateStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, PathBuf},
};

const VERSION: &str = "nodescale.observations.v1";
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 256;
const MAX_ITEMS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservationApiConfig {
    pub socket_path: PathBuf,
    pub peer_uid: u32,
}

impl ObservationApiConfig {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        if !self.socket_path.is_absolute()
            || self
                .socket_path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(RuntimeError::Configuration(
                "observation_api.socket_path must be an absolute safe path",
            ));
        }
        if self.peer_uid != geteuid().as_raw() {
            return Err(RuntimeError::Configuration(
                "observation_api.peer_uid must equal the service effective UID",
            ));
        }
        let parent = self
            .socket_path
            .parent()
            .ok_or(RuntimeError::Configuration(
                "observation_api.socket_path requires a parent",
            ))?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| {
            RuntimeError::Configuration("observation_api socket parent is unavailable")
        })?;
        let canonical_parent = fs::canonicalize(parent).map_err(|_| {
            RuntimeError::Configuration("observation_api socket parent is unavailable")
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || canonical_parent.as_path() != parent
            || metadata.uid() != self.peer_uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(RuntimeError::Configuration(
                "observation_api socket parent is unsafe",
            ));
        }
        Ok(())
    }
}

pub struct ObservationUdsListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    peer_uid: u32,
}

impl ObservationUdsListener {
    pub fn bind(config: &ObservationApiConfig) -> Result<Self, RuntimeError> {
        config.validate()?;
        if fs::symlink_metadata(&config.socket_path).is_ok() {
            return Err(RuntimeError::Configuration(
                "observation_api socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&config.socket_path).map_err(|_| {
            RuntimeError::Configuration("observation_api socket could not be bound")
        })?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).map_err(
            |_| RuntimeError::Configuration("observation_api socket permissions could not be set"),
        )?;
        let metadata = fs::symlink_metadata(&config.socket_path).map_err(|_| {
            RuntimeError::Configuration("observation_api socket metadata is unavailable")
        })?;
        if !metadata.file_type().is_socket() || metadata.mode() & 0o777 != 0o600 {
            return Err(RuntimeError::Configuration(
                "observation_api socket is unsafe",
            ));
        }
        listener.set_nonblocking(true).map_err(|_| {
            RuntimeError::Configuration("observation_api socket could not become nonblocking")
        })?;
        Ok(Self {
            listener,
            path: config.socket_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            peer_uid: config.peer_uid,
        })
    }

    /// Process at most one ready client on the runtime's owning thread.
    pub fn serve_available(&self, store: &StateStore) -> Result<bool, RuntimeError> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let authorized = getsockopt(&stream, PeerCredentials)
                    .map(|credentials| credentials.uid() == self.peer_uid)
                    .unwrap_or(false);
                if authorized {
                    let _ = serve_stream(stream, store);
                }
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err(RuntimeError::Configuration("observation_api accept failed")),
        }
    }
}

impl Drop for ObservationUdsListener {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn serve_stream(mut stream: UnixStream, store: &StateStore) -> Result<(), ()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
    let response = match read_request(&mut stream) {
        Ok(request) => match dispatch(store, request) {
            Ok(response) => response,
            Err(DispatchError::InvalidRequest) => WireResponse::error("invalid_request"),
            Err(DispatchError::Unavailable) => WireResponse::error("unavailable"),
        },
        Err(()) => WireResponse::error("invalid_request"),
    };
    write_response(&mut stream, &response)
}

fn read_request(stream: &mut UnixStream) -> Result<WireRequest, ()> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(|_| ())?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| ())?;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(());
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).map_err(|_| ())?;
    let mut trailing = [0; 1];
    if stream.read(&mut trailing).map_err(|_| ())? != 0 {
        return Err(());
    }
    serde_json::from_slice(&payload).map_err(|_| ())
}

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireRequest {
    #[serde(rename = "capabilities")]
    Capabilities { version: String },
    #[serde(rename = "summary")]
    Summary { version: String, network_id: String },
    #[serde(rename = "list")]
    List {
        version: String,
        network_id: String,
        limit: usize,
        cursor: Option<String>,
    },
}

enum DispatchError {
    InvalidRequest,
    Unavailable,
}

fn dispatch(store: &StateStore, request: WireRequest) -> Result<WireResponse, DispatchError> {
    let (version, network_id, limit, cursor, kind) = match request {
        WireRequest::Capabilities { version } => {
            if version != VERSION {
                return Err(DispatchError::InvalidRequest);
            }
            return Ok(WireResponse::capabilities());
        }
        WireRequest::Summary {
            version,
            network_id,
        } => (version, network_id, None, None, "summary"),
        WireRequest::List {
            version,
            network_id,
            limit,
            cursor,
        } => {
            if limit == 0
                || limit > PROVIDER_OBSERVATION_PAGE_MAX
                || cursor.as_ref().is_some_and(|value| {
                    value.is_empty()
                        || value.len() > MAX_TEXT_BYTES
                        || ProviderNodeId::parse(value).is_err()
                })
            {
                return Err(DispatchError::InvalidRequest);
            }
            (version, network_id, Some(limit), cursor, "list")
        }
    };
    if version != VERSION
        || (kind == "summary" && limit.is_some())
        || !matches!(kind, "summary" | "list")
    {
        return Err(DispatchError::InvalidRequest);
    }
    // serde's closed enum has already rejected duplicate and unknown fields.
    let network_id = NetworkId::parse(&network_id).map_err(|_| DispatchError::InvalidRequest)?;
    let network = store
        .network(network_id)
        .map_err(|_| DispatchError::Unavailable)?;
    let report = store
        .reconciliation_report(network_id)
        .map_err(|_| DispatchError::Unavailable)?;
    let summary = ReconciliationSummary::from_report(&report);
    if kind == "summary" {
        return Ok(WireResponse::summary(network_id.to_string(), summary));
    }
    let requested_limit = limit.unwrap_or(1);
    let observations = store
        .provider_observation_page(network_id, cursor.as_deref(), requested_limit)
        .map_err(|_| DispatchError::Unavailable)?;
    let observations = observations
        .into_iter()
        .map(|observation| ObservationDto::project(observation, network.provider_kind))
        .collect();
    WireResponse::list(
        network_id.to_string(),
        summary,
        observations,
        requested_limit,
    )
    .map_err(|_| DispatchError::Unavailable)
}

#[derive(Serialize)]
struct ReconciliationSummary {
    state: &'static str,
    last_attempted_at: Option<String>,
    last_successful_at: Option<String>,
    observed_count: u64,
}
impl ReconciliationSummary {
    fn from_report(report: &nodescale_state::ReconciliationReport) -> Self {
        Self {
            state: reconciliation_state(report.provider_state),
            last_attempted_at: report
                .last_attempted_reconciliation
                .map(|at| at.to_rfc3339()),
            last_successful_at: report
                .last_successful_reconciliation
                .map(|at| at.to_rfc3339()),
            observed_count: report.observed_count,
        }
    }
}

#[derive(Serialize)]
struct ObservationDto {
    observed_id: String,
    network_id: String,
    provider_kind: &'static str,
    provider_instance_id: String,
    provider_node_id: String,
    hostname: String,
    given_name: String,
    addresses: Vec<String>,
    tags: Vec<String>,
    registered_at: Option<String>,
    last_seen_at: Option<String>,
    expires_at: Option<String>,
    online: Option<bool>,
    expired: bool,
    classification: &'static str,
    first_observed_at: String,
    last_observed_at: String,
    snapshot_at: String,
}
impl ObservationDto {
    fn project(observation: ProviderObservation, provider_kind: ProviderKind) -> Self {
        let observed_id = opaque_observed_id(
            provider_kind,
            &observation.provider_instance_id.to_string(),
            &observation.canonical_provider_node_id,
            &observation.stable_machine_key_fingerprint,
        );
        Self {
            observed_id,
            network_id: observation.network_id.to_string(),
            provider_kind: provider_kind_name(provider_kind),
            provider_instance_id: observation.provider_instance_id.to_string(),
            provider_node_id: bounded_text(&observation.canonical_provider_node_id),
            hostname: bounded_text(&observation.node.hostname),
            given_name: bounded_text(&observation.node.given_name),
            addresses: observation
                .node
                .addresses
                .iter()
                .take(MAX_ITEMS)
                .map(|value| bounded_text(value))
                .collect(),
            tags: observation
                .node
                .tags
                .iter()
                .take(MAX_ITEMS)
                .map(|value| bounded_text(value))
                .collect(),
            registered_at: observation.node.registered_at.map(|at| at.to_rfc3339()),
            last_seen_at: observation.node.last_seen.map(|at| at.to_rfc3339()),
            expires_at: observation.node.expires_at.map(|at| at.to_rfc3339()),
            online: observation.node.online,
            expired: observation.node.expired,
            classification: classification_name(observation.classification),
            first_observed_at: observation.first_observed_at.to_rfc3339(),
            last_observed_at: observation.last_observed_at.to_rfc3339(),
            snapshot_at: observation.snapshot_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
struct WireResponse {
    version: &'static str,
    #[serde(rename = "kind")]
    response_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<Capabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconciliation: Option<ReconciliationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observations: Option<Vec<ObservationDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}
#[derive(Serialize)]
struct Capabilities {
    max_page_size: usize,
    max_response_bytes: usize,
}
impl WireResponse {
    fn capabilities() -> Self {
        Self {
            version: VERSION,
            response_kind: "capabilities",
            capabilities: Some(Capabilities {
                max_page_size: PROVIDER_OBSERVATION_PAGE_MAX,
                max_response_bytes: MAX_RESPONSE_BYTES,
            }),
            network_id: None,
            reconciliation: None,
            observations: None,
            next_cursor: None,
            error: None,
        }
    }
    fn summary(network_id: String, reconciliation: ReconciliationSummary) -> Self {
        Self {
            version: VERSION,
            response_kind: "summary",
            capabilities: None,
            network_id: Some(network_id),
            reconciliation: Some(reconciliation),
            observations: None,
            next_cursor: None,
            error: None,
        }
    }
    fn list(
        network_id: String,
        reconciliation: ReconciliationSummary,
        mut observations: Vec<ObservationDto>,
        requested_limit: usize,
    ) -> Result<Self, ()> {
        let loaded_count = observations.len();
        loop {
            let next_cursor = (!observations.is_empty()
                && (observations.len() < loaded_count || loaded_count == requested_limit))
                .then(|| observations.last().unwrap().provider_node_id.clone());
            let response = Self {
                version: VERSION,
                response_kind: "list",
                capabilities: None,
                network_id: Some(network_id.clone()),
                reconciliation: Some(ReconciliationSummary {
                    state: reconciliation.state,
                    last_attempted_at: reconciliation.last_attempted_at.clone(),
                    last_successful_at: reconciliation.last_successful_at.clone(),
                    observed_count: reconciliation.observed_count,
                }),
                observations: Some(observations),
                next_cursor,
                error: None,
            };
            if serde_json::to_vec(&response).map_err(|_| ())?.len() <= MAX_RESPONSE_BYTES {
                return Ok(response);
            }
            observations = response.observations.unwrap_or_default();
            if observations.pop().is_none() {
                return Err(());
            }
        }
    }
    fn error(error: &'static str) -> Self {
        Self {
            version: VERSION,
            response_kind: "error",
            capabilities: None,
            network_id: None,
            reconciliation: None,
            observations: None,
            next_cursor: None,
            error: Some(error),
        }
    }
}
fn write_response(stream: &mut UnixStream, response: &WireResponse) -> Result<(), ()> {
    let payload = serde_json::to_vec(response).map_err(|_| ())?;
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(&payload))
        .map_err(|_| ())
}
fn opaque_observed_id(kind: ProviderKind, instance: &str, node: &str, fingerprint: &str) -> String {
    let mut digest = Sha256::new();
    for part in [provider_kind_name(kind), instance, node, fingerprint] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}
fn bounded_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars().filter(|character| !character.is_control()) {
        if output.len() + character.len_utf8() > MAX_TEXT_BYTES {
            break;
        }
        output.push(character);
    }
    output
}
fn provider_kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Fake => "fake",
        ProviderKind::Headscale => "headscale",
        ProviderKind::Tailscale => "tailscale",
    }
}
fn classification_name(value: ObservationClassification) -> &'static str {
    match value {
        ObservationClassification::ExpectedJoining => "expected_joining",
        ObservationClassification::DiscoveredUnmanaged => "discovered_unmanaged",
        ObservationClassification::Active => "active",
        ObservationClassification::ProviderMissing => "provider_missing",
        ObservationClassification::ProviderExpired => "provider_expired",
        ObservationClassification::ProviderRemoved => "provider_removed",
        ObservationClassification::IdentityConflict => "identity_conflict",
        ObservationClassification::Quarantined => "quarantined",
        ObservationClassification::Revoked => "revoked",
    }
}
fn reconciliation_state(value: ProviderReconciliationState) -> &'static str {
    match value {
        ProviderReconciliationState::NeverReconciled => "never_reconciled",
        ProviderReconciliationState::Healthy => "healthy",
        ProviderReconciliationState::Unreachable => "unreachable",
        ProviderReconciliationState::AuthenticationFailed => "authentication_failed",
        ProviderReconciliationState::Incompatible => "incompatible",
        ProviderReconciliationState::Malformed => "malformed",
        ProviderReconciliationState::IdentityConflict => "identity_conflict",
        ProviderReconciliationState::StateFailure => "state_failure",
    }
}
