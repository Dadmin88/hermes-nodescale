use crate::RuntimeError;
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};
use nodescale_domain::{Device, DeviceId, NetworkId, Roles};
use nodescale_state::{DEVICE_PAGE_MAX, DeviceTrustView, N6BindingView, StateError, StateStore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, PathBuf},
};

const VERSION: &str = "nodescale.operator.v1";
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperatorApiConfig {
    pub socket_path: PathBuf,
    pub peer_uid: u32,
}

impl OperatorApiConfig {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        if !self.socket_path.is_absolute()
            || self
                .socket_path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(RuntimeError::Configuration(
                "operator_api.socket_path must be an absolute safe path",
            ));
        }
        if self.peer_uid != geteuid().as_raw() {
            return Err(RuntimeError::Configuration(
                "operator_api.peer_uid must equal the service effective UID",
            ));
        }
        let parent = self
            .socket_path
            .parent()
            .ok_or(RuntimeError::Configuration(
                "operator_api.socket_path requires a parent",
            ))?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| {
            RuntimeError::Configuration("operator_api socket parent is unavailable")
        })?;
        let canonical_parent = fs::canonicalize(parent).map_err(|_| {
            RuntimeError::Configuration("operator_api socket parent is unavailable")
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || canonical_parent.as_path() != parent
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(RuntimeError::Configuration(
                "operator_api socket parent is unsafe",
            ));
        }
        Ok(())
    }
}

pub struct OperatorUdsListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    peer_uid: u32,
}

impl OperatorUdsListener {
    pub fn bind(config: &OperatorApiConfig) -> Result<Self, RuntimeError> {
        config.validate()?;
        if fs::symlink_metadata(&config.socket_path).is_ok() {
            return Err(RuntimeError::Configuration(
                "operator_api socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&config.socket_path)
            .map_err(|_| RuntimeError::Configuration("operator_api socket could not be bound"))?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).map_err(
            |_| RuntimeError::Configuration("operator_api socket permissions could not be set"),
        )?;
        let metadata = fs::symlink_metadata(&config.socket_path).map_err(|_| {
            RuntimeError::Configuration("operator_api socket metadata is unavailable")
        })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(RuntimeError::Configuration("operator_api socket is unsafe"));
        }
        listener.set_nonblocking(true).map_err(|_| {
            RuntimeError::Configuration("operator_api socket could not become nonblocking")
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
            Err(_) => Err(RuntimeError::Configuration("operator_api accept failed")),
        }
    }
}

impl Drop for OperatorUdsListener {
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
            Err(DispatchError::NotFound) => WireResponse::error("not_found"),
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
    #[serde(rename = "devices.list")]
    DevicesList {
        version: String,
        network_id: String,
        limit: usize,
        cursor: Option<String>,
    },
    #[serde(rename = "devices.inspect")]
    DevicesInspect {
        version: String,
        network_id: String,
        device_id: String,
    },
}

enum DispatchError {
    InvalidRequest,
    NotFound,
    Unavailable,
}

fn dispatch(store: &StateStore, request: WireRequest) -> Result<WireResponse, DispatchError> {
    match request {
        WireRequest::Capabilities { version } => {
            require_version(&version)?;
            Ok(WireResponse::capabilities())
        }
        WireRequest::DevicesList {
            version,
            network_id,
            limit,
            cursor,
        } => {
            require_version(&version)?;
            if !(1..=DEVICE_PAGE_MAX).contains(&limit)
                || cursor.as_ref().is_some_and(|value| {
                    value.is_empty()
                        || value.len() > MAX_TEXT_BYTES
                        || DeviceId::parse(value).is_err()
                })
            {
                return Err(DispatchError::InvalidRequest);
            }
            let network_id =
                NetworkId::parse(&network_id).map_err(|_| DispatchError::InvalidRequest)?;
            store.network(network_id).map_err(map_lookup_error)?;
            let cursor = cursor
                .as_deref()
                .map(DeviceId::parse)
                .transpose()
                .map_err(|_| DispatchError::InvalidRequest)?;
            let devices = store
                .operator_device_page(network_id, cursor, limit)
                .map_err(|_| DispatchError::Unavailable)?;
            let mut projected = Vec::with_capacity(devices.len());
            for device in devices {
                projected.push(DeviceDto::project(store, device)?);
            }
            WireResponse::devices_list(network_id.to_string(), projected, limit)
                .map_err(|_| DispatchError::Unavailable)
        }
        WireRequest::DevicesInspect {
            version,
            network_id,
            device_id,
        } => {
            require_version(&version)?;
            let network_id =
                NetworkId::parse(&network_id).map_err(|_| DispatchError::InvalidRequest)?;
            let device_id =
                DeviceId::parse(&device_id).map_err(|_| DispatchError::InvalidRequest)?;
            let device = store.device(device_id).map_err(map_lookup_error)?;
            if device.network_id != network_id {
                return Err(DispatchError::NotFound);
            }
            Ok(WireResponse::device(
                network_id.to_string(),
                DeviceDto::project(store, device)?,
            ))
        }
    }
}

fn require_version(version: &str) -> Result<(), DispatchError> {
    if version == VERSION {
        Ok(())
    } else {
        Err(DispatchError::InvalidRequest)
    }
}

fn map_lookup_error(error: StateError) -> DispatchError {
    match error {
        StateError::NotFound(_) => DispatchError::NotFound,
        _ => DispatchError::Unavailable,
    }
}

#[derive(Serialize)]
struct DeviceDto {
    device_id: String,
    network_id: String,
    display_name: String,
    membership_state: String,
    roles: Roles,
    credential_generation: u64,
    keryx_binding_generation: u64,
    fleet_projection_generation: u64,
    fleet_projection_status: String,
    provider_instance_id: Option<String>,
    provider_node_id: Option<String>,
    durable_trust_state: Option<String>,
    durable_trust_revision: Option<u64>,
    live_trust_evidence: &'static str,
    provider_binding_state: Option<String>,
    provider_binding_revision: Option<u64>,
    keryx_binding_id: Option<String>,
    keryx_binding_state: Option<String>,
    verified_keryx_peer_id: Option<String>,
    keryx_binding_revision: Option<u64>,
    live_keryx_binding_health: &'static str,
    created_at: String,
    updated_at: String,
    revoked_at: Option<String>,
}

impl DeviceDto {
    fn project(store: &StateStore, device: Device) -> Result<Self, DispatchError> {
        let trust = store
            .durable_device_trust(device.device_id)
            .map_err(|_| DispatchError::Unavailable)?;
        let binding = store
            .latest_n6_binding(device.device_id)
            .map_err(|_| DispatchError::Unavailable)?;
        let (provider_instance_id, provider_node_id) = device
            .provider_identity
            .as_ref()
            .map(|identity| {
                (
                    Some(identity.provider_instance_id.to_string()),
                    Some(identity.node_id.to_string()),
                )
            })
            .unwrap_or((None, None));
        let (
            durable_trust_state,
            durable_trust_revision,
            provider_binding_state,
            provider_binding_revision,
        ) = trust_fields(trust.as_ref());
        let (keryx_binding_id, keryx_binding_state, verified_keryx_peer_id, keryx_binding_revision) =
            binding_fields(binding.as_ref());
        Ok(Self {
            device_id: device.device_id.to_string(),
            network_id: device.network_id.to_string(),
            display_name: bounded_text(&device.display_name),
            membership_state: wire_enum_name(device.membership_state.as_str()),
            roles: device.roles,
            credential_generation: device.generations.credential.get(),
            keryx_binding_generation: device.generations.keryx_binding.get(),
            fleet_projection_generation: device.generations.fleet_projection.get(),
            fleet_projection_status: wire_enum_name(device.fleet_projection_status.as_str()),
            provider_instance_id,
            provider_node_id,
            durable_trust_state,
            durable_trust_revision,
            live_trust_evidence: "not_reconciled_by_operator_read",
            provider_binding_state,
            provider_binding_revision,
            keryx_binding_id,
            keryx_binding_state,
            verified_keryx_peer_id,
            keryx_binding_revision,
            live_keryx_binding_health: "not_exposed",
            created_at: device.created_at.to_rfc3339(),
            updated_at: device.updated_at.to_rfc3339(),
            revoked_at: device.revoked_at.map(|at| at.to_rfc3339()),
        })
    }
}

type TrustFields = (Option<String>, Option<u64>, Option<String>, Option<u64>);

fn trust_fields(trust: Option<&DeviceTrustView>) -> TrustFields {
    let Some(trust) = trust else {
        return (None, None, None, None);
    };
    let (provider_state, provider_revision) = trust
        .provider_binding
        .as_ref()
        .map(|binding| {
            (
                Some(wire_enum_name(binding.binding_state.as_str())),
                Some(binding.binding_revision.get()),
            )
        })
        .unwrap_or((None, None));
    (
        Some(wire_enum_name(trust.trust_state.as_str())),
        Some(trust.trust_revision.get()),
        provider_state,
        provider_revision,
    )
}

type BindingFields = (Option<String>, Option<String>, Option<String>, Option<u64>);

fn binding_fields(binding: Option<&N6BindingView>) -> BindingFields {
    let Some(binding) = binding else {
        return (None, None, None, None);
    };
    (
        Some(binding.binding_id.to_string()),
        Some(binding.state.as_str().to_owned()),
        binding.verified_peer_id.as_ref().map(ToString::to_string),
        Some(binding.revision),
    )
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
    devices: Option<Vec<DeviceDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<DeviceDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct Capabilities {
    read_operations: [&'static str; 3],
    mutation_operations: [&'static str; 0],
    max_page_size: usize,
    max_response_bytes: usize,
}

impl WireResponse {
    fn capabilities() -> Self {
        Self {
            version: VERSION,
            response_kind: "capabilities",
            capabilities: Some(Capabilities {
                read_operations: ["capabilities", "devices.list", "devices.inspect"],
                mutation_operations: [],
                max_page_size: DEVICE_PAGE_MAX,
                max_response_bytes: MAX_RESPONSE_BYTES,
            }),
            network_id: None,
            devices: None,
            device: None,
            next_cursor: None,
            error: None,
        }
    }

    fn devices_list(
        network_id: String,
        mut devices: Vec<DeviceDto>,
        requested_limit: usize,
    ) -> Result<Self, ()> {
        let loaded = devices.len();
        loop {
            let next_cursor = (!devices.is_empty()
                && (devices.len() < loaded || loaded == requested_limit))
                .then(|| devices.last().unwrap().device_id.clone());
            let response = Self {
                version: VERSION,
                response_kind: "devices.list",
                capabilities: None,
                network_id: Some(network_id.clone()),
                devices: Some(devices),
                device: None,
                next_cursor,
                error: None,
            };
            if serde_json::to_vec(&response).map_err(|_| ())?.len() <= MAX_RESPONSE_BYTES {
                return Ok(response);
            }
            devices = response.devices.unwrap_or_default();
            if devices.pop().is_none() {
                return Err(());
            }
        }
    }

    fn device(network_id: String, device: DeviceDto) -> Self {
        Self {
            version: VERSION,
            response_kind: "devices.inspect",
            capabilities: None,
            network_id: Some(network_id),
            devices: None,
            device: Some(device),
            next_cursor: None,
            error: None,
        }
    }

    fn error(error: &'static str) -> Self {
        Self {
            version: VERSION,
            response_kind: "error",
            capabilities: None,
            network_id: None,
            devices: None,
            device: None,
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

fn wire_enum_name(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index != 0 {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use nodescale_domain::{
        DeviceId, DeviceTrustState, Generation, JoinSessionId, KeryxBindingId, KeryxBindingState,
        KeryxPeerId, NetworkId,
    };

    #[test]
    fn durable_authority_fields_preserve_state_without_inventing_live_health() {
        assert_eq!(wire_enum_name("FailedRetryable"), "failed_retryable");
        let trust = DeviceTrustView {
            device_id: DeviceId::new(),
            network_id: NetworkId::new(),
            trust_state: DeviceTrustState::Trusted,
            trust_revision: Generation::new(7).unwrap(),
            provider_binding: None,
            currently_trusted: false,
        };
        assert_eq!(
            trust_fields(Some(&trust)),
            (Some("trusted".into()), Some(7), None, None)
        );

        let binding = N6BindingView {
            binding_id: KeryxBindingId::new(),
            network_id: trust.network_id,
            device_id: trust.device_id,
            join_session_id: JoinSessionId::new(),
            verified_peer_id: Some(KeryxPeerId::parse("peer-a").unwrap()),
            generation: Generation::new(9).unwrap(),
            revision: 3,
            state: KeryxBindingState::Active,
            created_at: Utc::now(),
            confirmed_at: Some(Utc::now()),
            stale_at: None,
            rotated_at: None,
            revoked_at: None,
        };
        assert_eq!(
            binding_fields(Some(&binding)),
            (
                Some(binding.binding_id.to_string()),
                Some("active".into()),
                Some("peer-a".into()),
                Some(3),
            )
        );
    }
}
