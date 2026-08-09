//! Typed Nodescale client for Fleet's local managed-projection V1 UDS contract.
//!
//! This crate owns only the credential-free wire boundary. Fleet authenticates
//! the connected Unix peer with `SO_PEERCRED`; no request DTO can select an
//! identity or privilege.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

/// The only supported Fleet local-control schema revision.
pub const SCHEMA: &str = "fleet.managed-projection.v1";
/// Both request and response documents are bounded before JSON parsing.
pub const MAX_FRAME_BYTES: usize = 32_768;
/// Fleet's local-control contract has a finite, non-configurable I/O budget.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Closed request kinds Fleet advertises and accepts for this schema revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Capabilities,
    Apply,
    Inspect,
}

/// The closed capabilities result returned by Fleet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub kinds: Vec<RequestKind>,
}

/// The only authority source accepted by Fleet V1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProjectionSource {
    #[serde(rename = "nodescale")]
    Nodescale,
}

/// The only generated Fleet operation grants accepted by Fleet V1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GeneratedOperation {
    #[serde(rename = "fleet.health")]
    Health,
    #[serde(rename = "fleet.inventory")]
    Inventory,
    #[serde(rename = "fleet.message")]
    Message,
}

impl GeneratedOperation {
    const fn as_wire(self) -> &'static str {
        match self {
            Self::Health => "fleet.health",
            Self::Inventory => "fleet.inventory",
            Self::Message => "fleet.message",
        }
    }
}

/// A Fleet-managed projection transition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyOperation {
    Upsert,
    Disable,
    Remove,
}

/// The exact local-control provenance object accepted by Fleet's UDS parser.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: ProjectionSource,
    pub network_id: String,
    pub device_id: String,
    pub snapshot: String,
}

impl Provenance {
    #[must_use]
    pub fn new(
        network_id: impl Into<String>,
        device_id: impl Into<String>,
        snapshot: impl Into<String>,
    ) -> Self {
        Self {
            source: ProjectionSource::Nodescale,
            network_id: network_id.into(),
            device_id: device_id.into(),
            snapshot: snapshot.into(),
        }
    }
}

/// The closed complete document supplied with an apply request.
///
/// All fields are strings, enums, or string-enum arrays. Consequently its
/// serializer cannot emit a JSON number, `null`, or an unknown request field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDocument {
    pub source: ProjectionSource,
    pub network_id: String,
    pub device_id: String,
    pub projection_generation: String,
    pub membership_generation: String,
    pub binding_generation: String,
    pub content_hash: String,
    pub operation: ApplyOperation,
    pub generated_operations: Vec<GeneratedOperation>,
    pub provenance: Provenance,
}

/// The three independently durable generation values for one projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionGenerations {
    pub projection: String,
    pub membership: String,
    pub binding: String,
}

impl ProjectionGenerations {
    #[must_use]
    pub fn new(
        projection: impl Into<String>,
        membership: impl Into<String>,
        binding: impl Into<String>,
    ) -> Self {
        Self {
            projection: projection.into(),
            membership: membership.into(),
            binding: binding.into(),
        }
    }
}

impl ProjectionDocument {
    /// Build a canonical V1 document and calculate the hash Fleet validates.
    #[must_use]
    pub fn new(
        network_id: impl Into<String>,
        device_id: impl Into<String>,
        generations: ProjectionGenerations,
        operation: ApplyOperation,
        mut generated_operations: Vec<GeneratedOperation>,
        provenance: Provenance,
    ) -> Self {
        generated_operations.sort_unstable_by_key(|operation| operation.as_wire());
        generated_operations.dedup();
        let mut document = Self {
            source: ProjectionSource::Nodescale,
            network_id: network_id.into(),
            device_id: device_id.into(),
            projection_generation: generations.projection,
            membership_generation: generations.membership,
            binding_generation: generations.binding,
            content_hash: String::new(),
            operation,
            generated_operations,
            provenance,
        };
        document.content_hash = document.canonical_content_hash();
        document
    }

    /// SHA-256 of Fleet's actual canonical hash preimage.
    ///
    /// Fleet removes `content_hash` from the complete projection material,
    /// sorts object keys, uses compact separators, and serializes non-ASCII
    /// text with lowercase ASCII `\\uXXXX` escapes before hashing. It also
    /// canonicalizes generated operation order before constructing the preimage.
    #[must_use]
    pub fn canonical_content_hash(&self) -> String {
        let mut generated_operations: Vec<_> = self
            .generated_operations
            .iter()
            .copied()
            .map(GeneratedOperation::as_wire)
            .collect();
        generated_operations.sort_unstable();
        let material = CanonicalProjectionMaterial {
            source: self.source,
            network_id: &self.network_id,
            device_id: &self.device_id,
            projection_generation: &self.projection_generation,
            membership_generation: &self.membership_generation,
            binding_generation: &self.binding_generation,
            operation: self.operation,
            generated_operations,
            provenance: &self.provenance,
        };
        let value = serde_json::to_value(material)
            .expect("closed canonical projection material is serializable");
        let mut canonical = String::new();
        write_canonical_json(&value, &mut canonical);
        format!("{:x}", Sha256::digest(canonical.as_bytes()))
    }
}

/// Return Fleet V1's SHA-256 canonical content hash for a complete apply document.
#[must_use]
pub fn canonical_content_hash(document: &ProjectionDocument) -> String {
    document.canonical_content_hash()
}

#[derive(Serialize)]
struct CanonicalProjectionMaterial<'a> {
    source: ProjectionSource,
    network_id: &'a str,
    device_id: &'a str,
    projection_generation: &'a str,
    membership_generation: &'a str,
    binding_generation: &'a str,
    operation: ApplyOperation,
    generated_operations: Vec<&'static str>,
    provenance: &'a Provenance,
}

/// Typed durable apply outcomes returned by the current Fleet V1 store.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Applied,
    AlreadyApplied,
    Stale,
    Gap,
    Conflict,
}

/// The closed receipt from a completed apply request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApplyResult {
    pub outcome: ApplyOutcome,
}

/// Closed selector for Fleet's authoritative durable read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectSelector {
    pub source: ProjectionSource,
    pub network_id: String,
    pub device_id: String,
}

impl InspectSelector {
    #[must_use]
    pub fn new(network_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            source: ProjectionSource::Nodescale,
            network_id: network_id.into(),
            device_id: device_id.into(),
        }
    }
}

/// Durable generated member states returned by Fleet inspect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GeneratedStateKind {
    Active,
    Disabled,
    Removed,
}

/// Fleet's durable generated state for an exact identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GeneratedState {
    pub state: GeneratedStateKind,
    pub projection_generation: String,
    pub membership_generation: String,
    pub binding_generation: String,
    pub content_hash: String,
    pub allowed_operations: Vec<GeneratedOperation>,
    pub provenance: Provenance,
}

/// Fleet's effective authorization after local operator denial precedence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveState {
    pub state: GeneratedStateKind,
    pub allowed_operations: Vec<GeneratedOperation>,
    pub operator_denied_operations: Vec<GeneratedOperation>,
}

/// Fleet's authoritative durable read-back. A missing identity is represented
/// by `generated: None, effective: None` exactly as Fleet returns it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InspectResult {
    pub generated: Option<GeneratedState>,
    pub effective: Option<EffectiveState>,
}

/// Apply errors retain the retry-safety boundary of a durable write.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApplyError {
    #[error("Fleet local control socket was unavailable before apply was sent")]
    Unavailable,
    #[error("apply request was rejected before it could be sent")]
    RejectedBeforeSend,
    #[error("Fleet rejected the request with a typed protocol response")]
    ProtocolRejected,
    #[error("apply outcome is ambiguous; inspect Fleet durable state before retrying")]
    Ambiguous,
}

/// Fail-closed errors emitted before a typed operation result is available.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FleetClientError {
    #[error("Fleet local control socket is unavailable")]
    Unavailable,
    #[error("Fleet local control response was lost or timed out")]
    ResponseLost,
    #[error("Fleet rejected the request with a typed protocol response")]
    ProtocolRejected,
    #[error("Fleet local control response violated the V1 protocol")]
    Protocol,
    #[error("Fleet local control frame exceeds {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge,
}

/// Production async client for Fleet's authenticated local UDS boundary.
#[derive(Clone, Debug)]
pub struct FleetClient {
    socket_path: PathBuf,
}

impl FleetClient {
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Read Fleet's versioned supported request-kind set.
    pub async fn capabilities(&self) -> Result<Capabilities, FleetClientError> {
        let result = self
            .round_trip(&CapabilitiesRequest::new(), RequestKind::Capabilities)
            .await?;
        serde_json::from_value(result).map_err(|_| FleetClientError::Protocol)
    }

    /// Apply one projection document.
    ///
    /// A connection failure before the request is written is unavailable. Once
    /// connected, any non-typed transport/protocol failure is ambiguous and the
    /// caller must inspect rather than blindly replaying the write.
    pub async fn apply(&self, document: ProjectionDocument) -> Result<ApplyResult, ApplyError> {
        let result = self
            .round_trip(
                &ApplyRequest {
                    schema: SCHEMA,
                    kind: RequestKind::Apply,
                    document,
                },
                RequestKind::Apply,
            )
            .await
            .map_err(map_apply_error)?;
        serde_json::from_value(result).map_err(|_| ApplyError::Ambiguous)
    }

    /// Read Fleet's authoritative generated and effective durable state.
    pub async fn inspect(
        &self,
        selector: InspectSelector,
    ) -> Result<InspectResult, FleetClientError> {
        let result = self
            .round_trip(
                &InspectRequest {
                    schema: SCHEMA,
                    kind: RequestKind::Inspect,
                    selector,
                },
                RequestKind::Inspect,
            )
            .await?;
        serde_json::from_value(result).map_err(|_| FleetClientError::Protocol)
    }

    async fn round_trip<Request>(
        &self,
        request: &Request,
        expected_kind: RequestKind,
    ) -> Result<Value, FleetClientError>
    where
        Request: Serialize,
    {
        let payload = serde_json::to_vec(request).map_err(|_| FleetClientError::Protocol)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(FleetClientError::FrameTooLarge);
        }

        let response = timeout(REQUEST_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|_| FleetClientError::Unavailable)?;
            stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .await
                .map_err(|_| FleetClientError::ResponseLost)?;
            stream
                .write_all(&payload)
                .await
                .map_err(|_| FleetClientError::ResponseLost)?;
            // Fleet dispatches only after the request's write half is closed.
            // This remains inside the one total request deadline, and a close
            // failure is a post-send transport failure: apply maps it to
            // Ambiguous while read-only requests retain ResponseLost.
            stream
                .shutdown()
                .await
                .map_err(|_| FleetClientError::ResponseLost)?;

            let mut header = [0_u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|_| FleetClientError::ResponseLost)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(FleetClientError::Protocol);
            }
            let mut document = vec![0_u8; length];
            stream
                .read_exact(&mut document)
                .await
                .map_err(|_| FleetClientError::ResponseLost)?;
            Ok(document)
        })
        .await
        .map_err(|_| FleetClientError::ResponseLost)??;

        let envelope: ResponseEnvelope =
            serde_json::from_slice(&response).map_err(|_| FleetClientError::Protocol)?;
        envelope.result_for(expected_kind)
    }
}

#[derive(Serialize)]
struct CapabilitiesRequest {
    schema: &'static str,
    kind: RequestKind,
}

impl CapabilitiesRequest {
    const fn new() -> Self {
        Self {
            schema: SCHEMA,
            kind: RequestKind::Capabilities,
        }
    }
}

#[derive(Serialize)]
struct ApplyRequest {
    schema: &'static str,
    kind: RequestKind,
    document: ProjectionDocument,
}

#[derive(Serialize)]
struct InspectRequest {
    schema: &'static str,
    kind: RequestKind,
    selector: InspectSelector,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    schema: String,
    kind: String,
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

impl ResponseEnvelope {
    fn result_for(self, expected_kind: RequestKind) -> Result<Value, FleetClientError> {
        if self.schema != SCHEMA {
            return Err(FleetClientError::Protocol);
        }
        if !self.ok
            && self.kind == "error"
            && self.error.as_deref() == Some("invalid_request")
            && self.result.is_none()
        {
            return Err(FleetClientError::ProtocolRejected);
        }
        if self.ok && self.kind == expected_kind.as_wire() && self.error.is_none() {
            return self.result.ok_or(FleetClientError::Protocol);
        }
        Err(FleetClientError::Protocol)
    }
}

impl RequestKind {
    const fn as_wire(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Apply => "apply",
            Self::Inspect => "inspect",
        }
    }
}

fn map_apply_error(error: FleetClientError) -> ApplyError {
    match error {
        FleetClientError::Unavailable => ApplyError::Unavailable,
        FleetClientError::FrameTooLarge => ApplyError::RejectedBeforeSend,
        FleetClientError::ProtocolRejected => ApplyError::ProtocolRejected,
        FleetClientError::ResponseLost | FleetClientError::Protocol => ApplyError::Ambiguous,
    }
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => write_ascii_json_string(value, output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_ascii_json_string(key, output);
                output.push(':');
                write_canonical_json(value, output);
            }
            output.push('}');
        }
    }
}

fn write_ascii_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0C}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_ascii_graphic() || character == ' ' => output.push(character),
            character => {
                for code_unit in character.encode_utf16(&mut [0; 2]) {
                    write!(output, "\\u{code_unit:04x}")
                        .expect("writing into a string cannot fail");
                }
            }
        }
    }
    output.push('"');
}
