//! Strictly read-only stock Headscale provider adapter.

use chrono::{DateTime, Utc};
use nodescale_domain::{ProviderApiKey, ProviderIdentity, ProviderInstanceId, ProviderNodeId};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence, MutableIdentityEvidence,
    PreAuthAssociationStrength, PreAuthCorrelationObservation, ProviderCapability, ProviderError,
    ProviderHealth, ProviderHealthStatus, ProviderIdentityEvidence, ProviderNode,
    ProviderUserObservation, ReadOnlyProvider, ServerInspection,
};
use reqwest::{Client, StatusCode, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, time::Duration};
use thiserror::Error;

/// Exact upstream release contract verified for N1A.
pub const PINNED_HEADSCALE_VERSION: &str = "0.29.3";
const MAX_HEADSCALE_NODES: usize = 10_000;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HeadscaleError {
    #[error("malformed Headscale version")]
    MalformedVersion,
    #[error("invalid Headscale endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("failed to construct Headscale HTTP client")]
    ClientConstruction,
}

/// Classify only the exact verified release as fully compatible.
/// Older 0.29.x patches remain observable in degraded mode; all future,
/// prerelease, build-suffixed, and otherwise unknown versions fail closed.
pub fn classify_version(raw: &str) -> Result<CompatibilityStatus, HeadscaleError> {
    let version = Version::parse(raw.strip_prefix('v').unwrap_or(raw))
        .map_err(|_| HeadscaleError::MalformedVersion)?;
    let pinned = Version::parse(PINNED_HEADSCALE_VERSION).expect("pinned version is valid semver");

    if version == pinned {
        Ok(CompatibilityStatus::Compatible)
    } else if version.pre.is_empty()
        && version.build.is_empty()
        && version.major == 0
        && version.minor == 29
        && version.patch < pinned.patch
    {
        Ok(CompatibilityStatus::ReadOnlyDegraded)
    } else {
        Ok(CompatibilityStatus::Unsupported)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadscaleClientOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for HeadscaleClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    Authenticated,
    Failed,
    Unverified,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityFieldAvailability {
    pub headscale_node_id: bool,
    pub machine_key: bool,
    pub node_key: bool,
    pub disco_key: bool,
    pub user_id: bool,
    pub pre_auth_credential_id: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeadscaleDoctorReport {
    pub provider_endpoint: String,
    pub detected_version: Option<String>,
    pub compatibility: CompatibilityStatus,
    pub authentication: AuthenticationState,
    pub node_count: Option<usize>,
    pub capabilities: BTreeSet<ProviderCapability>,
    pub identity_fields: IdentityFieldAvailability,
    pub warnings: Vec<String>,
    pub mutation_allowed: bool,
}

pub struct HeadscaleProvider {
    endpoint: Url,
    instance_id: ProviderInstanceId,
    api_key: ProviderApiKey,
    client: Client,
    max_response_bytes: usize,
}

impl fmt::Debug for HeadscaleProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeadscaleProvider")
            .field("endpoint", &self.endpoint.as_str())
            .field("instance_id", &self.instance_id)
            .field("api_key", &"[REDACTED]")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl HeadscaleProvider {
    pub fn new(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
    ) -> Result<Self, HeadscaleError> {
        Self::build(endpoint, instance_id, api_key, options, false)
    }

    #[cfg(test)]
    fn new_for_test(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
    ) -> Result<Self, HeadscaleError> {
        Self::build(endpoint, instance_id, api_key, options, true)
    }

    fn build(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        allow_http_for_test: bool,
    ) -> Result<Self, HeadscaleError> {
        let mut endpoint = Url::parse(endpoint)
            .map_err(|_| HeadscaleError::InvalidEndpoint("must be an absolute URL"))?;
        if endpoint.scheme() != "https" && !(allow_http_for_test && endpoint.scheme() == "http") {
            return Err(HeadscaleError::InvalidEndpoint("HTTPS is required"));
        }
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(HeadscaleError::InvalidEndpoint(
                "must be an origin without credentials, path, query, or fragment",
            ));
        }
        if options.connect_timeout.is_zero()
            || options.request_timeout.is_zero()
            || options.max_response_bytes == 0
        {
            return Err(HeadscaleError::InvalidEndpoint(
                "timeouts and response bound must be positive",
            ));
        }
        endpoint.set_path("/");
        let client = Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| HeadscaleError::ClientConstruction)?;
        Ok(Self {
            endpoint,
            instance_id,
            api_key,
            client,
            max_response_bytes: options.max_response_bytes,
        })
    }

    #[must_use]
    pub fn sanitized_endpoint(&self) -> String {
        self.endpoint.as_str().trim_end_matches('/').to_owned()
    }

    pub async fn doctor(&self) -> HeadscaleDoctorReport {
        let mut report = HeadscaleDoctorReport {
            provider_endpoint: self.sanitized_endpoint(),
            detected_version: None,
            compatibility: CompatibilityStatus::Unreachable,
            authentication: AuthenticationState::Unverified,
            node_count: None,
            capabilities: BTreeSet::new(),
            identity_fields: IdentityFieldAvailability::default(),
            warnings: Vec::new(),
            mutation_allowed: false,
        };

        match self.inspect_server().await {
            Ok(inspection) => {
                report.detected_version = Some(inspection.provider_version);
                report.compatibility = inspection.compatibility;
                report.authentication = AuthenticationState::Authenticated;
                report.capabilities = inspection.capabilities;
                report.warnings.extend(inspection.constraints);
            }
            Err(error) => {
                report.compatibility = match error {
                    ProviderError::AuthenticationFailed => {
                        CompatibilityStatus::AuthenticationFailed
                    }
                    ProviderError::Timeout
                    | ProviderError::TlsFailure
                    | ProviderError::Unreachable(_) => CompatibilityStatus::Unreachable,
                    _ => CompatibilityStatus::Unsupported,
                };
                if matches!(error, ProviderError::AuthenticationFailed) {
                    report.authentication = AuthenticationState::Failed;
                }
                report.warnings.push(error.to_string());
                return report;
            }
        }

        match self.list_nodes().await {
            Ok(nodes) => {
                report.node_count = Some(nodes.len());
                report.identity_fields.headscale_node_id = !nodes.is_empty();
                report.identity_fields.machine_key = !nodes.is_empty();
                report.identity_fields.node_key = nodes
                    .iter()
                    .any(|node| node.identity_evidence.node_key.is_some());
                report.identity_fields.disco_key = nodes
                    .iter()
                    .any(|node| node.identity_evidence.disco_key.is_some());
                report.identity_fields.user_id = nodes.iter().any(|node| node.user.is_some());
                report.identity_fields.pre_auth_credential_id =
                    nodes.iter().any(|node| node.pre_auth.is_some());
            }
            Err(error) => report
                .warnings
                .push(format!("node inspection failed: {error}")),
        }

        report
    }

    async fn get_bytes(
        &self,
        path: &str,
        authenticated: bool,
    ) -> Result<Option<Vec<u8>>, ProviderError> {
        let url = self
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|_| ProviderError::Rejected("invalid provider API path".into()))?;
        let request = self.client.get(url);
        let request = if authenticated {
            request.bearer_auth(self.api_key.expose_secret())
        } else {
            request
        };
        let mut response = request.send().await.map_err(map_transport_error)?;
        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            return Err(ProviderError::AuthenticationFailed);
        }
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ProviderError::Rejected(format!(
                "provider returned HTTP {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(ProviderError::MalformedResponse(
                "Headscale response exceeds configured bound",
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(ProviderError::MalformedResponse(
                    "Headscale response exceeds configured bound",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    async fn get_required(
        &self,
        path: &str,
        authenticated: bool,
    ) -> Result<Vec<u8>, ProviderError> {
        self.get_bytes(path, authenticated)
            .await?
            .ok_or(ProviderError::MalformedResponse(
                "required Headscale endpoint returned not found",
            ))
    }

    async fn inspect_attempt(&self) -> InspectionAttempt {
        let version_body = match self.get_required("version", false).await {
            Ok(body) => body,
            Err(error) => return InspectionAttempt::failed(error, false),
        };
        let version: RawVersion = match serde_json::from_slice(&version_body) {
            Ok(version) => version,
            Err(_) => {
                return InspectionAttempt::failed(
                    ProviderError::MalformedResponse("invalid Headscale version response"),
                    false,
                );
            }
        };
        let mut compatibility = match classify_version(&version.version) {
            Ok(compatibility) => compatibility,
            Err(_) => {
                return InspectionAttempt::failed(
                    ProviderError::MalformedResponse("malformed Headscale version"),
                    false,
                );
            }
        };
        if version.dirty && compatibility == CompatibilityStatus::Compatible {
            compatibility = CompatibilityStatus::CompatibleWithConstraints;
        }

        let health_body = match self.get_required("api/v1/health", true).await {
            Ok(body) => body,
            Err(error) => return InspectionAttempt::failed(error, false),
        };
        let health: RawHealth = match serde_json::from_slice(&health_body) {
            Ok(health) => health,
            Err(_) => {
                return InspectionAttempt::failed(
                    ProviderError::MalformedResponse("invalid Headscale health response"),
                    true,
                );
            }
        };
        let mut constraints = vec![
            "N1A adapter is strictly read-only".into(),
            "pre-auth association is partial correlation evidence only".into(),
        ];
        if version.dirty {
            constraints.push("Headscale build reports uncommitted source changes".into());
        }
        if !health.database_connectivity {
            compatibility = CompatibilityStatus::ReadOnlyDegraded;
            constraints.push("provider database connectivity is unavailable".into());
        }

        InspectionAttempt {
            result: Ok(ServerInspection {
                provider_name: "headscale".into(),
                provider_version: version.version,
                instance_id: self.instance_id,
                compatibility,
                capabilities: [
                    ProviderCapability::InspectServer,
                    ProviderCapability::ListNodes,
                    ProviderCapability::GetNode,
                    ProviderCapability::Health,
                ]
                .into_iter()
                .collect(),
                constraints,
                mutation_allowed: false,
            }),
            authenticated: true,
        }
    }
}

struct InspectionAttempt {
    result: Result<ServerInspection, ProviderError>,
    authenticated: bool,
}

impl InspectionAttempt {
    fn failed(error: ProviderError, authenticated: bool) -> Self {
        Self {
            result: Err(error),
            authenticated,
        }
    }
}

fn map_transport_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        return ProviderError::Timeout;
    }
    let diagnostic = format!("{error:?}").to_ascii_lowercase();
    if diagnostic.contains("certificate")
        || diagnostic.contains("tls")
        || diagnostic.contains("invalidcontenttype")
        || diagnostic.contains("corrupt message")
    {
        ProviderError::TlsFailure
    } else {
        ProviderError::Unreachable("transport failure".into())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVersion {
    version: String,
    dirty: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawHealth {
    database_connectivity: bool,
}

#[async_trait::async_trait]
impl ReadOnlyProvider for HeadscaleProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        self.inspect_attempt().await.result
    }

    async fn verify_compatibility(&self) -> Result<CompatibilityReport, ProviderError> {
        match self.inspect_server().await {
            Ok(inspection) => Ok(CompatibilityReport::from_inspection(&inspection)),
            Err(error @ ProviderError::AuthenticationFailed) => Ok(CompatibilityReport {
                status: CompatibilityStatus::AuthenticationFailed,
                reason: error.to_string(),
                mutation_allowed: false,
            }),
            Err(
                error @ (ProviderError::Timeout
                | ProviderError::TlsFailure
                | ProviderError::Unreachable(_)),
            ) => Ok(CompatibilityReport {
                status: CompatibilityStatus::Unreachable,
                reason: error.to_string(),
                mutation_allowed: false,
            }),
            Err(error @ ProviderError::MalformedResponse(_)) => Ok(CompatibilityReport {
                status: CompatibilityStatus::Unsupported,
                reason: error.to_string(),
                mutation_allowed: false,
            }),
            Err(error) => Err(error),
        }
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        let body = self.get_required("api/v1/node", true).await?;
        let json = std::str::from_utf8(&body)
            .map_err(|_| ProviderError::MalformedResponse("Headscale node list is not UTF-8"))?;
        parse_nodes_fixture(json, self.instance_id, Utc::now())
    }

    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        if identity.provider_instance_id != self.instance_id {
            return Err(ProviderError::Conflict(
                "provider instance identity mismatch".into(),
            ));
        }
        let path = format!("api/v1/node/{}", identity.node_id);
        let Some(body) = self.get_bytes(&path, true).await? else {
            return Ok(None);
        };
        let json = std::str::from_utf8(&body)
            .map_err(|_| ProviderError::MalformedResponse("Headscale node is not UTF-8"))?;
        let node = parse_node_fixture(json, self.instance_id, Utc::now())?;
        if node.identity != *identity {
            return Err(ProviderError::Conflict(
                "stable Headscale provider identity mismatch".into(),
            ));
        }
        Ok(Some(node))
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        let attempt = self.inspect_attempt().await;
        match attempt.result {
            Ok(inspection) => {
                let healthy = matches!(
                    inspection.compatibility,
                    CompatibilityStatus::Compatible
                        | CompatibilityStatus::CompatibleWithConstraints
                );
                Ok(ProviderHealth {
                    status: if healthy {
                        ProviderHealthStatus::Healthy
                    } else {
                        ProviderHealthStatus::ReachableIncompatible
                    },
                    reachable: true,
                    authenticated: true,
                    detail: if healthy {
                        "Headscale API is reachable and authenticated".into()
                    } else {
                        "Headscale API is reachable but compatibility is constrained".into()
                    },
                })
            }
            Err(error) => Ok(health_from_error(&error, attempt.authenticated)),
        }
    }
}

fn health_from_error(error: &ProviderError, authenticated_response: bool) -> ProviderHealth {
    let (status, reachable, authenticated, detail) = match error {
        ProviderError::AuthenticationFailed => (
            ProviderHealthStatus::AuthenticationFailed,
            true,
            false,
            "Headscale API authentication failed",
        ),
        ProviderError::Timeout => (
            ProviderHealthStatus::Timeout,
            false,
            false,
            "Headscale API request timed out",
        ),
        ProviderError::TlsFailure => (
            ProviderHealthStatus::TlsFailure,
            false,
            false,
            "Headscale TLS verification failed",
        ),
        ProviderError::MalformedResponse(_) => (
            ProviderHealthStatus::MalformedResponse,
            true,
            authenticated_response,
            "Headscale returned a malformed response",
        ),
        _ => (
            ProviderHealthStatus::TransportFailure,
            false,
            false,
            "Headscale transport failed",
        ),
    };
    ProviderHealth {
        status,
        reachable,
        authenticated,
        detail: detail.into(),
    }
}

#[derive(Deserialize)]
struct RawNodeList {
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawNodeEnvelope {
    node: RawNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawNode {
    id: String,
    machine_key: String,
    #[serde(default)]
    node_key: String,
    #[serde(default)]
    disco_key: String,
    #[serde(default)]
    ip_addresses: Vec<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    given_name: String,
    user: Option<RawUser>,
    pre_auth_key: Option<RawPreAuthKey>,
    created_at: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    expiry: Option<DateTime<Utc>>,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    tags: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUser {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Deserialize)]
struct RawPreAuthKey {
    id: String,
}

fn parse_nodes_fixture(
    json: &str,
    instance_id: ProviderInstanceId,
    observed_at: DateTime<Utc>,
) -> Result<Vec<ProviderNode>, ProviderError> {
    let response: RawNodeList = serde_json::from_str(json)
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale node list JSON"))?;
    if response.nodes.len() > MAX_HEADSCALE_NODES {
        return Err(ProviderError::MalformedResponse(
            "Headscale node list exceeds configured count bound",
        ));
    }
    let mut nodes = response
        .nodes
        .into_iter()
        .map(|node| normalize_node(node, instance_id, observed_at))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    if nodes
        .iter()
        .any(|node| !seen.insert(node.identity.node_id.to_string()))
    {
        return Err(ProviderError::MalformedResponse(
            "duplicate Headscale node ID",
        ));
    }
    nodes.sort_by_key(|node| {
        node.identity
            .node_id
            .as_str()
            .parse::<u64>()
            .expect("normalized Headscale IDs are canonical uint64 values")
    });
    Ok(nodes)
}

fn parse_node_fixture(
    json: &str,
    instance_id: ProviderInstanceId,
    observed_at: DateTime<Utc>,
) -> Result<ProviderNode, ProviderError> {
    let response: RawNodeEnvelope = serde_json::from_str(json)
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale node JSON"))?;
    normalize_node(response.node, instance_id, observed_at)
}

fn normalize_node(
    raw: RawNode,
    instance_id: ProviderInstanceId,
    observed_at: DateTime<Utc>,
) -> Result<ProviderNode, ProviderError> {
    let numeric_node_id = raw
        .id
        .parse::<u64>()
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale node ID"))?;
    if numeric_node_id == 0 || numeric_node_id.to_string() != raw.id {
        return Err(ProviderError::MalformedResponse(
            "Headscale node ID must be a canonical positive uint64",
        ));
    }
    let node_id = ProviderNodeId::parse(numeric_node_id.to_string())
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale node ID"))?;
    let machine_key = ConditionalIdentityEvidence::new(raw.machine_key)
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale machine key"))?;
    let fingerprint = Sha256::digest(machine_key.as_str().as_bytes());
    let fingerprint = format!("sha256:{fingerprint:x}");
    let identity = ProviderIdentity::new(instance_id, node_id, fingerprint)
        .map_err(|_| ProviderError::MalformedResponse("invalid Headscale provider identity"))?;
    let node_key = optional_mutable(raw.node_key)?;
    let disco_key = optional_mutable(raw.disco_key)?;
    let user = raw.user.map(|user| ProviderUserObservation {
        id: user.id,
        name: user.name,
        display_name: user.display_name,
    });
    let pre_auth = raw
        .pre_auth_key
        .map(|key| {
            canonical_positive_u64(&key.id, "invalid Headscale pre-auth key ID").map(
                |credential_id| PreAuthCorrelationObservation {
                    credential_id,
                    association: PreAuthAssociationStrength::Partial,
                },
            )
        })
        .transpose()?;
    let expired = raw.expiry.is_some_and(|expiry| expiry <= observed_at);

    Ok(ProviderNode {
        identity,
        identity_evidence: ProviderIdentityEvidence {
            machine_key,
            node_key,
            disco_key,
        },
        hostname: raw.name,
        given_name: raw.given_name,
        addresses: raw.ip_addresses,
        user,
        pre_auth,
        tags: raw.tags,
        registered_at: raw.created_at,
        last_seen: raw.last_seen,
        expires_at: raw.expiry,
        observed_at,
        online: raw.online,
        expired,
    })
}

fn optional_mutable(value: String) -> Result<Option<MutableIdentityEvidence>, ProviderError> {
    if value.is_empty() {
        Ok(None)
    } else {
        MutableIdentityEvidence::new(value)
            .map(Some)
            .map_err(|_| ProviderError::MalformedResponse("invalid mutable Headscale key"))
    }
}

fn canonical_positive_u64(value: &str, error: &'static str) -> Result<String, ProviderError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ProviderError::MalformedResponse(error))?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(ProviderError::MalformedResponse(error));
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests;
