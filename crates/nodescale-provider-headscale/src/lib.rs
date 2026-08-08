//! Strictly read-only stock Headscale provider adapter.

use chrono::{DateTime, Utc};
use nodescale_domain::{
    Generation, NetworkId, ProviderApiKey, ProviderCredentialReference, ProviderIdentity,
    ProviderInstanceId, ProviderJoinCredential, ProviderNodeId,
};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence,
    HeadscaleMutationAuthorization, HeadscaleMutationAuthorizationContext, IssuedJoinCredential,
    MutableIdentityEvidence, MutationAmbiguity, MutationEvidence, MutationOutcome,
    MutationPolicyMode, MutationProvider, MutationTags, PreAuthAssociationStrength,
    PreAuthCorrelationObservation, ProviderCapability, ProviderError, ProviderHealth,
    ProviderHealthStatus, ProviderIdentityEvidence, ProviderMutation, ProviderNode,
    ProviderUserObservation, ReadOnlyProvider, ServerInspection,
};
use reqwest::{Client, StatusCode, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, io::Read, path::PathBuf, time::Duration};
use thiserror::Error;
use zeroize::Zeroizing;

/// Exact upstream release contract verified for N1A.
pub const PINNED_HEADSCALE_VERSION: &str = "0.29.3";
/// Exact, sanitized fallback for policy modes other than Headscale's official
/// database policy mode. File mode intentionally remains mutation-disabled.
pub const POLICY_MUTATION_UNSUPPORTED: &str = "policy mutation unsupported";
const MAX_HEADSCALE_NODES: usize = 10_000;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HeadscaleError {
    #[error("malformed Headscale version")]
    MalformedVersion,
    #[error("invalid Headscale endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("failed to construct Headscale HTTP client")]
    ClientConstruction,
    #[error("custom root CA could not be read")]
    CustomRootCaUnreadable,
    #[error("custom root CA exceeds configured bound")]
    CustomRootCaTooLarge,
    #[error("custom root CA must contain exactly one PEM certificate")]
    CustomRootCaMalformed,
    #[error("custom root certificate is not a certificate authority")]
    CustomRootCaNotCertificateAuthority,
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

pub const MAX_CUSTOM_ROOT_CA_BYTES: usize = 64 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub enum HeadscaleCustomRootCa {
    PemBytes(Vec<u8>),
    PemFile(PathBuf),
}
impl fmt::Debug for HeadscaleCustomRootCa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PemBytes(_) => "HeadscaleCustomRootCa::PemBytes([REDACTED])",
            Self::PemFile(_) => "HeadscaleCustomRootCa::PemFile([REDACTED])",
        })
    }
}
impl HeadscaleCustomRootCa {
    /// Materialize the bounded PEM bytes once so callers can bind and then use
    /// the same bytes without a file-path time-of-check/time-of-use gap.
    pub fn into_pem_bytes_and_sha256(self) -> Result<(Vec<u8>, String), HeadscaleError> {
        let bytes = read_custom_root_ca(self)?;
        let fingerprint = format!("sha256:{:x}", Sha256::digest(&bytes));
        Ok((bytes, fingerprint))
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

fn read_custom_root_ca(source: HeadscaleCustomRootCa) -> Result<Vec<u8>, HeadscaleError> {
    match source {
        HeadscaleCustomRootCa::PemBytes(bytes) => {
            if bytes.len() > MAX_CUSTOM_ROOT_CA_BYTES {
                return Err(HeadscaleError::CustomRootCaTooLarge);
            }
            if bytes.is_empty() {
                return Err(HeadscaleError::CustomRootCaMalformed);
            }
            Ok(bytes)
        }
        HeadscaleCustomRootCa::PemFile(path) => {
            let metadata =
                std::fs::metadata(&path).map_err(|_| HeadscaleError::CustomRootCaUnreadable)?;
            if !metadata.is_file() {
                return Err(HeadscaleError::CustomRootCaUnreadable);
            }
            if metadata.len() > MAX_CUSTOM_ROOT_CA_BYTES as u64 {
                return Err(HeadscaleError::CustomRootCaTooLarge);
            }
            let file =
                std::fs::File::open(path).map_err(|_| HeadscaleError::CustomRootCaUnreadable)?;
            let mut bytes = Vec::new();
            file.take((MAX_CUSTOM_ROOT_CA_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| HeadscaleError::CustomRootCaUnreadable)?;
            if bytes.len() > MAX_CUSTOM_ROOT_CA_BYTES {
                return Err(HeadscaleError::CustomRootCaTooLarge);
            }
            if bytes.is_empty() {
                return Err(HeadscaleError::CustomRootCaMalformed);
            }
            Ok(bytes)
        }
    }
}

fn validated_custom_root(pem_bytes: &[u8]) -> Result<reqwest::Certificate, HeadscaleError> {
    use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

    let trimmed = pem_bytes
        .strip_prefix(&[])
        .unwrap_or(pem_bytes)
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|start| &pem_bytes[start..])
        .ok_or(HeadscaleError::CustomRootCaMalformed)?;
    let (remaining, pem) =
        parse_x509_pem(trimmed).map_err(|_| HeadscaleError::CustomRootCaMalformed)?;
    if pem.label != "CERTIFICATE" || remaining.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(HeadscaleError::CustomRootCaMalformed);
    }
    let (der_remaining, certificate) =
        parse_x509_certificate(&pem.contents).map_err(|_| HeadscaleError::CustomRootCaMalformed)?;
    if !der_remaining.is_empty() {
        return Err(HeadscaleError::CustomRootCaMalformed);
    }
    let is_ca = certificate
        .basic_constraints()
        .map_err(|_| HeadscaleError::CustomRootCaMalformed)?
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(HeadscaleError::CustomRootCaNotCertificateAuthority);
    }
    reqwest::Certificate::from_pem(trimmed).map_err(|_| HeadscaleError::CustomRootCaMalformed)
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
        Self::build(endpoint, instance_id, api_key, options, false, None)
    }

    pub fn new_with_custom_root_ca(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        custom_root_ca: HeadscaleCustomRootCa,
    ) -> Result<Self, HeadscaleError> {
        Self::build(
            endpoint,
            instance_id,
            api_key,
            options,
            false,
            Some(custom_root_ca),
        )
    }

    #[cfg(test)]
    fn new_for_test(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
    ) -> Result<Self, HeadscaleError> {
        Self::build(endpoint, instance_id, api_key, options, true, None)
    }

    fn build(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        allow_http_for_test: bool,
        custom_root_ca: Option<HeadscaleCustomRootCa>,
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
        let mut client_builder = Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(custom_root_ca) = custom_root_ca {
            let root_pem = read_custom_root_ca(custom_root_ca)?;
            let root = validated_custom_root(&root_pem)?;
            client_builder = client_builder.add_root_certificate(root);
        }
        let client = client_builder
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
            self.api_key.expose(|api_key| request.bearer_auth(api_key))
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

    /// Singular authoritative node reads intentionally do not
    /// inherit the broad read-only "any 404 is absent" convenience behavior.
    /// Only Headscale's authenticated, resource-specific grpc-gateway envelope
    /// is evidence that a node is absent; a route miss, proxy response, or
    /// malformed body remains an error and cannot confirm deletion.
    async fn get_exact_node_bytes(&self, path: &str) -> Result<Option<Vec<u8>>, ProviderError> {
        let url = self
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|_| ProviderError::Rejected("invalid provider API path".into()))?;
        let request = self
            .api_key
            .expose(|api_key| self.client.get(url).bearer_auth(api_key));
        let mut response = request.send().await.map_err(map_transport_error)?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ProviderError::AuthenticationFailed);
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(ProviderError::MalformedResponse(
                "Headscale response exceeds configured bound",
            ));
        }
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(ProviderError::MalformedResponse(
                    "Headscale response exceeds configured bound",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        match status {
            StatusCode::NOT_FOUND if is_exact_node_absence(&body) => Ok(None),
            StatusCode::NOT_FOUND => Err(ProviderError::MalformedResponse(
                "node 404 is not the exact Headscale absence envelope",
            )),
            status if status.is_success() => Ok(Some(body)),
            status => Err(ProviderError::Rejected(format!(
                "provider returned HTTP {}",
                status.as_u16()
            ))),
        }
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
            "pre-auth association is authenticated provider-registration evidence only; it is never Nodescale trust".into(),
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

#[derive(Deserialize)]
struct RawGrpcGatewayError {
    code: i32,
    message: String,
    details: Vec<serde_json::Value>,
}

fn is_exact_node_absence(body: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<RawGrpcGatewayError>(body),
        Ok(error) if error.code == 5 && error.message == "node not found" && error.details.is_empty()
    )
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
        let Some(body) = self.get_exact_node_bytes(&path).await? else {
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

/// Non-authoritative transport facts that bind a state-issued token to this
/// adapter instance. It carries no enablement or capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadscaleMutationTransport {
    network_id: NetworkId,
    authorization_generation: Generation,
    configuration_generation: Generation,
    configuration_fingerprint: String,
    policy_mode: MutationPolicyMode,
}
impl HeadscaleMutationTransport {
    #[must_use]
    pub fn new(
        network_id: NetworkId,
        authorization_generation: Generation,
        configuration_generation: Generation,
        configuration_fingerprint: impl Into<String>,
        policy_mode: MutationPolicyMode,
    ) -> Self {
        Self {
            network_id,
            authorization_generation,
            configuration_generation,
            configuration_fingerprint: configuration_fingerprint.into(),
            policy_mode,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeadscalePolicySnapshot {
    pub policy: String,
    pub revision: String,
}

impl fmt::Debug for HeadscalePolicySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeadscalePolicySnapshot")
            .field("policy", &"[REDACTED]")
            .field("revision", &self.revision)
            .finish()
    }
}

/// Explicitly constructed v0.29.3 mutation capability. It is intentionally
/// not implemented by `HeadscaleProvider`, preserving that type's read-only
/// contract for existing import/reconciliation callers.
pub struct HeadscaleMutationProvider<A> {
    inner: HeadscaleProvider,
    transport: HeadscaleMutationTransport,
    authorization: std::marker::PhantomData<fn(A)>,
}
impl<A> std::fmt::Debug for HeadscaleMutationProvider<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadscaleMutationProvider")
            .field("endpoint", &self.inner.sanitized_endpoint())
            .field("instance_id", &self.inner.instance_id)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}
impl<A> HeadscaleMutationProvider<A> {
    pub fn new(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        transport: HeadscaleMutationTransport,
    ) -> Result<Self, HeadscaleError> {
        Ok(Self {
            inner: HeadscaleProvider::new(endpoint, instance_id, api_key, options)?,
            transport,
            authorization: std::marker::PhantomData,
        })
    }

    pub fn new_with_custom_root_ca(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        transport: HeadscaleMutationTransport,
        custom_root_ca: HeadscaleCustomRootCa,
    ) -> Result<Self, HeadscaleError> {
        Ok(Self {
            inner: HeadscaleProvider::new_with_custom_root_ca(
                endpoint,
                instance_id,
                api_key,
                options,
                custom_root_ca,
            )?,
            transport,
            authorization: std::marker::PhantomData,
        })
    }

    pub async fn inspect_policy(&self) -> Result<HeadscalePolicySnapshot, MutationOutcome> {
        self.readiness().await?;
        let policy = self.policy().await?.policy;
        Ok(HeadscalePolicySnapshot {
            revision: policy_revision(&policy),
            policy,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        endpoint: &str,
        instance_id: ProviderInstanceId,
        api_key: ProviderApiKey,
        options: HeadscaleClientOptions,
        transport: HeadscaleMutationTransport,
    ) -> Result<Self, HeadscaleError> {
        Ok(Self {
            inner: HeadscaleProvider::new_for_test(endpoint, instance_id, api_key, options)?,
            transport,
            authorization: std::marker::PhantomData,
        })
    }

    async fn readiness(&self) -> Result<(), MutationOutcome> {
        let version = self
            .inner
            .get_required("version", false)
            .await
            .map_err(outcome_from_error)?;
        let version: RawVersion =
            serde_json::from_slice(&version).map_err(|_| MutationOutcome::CompatibilityBlocked)?;
        if version.dirty || version.version != format!("v{PINNED_HEADSCALE_VERSION}") {
            return Err(MutationOutcome::CompatibilityBlocked);
        }
        let health = self
            .inner
            .get_required("api/v1/health", true)
            .await
            .map_err(outcome_from_error)?;
        let health: RawHealth =
            serde_json::from_slice(&health).map_err(|_| MutationOutcome::CompatibilityBlocked)?;
        if !health.database_connectivity {
            return Err(MutationOutcome::CompatibilityBlocked);
        }
        Ok(())
    }

    async fn write_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let url = self
            .inner
            .endpoint
            .join(path.trim_start_matches('/'))
            .map_err(|_| ProviderError::Rejected("invalid provider API path".into()))?;
        let request = self.inner.client.request(method, url);
        let mut request = self
            .inner
            .api_key
            .expose(|api_key| request.bearer_auth(api_key));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(map_transport_error)?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ProviderError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(ProviderError::Rejected(format!(
                "provider returned HTTP {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.inner.max_response_bytes as u64)
        {
            return Err(ProviderError::MalformedResponse(
                "Headscale response exceeds configured bound",
            ));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            if body.len().saturating_add(chunk.len()) > self.inner.max_response_bytes {
                return Err(ProviderError::MalformedResponse(
                    "Headscale response exceeds configured bound",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn pre_node(
        &self,
        target: &ProviderIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<Option<ProviderNode>, MutationOutcome> {
        if target.provider_instance_id != self.inner.instance_id {
            return Err(MutationOutcome::Conflict);
        }
        let path = format!("api/v1/node/{}", target.node_id.as_str());
        let Some(body) = self
            .inner
            .get_exact_node_bytes(&path)
            .await
            .map_err(outcome_from_error)?
        else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&body).map_err(|_| MutationOutcome::Rejected)?;
        let node = parse_node_fixture(text, self.inner.instance_id, observed_at)
            .map_err(outcome_from_error)?;
        if node.identity != *target {
            return Err(MutationOutcome::Conflict);
        }
        Ok(Some(node))
    }

    async fn policy(&self) -> Result<RawPolicy, MutationOutcome> {
        let body = self
            .inner
            .get_required("api/v1/policy", true)
            .await
            .map_err(outcome_from_error)?;
        serde_json::from_slice(&body).map_err(|_| MutationOutcome::Rejected)
    }

    /// Headscale can expose legacy plaintext keys from this endpoint. Keep the
    /// complete bounded body in a zeroizing owner even though the list DTO
    /// deliberately ignores `key`.
    async fn pre_auth_list(&self) -> Result<Vec<RawPreAuthKeyList>, ProviderError> {
        let body = self
            .write_json(reqwest::Method::GET, "api/v1/preauthkey", None)
            .await?;
        parse_pre_auth_list(&body)
            .map_err(|_| ProviderError::MalformedResponse("invalid Headscale pre-auth key list"))
    }
}

#[async_trait::async_trait]
impl<A: HeadscaleMutationAuthorization> MutationProvider for HeadscaleMutationProvider<A> {
    type Authorization = A;

    fn instance_id(&self) -> ProviderInstanceId {
        self.inner.instance_id
    }

    async fn execute_mutation(
        &self,
        authorization: Self::Authorization,
        mutation: ProviderMutation,
    ) -> MutationOutcome {
        let now = Utc::now();
        let capability = mutation.capability();
        if matches!(mutation, ProviderMutation::ApplyPolicy { .. })
            && !matches!(self.transport.policy_mode, MutationPolicyMode::Database)
        {
            let _ = POLICY_MUTATION_UNSUPPORTED;
            return MutationOutcome::Unsupported;
        }
        // Consume state-owned authorization before any local transport or
        // network request. Runtime version/health evidence follows below.
        if authorization
            .validate_for_headscale(HeadscaleMutationAuthorizationContext {
                network_id: self.transport.network_id,
                provider_instance_id: self.inner.instance_id,
                authorization_generation: self.transport.authorization_generation,
                configuration_generation: self.transport.configuration_generation,
                configuration_fingerprint: self.transport.configuration_fingerprint.clone(),
                version: "v0.29.3".into(),
                dirty: false,
                capability,
                policy_mode: self.transport.policy_mode,
                now,
            })
            .is_err()
        {
            return MutationOutcome::Rejected;
        }
        if let Err(outcome) = local_intent_outcome(&mutation, now) {
            return outcome;
        }
        if let Err(outcome) = self.readiness().await {
            return outcome;
        }
        match mutation {
            ProviderMutation::EnsureNetworkPrincipal { principal } => {
                let name_path = format!("api/v1/user?name={principal}");
                let before = match self.inner.get_required(&name_path, true).await {
                    Ok(body) => match parse_users(&body) {
                        Ok(users) => users,
                        Err(()) => return MutationOutcome::Rejected,
                    },
                    Err(error) => return outcome_from_error(error),
                };
                if before.len() == 1 && before[0].name == principal {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::PrincipalPresent {
                            principal,
                            provider_user_id: before[0].id.clone(),
                        },
                    };
                }
                if !before.is_empty() {
                    return MutationOutcome::Conflict;
                }
                let write = self.write_json(
                    reqwest::Method::POST,
                    "api/v1/user",
                    Some(serde_json::json!({"name": principal, "displayName": "", "email": "", "pictureUrl": ""})),
                ).await;
                let response_id = match write {
                    Ok(body) => match serde_json::from_slice::<RawUserEnvelope>(&body) {
                        Ok(envelope)
                            if canonical_positive_u64(&envelope.user.id, "invalid user ID")
                                .is_ok()
                                && envelope.user.name == principal =>
                        {
                            Some(envelope.user.id)
                        }
                        _ => None,
                    },
                    Err(ProviderError::AuthenticationFailed) => {
                        return MutationOutcome::AuthenticationFailed;
                    }
                    Err(_) => None,
                };
                if let Some(stable_id) = response_id {
                    let path = format!("api/v1/user?id={stable_id}");
                    match self.inner.get_required(&path, true).await {
                        Ok(body) => match parse_users(&body) {
                            Ok(users) => principal_readback(users, &principal, Some(&stable_id)),
                            Err(()) => MutationOutcome::Ambiguous {
                                reason: MutationAmbiguity::ReadBackUnavailable,
                            },
                        },
                        Err(_) => MutationOutcome::Ambiguous {
                            reason: MutationAmbiguity::ReadBackUnavailable,
                        },
                    }
                } else {
                    match self.inner.get_required(&name_path, true).await {
                        Ok(body) => match parse_users(&body) {
                            Ok(users) => principal_readback(users, &principal, None),
                            Err(()) => MutationOutcome::Ambiguous {
                                reason: MutationAmbiguity::ReadBackUnavailable,
                            },
                        },
                        Err(_) => MutationOutcome::Ambiguous {
                            reason: MutationAmbiguity::ReadBackUnavailable,
                        },
                    }
                }
            }
            ProviderMutation::CreateJoinCredential { request } => {
                if request.reusable
                    || request.max_uses != 1
                    || request
                        .principal
                        .parse::<u64>()
                        .ok()
                        .filter(|id| *id > 0)
                        .is_none()
                {
                    return MutationOutcome::Rejected;
                }
                let user_path = format!("api/v1/user?id={}", request.principal);
                match self.inner.get_required(&user_path, true).await {
                    Ok(body) if matches!(parse_users(&body), Ok(users) if users.len() == 1 && users[0].id == request.principal) =>
                        {}
                    Ok(_) => return MutationOutcome::Rejected,
                    Err(error) => return outcome_from_error(error),
                };
                let expires_at = request
                    .expires_at
                    .unwrap_or_else(|| now + chrono::Duration::minutes(15));
                let acl_tags = request.tags.iter().cloned().collect::<Vec<_>>();
                let result = self.write_json(reqwest::Method::POST, "api/v1/preauthkey", Some(serde_json::json!({"user": request.principal, "reusable": false, "ephemeral": false, "expiration": expires_at.to_rfc3339(), "aclTags": acl_tags}))).await;
                let body = match result {
                    Ok(body) => body,
                    Err(ProviderError::AuthenticationFailed) => {
                        return MutationOutcome::AuthenticationFailed;
                    }
                    Err(_) => {
                        return MutationOutcome::Ambiguous {
                            reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                        };
                    }
                };
                let response: RawPreAuthEnvelope = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return MutationOutcome::Ambiguous {
                            reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                        };
                    }
                };
                if canonical_positive_u64(&response.pre_auth_key.id, "invalid pre-auth key ID")
                    .is_err()
                    || response
                        .pre_auth_key
                        .user
                        .as_ref()
                        .is_none_or(|user| user.id != request.principal)
                    || response.pre_auth_key.reusable
                    || response.pre_auth_key.ephemeral
                    || response.pre_auth_key.used
                    || response.pre_auth_key.expiration != Some(expires_at)
                    || response.pre_auth_key.acl_tags != request.tags
                {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                    };
                }
                let reference =
                    match ProviderCredentialReference::new(response.pre_auth_key.id.clone()) {
                        Ok(reference) => reference,
                        Err(_) => return MutationOutcome::Rejected,
                    };
                let secret =
                    match ProviderJoinCredential::new(response.pre_auth_key.key.to_string()) {
                        Ok(secret) => secret,
                        Err(_) => {
                            return MutationOutcome::Ambiguous {
                                reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                            };
                        }
                    };
                let list = match self.pre_auth_list().await {
                    Ok(list) => list,
                    Err(_) => {
                        return MutationOutcome::Ambiguous {
                            reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                        };
                    }
                };
                if !list.iter().any(|key| {
                    key.id == reference.as_str()
                        && key
                            .user
                            .as_ref()
                            .is_some_and(|user| user.id == request.principal)
                        && !key.reusable
                        && !key.ephemeral
                        && !key.used
                        && key.expiration == Some(expires_at)
                        && key.acl_tags == request.tags
                }) {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                    };
                }
                MutationOutcome::Confirmed {
                    evidence: MutationEvidence::JoinCredentialIssued(IssuedJoinCredential {
                        provider_reference: reference,
                        secret,
                        expires_at,
                        max_uses: 1,
                    }),
                }
            }
            ProviderMutation::RevokeJoinCredential { credential } => {
                let verification_now = now;
                let before = match self.pre_auth_list().await {
                    Ok(keys) => keys,
                    Err(error) => return outcome_from_error(error),
                };
                let matching = before
                    .iter()
                    .filter(|key| key.id == credential.as_str())
                    .collect::<Vec<_>>();
                match matching.as_slice() {
                    [] => {
                        return MutationOutcome::AlreadySatisfied {
                            evidence: MutationEvidence::CredentialRevoked { credential },
                        };
                    }
                    [key]
                        if key
                            .expiration
                            .as_ref()
                            .is_some_and(|expiry| *expiry <= verification_now) =>
                    {
                        return MutationOutcome::AlreadySatisfied {
                            evidence: MutationEvidence::CredentialRevoked { credential },
                        };
                    }
                    [_] => {}
                    _ => return MutationOutcome::Conflict,
                }
                let result = self
                    .write_json(
                        reqwest::Method::POST,
                        "api/v1/preauthkey/expire",
                        Some(serde_json::json!({"id": credential.as_str()})),
                    )
                    .await;
                if matches!(result, Err(ProviderError::AuthenticationFailed)) {
                    return MutationOutcome::AuthenticationFailed;
                }
                let reconciliation_now = Utc::now();
                match self.pre_auth_list().await {
                    Ok(keys) => {
                        credential_revocation_readback(keys, credential, reconciliation_now)
                    }
                    Err(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                }
            }
            ProviderMutation::ReplaceNodeTags { target, tags } => {
                let tags = match MutationTags::new(tags) {
                    Ok(tags) => tags,
                    Err(_) => return MutationOutcome::Rejected,
                };
                let before = match self.pre_node(&target, now).await {
                    Ok(Some(node)) => node,
                    Ok(None) => return MutationOutcome::Rejected,
                    Err(outcome) => return outcome,
                };
                if before.tags == *tags.as_set() {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::NodeMatches(before),
                    };
                }
                let values = tags.as_set().iter().cloned().collect::<Vec<_>>();
                let result = self
                    .write_json(
                        reqwest::Method::POST,
                        &format!("api/v1/node/{}/tags", target.node_id.as_str()),
                        Some(serde_json::json!({"tags": values})),
                    )
                    .await;
                if matches!(result, Err(ProviderError::AuthenticationFailed)) {
                    return MutationOutcome::AuthenticationFailed;
                }
                match self.pre_node(&target, now).await {
                    Ok(Some(node)) if node.tags == *tags.as_set() => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeMatches(node),
                    },
                    Ok(Some(_)) => MutationOutcome::Failed { retryable: true },
                    Ok(None) => MutationOutcome::Conflict,
                    Err(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                }
            }
            ProviderMutation::ExpireNode { target } => {
                let before = match self.pre_node(&target, now).await {
                    Ok(Some(node)) => node,
                    Ok(None) => return MutationOutcome::Rejected,
                    Err(outcome) => return outcome,
                };
                if before.expired {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::NodeMatches(before),
                    };
                }
                let result = self
                    .write_json(
                        reqwest::Method::POST,
                        &format!("api/v1/node/{}/expire", target.node_id.as_str()),
                        None,
                    )
                    .await;
                if matches!(result, Err(ProviderError::AuthenticationFailed)) {
                    return MutationOutcome::AuthenticationFailed;
                }
                match self.pre_node(&target, now).await {
                    Ok(Some(node)) if node.expired => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeMatches(node),
                    },
                    Ok(Some(_)) => MutationOutcome::Failed { retryable: true },
                    Ok(None) => MutationOutcome::Conflict,
                    Err(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                }
            }
            ProviderMutation::DeleteNode { target } => {
                match self.pre_node(&target, now).await {
                    Ok(None) => {
                        return MutationOutcome::AlreadySatisfied {
                            evidence: MutationEvidence::NodeAbsent { target },
                        };
                    }
                    Ok(Some(_)) => {}
                    Err(outcome) => return outcome,
                }
                let result = self
                    .write_json(
                        reqwest::Method::DELETE,
                        &format!("api/v1/node/{}", target.node_id.as_str()),
                        None,
                    )
                    .await;
                if matches!(result, Err(ProviderError::AuthenticationFailed)) {
                    return MutationOutcome::AuthenticationFailed;
                }
                match self.pre_node(&target, now).await {
                    Ok(None) => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeAbsent { target },
                    },
                    Ok(Some(_)) => MutationOutcome::Failed { retryable: true },
                    Err(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                }
            }
            ProviderMutation::ApplyPolicy {
                expected_revision,
                policy,
            } => {
                let before = match self.policy().await {
                    Ok(policy) => policy,
                    Err(outcome) => return outcome,
                };
                if policy_revision(&before.policy) != expected_revision {
                    return MutationOutcome::Conflict;
                }
                if before.policy == policy {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::PolicyMatches {
                            revision: expected_revision,
                        },
                    };
                }
                if let Err(error) = self
                    .write_json(
                        reqwest::Method::POST,
                        "api/v1/policy/check",
                        Some(serde_json::json!({"policy": policy})),
                    )
                    .await
                {
                    return outcome_from_error(error);
                }
                let _put_result = self
                    .write_json(
                        reqwest::Method::PUT,
                        "api/v1/policy",
                        Some(serde_json::json!({"policy": policy})),
                    )
                    .await;
                // A PUT has reached the HTTP transport before any response,
                // non-auth response/parse/transport result. Reconcile exactly
                // once; v0.29.3 has no CAS or operation identity.
                match self.policy().await {
                    Ok(after) if after.policy == policy => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::PolicyMatches {
                            revision: policy_revision(&after.policy),
                        },
                    },
                    Ok(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    },
                    Err(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                }
            }
        }
    }
}

#[allow(clippy::result_large_err)]
fn local_intent_outcome(
    mutation: &ProviderMutation,
    now: DateTime<Utc>,
) -> Result<(), MutationOutcome> {
    match mutation {
        ProviderMutation::EnsureNetworkPrincipal { principal } => {
            if principal.is_empty()
                || principal.len() > 128
                || !principal
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(MutationOutcome::Rejected);
            }
        }
        ProviderMutation::CreateJoinCredential { request } => {
            if request.reusable
                || request.max_uses != 1
                || canonical_positive_u64(&request.principal, "invalid principal ID").is_err()
                || request.tags.len() > 4
                || request
                    .tags
                    .iter()
                    .any(|tag| MutationTags::new([tag.clone()]).is_err())
            {
                return Err(MutationOutcome::Rejected);
            }
            if let Some(expires_at) = request.expires_at {
                let remaining = expires_at - now;
                if remaining < chrono::Duration::minutes(5)
                    || remaining > chrono::Duration::hours(1)
                {
                    return Err(MutationOutcome::Rejected);
                }
            }
        }
        ProviderMutation::RevokeJoinCredential { credential } => {
            if canonical_positive_u64(credential.as_str(), "invalid credential ID").is_err() {
                return Err(MutationOutcome::Rejected);
            }
        }
        ProviderMutation::ReplaceNodeTags { target, tags } => {
            if canonical_positive_u64(target.node_id.as_str(), "invalid node ID").is_err()
                || MutationTags::new(tags.clone()).is_err()
            {
                return Err(MutationOutcome::Rejected);
            }
        }
        ProviderMutation::ExpireNode { target } | ProviderMutation::DeleteNode { target } => {
            if canonical_positive_u64(target.node_id.as_str(), "invalid node ID").is_err() {
                return Err(MutationOutcome::Rejected);
            }
        }
        ProviderMutation::ApplyPolicy {
            expected_revision,
            policy,
        } => {
            if expected_revision.is_empty() || policy.len() > 1024 * 1024 {
                return Err(MutationOutcome::Rejected);
            }
        }
    }
    Ok(())
}

fn outcome_from_error(error: ProviderError) -> MutationOutcome {
    match error {
        ProviderError::AuthenticationFailed => MutationOutcome::AuthenticationFailed,
        ProviderError::Timeout | ProviderError::TlsFailure | ProviderError::Unreachable(_) => {
            MutationOutcome::Unavailable
        }
        ProviderError::Conflict(_) => MutationOutcome::Conflict,
        ProviderError::Unsupported(_) => MutationOutcome::Unsupported,
        ProviderError::Rejected(_) | ProviderError::MalformedResponse(_) => {
            MutationOutcome::Rejected
        }
        ProviderError::AmbiguousMutation(_) => MutationOutcome::Ambiguous {
            reason: MutationAmbiguity::PotentiallyApplied,
        },
    }
}

#[derive(Deserialize)]
struct RawUsers {
    users: Vec<RawUserName>,
}
#[derive(Deserialize)]
struct RawUserName {
    id: String,
    name: String,
}
#[derive(Deserialize)]
struct RawUserEnvelope {
    user: RawUserName,
}
fn parse_users(body: &[u8]) -> Result<Vec<RawUserName>, ()> {
    let users: RawUsers = serde_json::from_slice(body).map_err(|_| ())?;
    if users.users.len() > 1_000
        || users.users.iter().any(|user| {
            canonical_positive_u64(&user.id, "invalid user ID").is_err()
                || user.name.is_empty()
                || user.name.len() > 128
        })
    {
        return Err(());
    }
    Ok(users.users)
}

fn principal_readback(
    users: Vec<RawUserName>,
    principal: &str,
    expected_id: Option<&str>,
) -> MutationOutcome {
    match users.as_slice() {
        [] => MutationOutcome::Failed { retryable: true },
        [user]
            if user.name == principal && expected_id.is_none_or(|expected| expected == user.id) =>
        {
            MutationOutcome::Confirmed {
                evidence: MutationEvidence::PrincipalPresent {
                    principal: principal.to_owned(),
                    provider_user_id: user.id.clone(),
                },
            }
        }
        _ => MutationOutcome::Conflict,
    }
}
fn credential_revocation_readback(
    keys: Vec<RawPreAuthKeyList>,
    credential: ProviderCredentialReference,
    verification_now: DateTime<Utc>,
) -> MutationOutcome {
    let matching = keys
        .iter()
        .filter(|key| key.id == credential.as_str())
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => MutationOutcome::Confirmed {
            evidence: MutationEvidence::CredentialRevoked { credential },
        },
        [key]
            if key
                .expiration
                .as_ref()
                .is_some_and(|expiry| *expiry <= verification_now) =>
        {
            MutationOutcome::Confirmed {
                evidence: MutationEvidence::CredentialRevoked { credential },
            }
        }
        [_] => MutationOutcome::Failed { retryable: true },
        _ => MutationOutcome::Conflict,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPreAuthEnvelope {
    pre_auth_key: RawPreAuthKeyMutation,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPreAuthList {
    pre_auth_keys: Vec<RawPreAuthKeyList>,
}
fn parse_pre_auth_list(body: &[u8]) -> Result<Vec<RawPreAuthKeyList>, ()> {
    let list: RawPreAuthList = serde_json::from_slice(body).map_err(|_| ())?;
    if list.pre_auth_keys.len() > 10_000
        || list.pre_auth_keys.iter().any(|key| {
            canonical_positive_u64(&key.id, "invalid pre-auth key ID").is_err()
                || key.user.as_ref().is_none_or(|user| {
                    canonical_positive_u64(&user.id, "invalid pre-auth user ID").is_err()
                })
                || key.acl_tags.len() > 4
                || key
                    .acl_tags
                    .iter()
                    .any(|tag| MutationTags::new([tag.clone()]).is_err())
        })
    {
        return Err(());
    }
    Ok(list.pre_auth_keys)
}
fn deserialize_zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPreAuthKeyMutation {
    id: String,
    #[serde(default, deserialize_with = "deserialize_zeroizing_string")]
    key: Zeroizing<String>,
    user: Option<RawUserName>,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    used: bool,
    expiration: Option<DateTime<Utc>>,
    #[serde(default)]
    acl_tags: BTreeSet<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPreAuthKeyList {
    id: String,
    user: Option<RawUserName>,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    used: bool,
    expiration: Option<DateTime<Utc>>,
    #[serde(default)]
    acl_tags: BTreeSet<String>,
}
#[derive(Deserialize)]
struct RawPolicy {
    policy: String,
}
fn policy_revision(policy: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(policy.as_bytes()))
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

/// Parse a sanitized Headscale `ListNodes` JSON fixture or captured response
/// through the adapter's real normalization path without opening a network connection.
pub fn parse_nodes_fixture(
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
                    association: PreAuthAssociationStrength::ProviderAuthenticatedRegistration,
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
