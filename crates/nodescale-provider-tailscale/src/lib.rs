//! Strict, provider-neutral read adapter for the documented Tailscale SaaS API v2.

use chrono::{DateTime, Utc};
use nodescale_domain::{ProviderApiKey, ProviderIdentity, ProviderInstanceId, ProviderNodeId};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence, ProviderCapability,
    ProviderError, ProviderHealth, ProviderHealthStatus, ProviderIdentityEvidence, ProviderNode,
    ReadOnlyProvider, ServerInspection,
};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, time::Duration};
use thiserror::Error;

const API_ORIGIN: &str = "https://api.tailscale.com/api/v2/";
const MAX_TAILSCALE_DEVICES: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TailscaleClientOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for TailscaleClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TailscaleError {
    #[error("invalid Tailscale tailnet: {0}")]
    InvalidTailnet(&'static str),
    #[error("invalid Tailscale client options")]
    InvalidClientOptions,
    #[error("failed to construct Tailscale HTTP client")]
    ClientConstruction,
}

pub enum TailscaleAuth {
    ApiAccessToken(ProviderApiKey),
    OAuthAccessToken(ProviderApiKey),
}

impl fmt::Debug for TailscaleAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiAccessToken(_) => formatter.write_str("ApiAccessToken([REDACTED])"),
            Self::OAuthAccessToken(_) => formatter.write_str("OAuthAccessToken([REDACTED])"),
        }
    }
}

impl TailscaleAuth {
    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::ApiAccessToken(token) => {
                token.expose(|token| request.basic_auth(token, Some("")))
            }
            Self::OAuthAccessToken(token) => token.expose(|token| request.bearer_auth(token)),
        }
    }
}

pub struct TailscaleProvider {
    endpoint: Url,
    tailnet: String,
    instance_id: ProviderInstanceId,
    auth: TailscaleAuth,
    client: Client,
    max_response_bytes: usize,
}

impl fmt::Debug for TailscaleProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TailscaleProvider")
            .field("endpoint", &self.endpoint.as_str())
            .field("tailnet", &self.tailnet)
            .field("instance_id", &self.instance_id)
            .field("auth", &self.auth)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl TailscaleProvider {
    pub fn new(
        tailnet: &str,
        instance_id: ProviderInstanceId,
        auth: TailscaleAuth,
        options: TailscaleClientOptions,
    ) -> Result<Self, TailscaleError> {
        let endpoint = Url::parse(API_ORIGIN).expect("the pinned Tailscale API origin is valid");
        Self::new_with_endpoint(tailnet, instance_id, auth, options, endpoint)
    }

    fn new_with_endpoint(
        tailnet: &str,
        instance_id: ProviderInstanceId,
        auth: TailscaleAuth,
        options: TailscaleClientOptions,
        endpoint: Url,
    ) -> Result<Self, TailscaleError> {
        validate_tailnet(tailnet)?;
        if options.connect_timeout.is_zero()
            || options.request_timeout.is_zero()
            || options.max_response_bytes == 0
        {
            return Err(TailscaleError::InvalidClientOptions);
        }
        let client = Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TailscaleError::ClientConstruction)?;
        Ok(Self {
            endpoint,
            tailnet: tailnet.to_owned(),
            instance_id,
            auth,
            client,
            max_response_bytes: options.max_response_bytes,
        })
    }

    fn devices_url(&self) -> Result<Url, ProviderError> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|()| ProviderError::Rejected("invalid Tailscale API origin".into()))?
            .pop_if_empty()
            .push("tailnet")
            .push(&self.tailnet)
            .push("devices");
        Ok(url)
    }

    async fn list_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        let request = self.auth.apply(self.client.get(self.devices_url()?));
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
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(ProviderError::MalformedResponse(
                "Tailscale response exceeds configured bound",
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(ProviderError::MalformedResponse(
                    "Tailscale response exceeds configured bound",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        if body.is_empty() {
            return Err(ProviderError::MalformedResponse(
                "Tailscale response is empty",
            ));
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl ReadOnlyProvider for TailscaleProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        self.list_nodes().await?;
        Ok(ServerInspection {
            provider_name: "tailscale".into(),
            provider_version: "api-v2".into(),
            instance_id: self.instance_id,
            compatibility: CompatibilityStatus::CompatibleWithConstraints,
            capabilities: read_only_capabilities(),
            constraints: vec![
                "Tailscale API does not expose provider-authoritative online state".into(),
                "Tailscale device responses do not expose provider-authenticated join credential correlation".into(),
                "Tailscale mutation operations are not enabled by this adapter".into(),
            ],
            mutation_allowed: false,
        })
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
        let body = self.list_bytes().await?;
        let json = std::str::from_utf8(&body)
            .map_err(|_| ProviderError::MalformedResponse("Tailscale device list is not UTF-8"))?;
        parse_devices_fixture(json, self.instance_id, Utc::now())
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
        Ok(self
            .list_nodes()
            .await?
            .into_iter()
            .find(|node| node.identity == *identity))
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        match self.list_nodes().await {
            Ok(_) => Ok(ProviderHealth {
                status: ProviderHealthStatus::Healthy,
                reachable: true,
                authenticated: true,
                detail: "Tailscale API is reachable and authenticated".into(),
            }),
            Err(error) => Ok(health_from_error(&error)),
        }
    }
}

#[must_use]
pub fn read_only_capabilities() -> BTreeSet<ProviderCapability> {
    [
        ProviderCapability::InspectServer,
        ProviderCapability::ListNodes,
        ProviderCapability::GetNode,
        ProviderCapability::Health,
    ]
    .into_iter()
    .collect()
}

#[derive(Deserialize)]
struct RawDeviceList {
    devices: Vec<RawDevice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDevice {
    node_id: String,
    name: String,
    hostname: String,
    #[serde(default)]
    addresses: Vec<String>,
    authorized: bool,
    #[serde(default)]
    machine_key: String,
    #[serde(default)]
    created: Option<DateTime<Utc>>,
    #[serde(default)]
    last_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    expires: Option<DateTime<Utc>>,
    #[serde(default)]
    tags: BTreeSet<String>,
}

pub fn parse_devices_fixture(
    json: &str,
    instance_id: ProviderInstanceId,
    observed_at: DateTime<Utc>,
) -> Result<Vec<ProviderNode>, ProviderError> {
    let raw: RawDeviceList = serde_json::from_str(json)
        .map_err(|_| ProviderError::MalformedResponse("invalid Tailscale device list JSON"))?;
    if raw.devices.len() > MAX_TAILSCALE_DEVICES {
        return Err(ProviderError::MalformedResponse(
            "Tailscale device list exceeds supported bound",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut nodes = Vec::with_capacity(raw.devices.len());
    for raw in raw.devices {
        let node_id = ProviderNodeId::parse(raw.node_id)
            .map_err(|_| ProviderError::MalformedResponse("invalid Tailscale nodeId"))?;
        if !seen.insert(node_id.to_string()) {
            return Err(ProviderError::MalformedResponse(
                "duplicate Tailscale nodeId",
            ));
        }
        validate_display(&raw.hostname, "invalid Tailscale hostname")?;
        validate_display(&raw.name, "invalid Tailscale device name")?;
        let mut addresses = raw.addresses;
        if addresses.len() > 256
            || addresses.iter().any(|address| {
                address.is_empty()
                    || address.len() > 128
                    || address.chars().any(char::is_whitespace)
            })
        {
            return Err(ProviderError::MalformedResponse(
                "invalid Tailscale device addresses",
            ));
        }
        addresses.sort();
        addresses.dedup();
        if raw.tags.len() > 256
            || raw.tags.iter().any(|tag| {
                !tag.starts_with("tag:") || tag.len() > 256 || tag.chars().any(char::is_whitespace)
            })
        {
            return Err(ProviderError::MalformedResponse(
                "invalid Tailscale device tags",
            ));
        }
        let stable_key_fingerprint =
            format!("sha256:{:x}", Sha256::digest(node_id.as_str().as_bytes()));
        let identity = ProviderIdentity::new(instance_id, node_id, stable_key_fingerprint)
            .map_err(|_| ProviderError::MalformedResponse("invalid Tailscale identity"))?;
        let machine_key = if raw.machine_key.is_empty() {
            None
        } else {
            Some(
                ConditionalIdentityEvidence::new(raw.machine_key).map_err(|_| {
                    ProviderError::MalformedResponse("invalid Tailscale machineKey")
                })?,
            )
        };
        let expired = !raw.authorized || raw.expires.is_some_and(|expiry| expiry <= observed_at);
        nodes.push(ProviderNode {
            identity,
            identity_evidence: ProviderIdentityEvidence {
                machine_key,
                node_key: None,
                disco_key: None,
            },
            hostname: raw.hostname,
            given_name: raw.name,
            addresses,
            user: None,
            pre_auth: None,
            tags: raw.tags,
            registered_at: raw.created,
            last_seen: raw.last_seen,
            expires_at: raw.expires,
            observed_at,
            online: None,
            expired,
        });
    }
    nodes.sort_by(|left, right| left.identity.node_id.cmp(&right.identity.node_id));
    Ok(nodes)
}

fn validate_tailnet(value: &str) -> Result<(), TailscaleError> {
    if value.is_empty() || value.len() > 256 || value.trim() != value {
        return Err(TailscaleError::InvalidTailnet(
            "must be bounded, non-empty, and unpadded",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-_@".contains(&byte))
    {
        return Err(TailscaleError::InvalidTailnet(
            "contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_display(value: &str, message: &'static str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ProviderError::MalformedResponse(message));
    }
    Ok(())
}

fn map_transport_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Timeout
    } else {
        let message = error.to_string().to_ascii_lowercase();
        if message.contains("certificate") || message.contains("tls") {
            ProviderError::TlsFailure
        } else {
            ProviderError::Unreachable("Tailscale transport failed".into())
        }
    }
}

fn health_from_error(error: &ProviderError) -> ProviderHealth {
    let (status, reachable, authenticated, detail) = match error {
        ProviderError::AuthenticationFailed => (
            ProviderHealthStatus::AuthenticationFailed,
            true,
            false,
            "Tailscale authentication failed",
        ),
        ProviderError::Timeout => (
            ProviderHealthStatus::Timeout,
            false,
            false,
            "Tailscale request timed out",
        ),
        ProviderError::TlsFailure => (
            ProviderHealthStatus::TlsFailure,
            false,
            false,
            "Tailscale TLS verification failed",
        ),
        ProviderError::MalformedResponse(_) => (
            ProviderHealthStatus::MalformedResponse,
            true,
            true,
            "Tailscale returned a malformed response",
        ),
        _ => (
            ProviderHealthStatus::TransportFailure,
            false,
            false,
            "Tailscale transport failed",
        ),
    };
    ProviderHealth {
        status,
        reachable,
        authenticated,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const BODY: &str = r#"{"devices":[{"nodeId":"node-a","name":"node-a.example.ts.net","hostname":"node-a","addresses":["100.64.0.1"],"authorized":true,"machineKey":"","created":"2026-01-01T00:00:00Z","lastSeen":"2026-01-02T00:00:00Z","expires":"2027-01-01T00:00:00Z","tags":[]}]}"#;

    async fn server(status: u16, body: &'static str) -> (Url, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let reason = if status == 200 { "OK" } else { "Found" };
            let location = if status == 302 {
                "Location: https://redirect.invalid/\r\n"
            } else {
                ""
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (
            Url::parse(&format!("http://{address}/api/v2/")).unwrap(),
            task,
        )
    }

    fn test_provider(
        endpoint: Url,
        auth: TailscaleAuth,
        max_response_bytes: usize,
    ) -> TailscaleProvider {
        TailscaleProvider::new_with_endpoint(
            "example.com",
            ProviderInstanceId::new(),
            auth,
            TailscaleClientOptions {
                max_response_bytes,
                ..TailscaleClientOptions::default()
            },
            endpoint,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn api_access_token_uses_exact_basic_auth_and_documented_path() {
        let token = "generic-api-token";
        let (endpoint, request) = server(200, BODY).await;
        let provider = test_provider(
            endpoint,
            TailscaleAuth::ApiAccessToken(ProviderApiKey::new(token.into()).unwrap()),
            4096,
        );
        assert_eq!(provider.list_nodes().await.unwrap().len(), 1);
        let request = request.await.unwrap();
        assert!(request.starts_with("GET /api/v2/tailnet/example.com/devices HTTP/1.1\r\n"));
        let expected = STANDARD.encode(format!("{token}:"));
        assert!(request.contains(&format!("authorization: Basic {expected}\r\n")));
    }

    #[tokio::test]
    async fn oauth_access_token_uses_bearer_auth() {
        let token = "generic-oauth-token";
        let (endpoint, request) = server(200, BODY).await;
        let provider = test_provider(
            endpoint,
            TailscaleAuth::OAuthAccessToken(ProviderApiKey::new(token.into()).unwrap()),
            4096,
        );
        assert_eq!(provider.list_nodes().await.unwrap().len(), 1);
        let request = request.await.unwrap();
        assert!(request.contains(&format!("authorization: Bearer {token}\r\n")));
    }

    #[tokio::test]
    async fn redirects_and_oversized_responses_fail_closed() {
        let (endpoint, request) = server(302, "{}").await;
        let provider = test_provider(
            endpoint,
            TailscaleAuth::ApiAccessToken(ProviderApiKey::new("generic-token".into()).unwrap()),
            4096,
        );
        assert!(matches!(
            provider.list_nodes().await,
            Err(ProviderError::Rejected(_))
        ));
        request.await.unwrap();

        let (endpoint, request) = server(200, BODY).await;
        let provider = test_provider(
            endpoint,
            TailscaleAuth::ApiAccessToken(ProviderApiKey::new("generic-token".into()).unwrap()),
            8,
        );
        assert!(matches!(
            provider.list_nodes().await,
            Err(ProviderError::MalformedResponse(_))
        ));
        request.await.unwrap();
    }
}
