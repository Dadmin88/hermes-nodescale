//! Provider-neutral Nodescale integration contract.

use chrono::{DateTime, Utc};
use nodescale_domain::{
    ProviderCredentialId, ProviderIdentity, ProviderInstanceId, ProviderJoinCredential,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    CompatibleWithConstraints,
    ReadOnlyDegraded,
    Unsupported,
    Unreachable,
    AuthenticationFailed,
}
impl CompatibilityStatus {
    #[must_use]
    pub const fn allows_mutation(self) -> bool {
        matches!(self, Self::Compatible | Self::CompatibleWithConstraints)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    InspectServer,
    EnsureNetworkPrincipal,
    CreateJoinCredential,
    RevokeJoinCredential,
    ListNodes,
    GetNode,
    SetNodeTags,
    ExpireNode,
    DeleteNode,
    GetPolicy,
    ApplyPolicy,
    Health,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerInspection {
    pub provider_name: String,
    pub provider_version: String,
    pub instance_id: ProviderInstanceId,
    pub compatibility: CompatibilityStatus,
    pub capabilities: BTreeSet<ProviderCapability>,
    pub constraints: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompatibilityReport {
    pub status: CompatibilityStatus,
    pub reason: String,
    pub mutation_allowed: bool,
}
impl CompatibilityReport {
    #[must_use]
    pub fn from_inspection(inspection: &ServerInspection) -> Self {
        Self {
            status: inspection.compatibility,
            reason: inspection.constraints.join("; "),
            mutation_allowed: inspection.compatibility.allows_mutation(),
        }
    }
}

pub struct JoinCredential {
    pub credential_id: ProviderCredentialId,
    pub secret: ProviderJoinCredential,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
}
impl std::fmt::Debug for JoinCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinCredential")
            .field("credential_id", &self.credential_id)
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinCredentialRequest {
    pub principal: String,
    pub reusable: bool,
    pub max_uses: u32,
}
impl JoinCredentialRequest {
    #[must_use]
    pub fn single_use(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            reusable: false,
            max_uses: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderNode {
    pub identity: ProviderIdentity,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub tags: BTreeSet<String>,
    pub observed_at: DateTime<Utc>,
    pub expired: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPolicy {
    pub revision: String,
    pub normalized_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderHealth {
    pub reachable: bool,
    pub authenticated: bool,
    pub detail: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("provider operation is unsupported: {0}")]
    Unsupported(&'static str),
    #[error("provider is unreachable: {0}")]
    Unreachable(String),
    #[error("provider authentication failed")]
    AuthenticationFailed,
    #[error("provider mutation outcome is ambiguous: {0}")]
    AmbiguousMutation(String),
    #[error("provider conflict: {0}")]
    Conflict(String),
    #[error("provider rejected request: {0}")]
    Rejected(String),
}

pub trait Provider {
    fn instance_id(&self) -> ProviderInstanceId;
    fn inspect_server(&self) -> Result<ServerInspection, ProviderError>;
    fn verify_compatibility(&self) -> Result<CompatibilityReport, ProviderError> {
        self.inspect_server()
            .map(|inspection| CompatibilityReport::from_inspection(&inspection))
    }
    fn ensure_network_principal(&mut self, principal: &str) -> Result<(), ProviderError>;
    fn create_join_credential(
        &mut self,
        request: &JoinCredentialRequest,
    ) -> Result<JoinCredential, ProviderError>;
    fn revoke_join_credential(
        &mut self,
        credential_id: ProviderCredentialId,
    ) -> Result<(), ProviderError>;
    fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError>;
    fn get_node(&self, identity: &ProviderIdentity) -> Result<Option<ProviderNode>, ProviderError>;
    fn set_node_tags(
        &mut self,
        identity: &ProviderIdentity,
        tags: &[String],
    ) -> Result<(), ProviderError>;
    fn expire_node(&mut self, identity: &ProviderIdentity) -> Result<(), ProviderError>;
    fn delete_node(&mut self, identity: &ProviderIdentity) -> Result<(), ProviderError>;
    fn get_policy(&self) -> Result<ProviderPolicy, ProviderError>;
    fn apply_policy(&mut self, policy: &ProviderPolicy) -> Result<(), ProviderError>;
    fn provider_health(&self) -> Result<ProviderHealth, ProviderError>;
}
