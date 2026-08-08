//! Provider-neutral Nodescale integration contract.

use chrono::{DateTime, Utc};
use nodescale_domain::{
    ProviderCredentialId, ProviderCredentialReference, ProviderIdentity, ProviderInstanceId,
    ProviderJoinCredential,
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
    /// An explicit adapter-mode gate in addition to version compatibility.
    pub mutation_allowed: bool,
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
            mutation_allowed: inspection.compatibility.allows_mutation()
                && inspection.mutation_allowed,
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
    /// Empty means the adapter must select its explicit 15-minute default.
    pub expires_at: Option<DateTime<Utc>>,
    /// Requested Headscale ACL tags. The adapter applies the closed vocabulary.
    pub tags: BTreeSet<String>,
}
impl JoinCredentialRequest {
    #[must_use]
    pub fn single_use(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            reusable: false,
            max_uses: 1,
            expires_at: None,
            tags: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEvidenceClass {
    StrongImmutable,
    StableConditional,
    Mutable,
    DisplayOnly,
    UnsafeForIdentity,
}

macro_rules! identity_evidence {
    ($name:ident, $class:expr, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
                let value = value.into();
                if value.is_empty() || value.len() > 512 {
                    return Err(ProviderError::MalformedResponse(concat!(
                        $kind,
                        " must be bounded and non-empty"
                    )));
                }
                Ok(Self(value))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
            #[must_use]
            pub const fn class(&self) -> IdentityEvidenceClass {
                $class
            }
        }
    };
}

identity_evidence!(
    StrongIdentityEvidence,
    IdentityEvidenceClass::StrongImmutable,
    "strong identity evidence"
);
identity_evidence!(
    ConditionalIdentityEvidence,
    IdentityEvidenceClass::StableConditional,
    "conditional identity evidence"
);
identity_evidence!(
    MutableIdentityEvidence,
    IdentityEvidenceClass::Mutable,
    "mutable identity observation"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderIdentityEvidence {
    /// Strong correlation evidence, but replaceable in Headscale.
    pub machine_key: ConditionalIdentityEvidence,
    /// Rotating cryptographic observations; never canonical identity.
    pub node_key: Option<MutableIdentityEvidence>,
    pub disco_key: Option<MutableIdentityEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderUserObservation {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreAuthAssociationStrength {
    /// A correlation hint only; never sufficient for N5 identity confirmation.
    Partial,
    /// The authenticated provider registration record itself names the exact
    /// provider-native credential used for that registration.
    ProviderAuthenticatedRegistration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreAuthCorrelationObservation {
    pub credential_id: String,
    pub association: PreAuthAssociationStrength,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderNode {
    pub identity: ProviderIdentity,
    pub identity_evidence: ProviderIdentityEvidence,
    /// Presentation metadata; never canonical identity.
    pub hostname: String,
    /// Mutable provider-assigned display metadata.
    pub given_name: String,
    /// Addressing metadata; never canonical identity.
    pub addresses: Vec<String>,
    pub user: Option<ProviderUserObservation>,
    pub pre_auth: Option<PreAuthCorrelationObservation>,
    pub tags: BTreeSet<String>,
    pub registered_at: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub online: bool,
    pub expired: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPolicy {
    pub revision: String,
    pub normalized_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealthStatus {
    Healthy,
    ReachableIncompatible,
    AuthenticationFailed,
    TransportFailure,
    TlsFailure,
    Timeout,
    MalformedResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderHealth {
    pub status: ProviderHealthStatus,
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
    #[error("provider request timed out")]
    Timeout,
    #[error("provider TLS verification failed")]
    TlsFailure,
    #[error("provider response is malformed: {0}")]
    MalformedResponse(&'static str),
    #[error("provider authentication failed")]
    AuthenticationFailed,
    #[error("provider mutation outcome is ambiguous: {0}")]
    AmbiguousMutation(String),
    #[error("provider conflict: {0}")]
    Conflict(String),
    #[error("provider rejected request: {0}")]
    Rejected(String),
}

/// Permanent async read boundary for real provider adapters.
/// It contains no mutation methods, so a read-only adapter cannot accidentally
/// gain write authority through this trait.
#[async_trait::async_trait]
pub trait ReadOnlyProvider: Send + Sync {
    fn instance_id(&self) -> ProviderInstanceId;
    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError>;
    async fn verify_compatibility(&self) -> Result<CompatibilityReport, ProviderError> {
        self.inspect_server()
            .await
            .map(|inspection| CompatibilityReport::from_inspection(&inspection))
    }
    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError>;
    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError>;
    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError>;
}

/// N0C deterministic provider contract, including future mutation simulations.
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

/// Mutations are separately capability-scoped and never widen `ReadOnlyProvider`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMutationCapability {
    EnsureNetworkPrincipal,
    CreateJoinCredential,
    InvalidateJoinCredential,
    ReplaceNodeTags,
    ExpireNode,
    DeleteNode,
    ManagePolicy,
}

/// Trusted configuration provenance for the provider policy storage mode.
/// `Unknown` is intentionally fail-closed for policy writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationPolicyMode {
    Database,
    File,
    Unknown,
}

/// Validated, sorted Headscale tag collection. A BTreeSet makes request and
/// read-back comparison deterministic without allowing unsafe tag spellings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationTags(BTreeSet<String>);
impl MutationTags {
    pub fn new(tags: impl IntoIterator<Item = String>) -> Result<Self, ProviderError> {
        let tags = tags.into_iter().collect::<BTreeSet<_>>();
        const ALLOWED: [&str; 6] = [
            "tag:nodescale-node",
            "tag:nodescale-worker",
            "tag:nodescale-controller",
            "tag:nodescale-profile-host",
            "tag:nodescale-observer",
            "tag:nodescale-admin",
        ];
        if tags.is_empty()
            || tags.len() > 4
            || tags.iter().any(|tag| !ALLOWED.contains(&tag.as_str()))
        {
            return Err(ProviderError::Rejected("invalid mutation tags".into()));
        }
        Ok(Self(tags))
    }
    #[must_use]
    pub fn as_set(&self) -> &BTreeSet<String> {
        &self.0
    }
}

pub enum ProviderMutation {
    EnsureNetworkPrincipal {
        principal: String,
    },
    CreateJoinCredential {
        request: JoinCredentialRequest,
    },
    RevokeJoinCredential {
        credential: ProviderCredentialReference,
    },
    ReplaceNodeTags {
        target: ProviderIdentity,
        tags: BTreeSet<String>,
    },
    ExpireNode {
        target: ProviderIdentity,
    },
    DeleteNode {
        target: ProviderIdentity,
    },
    ApplyPolicy {
        expected_revision: String,
        policy: String,
    },
}
impl ProviderMutation {
    #[must_use]
    pub const fn capability(&self) -> ProviderMutationCapability {
        match self {
            Self::EnsureNetworkPrincipal { .. } => {
                ProviderMutationCapability::EnsureNetworkPrincipal
            }
            Self::CreateJoinCredential { .. } => ProviderMutationCapability::CreateJoinCredential,
            Self::RevokeJoinCredential { .. } => {
                ProviderMutationCapability::InvalidateJoinCredential
            }
            Self::ReplaceNodeTags { .. } => ProviderMutationCapability::ReplaceNodeTags,
            Self::ExpireNode { .. } => ProviderMutationCapability::ExpireNode,
            Self::DeleteNode { .. } => ProviderMutationCapability::DeleteNode,
            Self::ApplyPolicy { .. } => ProviderMutationCapability::ManagePolicy,
        }
    }
}

/// Sanitized evidence is required for every confirmed or already-satisfied
/// mutation. It deliberately contains no API or join credential secret.
pub struct IssuedJoinCredential {
    pub provider_reference: ProviderCredentialReference,
    pub secret: ProviderJoinCredential,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
}
impl std::fmt::Debug for IssuedJoinCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedJoinCredential")
            .field("provider_reference", &self.provider_reference)
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .finish()
    }
}

#[allow(clippy::large_enum_variant)]
pub enum MutationEvidence {
    PrincipalPresent {
        principal: String,
        /// Stable provider-native principal ID observed through authoritative
        /// readback. Display names are not identity evidence.
        provider_user_id: String,
    },
    JoinCredentialIssued(IssuedJoinCredential),
    CredentialRevoked {
        credential: ProviderCredentialReference,
    },
    NodeMatches(ProviderNode),
    NodeAbsent {
        target: ProviderIdentity,
    },
    PolicyMatches {
        revision: String,
    },
}
impl std::fmt::Debug for MutationEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrincipalPresent {
                principal,
                provider_user_id,
            } => f
                .debug_struct("PrincipalPresent")
                .field("principal", principal)
                .field("provider_user_id", provider_user_id)
                .finish(),
            Self::JoinCredentialIssued(credential) => f
                .debug_tuple("JoinCredentialIssued")
                .field(credential)
                .finish(),
            Self::CredentialRevoked { credential } => f
                .debug_tuple("CredentialRevoked")
                .field(credential)
                .finish(),
            Self::NodeMatches(node) => f.debug_tuple("NodeMatches").field(node).finish(),
            Self::NodeAbsent { target } => f.debug_tuple("NodeAbsent").field(target).finish(),
            Self::PolicyMatches { revision } => {
                f.debug_tuple("PolicyMatches").field(revision).finish()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAmbiguity {
    PotentiallyApplied,
    PotentiallyAppliedSecretUnavailable,
    ReadBackUnavailable,
}

pub enum MutationOutcome {
    Confirmed { evidence: MutationEvidence },
    AlreadySatisfied { evidence: MutationEvidence },
    Rejected,
    Failed { retryable: bool },
    Unsupported,
    AuthenticationFailed,
    Unavailable,
    CompatibilityBlocked,
    Conflict,
    Ambiguous { reason: MutationAmbiguity },
}
impl std::fmt::Debug for MutationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed { evidence } => f
                .debug_struct("Confirmed")
                .field("evidence", evidence)
                .finish(),
            Self::AlreadySatisfied { evidence } => f
                .debug_struct("AlreadySatisfied")
                .field("evidence", evidence)
                .finish(),
            Self::Rejected => f.write_str("Rejected"),
            Self::Failed { retryable } => f
                .debug_struct("Failed")
                .field("retryable", retryable)
                .finish(),
            Self::Unsupported => f.write_str("Unsupported"),
            Self::AuthenticationFailed => f.write_str("AuthenticationFailed"),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::CompatibilityBlocked => f.write_str("CompatibilityBlocked"),
            Self::Conflict => f.write_str("Conflict"),
            Self::Ambiguous { reason } => {
                f.debug_struct("Ambiguous").field("reason", reason).finish()
            }
        }
    }
}

/// The async mutation plane is intentionally a sibling of `ReadOnlyProvider`.
/// A caller must receive this explicitly constructed capability to issue writes.
///
/// ```compile_fail
/// use nodescale_provider::{MutationProvider, ReadOnlyProvider};
/// fn requires_mutation<T: MutationProvider>() {}
/// fn read_only_is_not_mutation<T: ReadOnlyProvider>() {
///     requires_mutation::<T>();
/// }
/// ```
#[async_trait::async_trait]
pub trait MutationProvider: Send + Sync {
    /// An authorization is provider-specific and consumed exactly once by the
    /// mutation call. A real adapter can therefore require a state-owned token
    /// while deterministic fakes retain a deliberately incompatible test token.
    type Authorization: Send;

    fn instance_id(&self) -> ProviderInstanceId;
    async fn execute_mutation(
        &self,
        authorization: Self::Authorization,
        mutation: ProviderMutation,
    ) -> MutationOutcome;
}
