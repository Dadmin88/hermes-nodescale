//! Pure Nodescale domain model and fail-closed lifecycle rules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid {kind}: {reason}")]
    InvalidValue {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("invalid transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("stale generation: expected {expected}, actual {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("generation must advance monotonically")]
    NonMonotonicGeneration,
}

pub trait TypedId: Sized {
    fn new() -> Self;
    fn parse(value: &str) -> Result<Self, DomainError>;
}

macro_rules! uuid_id {
    ($name:ident, $kind:literal) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);
        impl TypedId for $name {
            fn new() -> Self {
                Self(Uuid::new_v4())
            }
            fn parse(value: &str) -> Result<Self, DomainError> {
                let parsed = Uuid::parse_str(value).map_err(|_| DomainError::InvalidValue {
                    kind: $kind,
                    reason: "must be a UUID",
                })?;
                if parsed.is_nil() {
                    return Err(DomainError::InvalidValue {
                        kind: $kind,
                        reason: "nil UUID is forbidden",
                    });
                }
                Ok(Self(parsed))
            }
        }
        impl $name {
            #[must_use]
            pub fn new() -> Self {
                <Self as TypedId>::new()
            }
            pub fn parse(value: &str) -> Result<Self, DomainError> {
                <Self as TypedId>::parse(value)
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_id!(NetworkId, "network ID");
uuid_id!(DeviceId, "device ID");
uuid_id!(InvitationId, "invitation ID");
uuid_id!(JoinSessionId, "join session ID");
uuid_id!(KeryxBindingId, "Keryx binding ID");
uuid_id!(ProviderInstanceId, "provider instance ID");
uuid_id!(ProviderCredentialId, "provider credential ID");
uuid_id!(RevocationId, "revocation ID");
uuid_id!(AuditEventId, "audit event ID");

macro_rules! bounded_string_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                let valid = !value.is_empty()
                    && value.len() <= 255
                    && value.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
                    });
                if !valid {
                    return Err(DomainError::InvalidValue {
                        kind: $kind,
                        reason: "must be 1..=255 safe identifier characters",
                    });
                }
                Ok(Self(value))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

bounded_string_id!(ProviderNodeId, "provider node ID");
bounded_string_id!(KeryxPeerId, "Keryx peer ID");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Generation(u64);
impl Generation {
    pub fn new(value: u64) -> Result<Self, DomainError> {
        if value == 0 {
            return Err(DomainError::InvalidValue {
                kind: "generation",
                reason: "must be positive",
            });
        }
        Ok(Self(value))
    }
    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
    pub fn validate_advance(self, expected: Self, next: Self) -> Result<(), DomainError> {
        if self != expected {
            return Err(DomainError::StaleGeneration {
                expected: expected.0,
                actual: self.0,
            });
        }
        if next.0 <= self.0 {
            return Err(DomainError::NonMonotonicGeneration);
        }
        Ok(())
    }
}
impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Node,
    Worker,
    Controller,
    ProfileHost,
    Observer,
    Admin,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Roles(BTreeSet<Role>);
impl Roles {
    pub fn new(values: impl IntoIterator<Item = Role>) -> Result<Self, DomainError> {
        let roles = values.into_iter().collect::<BTreeSet<_>>();
        if roles.is_empty() {
            return Err(DomainError::InvalidValue {
                kind: "roles",
                reason: "at least one role is required",
            });
        }
        Ok(Self(roles))
    }
    #[must_use]
    pub fn contains(&self, role: Role) -> bool {
        self.0.contains(&role)
    }
    #[must_use]
    pub const fn operations(&self) -> &'static [Operation] {
        &[]
    }
    pub fn iter(&self) -> impl Iterator<Item = Role> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Operation {
    FleetHealth,
    FleetInventory,
    FleetMessage,
    FleetHermesRun,
}
impl Operation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FleetHealth => "fleet.health",
            Self::FleetInventory => "fleet.inventory",
            Self::FleetMessage => "fleet.message",
            Self::FleetHermesRun => "fleet.hermes.run",
        }
    }
}
impl FromStr for Operation {
    type Err = DomainError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "fleet.health" => Ok(Self::FleetHealth),
            "fleet.inventory" => Ok(Self::FleetInventory),
            "fleet.message" => Ok(Self::FleetMessage),
            "fleet.hermes.run" => Ok(Self::FleetHermesRun),
            _ => Err(DomainError::InvalidValue {
                kind: "operation",
                reason: "unknown exact operation",
            }),
        }
    }
}

macro_rules! transition_enum {
    ($name:ident { $($variant:ident),+ $(,)? }, $allowed:expr) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn transition(self, next: Self) -> Result<Self, DomainError> {
                if self == next || ($allowed)(self, next) { Ok(next) } else { Err(DomainError::InvalidTransition { from: self.as_str(), to: next.as_str() }) }
            }
            #[must_use] pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => stringify!($variant)),+ } }
        }
    };
}

transition_enum!(
    NetworkState {
        Creating,
        Active,
        Suspended,
        Revoking,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            NetworkState::Creating,
            NetworkState::Active | NetworkState::Revoked
        ) | (
            NetworkState::Active,
            NetworkState::Suspended | NetworkState::Revoking
        ) | (
            NetworkState::Suspended,
            NetworkState::Active | NetworkState::Revoking
        ) | (NetworkState::Revoking, NetworkState::Revoked)
    )
);
transition_enum!(
    MembershipState {
        Pending,
        Joining,
        Active,
        Suspended,
        Revoking,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            MembershipState::Pending,
            MembershipState::Joining | MembershipState::Revoking | MembershipState::Revoked
        ) | (
            MembershipState::Joining,
            MembershipState::Revoking | MembershipState::Revoked
        ) | (
            MembershipState::Active,
            MembershipState::Suspended | MembershipState::Revoking
        ) | (MembershipState::Suspended, MembershipState::Revoking)
            | (MembershipState::Revoking, MembershipState::Revoked)
    )
);
transition_enum!(
    InvitationState {
        Issued,
        Redeemed,
        Exhausted,
        Expired,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            InvitationState::Issued,
            InvitationState::Redeemed
                | InvitationState::Exhausted
                | InvitationState::Expired
                | InvitationState::Revoked
        ) | (
            InvitationState::Redeemed,
            InvitationState::Exhausted | InvitationState::Expired | InvitationState::Revoked
        )
    )
);
transition_enum!(
    JoinSessionState {
        Created,
        InvitationValidated,
        ProviderCredentialIssued,
        MeshJoinObserved,
        AgentRegistered,
        KeryxBindingPending,
        KeryxBindingVerified,
        FleetProjectionPending,
        Active,
        Expired,
        Failed,
        Revoked
    },
    |a, b| {
        let terminal = matches!(
            b,
            JoinSessionState::Expired | JoinSessionState::Failed | JoinSessionState::Revoked
        ) && !matches!(
            a,
            JoinSessionState::Active
                | JoinSessionState::Expired
                | JoinSessionState::Failed
                | JoinSessionState::Revoked
        );
        terminal
            || matches!(
                (a, b),
                (
                    JoinSessionState::Created,
                    JoinSessionState::InvitationValidated
                ) | (
                    JoinSessionState::InvitationValidated,
                    JoinSessionState::ProviderCredentialIssued
                ) | (
                    JoinSessionState::ProviderCredentialIssued,
                    JoinSessionState::MeshJoinObserved
                ) | (
                    JoinSessionState::MeshJoinObserved,
                    JoinSessionState::AgentRegistered
                ) | (
                    JoinSessionState::AgentRegistered,
                    JoinSessionState::KeryxBindingPending
                ) | (
                    JoinSessionState::KeryxBindingPending,
                    JoinSessionState::KeryxBindingVerified
                ) | (
                    JoinSessionState::KeryxBindingVerified,
                    JoinSessionState::FleetProjectionPending
                ) | (
                    JoinSessionState::FleetProjectionPending,
                    JoinSessionState::Active
                )
            )
    }
);
transition_enum!(
    KeryxBindingState {
        Pending,
        Verified,
        RotationPending,
        Disabled,
        Tombstoned
    },
    |a, b| matches!(
        (a, b),
        (
            KeryxBindingState::Pending,
            KeryxBindingState::Verified
                | KeryxBindingState::Disabled
                | KeryxBindingState::Tombstoned
        ) | (
            KeryxBindingState::Verified,
            KeryxBindingState::RotationPending
                | KeryxBindingState::Disabled
                | KeryxBindingState::Tombstoned
        ) | (
            KeryxBindingState::RotationPending,
            KeryxBindingState::Verified
                | KeryxBindingState::Disabled
                | KeryxBindingState::Tombstoned
        ) | (KeryxBindingState::Disabled, KeryxBindingState::Tombstoned)
    )
);
transition_enum!(
    ProjectionStatus {
        NotRequested,
        Pending,
        Applied,
        FailedRetryable,
        Conflict,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            ProjectionStatus::NotRequested,
            ProjectionStatus::Pending | ProjectionStatus::Revoked
        ) | (
            ProjectionStatus::Pending,
            ProjectionStatus::Applied
                | ProjectionStatus::FailedRetryable
                | ProjectionStatus::Conflict
                | ProjectionStatus::Revoked
        ) | (
            ProjectionStatus::FailedRetryable,
            ProjectionStatus::Pending | ProjectionStatus::Revoked
        ) | (
            ProjectionStatus::Conflict,
            ProjectionStatus::Pending | ProjectionStatus::Revoked
        ) | (ProjectionStatus::Applied, ProjectionStatus::Revoked)
    )
);
transition_enum!(
    RevocationState {
        Requested,
        ApplicationTrustRemovalPending,
        CredentialRevocationPending,
        KeryxBindingDisablePending,
        ProviderCleanupPending,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            RevocationState::Requested,
            RevocationState::ApplicationTrustRemovalPending
        ) | (
            RevocationState::ApplicationTrustRemovalPending,
            RevocationState::CredentialRevocationPending
        ) | (
            RevocationState::CredentialRevocationPending,
            RevocationState::KeryxBindingDisablePending
        ) | (
            RevocationState::KeryxBindingDisablePending,
            RevocationState::ProviderCleanupPending
        ) | (
            RevocationState::ProviderCleanupPending,
            RevocationState::Revoked
        )
    )
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Fake,
    Headscale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderIdentity {
    pub provider_instance_id: ProviderInstanceId,
    pub node_id: ProviderNodeId,
    pub stable_key_fingerprint: String,
}
impl ProviderIdentity {
    pub fn new(
        provider_instance_id: ProviderInstanceId,
        node_id: ProviderNodeId,
        fingerprint: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let stable_key_fingerprint = fingerprint.into();
        if stable_key_fingerprint.is_empty() || stable_key_fingerprint.len() > 512 {
            return Err(DomainError::InvalidValue {
                kind: "provider fingerprint",
                reason: "must be bounded and non-empty",
            });
        }
        Ok(Self {
            provider_instance_id,
            node_id,
            stable_key_fingerprint,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeryxBindingIdentity {
    binding_id: KeryxBindingId,
    network_id: NetworkId,
    device_id: DeviceId,
    verified_peer_id: Option<KeryxPeerId>,
    generation: Generation,
    state: KeryxBindingState,
    verified_at: Option<DateTime<Utc>>,
    rotated_from: Option<KeryxBindingId>,
}

#[derive(Deserialize)]
struct PersistedKeryxBindingIdentity {
    binding_id: KeryxBindingId,
    network_id: NetworkId,
    device_id: DeviceId,
    verified_peer_id: Option<KeryxPeerId>,
    generation: Generation,
    state: KeryxBindingState,
    verified_at: Option<DateTime<Utc>>,
    rotated_from: Option<KeryxBindingId>,
}

impl<'de> Deserialize<'de> for KeryxBindingIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = PersistedKeryxBindingIdentity::deserialize(deserializer)?;
        if matches!(
            value.state,
            KeryxBindingState::Verified | KeryxBindingState::RotationPending
        ) || value.verified_peer_id.is_some()
            || value.verified_at.is_some()
        {
            return Err(serde::de::Error::custom(
                "verified Keryx bindings require the gated provenance path",
            ));
        }
        Ok(Self {
            binding_id: value.binding_id,
            network_id: value.network_id,
            device_id: value.device_id,
            verified_peer_id: None,
            generation: value.generation,
            state: value.state,
            verified_at: None,
            rotated_from: value.rotated_from,
        })
    }
}

impl KeryxBindingIdentity {
    #[must_use]
    pub fn pending(
        binding_id: KeryxBindingId,
        network_id: NetworkId,
        device_id: DeviceId,
        generation: Generation,
    ) -> Self {
        Self {
            binding_id,
            network_id,
            device_id,
            verified_peer_id: None,
            generation,
            state: KeryxBindingState::Pending,
            verified_at: None,
            rotated_from: None,
        }
    }

    #[must_use]
    pub fn binding_id(&self) -> KeryxBindingId {
        self.binding_id
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
    pub fn verified_peer_id(&self) -> Option<&KeryxPeerId> {
        self.verified_peer_id.as_ref()
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    #[must_use]
    pub fn state(&self) -> KeryxBindingState {
        self.state
    }
    #[must_use]
    pub fn verified_at(&self) -> Option<DateTime<Utc>> {
        self.verified_at
    }
    #[must_use]
    pub fn rotated_from(&self) -> Option<KeryxBindingId> {
        self.rotated_from
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceGenerations {
    pub credential: Generation,
    pub keryx_binding: Generation,
    pub fleet_projection: Generation,
}
impl DeviceGenerations {
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            credential: Generation::initial(),
            keryx_binding: Generation::initial(),
            fleet_projection: Generation::initial(),
        }
    }
    pub fn advance_credential(
        &mut self,
        expected: Generation,
        next: Generation,
    ) -> Result<(), DomainError> {
        self.credential.validate_advance(expected, next)?;
        self.credential = next;
        Ok(())
    }
    pub fn advance_keryx_binding(
        &mut self,
        expected: Generation,
        next: Generation,
    ) -> Result<(), DomainError> {
        self.keryx_binding.validate_advance(expected, next)?;
        self.keryx_binding = next;
        Ok(())
    }
    pub fn advance_fleet_projection(
        &mut self,
        expected: Generation,
        next: Generation,
    ) -> Result<(), DomainError> {
        self.fleet_projection.validate_advance(expected, next)?;
        self.fleet_projection = next;
        Ok(())
    }
}
impl Default for DeviceGenerations {
    fn default() -> Self {
        Self::initial()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Network {
    pub network_id: NetworkId,
    pub name: String,
    pub state: NetworkState,
    pub provider_kind: ProviderKind,
    pub provider_instance_id: ProviderInstanceId,
    pub membership_generation: Generation,
    pub policy_generation: Generation,
    pub default_roles: Roles,
    pub baseline_operations: BTreeSet<Operation>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl Network {
    pub fn new(
        network_id: NetworkId,
        name: impl Into<String>,
        provider_kind: ProviderKind,
        provider_instance_id: ProviderInstanceId,
        now: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let name = validate_name(name.into(), "network name")?;
        Ok(Self {
            network_id,
            name,
            state: NetworkState::Creating,
            provider_kind,
            provider_instance_id,
            membership_generation: Generation::initial(),
            policy_generation: Generation::initial(),
            default_roles: Roles::new([Role::Node])?,
            baseline_operations: [
                Operation::FleetHealth,
                Operation::FleetInventory,
                Operation::FleetMessage,
            ]
            .into_iter()
            .collect(),
            created_at: now,
            updated_at: now,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Device {
    pub device_id: DeviceId,
    pub network_id: NetworkId,
    pub display_name: String,
    pub membership_state: MembershipState,
    pub roles: Roles,
    pub provider_identity: Option<ProviderIdentity>,
    pub generations: DeviceGenerations,
    pub keryx_binding: Option<KeryxBindingIdentity>,
    pub fleet_projection_status: ProjectionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}
impl Device {
    pub fn new(
        device_id: DeviceId,
        network_id: NetworkId,
        display_name: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            device_id,
            network_id,
            display_name: validate_name(display_name.into(), "display name")?,
            membership_state: MembershipState::Pending,
            roles: Roles::new([Role::Node])?,
            provider_identity: None,
            generations: DeviceGenerations::initial(),
            keryx_binding: None,
            fleet_projection_status: ProjectionStatus::NotRequested,
            created_at: now,
            updated_at: now,
            revoked_at: None,
            revocation_reason: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretVerifier(String);
impl SecretVerifier {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for InvitationSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationSecret([REDACTED])")
    }
}
impl fmt::Display for InvitationSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct InvitationSecret(String);
impl InvitationSecret {
    pub fn new(value: String) -> Result<Self, DomainError> {
        if value.len() < 16 {
            return Err(DomainError::InvalidValue {
                kind: "invitation secret",
                reason: "must have at least 16 characters",
            });
        }
        Ok(Self(value))
    }
    #[must_use]
    pub fn verifier(&self) -> SecretVerifier {
        let digest = Sha256::digest(self.0.as_bytes());
        SecretVerifier(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
}

struct SecretText(String);
impl SecretText {
    fn new(value: String, kind: &'static str) -> Result<Self, DomainError> {
        if value.is_empty() {
            Err(DomainError::InvalidValue {
                kind,
                reason: "must be non-empty",
            })
        } else {
            Ok(Self(value))
        }
    }

    fn expose<R>(&self, f: impl for<'a> FnOnce(&'a str) -> R) -> R {
        f(&self.0)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn wipe(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretText {}

#[cfg(test)]
mod secret_tests {
    use super::SecretText;

    #[test]
    fn wipe_zeroizes_the_owned_allocation_before_drop() {
        let mut secret = SecretText::new("secret".into(), "test").unwrap();
        secret.wipe();
        assert_eq!(secret.expose(str::len), 0);
    }
}

macro_rules! redacted_secret {
    ($name:ident) => {
        pub struct $name(SecretText);
        impl $name {
            pub fn new(value: String) -> Result<Self, DomainError> {
                SecretText::new(value, stringify!($name)).map(Self)
            }
            pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a str) -> R) -> R {
                self.0.expose(f)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}([REDACTED])", stringify!($name))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[REDACTED]")
            }
        }
    };
}
redacted_secret!(ProviderApiKey);
redacted_secret!(ProviderJoinCredential);
redacted_secret!(DeviceCredential);
redacted_secret!(BindingNonce);

/// Opaque provider-native credential handle. It is deliberately neither
/// serializable nor displayable: a provider may use an integer or another
/// implementation-specific identifier, and it must never be mistaken for a
/// Nodescale UUID credential ID or exposed in diagnostics.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderCredentialReference(String);
impl ProviderCredentialReference {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            });
        if !valid {
            return Err(DomainError::InvalidValue {
                kind: "provider credential reference",
                reason: "must be 1..=255 safe identifier characters",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for ProviderCredentialReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCredentialReference([REDACTED])")
    }
}
impl fmt::Display for ProviderCredentialReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Invitation {
    pub invitation_id: InvitationId,
    pub network_id: NetworkId,
    pub state: InvitationState,
    pub roles: Roles,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
    pub used_count: u32,
    pub secret_verifier: SecretVerifier,
    pub provider_credential_reference: Option<ProviderCredentialId>,
    pub join_constraints: BTreeSet<String>,
}
impl Invitation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invitation_id: InvitationId,
        network_id: NetworkId,
        roles: Roles,
        secret_verifier: SecretVerifier,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        max_uses: u32,
    ) -> Result<Self, DomainError> {
        if expires_at <= created_at {
            return Err(DomainError::InvalidValue {
                kind: "invitation expiry",
                reason: "must follow creation",
            });
        }
        if max_uses == 0 {
            return Err(DomainError::InvalidValue {
                kind: "invitation max uses",
                reason: "must be positive",
            });
        }
        Ok(Self {
            invitation_id,
            network_id,
            state: InvitationState::Issued,
            roles,
            created_at,
            expires_at,
            max_uses,
            used_count: 0,
            secret_verifier,
            provider_credential_reference: None,
            join_constraints: BTreeSet::new(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JoinSession {
    pub join_session_id: JoinSessionId,
    pub invitation_id: InvitationId,
    pub network_id: NetworkId,
    pub device_id: Option<DeviceId>,
    pub state: JoinSessionState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub failure_reason: Option<String>,
}
impl JoinSession {
    pub fn new(
        join_session_id: JoinSessionId,
        invitation_id: InvitationId,
        network_id: NetworkId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if expires_at <= created_at {
            return Err(DomainError::InvalidValue {
                kind: "join session expiry",
                reason: "must follow creation",
            });
        }
        Ok(Self {
            join_session_id,
            invitation_id,
            network_id,
            device_id: None,
            state: JoinSessionState::Created,
            created_at,
            expires_at,
            updated_at: created_at,
            failure_reason: None,
        })
    }

    pub fn transition(
        &mut self,
        next: JoinSessionState,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        self.state = self.state.transition(next)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Revocation {
    pub revocation_id: RevocationId,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub state: RevocationState,
    pub requested_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub application_trust_removed_at: Option<DateTime<Utc>>,
    pub provider_cleanup_completed_at: Option<DateTime<Utc>>,
}
impl Revocation {
    #[must_use]
    pub fn requested(
        revocation_id: RevocationId,
        network_id: NetworkId,
        device_id: DeviceId,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            revocation_id,
            network_id,
            device_id,
            state: RevocationState::Requested,
            requested_at: now,
            updated_at: now,
            application_trust_removed_at: None,
            provider_cleanup_completed_at: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditActor {
    pub source: String,
    pub actor_id: Option<String>,
}
impl AuditActor {
    #[must_use]
    pub fn system() -> Self {
        Self {
            source: "nodescale".into(),
            actor_id: None,
        }
    }
}

fn validate_name(value: String, kind: &'static str) -> Result<String, DomainError> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(DomainError::InvalidValue {
            kind,
            reason: "must be 1..=128 printable characters",
        });
    }
    Ok(value)
}
