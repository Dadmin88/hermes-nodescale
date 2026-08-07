//! Pure Nodescale domain model and fail-closed lifecycle rules.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
        Redeeming,
        Consumed,
        Revoking,
        Expiring,
        Failed,
        Redeemed,
        Exhausted,
        Expired,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            InvitationState::Issued,
            InvitationState::Redeeming
                | InvitationState::Revoking
                | InvitationState::Expiring
                | InvitationState::Redeemed
                | InvitationState::Exhausted
                | InvitationState::Expired
                | InvitationState::Revoked
        ) | (
            InvitationState::Redeeming,
            InvitationState::Consumed
                | InvitationState::Revoking
                | InvitationState::Expiring
                | InvitationState::Failed
                | InvitationState::Expired
                | InvitationState::Revoked
        ) | (
            InvitationState::Failed,
            InvitationState::Revoking | InvitationState::Expiring
        ) | (
            InvitationState::Consumed,
            InvitationState::Revoking | InvitationState::Expiring
        ) | (
            InvitationState::Revoking,
            InvitationState::Revoked | InvitationState::Failed
        ) | (
            InvitationState::Expiring,
            InvitationState::Expired | InvitationState::Failed
        ) | (
            InvitationState::Redeemed,
            InvitationState::Exhausted
                | InvitationState::Revoking
                | InvitationState::Expiring
                | InvitationState::Expired
                | InvitationState::Revoked
        )
    )
);
transition_enum!(
    JoinSessionState {
        Created,
        InvitationValidated,
        ProviderCredentialIssuing,
        ProviderCredentialIssued,
        ProviderCredentialAmbiguous,
        ProviderCredentialRevocationPending,
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
                    JoinSessionState::ProviderCredentialIssuing
                ) | (
                    JoinSessionState::ProviderCredentialIssuing,
                    JoinSessionState::ProviderCredentialIssued
                        | JoinSessionState::ProviderCredentialAmbiguous
                        | JoinSessionState::ProviderCredentialRevocationPending
                ) | (
                    JoinSessionState::ProviderCredentialIssued,
                    JoinSessionState::ProviderCredentialRevocationPending
                ) | (
                    JoinSessionState::ProviderCredentialAmbiguous,
                    JoinSessionState::ProviderCredentialRevocationPending
                ) | (
                    JoinSessionState::ProviderCredentialRevocationPending,
                    JoinSessionState::Revoked | JoinSessionState::Expired
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

/// Fixed N4 token hashing profile: Argon2id v1.3, 19 MiB memory, two passes,
/// one lane, and a 32-byte output. Tokens already carry 256 bits of CSPRNG entropy;
/// this bounded profile hardens a disclosed verifier without imposing the heavier
/// cost intended for human passwords. A future network ingress must still rate-limit.
const N4_ARGON_MEMORY_KIB: u32 = 19_456;
const N4_ARGON_TIME_COST: u32 = 2;
const N4_ARGON_PARALLELISM: u32 = 1;
const N4_ARGON_OUTPUT_LEN: usize = 32;
const INVITATION_TOKEN_PREFIX: &str = "nsjoin_";
const INVITATION_TOKEN_BYTES: usize = 48;
const INVITATION_TOKEN_ENCODED_LEN: usize = 64;

/// Opaque, one-time delivery material for a N4 invitation. The embedded UUID is
/// lookup-only; authentication always uses the 256-bit random secret.
pub struct InvitationToken {
    invitation_id: InvitationId,
    secret: [u8; N4_ARGON_OUTPUT_LEN],
}
impl InvitationToken {
    #[must_use]
    pub fn generate(invitation_id: InvitationId) -> Self {
        let mut secret = [0_u8; N4_ARGON_OUTPUT_LEN];
        OsRng.fill_bytes(&mut secret);
        Self {
            invitation_id,
            secret,
        }
    }

    #[must_use]
    pub const fn invitation_id(&self) -> InvitationId {
        self.invitation_id
    }

    /// Exposes the plaintext only for immediate delivery. Callers must not retain
    /// the supplied string or treat the embedded invitation ID as authentication.
    pub fn expose_for_delivery<R>(self, f: impl for<'a> FnOnce(&'a str) -> R) -> R {
        let mut bytes = [0_u8; INVITATION_TOKEN_BYTES];
        bytes[..16].copy_from_slice(self.invitation_id.0.as_bytes());
        bytes[16..].copy_from_slice(&self.secret);
        let plaintext = Zeroizing::new(format!(
            "{INVITATION_TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ));
        bytes.zeroize();
        f(plaintext.as_str())
    }

    fn with_secret<R>(&self, f: impl FnOnce(&[u8; N4_ARGON_OUTPUT_LEN]) -> R) -> R {
        f(&self.secret)
    }
}
impl Drop for InvitationToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl fmt::Debug for InvitationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationToken([REDACTED])")
    }
}
impl fmt::Display for InvitationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl FromStr for InvitationToken {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded =
            value
                .strip_prefix(INVITATION_TOKEN_PREFIX)
                .ok_or(DomainError::InvalidValue {
                    kind: "invitation token",
                    reason: "must use the exact nsjoin_ prefix",
                })?;
        if encoded.len() != INVITATION_TOKEN_ENCODED_LEN
            || value.len() != INVITATION_TOKEN_PREFIX.len() + INVITATION_TOKEN_ENCODED_LEN
        {
            return Err(DomainError::InvalidValue {
                kind: "invitation token",
                reason: "must be an exact 48-byte base64url token without padding",
            });
        }

        let mut bytes = [0_u8; INVITATION_TOKEN_BYTES];
        let decoded = match URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes) {
            Ok(decoded) => decoded,
            Err(_) => {
                bytes.zeroize();
                return Err(DomainError::InvalidValue {
                    kind: "invitation token",
                    reason: "must be canonical base64url without padding",
                });
            }
        };
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        if decoded != INVITATION_TOKEN_BYTES || canonical.as_str() != encoded {
            bytes.zeroize();
            return Err(DomainError::InvalidValue {
                kind: "invitation token",
                reason: "must be canonical base64url without padding",
            });
        }
        let uuid = Uuid::from_bytes(bytes[..16].try_into().expect("fixed UUID byte width"));
        let invitation_id = match InvitationId::parse(&uuid.to_string()) {
            Ok(invitation_id) => invitation_id,
            Err(error) => {
                bytes.zeroize();
                return Err(error);
            }
        };
        let mut secret = [0_u8; N4_ARGON_OUTPUT_LEN];
        secret.copy_from_slice(&bytes[16..]);
        bytes.zeroize();
        Ok(Self {
            invitation_id,
            secret,
        })
    }
}

/// A persisted verifier only. It never contains a plaintext invitation token.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretVerifier(String);
impl<'de> Deserialize<'de> for SecretVerifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if validate_n4_verifier(&value).is_ok() || is_legacy_sha256_verifier(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                "secret verifier must be a fixed N4 Argon2id PHC or legacy SHA-256 digest",
            ))
        }
    }
}
impl SecretVerifier {
    /// Builds an Argon2id PHC verifier using a fresh random salt for this record.
    pub fn from_token(token: &InvitationToken) -> Result<Self, DomainError> {
        let params = n4_argon_params()?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        token.with_secret(|secret| {
            let salt = SaltString::generate(&mut OsRng);
            let phc = argon
                .hash_password(secret, &salt)
                .map_err(|_| invalid_verifier())?
                .to_string();
            Self::parse(phc)
        })
    }

    /// Validates a stored N4 Argon2id PHC verifier before accepting persistence.
    pub fn parse(value: String) -> Result<Self, DomainError> {
        validate_n4_verifier(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verifies a N4 token against this persisted PHC record without exposing its
    /// plaintext token representation.
    pub fn verify(&self, token: &InvitationToken) -> Result<bool, DomainError> {
        let parsed = validate_n4_verifier(&self.0)?;
        token.with_secret(|secret| Ok(Argon2::default().verify_password(secret, &parsed).is_ok()))
    }

    fn is_n4(&self) -> bool {
        validate_n4_verifier(&self.0).is_ok()
    }

    fn legacy_sha256(value: String) -> Self {
        Self(value)
    }
}
impl fmt::Debug for SecretVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretVerifier([REDACTED])")
    }
}
impl fmt::Display for SecretVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

fn n4_argon_params() -> Result<Params, DomainError> {
    Params::new(
        N4_ARGON_MEMORY_KIB,
        N4_ARGON_TIME_COST,
        N4_ARGON_PARALLELISM,
        Some(N4_ARGON_OUTPUT_LEN),
    )
    .map_err(|_| invalid_verifier())
}

fn validate_n4_verifier(value: &str) -> Result<PasswordHash<'_>, DomainError> {
    let parsed = PasswordHash::new(value).map_err(|_| invalid_verifier())?;
    let correct_profile = parsed.algorithm.as_str() == "argon2id"
        && parsed.version == Some(0x13)
        && parsed.params.get_decimal("m") == Some(N4_ARGON_MEMORY_KIB)
        && parsed.params.get_decimal("t") == Some(N4_ARGON_TIME_COST)
        && parsed.params.get_decimal("p") == Some(N4_ARGON_PARALLELISM)
        && parsed
            .hash
            .is_some_and(|hash| hash.as_bytes().len() == N4_ARGON_OUTPUT_LEN);
    if correct_profile {
        Ok(parsed)
    } else {
        Err(invalid_verifier())
    }
}

fn is_legacy_sha256_verifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_verifier() -> DomainError {
    DomainError::InvalidValue {
        kind: "secret verifier",
        reason: "must be the fixed Argon2id PHC N4 profile",
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

/// Legacy N0-N3 compatibility only. It cannot be used by `Invitation::new_n4`.
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
        SecretVerifier::legacy_sha256(digest.iter().map(|byte| format!("{byte:02x}")).collect())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationAdminIntent {
    _explicit: (),
}
impl InvitationAdminIntent {
    /// Explicit construction is required whenever an invitation assigns `Role::Admin`.
    #[must_use]
    pub const fn explicit() -> Self {
        Self { _explicit: () }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvitationWorkflow {
    #[default]
    Legacy,
    N4a,
}

/// Optional bounded matching hints. They are not authenticated identity claims.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct JoinConstraints {
    expected_platform: Option<String>,
    expected_hostname_hint: Option<String>,
}
impl JoinConstraints {
    pub fn new(
        expected_platform: Option<String>,
        expected_hostname_hint: Option<String>,
    ) -> Result<Self, DomainError> {
        validate_join_hint(expected_platform.as_deref(), "expected platform", 64)?;
        validate_join_hint(
            expected_hostname_hint.as_deref(),
            "expected hostname hint",
            128,
        )?;
        Ok(Self {
            expected_platform,
            expected_hostname_hint,
        })
    }

    #[must_use]
    pub fn expected_platform(&self) -> Option<&str> {
        self.expected_platform.as_deref()
    }

    #[must_use]
    pub fn expected_hostname_hint(&self) -> Option<&str> {
        self.expected_hostname_hint.as_deref()
    }
}
impl<'de> Deserialize<'de> for JoinConstraints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            N4 {
                #[serde(default)]
                expected_platform: Option<String>,
                #[serde(default)]
                expected_hostname_hint: Option<String>,
            },
            Legacy(BTreeSet<String>),
        }

        match Wire::deserialize(deserializer)? {
            Wire::N4 {
                expected_platform,
                expected_hostname_hint,
            } => JoinConstraints::new(expected_platform, expected_hostname_hint)
                .map_err(serde::de::Error::custom),
            // Legacy constraints were untyped strings. Retain persistence compatibility
            // without promoting them to an identity or a N4 matching condition.
            Wire::Legacy(_legacy) => Ok(Self::default()),
        }
    }
}

fn validate_join_hint(
    value: Option<&str>,
    kind: &'static str,
    max_len: usize,
) -> Result<(), DomainError> {
    if value.is_some_and(|hint| {
        hint.is_empty()
            || hint.len() > max_len
            || hint.chars().any(char::is_control)
            || hint.trim() != hint
    }) {
        return Err(DomainError::InvalidValue {
            kind,
            reason: "must be a bounded printable hint, not an identity",
        });
    }
    Ok(())
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
    #[serde(default)]
    pub join_constraints: JoinConstraints,
    #[serde(default)]
    workflow: InvitationWorkflow,
    #[serde(default)]
    elevated_admin_intent: bool,
}
impl Invitation {
    /// Legacy N0-N3 constructor. It deliberately rejects `Role::Admin`; N4 admin
    /// invitations must use `new_n4` with an explicit `InvitationAdminIntent`.
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
        validate_invitation_issuance(&roles, None, false)?;
        Self::build(
            invitation_id,
            network_id,
            roles,
            secret_verifier,
            JoinConstraints::default(),
            created_at,
            expires_at,
            max_uses,
            InvitationWorkflow::Legacy,
            false,
        )
    }

    /// Issues an N4 invitation. Legacy `InvitationSecret` verifiers are rejected,
    /// and `Role::Admin` is accepted only with explicit elevated intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_n4(
        invitation_id: InvitationId,
        network_id: NetworkId,
        roles: Roles,
        admin_intent: Option<InvitationAdminIntent>,
        secret_verifier: SecretVerifier,
        join_constraints: JoinConstraints,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        max_uses: u32,
    ) -> Result<Self, DomainError> {
        validate_invitation_issuance(&roles, admin_intent, true)?;
        let elevated_admin_intent = admin_intent.is_some();
        if !secret_verifier.is_n4() {
            return Err(DomainError::InvalidValue {
                kind: "N4 invitation verifier",
                reason: "must be generated from an InvitationToken",
            });
        }
        if max_uses != 1 {
            return Err(DomainError::InvalidValue {
                kind: "N4 invitation max uses",
                reason: "N4 invitations are exactly single-use",
            });
        }
        Self::build(
            invitation_id,
            network_id,
            roles,
            secret_verifier,
            join_constraints,
            created_at,
            expires_at,
            max_uses,
            InvitationWorkflow::N4a,
            elevated_admin_intent,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        invitation_id: InvitationId,
        network_id: NetworkId,
        roles: Roles,
        secret_verifier: SecretVerifier,
        join_constraints: JoinConstraints,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        max_uses: u32,
        workflow: InvitationWorkflow,
        elevated_admin_intent: bool,
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
            join_constraints,
            workflow,
            elevated_admin_intent,
        })
    }

    #[must_use]
    pub const fn is_n4(&self) -> bool {
        matches!(self.workflow, InvitationWorkflow::N4a)
    }

    pub fn validate_n4_issuance(&self) -> Result<(), DomainError> {
        if !self.is_n4()
            || self.state != InvitationState::Issued
            || !self.secret_verifier.is_n4()
            || self.max_uses != 1
            || self.used_count != 0
            || self.provider_credential_reference.is_some()
            || self.roles.contains(Role::Admin) != self.elevated_admin_intent
        {
            return Err(DomainError::InvalidValue {
                kind: "N4 invitation",
                reason: "record does not satisfy N4 issuance invariants",
            });
        }
        Ok(())
    }
}

fn validate_invitation_issuance(
    roles: &Roles,
    admin_intent: Option<InvitationAdminIntent>,
    n4: bool,
) -> Result<(), DomainError> {
    match (roles.contains(Role::Admin), admin_intent.is_some(), n4) {
        (true, true, true) | (false, false, _) => Ok(()),
        (true, false, _) => Err(DomainError::InvalidValue {
            kind: "invitation admin intent",
            reason: "Role::Admin requires explicit elevated intent",
        }),
        (false, true, _) => Err(DomainError::InvalidValue {
            kind: "invitation admin intent",
            reason: "cannot be present without Role::Admin",
        }),
        (true, true, false) => Err(DomainError::InvalidValue {
            kind: "invitation admin intent",
            reason: "Role::Admin requires the N4 invitation constructor",
        }),
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JoinWorkflow {
    #[default]
    Legacy,
    N4a,
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
    #[serde(default)]
    workflow: JoinWorkflow,
}
impl JoinSession {
    pub fn new(
        join_session_id: JoinSessionId,
        invitation_id: InvitationId,
        network_id: NetworkId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        Self::build(
            join_session_id,
            invitation_id,
            network_id,
            created_at,
            expires_at,
            JoinWorkflow::Legacy,
        )
    }

    pub fn new_n4(
        join_session_id: JoinSessionId,
        invitation_id: InvitationId,
        network_id: NetworkId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        Self::build(
            join_session_id,
            invitation_id,
            network_id,
            created_at,
            expires_at,
            JoinWorkflow::N4a,
        )
    }

    fn build(
        join_session_id: JoinSessionId,
        invitation_id: InvitationId,
        network_id: NetworkId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        workflow: JoinWorkflow,
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
            workflow,
        })
    }

    #[must_use]
    pub const fn is_n4(&self) -> bool {
        matches!(self.workflow, JoinWorkflow::N4a)
    }

    pub fn transition(
        &mut self,
        next: JoinSessionState,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        if self.is_n4() {
            let future_state = matches!(
                next,
                JoinSessionState::MeshJoinObserved
                    | JoinSessionState::AgentRegistered
                    | JoinSessionState::KeryxBindingPending
                    | JoinSessionState::KeryxBindingVerified
                    | JoinSessionState::FleetProjectionPending
                    | JoinSessionState::Active
            );
            let skips_credential_cleanup = self.state == JoinSessionState::ProviderCredentialIssued
                && next != JoinSessionState::ProviderCredentialRevocationPending;
            if future_state || skips_credential_cleanup {
                return Err(DomainError::InvalidTransition {
                    from: self.state.as_str(),
                    to: next.as_str(),
                });
            }
        }
        self.state = self.state.transition(next)?;
        self.updated_at = now;
        Ok(())
    }

    /// N4 deliberately stops after issuing a provider credential. Later mesh,
    /// agent, binding, projection, and activation stages belong to future slices.
    pub fn advance_n4(
        &mut self,
        next: JoinSessionState,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        if !self.is_n4() {
            return Err(DomainError::InvalidTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }
        let n4_state = matches!(
            self.state,
            JoinSessionState::Created
                | JoinSessionState::InvitationValidated
                | JoinSessionState::ProviderCredentialIssuing
                | JoinSessionState::ProviderCredentialIssued
                | JoinSessionState::ProviderCredentialAmbiguous
                | JoinSessionState::ProviderCredentialRevocationPending
        );
        let n4_next = matches!(
            next,
            JoinSessionState::InvitationValidated
                | JoinSessionState::ProviderCredentialIssuing
                | JoinSessionState::ProviderCredentialIssued
                | JoinSessionState::ProviderCredentialAmbiguous
                | JoinSessionState::ProviderCredentialRevocationPending
                | JoinSessionState::Expired
                | JoinSessionState::Failed
                | JoinSessionState::Revoked
        );
        if !n4_state || !n4_next {
            return Err(DomainError::InvalidTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }
        self.transition(next, now)
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
