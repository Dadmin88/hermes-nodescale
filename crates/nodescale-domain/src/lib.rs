//! Pure Nodescale domain model and fail-closed lifecycle rules.

pub mod n7;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
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
uuid_id!(KeryxBindingChallengeId, "Keryx binding challenge ID");
uuid_id!(KeryxBindingDecisionId, "Keryx binding decision ID");
uuid_id!(
    KeryxBindingAuthorizationId,
    "Keryx binding authorization ID"
);
uuid_id!(ProviderInstanceId, "provider instance ID");
uuid_id!(ProviderCredentialId, "provider credential ID");
uuid_id!(RevocationId, "revocation ID");
uuid_id!(AuditEventId, "audit event ID");
uuid_id!(ProviderBindingId, "provider binding ID");
uuid_id!(TrustRootId, "trust root ID");
uuid_id!(TrustAuthorityId, "trust authority ID");
uuid_id!(TrustDecisionId, "trust decision ID");
uuid_id!(TrustActionId, "trust action ID");

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
    pub fn next_exact(self) -> Result<Self, DomainError> {
        self.0
            .checked_add(1)
            .ok_or(DomainError::NonMonotonicGeneration)
            .and_then(Self::new)
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
            MembershipState::Active | MembershipState::Revoking | MembershipState::Revoked
        ) | (
            MembershipState::Active,
            MembershipState::Suspended | MembershipState::Revoking
        ) | (MembershipState::Suspended, MembershipState::Revoking)
            | (MembershipState::Revoking, MembershipState::Revoked)
    )
);
transition_enum!(
    DeviceTrustState {
        Untrusted,
        Trusted,
        Revoked
    },
    |a, b| matches!(
        (a, b),
        (
            DeviceTrustState::Untrusted,
            DeviceTrustState::Trusted | DeviceTrustState::Revoked
        ) | (DeviceTrustState::Trusted, DeviceTrustState::Revoked)
    )
);
transition_enum!(
    ProviderBindingState {
        Active,
        Stale,
        CleanupPending,
        Removed
    },
    |a, b| matches!(
        (a, b),
        (
            ProviderBindingState::Active,
            ProviderBindingState::Stale | ProviderBindingState::CleanupPending
        ) | (
            ProviderBindingState::Stale,
            ProviderBindingState::CleanupPending | ProviderBindingState::Removed
        ) | (
            ProviderBindingState::CleanupPending,
            ProviderBindingState::Removed
        )
    )
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum DeviceTrustCapability {
    ActivateDeviceTrust,
    RevokeDeviceTrust,
    AdoptExistingProviderDevice,
}
impl DeviceTrustCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivateDeviceTrust => "ActivateDeviceTrust",
            Self::RevokeDeviceTrust => "RevokeDeviceTrust",
            Self::AdoptExistingProviderDevice => "AdoptExistingProviderDevice",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDecisionKind {
    Activate,
    Revoke,
}
impl TrustDecisionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Revoke => "revoke",
        }
    }
}

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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeryxBindingState {
    Pending,
    Active,
    Stale,
    Rotated,
    Revoked,
}
impl KeryxBindingState {
    pub fn transition(self, next: Self) -> Result<Self, DomainError> {
        if matches!(
            (self, next),
            (Self::Pending, Self::Active | Self::Revoked)
                | (Self::Active, Self::Stale | Self::Rotated | Self::Revoked)
                | (Self::Stale, Self::Rotated | Self::Revoked)
        ) {
            Ok(next)
        } else {
            Err(DomainError::InvalidTransition {
                from: self.as_str(),
                to: next.as_str(),
            })
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Rotated => "rotated",
            Self::Revoked => "revoked",
        }
    }
}
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
        ) | (
            ProjectionStatus::Applied,
            ProjectionStatus::Pending | ProjectionStatus::Revoked
        )
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
    Tailscale,
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
#[serde(transparent)]
pub struct AgentVersion(String);
impl<'de> Deserialize<'de> for AgentVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl AgentVersion {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if !(1..=128).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            })
        {
            return Err(DomainError::InvalidValue {
                kind: "agent version",
                reason: "must be 1..=128 ASCII [A-Za-z0-9_.:-] characters",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct KeryxBindingIdentityRecord {
    binding_id: KeryxBindingId,
    network_id: NetworkId,
    device_id: DeviceId,
    provider_binding_id: ProviderBindingId,
    verified_peer_id: Option<KeryxPeerId>,
    generation: Generation,
    revision: u64,
    state: KeryxBindingState,
    created_at: DateTime<Utc>,
    confirmed_at: Option<DateTime<Utc>>,
    rotated_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    stale_at: Option<DateTime<Utc>>,
    last_verified_at: Option<DateTime<Utc>>,
    /// Local lineage shape only. State SQL proves this is the exact generation
    /// `n - 1` predecessor and revision before accepting the row.
    rotated_from: Option<KeryxBindingId>,
    agent_version: AgentVersion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeryxBindingIdentity(KeryxBindingIdentityRecord);

impl KeryxBindingIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn pending(
        binding_id: KeryxBindingId,
        network_id: NetworkId,
        device_id: DeviceId,
        provider_binding_id: ProviderBindingId,
        generation: Generation,
        revision: u64,
        created_at: DateTime<Utc>,
        agent_version: AgentVersion,
    ) -> Result<Self, DomainError> {
        Self::from_persisted(KeryxBindingIdentityRecord {
            binding_id,
            network_id,
            device_id,
            provider_binding_id,
            verified_peer_id: None,
            generation,
            revision,
            state: KeryxBindingState::Pending,
            created_at,
            confirmed_at: None,
            rotated_at: None,
            revoked_at: None,
            stale_at: None,
            last_verified_at: None,
            rotated_from: None,
            agent_version,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pending_rotation(
        binding_id: KeryxBindingId,
        network_id: NetworkId,
        device_id: DeviceId,
        provider_binding_id: ProviderBindingId,
        generation: Generation,
        revision: u64,
        created_at: DateTime<Utc>,
        agent_version: AgentVersion,
        rotated_from: KeryxBindingId,
    ) -> Result<Self, DomainError> {
        Self::from_persisted(KeryxBindingIdentityRecord {
            binding_id,
            network_id,
            device_id,
            provider_binding_id,
            verified_peer_id: None,
            generation,
            revision,
            state: KeryxBindingState::Pending,
            created_at,
            confirmed_at: None,
            rotated_at: None,
            revoked_at: None,
            stale_at: None,
            last_verified_at: None,
            rotated_from: Some(rotated_from),
            agent_version,
        })
    }

    fn from_persisted(record: KeryxBindingIdentityRecord) -> Result<Self, DomainError> {
        validate_keryx_binding_identity(&record)?;
        Ok(Self(record))
    }

    #[must_use]
    pub fn binding_id(&self) -> KeryxBindingId {
        self.0.binding_id
    }
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.0.network_id
    }
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.0.device_id
    }
    #[must_use]
    pub fn provider_binding_id(&self) -> ProviderBindingId {
        self.0.provider_binding_id
    }
    #[must_use]
    pub fn verified_peer_id(&self) -> Option<&KeryxPeerId> {
        self.0.verified_peer_id.as_ref()
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.0.generation
    }
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.0.revision
    }
    #[must_use]
    pub fn state(&self) -> KeryxBindingState {
        self.0.state
    }
    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
    #[must_use]
    pub fn confirmed_at(&self) -> Option<DateTime<Utc>> {
        self.0.confirmed_at
    }
    #[must_use]
    pub fn rotated_at(&self) -> Option<DateTime<Utc>> {
        self.0.rotated_at
    }
    #[must_use]
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.0.revoked_at
    }
    #[must_use]
    pub fn stale_at(&self) -> Option<DateTime<Utc>> {
        self.0.stale_at
    }
    #[must_use]
    pub fn last_verified_at(&self) -> Option<DateTime<Utc>> {
        self.0.last_verified_at
    }
    #[must_use]
    pub fn rotated_from(&self) -> Option<KeryxBindingId> {
        self.0.rotated_from
    }
    #[must_use]
    pub fn agent_version(&self) -> &AgentVersion {
        &self.0.agent_version
    }
}

fn validate_keryx_binding_identity_authority_values(
    record: &KeryxBindingIdentityRecord,
) -> Result<(), DomainError> {
    KeryxBindingId::parse(&record.binding_id.to_string())?;
    NetworkId::parse(&record.network_id.to_string())?;
    DeviceId::parse(&record.device_id.to_string())?;
    ProviderBindingId::parse(&record.provider_binding_id.to_string())?;
    if let Some(rotated_from) = record.rotated_from {
        KeryxBindingId::parse(&rotated_from.to_string())?;
    }
    if let Some(peer_id) = &record.verified_peer_id {
        KeryxPeerId::parse(peer_id.as_str())?;
    }
    if record.generation.get() == 0 {
        return Err(DomainError::InvalidValue {
            kind: "generation",
            reason: "must be positive",
        });
    }
    Ok(())
}

fn validate_keryx_binding_rotation_lineage(
    record: &KeryxBindingIdentityRecord,
) -> Result<(), DomainError> {
    if record.generation.get() == 1 {
        if record.rotated_from.is_none() {
            return Ok(());
        }
        return Err(DomainError::InvalidValue {
            kind: "Keryx binding rotation",
            reason: "generation one cannot have a predecessor",
        });
    }
    match record.rotated_from {
        Some(predecessor) if predecessor != record.binding_id => Ok(()),
        None => Err(DomainError::InvalidValue {
            kind: "Keryx binding rotation",
            reason: "successor generations require a predecessor",
        }),
        Some(_) => Err(DomainError::InvalidValue {
            kind: "Keryx binding rotation",
            reason: "cannot rotate from itself",
        }),
    }
}

fn validate_keryx_binding_identity(record: &KeryxBindingIdentityRecord) -> Result<(), DomainError> {
    validate_keryx_binding_identity_authority_values(record)?;
    if record.revision == 0 {
        return Err(DomainError::InvalidValue {
            kind: "Keryx binding revision",
            reason: "must be positive",
        });
    }
    for timestamp in [
        record.confirmed_at,
        record.rotated_at,
        record.revoked_at,
        record.stale_at,
        record.last_verified_at,
    ] {
        if timestamp.is_some_and(|timestamp| timestamp < record.created_at) {
            return Err(DomainError::InvalidValue {
                kind: "Keryx binding timestamp",
                reason: "cannot precede creation",
            });
        }
    }
    validate_keryx_binding_rotation_lineage(record)?;
    let peer_and_confirmation = record.verified_peer_id.is_some() && record.confirmed_at.is_some();
    let no_peer_evidence = record.verified_peer_id.is_none() && record.confirmed_at.is_none();
    let valid = match record.state {
        KeryxBindingState::Pending => {
            no_peer_evidence
                && record.rotated_at.is_none()
                && record.revoked_at.is_none()
                && record.stale_at.is_none()
                && record.last_verified_at.is_none()
        }
        KeryxBindingState::Active => {
            peer_and_confirmation
                && record.rotated_at.is_none()
                && record.revoked_at.is_none()
                && record.stale_at.is_none()
                && record.last_verified_at.is_some()
        }
        KeryxBindingState::Stale => {
            peer_and_confirmation
                && record.stale_at.is_some()
                && record.rotated_at.is_none()
                && record.revoked_at.is_none()
                && record.last_verified_at.is_some()
        }
        KeryxBindingState::Rotated => {
            peer_and_confirmation
                && record.rotated_at.is_some()
                && record.revoked_at.is_none()
                && record.last_verified_at.is_some()
        }
        KeryxBindingState::Revoked => {
            record.revoked_at.is_some()
                && record.rotated_at.is_none()
                && ((no_peer_evidence
                    && record.stale_at.is_none()
                    && record.last_verified_at.is_none())
                    || (peer_and_confirmation && record.last_verified_at.is_some()))
        }
    };
    if !valid {
        return Err(DomainError::InvalidValue {
            kind: "Keryx binding identity",
            reason: "state evidence and lifecycle timestamps are inconsistent",
        });
    }
    if record.last_verified_at.is_some() && record.verified_peer_id.is_none() {
        return Err(DomainError::InvalidValue {
            kind: "Keryx binding last verification",
            reason: "requires verified peer evidence",
        });
    }
    if let Some(confirmed_at) = record.confirmed_at {
        for timestamp in [
            record.last_verified_at,
            record.stale_at,
            record.rotated_at,
            record.revoked_at,
        ] {
            if timestamp.is_some_and(|timestamp| timestamp < confirmed_at) {
                return Err(DomainError::InvalidValue {
                    kind: "Keryx binding timestamp",
                    reason: "cannot precede confirmation",
                });
            }
        }
    }
    let last_verification_upper_bound = match record.state {
        KeryxBindingState::Stale => record.stale_at,
        KeryxBindingState::Rotated => record.stale_at.or(record.rotated_at),
        KeryxBindingState::Revoked => record.stale_at.or(record.revoked_at),
        KeryxBindingState::Pending | KeryxBindingState::Active => None,
    };
    if let (Some(last_verified_at), Some(transition_at)) =
        (record.last_verified_at, last_verification_upper_bound)
    {
        if last_verified_at > transition_at {
            return Err(DomainError::InvalidValue {
                kind: "Keryx binding last verification",
                reason: "cannot follow an irreversible lifecycle transition",
            });
        }
    }
    for (earlier, later, reason) in [
        (
            record.stale_at,
            record.rotated_at,
            "stale evidence cannot follow rotation",
        ),
        (
            record.stale_at,
            record.revoked_at,
            "stale evidence cannot follow revocation",
        ),
    ] {
        if let (Some(earlier), Some(later)) = (earlier, later) {
            if earlier > later {
                return Err(DomainError::InvalidValue {
                    kind: "Keryx binding timestamp",
                    reason,
                });
            }
        }
    }
    if record.last_verified_at.is_some_and(|timestamp| {
        timestamp
            < record
                .confirmed_at
                .expect("peer evidence includes confirmation")
    }) {
        return Err(DomainError::InvalidValue {
            kind: "Keryx binding last verification",
            reason: "cannot precede confirmation",
        });
    }
    Ok(())
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
    /// Durable N6 identity is state-owned and is never accepted from a public
    /// Device deserialization boundary.
    #[serde(skip_deserializing)]
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
const LEGACY_INVITATION_ARGON_TIME_COST: u32 = 3;
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

/// Opaque local-owner capability for configuring and using the N5 trust root.
/// The UUID is lookup-only; authorization always requires the random secret.
pub struct OwnerTrustRootToken {
    trust_root_id: TrustRootId,
    secret: [u8; N4_ARGON_OUTPUT_LEN],
}
impl OwnerTrustRootToken {
    #[must_use]
    pub fn generate(trust_root_id: TrustRootId) -> Self {
        let mut secret = [0_u8; N4_ARGON_OUTPUT_LEN];
        OsRng.fill_bytes(&mut secret);
        Self {
            trust_root_id,
            secret,
        }
    }

    #[must_use]
    pub const fn trust_root_id(&self) -> TrustRootId {
        self.trust_root_id
    }

    pub fn expose_for_delivery<R>(self, f: impl for<'a> FnOnce(&'a str) -> R) -> R {
        const PREFIX: &str = "nstrust_";
        let mut bytes = [0_u8; INVITATION_TOKEN_BYTES];
        bytes[..16].copy_from_slice(self.trust_root_id.0.as_bytes());
        bytes[16..].copy_from_slice(&self.secret);
        let plaintext = Zeroizing::new(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
        bytes.zeroize();
        f(plaintext.as_str())
    }

    fn with_secret<R>(&self, f: impl FnOnce(&[u8; N4_ARGON_OUTPUT_LEN]) -> R) -> R {
        f(&self.secret)
    }
}
impl Drop for OwnerTrustRootToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl fmt::Debug for OwnerTrustRootToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerTrustRootToken([REDACTED])")
    }
}
impl fmt::Display for OwnerTrustRootToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl FromStr for OwnerTrustRootToken {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        const PREFIX: &str = "nstrust_";
        let encoded = value
            .strip_prefix(PREFIX)
            .ok_or(DomainError::InvalidValue {
                kind: "owner trust root token",
                reason: "must use the exact nstrust_ prefix",
            })?;
        if encoded.len() != INVITATION_TOKEN_ENCODED_LEN
            || value.len() != PREFIX.len() + INVITATION_TOKEN_ENCODED_LEN
        {
            return Err(DomainError::InvalidValue {
                kind: "owner trust root token",
                reason: "must be an exact 48-byte base64url token without padding",
            });
        }
        let mut bytes = [0_u8; INVITATION_TOKEN_BYTES];
        let decoded = match URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes) {
            Ok(decoded) => decoded,
            Err(_) => {
                bytes.zeroize();
                return Err(DomainError::InvalidValue {
                    kind: "owner trust root token",
                    reason: "must be canonical base64url without padding",
                });
            }
        };
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        if decoded != INVITATION_TOKEN_BYTES || canonical.as_str() != encoded {
            bytes.zeroize();
            return Err(DomainError::InvalidValue {
                kind: "owner trust root token",
                reason: "must be canonical base64url without padding",
            });
        }
        let uuid = Uuid::from_bytes(bytes[..16].try_into().expect("fixed UUID byte width"));
        let trust_root_id = TrustRootId::parse(&uuid.to_string())?;
        let mut secret = [0_u8; N4_ARGON_OUTPUT_LEN];
        secret.copy_from_slice(&bytes[16..]);
        bytes.zeroize();
        Ok(Self {
            trust_root_id,
            secret,
        })
    }
}

/// Opaque, single-action proof challenge for existing-provider adoption.
/// The UUID is correlation-only; proof requires the random secret.
pub struct AdoptionChallengeToken {
    challenge_id: Uuid,
    secret: [u8; N4_ARGON_OUTPUT_LEN],
}
impl AdoptionChallengeToken {
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = [0_u8; N4_ARGON_OUTPUT_LEN];
        OsRng.fill_bytes(&mut secret);
        Self {
            challenge_id: Uuid::new_v4(),
            secret,
        }
    }

    #[must_use]
    pub fn challenge_id(&self) -> String {
        self.challenge_id.to_string()
    }

    pub fn with_encoded<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        let encoded = format!(
            "nsadopt1_{}_{}",
            self.challenge_id,
            URL_SAFE_NO_PAD.encode(self.secret)
        );
        f(&encoded)
    }

    fn with_secret<R>(&self, f: impl FnOnce(&[u8; N4_ARGON_OUTPUT_LEN]) -> R) -> R {
        f(&self.secret)
    }
}
impl FromStr for AdoptionChallengeToken {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || DomainError::InvalidValue {
            kind: "adoption challenge",
            reason: "malformed encoded secret",
        };
        let rest = value.strip_prefix("nsadopt1_").ok_or_else(invalid)?;
        let (challenge_id, encoded) = rest.split_once('_').ok_or_else(invalid)?;
        let challenge_id = challenge_id.parse::<Uuid>().map_err(|_| invalid())?;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
        let secret: [u8; N4_ARGON_OUTPUT_LEN] = decoded.try_into().map_err(|_| invalid())?;
        Ok(Self {
            challenge_id,
            secret,
        })
    }
}
impl Drop for AdoptionChallengeToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl fmt::Debug for AdoptionChallengeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdoptionChallengeToken([REDACTED])")
    }
}
impl fmt::Display for AdoptionChallengeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// A persisted verifier only. It never contains a plaintext invitation, trust-root token, or adoption challenge.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretVerifier(String);
impl<'de> Deserialize<'de> for SecretVerifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if validate_n4_verifier(&value).is_ok()
            || validate_legacy_invitation_verifier(&value).is_ok()
            || is_legacy_sha256_verifier(&value)
        {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                "secret verifier must be an approved Argon2id PHC or legacy SHA-256 digest",
            ))
        }
    }
}
impl SecretVerifier {
    /// Builds an Argon2id PHC verifier using a fresh random salt for this record.
    pub fn from_token(token: &InvitationToken) -> Result<Self, DomainError> {
        token.with_secret(|secret| Self::from_secret(secret))
    }

    /// Builds a verifier for an N5 local-owner trust-root capability.
    pub fn from_trust_root_token(token: &OwnerTrustRootToken) -> Result<Self, DomainError> {
        token.with_secret(|secret| Self::from_secret(secret))
    }

    /// Builds a verifier for one existing-provider adoption proof challenge.
    pub fn from_adoption_challenge(token: &AdoptionChallengeToken) -> Result<Self, DomainError> {
        token.with_secret(|secret| Self::from_secret(secret))
    }

    fn from_secret(secret: &[u8]) -> Result<Self, DomainError> {
        Self::from_secret_with_time_cost(secret, N4_ARGON_TIME_COST)
    }

    fn from_legacy_invitation_secret(secret: &[u8]) -> Result<Self, DomainError> {
        Self::from_secret_with_time_cost(secret, LEGACY_INVITATION_ARGON_TIME_COST)
    }

    fn from_secret_with_time_cost(secret: &[u8], time_cost: u32) -> Result<Self, DomainError> {
        let params = argon_params(time_cost)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let phc = argon
            .hash_password(secret, &salt)
            .map_err(|_| invalid_verifier())?
            .to_string();
        if time_cost == N4_ARGON_TIME_COST {
            Self::parse(phc)
        } else {
            validate_legacy_invitation_verifier(&phc)?;
            Ok(Self(phc))
        }
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
        token.with_secret(|secret| self.verify_secret(secret))
    }

    /// Verifies an N5 owner trust-root token without exposing its plaintext.
    pub fn verify_trust_root(&self, token: &OwnerTrustRootToken) -> Result<bool, DomainError> {
        token.with_secret(|secret| self.verify_secret(secret))
    }

    /// Verifies one adoption challenge without exposing its plaintext.
    pub fn verify_adoption_challenge(
        &self,
        token: &AdoptionChallengeToken,
    ) -> Result<bool, DomainError> {
        token.with_secret(|secret| self.verify_secret(secret))
    }

    fn verify_secret(&self, secret: &[u8; N4_ARGON_OUTPUT_LEN]) -> Result<bool, DomainError> {
        let parsed = validate_n4_verifier(&self.0)?;
        Ok(Argon2::default().verify_password(secret, &parsed).is_ok())
    }

    fn is_n4(&self) -> bool {
        validate_n4_verifier(&self.0).is_ok()
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

fn argon_params(time_cost: u32) -> Result<Params, DomainError> {
    Params::new(
        N4_ARGON_MEMORY_KIB,
        time_cost,
        N4_ARGON_PARALLELISM,
        Some(N4_ARGON_OUTPUT_LEN),
    )
    .map_err(|_| invalid_verifier())
}

fn validate_legacy_invitation_verifier(value: &str) -> Result<PasswordHash<'_>, DomainError> {
    let parsed = PasswordHash::new(value).map_err(|_| invalid_verifier())?;
    let correct_profile = parsed.algorithm.as_str() == "argon2id"
        && parsed.version == Some(0x13)
        && parsed.params.get_decimal("m") == Some(N4_ARGON_MEMORY_KIB)
        && parsed.params.get_decimal("t") == Some(LEGACY_INVITATION_ARGON_TIME_COST)
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

/// Legacy N0-N3 secret input. New issuance should use `InvitationToken`.
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
        SecretVerifier::from_legacy_invitation_secret(self.0.as_bytes())
            .expect("the fixed Argon2id verifier profile is valid")
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

const BINDING_NONCE_PREFIX: &str = "nsbind_";
const BINDING_NONCE_BYTES: usize = 32;
const BINDING_NONCE_ENCODED_LEN: usize = 43;
const N6_ARGON_MEMORY_KIB: u32 = 19_456;
const N6_ARGON_TIME_COST: u32 = 2;
const N6_ARGON_PARALLELISM: u32 = 1;

/// A one-time N6 proof-of-possession nonce. It is never serializable or cloneable.
pub struct BindingNonce([u8; BINDING_NONCE_BYTES]);
impl BindingNonce {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; BINDING_NONCE_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Provides canonical transport form only to an immediate caller-owned closure.
    pub fn with_encoded<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        let encoded = Zeroizing::new(format!(
            "{BINDING_NONCE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.0)
        ));
        f(encoded.as_str())
    }

    /// Provides raw nonce bytes only to the verifier or immediate authenticated transport.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; BINDING_NONCE_BYTES]) -> R) -> R {
        f(&self.0)
    }
}
impl Drop for BindingNonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for BindingNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BindingNonce([REDACTED])")
    }
}
impl fmt::Display for BindingNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl FromStr for BindingNonce {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded =
            value
                .strip_prefix(BINDING_NONCE_PREFIX)
                .ok_or(DomainError::InvalidValue {
                    kind: "binding nonce",
                    reason: "must use the exact nsbind_ prefix",
                })?;
        if encoded.len() != BINDING_NONCE_ENCODED_LEN
            || value.len() != BINDING_NONCE_PREFIX.len() + BINDING_NONCE_ENCODED_LEN
        {
            return Err(DomainError::InvalidValue {
                kind: "binding nonce",
                reason: "must be an exact 32-byte base64url nonce without padding",
            });
        }
        let mut bytes = [0_u8; BINDING_NONCE_BYTES];
        let decoded = match URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes) {
            Ok(decoded) => decoded,
            Err(_) => {
                bytes.zeroize();
                return Err(DomainError::InvalidValue {
                    kind: "binding nonce",
                    reason: "must be canonical base64url without padding",
                });
            }
        };
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        if decoded != BINDING_NONCE_BYTES || canonical.as_str() != encoded {
            bytes.zeroize();
            return Err(DomainError::InvalidValue {
                kind: "binding nonce",
                reason: "must be canonical base64url without padding",
            });
        }
        Ok(Self(bytes))
    }
}

/// Persistable N6 nonce verifier. Its PHC spelling is validated before use or deserialization.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BindingNonceVerifier(String);
impl<'de> Deserialize<'de> for BindingNonceVerifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl BindingNonceVerifier {
    pub fn from_nonce(nonce: &BindingNonce) -> Result<Self, DomainError> {
        nonce.with_secret(Self::from_secret)
    }

    fn from_secret(secret: &[u8; BINDING_NONCE_BYTES]) -> Result<Self, DomainError> {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, n6_argon_params()?);
        let salt = SaltString::generate(&mut OsRng);
        let phc = argon
            .hash_password(secret, &salt)
            .map_err(|_| invalid_n6_verifier())?
            .to_string();
        Self::parse(phc)
    }

    pub fn parse(value: String) -> Result<Self, DomainError> {
        validate_n6_verifier(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn verify(&self, nonce: &BindingNonce) -> Result<bool, DomainError> {
        let parsed = validate_n6_verifier(&self.0)?;
        Ok(nonce.with_secret(|secret| Argon2::default().verify_password(secret, &parsed).is_ok()))
    }
}
impl fmt::Debug for BindingNonceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BindingNonceVerifier([REDACTED])")
    }
}
impl fmt::Display for BindingNonceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

fn n6_argon_params() -> Result<Params, DomainError> {
    Params::new(
        N6_ARGON_MEMORY_KIB,
        N6_ARGON_TIME_COST,
        N6_ARGON_PARALLELISM,
        Some(BINDING_NONCE_BYTES),
    )
    .map_err(|_| invalid_n6_verifier())
}

fn validate_n6_verifier(value: &str) -> Result<PasswordHash<'_>, DomainError> {
    const PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";
    const SALT_BASE64_LEN: usize = 22;
    const HASH_BASE64_LEN: usize = 43;
    const VERIFIER_LEN: usize = PREFIX.len() + SALT_BASE64_LEN + 1 + HASH_BASE64_LEN;

    if value.len() != VERIFIER_LEN {
        return Err(invalid_n6_verifier());
    }
    let remainder = value.strip_prefix(PREFIX).ok_or_else(invalid_n6_verifier)?;
    let (salt, hash) = remainder.split_once('$').ok_or_else(invalid_n6_verifier)?;
    if hash.contains('$')
        || salt.len() != SALT_BASE64_LEN
        || hash.len() != HASH_BASE64_LEN
        || !salt
            .bytes()
            .chain(hash.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return Err(invalid_n6_verifier());
    }
    let decoded_salt = STANDARD_NO_PAD
        .decode(salt)
        .map_err(|_| invalid_n6_verifier())?;
    let decoded_hash = STANDARD_NO_PAD
        .decode(hash)
        .map_err(|_| invalid_n6_verifier())?;
    if decoded_salt.len() != 16
        || decoded_hash.len() != BINDING_NONCE_BYTES
        || STANDARD_NO_PAD.encode(&decoded_salt) != salt
        || STANDARD_NO_PAD.encode(&decoded_hash) != hash
    {
        return Err(invalid_n6_verifier());
    }

    let parsed = PasswordHash::new(value).map_err(|_| invalid_n6_verifier())?;
    let valid = parsed.algorithm.as_str() == "argon2id"
        && parsed.version == Some(0x13)
        && parsed.params.get_decimal("m") == Some(N6_ARGON_MEMORY_KIB)
        && parsed.params.get_decimal("t") == Some(N6_ARGON_TIME_COST)
        && parsed.params.get_decimal("p") == Some(N6_ARGON_PARALLELISM)
        && parsed
            .hash
            .is_some_and(|parsed_hash| parsed_hash.as_bytes().len() == BINDING_NONCE_BYTES);
    if valid {
        Ok(parsed)
    } else {
        Err(invalid_n6_verifier())
    }
}

fn invalid_n6_verifier() -> DomainError {
    DomainError::InvalidValue {
        kind: "binding nonce verifier",
        reason: "must be fixed Argon2id v=19 m=19456,t=2,p=1 with a 32-byte output",
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationId(String);
impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl OperationId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_safe_identifier(&value, "operation ID", 128)?;
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ReasonCode(String);
impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl ReasonCode {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_safe_identifier(&value, "reason code", 64)?;
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_safe_identifier(
    value: &str,
    kind: &'static str,
    maximum: usize,
) -> Result<(), DomainError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(DomainError::InvalidValue {
            kind,
            reason: "must use bounded safe identifier characters",
        });
    }
    Ok(())
}

// Legacy transparent serde can materialize these typed values without their public parsers.
// Keep this boundary-local: changing legacy serde would expand N0-N5 scope.
fn revalidate_n6_uuid_id<T>(
    value: &T,
    parse: impl FnOnce(&str) -> Result<T, DomainError>,
) -> Result<(), DomainError>
where
    T: fmt::Display,
{
    parse(&value.to_string()).map(|_| ())
}

fn revalidate_n6_generation(generation: Generation) -> Result<(), DomainError> {
    if generation.get() > 0 {
        Ok(())
    } else {
        Err(DomainError::InvalidValue {
            kind: "generation",
            reason: "must be positive",
        })
    }
}

fn revalidate_n6_peer_id(peer_id: &KeryxPeerId) -> Result<(), DomainError> {
    KeryxPeerId::parse(peer_id.as_str()).map(|_| ())
}

fn revalidate_n6_agent_version(agent_version: &AgentVersion) -> Result<(), DomainError> {
    AgentVersion::parse(agent_version.as_str()).map(|_| ())
}

fn revalidate_n6_operation_id(operation_id: &OperationId) -> Result<(), DomainError> {
    OperationId::parse(operation_id.as_str()).map(|_| ())
}

fn revalidate_n6_reason_code(reason_code: &ReasonCode) -> Result<(), DomainError> {
    ReasonCode::parse(reason_code.as_str()).map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct N6BindingChallengeRequest {
    network_id: NetworkId,
    device_id: DeviceId,
    provider_binding_id: ProviderBindingId,
    expected_authenticated_peer_id: KeryxPeerId,
    generation: Generation,
    expires_at: DateTime<Utc>,
    agent_version: AgentVersion,
}
impl N6BindingChallengeRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: NetworkId,
        device_id: DeviceId,
        provider_binding_id: ProviderBindingId,
        expected_authenticated_peer_id: KeryxPeerId,
        generation: Generation,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        agent_version: AgentVersion,
    ) -> Result<Self, DomainError> {
        revalidate_n6_uuid_id(&network_id, NetworkId::parse)?;
        revalidate_n6_uuid_id(&device_id, DeviceId::parse)?;
        revalidate_n6_uuid_id(&provider_binding_id, ProviderBindingId::parse)?;
        revalidate_n6_peer_id(&expected_authenticated_peer_id)?;
        revalidate_n6_generation(generation)?;
        revalidate_n6_agent_version(&agent_version)?;
        validate_expiry(expires_at, now, "binding challenge expiry")?;
        Ok(Self {
            network_id,
            device_id,
            provider_binding_id,
            expected_authenticated_peer_id,
            generation,
            expires_at,
            agent_version,
        })
    }

    /// Rechecks all authority-bearing values and expiry immediately before challenge issuance.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        revalidate_n6_uuid_id(&self.network_id, NetworkId::parse)?;
        revalidate_n6_uuid_id(&self.device_id, DeviceId::parse)?;
        revalidate_n6_uuid_id(&self.provider_binding_id, ProviderBindingId::parse)?;
        revalidate_n6_peer_id(&self.expected_authenticated_peer_id)?;
        revalidate_n6_generation(self.generation)?;
        revalidate_n6_agent_version(&self.agent_version)?;
        validate_expiry(self.expires_at, now, "binding challenge expiry")
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
    pub fn provider_binding_id(&self) -> ProviderBindingId {
        self.provider_binding_id
    }
    #[must_use]
    pub fn expected_authenticated_peer_id(&self) -> &KeryxPeerId {
        &self.expected_authenticated_peer_id
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    #[must_use]
    pub fn agent_version(&self) -> &AgentVersion {
        &self.agent_version
    }
}

/// Immediate delivery material. Ownership prevents nonce duplication or persistence serialization.
pub struct N6BindingChallengeDelivery {
    challenge_id: KeryxBindingChallengeId,
    binding_id: KeryxBindingId,
    generation: Generation,
    nonce: BindingNonce,
    expires_at: DateTime<Utc>,
}
impl N6BindingChallengeDelivery {
    pub fn new(
        challenge_id: KeryxBindingChallengeId,
        binding_id: KeryxBindingId,
        generation: Generation,
        nonce: BindingNonce,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        revalidate_n6_uuid_id(&challenge_id, KeryxBindingChallengeId::parse)?;
        revalidate_n6_uuid_id(&binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(generation)?;
        validate_expiry(expires_at, now, "binding challenge delivery expiry")?;
        Ok(Self {
            challenge_id,
            binding_id,
            generation,
            nonce,
            expires_at,
        })
    }

    /// Rechecks expiry and deserialization-bypassable authority values before delivery use.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        revalidate_n6_uuid_id(&self.challenge_id, KeryxBindingChallengeId::parse)?;
        revalidate_n6_uuid_id(&self.binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(self.generation)?;
        validate_expiry(self.expires_at, now, "binding challenge delivery expiry")
    }
    pub fn with_nonce<R>(&self, f: impl FnOnce(&BindingNonce) -> R) -> R {
        f(&self.nonce)
    }
    #[must_use]
    pub fn challenge_id(&self) -> KeryxBindingChallengeId {
        self.challenge_id
    }
    #[must_use]
    pub fn binding_id(&self) -> KeryxBindingId {
        self.binding_id
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}
impl fmt::Debug for N6BindingChallengeDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N6BindingChallengeDelivery([REDACTED])")
    }
}

/// Bind request material after transport authentication. No peer/sender claim is accepted here.
pub struct N6AuthenticatedBindRequest {
    operation_id: OperationId,
    network_id: NetworkId,
    device_id: DeviceId,
    provider_binding_id: ProviderBindingId,
    binding_nonce: BindingNonce,
    generation: Generation,
    agent_version: AgentVersion,
}
impl N6AuthenticatedBindRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        network_id: NetworkId,
        device_id: DeviceId,
        provider_binding_id: ProviderBindingId,
        binding_nonce: BindingNonce,
        generation: Generation,
        agent_version: AgentVersion,
    ) -> Result<Self, DomainError> {
        revalidate_n6_operation_id(&operation_id)?;
        revalidate_n6_uuid_id(&network_id, NetworkId::parse)?;
        revalidate_n6_uuid_id(&device_id, DeviceId::parse)?;
        revalidate_n6_uuid_id(&provider_binding_id, ProviderBindingId::parse)?;
        revalidate_n6_generation(generation)?;
        revalidate_n6_agent_version(&agent_version)?;
        Ok(Self {
            operation_id,
            network_id,
            device_id,
            provider_binding_id,
            binding_nonce,
            generation,
            agent_version,
        })
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    pub fn with_nonce<R>(&self, f: impl FnOnce(&BindingNonce) -> R) -> R {
        f(&self.binding_nonce)
    }
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
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
    pub fn provider_binding_id(&self) -> ProviderBindingId {
        self.provider_binding_id
    }
    #[must_use]
    pub fn agent_version(&self) -> &AgentVersion {
        &self.agent_version
    }
}
impl fmt::Debug for N6AuthenticatedBindRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N6AuthenticatedBindRequest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeryxBindingAuthorizationCapability {
    Rotate,
    Revoke,
}

fn validate_n6_audit_actor(actor: &AuditActor) -> Result<(), DomainError> {
    validate_n6_audit_actor_component(&actor.source, "binding authorization actor source", 64)?;
    match &actor.actor_id {
        Some(actor_id) => {
            validate_n6_audit_actor_component(actor_id, "binding authorization actor ID", 255)
        }
        None if actor.source == "nodescale" => Ok(()),
        None => Err(DomainError::InvalidValue {
            kind: "binding authorization actor ID",
            reason: "is required unless the source is nodescale",
        }),
    }
}

fn validate_n6_audit_actor_component(
    value: &str,
    kind: &'static str,
    maximum: usize,
) -> Result<(), DomainError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(DomainError::InvalidValue {
            kind,
            reason: "must be a bounded safe audit actor identifier",
        });
    }
    Ok(())
}

/// A live, constructor-issued command authorization.
///
/// This is not a persistence read model and is deliberately non-deserializable.
/// The state mutation boundary must call `validate_at(now)` immediately before use:
/// constructor-time validity alone is not durable authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeryxBindingAuthorization {
    authorization_id: KeryxBindingAuthorizationId,
    authority_id: TrustAuthorityId,
    actor: AuditActor,
    capability: KeryxBindingAuthorizationCapability,
    binding_id: KeryxBindingId,
    generation: Generation,
    revision: u64,
    expires_at: DateTime<Utc>,
}
impl KeryxBindingAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: KeryxBindingAuthorizationId,
        authority_id: TrustAuthorityId,
        actor: AuditActor,
        capability: KeryxBindingAuthorizationCapability,
        binding_id: KeryxBindingId,
        generation: Generation,
        revision: u64,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        revalidate_n6_uuid_id(&authorization_id, KeryxBindingAuthorizationId::parse)?;
        revalidate_n6_uuid_id(&authority_id, TrustAuthorityId::parse)?;
        revalidate_n6_uuid_id(&binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(generation)?;
        validate_n6_audit_actor(&actor)?;
        if revision == 0 {
            return Err(DomainError::InvalidValue {
                kind: "binding authorization revision",
                reason: "must be positive",
            });
        }
        validate_expiry(expires_at, now, "binding authorization expiry")?;
        Ok(Self {
            authorization_id,
            authority_id,
            actor,
            capability,
            binding_id,
            generation,
            revision,
            expires_at,
        })
    }

    /// Rechecks expiry when authority is consumed at a state mutation boundary.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        revalidate_n6_uuid_id(&self.authorization_id, KeryxBindingAuthorizationId::parse)?;
        revalidate_n6_uuid_id(&self.authority_id, TrustAuthorityId::parse)?;
        revalidate_n6_uuid_id(&self.binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(self.generation)?;
        validate_n6_audit_actor(&self.actor)?;
        if self.revision == 0 {
            return Err(DomainError::InvalidValue {
                kind: "binding authorization revision",
                reason: "must be positive",
            });
        }
        validate_expiry(self.expires_at, now, "binding authorization expiry")
    }

    #[must_use]
    pub fn authorization_id(&self) -> KeryxBindingAuthorizationId {
        self.authorization_id
    }
    #[must_use]
    pub fn authority_id(&self) -> TrustAuthorityId {
        self.authority_id
    }
    #[must_use]
    pub fn actor(&self) -> &AuditActor {
        &self.actor
    }
    #[must_use]
    pub fn capability(&self) -> KeryxBindingAuthorizationCapability {
        self.capability
    }
    #[must_use]
    pub fn binding_id(&self) -> KeryxBindingId {
        self.binding_id
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// A live rotation command. It is deliberately non-deserializable; call
/// `validate_at(now)` at the state mutation boundary before applying it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct N6BindingRotationIntent {
    decision_id: KeryxBindingDecisionId,
    authorization: KeryxBindingAuthorization,
    predecessor_binding_id: KeryxBindingId,
    predecessor_generation: Generation,
    predecessor_revision: u64,
    expected_next_generation: Generation,
    expires_at: DateTime<Utc>,
    reason_code: ReasonCode,
}

impl N6BindingRotationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_id: KeryxBindingDecisionId,
        authorization: KeryxBindingAuthorization,
        predecessor_binding_id: KeryxBindingId,
        predecessor_generation: Generation,
        predecessor_revision: u64,
        expected_next_generation: Generation,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        reason_code: ReasonCode,
    ) -> Result<Self, DomainError> {
        revalidate_n6_uuid_id(&decision_id, KeryxBindingDecisionId::parse)?;
        revalidate_n6_uuid_id(&predecessor_binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(predecessor_generation)?;
        revalidate_n6_generation(expected_next_generation)?;
        revalidate_n6_reason_code(&reason_code)?;
        validate_authorization(
            &authorization,
            KeryxBindingAuthorizationCapability::Rotate,
            predecessor_binding_id,
            predecessor_generation,
            predecessor_revision,
            expires_at,
            now,
        )?;
        validate_exact_rotation_generation(predecessor_generation, expected_next_generation)?;
        Ok(Self {
            decision_id,
            authorization,
            predecessor_binding_id,
            predecessor_generation,
            predecessor_revision,
            expected_next_generation,
            expires_at,
            reason_code,
        })
    }

    /// Revalidates every authority fence at the state mutation boundary.
    /// Constructor-time validity alone is not durable authority.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        revalidate_n6_uuid_id(&self.decision_id, KeryxBindingDecisionId::parse)?;
        revalidate_n6_uuid_id(&self.predecessor_binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(self.predecessor_generation)?;
        revalidate_n6_generation(self.expected_next_generation)?;
        revalidate_n6_reason_code(&self.reason_code)?;
        validate_authorization(
            &self.authorization,
            KeryxBindingAuthorizationCapability::Rotate,
            self.predecessor_binding_id,
            self.predecessor_generation,
            self.predecessor_revision,
            self.expires_at,
            now,
        )?;
        validate_exact_rotation_generation(
            self.predecessor_generation,
            self.expected_next_generation,
        )
    }

    #[must_use]
    pub fn decision_id(&self) -> KeryxBindingDecisionId {
        self.decision_id
    }
    #[must_use]
    pub fn authorization(&self) -> &KeryxBindingAuthorization {
        &self.authorization
    }
    #[must_use]
    pub fn predecessor_binding_id(&self) -> KeryxBindingId {
        self.predecessor_binding_id
    }
    #[must_use]
    pub fn predecessor_generation(&self) -> Generation {
        self.predecessor_generation
    }
    #[must_use]
    pub fn predecessor_revision(&self) -> u64 {
        self.predecessor_revision
    }
    #[must_use]
    pub fn expected_next_generation(&self) -> Generation {
        self.expected_next_generation
    }
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    #[must_use]
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }
}

/// A live revocation command. It is deliberately non-deserializable; call
/// `validate_at(now)` at the state mutation boundary before applying it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct N6BindingRevocationIntent {
    decision_id: KeryxBindingDecisionId,
    authorization: KeryxBindingAuthorization,
    binding_id: KeryxBindingId,
    generation: Generation,
    revision: u64,
    expires_at: DateTime<Utc>,
    reason_code: ReasonCode,
}
impl N6BindingRevocationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_id: KeryxBindingDecisionId,
        authorization: KeryxBindingAuthorization,
        binding_id: KeryxBindingId,
        generation: Generation,
        revision: u64,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        reason_code: ReasonCode,
    ) -> Result<Self, DomainError> {
        revalidate_n6_uuid_id(&decision_id, KeryxBindingDecisionId::parse)?;
        revalidate_n6_uuid_id(&binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(generation)?;
        revalidate_n6_reason_code(&reason_code)?;
        validate_authorization(
            &authorization,
            KeryxBindingAuthorizationCapability::Revoke,
            binding_id,
            generation,
            revision,
            expires_at,
            now,
        )?;
        Ok(Self {
            decision_id,
            authorization,
            binding_id,
            generation,
            revision,
            expires_at,
            reason_code,
        })
    }

    /// Revalidates every authority fence at the state mutation boundary.
    /// Constructor-time validity alone is not durable authority.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        revalidate_n6_uuid_id(&self.decision_id, KeryxBindingDecisionId::parse)?;
        revalidate_n6_uuid_id(&self.binding_id, KeryxBindingId::parse)?;
        revalidate_n6_generation(self.generation)?;
        revalidate_n6_reason_code(&self.reason_code)?;
        validate_authorization(
            &self.authorization,
            KeryxBindingAuthorizationCapability::Revoke,
            self.binding_id,
            self.generation,
            self.revision,
            self.expires_at,
            now,
        )
    }

    #[must_use]
    pub fn decision_id(&self) -> KeryxBindingDecisionId {
        self.decision_id
    }
    #[must_use]
    pub fn authorization(&self) -> &KeryxBindingAuthorization {
        &self.authorization
    }
    #[must_use]
    pub fn binding_id(&self) -> KeryxBindingId {
        self.binding_id
    }
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    #[must_use]
    pub fn reason(&self) -> &ReasonCode {
        &self.reason_code
    }
    #[must_use]
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }
}

fn validate_exact_rotation_generation(
    predecessor_generation: Generation,
    expected_next_generation: Generation,
) -> Result<(), DomainError> {
    if expected_next_generation == predecessor_generation.next_exact()? {
        Ok(())
    } else {
        Err(DomainError::NonMonotonicGeneration)
    }
}

fn validate_expiry(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    kind: &'static str,
) -> Result<(), DomainError> {
    if expires_at <= now {
        return Err(DomainError::InvalidValue {
            kind,
            reason: "must be in the future",
        });
    }
    Ok(())
}

fn validate_authorization(
    authorization: &KeryxBindingAuthorization,
    capability: KeryxBindingAuthorizationCapability,
    binding_id: KeryxBindingId,
    generation: Generation,
    revision: u64,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    authorization.validate_at(now)?;
    validate_expiry(expires_at, now, "binding intent expiry")?;
    if authorization.capability != capability
        || authorization.binding_id != binding_id
        || authorization.generation != generation
        || authorization.revision != revision
        || expires_at > authorization.expires_at
    {
        return Err(DomainError::InvalidValue {
            kind: "binding authorization",
            reason: "does not fence this intent",
        });
    }
    Ok(())
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTrustAuthorityAdminIntent {
    _explicit: (),
}
impl DeviceTrustAuthorityAdminIntent {
    /// Explicit owner-controlled intent is required to configure N5 trust authority.
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
