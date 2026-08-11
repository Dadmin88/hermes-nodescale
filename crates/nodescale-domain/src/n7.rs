//! N7's pure, provenance-fenced desired Hermes Fleet projection model.
//!
//! This module models only Nodescale's desired state. Fleet remains responsible
//! for local approval and final exact-operation authorization.

use crate::{
    DeviceId, DomainError, Generation, KeryxBindingId, KeryxBindingIdentity, KeryxBindingState,
    KeryxPeerId, MembershipState, NetworkId, Operation, Role, Roles,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write;
use std::str::FromStr;

/// The sole source permitted for N7-generated Fleet records.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetProjectionSource {
    Nodescale,
}
impl FleetProjectionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nodescale => "nodescale",
        }
    }
}

/// The Nodescale-controlled enrollment lifecycle exposed to Fleet.
///
/// `Approved` is deliberately absent: that remains an independent Fleet-local
/// decision and cannot be manufactured by Nodescale projection intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetEnrollmentState {
    Pending,
    Disabled,
    Removed,
}
impl FleetEnrollmentState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Disabled => "disabled",
            Self::Removed => "removed",
        }
    }
}

/// The concrete local-control operation implied by a desired enrollment state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetProjectionOperation {
    Upsert,
    Disable,
    Remove,
}
impl FleetProjectionOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Disable => "disable",
            Self::Remove => "remove",
        }
    }
}

/// N6 evidence that a projection is bound to one active authenticated peer.
///
/// There is no state flag because this type itself is the active-only boundary:
/// callers must obtain it from the N6 active-binding read path rather than
/// treating an arbitrary pending, stale, rotated, or revoked binding as proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct N6ActiveBindingProvenance {
    network_id: NetworkId,
    device_id: DeviceId,
    binding_id: KeryxBindingId,
    authenticated_peer_id: KeryxPeerId,
    binding_generation: Generation,
}
impl N6ActiveBindingProvenance {
    /// Builds active-binding evidence at the internal trusted-runtime boundary.
    ///
    /// The caller must have just validated one exact durable
    /// `n6_binding_records` row as `active`, with this verified peer, network,
    /// device, binding ID, and positive generation. This is intentionally not
    /// a request or JSON construction API: the fields remain private, this type
    /// has no `Deserialize` implementation, and untrusted callers must not use
    /// request identity values to manufacture authenticated provenance.
    ///
    /// The StateStore active-row read is the production caller for this seam.
    pub fn from_verified_active_runtime_row(
        network_id: NetworkId,
        device_id: DeviceId,
        binding_id: KeryxBindingId,
        authenticated_peer_id: KeryxPeerId,
        binding_generation: Generation,
    ) -> Result<Self, DomainError> {
        Self::new(
            network_id,
            device_id,
            binding_id,
            authenticated_peer_id,
            binding_generation,
        )
    }

    fn new(
        network_id: NetworkId,
        device_id: DeviceId,
        binding_id: KeryxBindingId,
        authenticated_peer_id: KeryxPeerId,
        binding_generation: Generation,
    ) -> Result<Self, DomainError> {
        let value = Self {
            network_id,
            device_id,
            binding_id,
            authenticated_peer_id,
            binding_generation,
        };
        value.validate()?;
        Ok(value)
    }

    /// Extracts the only acceptable N6 evidence from an authoritative active
    /// binding read model. Pending, stale, rotated, and revoked bindings fail
    /// closed before a Fleet desired projection can be created.
    fn from_active_binding(binding: &KeryxBindingIdentity) -> Result<Self, DomainError> {
        if binding.state() != KeryxBindingState::Active {
            return Err(DomainError::InvalidValue {
                kind: "N6 binding provenance",
                reason: "must reference an active N6 binding",
            });
        }
        let authenticated_peer_id =
            binding
                .verified_peer_id()
                .cloned()
                .ok_or(DomainError::InvalidValue {
                    kind: "N6 binding provenance",
                    reason: "active N6 binding must have an authenticated peer",
                })?;
        Self::new(
            binding.network_id(),
            binding.device_id(),
            binding.binding_id(),
            authenticated_peer_id,
            binding.generation(),
        )
    }

    fn validate(&self) -> Result<(), DomainError> {
        NetworkId::parse(&self.network_id.to_string())?;
        DeviceId::parse(&self.device_id.to_string())?;
        KeryxBindingId::parse(&self.binding_id.to_string())?;
        KeryxPeerId::parse(self.authenticated_peer_id.as_str())?;
        positive_generation(self.binding_generation)
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
    pub fn binding_id(&self) -> KeryxBindingId {
        self.binding_id
    }
    #[must_use]
    pub fn authenticated_peer_id(&self) -> &KeryxPeerId {
        &self.authenticated_peer_id
    }
    #[must_use]
    pub fn binding_generation(&self) -> Generation {
        self.binding_generation
    }
}
/// Canonical, source-generated Fleet grants.
///
/// Roles are descriptive metadata only. This value is always explicitly chosen
/// and can contain only the three N7-generated non-execution operations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FleetGeneratedGrants(BTreeSet<Operation>);
impl FleetGeneratedGrants {
    pub fn new(values: impl IntoIterator<Item = Operation>) -> Result<Self, DomainError> {
        let grants = Self(values.into_iter().collect());
        grants.validate()?;
        Ok(grants)
    }

    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.0.iter().all(|operation| {
            matches!(
                operation,
                Operation::FleetHealth | Operation::FleetInventory | Operation::FleetMessage
            )
        }) {
            Ok(())
        } else {
            Err(DomainError::InvalidValue {
                kind: "generated Fleet grant",
                reason: "must be fleet.health, fleet.inventory, or fleet.message",
            })
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[must_use]
    pub fn contains(&self, operation: Operation) -> bool {
        self.0.contains(&operation)
    }
    pub fn iter(&self) -> impl Iterator<Item = Operation> + '_ {
        self.0.iter().copied()
    }
}
impl Serialize for FleetGeneratedGrants {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for operation in &self.0 {
            sequence.serialize_element(operation.as_str())?;
        }
        sequence.end()
    }
}
impl<'de> Deserialize<'de> for FleetGeneratedGrants {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        let mut grants = BTreeSet::new();
        for value in values {
            let operation = Operation::from_str(&value).map_err(serde::de::Error::custom)?;
            if !grants.insert(operation) {
                return Err(serde::de::Error::custom(
                    "generated Fleet grants must not contain duplicates",
                ));
            }
        }
        Self::new(grants).map_err(serde::de::Error::custom)
    }
}

/// A SHA-256 identity over the canonical semantic content of a desired projection.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FleetProjectionContentDigest(String);
impl FleetProjectionContentDigest {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fleet-local approval is observed read-back, never Nodescale desired state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetObservedApprovalState {
    Pending,
    Approved,
    Denied,
}

/// Authoritative Fleet inspection evidence kept separate from Nodescale intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FleetObservedApproval {
    network_id: NetworkId,
    device_id: DeviceId,
    projection_generation: Generation,
    content_digest: FleetProjectionContentDigest,
    state: FleetObservedApprovalState,
}
impl FleetObservedApproval {
    pub fn from_authoritative_inspection(
        network_id: NetworkId,
        device_id: DeviceId,
        projection_generation: Generation,
        content_digest: FleetProjectionContentDigest,
        state: FleetObservedApprovalState,
    ) -> Result<Self, DomainError> {
        NetworkId::parse(&network_id.to_string())?;
        DeviceId::parse(&device_id.to_string())?;
        positive_generation(projection_generation)?;
        Ok(Self {
            network_id,
            device_id,
            projection_generation,
            content_digest,
            state,
        })
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
    pub fn projection_generation(&self) -> Generation {
        self.projection_generation
    }
    #[must_use]
    pub fn content_digest(&self) -> &FleetProjectionContentDigest {
        &self.content_digest
    }
    #[must_use]
    pub const fn state(&self) -> FleetObservedApprovalState {
        self.state
    }
}

/// Complete N7 desired state for one managed Fleet enrollment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct N7FleetDesiredProjection {
    source: FleetProjectionSource,
    network_id: NetworkId,
    device_id: DeviceId,
    display_name: String,
    managed_membership_state: MembershipState,
    membership_generation: Generation,
    projection_generation: Generation,
    binding_provenance: N6ActiveBindingProvenance,
    roles: Roles,
    enrollment_state: FleetEnrollmentState,
    generated_grants: FleetGeneratedGrants,
    content_digest: FleetProjectionContentDigest,
}
impl N7FleetDesiredProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        network_id: NetworkId,
        device_id: DeviceId,
        display_name: impl Into<String>,
        managed_membership_state: MembershipState,
        membership_generation: Generation,
        projection_generation: Generation,
        active_binding: &KeryxBindingIdentity,
        roles: Roles,
        generated_grants: FleetGeneratedGrants,
    ) -> Result<Self, DomainError> {
        Self::from_parts(
            network_id,
            device_id,
            display_name.into(),
            managed_membership_state,
            membership_generation,
            projection_generation,
            N6ActiveBindingProvenance::from_active_binding(active_binding)?,
            roles,
            FleetEnrollmentState::Pending,
            generated_grants,
        )
    }

    /// Creates desired state from authenticated N6 evidence obtained through
    /// the StateStore's exact active-binding runtime read. Request JSON cannot
    /// construct the opaque provenance value accepted here.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_from_active_n6_provenance(
        network_id: NetworkId,
        device_id: DeviceId,
        display_name: impl Into<String>,
        managed_membership_state: MembershipState,
        membership_generation: Generation,
        projection_generation: Generation,
        active_binding_provenance: N6ActiveBindingProvenance,
        roles: Roles,
        generated_grants: FleetGeneratedGrants,
    ) -> Result<Self, DomainError> {
        Self::from_parts(
            network_id,
            device_id,
            display_name.into(),
            managed_membership_state,
            membership_generation,
            projection_generation,
            active_binding_provenance,
            roles,
            FleetEnrollmentState::Pending,
            generated_grants,
        )
    }

    /// Disabling always clears generated grants before Fleet can rely on later
    /// credential or provider cleanup.
    pub fn disable(&self, next_projection_generation: Generation) -> Result<Self, DomainError> {
        self.transition(FleetEnrollmentState::Disabled, next_projection_generation)
    }

    /// Removing is terminal and likewise cannot carry generated grants.
    pub fn remove(&self, next_projection_generation: Generation) -> Result<Self, DomainError> {
        self.transition(FleetEnrollmentState::Removed, next_projection_generation)
    }

    fn transition(
        &self,
        next_state: FleetEnrollmentState,
        next_projection_generation: Generation,
    ) -> Result<Self, DomainError> {
        self.validate()?;
        if self.enrollment_state == FleetEnrollmentState::Removed {
            return Err(DomainError::InvalidTransition {
                from: self.enrollment_state.as_str(),
                to: next_state.as_str(),
            });
        }
        self.projection_generation
            .validate_advance(self.projection_generation, next_projection_generation)?;
        Self::from_parts(
            self.network_id,
            self.device_id,
            self.display_name.clone(),
            self.managed_membership_state,
            self.membership_generation,
            next_projection_generation,
            self.binding_provenance.clone(),
            self.roles.clone(),
            next_state,
            FleetGeneratedGrants::none(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        network_id: NetworkId,
        device_id: DeviceId,
        display_name: String,
        managed_membership_state: MembershipState,
        membership_generation: Generation,
        projection_generation: Generation,
        binding_provenance: N6ActiveBindingProvenance,
        roles: Roles,
        enrollment_state: FleetEnrollmentState,
        generated_grants: FleetGeneratedGrants,
    ) -> Result<Self, DomainError> {
        let mut value = Self {
            source: FleetProjectionSource::Nodescale,
            network_id,
            device_id,
            display_name,
            managed_membership_state,
            membership_generation,
            projection_generation,
            binding_provenance,
            roles,
            enrollment_state,
            generated_grants,
            content_digest: FleetProjectionContentDigest(String::new()),
        };
        value.validate_without_digest()?;
        value.content_digest = value.compute_content_digest();
        Ok(value)
    }

    fn validate_without_digest(&self) -> Result<(), DomainError> {
        NetworkId::parse(&self.network_id.to_string())?;
        DeviceId::parse(&self.device_id.to_string())?;
        validate_display_name(&self.display_name)?;
        positive_generation(self.membership_generation)?;
        positive_generation(self.projection_generation)?;
        self.binding_provenance.validate()?;
        if self.binding_provenance.network_id != self.network_id
            || self.binding_provenance.device_id != self.device_id
        {
            return Err(DomainError::InvalidValue {
                kind: "N6 binding provenance",
                reason: "must match projection network and device",
            });
        }
        let canonical_roles = Roles::new(self.roles.iter())?;
        if canonical_roles != self.roles {
            return Err(DomainError::InvalidValue {
                kind: "Fleet projection roles",
                reason: "must be canonical and non-empty",
            });
        }
        self.generated_grants.validate()?;
        if matches!(
            self.enrollment_state,
            FleetEnrollmentState::Disabled | FleetEnrollmentState::Removed
        ) && !self.generated_grants.is_empty()
        {
            return Err(DomainError::InvalidValue {
                kind: "Fleet projection grants",
                reason: "disabled and removed enrollment must have no generated grants",
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), DomainError> {
        self.validate_without_digest()?;
        if self.content_digest == self.compute_content_digest() {
            Ok(())
        } else {
            Err(DomainError::InvalidValue {
                kind: "Fleet projection content digest",
                reason: "does not match canonical projection content",
            })
        }
    }

    fn compute_content_digest(&self) -> FleetProjectionContentDigest {
        let mut hasher = Sha256::new();
        canonical_part(&mut hasher, "nodescale.n7.fleet-projection.v1");
        canonical_part(&mut hasher, self.source.as_str());
        canonical_part(&mut hasher, self.enrollment_state.as_str());
        canonical_part(&mut hasher, &self.network_id.to_string());
        canonical_part(&mut hasher, &self.device_id.to_string());
        canonical_part(&mut hasher, &self.display_name);
        canonical_part(
            &mut hasher,
            managed_membership_state_name(self.managed_membership_state),
        );
        canonical_part(&mut hasher, &self.membership_generation.get().to_string());
        canonical_part(&mut hasher, &self.projection_generation.get().to_string());
        canonical_part(&mut hasher, &self.binding_provenance.binding_id.to_string());
        canonical_part(
            &mut hasher,
            self.binding_provenance.authenticated_peer_id.as_str(),
        );
        canonical_part(
            &mut hasher,
            &self.binding_provenance.binding_generation.get().to_string(),
        );
        for role in self.roles.iter() {
            canonical_part(&mut hasher, role_name(role));
        }
        canonical_part(&mut hasher, "roles-end");
        for grant in self.generated_grants.iter() {
            canonical_part(&mut hasher, grant.as_str());
        }
        canonical_part(&mut hasher, "grants-end");

        let mut encoded = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(&mut encoded, "{byte:02x}").expect("writing into String cannot fail");
        }
        FleetProjectionContentDigest(encoded)
    }

    #[must_use]
    pub const fn source(&self) -> FleetProjectionSource {
        self.source
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
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    #[must_use]
    pub const fn managed_membership_state(&self) -> MembershipState {
        self.managed_membership_state
    }
    #[must_use]
    pub fn membership_generation(&self) -> Generation {
        self.membership_generation
    }
    #[must_use]
    pub fn projection_generation(&self) -> Generation {
        self.projection_generation
    }
    #[must_use]
    pub fn binding_provenance(&self) -> &N6ActiveBindingProvenance {
        &self.binding_provenance
    }
    #[must_use]
    pub fn roles(&self) -> &Roles {
        &self.roles
    }
    #[must_use]
    pub const fn enrollment_state(&self) -> FleetEnrollmentState {
        self.enrollment_state
    }
    #[must_use]
    pub const fn operation(&self) -> FleetProjectionOperation {
        match self.enrollment_state {
            FleetEnrollmentState::Pending => FleetProjectionOperation::Upsert,
            FleetEnrollmentState::Disabled => FleetProjectionOperation::Disable,
            FleetEnrollmentState::Removed => FleetProjectionOperation::Remove,
        }
    }
    #[must_use]
    pub fn generated_grants(&self) -> &FleetGeneratedGrants {
        &self.generated_grants
    }
    #[must_use]
    pub fn content_digest(&self) -> &FleetProjectionContentDigest {
        &self.content_digest
    }
}
impl<'de> Deserialize<'de> for FleetProjectionContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                "Fleet projection content digest must be lowercase SHA-256 hex",
            ))
        }
    }
}

fn validate_display_name(value: &str) -> Result<(), DomainError> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(DomainError::InvalidValue {
            kind: "Fleet projection display name",
            reason: "must be 1..=128 printable characters",
        });
    }
    Ok(())
}

const fn managed_membership_state_name(state: MembershipState) -> &'static str {
    match state {
        MembershipState::Pending => "pending",
        MembershipState::Joining => "joining",
        MembershipState::Active => "active",
        MembershipState::Suspended => "suspended",
        MembershipState::Revoking => "revoking",
        MembershipState::Revoked => "revoked",
    }
}

fn positive_generation(generation: Generation) -> Result<(), DomainError> {
    Generation::new(generation.get()).map(|_| ())
}

fn canonical_part(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Node => "node",
        Role::Worker => "worker",
        Role::Controller => "controller",
        Role::ProfileHost => "profile_host",
        Role::Observer => "observer",
        Role::Admin => "admin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentVersion, KeryxBindingIdentityRecord, MembershipState, ProviderBindingId};
    use chrono::Utc;

    fn active_binding(
        network_id: NetworkId,
        device_id: DeviceId,
        generation: Generation,
    ) -> KeryxBindingIdentity {
        let now = Utc::now();
        KeryxBindingIdentity::from_persisted(KeryxBindingIdentityRecord {
            binding_id: KeryxBindingId::new(),
            network_id,
            device_id,
            provider_binding_id: ProviderBindingId::new(),
            verified_peer_id: Some(KeryxPeerId::parse("keryx-peer-n7").unwrap()),
            generation,
            revision: 1,
            state: KeryxBindingState::Active,
            created_at: now,
            confirmed_at: Some(now),
            rotated_at: None,
            revoked_at: None,
            stale_at: None,
            last_verified_at: Some(now),
            rotated_from: (generation.get() > 1).then(KeryxBindingId::new),
            agent_version: AgentVersion::parse("nodescale-agent:7.0.0").unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn desired_digest_covers_bounded_display_name_and_managed_membership() {
        let network_id = NetworkId::new();
        let device_id = DeviceId::new();
        let binding = active_binding(network_id, device_id, Generation::new(3).unwrap());
        let roles = Roles::new([Role::Worker]).unwrap();

        let desired = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-seven",
            MembershipState::Active,
            Generation::new(9).unwrap(),
            Generation::new(7).unwrap(),
            &binding,
            roles.clone(),
            FleetGeneratedGrants::none(),
        )
        .unwrap();
        let renamed = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-eight",
            MembershipState::Active,
            Generation::new(9).unwrap(),
            Generation::new(7).unwrap(),
            &binding,
            roles.clone(),
            FleetGeneratedGrants::none(),
        )
        .unwrap();
        let membership_changed = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-seven",
            MembershipState::Suspended,
            Generation::new(9).unwrap(),
            Generation::new(7).unwrap(),
            &binding,
            roles,
            FleetGeneratedGrants::none(),
        )
        .unwrap();

        assert_eq!(desired.display_name(), "node-seven");
        assert_eq!(desired.managed_membership_state(), MembershipState::Active);
        assert_ne!(desired.content_digest(), renamed.content_digest());
        assert_ne!(
            desired.content_digest(),
            membership_changed.content_digest()
        );
        assert!(
            N7FleetDesiredProjection::upsert(
                network_id,
                device_id,
                "x".repeat(129),
                MembershipState::Active,
                Generation::new(9).unwrap(),
                Generation::new(7).unwrap(),
                &binding,
                Roles::new([Role::Worker]).unwrap(),
                FleetGeneratedGrants::none(),
            )
            .is_err()
        );
    }

    #[test]
    fn observed_fleet_approval_is_separate_from_nodescale_desired_state() {
        let network_id = NetworkId::new();
        let device_id = DeviceId::new();
        let binding = active_binding(network_id, device_id, Generation::initial());
        let desired = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-seven",
            MembershipState::Active,
            Generation::initial(),
            Generation::initial(),
            &binding,
            Roles::new([Role::Node]).unwrap(),
            FleetGeneratedGrants::none(),
        )
        .unwrap();

        let observed = FleetObservedApproval::from_authoritative_inspection(
            network_id,
            device_id,
            desired.projection_generation(),
            desired.content_digest().clone(),
            FleetObservedApprovalState::Approved,
        )
        .unwrap();

        assert_eq!(desired.enrollment_state(), FleetEnrollmentState::Pending);
        assert_eq!(observed.state(), FleetObservedApprovalState::Approved);
    }

    #[test]
    fn roles_are_metadata_only_and_disable_remove_clear_grants_terminally() {
        let network_id = NetworkId::new();
        let device_id = DeviceId::new();
        let binding_generation = Generation::new(4).unwrap();
        let binding = active_binding(network_id, device_id, binding_generation);
        let roles = Roles::new([Role::Admin, Role::Node]).unwrap();
        let desired = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-seven",
            MembershipState::Active,
            Generation::new(2).unwrap(),
            Generation::initial(),
            &binding,
            roles.clone(),
            FleetGeneratedGrants::new([
                Operation::FleetHealth,
                Operation::FleetInventory,
                Operation::FleetMessage,
            ])
            .unwrap(),
        )
        .unwrap();
        let metadata_only = N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-seven",
            MembershipState::Active,
            Generation::new(2).unwrap(),
            Generation::initial(),
            &binding,
            roles,
            FleetGeneratedGrants::none(),
        )
        .unwrap();

        assert_eq!(desired.membership_generation().get(), 2);
        assert_eq!(
            desired.binding_provenance().binding_generation(),
            binding_generation
        );
        assert_eq!(desired.projection_generation().get(), 1);
        assert!(
            !desired
                .generated_grants()
                .contains(Operation::FleetHermesRun)
        );
        assert!(metadata_only.generated_grants().is_empty());

        let disabled = desired.disable(Generation::new(2).unwrap()).unwrap();
        assert_eq!(disabled.enrollment_state(), FleetEnrollmentState::Disabled);
        assert!(disabled.generated_grants().is_empty());
        let removed = disabled.remove(Generation::new(3).unwrap()).unwrap();
        assert_eq!(removed.enrollment_state(), FleetEnrollmentState::Removed);
        assert!(removed.generated_grants().is_empty());
        assert!(removed.remove(Generation::new(4).unwrap()).is_err());
    }
}
