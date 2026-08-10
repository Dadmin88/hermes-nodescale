//! Deterministic in-memory provider used by domain and correlation tests.

use chrono::{Duration, Utc};
use nodescale_domain::{
    Generation, NetworkId, ProviderCredentialId, ProviderCredentialReference, ProviderIdentity,
    ProviderInstanceId, ProviderJoinCredential, ProviderNodeId,
};
use nodescale_provider::{
    CompatibilityStatus, ConditionalIdentityEvidence, IssuedJoinCredential, JoinCredential,
    JoinCredentialRequest, MutableIdentityEvidence, MutationAmbiguity, MutationEvidence,
    MutationOutcome, MutationPolicyMode, MutationProvider, MutationTags, Provider,
    ProviderCapability, ProviderError, ProviderHealth, ProviderHealthStatus,
    ProviderIdentityEvidence, ProviderMutation, ProviderMutationCapability, ProviderNode,
    ProviderPolicy, ReadOnlyProvider, ServerInspection,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFailure {
    Unavailable,
    AuthenticationFailed,
    AmbiguousMutation,
    Rejected,
}

pub struct FakeProvider {
    fixture: String,
    instance_id: ProviderInstanceId,
    compatibility: CompatibilityStatus,
    nodes: BTreeMap<String, ProviderNode>,
    credentials: BTreeMap<String, bool>,
    principals: BTreeSet<String>,
    policy: ProviderPolicy,
    /// Test-only async read projection override. It is never consulted by the
    /// legacy mutable N0C `Provider` contract.
    read_only_snapshot: Option<Vec<ProviderNode>>,
    read_only_provider_name: String,
    read_only_provider_version: String,
    next_node: u64,
    next_credential: u64,
    next_failure: Mutex<Option<FakeFailure>>,
}

impl FakeProvider {
    #[must_use]
    pub fn compatible(fixture: &str) -> Self {
        Self::with_status(fixture, CompatibilityStatus::Compatible)
    }
    #[must_use]
    pub fn degraded(fixture: &str) -> Self {
        Self::with_status(fixture, CompatibilityStatus::ReadOnlyDegraded)
    }
    #[must_use]
    pub fn unsupported(fixture: &str) -> Self {
        Self::with_status(fixture, CompatibilityStatus::Unsupported)
    }
    #[must_use]
    pub fn authentication_failed(fixture: &str) -> Self {
        Self::with_status(fixture, CompatibilityStatus::AuthenticationFailed)
    }
    #[must_use]
    pub fn unreachable(fixture: &str) -> Self {
        Self::with_status(fixture, CompatibilityStatus::Unreachable)
    }

    fn with_status(fixture: &str, compatibility: CompatibilityStatus) -> Self {
        let instance_id = ProviderInstanceId::parse(&deterministic_uuid(fixture, 0))
            .expect("deterministic UUID is valid");
        Self {
            fixture: fixture.to_owned(),
            instance_id,
            compatibility,
            nodes: BTreeMap::new(),
            credentials: BTreeMap::new(),
            principals: BTreeSet::new(),
            policy: ProviderPolicy {
                revision: "fake-policy-0".into(),
                normalized_rules: BTreeMap::new(),
            },
            read_only_snapshot: None,
            read_only_provider_name: "nodescale-fake".into(),
            read_only_provider_version: "1".into(),
            next_node: 1,
            next_credential: 1,
            next_failure: Mutex::new(None),
        }
    }

    pub fn fail_next(&mut self, failure: FakeFailure) {
        *self
            .next_failure
            .get_mut()
            .expect("fake failure mutex is healthy") = Some(failure);
    }

    /// Direct deterministic test seeding for the strictly read-only async
    /// projection. It is not provider mutation authority and deliberately
    /// permits malformed/duplicate snapshots so reconcilers can fail closed.
    pub fn seed_read_only_snapshot(&mut self, nodes: Vec<ProviderNode>) {
        self.read_only_snapshot = Some(nodes);
    }

    /// Configure the async fake as a deterministic stock-Headscale fixture so
    /// import/reconciliation tests exercise the same provider-neutral path.
    #[must_use]
    pub fn headscale_fixture(fixture: &str) -> Self {
        let mut provider = Self::compatible(fixture);
        provider.read_only_provider_name = "headscale".into();
        provider.read_only_provider_version = "v0.29.3".into();
        provider
    }

    /// Return the async read projection to the legacy fixture inventory.
    pub fn clear_read_only_snapshot(&mut self) {
        self.read_only_snapshot = None;
    }

    pub fn observe_join(
        &mut self,
        credential: &JoinCredential,
        hostname: &str,
    ) -> Result<ProviderNode, ProviderError> {
        self.check_mutation("observe_join")?;
        let key = credential.credential_id.to_string();
        if !self.credentials.get(&key).copied().unwrap_or(false) {
            return Err(ProviderError::Rejected(
                "join credential is inactive".into(),
            ));
        }
        self.credentials.insert(key, false);
        let node_number = self.next_node;
        self.next_node += 1;
        let node_id = ProviderNodeId::parse(format!("fake-node-{node_number:04}"))
            .map_err(|error| ProviderError::Rejected(error.to_string()))?;
        let stable_key = format!("fake-stable-key-{node_number:04}");
        let identity = ProviderIdentity::new(self.instance_id, node_id, stable_key.clone())
            .map_err(|error| ProviderError::Rejected(error.to_string()))?;
        let node = ProviderNode {
            identity: identity.clone(),
            identity_evidence: ProviderIdentityEvidence {
                machine_key: Some(ConditionalIdentityEvidence::new(stable_key)?),
                node_key: Some(MutableIdentityEvidence::new(format!(
                    "fake-node-key-{node_number:04}"
                ))?),
                disco_key: Some(MutableIdentityEvidence::new(format!(
                    "fake-disco-key-{node_number:04}"
                ))?),
            },
            hostname: hostname.to_owned(),
            given_name: hostname.to_owned(),
            addresses: vec![format!("198.51.100.{}", node_number.min(254))],
            user: None,
            pre_auth: None,
            tags: BTreeSet::new(),
            registered_at: Some(fake_now()),
            last_seen: None,
            expires_at: None,
            observed_at: fake_now(),
            online: Some(true),
            expired: false,
        };
        self.nodes
            .insert(identity.node_id.to_string(), node.clone());
        Ok(node)
    }

    fn capabilities() -> BTreeSet<ProviderCapability> {
        [
            ProviderCapability::InspectServer,
            ProviderCapability::EnsureNetworkPrincipal,
            ProviderCapability::CreateJoinCredential,
            ProviderCapability::RevokeJoinCredential,
            ProviderCapability::ListNodes,
            ProviderCapability::GetNode,
            ProviderCapability::SetNodeTags,
            ProviderCapability::ExpireNode,
            ProviderCapability::DeleteNode,
            ProviderCapability::GetPolicy,
            ProviderCapability::ApplyPolicy,
            ProviderCapability::Health,
        ]
        .into_iter()
        .collect()
    }

    fn read_capabilities() -> BTreeSet<ProviderCapability> {
        [
            ProviderCapability::InspectServer,
            ProviderCapability::ListNodes,
            ProviderCapability::GetNode,
            ProviderCapability::Health,
        ]
        .into_iter()
        .collect()
    }

    fn injected_failure(&self) -> Result<(), ProviderError> {
        match self
            .next_failure
            .lock()
            .expect("fake failure mutex is healthy")
            .take()
        {
            None => Ok(()),
            Some(FakeFailure::Unavailable) => {
                Err(ProviderError::Unreachable("injected fake outage".into()))
            }
            Some(FakeFailure::AuthenticationFailed) => Err(ProviderError::AuthenticationFailed),
            Some(FakeFailure::AmbiguousMutation) => Err(ProviderError::AmbiguousMutation(
                "injected unknown commit outcome".into(),
            )),
            Some(FakeFailure::Rejected) => {
                Err(ProviderError::Rejected("injected rejection".into()))
            }
        }
    }

    fn check_read(&self) -> Result<(), ProviderError> {
        self.injected_failure()?;
        match self.compatibility {
            CompatibilityStatus::Unreachable => {
                Err(ProviderError::Unreachable("fake provider offline".into()))
            }
            CompatibilityStatus::AuthenticationFailed => Err(ProviderError::AuthenticationFailed),
            _ => Ok(()),
        }
    }

    fn check_mutation(&self, operation: &'static str) -> Result<(), ProviderError> {
        self.check_read()?;
        if !self.compatibility.allows_mutation() {
            return Err(ProviderError::Unsupported(operation));
        }
        Ok(())
    }

    fn matches_instance(&self, identity: &ProviderIdentity) -> Result<(), ProviderError> {
        if identity.provider_instance_id != self.instance_id {
            return Err(ProviderError::Conflict(
                "provider instance identity mismatch".into(),
            ));
        }
        Ok(())
    }
}

impl Provider for FakeProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        self.injected_failure()?;
        Ok(ServerInspection {
            provider_name: "nodescale-fake".into(),
            provider_version: "1".into(),
            instance_id: self.instance_id,
            compatibility: self.compatibility,
            capabilities: Self::capabilities(),
            constraints: match self.compatibility {
                CompatibilityStatus::ReadOnlyDegraded => vec!["mutations disabled".into()],
                CompatibilityStatus::Unsupported => vec!["version unsupported".into()],
                CompatibilityStatus::Unreachable => vec!["provider unreachable".into()],
                CompatibilityStatus::AuthenticationFailed => vec!["authentication failed".into()],
                _ => vec![],
            },
            mutation_allowed: self.compatibility.allows_mutation(),
        })
    }

    fn ensure_network_principal(&mut self, principal: &str) -> Result<(), ProviderError> {
        self.check_mutation("ensure_network_principal")?;
        if principal.is_empty() {
            return Err(ProviderError::Rejected("principal is blank".into()));
        }
        self.principals.insert(principal.to_owned());
        Ok(())
    }

    fn create_join_credential(
        &mut self,
        request: &JoinCredentialRequest,
    ) -> Result<JoinCredential, ProviderError> {
        self.check_mutation("create_join_credential")?;
        if request.max_uses != 1 || request.reusable {
            return Err(ProviderError::Rejected(
                "fake N0C credentials are one-use".into(),
            ));
        }
        let sequence = self.next_credential;
        self.next_credential += 1;
        let credential_id =
            ProviderCredentialId::parse(&deterministic_uuid(&self.fixture, sequence))
                .expect("deterministic UUID is valid");
        self.credentials.insert(credential_id.to_string(), true);
        Ok(JoinCredential {
            credential_id,
            secret: ProviderJoinCredential::new(format!("fake-secret-{sequence:08}"))
                .expect("non-empty fake secret"),
            expires_at: fake_now() + Duration::minutes(10),
            max_uses: 1,
        })
    }

    fn revoke_join_credential(
        &mut self,
        credential_id: ProviderCredentialId,
    ) -> Result<(), ProviderError> {
        self.check_mutation("revoke_join_credential")?;
        let active = self
            .credentials
            .get_mut(&credential_id.to_string())
            .ok_or_else(|| ProviderError::Rejected("unknown credential".into()))?;
        *active = false;
        Ok(())
    }

    fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        self.check_read()?;
        Ok(self.nodes.values().cloned().collect())
    }

    fn get_node(&self, identity: &ProviderIdentity) -> Result<Option<ProviderNode>, ProviderError> {
        self.check_read()?;
        self.matches_instance(identity)?;
        Ok(self
            .nodes
            .get(identity.node_id.as_str())
            .filter(|node| node.identity == *identity)
            .cloned())
    }

    fn set_node_tags(
        &mut self,
        identity: &ProviderIdentity,
        tags: &[String],
    ) -> Result<(), ProviderError> {
        self.check_mutation("set_node_tags")?;
        self.matches_instance(identity)?;
        let node = self
            .nodes
            .get_mut(identity.node_id.as_str())
            .ok_or_else(|| ProviderError::Rejected("unknown node".into()))?;
        if node.identity != *identity {
            return Err(ProviderError::Conflict(
                "stable provider identity mismatch".into(),
            ));
        }
        node.tags = tags.iter().cloned().collect();
        Ok(())
    }

    fn expire_node(&mut self, identity: &ProviderIdentity) -> Result<(), ProviderError> {
        self.check_mutation("expire_node")?;
        self.matches_instance(identity)?;
        let node = self
            .nodes
            .get_mut(identity.node_id.as_str())
            .ok_or_else(|| ProviderError::Rejected("unknown node".into()))?;
        if node.identity != *identity {
            return Err(ProviderError::Conflict(
                "stable provider identity mismatch".into(),
            ));
        }
        node.expired = true;
        Ok(())
    }

    fn delete_node(&mut self, identity: &ProviderIdentity) -> Result<(), ProviderError> {
        self.check_mutation("delete_node")?;
        self.matches_instance(identity)?;
        let existing = self
            .nodes
            .get(identity.node_id.as_str())
            .ok_or_else(|| ProviderError::Rejected("unknown node".into()))?;
        if existing.identity != *identity {
            return Err(ProviderError::Conflict(
                "stable provider identity mismatch".into(),
            ));
        }
        self.nodes.remove(identity.node_id.as_str());
        Ok(())
    }

    fn get_policy(&self) -> Result<ProviderPolicy, ProviderError> {
        self.check_read()?;
        Ok(self.policy.clone())
    }
    fn apply_policy(&mut self, policy: &ProviderPolicy) -> Result<(), ProviderError> {
        self.check_mutation("apply_policy")?;
        self.policy = policy.clone();
        Ok(())
    }
    fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        self.check_read()?;
        Ok(ProviderHealth {
            status: ProviderHealthStatus::Healthy,
            reachable: true,
            authenticated: true,
            detail: "deterministic fake healthy".into(),
        })
    }
}

#[async_trait::async_trait]
impl ReadOnlyProvider for FakeProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        Provider::instance_id(self)
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        self.injected_failure()?;
        match self.compatibility {
            CompatibilityStatus::Unreachable => {
                return Err(ProviderError::Unreachable("fake provider offline".into()));
            }
            CompatibilityStatus::AuthenticationFailed => {
                return Err(ProviderError::AuthenticationFailed);
            }
            _ => {}
        }
        Ok(ServerInspection {
            provider_name: self.read_only_provider_name.clone(),
            provider_version: self.read_only_provider_version.clone(),
            instance_id: self.instance_id,
            compatibility: self.compatibility,
            capabilities: Self::read_capabilities(),
            constraints: vec!["async fake projection is strictly read-only".into()],
            mutation_allowed: false,
        })
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        self.check_read()?;
        Ok(self
            .read_only_snapshot
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.nodes.values().cloned().collect()))
    }

    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        self.check_read()?;
        self.matches_instance(identity)?;
        let nodes = self
            .read_only_snapshot
            .as_ref()
            .map_or_else(|| self.nodes.values().cloned().collect(), Clone::clone);
        Ok(nodes.into_iter().find(|node| node.identity == *identity))
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        self.injected_failure()?;
        let (status, reachable, authenticated, detail) = match self.compatibility {
            CompatibilityStatus::Compatible | CompatibilityStatus::CompatibleWithConstraints => (
                ProviderHealthStatus::Healthy,
                true,
                true,
                "deterministic fake healthy",
            ),
            CompatibilityStatus::ReadOnlyDegraded | CompatibilityStatus::Unsupported => (
                ProviderHealthStatus::ReachableIncompatible,
                true,
                true,
                "deterministic fake reachable but incompatible",
            ),
            CompatibilityStatus::AuthenticationFailed => (
                ProviderHealthStatus::AuthenticationFailed,
                true,
                false,
                "deterministic fake authentication failed",
            ),
            CompatibilityStatus::Unreachable => (
                ProviderHealthStatus::TransportFailure,
                false,
                false,
                "deterministic fake unreachable",
            ),
        };
        Ok(ProviderHealth {
            status,
            reachable,
            authenticated,
            detail: detail.into(),
        })
    }
}

fn fake_now() -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixed fake timestamp is valid")
        .with_timezone(&Utc)
}

fn deterministic_uuid(fixture: &str, sequence: u64) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in fixture.bytes().chain(sequence.to_le_bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (hash >> 32) as u32,
        (hash >> 16) as u16,
        (hash & 0x0fff) as u16,
        ((hash >> 12) & 0x0fff) as u16,
        hash & 0x0000_ffff_ffff_ffff
    )
}

/// Deterministic failure points matching the mutation adapter's transport
/// boundary. Scripts are FIFO per capability and never contain secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeMutationScript {
    BeforeSendUnavailable,
    BeforeSendAuthenticationFailed,
    BeforeSendRejected,
    BeforeSendConflict,
    AfterApplyResponseLoss,
    AfterApplyReadBackUnavailable,
    /// The write was accepted but authoritative readback is still old.
    AfterApplyReadBackOld,
    /// The write was accepted but authoritative readback conflicts.
    AfterApplyReadBackConflict,
}

/// Sanitized deterministic mutation observation. It intentionally records no
/// request body, credential secret, or authorization material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeMutationTrace {
    pub capability: ProviderMutationCapability,
    pub dispatched: bool,
    pub read_back: bool,
}

/// Test-only mutation token for the deterministic fake. It is intentionally a
/// different public type from state-owned real authorization.
#[derive(Clone)]
pub struct FakeMutationAuthorization {
    network_id: NetworkId,
    instance_id: ProviderInstanceId,
    generation: Generation,
    capabilities: BTreeSet<ProviderMutationCapability>,
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl std::fmt::Debug for FakeMutationAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeMutationAuthorization([REDACTED])")
    }
}
impl FakeMutationAuthorization {
    #[must_use]
    pub fn new(
        network_id: NetworkId,
        instance_id: ProviderInstanceId,
        generation: Generation,
        capabilities: impl IntoIterator<Item = ProviderMutationCapability>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            network_id,
            instance_id,
            generation,
            capabilities: capabilities.into_iter().collect(),
            expires_at,
        }
    }
    fn permits(
        &self,
        network_id: NetworkId,
        instance_id: ProviderInstanceId,
        generation: Generation,
        capability: ProviderMutationCapability,
    ) -> bool {
        self.network_id == network_id
            && self.instance_id == instance_id
            && self.generation == generation
            && self.expires_at > Utc::now()
            && self.capabilities.contains(&capability)
    }
}

/// Async mutation capability for deterministic tests. It is deliberately a
/// separate wrapper, so a `FakeProvider` handed to read-only consumers cannot
/// be used as a mutation capability.
pub struct AsyncFakeMutationProvider {
    provider: Mutex<FakeProvider>,
    scripts: Mutex<BTreeMap<ProviderMutationCapability, VecDeque<FakeMutationScript>>>,
    network_id: NetworkId,
    generation: Generation,
    enabled: bool,
    policy_mode: MutationPolicyMode,
    policy_document: Mutex<String>,
    trace: Mutex<Vec<FakeMutationTrace>>,
}
impl AsyncFakeMutationProvider {
    #[must_use]
    pub fn new(provider: FakeProvider) -> Self {
        Self::configured(
            provider,
            NetworkId::new(),
            Generation::initial(),
            true,
            MutationPolicyMode::Database,
        )
    }

    #[must_use]
    pub fn configured(
        provider: FakeProvider,
        network_id: NetworkId,
        generation: Generation,
        enabled: bool,
        policy_mode: MutationPolicyMode,
    ) -> Self {
        Self {
            provider: Mutex::new(provider),
            scripts: Mutex::new(BTreeMap::new()),
            network_id,
            generation,
            enabled,
            policy_mode,
            policy_document: Mutex::new("{}".into()),
            trace: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn script(&self, capability: ProviderMutationCapability, script: FakeMutationScript) {
        self.scripts
            .lock()
            .expect("fake scripts mutex is healthy")
            .entry(capability)
            .or_default()
            .push_back(script);
    }

    fn take_script(&self, capability: ProviderMutationCapability) -> Option<FakeMutationScript> {
        self.scripts
            .lock()
            .expect("fake scripts mutex is healthy")
            .get_mut(&capability)
            .and_then(VecDeque::pop_front)
    }

    /// Ordered, sanitized observations for contract tests.
    #[must_use]
    pub fn mutation_trace(&self) -> Vec<FakeMutationTrace> {
        self.trace
            .lock()
            .expect("fake trace mutex is healthy")
            .clone()
    }

    #[must_use]
    pub fn mutation_dispatch_count(&self) -> usize {
        self.mutation_trace()
            .iter()
            .filter(|entry| entry.dispatched)
            .count()
    }

    fn trace(&self, capability: ProviderMutationCapability, dispatched: bool, read_back: bool) {
        self.trace
            .lock()
            .expect("fake trace mutex is healthy")
            .push(FakeMutationTrace {
                capability,
                dispatched,
                read_back,
            });
    }
}

#[async_trait::async_trait]
impl MutationProvider for AsyncFakeMutationProvider {
    type Authorization = FakeMutationAuthorization;

    fn instance_id(&self) -> ProviderInstanceId {
        Provider::instance_id(
            &*self
                .provider
                .lock()
                .expect("fake provider mutex is healthy"),
        )
    }

    async fn execute_mutation(
        &self,
        authorization: Self::Authorization,
        mutation: ProviderMutation,
    ) -> MutationOutcome {
        let capability = mutation.capability();
        let actual_instance_id = self.instance_id();
        if !self.enabled
            || !authorization.permits(
                self.network_id,
                actual_instance_id,
                self.generation,
                capability,
            )
        {
            return MutationOutcome::Rejected;
        }
        if matches!(mutation, ProviderMutation::ApplyPolicy { .. })
            && !matches!(self.policy_mode, MutationPolicyMode::Database)
        {
            return MutationOutcome::Unsupported;
        }
        let mut provider = self
            .provider
            .lock()
            .expect("fake provider mutex is healthy");
        let inspection = match Provider::inspect_server(&*provider) {
            Ok(inspection) => inspection,
            Err(error) => return mutation_error_outcome(error),
        };
        match inspection.compatibility {
            CompatibilityStatus::AuthenticationFailed => {
                return MutationOutcome::AuthenticationFailed;
            }
            CompatibilityStatus::Unreachable => return MutationOutcome::Unavailable,
            _ => {}
        }
        if !inspection.compatibility.allows_mutation() || !inspection.mutation_allowed {
            return MutationOutcome::CompatibilityBlocked;
        }
        let after_apply_script = match self.take_script(capability) {
            Some(FakeMutationScript::BeforeSendUnavailable) => {
                return MutationOutcome::Unavailable;
            }
            Some(FakeMutationScript::BeforeSendAuthenticationFailed) => {
                return MutationOutcome::AuthenticationFailed;
            }
            Some(FakeMutationScript::BeforeSendRejected) => return MutationOutcome::Rejected,
            Some(FakeMutationScript::BeforeSendConflict) => return MutationOutcome::Conflict,
            script @ Some(
                FakeMutationScript::AfterApplyResponseLoss
                | FakeMutationScript::AfterApplyReadBackUnavailable
                | FakeMutationScript::AfterApplyReadBackOld
                | FakeMutationScript::AfterApplyReadBackConflict,
            ) => script,
            None => None,
        };
        let response_loss = matches!(
            after_apply_script,
            Some(FakeMutationScript::AfterApplyResponseLoss)
        );
        let readback_unavailable = matches!(
            after_apply_script,
            Some(FakeMutationScript::AfterApplyReadBackUnavailable)
        );
        let readback_old = matches!(
            after_apply_script,
            Some(FakeMutationScript::AfterApplyReadBackOld)
        );
        let readback_conflict = matches!(
            after_apply_script,
            Some(FakeMutationScript::AfterApplyReadBackConflict)
        );
        if !matches!(
            &mutation,
            ProviderMutation::CreateJoinCredential { .. }
                | ProviderMutation::RevokeJoinCredential { .. }
        ) {
            self.trace(capability, true, !readback_unavailable);
        }
        match mutation {
            ProviderMutation::EnsureNetworkPrincipal { principal } => {
                let already = provider.principals.contains(&principal);
                if let Err(error) = Provider::ensure_network_principal(&mut *provider, &principal) {
                    return mutation_error_outcome(error);
                }
                if readback_unavailable {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    };
                }
                if readback_old {
                    return MutationOutcome::Failed { retryable: true };
                }
                if readback_conflict {
                    return MutationOutcome::Conflict;
                }
                // Principal membership is the authoritative local fake read-back.
                if provider.principals.contains(&principal) {
                    let evidence = MutationEvidence::PrincipalPresent {
                        provider_user_id: principal.clone(),
                        principal,
                    };
                    if already {
                        MutationOutcome::AlreadySatisfied { evidence }
                    } else {
                        MutationOutcome::Confirmed { evidence }
                    }
                } else if response_loss {
                    MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    }
                } else {
                    MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    }
                }
            }
            ProviderMutation::CreateJoinCredential { request } => {
                if request.max_uses != 1 || request.reusable {
                    return MutationOutcome::Rejected;
                }
                self.trace(capability, true, !readback_unavailable);
                let credential = match Provider::create_join_credential(&mut *provider, &request) {
                    Ok(credential) => credential,
                    Err(error) => return mutation_error_outcome(error),
                };
                if readback_unavailable {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    };
                }
                // A response loss or unconfirmable post-state cannot safely
                // deliver the only plaintext credential.
                if response_loss || readback_old || readback_conflict {
                    MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable,
                    }
                } else {
                    let issued = IssuedJoinCredential {
                        provider_reference: ProviderCredentialReference::new(
                            credential.credential_id.to_string(),
                        )
                        .expect("fake credential UUID is a safe reference"),
                        secret: credential.secret,
                        expires_at: credential.expires_at,
                        max_uses: credential.max_uses,
                    };
                    MutationOutcome::Confirmed {
                        evidence: MutationEvidence::JoinCredentialIssued(issued),
                    }
                }
            }
            ProviderMutation::RevokeJoinCredential { credential } => {
                let credential_id = match ProviderCredentialId::parse(credential.as_str()) {
                    Ok(credential_id) => credential_id,
                    Err(_) => return MutationOutcome::Rejected,
                };
                let credential_key = credential_id.to_string();
                let active = match provider.credentials.get(&credential_key).copied() {
                    Some(active) => active,
                    None => return MutationOutcome::Rejected,
                };
                if !active {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::CredentialRevoked { credential },
                    };
                }
                self.trace(capability, true, !readback_unavailable);
                let result = Provider::revoke_join_credential(&mut *provider, credential_id);
                match result {
                    Ok(()) if readback_unavailable => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                    Ok(()) if readback_old => MutationOutcome::Failed { retryable: true },
                    Ok(()) if readback_conflict => MutationOutcome::Conflict,
                    Ok(()) => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::CredentialRevoked { credential },
                    },
                    Err(error) => mutation_error_outcome(error),
                }
            }
            ProviderMutation::ReplaceNodeTags { target, tags } => {
                let tags = match MutationTags::new(tags) {
                    Ok(tags) => tags,
                    Err(_) => return MutationOutcome::Rejected,
                };
                let before = match Provider::get_node(&*provider, &target) {
                    Ok(Some(node)) => node,
                    Ok(None) => return MutationOutcome::Rejected,
                    Err(error) => return mutation_error_outcome(error),
                };
                if before.tags == *tags.as_set() {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::NodeMatches(before),
                    };
                }
                let values = tags.as_set().iter().cloned().collect::<Vec<_>>();
                if let Err(error) = Provider::set_node_tags(&mut *provider, &target, &values) {
                    return mutation_error_outcome(error);
                }
                if readback_unavailable {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    };
                }
                if readback_old {
                    return MutationOutcome::Failed { retryable: true };
                }
                if readback_conflict {
                    return MutationOutcome::Conflict;
                }
                match Provider::get_node(&*provider, &target) {
                    Ok(Some(node)) if node.tags == *tags.as_set() => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeMatches(node),
                    },
                    Ok(_) if response_loss => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                    Ok(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    },
                    Err(error) => mutation_error_outcome(error),
                }
            }
            ProviderMutation::ExpireNode { target } => {
                let before = match Provider::get_node(&*provider, &target) {
                    Ok(Some(node)) => node,
                    Ok(None) => return MutationOutcome::Rejected,
                    Err(error) => return mutation_error_outcome(error),
                };
                if before.expired {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::NodeMatches(before),
                    };
                }
                if let Err(error) = Provider::expire_node(&mut *provider, &target) {
                    return mutation_error_outcome(error);
                }
                if readback_unavailable {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    };
                }
                if readback_old {
                    return MutationOutcome::Failed { retryable: true };
                }
                if readback_conflict {
                    return MutationOutcome::Conflict;
                }
                match Provider::get_node(&*provider, &target) {
                    Ok(Some(node)) if node.expired => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeMatches(node),
                    },
                    Ok(_) if response_loss => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                    Ok(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    },
                    Err(error) => mutation_error_outcome(error),
                }
            }
            ProviderMutation::DeleteNode { target } => {
                let before = match Provider::get_node(&*provider, &target) {
                    Ok(Some(node)) => node,
                    Ok(None) => {
                        return MutationOutcome::AlreadySatisfied {
                            evidence: MutationEvidence::NodeAbsent { target },
                        };
                    }
                    Err(error) => return mutation_error_outcome(error),
                };
                if before.identity != target {
                    return MutationOutcome::Conflict;
                }
                if let Err(error) = Provider::delete_node(&mut *provider, &target) {
                    return mutation_error_outcome(error);
                }
                if readback_unavailable {
                    return MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    };
                }
                if readback_old {
                    return MutationOutcome::Failed { retryable: true };
                }
                if readback_conflict {
                    return MutationOutcome::Conflict;
                }
                match Provider::get_node(&*provider, &target) {
                    Ok(None) => MutationOutcome::Confirmed {
                        evidence: MutationEvidence::NodeAbsent { target },
                    },
                    Ok(_) if response_loss => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    },
                    Ok(_) => MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    },
                    Err(error) => mutation_error_outcome(error),
                }
            }
            ProviderMutation::ApplyPolicy {
                expected_revision,
                policy,
            } => {
                let mut document = self
                    .policy_document
                    .lock()
                    .expect("fake policy mutex is healthy");
                let before_revision = fake_policy_revision(&document);
                if before_revision != expected_revision {
                    return MutationOutcome::Conflict;
                }
                if *document == policy {
                    return MutationOutcome::AlreadySatisfied {
                        evidence: MutationEvidence::PolicyMatches {
                            revision: before_revision,
                        },
                    };
                }
                *document = policy;
                if readback_unavailable {
                    MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::ReadBackUnavailable,
                    }
                } else if readback_old || readback_conflict {
                    MutationOutcome::Ambiguous {
                        reason: MutationAmbiguity::PotentiallyApplied,
                    }
                } else {
                    MutationOutcome::Confirmed {
                        evidence: MutationEvidence::PolicyMatches {
                            revision: fake_policy_revision(&document),
                        },
                    }
                }
            }
        }
    }
}

/// Stable, dependency-free digest suitable only for fake-test policy revisions.
#[must_use]
pub fn fake_policy_revision(policy: &str) -> String {
    let hash = policy
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    format!("fake-policy-{hash:016x}")
}

fn mutation_error_outcome(error: ProviderError) -> MutationOutcome {
    match error {
        ProviderError::AuthenticationFailed => MutationOutcome::AuthenticationFailed,
        ProviderError::Timeout | ProviderError::TlsFailure | ProviderError::Unreachable(_) => {
            MutationOutcome::Unavailable
        }
        ProviderError::Unsupported(_) => MutationOutcome::Unsupported,
        ProviderError::Conflict(_) => MutationOutcome::Conflict,
        ProviderError::AmbiguousMutation(_) => MutationOutcome::Ambiguous {
            reason: MutationAmbiguity::PotentiallyApplied,
        },
        ProviderError::Rejected(_) | ProviderError::MalformedResponse(_) => {
            MutationOutcome::Rejected
        }
    }
}
