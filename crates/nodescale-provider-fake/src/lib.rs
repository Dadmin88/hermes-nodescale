//! Deterministic in-memory provider used by domain and correlation tests.

use chrono::{Duration, Utc};
use nodescale_domain::{
    ProviderCredentialId, ProviderIdentity, ProviderInstanceId, ProviderJoinCredential,
    ProviderNodeId,
};
use nodescale_provider::{
    CompatibilityStatus, JoinCredential, JoinCredentialRequest, Provider, ProviderCapability,
    ProviderError, ProviderHealth, ProviderNode, ProviderPolicy, ServerInspection,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
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
    next_node: u64,
    next_credential: u64,
    next_failure: RefCell<Option<FakeFailure>>,
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
            next_node: 1,
            next_credential: 1,
            next_failure: RefCell::new(None),
        }
    }

    pub fn fail_next(&mut self, failure: FakeFailure) {
        self.next_failure.replace(Some(failure));
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
        let identity = ProviderIdentity::new(
            self.instance_id,
            node_id,
            format!("fake-stable-key-{node_number:04}"),
        )
        .map_err(|error| ProviderError::Rejected(error.to_string()))?;
        let node = ProviderNode {
            identity: identity.clone(),
            hostname: hostname.to_owned(),
            addresses: vec![format!("198.51.100.{}", node_number.min(254))],
            tags: BTreeSet::new(),
            observed_at: fake_now(),
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

    fn injected_failure(&self) -> Result<(), ProviderError> {
        match self.next_failure.take() {
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
            reachable: true,
            authenticated: true,
            detail: "deterministic fake healthy".into(),
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
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        hash as u32,
        (hash >> 32) as u16,
        ((hash >> 16) as u16) & 0x0fff,
        (hash as u16) & 0x0fff,
        hash & 0x0000_ffff_ffff_ffff
    )
}
