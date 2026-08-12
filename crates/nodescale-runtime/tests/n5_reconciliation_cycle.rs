use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, DeviceTrustState,
    Generation, MembershipState, Network, ProviderIdentity, ProviderInstanceId, ProviderKind,
    ProviderNodeId, TrustAuthorityId,
};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence, MutableIdentityEvidence,
    ProviderCapability, ProviderError, ProviderHealth, ProviderHealthStatus,
    ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider, ServerInspection,
};
use nodescale_runtime::run_observation_and_n5_reconciliation;
use nodescale_state::{
    ExistingProviderAdoptionProof, N5TrustAuthorityConfiguration, N5TrustReason, StateStore,
    TailscaleImportConfig,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn now() -> DateTime<Utc> {
    "2026-08-10T00:00:00Z".parse().unwrap()
}

struct TailscaleFixture {
    instance: ProviderInstanceId,
    nodes: Vec<ProviderNode>,
}

#[async_trait::async_trait]
impl ReadOnlyProvider for TailscaleFixture {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "tailscale".into(),
            provider_version: "api-v2".into(),
            instance_id: self.instance,
            compatibility: CompatibilityStatus::CompatibleWithConstraints,
            capabilities: [
                ProviderCapability::InspectServer,
                ProviderCapability::ListNodes,
                ProviderCapability::GetNode,
                ProviderCapability::Health,
            ]
            .into_iter()
            .collect(),
            constraints: vec!["read-only fixture".into()],
            mutation_allowed: false,
        })
    }

    async fn verify_compatibility(&self) -> Result<CompatibilityReport, ProviderError> {
        Ok(CompatibilityReport::from_inspection(
            &self.inspect_server().await?,
        ))
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        Ok(self.nodes.clone())
    }

    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Ok(self
            .nodes
            .iter()
            .find(|node| node.identity == *identity)
            .cloned())
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        Ok(ProviderHealth {
            status: ProviderHealthStatus::Healthy,
            reachable: true,
            authenticated: true,
            detail: "fixture".into(),
        })
    }
}

fn adopted_node(instance: ProviderInstanceId) -> ProviderNode {
    let provider_node_id = "n292kg92CNTRL";
    let machine_key = "mkey:adoptable-machine";
    ProviderNode {
        identity: ProviderIdentity::new(
            instance,
            ProviderNodeId::parse(provider_node_id).unwrap(),
            format!("sha256:{:x}", Sha256::digest(provider_node_id.as_bytes())),
        )
        .unwrap(),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(ConditionalIdentityEvidence::new(machine_key).unwrap()),
            node_key: Some(MutableIdentityEvidence::new("nodekey:adoptable-current").unwrap()),
            disco_key: None,
        },
        hostname: "adopted-host".into(),
        given_name: "adopted-host.example.ts.net".into(),
        addresses: vec!["192.0.2.100".into()],
        user: None,
        pre_auth: None,
        tags: BTreeSet::new(),
        registered_at: Some(now()),
        last_seen: Some(now()),
        expires_at: None,
        observed_at: now(),
        online: Some(true),
        expired: false,
    }
}

async fn adopted_stale_fixture(
    path: &std::path::Path,
) -> (
    StateStore,
    Network,
    TailscaleFixture,
    nodescale_domain::DeviceId,
    String,
) {
    let store = StateStore::open(path).unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        nodescale_domain::NetworkId::new(),
        "runtime N5 reconciliation",
        ProviderKind::Tailscale,
        instance,
        now(),
    )
    .unwrap();
    let provider = TailscaleFixture {
        instance,
        nodes: vec![adopted_node(instance)],
    };
    let import =
        TailscaleImportConfig::new("example.com", instance, "secret://systemd/provider-token")
            .unwrap();
    store
        .import_tailscale_network(&network, &import, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    let root = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "runtime-n5-test",
            DeviceTrustAuthorityAdminIntent::explicit(),
            now(),
            AuditActor::system(),
        )
        .unwrap();
    let authority_id = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "local-owner",
                "runtime-n5-test",
                Generation::initial(),
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                [
                    DeviceTrustCapability::AdoptExistingProviderDevice,
                    DeviceTrustCapability::ActivateDeviceTrust,
                ],
                now(),
            )
            .unwrap(),
        )
        .unwrap();
    let action = store
        .issue_existing_provider_adoption(
            &root,
            authority_id,
            network.network_id,
            "n292kg92CNTRL",
            "runtime-adopt",
            now(),
        )
        .unwrap();
    let proof = ExistingProviderAdoptionProof {
        operation_id: "runtime-proof".into(),
        challenge: action
            .challenge
            .with_encoded(str::to_owned)
            .parse()
            .unwrap(),
        target_origin_provider_node_id: "n292kg92CNTRL".into(),
        whois_provider_node_id: "n292kg92CNTRL".into(),
        whois_node_key: "nodekey:adoptable-current".into(),
        local_provider_node_id: "n292kg92CNTRL".into(),
        local_node_key: "nodekey:adoptable-current".into(),
    };
    let confirmation = store
        .confirm_existing_provider_adoption(&provider, &action, &proof, now(), AuditActor::system())
        .await
        .unwrap();
    let trust = store
        .issue_device_trust_authorization(
            &root,
            authority_id,
            confirmation.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    store
        .activate_device_trust(trust, now(), N5TrustReason::OwnerApproved)
        .unwrap();
    store
        .activate_trusted_device_membership(
            &root,
            authority_id,
            confirmation.device_id,
            now() + Duration::seconds(1),
        )
        .unwrap();
    store
        .mark_n5_provider_binding_stale(
            confirmation.device_id,
            Generation::initial(),
            now() + Duration::seconds(2),
            AuditActor::system(),
        )
        .unwrap();
    (
        store,
        network,
        provider,
        confirmation.device_id,
        confirmation.provider_binding_id.to_string(),
    )
}

fn authority_counts(path: &std::path::Path) -> (u64, u64, u64, u64) {
    let db = Connection::open(path).unwrap();
    (
        db.query_row("SELECT COUNT(*) FROM n5_device_identities", [], |r| {
            r.get(0)
        })
        .unwrap(),
        db.query_row("SELECT COUNT(*) FROM n5_provider_bindings", [], |r| {
            r.get(0)
        })
        .unwrap(),
        db.query_row("SELECT COUNT(*) FROM n6_binding_records", [], |r| r.get(0))
            .unwrap(),
        db.query_row(
            "SELECT COUNT(*) FROM n7_fleet_projection_records",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    )
}

fn binding_state(path: &std::path::Path) -> (String, String, u64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT binding_id,binding_state,binding_revision FROM n5_provider_bindings",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn runtime_cycle_reactivates_the_same_exact_adopted_binding_only() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, provider, device_id, binding_id) = adopted_stale_fixture(&path).await;

    run_observation_and_n5_reconciliation(
        &store,
        network.network_id,
        &provider,
        now() + Duration::seconds(3),
    )
    .await
    .unwrap();

    let view = store.durable_device_trust(device_id).unwrap().unwrap();
    assert_eq!(binding_state(&path), (binding_id, "active".into(), 3));
    assert_eq!(view.trust_state, DeviceTrustState::Trusted);
    assert_eq!(
        store.device(device_id).unwrap().membership_state,
        MembershipState::Active
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}

#[tokio::test]
async fn runtime_cycle_does_not_reactivate_mismatched_provider_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, mut provider, device_id, binding_id) = adopted_stale_fixture(&path).await;
    provider.nodes[0].identity_evidence.node_key =
        Some(MutableIdentityEvidence::new("nodekey:mismatched").unwrap());

    run_observation_and_n5_reconciliation(
        &store,
        network.network_id,
        &provider,
        now() + Duration::seconds(3),
    )
    .await
    .unwrap();

    let view = store.durable_device_trust(device_id).unwrap().unwrap();
    assert_eq!(binding_state(&path), (binding_id, "stale".into(), 2));
    assert_eq!(view.trust_state, DeviceTrustState::Trusted);
    assert_eq!(
        store.device(device_id).unwrap().membership_state,
        MembershipState::Active
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}

#[tokio::test]
async fn runtime_cycle_does_not_reactivate_mismatched_machine_key_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, mut provider, device_id, binding_id) = adopted_stale_fixture(&path).await;
    provider.nodes[0].identity_evidence.machine_key =
        Some(ConditionalIdentityEvidence::new("mkey:mismatched").unwrap());

    run_observation_and_n5_reconciliation(
        &store,
        network.network_id,
        &provider,
        now() + Duration::seconds(3),
    )
    .await
    .unwrap();

    assert_eq!(binding_state(&path), (binding_id, "stale".into(), 2));
    assert_eq!(
        store
            .durable_device_trust(device_id)
            .unwrap()
            .unwrap()
            .trust_state,
        DeviceTrustState::Trusted
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}

#[tokio::test]
async fn runtime_cycle_does_not_reactivate_mismatched_provider_node_id() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, mut provider, device_id, binding_id) = adopted_stale_fixture(&path).await;
    provider.nodes[0].identity = ProviderIdentity::new(
        provider.instance,
        ProviderNodeId::parse("different-node").unwrap(),
        format!("sha256:{:x}", Sha256::digest(b"different-node")),
    )
    .unwrap();

    run_observation_and_n5_reconciliation(
        &store,
        network.network_id,
        &provider,
        now() + Duration::seconds(3),
    )
    .await
    .unwrap();

    assert_eq!(binding_state(&path), (binding_id, "stale".into(), 2));
    assert_eq!(
        store
            .durable_device_trust(device_id)
            .unwrap()
            .unwrap()
            .trust_state,
        DeviceTrustState::Trusted
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}

#[tokio::test]
async fn runtime_cycle_rejects_mismatched_provider_instance_and_leaves_binding_stale() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, mut provider, device_id, binding_id) = adopted_stale_fixture(&path).await;
    provider.instance = ProviderInstanceId::new();

    assert!(
        run_observation_and_n5_reconciliation(
            &store,
            network.network_id,
            &provider,
            now() + Duration::seconds(3),
        )
        .await
        .is_err()
    );

    assert_eq!(binding_state(&path), (binding_id, "stale".into(), 2));
    assert_eq!(
        store
            .durable_device_trust(device_id)
            .unwrap()
            .unwrap()
            .trust_state,
        DeviceTrustState::Trusted
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}

#[tokio::test]
async fn runtime_cycle_does_not_reactivate_expired_provider_evidence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let (store, network, mut provider, device_id, binding_id) = adopted_stale_fixture(&path).await;
    provider.nodes[0].expired = true;

    run_observation_and_n5_reconciliation(
        &store,
        network.network_id,
        &provider,
        now() + Duration::seconds(5),
    )
    .await
    .unwrap();

    let view = store.durable_device_trust(device_id).unwrap().unwrap();
    assert_eq!(binding_state(&path), (binding_id, "stale".into(), 2));
    assert_eq!(view.trust_state, DeviceTrustState::Trusted);
    assert_eq!(
        store.device(device_id).unwrap().membership_state,
        MembershipState::Active
    );
    assert_eq!(authority_counts(&path), (1, 1, 0, 0));
}
