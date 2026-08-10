use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use nodescale_domain::{
    AuditActor, Network, ProviderIdentity, ProviderInstanceId, ProviderKind, ProviderNodeId,
};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ProviderCapability, ProviderError, ProviderHealth,
    ProviderHealthStatus, ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider,
    ServerInspection,
};
use nodescale_state::{StateStore, TailscaleImportConfig};
use tempfile::tempdir;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap()
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

fn node(instance: ProviderInstanceId) -> ProviderNode {
    ProviderNode {
        identity: ProviderIdentity::new(
            instance,
            ProviderNodeId::parse("n292kg92CNTRL").unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: None,
            node_key: None,
            disco_key: None,
        },
        hostname: "workstation".into(),
        given_name: "workstation.example.ts.net".into(),
        addresses: vec!["100.64.0.10".into()],
        user: None,
        pre_auth: None,
        tags: BTreeSet::from(["tag:worker".into()]),
        registered_at: Some(now()),
        last_seen: Some(now()),
        expires_at: None,
        observed_at: now(),
        online: None,
        expired: false,
    }
}

#[tokio::test]
async fn tailscale_import_and_reconciliation_are_restart_safe_and_secret_reference_only() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("nodescale.sqlite3");
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        nodescale_domain::NetworkId::new(),
        "Tailscale network",
        ProviderKind::Tailscale,
        instance,
        now(),
    )
    .unwrap();
    let config = TailscaleImportConfig::new(
        "example.com",
        instance,
        "secret://proton-pass/nodescale/tailscale#api-token",
    )
    .unwrap();
    let provider = TailscaleFixture {
        instance,
        nodes: vec![node(instance)],
    };

    let store = StateStore::open(&path).unwrap();
    store
        .import_tailscale_network(&network, &config, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    drop(store);

    let reopened = StateStore::open(&path).unwrap();
    let observations = reopened.provider_observations(network.network_id).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].node.identity_evidence.machine_key, None);
    assert_eq!(observations[0].node.online, None);
    assert_eq!(reopened.device_count(network.network_id).unwrap(), 0);
    let report = reopened
        .reconcile_read_only(network.network_id, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(report.observed_count, 1);
    assert_eq!(report.discovered_unmanaged_count, 1);
    assert!(
        !reopened
            .database_text_dump_for_test()
            .unwrap()
            .contains("tskey-")
    );
}
