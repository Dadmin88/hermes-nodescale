use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use nodescale_domain::{
    AgentVersion, AuditActor, BindingNonce, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability,
    DeviceTrustState, Generation, KeryxBindingState, KeryxPeerId, N6AuthenticatedBindRequest,
    N6BindingChallengeRequest, Network, OperationId, ProviderIdentity, ProviderInstanceId,
    ProviderKind, ProviderNodeId, TrustAuthorityId,
};
use nodescale_provider::{
    CompatibilityReport, CompatibilityStatus, ConditionalIdentityEvidence, MutableIdentityEvidence,
    ProviderCapability, ProviderError, ProviderHealth, ProviderHealthStatus,
    ProviderIdentityEvidence, ProviderNode, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    ExistingProviderAdoptionOutcome, ExistingProviderAdoptionProof, Failpoint,
    N5TrustAuthorityConfiguration, N5TrustReason, N6AuthenticatedBindOutcome,
    N7AuthoritativeInspection, N7ProjectionAttemptOutcome, N7ProjectionReservationOutcome,
    N7ProjectionState, N7ProjectionSubmission, StateStore, TailscaleImportConfig,
};
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
        addresses: vec!["192.0.2.100".into()],
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

fn adoptable_node(instance: ProviderInstanceId) -> ProviderNode {
    let mut node = node(instance);
    node.identity_evidence.machine_key =
        Some(ConditionalIdentityEvidence::new("mkey:adoptable-machine").unwrap());
    node.identity_evidence.node_key =
        Some(MutableIdentityEvidence::new("nodekey:adoptable-current").unwrap());
    node
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

#[tokio::test]
async fn owner_proof_adopts_once_untrusted_and_exact_retry_replays() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("nodescale.sqlite3");
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        nodescale_domain::NetworkId::new(),
        "Tailscale adoption network",
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
        nodes: vec![adoptable_node(instance)],
    };
    let store = StateStore::open(&path).unwrap();
    store
        .import_tailscale_network(&network, &config, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    let root = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-v10",
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
                "owner-v10",
                Generation::initial(),
                now() - chrono::Duration::minutes(1),
                now() + chrono::Duration::hours(1),
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
            "adopt-authorize-1",
            now(),
        )
        .unwrap();
    let challenge = action.challenge.with_encoded(str::to_owned);

    let substituted = ExistingProviderAdoptionProof {
        operation_id: "adopt-proof-bad".into(),
        challenge: challenge.parse().unwrap(),
        target_origin_provider_node_id: "n292kg92CNTRL".into(),
        whois_provider_node_id: "n292kg92CNTRL".into(),
        whois_node_key: "nodekey:substituted".into(),
        local_provider_node_id: "n292kg92CNTRL".into(),
        local_node_key: "nodekey:substituted".into(),
    };
    assert!(
        store
            .confirm_existing_provider_adoption(
                &provider,
                &action,
                &substituted,
                now(),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);

    let interrupted = ExistingProviderAdoptionProof {
        operation_id: "adopt-proof-interrupted".into(),
        challenge: challenge.parse().unwrap(),
        target_origin_provider_node_id: "n292kg92CNTRL".into(),
        whois_provider_node_id: "n292kg92CNTRL".into(),
        whois_node_key: "nodekey:adoptable-current".into(),
        local_provider_node_id: "n292kg92CNTRL".into(),
        local_node_key: "nodekey:adoptable-current".into(),
    };
    store.set_failpoint(Failpoint::BeforeAuditInsert, true);
    assert!(matches!(
        store
            .confirm_existing_provider_adoption(
                &provider,
                &action,
                &interrupted,
                now(),
                AuditActor::system(),
            )
            .await,
        Err(nodescale_state::StateError::InjectedFailure)
    ));
    store.set_failpoint(Failpoint::BeforeAuditInsert, false);
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);

    let proof = ExistingProviderAdoptionProof {
        operation_id: "adopt-proof-1".into(),
        challenge: challenge.parse().unwrap(),
        target_origin_provider_node_id: "n292kg92CNTRL".into(),
        whois_provider_node_id: "n292kg92CNTRL".into(),
        whois_node_key: "nodekey:adoptable-current".into(),
        local_provider_node_id: "n292kg92CNTRL".into(),
        local_node_key: "nodekey:adoptable-current".into(),
    };
    let confirmed = store
        .confirm_existing_provider_adoption(&provider, &action, &proof, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(
        confirmed.outcome,
        ExistingProviderAdoptionOutcome::Confirmed
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 1);
    assert_eq!(
        store
            .durable_device_trust(confirmed.device_id)
            .unwrap()
            .unwrap()
            .trust_state,
        DeviceTrustState::Untrusted
    );
    let replay = store
        .confirm_existing_provider_adoption(&provider, &action, &proof, now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(replay.outcome, ExistingProviderAdoptionOutcome::Replayed);
    assert_eq!(replay.device_id, confirmed.device_id);
    assert_eq!(replay.provider_binding_id, confirmed.provider_binding_id);
    assert_eq!(store.device_count(network.network_id).unwrap(), 1);

    let trust = store
        .issue_device_trust_authorization(
            &root,
            authority_id,
            confirmed.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            now(),
        )
        .unwrap();
    let trusted = store
        .activate_device_trust(trust, now(), N5TrustReason::OwnerApproved)
        .unwrap();
    assert_eq!(trusted.view.trust_state, DeviceTrustState::Trusted);
    let member = store
        .activate_trusted_device_membership(
            &root,
            authority_id,
            confirmed.device_id,
            now() + chrono::Duration::seconds(4),
        )
        .unwrap();
    assert_eq!(
        member.membership_state,
        nodescale_domain::MembershipState::Active
    );

    let peer = KeryxPeerId::parse("12D3KooWAdoptedPeer").unwrap();
    let agent_version = AgentVersion::parse("nodescale-agent:10.0.0").unwrap();
    let delivery = store
        .issue_n6_binding_challenge(
            OperationId::parse("v10-challenge-1").unwrap(),
            N6BindingChallengeRequest::new(
                network.network_id,
                confirmed.device_id,
                confirmed.provider_binding_id,
                peer.clone(),
                Generation::initial(),
                now() + chrono::Duration::minutes(5),
                now(),
                agent_version.clone(),
            )
            .unwrap(),
            now(),
        )
        .unwrap();
    let nonce = delivery.with_nonce(|nonce| nonce.with_encoded(str::to_owned));
    let bind = N6AuthenticatedBindRequest::new(
        OperationId::parse("v10-bind-1").unwrap(),
        network.network_id,
        confirmed.device_id,
        confirmed.provider_binding_id,
        nonce.parse::<BindingNonce>().unwrap(),
        Generation::initial(),
        agent_version,
    )
    .unwrap();
    let active = store
        .confirm_n6_authenticated_binding(peer, bind, now())
        .unwrap();
    let N6AuthenticatedBindOutcome::Confirmed(active) = active else {
        panic!("adopted provider binding did not confirm exactly once")
    };
    assert_eq!(active.state, KeryxBindingState::Active);

    let projection_operation = OperationId::parse("v10-fleet-project-1").unwrap();
    let desired = format!(
        "{{\"device_id\":\"{}\",\"state\":\"managed\"}}",
        confirmed.device_id
    )
    .into_bytes();
    let submission = N7ProjectionSubmission::from_canonical(
        projection_operation.clone(),
        network.network_id,
        confirmed.device_id,
        Generation::initial(),
        desired.clone(),
        active.binding_id.to_string(),
        active.verified_peer_id.as_ref().unwrap().to_string(),
        active.generation,
    )
    .unwrap();
    assert!(matches!(
        store.reserve_n7_projection(&submission, now()).unwrap(),
        N7ProjectionReservationOutcome::Reserved(_)
    ));
    let attempt = store
        .record_n7_projection_dispatch_attempt(
            &projection_operation,
            confirmed.device_id,
            Generation::initial(),
            1,
            now(),
        )
        .unwrap();
    let N7ProjectionAttemptOutcome::Recorded(attempt) = attempt else {
        panic!("projection dispatch attempt was not recorded")
    };
    let applied = store
        .recover_n7_projection_from_inspection(
            &projection_operation,
            confirmed.device_id,
            Generation::initial(),
            attempt.revision,
            N7AuthoritativeInspection::observed(desired).unwrap(),
            now(),
        )
        .unwrap();
    assert_eq!(applied.state, N7ProjectionState::Applied);
}

#[tokio::test]
async fn stale_pinned_observation_creates_no_device_id() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("tailscale-adoption-stale.db");
    let store = StateStore::open(&path).unwrap();
    let network = Network::new(
        nodescale_domain::NetworkId::new(),
        "tailscale adoption stale",
        ProviderKind::Tailscale,
        ProviderInstanceId::new(),
        now(),
    )
    .unwrap();
    let first = adoptable_node(network.provider_instance_id);
    let provider = TailscaleFixture {
        instance: network.provider_instance_id,
        nodes: vec![first],
    };
    let import = TailscaleImportConfig::new(
        "tailnet.example",
        network.provider_instance_id,
        "secret://systemd/tailscale-token",
    )
    .unwrap();
    store
        .import_tailscale_network(&network, &import, &provider, now(), AuditActor::system())
        .await
        .unwrap();
    let root = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "local-owner",
            "owner-v10-stale",
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
                "owner-v10-stale",
                Generation::initial(),
                now() - chrono::Duration::minutes(1),
                now() + chrono::Duration::hours(1),
                [DeviceTrustCapability::AdoptExistingProviderDevice],
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
            "adopt-stale-authorize",
            now(),
        )
        .unwrap();
    let challenge = action.challenge.with_encoded(str::to_owned);

    let mut changed = adoptable_node(network.provider_instance_id);
    changed.identity_evidence.node_key =
        Some(MutableIdentityEvidence::new("nodekey:rotated-after-issue").unwrap());
    let changed_provider = TailscaleFixture {
        instance: network.provider_instance_id,
        nodes: vec![changed],
    };
    store
        .reconcile_read_only(
            network.network_id,
            &changed_provider,
            now() + chrono::Duration::seconds(1),
            AuditActor::system(),
        )
        .await
        .unwrap();
    let proof = ExistingProviderAdoptionProof {
        operation_id: "adopt-stale-proof".into(),
        challenge: challenge.parse().unwrap(),
        target_origin_provider_node_id: "n292kg92CNTRL".into(),
        whois_provider_node_id: "n292kg92CNTRL".into(),
        whois_node_key: "nodekey:rotated-after-issue".into(),
        local_provider_node_id: "n292kg92CNTRL".into(),
        local_node_key: "nodekey:rotated-after-issue".into(),
    };
    assert!(
        store
            .confirm_existing_provider_adoption(
                &changed_provider,
                &action,
                &proof,
                now() + chrono::Duration::seconds(1),
                AuditActor::system(),
            )
            .await
            .is_err()
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
}
