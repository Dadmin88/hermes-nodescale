use chrono::{TimeZone, Utc};
use nodescale_domain::{ProviderIdentity, ProviderInstanceId, ProviderNodeId};
use nodescale_provider::*;
use std::collections::BTreeSet;

fn instance() -> ProviderInstanceId {
    ProviderInstanceId::parse("123e4567-e89b-42d3-a456-426614174000").unwrap()
}

#[test]
fn compatible_read_only_adapter_never_reports_mutation_permission() {
    let inspection = ServerInspection {
        provider_name: "headscale".into(),
        provider_version: "0.29.3".into(),
        instance_id: instance(),
        compatibility: CompatibilityStatus::Compatible,
        capabilities: [
            ProviderCapability::InspectServer,
            ProviderCapability::ListNodes,
            ProviderCapability::GetNode,
            ProviderCapability::Health,
        ]
        .into_iter()
        .collect(),
        constraints: vec!["read-only adapter".into()],
        mutation_allowed: false,
    };
    let report = CompatibilityReport::from_inspection(&inspection);
    assert_eq!(report.status, CompatibilityStatus::Compatible);
    assert!(!report.mutation_allowed);
}

#[test]
fn provider_node_keeps_identity_classes_separate() {
    let identity = ProviderIdentity::new(
        instance(),
        ProviderNodeId::parse("42").unwrap(),
        "sha256:machine-key-fingerprint",
    )
    .unwrap();
    let node = ProviderNode {
        identity,
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(ConditionalIdentityEvidence::new("mkey:synthetic").unwrap()),
            node_key: Some(MutableIdentityEvidence::new("nodekey:synthetic").unwrap()),
            disco_key: Some(MutableIdentityEvidence::new("discokey:synthetic").unwrap()),
        },
        hostname: "worker-1".into(),
        given_name: "worker-1".into(),
        addresses: vec!["192.0.2.10".into()],
        user: Some(ProviderUserObservation {
            id: "7".into(),
            name: "user-1".into(),
            display_name: "User One".into(),
        }),
        pre_auth: Some(PreAuthCorrelationObservation {
            credential_id: "9".into(),
            association: PreAuthAssociationStrength::Partial,
        }),
        tags: BTreeSet::new(),
        registered_at: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        last_seen: None,
        expires_at: None,
        observed_at: Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
        online: Some(false),
        expired: false,
    };

    assert_eq!(
        node.identity_evidence.machine_key.as_ref().unwrap().class(),
        IdentityEvidenceClass::StableConditional
    );
    assert_eq!(
        node.identity_evidence.node_key.unwrap().class(),
        IdentityEvidenceClass::Mutable
    );
    assert_ne!(node.identity.node_id.as_str(), node.hostname);
    assert!(!node.addresses.contains(&node.identity.node_id.to_string()));
    assert_eq!(
        node.pre_auth.unwrap().association,
        PreAuthAssociationStrength::Partial
    );
}
