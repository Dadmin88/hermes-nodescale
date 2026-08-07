use chrono::{Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, Network, NetworkId, ProviderApiKey, ProviderCredentialId,
    ProviderInstanceId, ProviderKind,
};
use nodescale_provider::{
    IssuedJoinCredential, JoinCredentialRequest, MutationEvidence, MutationOutcome,
    MutationPolicyMode, MutationProvider, ProviderMutation, ProviderMutationCapability,
};
use nodescale_provider_headscale::{
    HeadscaleClientOptions, HeadscaleCustomRootCa, HeadscaleMutationProvider,
    HeadscaleMutationTransport, HeadscaleProvider,
};
use nodescale_state::{
    ConfirmedProviderCredentialReference, HeadscaleImportConfig, ProviderMutationConfiguration,
    StateStore, TlsVerificationPolicy,
};

const FINGERPRINT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("ignored disposable proof requires {name}"))
}

fn loopback_https_endpoint(endpoint: &str) -> Result<reqwest::Url, &'static str> {
    let endpoint = reqwest::Url::parse(endpoint).map_err(|_| "proof URL must parse")?;
    let host = endpoint.host_str().ok_or("proof URL requires a host")?;
    let is_loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if endpoint.scheme() != "https"
        || !is_loopback
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err("proof URL must be an HTTPS loopback origin without userinfo");
    }
    Ok(endpoint)
}

#[test]
fn disposable_proof_endpoint_is_strictly_loopback() {
    for accepted in [
        "https://localhost:18443",
        "https://127.0.0.1:18443",
        "https://[::1]:18443",
    ] {
        loopback_https_endpoint(accepted).unwrap();
    }
    for rejected in [
        "http://localhost:18443",
        "https://localhost:18443.example.invalid",
        "https://localhost:18443@provider.example.invalid",
        "https://provider.example.invalid:18443",
    ] {
        assert!(loopback_https_endpoint(rejected).is_err(), "{rejected}");
    }
}

/// Real-provider proof harness. Run only against a freshly created, loopback-
/// bound, disposable Headscale v0.29.3 instance. The surrounding proof runner
/// owns image provenance, before/after host invariants, and resource cleanup.
#[tokio::test]
#[ignore = "requires disposable loopback Headscale v0.29.3 with verified custom-root TLS"]
async fn disposable_headscale_tls_principal_and_credential_lifecycle() {
    let endpoint = required_env("NODESCALE_PROOF_HEADSCALE_URL");
    loopback_https_endpoint(&endpoint).unwrap();
    let api_key = required_env("NODESCALE_PROOF_HEADSCALE_API_KEY");
    let root_ca = std::fs::read(required_env("NODESCALE_PROOF_HEADSCALE_CA_FILE")).unwrap();

    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n3a-disposable-proof",
        ProviderKind::Headscale,
        instance,
        Utc::now(),
    )
    .unwrap();
    let read_provider = HeadscaleProvider::new_with_custom_root_ca(
        &endpoint,
        instance,
        ProviderApiKey::new(api_key.clone()).unwrap(),
        HeadscaleClientOptions::default(),
        HeadscaleCustomRootCa::PemBytes(root_ca.clone()),
    )
    .unwrap();
    let store = StateStore::open_in_memory().unwrap();
    store
        .import_headscale_network(
            &network,
            &HeadscaleImportConfig::new(
                &endpoint,
                instance,
                "secret://proof/runtime/headscale-api-key",
                "v0.29.3",
                TlsVerificationPolicy::Verify,
            )
            .unwrap(),
            &read_provider,
            Utc::now(),
            AuditActor::system(),
        )
        .await
        .unwrap();

    let now = Utc::now();
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            ProviderMutationConfiguration::new(
                instance,
                Generation::initial(),
                Generation::initial(),
                FINGERPRINT,
                "headscale",
                "v0.29.3",
                true,
                false,
                now - Duration::minutes(1),
                now + Duration::minutes(15),
                MutationPolicyMode::Database,
                [
                    ProviderMutationCapability::EnsureNetworkPrincipal,
                    ProviderMutationCapability::CreateJoinCredential,
                    ProviderMutationCapability::InvalidateJoinCredential,
                    ProviderMutationCapability::ManagePolicy,
                ],
            )
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();

    let mutation_provider = HeadscaleMutationProvider::new_with_custom_root_ca(
        &endpoint,
        instance,
        ProviderApiKey::new(api_key).unwrap(),
        HeadscaleClientOptions::default(),
        HeadscaleMutationTransport::new(
            network.network_id,
            Generation::initial(),
            Generation::initial(),
            FINGERPRINT,
            MutationPolicyMode::Database,
        ),
        HeadscaleCustomRootCa::PemBytes(root_ca),
    )
    .unwrap();

    let principal_outcome = mutation_provider
        .execute_mutation(
            store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::EnsureNetworkPrincipal,
                    Utc::now(),
                )
                .unwrap(),
            ProviderMutation::EnsureNetworkPrincipal {
                principal: "nodescale-n3a-proof".into(),
            },
        )
        .await;
    let principal_id = match principal_outcome {
        MutationOutcome::Confirmed {
            evidence:
                MutationEvidence::PrincipalPresent {
                    provider_user_id, ..
                },
        }
        | MutationOutcome::AlreadySatisfied {
            evidence:
                MutationEvidence::PrincipalPresent {
                    provider_user_id, ..
                },
        } => provider_user_id,
        other => panic!("principal proof did not confirm: {other:?}"),
    };

    let mut request = JoinCredentialRequest::single_use(principal_id);
    request.expires_at = Some(Utc::now() + Duration::minutes(15));
    let credential_outcome = mutation_provider
        .execute_mutation(
            store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::CreateJoinCredential,
                    Utc::now(),
                )
                .unwrap(),
            ProviderMutation::CreateJoinCredential { request },
        )
        .await;
    let IssuedJoinCredential {
        provider_reference,
        secret,
        expires_at,
        max_uses,
    } = match credential_outcome {
        MutationOutcome::Confirmed {
            evidence: MutationEvidence::JoinCredentialIssued(issued),
        } => issued,
        other => panic!("credential proof did not confirm: {other:?}"),
    };
    drop(secret);

    let credential_id = ProviderCredentialId::new();
    store
        .record_confirmed_provider_credential_reference(
            &ConfirmedProviderCredentialReference::new(
                credential_id,
                network.network_id,
                instance,
                provider_reference.clone(),
                Generation::initial(),
                Generation::initial(),
                FINGERPRINT,
                Utc::now(),
                expires_at,
                max_uses,
            )
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .confirmed_provider_credential_reference(credential_id)
            .unwrap()
            .provider_reference,
        provider_reference
    );

    let invalidate_outcome = mutation_provider
        .execute_mutation(
            store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::InvalidateJoinCredential,
                    Utc::now(),
                )
                .unwrap(),
            ProviderMutation::RevokeJoinCredential {
                credential: provider_reference,
            },
        )
        .await;
    match invalidate_outcome {
        MutationOutcome::Confirmed {
            evidence: MutationEvidence::CredentialRevoked { .. },
        }
        | MutationOutcome::AlreadySatisfied {
            evidence: MutationEvidence::CredentialRevoked { .. },
        } => {}
        other => panic!("credential invalidation did not confirm: {other:?}"),
    }

    let before_policy = mutation_provider.inspect_policy().await.unwrap();
    let replacement_policy = if before_policy.policy.trim() == r#"{"acls":[]}"# {
        r#"{"acls":[],"groups":{}}"#.to_owned()
    } else {
        r#"{"acls":[]}"#.to_owned()
    };
    let policy_outcome = mutation_provider
        .execute_mutation(
            store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::ManagePolicy,
                    Utc::now(),
                )
                .unwrap(),
            ProviderMutation::ApplyPolicy {
                expected_revision: before_policy.revision,
                policy: replacement_policy.clone(),
            },
        )
        .await;
    assert!(matches!(
        policy_outcome,
        MutationOutcome::Confirmed {
            evidence: MutationEvidence::PolicyMatches { .. }
        }
    ));
    assert_eq!(
        mutation_provider.inspect_policy().await.unwrap().policy,
        replacement_policy
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
}
