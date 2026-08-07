use chrono::{Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, InvitationToken, JoinConstraints, Network, NetworkId, ProviderApiKey,
    ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_invitation::{
    CreateInvitationRequest, InvitationService, InvitationServiceError, RedeemInvitationRequest,
};
use nodescale_provider::{
    MutationEvidence, MutationOutcome, MutationPolicyMode, MutationProvider, ProviderMutation,
    ProviderMutationCapability, ReadOnlyProvider,
};
use nodescale_provider_headscale::{
    HeadscaleClientOptions, HeadscaleCustomRootCa, HeadscaleMutationProvider,
    HeadscaleMutationTransport, HeadscaleProvider,
};
use nodescale_state::{
    HeadscaleImportConfig, N4PresentedMetadata, ProviderMutationConfiguration, StateStore,
    TlsVerificationPolicy,
};

const FINGERPRINT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("ignored disposable proof requires {name}"))
}

fn assert_secret_absent_from_state_files(path: &std::path::Path, secret: &str) {
    for candidate in [
        path.to_path_buf(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
        std::path::PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if candidate.exists() {
            let bytes = std::fs::read(candidate).unwrap();
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
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
async fn disposable_headscale_tls_invitation_service_lifecycle() {
    let endpoint = required_env("NODESCALE_PROOF_HEADSCALE_URL");
    loopback_https_endpoint(&endpoint).unwrap();
    let api_key = required_env("NODESCALE_PROOF_HEADSCALE_API_KEY");
    let root_ca = std::fs::read(required_env("NODESCALE_PROOF_HEADSCALE_CA_FILE")).unwrap();
    let state_path = std::path::PathBuf::from(required_env("NODESCALE_PROOF_STATE_DB"));

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
    let store = StateStore::open(&state_path).unwrap();
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
    assert!(read_provider.list_nodes().await.unwrap().is_empty());

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

    let invitation_service = InvitationService::new(&store, &mutation_provider, &store);
    let issued = invitation_service
        .create(
            CreateInvitationRequest {
                network_id: network.network_id,
                provider_instance_id: instance,
                provider_principal_id: principal_id,
                roles: Roles::new([Role::Worker]).unwrap(),
                admin_intent: None,
                join_constraints: JoinConstraints::default(),
                actor: AuditActor::system(),
            },
            Utc::now(),
        )
        .unwrap();
    let invitation_id = issued.view().invitation_id;
    let (_, invitation_token) = issued.deliver_token(str::to_owned);
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains(&invitation_token)
    );
    assert_secret_absent_from_state_files(&state_path, &invitation_token);
    let delivery = invitation_service
        .redeem(
            RedeemInvitationRequest {
                token: invitation_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let (receipt, ()) = delivery.deliver_once(|provider_secret| {
        assert_secret_absent_from_state_files(&state_path, provider_secret);
    });
    assert_eq!(receipt.invitation_id, invitation_id);
    assert_eq!(receipt.max_uses, 1);
    assert_eq!(
        invitation_service.show(invitation_id).unwrap().state,
        nodescale_domain::InvitationState::Consumed
    );
    let durable_reference = store
        .confirmed_provider_credential_reference(receipt.credential_id)
        .unwrap();
    let replay = invitation_service
        .redeem(
            RedeemInvitationRequest {
                token: invitation_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            Utc::now(),
        )
        .await;
    assert_eq!(replay.unwrap_err(), InvitationServiceError::Conflict);
    assert_eq!(
        store
            .confirmed_provider_credential_reference(receipt.credential_id)
            .unwrap()
            .provider_reference,
        durable_reference.provider_reference
    );
    let revoked = invitation_service
        .revoke(invitation_id, Utc::now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(revoked.state, nodescale_domain::InvitationState::Revoked);
    assert_eq!(
        revoked.cleanup_state,
        nodescale_state::N4CleanupState::Confirmed
    );
    assert_secret_absent_from_state_files(&state_path, &invitation_token);

    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);
    assert!(read_provider.list_nodes().await.unwrap().is_empty());
}
