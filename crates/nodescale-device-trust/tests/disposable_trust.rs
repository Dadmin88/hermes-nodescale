use async_trait::async_trait;
use chrono::{Duration, Utc};
use nodescale_device_trust::DeviceIdentityService;
use nodescale_domain::{
    AuditActor, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation,
    JoinConstraints, JoinSessionId, Network, NetworkId, ProviderApiKey, ProviderCredentialId,
    ProviderInstanceId, ProviderKind, Role, Roles, TrustAuthorityId,
};
use nodescale_invitation::{CreateInvitationRequest, InvitationService};
use nodescale_provider::{
    MutationEvidence, MutationOutcome, MutationPolicyMode, MutationProvider, ProviderMutation,
    ProviderMutationCapability, ReadOnlyProvider,
};
use nodescale_provider_headscale::{
    HeadscaleClientOptions, HeadscaleCustomRootCa, HeadscaleMutationProvider,
    HeadscaleMutationTransport, HeadscaleProvider,
};
use nodescale_redemption_ingress::{
    AdmissionLimits, JoinBootstrapConfig, RedemptionAttempt, RedemptionBackend, RedemptionFailure,
    RedemptionHandoff, TlsServeConfig, redemption_router, serve_tls,
    spawn_state_authorized_redemption_worker,
};
use nodescale_state::{
    HeadscaleImportConfig, MutationAuthorization, N5TrustAuthorityConfiguration, N5TrustReason,
    ProviderMutationConfiguration, StateStore, TlsVerificationPolicy,
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

const FINGERPRINT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("ignored N5 proof requires {name}"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required_env(name))
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

async fn wait_for_file(path: &Path, timeout: std::time::Duration) {
    let started = Instant::now();
    while !path.exists() {
        assert!(started.elapsed() < timeout, "proof marker timed out");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn wait_for_listener(bind: SocketAddr) {
    let started = Instant::now();
    loop {
        if tokio::net::TcpStream::connect(bind).await.is_ok() {
            return;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "ingress TLS listener did not become ready"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn assert_secret_absent_from_state_files(path: &Path, secret: &str) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if candidate.exists() {
            let bytes = fs::read(candidate).unwrap();
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

struct ObservingBackend {
    inner: Arc<nodescale_redemption_ingress::RedemptionWorkerClient>,
    observer: Mutex<
        Option<
            oneshot::Sender<(
                nodescale_domain::InvitationId,
                JoinSessionId,
                ProviderCredentialId,
            )>,
        >,
    >,
}

#[async_trait]
impl RedemptionBackend for ObservingBackend {
    async fn redeem(
        &self,
        attempt: RedemptionAttempt,
    ) -> Result<RedemptionHandoff, RedemptionFailure> {
        let delivery = self.inner.redeem(attempt).await?;
        let receipt = delivery.receipt();
        if let Some(observer) = self.observer.lock().unwrap().take() {
            let _ = observer.send((
                receipt.invitation_id,
                receipt.join_session_id,
                receipt.credential_id,
            ));
        }
        Ok(delivery)
    }
}

fn mutation_provider(
    endpoint: &str,
    instance: ProviderInstanceId,
    network: NetworkId,
    api_key: &str,
    root_ca: Vec<u8>,
) -> HeadscaleMutationProvider<MutationAuthorization> {
    HeadscaleMutationProvider::new_with_custom_root_ca(
        endpoint,
        instance,
        ProviderApiKey::new(api_key.to_owned()).unwrap(),
        HeadscaleClientOptions::default(),
        HeadscaleMutationTransport::new(
            network,
            Generation::initial(),
            Generation::initial(),
            FINGERPRINT,
            MutationPolicyMode::Database,
        ),
        HeadscaleCustomRootCa::PemBytes(root_ca),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires the retained disposable Headscale/Tailscale proof runner"]
async fn disposable_join_confirms_identity_activates_revokes_and_cleans_up() {
    let proof_root = required_path("NODESCALE_N5_PROOF_ROOT");
    let canonical_root = proof_root.canonicalize().unwrap();
    let container_proof_root = canonical_root == Path::new("/proof")
        && env::var("NODESCALE_N5_ALLOW_PUBLIC_BIND").as_deref() == Ok("proof-only");
    assert!(canonical_root.starts_with(std::env::temp_dir()) || container_proof_root);
    let state_path = required_path("NODESCALE_N5_PROOF_STATE_DB");
    assert!(state_path.starts_with(&canonical_root));
    let endpoint = required_env("NODESCALE_N5_HEADSCALE_URL");
    let login_server = required_env("NODESCALE_N5_LOGIN_SERVER");
    let bind = required_env("NODESCALE_N5_INGRESS_BIND")
        .parse::<SocketAddr>()
        .unwrap();
    assert!(
        bind.ip().is_ipv4()
            && (!bind.ip().is_unspecified()
                || env::var("NODESCALE_N5_ALLOW_PUBLIC_BIND").as_deref() == Ok("proof-only"))
    );
    let root_ca = fs::read(required_path("NODESCALE_N5_CA_FILE")).unwrap();
    let root_ca_pem = String::from_utf8(root_ca.clone()).unwrap();
    let api_key = Zeroizing::new(
        fs::read_to_string(required_path("NODESCALE_N5_HEADSCALE_API_KEY_FILE"))
            .unwrap()
            .trim()
            .to_owned(),
    );

    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "n5-disposable-device-trust-proof",
        ProviderKind::Headscale,
        instance,
        Utc::now(),
    )
    .unwrap();
    let read_provider = HeadscaleProvider::new_with_custom_root_ca(
        &endpoint,
        instance,
        ProviderApiKey::new(api_key.to_string()).unwrap(),
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
            .unwrap()
            .with_custom_root_ca_sha256(
                HeadscaleCustomRootCa::PemBytes(root_ca.clone())
                    .into_pem_bytes_and_sha256()
                    .unwrap()
                    .1,
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
                    ProviderMutationCapability::DeleteNode,
                ],
            )
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();

    let provider = mutation_provider(
        &endpoint,
        instance,
        network.network_id,
        &api_key,
        root_ca.clone(),
    );
    let principal_outcome = provider
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
                principal: "principal-42".into(),
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
        other => panic!("failed to resolve disposable Headscale principal: {other:?}"),
    };
    let (invitation_id, invitation_token) = {
        let service = InvitationService::new(&store, &provider, &store);
        let issued = service
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
        let (_, invitation_token) = issued.deliver_token(|value| Zeroizing::new(value.to_owned()));
        (invitation_id, invitation_token)
    };

    let proof_limits = AdmissionLimits::bounded(
        256,
        4,
        std::time::Duration::from_secs(1),
        16,
        std::time::Duration::from_secs(1),
        1_024,
        2,
    )
    .unwrap()
    .with_initial_tokens(1, 2)
    .unwrap();
    let worker = spawn_state_authorized_redemption_worker(store, provider, proof_limits).unwrap();
    let (observation, observed) = oneshot::channel();
    let router = redemption_router(
        Arc::new(ObservingBackend {
            inner: Arc::clone(&worker),
            observer: Mutex::new(Some(observation)),
        }),
        proof_limits,
        JoinBootstrapConfig::new(&login_server, Some(root_ca_pem)).unwrap(),
    )
    .unwrap();
    let bind_constructor =
        if env::var("NODESCALE_N5_ALLOW_PUBLIC_BIND").as_deref() == Ok("proof-only") {
            TlsServeConfig::explicitly_public_bind
        } else {
            TlsServeConfig::private_bind
        };
    let tls = bind_constructor(
        bind,
        required_path("NODESCALE_N5_INGRESS_CERT_FILE"),
        required_path("NODESCALE_N5_INGRESS_KEY_FILE"),
    )
    .unwrap();
    let server = tokio::spawn(serve_tls(tls, router));
    wait_for_listener(bind).await;

    let token_path = canonical_root.join("invitation-token");
    write_new(&token_path, invitation_token.as_bytes(), 0o600);
    write_new(&canonical_root.join("ingress-ready"), b"ready\n", 0o600);
    let (observed_invitation, observed_join_session, credential_id) =
        tokio::time::timeout(std::time::Duration::from_secs(60), observed)
            .await
            .expect("redemption observation timed out")
            .unwrap();
    assert_eq!(observed_invitation, invitation_id);
    wait_for_file(
        &canonical_root.join("client-running"),
        std::time::Duration::from_secs(60),
    )
    .await;

    let joined = {
        let started = Instant::now();
        loop {
            let nodes = read_provider.list_nodes().await.unwrap();
            if nodes.len() == 1 {
                break nodes.into_iter().next().unwrap();
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(60),
                "authoritative Headscale node did not appear"
            );
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    };
    let reference = StateStore::open(&state_path)
        .unwrap()
        .confirmed_provider_credential_reference(credential_id)
        .unwrap();
    assert_eq!(
        joined
            .pre_auth
            .as_ref()
            .map(|value| value.credential_id.as_str()),
        Some(reference.provider_reference.as_str())
    );

    let identity_store = StateStore::open(&state_path).unwrap();
    let configured_provider = identity_store
        .configured_n5_headscale_provider_with_custom_root_ca(
            network.network_id,
            ProviderApiKey::new(api_key.as_str().to_owned()).unwrap(),
            HeadscaleClientOptions::default(),
            HeadscaleCustomRootCa::PemBytes(root_ca.clone()),
        )
        .unwrap();
    let trust_service = DeviceIdentityService::new(&identity_store, &configured_provider);
    assert_eq!(identity_store.device_count(network.network_id).unwrap(), 0);
    let confirmation = trust_service
        .confirm_join_identity(observed_join_session, Utc::now(), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(
        confirmation.identity.provider_identity.node_id,
        joined.identity.node_id
    );
    assert_eq!(
        confirmation.identity.provider_reference,
        reference.provider_reference
    );
    let device_id = confirmation.identity.device_id;
    let binding_revision = confirmation.identity.binding_revision;
    let before = trust_service
        .trust_view_for_provider_registration(
            joined.identity.node_id.clone(),
            Utc::now(),
            AuditActor::system(),
        )
        .await
        .unwrap()
        .expect("provider registration must resolve to the confirmed logical device");
    assert_eq!(before.device_id, device_id);
    assert_eq!(before.trust_state.as_str(), "Untrusted");
    assert!(!before.currently_trusted);
    write_new(
        &canonical_root.join("identity-confirmed-untrusted"),
        b"confirmed-untrusted\n",
        0o600,
    );

    let authority_id = TrustAuthorityId::new();
    let trust_now = Utc::now();
    let root_token = trust_service
        .bootstrap_owner_trust_root(
            network.network_id,
            "local-owner",
            "n5-disposable-owner",
            DeviceTrustAuthorityAdminIntent::explicit(),
            trust_now,
            AuditActor::system(),
        )
        .unwrap();
    trust_service
        .configure_trust_authority(
            &root_token,
            &N5TrustAuthorityConfiguration::new(
                authority_id,
                network.network_id,
                "owner",
                "n5-disposable-owner",
                Generation::initial(),
                trust_now - Duration::minutes(1),
                trust_now + Duration::minutes(10),
                [
                    DeviceTrustCapability::ActivateDeviceTrust,
                    DeviceTrustCapability::RevokeDeviceTrust,
                ],
                trust_now,
            )
            .unwrap(),
        )
        .unwrap();
    let activation = trust_service
        .issue_trust_authorization(
            &root_token,
            authority_id,
            device_id,
            before.trust_revision,
            DeviceTrustCapability::ActivateDeviceTrust,
            trust_now,
        )
        .unwrap();
    let trusted = trust_service
        .activate_trust(activation, trust_now, N5TrustReason::OwnerApproved)
        .unwrap();
    assert!(!trusted.view.currently_trusted);
    let fresh_trusted = trust_service
        .trust_view(device_id, Utc::now(), AuditActor::system())
        .await
        .unwrap();
    assert!(fresh_trusted.currently_trusted);
    write_new(&canonical_root.join("trust-activated"), b"trusted\n", 0o600);

    let revocation_now = trust_now + Duration::milliseconds(1);
    let revocation = trust_service
        .issue_trust_authorization(
            &root_token,
            authority_id,
            device_id,
            trusted.view.trust_revision,
            DeviceTrustCapability::RevokeDeviceTrust,
            revocation_now,
        )
        .unwrap();
    let revoked = trust_service
        .revoke_trust(revocation, revocation_now, N5TrustReason::OwnerRevoked)
        .unwrap();
    assert_eq!(revoked.view.trust_state.as_str(), "Revoked");
    assert!(!revoked.view.currently_trusted);
    let fresh_revoked = trust_service
        .trust_view(device_id, Utc::now(), AuditActor::system())
        .await
        .unwrap();
    assert!(!fresh_revoked.currently_trusted);
    assert_secret_absent_from_state_files(
        &state_path,
        joined.identity_evidence.machine_key.as_str(),
    );
    write_new(&canonical_root.join("trust-revoked"), b"revoked\n", 0o600);
    write_new(&canonical_root.join("node-observed"), b"observed\n", 0o600);
    wait_for_file(
        &canonical_root.join("client-stopped"),
        std::time::Duration::from_secs(60),
    )
    .await;

    let cleanup_store = StateStore::open(&state_path).unwrap();
    let cleanup_provider = mutation_provider(
        &endpoint,
        instance,
        network.network_id,
        &api_key,
        root_ca.clone(),
    );
    let cleanup_service = InvitationService::new(&cleanup_store, &cleanup_provider, &cleanup_store);
    cleanup_service
        .revoke(invitation_id, Utc::now(), AuditActor::system())
        .await
        .unwrap();
    let delete = cleanup_provider
        .execute_mutation(
            cleanup_store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::DeleteNode,
                    Utc::now(),
                )
                .unwrap(),
            ProviderMutation::DeleteNode {
                target: joined.identity.clone(),
            },
        )
        .await;
    assert!(matches!(
        delete,
        MutationOutcome::Confirmed {
            evidence: MutationEvidence::NodeAbsent { .. }
        } | MutationOutcome::AlreadySatisfied {
            evidence: MutationEvidence::NodeAbsent { .. }
        }
    ));
    assert!(read_provider.list_nodes().await.unwrap().is_empty());
    let cleanup_configured_provider = cleanup_store
        .configured_n5_headscale_provider_with_custom_root_ca(
            network.network_id,
            ProviderApiKey::new(api_key.as_str().to_owned()).unwrap(),
            HeadscaleClientOptions::default(),
            HeadscaleCustomRootCa::PemBytes(root_ca),
        )
        .unwrap();
    let cleanup_trust = DeviceIdentityService::new(&cleanup_store, &cleanup_configured_provider);
    let final_view = cleanup_trust
        .mark_active_binding_stale(
            device_id,
            binding_revision,
            Utc::now(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(final_view.trust_state.as_str(), "Revoked");
    assert!(!final_view.currently_trusted);
    assert_eq!(cleanup_store.device_count(network.network_id).unwrap(), 1);
    assert_eq!(
        cleanup_store
            .keryx_binding_count(network.network_id)
            .unwrap(),
        0
    );
    assert_eq!(
        cleanup_store
            .fleet_projection_count(network.network_id)
            .unwrap(),
        0
    );
    assert_secret_absent_from_state_files(&state_path, &invitation_token);
    assert!(!token_path.exists());
    write_new(&canonical_root.join("cleanup-complete"), b"clean\n", 0o600);

    server.abort();
    let _ = server.await;
    worker
        .shutdown_timeout(std::time::Duration::from_secs(10))
        .unwrap();
}
