//! Disposable authenticated N6 edge-stream integration selector.
//!
//! This intentionally ignored proof exercises the public Keryx stream seam,
//! rather than adapter-local handlers or test-only provenance constructors.

use async_trait::async_trait;
use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, Utc};
use keryx_proto::v1::{
    HealthRequest, NodescaleIdentityBindDisposition, NodescaleIdentityBindV1,
    NodescaleIdentityChallengeDisposition, NodescaleIdentityChallengeV1,
    PublishNodescaleIdentityBindRequest, PublishNodescaleIdentityChallengeRequest,
    keryx_relay_client::KeryxRelayClient, keryx_relay_server::KeryxRelayServer,
};
use keryx_relay::{
    RelayRuntime, SkillRegistry,
    health_server::{NODE_ID_METADATA_KEY, NODE_TOKEN_METADATA_KEY, RelayHealthService},
    run_relay_stream_with_direct_control_handlers,
    security::NodeTokenAuth,
};
use nodescale_binding::{N6BindingService, N6Clock};
use nodescale_domain::{
    AuditActor, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation, Invitation,
    InvitationId, InvitationToken, JoinConstraints, KeryxPeerId, Network, NetworkId,
    ProviderApiKey, ProviderCredentialId, ProviderCredentialReference, ProviderIdentity,
    ProviderInstanceId, ProviderKind, ProviderNodeId, Role, Roles, TrustAuthorityId,
};
use nodescale_keryx_adapter::TryNodescaleKeryxAdapter;
use nodescale_provider::{
    CompatibilityStatus, ConditionalIdentityEvidence, MutationPolicyMode,
    PreAuthAssociationStrength, PreAuthCorrelationObservation, ProviderError, ProviderHealth,
    ProviderIdentityEvidence, ProviderMutationCapability, ProviderNode, ReadOnlyProvider,
    ServerInspection,
};
use nodescale_provider_headscale::HeadscaleCustomRootCa;
use nodescale_state::{
    HeadscaleImportConfig, N4CredentialConfirmation, N4InvitationContext, N4PresentedMetadata,
    N5TrustAuthorityConfiguration, N5TrustReason, ProviderMutationConfiguration, SanitizedMetadata,
    StateStore, TlsVerificationPolicy,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Request,
    transport::{Channel, Endpoint, Server},
};

const SOURCE_NODE: &str = "n6-source-node";
const WRONG_NODE: &str = "n6-wrong-node";
const DESTINATION_NODE: &str = "n6-binding-node";
const SOURCE_TOKEN: &str = "n6-source-token";
const WRONG_TOKEN: &str = "n6-wrong-token";
const DESTINATION_TOKEN: &str = "n6-binding-token";
const PROVIDER_TOKEN: &str = "n6-provider-token";
const NODE_FIXTURE: &str =
    include_str!("../../nodescale-provider-headscale/fixtures/v0.29.3-node.json");
const NODES_FIXTURE: &str = r#"{"nodes":[{"id":"42","machineKey":"mkey:synthetic-machine-key","nodeKey":"nodekey:synthetic-node-key","discoKey":"discokey:synthetic-disco-key","ipAddresses":["192.0.2.10"],"name":"worker-1","givenName":"worker-1","user":{"id":"7","name":"user-1","displayName":"User One"},"preAuthKey":{"id":"9","used":true},"createdAt":"2026-07-29T12:00:00Z","online":true,"tags":["tag:worker"]}]}"#;

struct DisposableDb {
    path: PathBuf,
}

impl DisposableDb {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::var_os("NODESCALE_N6_PROOF_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self {
            path: root.join(format!(
                "nodescale-disposable-n6-{}-{unique}.sqlite",
                std::process::id()
            )),
        }
    }
}

impl Drop for DisposableDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(self.path.with_extension("sqlite-shm"));
    }
}

#[derive(Clone)]
struct FixedN6Clock(chrono::DateTime<Utc>);

impl N6Clock for FixedN6Clock {
    fn now(&self) -> chrono::DateTime<Utc> {
        self.0
    }
}

#[derive(Clone)]
struct SeedProvider {
    instance: ProviderInstanceId,
    node: ProviderNode,
}

#[async_trait]
impl ReadOnlyProvider for SeedProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.instance,
            compatibility: CompatibilityStatus::Compatible,
            capabilities: BTreeSet::new(),
            constraints: Vec::new(),
            mutation_allowed: false,
        })
    }

    async fn list_nodes(&self) -> Result<Vec<ProviderNode>, ProviderError> {
        Ok(vec![self.node.clone()])
    }

    async fn get_node(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<Option<ProviderNode>, ProviderError> {
        Ok((&self.node.identity == identity).then(|| self.node.clone()))
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        unreachable!("the N6 selector only seeds N4/N5 prerequisite state")
    }
}

struct HeadscaleStub {
    endpoint: String,
    addr: SocketAddr,
    root_pem: Vec<u8>,
    task: JoinHandle<()>,
}

impl Drop for HeadscaleStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn headscale_node(headers: HeaderMap) -> Response {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some("Bearer n6-provider-token");
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, NODE_FIXTURE).into_response()
}

async fn headscale_nodes(headers: HeaderMap) -> Response {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some("Bearer n6-provider-token");
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, NODES_FIXTURE).into_response()
}

async fn start_headscale_stub() -> HeadscaleStub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Headscale proof stub");
    let addr = listener.local_addr().expect("Headscale stub address");

    let mut ca_params =
        CertificateParams::new(Vec::new()).expect("valid local certificate authority parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca_key = KeyPair::generate().expect("generate Headscale stub CA key");
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("self-sign Headscale stub CA certificate");
    let root_pem = ca_certificate.pem().into_bytes();

    let mut leaf_params = CertificateParams::new(vec!["localhost".into()])
        .expect("valid local TLS certificate parameters");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().expect("generate Headscale stub TLS key");
    let certificate = leaf_params
        .signed_by(&leaf_key, &ca_certificate, &ca_key)
        .expect("sign Headscale stub TLS certificate");
    let leaf_pem = certificate.pem().into_bytes();
    let key_pem = leaf_key.serialize_pem().into_bytes();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(leaf_pem, key_pem)
        .await
        .expect("configure Headscale stub TLS");
    let app = Router::new()
        .route("/api/v1/node", get(headscale_nodes))
        .route("/api/v1/node/42", get(headscale_node));
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().expect("convert stub listener"), tls)
            .handle(axum_server::Handle::new())
            .serve(app.into_make_service())
            .await
            .expect("serve Headscale proof stub");
    });

    HeadscaleStub {
        endpoint: format!("https://localhost:{}", addr.port()),
        addr,
        root_pem,
        task,
    }
}

fn provider_node(
    instance: ProviderInstanceId,
    reference: &ProviderCredentialReference,
) -> ProviderNode {
    let machine_key = "mkey:synthetic-machine-key";
    ProviderNode {
        identity: ProviderIdentity::new(
            instance,
            ProviderNodeId::parse("42").expect("valid fixture node id"),
            format!("sha256:{:x}", Sha256::digest(machine_key.as_bytes())),
        )
        .expect("valid fixture identity"),
        identity_evidence: ProviderIdentityEvidence {
            machine_key: Some(
                ConditionalIdentityEvidence::new(machine_key).expect("valid fixture machine key"),
            ),
            node_key: None,
            disco_key: None,
        },
        hostname: "worker-1".into(),
        given_name: "worker-1".into(),
        addresses: vec!["192.0.2.10".into()],
        user: None,
        pre_auth: Some(PreAuthCorrelationObservation {
            credential_id: reference.as_str().into(),
            association: PreAuthAssociationStrength::ProviderAuthenticatedRegistration,
        }),
        tags: BTreeSet::new(),
        registered_at: Some(Utc::now()),
        last_seen: Some(Utc::now()),
        expires_at: None,
        observed_at: Utc::now(),
        online: Some(true),
        expired: false,
    }
}

async fn seed_n4_n5_prerequisites(
    path: &std::path::Path,
    endpoint: &str,
    root_pem: &[u8],
) -> (
    NetworkId,
    nodescale_domain::DeviceId,
    nodescale_domain::JoinSessionId,
) {
    let store = StateStore::open(path).expect("open disposable N6 state database");
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "disposable-n6",
        ProviderKind::Headscale,
        instance,
        Utc::now(),
    )
    .expect("create N6 network");
    let reference = ProviderCredentialReference::new("9").expect("fixture credential reference");
    let seed_provider = SeedProvider {
        instance,
        node: provider_node(instance, &reference),
    };
    let root_fingerprint = format!("sha256:{:x}", Sha256::digest(root_pem));
    let import = HeadscaleImportConfig::new(
        endpoint,
        instance,
        "secret://vault/disposable-n6",
        "v0.29.3",
        TlsVerificationPolicy::Verify,
    )
    .expect("valid persisted Headscale import")
    .with_custom_root_ca_sha256(root_fingerprint)
    .expect("persist local Headscale root fingerprint");
    store
        .import_headscale_network(
            &network,
            &import,
            &seed_provider,
            Utc::now(),
            AuditActor::system(),
        )
        .await
        .expect("persist N2 provider import");
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            ProviderMutationConfiguration::new(
                instance,
                Generation::initial(),
                Generation::initial(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "headscale",
                "v0.29.3",
                true,
                false,
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::hours(1),
                MutationPolicyMode::Database,
                [
                    ProviderMutationCapability::CreateJoinCredential,
                    ProviderMutationCapability::InvalidateJoinCredential,
                ],
            )
            .expect("valid N4 mutation configuration"),
            AuditActor::system(),
        )
        .expect("persist N4 mutation configuration");

    let token = InvitationToken::generate(InvitationId::new());
    let invitation = Invitation::new_n4(
        token.invitation_id(),
        network.network_id,
        Roles::new([Role::Worker]).expect("worker role"),
        None,
        nodescale_domain::SecretVerifier::from_token(&token).expect("invitation verifier"),
        JoinConstraints::default(),
        Utc::now(),
        Utc::now() + Duration::minutes(15),
        1,
    )
    .expect("N4 invitation");
    store
        .issue_n4_invitation(
            &invitation,
            N4InvitationContext::new(instance, "n6-principal").expect("N4 context"),
            Utc::now(),
            AuditActor::system(),
        )
        .expect("issue N4 invitation");
    let candidate = store
        .n4_invitation_candidate(invitation.invitation_id)
        .expect("N4 candidate");
    let join_session_id = nodescale_domain::JoinSessionId::new();
    store
        .reserve_n4_redemption(
            invitation.invitation_id,
            candidate.revision,
            join_session_id,
            Utc::now(),
            N4PresentedMetadata::default(),
            AuditActor::system(),
        )
        .expect("reserve N4 redemption");
    let dispatch = store
        .begin_n4_credential_dispatch(join_session_id, Utc::now(), AuditActor::system())
        .expect("begin N4 credential dispatch");
    store
        .confirm_n4_credential(
            join_session_id,
            N4CredentialConfirmation {
                credential_id: ProviderCredentialId::new(),
                provider_reference: reference.clone(),
                provider_principal_id: dispatch.context.provider_principal_id,
                ephemeral: false,
                approved_tags: vec!["tag:nodescale-worker".into()],
                expires_at: Utc::now() + Duration::minutes(10),
                confirmed_at: Utc::now(),
                safe_correlation: SanitizedMetadata::new(serde_json::json!({"proof": "n6"}))
                    .expect("sanitized N4 correlation"),
            },
            AuditActor::system(),
        )
        .expect("confirm N4 credential");
    let configured = store
        .configured_n5_headscale_provider_with_custom_root_ca(
            network.network_id,
            ProviderApiKey::new(PROVIDER_TOKEN.into()).expect("provider API key"),
            Default::default(),
            HeadscaleCustomRootCa::PemBytes(root_pem.to_vec()),
        )
        .expect("construct configured provider for N5 proof seed");
    let confirmed = store
        .confirm_n5_device_identity(
            &configured,
            join_session_id,
            Utc::now(),
            AuditActor::system(),
        )
        .await
        .expect("confirm N5 provider identity");
    let root = store
        .bootstrap_n5_owner_trust_root(
            network.network_id,
            "nodescale",
            "n6-owner",
            DeviceTrustAuthorityAdminIntent::explicit(),
            Utc::now(),
            AuditActor::system(),
        )
        .expect("bootstrap N5 owner root");
    let authority = TrustAuthorityId::new();
    store
        .configure_n5_trust_authority(
            &root,
            &N5TrustAuthorityConfiguration::new(
                authority,
                network.network_id,
                "nodescale",
                "n6-owner",
                Generation::initial(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::hours(1),
                [DeviceTrustCapability::ActivateDeviceTrust],
                Utc::now(),
            )
            .expect("N5 trust authority"),
        )
        .expect("configure N5 trust authority");
    let authorization = store
        .issue_device_trust_authorization(
            &root,
            authority,
            confirmed.identity.device_id,
            Generation::initial(),
            DeviceTrustCapability::ActivateDeviceTrust,
            Utc::now(),
        )
        .expect("issue N5 trust authorization");
    store
        .activate_device_trust(authorization, Utc::now(), N5TrustReason::OwnerApproved)
        .expect("activate N5 trust");

    (
        network.network_id,
        confirmed.identity.device_id,
        join_session_id,
    )
}

fn new_production_service(
    path: &std::path::Path,
    network_id: NetworkId,
    root_pem: &[u8],
    clock: chrono::DateTime<Utc>,
) -> Arc<N6BindingService<FixedN6Clock>> {
    let store = StateStore::open(path).expect("reopen durable N6 state database");
    let provider = store
        .configured_n5_headscale_provider_with_custom_root_ca(
            network_id,
            ProviderApiKey::new(PROVIDER_TOKEN.into()).expect("provider API key"),
            Default::default(),
            HeadscaleCustomRootCa::PemBytes(root_pem.to_vec()),
        )
        .expect("construct configured production Headscale provider");
    Arc::new(
        N6BindingService::with_clock(
            store,
            provider,
            Duration::seconds(300),
            Arc::new(FixedN6Clock(clock)),
        )
        .expect("construct production N6 binding service"),
    )
}

struct RelayHarness {
    endpoint: String,
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl RelayHarness {
    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("relay server task");
    }
}

async fn start_authenticated_relay() -> RelayHarness {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind disposable Keryx relay");
    let addr: SocketAddr = listener.local_addr().expect("relay address");
    let runtime = RelayRuntime::new("disposable-n6-relay");
    let registry = Arc::new(SkillRegistry::new());
    registry
        .register_with_features(
            DESTINATION_NODE.parse().expect("destination node id"),
            Vec::new(),
            DESTINATION_NODE.into(),
            String::new(),
            vec![
                "nodescale_identity_bind_v1".into(),
                "nodescale.identity.challenge.v1".into(),
            ],
            None,
        )
        .await;
    for node_id in [SOURCE_NODE, WRONG_NODE] {
        registry
            .register_with_features(
                node_id.parse().expect("source node id"),
                Vec::new(),
                node_id.into(),
                String::new(),
                Vec::new(),
                None,
            )
            .await;
    }
    let tokens = HashMap::from([
        (
            SOURCE_NODE.parse().expect("source node token id"),
            SOURCE_TOKEN.into(),
        ),
        (
            WRONG_NODE.parse().expect("wrong node token id"),
            WRONG_TOKEN.into(),
        ),
        (
            DESTINATION_NODE.parse().expect("destination node token id"),
            DESTINATION_TOKEN.into(),
        ),
    ]);
    let service = RelayHealthService::with_registry_and_auth(
        runtime,
        registry,
        Arc::new(NodeTokenAuth::new(tokens, Default::default())),
    );
    let (shutdown, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(KeryxRelayServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                let _ = receiver.await;
            })
            .await
            .expect("serve disposable Keryx relay");
    });
    RelayHarness {
        endpoint: format!("http://{addr}"),
        addr,
        shutdown: Some(shutdown),
        task,
    }
}

fn authenticated_request<T>(node_id: &str, token: &str, value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        NODE_ID_METADATA_KEY,
        node_id.parse().expect("ASCII node metadata"),
    );
    request.metadata_mut().insert(
        NODE_TOKEN_METADATA_KEY,
        token.parse().expect("ASCII token metadata"),
    );
    request
}

async fn relay_client(endpoint: &str) -> KeryxRelayClient<Channel> {
    KeryxRelayClient::new(
        Endpoint::from_shared(endpoint.to_owned())
            .expect("relay endpoint")
            .connect()
            .await
            .expect("connect relay client"),
    )
}

async fn wait_for_edge_connection(endpoint: &str) {
    for _ in 0..80 {
        let mut client = relay_client(endpoint).await;
        if client
            .health(Request::new(HealthRequest {}))
            .await
            .expect("relay health")
            .into_inner()
            .connected_peers
            == 1
        {
            return;
        }
        tokio::time::sleep(StdDuration::from_millis(25)).await;
    }
    panic!("public edge stream did not authenticate and connect");
}

async fn wait_for_no_edge_connection(endpoint: &str) {
    for _ in 0..80 {
        let mut client = relay_client(endpoint).await;
        if client
            .health(Request::new(HealthRequest {}))
            .await
            .expect("relay health")
            .into_inner()
            .connected_peers
            == 0
        {
            return;
        }
        tokio::time::sleep(StdDuration::from_millis(25)).await;
    }
    panic!("cancelled public edge stream was not cleaned up");
}

fn challenge(
    operation_id: &str,
    network_id: NetworkId,
    device_id: nodescale_domain::DeviceId,
    join_session_id: nodescale_domain::JoinSessionId,
) -> NodescaleIdentityChallengeV1 {
    NodescaleIdentityChallengeV1 {
        operation_id: operation_id.into(),
        network_id: network_id.to_string(),
        device_id: device_id.to_string(),
        join_session_id: join_session_id.to_string(),
        agent_version: "nodescale-agent:6.0.0".into(),
    }
}

fn bind(
    operation_id: &str,
    network_id: NetworkId,
    device_id: nodescale_domain::DeviceId,
    join_session_id: nodescale_domain::JoinSessionId,
    nonce: String,
    generation: u64,
) -> NodescaleIdentityBindV1 {
    NodescaleIdentityBindV1 {
        operation_id: operation_id.into(),
        network_id: network_id.to_string(),
        device_id: device_id.to_string(),
        join_session_id: join_session_id.to_string(),
        binding_nonce: nonce,
        binding_generation: generation,
        agent_version: "nodescale-agent:6.0.0".into(),
    }
}

async fn spawn_edge<C: N6Clock>(
    endpoint: &str,
    service: Arc<N6BindingService<C>>,
) -> (
    JoinHandle<anyhow::Result<()>>,
    TryNodescaleKeryxAdapter<N6BindingService<C>>,
) {
    let adapter =
        TryNodescaleKeryxAdapter::new(service).expect("construct Nodescale Keryx adapter");
    let handlers = adapter.direct_control_handlers();
    let endpoint = endpoint.to_owned();
    let edge = tokio::spawn(async move {
        run_relay_stream_with_direct_control_handlers(
            endpoint,
            DESTINATION_NODE.into(),
            Some(DESTINATION_TOKEN.into()),
            None,
            handlers,
        )
        .await
    });
    (edge, adapter)
}

fn publish_proof_readiness(endpoints: &[SocketAddr]) {
    let Some(marker) = std::env::var_os("NODESCALE_N6_PROOF_READY_MARKER") else {
        return;
    };
    let prefix = std::env::var("NODESCALE_N6_PROOF_PREFIX").expect("proof prefix");
    let sentinel_a =
        std::env::var("NODESCALE_N6_PROOF_SECRET_SENTINEL_A").expect("proof sentinel A");
    let sentinel_b =
        std::env::var("NODESCALE_N6_PROOF_SECRET_SENTINEL_B").expect("proof sentinel B");
    assert!(!sentinel_a.is_empty() && !sentinel_b.is_empty() && sentinel_a != sentinel_b);
    let owned_endpoints = endpoints
        .iter()
        .map(|endpoint| {
            serde_json::json!({
                "address": endpoint.ip().to_string(),
                "port": endpoint.port(),
                "transport": "tcp",
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "owned_endpoints": owned_endpoints,
        "phase": "owned",
        "prefix": prefix,
    });
    fs::write(
        marker,
        serde_json::to_vec(&payload).expect("serialize proof readiness"),
    )
    .expect("write proof readiness marker");
}

#[tokio::test]
#[ignore]
async fn disposable_authenticated_keryx_binding_is_durable_and_cleans_up() {
    let database = DisposableDb::new();
    let headscale = start_headscale_stub().await;
    let (network_id, device_id, join_session_id) =
        seed_n4_n5_prerequisites(&database.path, &headscale.endpoint, &headscale.root_pem).await;
    let relay = start_authenticated_relay().await;
    let n6_clock = Utc::now();

    let service = new_production_service(&database.path, network_id, &headscale.root_pem, n6_clock);
    let (edge, adapter) = spawn_edge(&relay.endpoint, Arc::clone(&service)).await;
    wait_for_edge_connection(&relay.endpoint).await;
    publish_proof_readiness(&[headscale.addr, relay.addr]);

    let mut client = relay_client(&relay.endpoint).await;
    let issued = client
        .publish_nodescale_identity_challenge(authenticated_request(
            SOURCE_NODE,
            SOURCE_TOKEN,
            PublishNodescaleIdentityChallengeRequest {
                operation: Some(challenge(
                    "challenge-retry",
                    network_id,
                    device_id,
                    join_session_id,
                )),
                target_node_id: DESTINATION_NODE.into(),
            },
        ))
        .await
        .expect("challenge through authenticated relay stream")
        .into_inner()
        .result
        .expect("challenge result");
    assert!(issued.accepted);
    assert_eq!(
        issued.disposition,
        NodescaleIdentityChallengeDisposition::Issued as i32
    );
    assert!(!issued.challenge_secret.is_empty());
    let binding_nonce = issued.challenge_secret.clone();

    // This is the caller retry after a lost response: it must neither expose a
    // second secret nor mint a second durable challenge.
    let retried = client
        .publish_nodescale_identity_challenge(authenticated_request(
            SOURCE_NODE,
            SOURCE_TOKEN,
            PublishNodescaleIdentityChallengeRequest {
                operation: Some(challenge(
                    "challenge-retry",
                    network_id,
                    device_id,
                    join_session_id,
                )),
                target_node_id: DESTINATION_NODE.into(),
            },
        ))
        .await
        .expect("retry challenge through authenticated relay stream")
        .into_inner()
        .result
        .expect("retry result");
    assert!(!retried.accepted);
    assert_eq!(retried.code, "duplicate");
    assert!(retried.challenge_secret.is_empty());

    let wrong_peer = client
        .publish_nodescale_identity_bind(authenticated_request(
            WRONG_NODE,
            WRONG_TOKEN,
            PublishNodescaleIdentityBindRequest {
                operation: Some(bind(
                    "bind-wrong-peer",
                    network_id,
                    device_id,
                    join_session_id,
                    binding_nonce.clone(),
                    issued.binding_generation,
                )),
                target_node_id: DESTINATION_NODE.into(),
            },
        ))
        .await
        .expect("wrong peer bind receives typed rejection")
        .into_inner()
        .result
        .expect("wrong peer result");
    assert!(!wrong_peer.accepted);
    assert_eq!(wrong_peer.code, "rejected");

    let bound = client
        .publish_nodescale_identity_bind(authenticated_request(
            SOURCE_NODE,
            SOURCE_TOKEN,
            PublishNodescaleIdentityBindRequest {
                operation: Some(bind(
                    "bind-durable",
                    network_id,
                    device_id,
                    join_session_id,
                    binding_nonce.clone(),
                    issued.binding_generation,
                )),
                target_node_id: DESTINATION_NODE.into(),
            },
        ))
        .await
        .expect("bind through authenticated relay stream")
        .into_inner()
        .result
        .expect("bind result");
    assert!(bound.accepted);
    assert_eq!(
        bound.disposition,
        NodescaleIdentityBindDisposition::Active as i32
    );

    edge.abort();
    assert!(edge.await.expect_err("cancelled edge task").is_cancelled());
    drop(adapter);
    drop(service);
    wait_for_no_edge_connection(&relay.endpoint).await;

    let restarted_service =
        new_production_service(&database.path, network_id, &headscale.root_pem, n6_clock);
    let (restarted_edge, restarted_adapter) =
        spawn_edge(&relay.endpoint, Arc::clone(&restarted_service)).await;
    wait_for_edge_connection(&relay.endpoint).await;
    let replayed = relay_client(&relay.endpoint)
        .await
        .publish_nodescale_identity_bind(authenticated_request(
            SOURCE_NODE,
            SOURCE_TOKEN,
            PublishNodescaleIdentityBindRequest {
                operation: Some(bind(
                    "bind-durable",
                    network_id,
                    device_id,
                    join_session_id,
                    // Retry the exact authenticated request after process restart;
                    // the durable operation record, not this in-memory edge, settles it.
                    binding_nonce,
                    bound.generation,
                )),
                target_node_id: DESTINATION_NODE.into(),
            },
        ))
        .await
        .expect("durable bind replay through restarted edge")
        .into_inner()
        .result
        .expect("durable replay result");
    assert!(replayed.accepted);
    assert_eq!(
        replayed.disposition,
        NodescaleIdentityBindDisposition::AlreadyConfirmed as i32
    );
    assert_eq!(replayed.binding_id, bound.binding_id);

    restarted_edge.abort();
    assert!(
        restarted_edge
            .await
            .expect_err("cancelled restarted edge task")
            .is_cancelled()
    );
    drop(restarted_adapter);
    drop(restarted_service);
    wait_for_no_edge_connection(&relay.endpoint).await;

    let durable = StateStore::open(&database.path).expect("inspect durable N6 state");
    let active = durable
        .n6_active_binding(
            network_id,
            &KeryxPeerId::parse(SOURCE_NODE).expect("source peer id"),
        )
        .expect("inspect durable binding");
    assert_eq!(active.device_id, device_id);
    drop(durable);
    relay.stop().await;
}
