//! Disposable exact-tree N7 acceptance selector.
//!
//! This selector composes the real file-backed Nodescale state machine, the
//! production N7 actor and typed Fleet client, and Fleet's archived Python UDS
//! service. Fleet authenticates the Unix peer with `SO_PEERCRED`; the closed
//! `fleet.managed-projection.v1` transport has four-byte big-endian `32768`-byte
//! framing and no bearer credential. Raw UDS writes are deliberately confined to
//! duplicate-key, numeric-JSON, malformed, and trailing-byte protocol gates;
//! lifecycle transitions always use the public Nodescale/Fleet APIs.

use std::{
    env, fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use nodescale_domain::n7::{FleetGeneratedGrants, N7FleetDesiredProjection};
use nodescale_domain::{
    AgentVersion, Device, DeviceId, Generation, JoinSessionId, KeryxPeerId, MembershipState,
    N6AuthenticatedBindRequest, N6BindingChallengeRequest, Network, NetworkId, Operation,
    OperationId, ProviderBindingId, ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_fleet_client::{
    ApplyOperation, FleetClient, FleetClientError, GeneratedOperation, GeneratedStateKind,
    InspectSelector, ProjectionDocument, ProjectionGenerations, Provenance, RequestKind,
};
use nodescale_projection::production::{N7ProjectionOutcome, N7ProjectionService};
use nodescale_state::StateStore;
use rusqlite::Connection;
use serde_json::{Value, json};

const TEST_NAME: &str = "disposable_authenticated_fleet_projection_is_durable_and_cleans_up";
const SCHEMA: &str = "fleet.managed-projection.v1";
const MAX_FRAME: usize = 32_768;

struct FleetService {
    source: PathBuf,
    socket: PathBuf,
    database: PathBuf,
    allowed_uid: u32,
    child: Option<Child>,
}

impl FleetService {
    fn start(source: &Path, _prefix: &str, name: &str, allowed_uid: u32) -> Self {
        // The proof root itself is nonce-qualified and private; keep the leaf short enough
        // for Linux's 108-byte Unix-socket pathname limit inside archived roots.
        let socket = source.join(format!("n7-{name}.sock"));
        let database = source.join(format!("n7-{name}.sqlite"));
        let mut service = Self {
            source: source.to_path_buf(),
            socket,
            database,
            allowed_uid,
            child: None,
        };
        service.start_child();
        service
    }

    fn start_child(&mut self) {
        assert!(
            !self.socket.exists(),
            "test-owned Fleet socket must not pre-exist"
        );
        assert!(
            self.child.is_none(),
            "Fleet service must be stopped before restart"
        );
        self.child = Some(
            Command::new("python3")
                .args(["-m", "hermes_fleet.managed_service"])
                .arg("--socket")
                .arg(&self.socket)
                .arg("--database")
                .arg(&self.database)
                .arg("--allowed-uid")
                .arg(self.allowed_uid.to_string())
                .arg("--log-level")
                .arg("CRITICAL")
                .env("PYTHONPATH", &self.source)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("archived Fleet production module must start"),
        );
        self.wait_ready();
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.socket.exists() && UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            if self
                .child
                .as_mut()
                .expect("owned Fleet child")
                .try_wait()
                .expect("inspect Fleet child")
                .is_some()
            {
                panic!("archived Fleet production service exited before readiness");
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for archived Fleet production service");
    }

    fn restart(&mut self) {
        self.stop();
        self.start_child();
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&self.socket);
        assert!(
            !self.socket.exists(),
            "stopped Fleet socket must be unlinked"
        );
    }

    fn cleanup(&mut self) {
        self.stop();
        remove_sqlite(&self.database);
        assert!(!self.socket.exists(), "Fleet UDS cleanup");
        assert_sqlite_absent(&self.database);
    }
}

impl Drop for FleetService {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// A transparent, test-only fault boundary. It forwards the exact bytes emitted
/// by the production client. Capability traffic receives Fleet's response; the
/// subsequent production `apply` reaches and commits in Fleet, then its response
/// is deliberately discarded and the listener unlinked before N7 can inspect.
struct ResponseDroppingRelay {
    socket: PathBuf,
    committed_apply: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ResponseDroppingRelay {
    fn start(socket: PathBuf, upstream: PathBuf) -> Self {
        assert!(
            !socket.exists(),
            "test-owned relay socket must not pre-exist"
        );
        let listener = UnixListener::bind(&socket).expect("bind response-loss relay");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .expect("restrict response-loss relay socket");
        let committed_apply = Arc::new(AtomicBool::new(false));
        let committed = Arc::clone(&committed_apply);
        let owned_socket = socket.clone();
        let join = thread::spawn(move || {
            for request_number in 0..2 {
                let (mut downstream, _) = listener.accept().expect("accept production client");
                downstream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("relay downstream timeout");
                let mut frame = Vec::new();
                downstream
                    .read_to_end(&mut frame)
                    .expect("read exact production request frame");
                assert!(
                    frame.len() >= 4,
                    "production client writes a framed request"
                );
                let declared =
                    u32::from_be_bytes(frame[..4].try_into().expect("frame header")) as usize;
                assert_eq!(
                    declared + 4,
                    frame.len(),
                    "relay forwards exactly one full frame"
                );
                let mut upstream_stream =
                    UnixStream::connect(&upstream).expect("connect real Fleet");
                upstream_stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("relay upstream timeout");
                upstream_stream
                    .write_all(&frame)
                    .expect("forward exact production bytes");
                upstream_stream
                    .shutdown(Shutdown::Write)
                    .expect("half-close forwarded production request");
                let response = read_response_bytes(&mut upstream_stream)
                    .expect("real Fleet response arrives before deliberate loss");
                assert!(!response.is_empty(), "real Fleet returned a response");
                if request_number == 0 {
                    let mut framed_response = (response.len() as u32).to_be_bytes().to_vec();
                    framed_response.extend_from_slice(&response);
                    downstream
                        .write_all(&framed_response)
                        .expect("forward complete capabilities response frame");
                } else {
                    assert!(
                        frame
                            .windows(b"\"kind\":\"apply\"".len())
                            .any(|item| item == b"\"kind\":\"apply\""),
                        "only the production apply response is dropped"
                    );
                    committed.store(true, Ordering::SeqCst);
                    fs::remove_file(&owned_socket).expect("unlink relay before recovery inspect");
                    return;
                }
            }
            panic!("relay did not receive production apply");
        });
        Self {
            socket,
            committed_apply,
            join: Some(join),
        }
    }

    fn join_and_assert_committed(&mut self) {
        self.join
            .take()
            .expect("relay join exactly once")
            .join()
            .expect("response-loss relay thread");
        assert!(
            self.committed_apply.load(Ordering::SeqCst),
            "the real Fleet apply committed before its response was dropped"
        );
        assert!(
            !self.socket.exists(),
            "response-loss relay is closed before recovery"
        );
    }

    fn cleanup(&mut self) {
        // Normal execution joins after the intentional apply. On a preceding assertion
        // failure, detach rather than waiting forever in `accept`; process teardown owns it.
        let _ = self.join.take();
        let _ = fs::remove_file(&self.socket);
        assert!(!self.socket.exists(), "relay UDS cleanup");
    }
}

impl Drop for ResponseDroppingRelay {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn environment(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required for {TEST_NAME}"))
}

fn now() -> DateTime<Utc> {
    "2026-08-08T00:00:00Z".parse().expect("fixed fixture time")
}

fn operation(value: &str) -> OperationId {
    OperationId::parse(value).expect("bounded operation ID")
}

/// The only raw SQL fixture work establishes N5's already-confirmed prerequisite.
/// N6 active evidence is then issued and confirmed through public state APIs.
fn fixture(path: &Path) -> (StateStore, N7FleetDesiredProjection) {
    let store = StateStore::open(path).expect("open file-backed Nodescale state");
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    store
        .create_network(
            &Network::new(
                network_id,
                "n7 disposable production integration",
                ProviderKind::Headscale,
                ProviderInstanceId::new(),
                now(),
            )
            .expect("canonical network"),
            nodescale_domain::AuditActor::system(),
        )
        .expect("persist network");
    store
        .create_device(
            &Device::new(device_id, network_id, "n7-device", now()).expect("canonical device"),
            nodescale_domain::AuditActor::system(),
        )
        .expect("persist device");

    let provider_binding_id = seed_confirmed_n5_provenance(path, network_id, device_id);
    let peer = KeryxPeerId::parse("n7-disposable-production-peer").expect("peer");
    let version = AgentVersion::parse("nodescale-agent:7.0.0").expect("agent version");
    let challenge = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        provider_binding_id,
        peer.clone(),
        Generation::initial(),
        now() + ChronoDuration::minutes(5),
        now(),
        version.clone(),
    )
    .expect("canonical N6 challenge request");
    let delivery = store
        .issue_n6_binding_challenge(
            operation("n7-disposable-binding-challenge"),
            challenge,
            now(),
        )
        .expect("issue public N6 challenge");
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    let confirmed = store
        .confirm_n6_authenticated_binding(
            peer,
            N6AuthenticatedBindRequest::new(
                operation("n7-disposable-binding-confirm"),
                network_id,
                device_id,
                provider_binding_id,
                nonce.parse().expect("issued nonce"),
                Generation::initial(),
                version,
            )
            .expect("canonical authenticated N6 confirmation"),
            now(),
        )
        .expect("confirm public N6 binding");
    let binding = match confirmed {
        nodescale_state::N6AuthenticatedBindOutcome::Confirmed(binding) => binding,
        other => panic!("unexpected N6 binding outcome: {other:?}"),
    };
    let active = store
        .n6_active_binding_provenance(
            binding.binding_id,
            network_id,
            device_id,
            binding.generation,
        )
        .expect("read public exact active N6 provenance");
    let desired = N7FleetDesiredProjection::upsert_from_active_n6_provenance(
        network_id,
        device_id,
        "n7-device",
        MembershipState::Active,
        Generation::initial(),
        Generation::initial(),
        active,
        Roles::new([Role::Worker]).expect("roles"),
        FleetGeneratedGrants::new([Operation::FleetHealth, Operation::FleetInventory])
            .expect("canonical generated grants"),
    )
    .expect("canonical N7 desired projection");
    (store, desired)
}

fn seed_confirmed_n5_provenance(
    path: &Path,
    network_id: NetworkId,
    device_id: DeviceId,
) -> ProviderBindingId {
    let invitation_id = "60000000-0000-0000-0000-000000000001";
    let session_id =
        JoinSessionId::parse("70000000-0000-0000-0000-000000000001").expect("fixture session ID");
    let credential_id = "80000000-0000-0000-0000-000000000001";
    let network = network_id.to_string();
    let device = device_id.to_string();
    let connection = Connection::open(path).expect("open N5 prerequisite fixture");
    connection
        .execute_batch(&format!(
            "BEGIN; PRAGMA defer_foreign_keys=ON;\n             INSERT INTO invitations (invitation_id,network_id,state,secret_verifier,provider_credential_reference,max_uses,used_count,record_json,created_at,expires_at) VALUES ('{invitation_id}','{network}','issued','$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$MDEyMzQ1Njc4OWFiY2RlZg',NULL,1,0,'{{}}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z');
             INSERT INTO join_sessions (join_session_id,invitation_id,network_id,device_id,state,record_json,created_at,expires_at,updated_at) VALUES ('{session_id}','{invitation_id}','{network}','{device}','credential_issued','{{}}','2026-08-08T00:00:00Z','2026-08-09T00:00:00Z','2026-08-08T00:00:00Z');
             INSERT INTO provider_imports (network_id,provider_instance_id,server_url,opaque_secret_reference,compatibility_pin,tls_verification,read_only,mutation_allowed,compatibility,provider_version,last_success_at,last_attempt_at,last_failure_kind,last_failure_detail,custom_root_ca_sha256) VALUES ('{network}','provider-n7','https://provider.example.test','secret://vault/n7','v0.29.3','verify',1,0,'compatible','v0.29.3',NULL,NULL,NULL,NULL,NULL);
             INSERT INTO provider_mutation_configurations (network_id,provider_instance_id,authorization_generation,configuration_generation,configuration_fingerprint,adapter,expected_version,enabled,revoked,not_before_ms,expires_at_ms,policy_mode) VALUES ('{network}','provider-n7',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','headscale','v0.29.3',1,0,0,999999999999,'database');
             INSERT INTO confirmed_provider_credential_references (credential_id,network_id,provider_instance_id,provider_reference,authorization_generation,configuration_generation,configuration_fingerprint,confirmed_at_ms,expires_at_ms,max_uses) VALUES ('{credential_id}','{network}','provider-n7','provider-ref-n7',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,999999999999,1);
             INSERT INTO n4_invitation_details (invitation_id,network_id,provider_instance_id,provider_principal_id,roles_json,constraints_json,created_by_source,created_by_id,revision,last_redemption_metadata_json) VALUES ('{invitation_id}','{network}','provider-n7','principal-n7','[]','{{}}','nodescale',NULL,1,'{{}}');
             INSERT INTO n4_join_session_dispatches (join_session_id,invitation_id,network_id,provider_instance_id,provider_principal_id,create_request_id,dispatch_state,authorization_generation,configuration_generation,configuration_fingerprint,dispatched_at_ms,resolved_at_ms,credential_id) VALUES ('{session_id}','{invitation_id}','{network}','provider-n7','principal-n7','90000000-0000-0000-0000-000000000001','confirmed',1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,1001,'{credential_id}');
             INSERT INTO n4_provider_credential_metadata (credential_id,join_session_id,network_id,provider_instance_id,provider_principal_id,single_use,reusable,ephemeral,approved_tags_json,expires_at_ms,confirmed_at_ms,invalidation_state,safe_correlation_json) VALUES ('{credential_id}','{session_id}','{network}','provider-n7','principal-n7',1,0,1,'[]',999999999999,1001,'active','{{}}');\n             INSERT INTO n5_device_identities (device_id,network_id,identity_origin_kind,identity_origin_id,n4_origin_id,adoption_origin_id,confirmed_at_ms,identity_revision,safe_correlation_digest) VALUES ('{device}','{network}','n4_join_session','{session_id}','{session_id}',NULL,1001,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');\n             INSERT INTO n5_n4_identity_origins (origin_id,origin_kind,device_id,network_id,join_session_id) VALUES ('{session_id}','n4_join_session','{device}','{network}','{session_id}');\n             INSERT INTO n5_provider_bindings (binding_id,device_id,network_id,provenance_kind,n4_provenance_binding_id,adoption_provenance_binding_id,provider_instance_id,provider_node_id,machine_key_fingerprint,binding_state,binding_revision,observed_at_ms) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','{device}','{network}','n4_join_session','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',NULL,'provider-n7','provider-node-n7','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','active',1,1001);\n             INSERT INTO n5_n4_provider_binding_provenance (binding_id,provenance_kind,device_id,network_id,identity_origin_kind,identity_origin_id,join_session_id,credential_id,provider_credential_reference,provider_instance_id) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','n4_join_session','{device}','{network}','n4_join_session','{session_id}','{session_id}','{credential_id}','provider-ref-n7','provider-n7'); COMMIT;"
        ))
        .expect("seed only confirmed N5 prerequisite");
    ProviderBindingId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .expect("fixture provider binding")
}

fn write_readiness(marker: &Path, prefix: &str, sockets: &[&Path]) {
    assert!(!sockets.is_empty(), "every owned UDS is explicitly tracked");
    assert!(
        sockets.iter().all(|socket| socket.exists()),
        "UDS ready before marker"
    );
    let paths = sockets
        .iter()
        .map(|socket| format!("\"{}\"", socket.display()))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        marker,
        format!(r#"{{"owned_uds_paths":[{paths}],"phase":"owned","prefix":"{prefix}"}}"#),
    )
    .expect("write secret-free readiness marker");
    fs::set_permissions(marker, fs::Permissions::from_mode(0o600))
        .expect("restrict readiness marker");
}

fn remove_sqlite(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = fs::remove_file(candidate);
    }
}

fn assert_sqlite_absent(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        assert!(
            !PathBuf::from(format!("{}{}", path.display(), suffix)).exists(),
            "SQLite cleanup for {}{}",
            path.display(),
            suffix
        );
    }
}

fn read_response_bytes(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid response frame",
        ));
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn request_frame(
    socket: &Path,
    declared_length: u32,
    payload: &[u8],
    trailing: &[u8],
    close_write: bool,
) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&declared_length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.write_all(trailing)?;
    if close_write {
        stream.shutdown(Shutdown::Write)?;
    }
    let response = read_response_bytes(&mut stream)?;
    String::from_utf8(response).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn request(socket: &Path, payload: &[u8], trailing: &[u8]) -> io::Result<String> {
    request_frame(socket, payload.len() as u32, payload, trailing, true)
}

fn assert_closed_error(response: String) {
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("Fleet closed error JSON"),
        json!({
            "schema": SCHEMA,
            "kind": "error",
            "ok": false,
            "error": "invalid_request",
        }),
        "Fleet returns only the closed V1 invalid-request envelope"
    );
}

fn assert_invalid(socket: &Path, payload: &[u8], trailing: &[u8]) {
    assert_closed_error(
        request(socket, payload, trailing).expect("real Fleet closed error response"),
    );
}

fn assert_invalid_frame(socket: &Path, declared_length: u32, payload: &[u8], trailing: &[u8]) {
    assert_closed_error(
        request_frame(socket, declared_length, payload, trailing, true)
            .expect("real Fleet framed error response"),
    );
}

fn direct_document(
    network: &str,
    device: &str,
    generation: u64,
    generated_operations: Vec<GeneratedOperation>,
) -> ProjectionDocument {
    let generation = generation.to_string();
    ProjectionDocument::new(
        network,
        device,
        ProjectionGenerations::new(&generation, &generation, &generation),
        ApplyOperation::Upsert,
        generated_operations,
        Provenance::new(network, device, generation),
    )
}

fn raw_apply(socket: &Path, document: &ProjectionDocument) -> Value {
    let payload = serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "kind": "apply",
        "document": document,
    }))
    .expect("serialize closed direct apply request");
    serde_json::from_str(&request(socket, &payload, b"").expect("direct Fleet apply response"))
        .expect("direct Fleet apply JSON")
}

fn assert_apply_outcome(socket: &Path, document: &ProjectionDocument, outcome: &str) {
    assert_eq!(
        raw_apply(socket, document),
        json!({
            "schema": SCHEMA,
            "kind": "apply",
            "ok": true,
            "result": {"outcome": outcome},
        }),
        "Fleet apply response uses the closed V1 outcome envelope"
    );
}

fn assert_frozen_v1_protocol_gates(socket: &Path) {
    let capabilities = br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities"}"#;
    assert_eq!(
        serde_json::from_str::<Value>(
            &request(socket, capabilities, b"").expect("capabilities response")
        )
        .expect("capabilities response JSON"),
        json!({
            "schema": SCHEMA,
            "kind": "capabilities",
            "ok": true,
            "result": {"kinds": ["capabilities", "apply", "inspect"]},
        }),
        "capabilities is the exact selected V1 surface"
    );
    let mut maximum_legal_frame = capabilities.to_vec();
    maximum_legal_frame.resize(MAX_FRAME, b' ');
    assert_eq!(
        serde_json::from_str::<Value>(
            &request(socket, &maximum_legal_frame, b"").expect("maximum legal frame response"),
        )
        .expect("maximum legal frame JSON"),
        json!({
            "schema": SCHEMA,
            "kind": "capabilities",
            "ok": true,
            "result": {"kinds": ["capabilities", "apply", "inspect"]},
        }),
        "the inclusive 32768-byte frame limit remains valid"
    );

    // Framing failures: zero/oversized declared lengths, truncated frames,
    // invalid UTF-8, malformed JSON, trailing bytes, and omitted half-close.
    assert_invalid_frame(socket, 0, b"", b"");
    assert_invalid_frame(socket, MAX_FRAME as u32 + 1, b"", b"");
    assert_invalid_frame(socket, 3, b"{}", b"");
    assert_invalid(socket, &[0xff], b"");
    assert_invalid(socket, b"{", b"");
    assert_invalid(socket, capabilities, b"unexpected");
    assert_closed_error(
        request_frame(socket, capabilities.len() as u32, capabilities, b"", false)
            .expect("Fleet rejects a frame without write half-close"),
    );

    // Closed request grammar: no alternate envelope, unknown or missing keys,
    // malformed document/selector/provenance, every nesting-level duplicate,
    // and all JSON number spellings fail before dispatch.
    for payload in [
        br#"{}"#.as_slice(),
        br#"[]"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","extra":true}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","request_id":"x"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","body":{}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","bearer":"not-a-credential"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","authorization":"not-a-credential"}"#.as_slice(),
        br#"{"schema":"not-fleet.v1","kind":"capabilities"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"other"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","kind":"apply"}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"apply","document":{"source":"nodescale","source":"other"}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"apply","document":{"source":"nodescale","network_id":"n","device_id":"d","projection_generation":"1","membership_generation":"1","binding_generation":"1","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"upsert","generated_operations":[],"provenance":{"source":"nodescale","source":"other","network_id":"n","device_id":"d","snapshot":"1"}}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale","source":"other","network_id":"n","device_id":"d"}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"apply","document":{"source":"nodescale"}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale","network_id":"n","device_id":"d","extra":"x"}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale"}}"#.as_slice(),
        br#"{"schema":"fleet.managed-projection.v1","kind":"apply","document":{"source":"nodescale","network_id":"n","device_id":"d","projection_generation":1,"membership_generation":"1","binding_generation":"1","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"upsert","generated_operations":[],"provenance":{}}}"#.as_slice(),
        br#"1"#.as_slice(),
        br#"1.5"#.as_slice(),
        br#"1e2"#.as_slice(),
        br#"NaN"#.as_slice(),
        br#"Infinity"#.as_slice(),
        br#"-Infinity"#.as_slice(),
    ] {
        assert_invalid(socket, payload, b"");
    }

    let network = "n7-frozen-v1-gates-network";
    let device = "n7-frozen-v1-gates-device";
    let missing = br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale","network_id":"n7-frozen-v1-gates-network","device_id":"n7-frozen-v1-gates-device"}}"#;
    assert_eq!(
        serde_json::from_str::<Value>(
            &request(socket, missing, b"").expect("missing inspect response")
        )
        .expect("missing inspect JSON"),
        json!({
            "schema": SCHEMA,
            "kind": "inspect",
            "ok": true,
            "result": {"generated": null, "effective": null},
        }),
        "a missing durable managed identity is an explicit null inspect result"
    );

    let generation_ten = direct_document(
        network,
        device,
        10,
        vec![
            GeneratedOperation::Health,
            GeneratedOperation::Inventory,
            GeneratedOperation::Message,
        ],
    );
    let mut malformed_document =
        serde_json::to_value(&generation_ten).expect("direct document JSON");
    malformed_document["extra"] = json!("forbidden");
    let payload = serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "kind": "apply",
        "document": malformed_document,
    }))
    .expect("unknown-document-field request JSON");
    assert_invalid(socket, &payload, b"");
    let mut malformed_document =
        serde_json::to_value(&generation_ten).expect("direct document JSON");
    malformed_document["generated_operations"] = json!(["fleet.health", "fleet.health"]);
    let payload = serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "kind": "apply",
        "document": malformed_document,
    }))
    .expect("duplicate-generated-operation request JSON");
    assert_invalid(socket, &payload, b"");
    let mut malformed_document =
        serde_json::to_value(&generation_ten).expect("direct document JSON");
    malformed_document["provenance"]["network_id"] = json!("different-network");
    let payload = serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "kind": "apply",
        "document": malformed_document,
    }))
    .expect("mismatched-provenance request JSON");
    assert_invalid(socket, &payload, b"");
    assert_apply_outcome(socket, &generation_ten, "applied");
    assert_apply_outcome(socket, &generation_ten, "already_applied");
    assert_apply_outcome(
        socket,
        &direct_document(network, device, 10, vec![GeneratedOperation::Health]),
        "conflict",
    );
    assert_apply_outcome(
        socket,
        &direct_document(network, device, 9, vec![GeneratedOperation::Health]),
        "stale",
    );
    assert_apply_outcome(
        socket,
        &direct_document(network, device, 12, vec![GeneratedOperation::Health]),
        "gap",
    );
    let generation_eleven = direct_document(
        network,
        device,
        11,
        vec![
            GeneratedOperation::Health,
            GeneratedOperation::Inventory,
            GeneratedOperation::Message,
        ],
    );
    assert_apply_outcome(socket, &generation_eleven, "applied");

    let mut unsupported = serde_json::to_value(&generation_eleven).expect("direct document JSON");
    for operation in [
        "fleet.hermes.run",
        "fleet.execution",
        "fleet.admin",
        "fleet.*",
    ] {
        unsupported["generated_operations"] = json!([operation]);
        let payload = serde_json::to_vec(&json!({
            "schema": SCHEMA,
            "kind": "apply",
            "document": unsupported,
        }))
        .expect("unsupported-operation request JSON");
        assert_invalid(socket, &payload, b"");
    }

    let inspect = br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale","network_id":"n7-frozen-v1-gates-network","device_id":"n7-frozen-v1-gates-device"}}"#;
    assert_eq!(
        serde_json::from_str::<Value>(
            &request(socket, inspect, b"").expect("direct inspect response")
        )
        .expect("direct inspect JSON"),
        json!({
            "schema": SCHEMA,
            "kind": "inspect",
            "ok": true,
            "result": {
                "generated": {
                    "state": "active",
                    "projection_generation": "11",
                    "membership_generation": "11",
                    "binding_generation": "11",
                    "content_hash": generation_eleven.content_hash,
                    "allowed_operations": ["fleet.health", "fleet.inventory", "fleet.message"],
                    "provenance": {
                        "source": "nodescale",
                        "network_id": network,
                        "device_id": device,
                        "snapshot": "11",
                    },
                },
                "effective": {
                    "state": "active",
                    "allowed_operations": ["fleet.health", "fleet.inventory", "fleet.message"],
                    "operator_denied_operations": [],
                },
            },
        }),
        "Fleet inspect is durable generated/effective authority, never an apply echo"
    );
}

fn assert_fleet_audit_count(database: &Path, generation: u64, expected: i64) {
    let connection = Connection::open(database).expect("open Fleet durable audit");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM managed_projection_audit WHERE projection_generation=?1 AND outcome='applied'",
                [generation.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("Fleet applied audit count"),
        expected,
        "Fleet applies each generation once"
    );
}

fn assert_nodescale_durable_state(database: &Path) {
    let connection = Connection::open(database).expect("open durable Nodescale state");
    for generation in 1..=3 {
        let state: String = connection
            .query_row(
                "SELECT projection_state FROM n7_fleet_projection_records WHERE generation=?1",
                [generation],
                |row| row.get(0),
            )
            .expect("durable N7 record");
        assert_eq!(state, "applied", "generation {generation} durable result");
    }
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM n7_fleet_projection_audit WHERE event_kind='projection_applied'", [], |row| row.get::<_, i64>(0))
            .expect("Nodescale applied audit"),
        3,
        "all three production transitions have durable Nodescale audit evidence"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM n7_fleet_projection_inspections WHERE inspection_kind='observed'", [], |row| row.get::<_, i64>(0))
            .expect("Nodescale authoritative inspections"),
        3,
        "response recovery plus later transitions use real Fleet inspections"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM n7_fleet_projection_inspections WHERE inspection_kind='unavailable'", [], |row| row.get::<_, i64>(0))
            .expect("Nodescale unavailable inspection"),
        1,
        "lost apply response is durably classified before restart recovery"
    );
}

fn set_operator_deny(fleet_root: &Path, database: &Path, network: &str, device: &str) {
    let status = Command::new("python3")
        .args([
            "-c",
            "from hermes_fleet.managed_projection import ManagedProjectionStore as S; import sys; S(sys.argv[1]).set_operator_deny(source='nodescale', network_id=sys.argv[2], device_id=sys.argv[3], operation='fleet.inventory', denied=True)",
        ])
        .arg(database)
        .arg(network)
        .arg(device)
        .env("PYTHONPATH", fleet_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("call Fleet's production local policy API");
    assert!(status.success(), "Fleet operator-deny mutation");
}

fn current_uid() -> u32 {
    let output = Command::new("id").arg("-u").output().expect("read uid");
    assert!(output.status.success(), "id -u");
    std::str::from_utf8(&output.stdout)
        .expect("uid UTF-8")
        .trim()
        .parse()
        .expect("numeric UID")
}

#[test]
#[ignore]
fn disposable_authenticated_fleet_projection_is_durable_and_cleans_up() {
    let root = PathBuf::from(environment("NODESCALE_N7_PROOF_ROOT"));
    let fleet_root = PathBuf::from(environment("FLEET_N7_PROOF_ROOT"));
    let prefix = environment("NODESCALE_N7_PROOF_PREFIX");
    let marker = PathBuf::from(environment("NODESCALE_N7_PROOF_READY_MARKER"));
    // Sentinels are deliberately read but never serialized, forwarded, or persisted.
    let _sentinel_a = environment("NODESCALE_N7_PROOF_SECRET_SENTINEL_A");
    let _sentinel_b = environment("NODESCALE_N7_PROOF_SECRET_SENTINEL_B");
    assert!(
        root.is_dir() && fleet_root.is_dir(),
        "runner provides private archived roots"
    );
    assert_eq!(marker.parent(), Some(root.as_path()));

    let uid = current_uid();
    let mut fleet = FleetService::start(&fleet_root, &prefix, "primary", uid);
    let mut wrong_uid =
        FleetService::start(&fleet_root, &prefix, "wrong-uid", uid.saturating_add(1));
    let relay_socket = fleet_root.join("n7-response-loss.sock");
    let mut relay = ResponseDroppingRelay::start(relay_socket, fleet.socket.clone());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let direct_client = FleetClient::new(&fleet.socket);
    let wrong_client = FleetClient::new(&wrong_uid.socket);
    assert_frozen_v1_protocol_gates(&fleet.socket);
    let capabilities = runtime
        .block_on(direct_client.capabilities())
        .expect("production client against real Fleet");
    assert_eq!(
        capabilities.kinds,
        vec![
            RequestKind::Capabilities,
            RequestKind::Apply,
            RequestKind::Inspect
        ],
        "real Fleet advertises the closed V1 contract"
    );
    assert!(
        matches!(
            runtime.block_on(wrong_client.capabilities()),
            Err(FleetClientError::Unavailable | FleetClientError::ResponseLost)
        ),
        "wrong SO_PEERCRED UID is denied through the production FleetClient"
    );

    let state_database = root.join(format!("{prefix}-nodescale-state.sqlite"));
    let (store, desired_one) = fixture(&state_database);
    let first = N7ProjectionService::start(store, FleetClient::new(&relay.socket))
        .expect("start real N7 service with transparent response-loss relay");
    let first_operation = operation("n7-disposable-response-loss");
    assert_eq!(
        runtime
            .block_on(first.reconcile(first_operation.clone(), desired_one.clone()))
            .expect("ambiguous first reconciliation"),
        N7ProjectionOutcome::Retryable,
        "lost production apply response never becomes local success without inspection"
    );
    runtime
        .block_on(first.shutdown())
        .expect("shutdown first N7 actor");
    relay.join_and_assert_committed();
    assert_fleet_audit_count(&fleet.database, 1, 1);

    // Restarting Fleet proves the accepted write is file-backed, then reopening Nodescale
    // proves recovery inspects the real authority before any reapply.
    fleet.restart();
    let after_fleet_restart = runtime
        .block_on(direct_client.inspect(InspectSelector::new(
            desired_one.network_id().to_string(),
            desired_one.device_id().to_string(),
        )))
        .expect("typed Fleet inspect after restart");
    let generated = after_fleet_restart
        .generated
        .expect("Fleet persisted generation one");
    assert_eq!(generated.state, GeneratedStateKind::Active);
    assert_eq!(generated.projection_generation, "1");
    assert_eq!(
        generated.content_hash.len(),
        64,
        "Fleet returned a SHA-256 hash"
    );
    assert!(
        generated
            .content_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "typed Fleet inspect returns the production canonical hash"
    );
    assert_eq!(
        generated.allowed_operations,
        vec![GeneratedOperation::Health, GeneratedOperation::Inventory]
    );

    let recovered = N7ProjectionService::start(
        StateStore::open(&state_database).expect("reopen durable Nodescale state"),
        FleetClient::new(&fleet.socket),
    )
    .expect("restart N7 service with direct production FleetClient");
    assert_eq!(
        runtime
            .block_on(recovered.reconcile(first_operation.clone(), desired_one.clone()))
            .expect("inspection-first recovery"),
        N7ProjectionOutcome::Applied
    );
    assert_fleet_audit_count(&fleet.database, 1, 1);
    assert_eq!(
        runtime
            .block_on(recovered.reconcile(first_operation, desired_one.clone()))
            .expect("exact terminal replay"),
        N7ProjectionOutcome::AlreadyApplied
    );
    assert_fleet_audit_count(&fleet.database, 1, 1);

    // Publish interruption readiness only after the test-only relay has exited and
    // unlinked its socket. The only live owned UDS paths are now production Fleet
    // services, both of which handle SIGTERM and unlink themselves.
    write_readiness(
        &marker,
        &prefix,
        &[fleet.socket.as_path(), wrong_uid.socket.as_path()],
    );

    set_operator_deny(
        &fleet_root,
        &fleet.database,
        &desired_one.network_id().to_string(),
        &desired_one.device_id().to_string(),
    );
    let denied = runtime
        .block_on(direct_client.inspect(InspectSelector::new(
            desired_one.network_id().to_string(),
            desired_one.device_id().to_string(),
        )))
        .expect("typed Fleet inspect after local deny");
    assert_eq!(
        denied
            .generated
            .expect("generated state remains authoritative")
            .allowed_operations,
        vec![GeneratedOperation::Health, GeneratedOperation::Inventory]
    );
    assert_eq!(
        denied
            .effective
            .expect("effective Fleet state")
            .allowed_operations,
        vec![GeneratedOperation::Health],
        "Fleet-local deny does not rewrite Nodescale-generated truth"
    );

    let desired_two = desired_one
        .disable(Generation::new(2).expect("generation two"))
        .expect("canonical disabled desired projection");
    assert_eq!(
        runtime
            .block_on(recovered.reconcile(operation("n7-disposable-disable"), desired_two.clone()))
            .expect("disable reconciliation"),
        N7ProjectionOutcome::Applied
    );
    let disabled = runtime
        .block_on(direct_client.inspect(InspectSelector::new(
            desired_two.network_id().to_string(),
            desired_two.device_id().to_string(),
        )))
        .expect("typed disabled inspection")
        .generated
        .expect("disabled generated record");
    assert_eq!(disabled.state, GeneratedStateKind::Disabled);
    assert_eq!(disabled.projection_generation, "2");
    assert!(
        disabled.allowed_operations.is_empty(),
        "disable clears generated grants"
    );
    assert_fleet_audit_count(&fleet.database, 2, 1);

    let desired_three = desired_two
        .remove(Generation::new(3).expect("generation three"))
        .expect("canonical removed desired projection");
    assert_eq!(
        runtime
            .block_on(recovered.reconcile(operation("n7-disposable-remove"), desired_three.clone()))
            .expect("remove reconciliation"),
        N7ProjectionOutcome::Applied
    );
    let removed = runtime
        .block_on(direct_client.inspect(InspectSelector::new(
            desired_three.network_id().to_string(),
            desired_three.device_id().to_string(),
        )))
        .expect("typed removed inspection")
        .generated
        .expect("removed generated tombstone");
    assert_eq!(removed.state, GeneratedStateKind::Removed);
    assert_eq!(removed.projection_generation, "3");
    assert!(
        removed.allowed_operations.is_empty(),
        "remove clears generated grants"
    );
    assert_fleet_audit_count(&fleet.database, 3, 1);
    runtime
        .block_on(recovered.shutdown())
        .expect("shutdown recovered N7 actor");
    assert_nodescale_durable_state(&state_database);

    // These hostile raw frames are deliberately only narrow closed-protocol gates.
    assert_invalid(
        &fleet.socket,
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","kind":"apply"}"#,
        b"",
    );
    assert_invalid(
        &fleet.socket,
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","n":1}"#,
        b"",
    );
    assert_invalid(
        &fleet.socket,
        br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities"}"#,
        b"x",
    );
    let oversize = (MAX_FRAME as u32 + 1).to_be_bytes();
    let mut oversize_stream = UnixStream::connect(&fleet.socket).expect("oversize gate connect");
    oversize_stream
        .write_all(&oversize)
        .expect("oversize header");
    oversize_stream
        .shutdown(Shutdown::Write)
        .expect("oversize EOF");
    let response = read_response_bytes(&mut oversize_stream).expect("oversize error response");
    assert_closed_error(String::from_utf8(response).expect("closed oversize error response UTF-8"));

    fleet.cleanup();
    wrong_uid.cleanup();
    relay.cleanup();
    fs::remove_file(&marker).expect("remove readiness marker");
    remove_sqlite(&state_database);
    assert!(!marker.exists(), "readiness marker cleanup");
    assert_sqlite_absent(&state_database);
    assert!(
        !fleet.socket.exists() && !wrong_uid.socket.exists() && !relay.socket.exists(),
        "all test-owned UDS paths closed"
    );
}
