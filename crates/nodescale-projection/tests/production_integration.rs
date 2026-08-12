//! RED contract for the production N7 service.
//!
//! This is deliberately not a second local projection model: inputs are the
//! canonical domain desired projection, persistence is the real file-backed
//! `StateStore`, and the only fake is a scripted implementation of the narrow
//! `nodescale-fleet-client` transport adapter.  The production implementation
//! must provide the imported API without widening the Fleet boundary.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};
use nodescale_domain::n7::{FleetGeneratedGrants, N7FleetDesiredProjection};
use nodescale_domain::{
    AgentVersion, Device, DeviceId, Generation, JoinSessionId, KeryxPeerId, MembershipState,
    N6AuthenticatedBindRequest, N6BindingChallengeRequest, Network, NetworkId, Operation,
    OperationId, ProviderBindingId, ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_fleet_client::{
    ApplyError, ApplyOperation, ApplyOutcome, ApplyResult, Capabilities, FleetClientError,
    GeneratedOperation, GeneratedState, GeneratedStateKind, InspectResult, InspectSelector,
    ProjectionDocument, Provenance,
};
use nodescale_projection::production::{
    FleetProjectionTransport, N7ProductionError, N7ProjectionOutcome, N7ProjectionService,
};
use nodescale_state::StateStore;
use rusqlite::Connection;
use tempfile::tempdir;

fn now() -> DateTime<Utc> {
    "2026-08-08T00:00:00Z".parse().expect("fixed test time")
}

/// A real StateStore fixture with an already-active N6 tuple.  The production
/// integration is responsible for rechecking this exact tuple before its first
/// Fleet call; the domain desired value does not manufacture that evidence.
fn fixture(path: &Path) -> (StateStore, N7FleetDesiredProjection) {
    let store = StateStore::open(path).expect("open file-backed N7 state");
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    store
        .create_network(
            &Network::new(
                network_id,
                "n7 production integration",
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
    let peer = KeryxPeerId::parse("n7-production-peer").expect("peer");
    let version = AgentVersion::parse("nodescale-agent:7.0.0").expect("agent version");
    let challenge = N6BindingChallengeRequest::new(
        network_id,
        device_id,
        provider_binding_id,
        peer.clone(),
        Generation::initial(),
        now() + Duration::minutes(5),
        now(),
        version.clone(),
    )
    .expect("canonical challenge request");
    let delivery = store
        .issue_n6_binding_challenge(operation("n7-binding-challenge"), challenge, now())
        .expect("issue authenticated N6 challenge");
    let nonce = delivery.with_nonce(|value| value.with_encoded(str::to_owned));
    let confirmed = store
        .confirm_n6_authenticated_binding(
            peer,
            N6AuthenticatedBindRequest::new(
                operation("n7-binding-confirm"),
                network_id,
                device_id,
                provider_binding_id,
                nonce.parse().expect("reparse issued nonce"),
                Generation::initial(),
                version,
            )
            .expect("canonical authenticated binding request"),
            now(),
        )
        .expect("confirm authenticated N6 binding");
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
        .expect("read exact active N6 provenance through the production seam");

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
            .expect("generated grants"),
    )
    .expect("canonical domain desired projection");
    (store, desired)
}

/// Raw fixture rows establish only the N5-confirmed prerequisite that existing
/// N6 lifecycle tests use. The active binding itself is always created through
/// the public N6 challenge and authenticated-confirmation state machine above.
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
    let connection = Connection::open(path).expect("open fixture state");
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
        .expect("seed confirmed N5 provenance");
    ProviderBindingId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .expect("fixture provider binding")
}

fn start_service(
    store: StateStore,
    transport: ScriptedTransport,
) -> N7ProjectionService<ScriptedTransport> {
    N7ProjectionService::start(store, transport).expect("start single-owner production actor")
}

fn operation(value: &str) -> OperationId {
    OperationId::parse(value).expect("operation id")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Capabilities,
    Apply,
    Inspect,
}

enum InspectStep {
    Fixed(Box<Result<InspectResult, FleetClientError>>),
    MatchingLastAppliedDocument,
}

#[derive(Clone)]
struct ScriptedTransport {
    state_path: PathBuf,
    events: Arc<Mutex<Vec<Event>>>,
    apply: Arc<Mutex<VecDeque<Result<ApplyResult, ApplyError>>>>,
    inspect: Arc<Mutex<VecDeque<InspectStep>>>,
    last_document: Arc<Mutex<Option<ProjectionDocument>>>,
}

impl ScriptedTransport {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            state_path: path.into(),
            events: Arc::new(Mutex::new(Vec::new())),
            apply: Arc::new(Mutex::new(VecDeque::new())),
            inspect: Arc::new(Mutex::new(VecDeque::new())),
            last_document: Arc::new(Mutex::new(None)),
        }
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().expect("events lock").clone()
    }

    fn push_apply(&self, result: Result<ApplyResult, ApplyError>) {
        self.apply.lock().expect("apply lock").push_back(result);
    }

    fn push_inspect(&self, result: Result<InspectResult, FleetClientError>) {
        self.inspect
            .lock()
            .expect("inspect lock")
            .push_back(InspectStep::Fixed(Box::new(result)));
    }

    fn push_matching_inspection(&self) {
        self.inspect
            .lock()
            .expect("inspect lock")
            .push_back(InspectStep::MatchingLastAppliedDocument);
    }

    fn matching_inspection(&self) -> InspectResult {
        let document = self
            .last_document
            .lock()
            .expect("document lock")
            .clone()
            .expect("apply precedes matching inspection");
        let state = match document.operation {
            ApplyOperation::Upsert => GeneratedStateKind::Active,
            ApplyOperation::Disable => GeneratedStateKind::Disabled,
            ApplyOperation::Remove => GeneratedStateKind::Removed,
        };
        InspectResult {
            generated: Some(GeneratedState {
                state,
                projection_generation: document.projection_generation,
                membership_generation: document.membership_generation,
                binding_generation: document.binding_generation,
                content_hash: document.content_hash,
                allowed_operations: document.generated_operations,
                provenance: document.provenance,
            }),
            effective: None,
        }
    }

    fn assert_desired_and_attempted_are_durable_before_apply(&self, document: &ProjectionDocument) {
        let connection =
            Connection::open(&self.state_path).expect("open durable state for assertion");
        let row: (Vec<u8>, String, String, String, u64, String, i64) = connection
            .query_row(
                "SELECT desired_body, desired_hash, binding_id, authenticated_peer_id, binding_generation, projection_state, attempted_at_ms FROM n7_fleet_projection_records WHERE generation=?1",
                [document
                    .projection_generation
                    .parse::<u64>()
                    .expect("projection generation is numeric")],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .expect("desired projection must be committed before Fleet apply");
        assert!(!row.0.is_empty(), "canonical desired bytes are durable");
        assert!(
            row.1.starts_with("sha256:"),
            "desired bytes have durable digest"
        );
        assert!(
            !row.2.is_empty() && !row.3.is_empty() && row.4 > 0,
            "exact active N6 provenance is durable"
        );
        assert_eq!(document.provenance.binding_id(), Some(row.2.as_str()));
        assert_eq!(
            document.provenance.authenticated_peer_id(),
            Some(row.3.as_str())
        );
        assert_eq!(row.5, "attempted", "attempted is recorded before apply");
        assert!(row.6 >= 0, "attempt timestamp is durable before apply");
        assert!(
            matches!(
                document.operation,
                ApplyOperation::Upsert | ApplyOperation::Disable | ApplyOperation::Remove
            ),
            "N7 applies only its three canonical projection operations"
        );
    }
}

impl FleetProjectionTransport for ScriptedTransport {
    async fn capabilities(&self) -> Result<Capabilities, FleetClientError> {
        self.events
            .lock()
            .expect("events lock")
            .push(Event::Capabilities);
        Ok(Capabilities {
            kinds: vec![
                nodescale_fleet_client::RequestKind::Capabilities,
                nodescale_fleet_client::RequestKind::Apply,
                nodescale_fleet_client::RequestKind::Inspect,
            ],
        })
    }

    async fn apply(&self, document: ProjectionDocument) -> Result<ApplyResult, ApplyError> {
        self.assert_desired_and_attempted_are_durable_before_apply(&document);
        self.events.lock().expect("events lock").push(Event::Apply);
        *self.last_document.lock().expect("document lock") = Some(document);
        self.apply
            .lock()
            .expect("apply lock")
            .pop_front()
            .expect("test must script apply")
    }

    async fn inspect(&self, _selector: InspectSelector) -> Result<InspectResult, FleetClientError> {
        self.events
            .lock()
            .expect("events lock")
            .push(Event::Inspect);
        match self
            .inspect
            .lock()
            .expect("inspect lock")
            .pop_front()
            .expect("test must script inspection")
        {
            InspectStep::Fixed(result) => *result,
            InspectStep::MatchingLastAppliedDocument => Ok(self.matching_inspection()),
        }
    }
}

#[tokio::test]
async fn desired_bytes_active_n6_provenance_and_attempt_are_committed_before_any_apply() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-before-apply.sqlite");
    let (store, desired) = fixture(&path);
    let transport = ScriptedTransport::new(&path);
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_matching_inspection();

    let service = start_service(store, transport.clone());
    assert_eq!(
        service
            .reconcile(operation("n7-before-apply"), desired)
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );
    assert_eq!(
        transport.events(),
        vec![Event::Capabilities, Event::Apply, Event::Inspect]
    );
    service.shutdown().await.expect("actor shutdown");
}

#[tokio::test]
async fn response_loss_then_restart_inspects_an_exact_match_without_reapplying() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-response-loss.sqlite");
    let (store, desired) = fixture(&path);
    let first = ScriptedTransport::new(&path);
    first.push_apply(Err(ApplyError::Ambiguous));
    first.push_inspect(Ok(InspectResult {
        generated: None,
        effective: None,
    }));
    let service = start_service(store, first.clone());
    assert_eq!(
        service
            .reconcile(operation("n7-response-loss"), desired.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Retryable
    );
    service.shutdown().await.expect("first actor shutdown");

    let observed_after_restart = first.matching_inspection();
    let restarted = ScriptedTransport::new(&path);
    restarted.push_inspect(Ok(observed_after_restart));
    let service = start_service(
        StateStore::open(&path).expect("reopen state"),
        restarted.clone(),
    );
    assert_eq!(
        service
            .reconcile(operation("n7-response-loss"), desired)
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );
    assert_eq!(
        restarted.events(),
        vec![Event::Capabilities, Event::Inspect],
        "a restarted ambiguous operation must inspect authoritative state before any reapply"
    );
    service.shutdown().await.expect("restarted actor shutdown");
}

#[tokio::test]
async fn unavailable_then_authoritative_missing_retries_with_a_new_durable_attempt_and_converges() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-retryable.sqlite");
    let (store, desired) = fixture(&path);
    let transport = ScriptedTransport::new(&path);
    transport.push_apply(Err(ApplyError::Unavailable));
    let service = start_service(store, transport.clone());
    assert_eq!(
        service
            .reconcile(operation("n7-retryable"), desired.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Retryable
    );
    service.shutdown().await.expect("first actor shutdown");

    let retry = ScriptedTransport::new(&path);
    retry.push_inspect(Ok(InspectResult {
        generated: None,
        effective: None,
    }));
    retry.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    retry.push_matching_inspection();
    let service = start_service(
        StateStore::open(&path).expect("reopen state"),
        retry.clone(),
    );
    assert_eq!(
        service
            .reconcile(operation("n7-retryable"), desired)
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );
    assert_eq!(
        retry.events(),
        vec![
            Event::Capabilities,
            Event::Inspect,
            Event::Apply,
            Event::Inspect
        ],
        "only an authoritative Missing after inspection may create the next append-only attempt"
    );
    assert_eq!(
        Connection::open(&path)
            .expect("open durable state")
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_attempts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("attempt count"),
        2,
        "the missing recovery reuses desired bytes through a distinct durable attempt"
    );
    service.shutdown().await.expect("retry actor shutdown");
}

#[tokio::test]
async fn disable_and_remove_converge_after_a_prior_uds_unavailability_only_via_missing_inspection()
{
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-disable-remove-retry.sqlite");
    let (store, desired) = fixture(&path);
    let transport = ScriptedTransport::new(&path);
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_matching_inspection();
    let service = start_service(store, transport.clone());
    assert_eq!(
        service
            .reconcile(operation("n7-retry-upsert"), desired.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );

    let disabled = desired
        .disable(Generation::new(2).expect("generation two"))
        .expect("canonical disabled desired projection");
    transport.push_apply(Err(ApplyError::Unavailable));
    assert_eq!(
        service
            .reconcile(operation("n7-retry-disable"), disabled.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Retryable
    );
    transport.push_inspect(Ok(InspectResult {
        generated: None,
        effective: None,
    }));
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_matching_inspection();
    assert_eq!(
        service
            .reconcile(operation("n7-retry-disable"), disabled.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );

    let removed = disabled
        .remove(Generation::new(3).expect("generation three"))
        .expect("canonical removed desired projection");
    transport.push_apply(Err(ApplyError::Unavailable));
    assert_eq!(
        service
            .reconcile(operation("n7-retry-remove"), removed.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Retryable
    );
    transport.push_inspect(Ok(InspectResult {
        generated: None,
        effective: None,
    }));
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_matching_inspection();
    assert_eq!(
        service
            .reconcile(operation("n7-retry-remove"), removed)
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );
    assert_eq!(
        Connection::open(&path)
            .expect("open durable attempts")
            .query_row(
                "SELECT COUNT(*) FROM n7_fleet_projection_attempts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("attempt count"),
        5,
        "upsert is one attempt; each unavailable disable/remove gets a fresh attempt only after Missing"
    );
    service.shutdown().await.expect("retry actor shutdown");
}

#[tokio::test]
async fn authoritative_mismatch_marks_a_durable_conflict_without_false_applied_evidence() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-conflict-replay.sqlite");
    let (store, desired) = fixture(&path);
    let transport = ScriptedTransport::new(&path);
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_inspect(Ok(InspectResult {
        generated: Some(GeneratedState {
            state: GeneratedStateKind::Active,
            projection_generation: "1".into(),
            membership_generation: "1".into(),
            binding_generation: "1".into(),
            content_hash: "0".repeat(64),
            allowed_operations: vec![GeneratedOperation::Health],
            provenance: Provenance::new("wrong-network", "wrong-device", "1"),
        }),
        effective: None,
    }));
    let service = start_service(store, transport.clone());
    assert_eq!(
        service
            .reconcile(operation("n7-conflict"), desired)
            .await
            .unwrap(),
        N7ProjectionOutcome::Conflict
    );
    assert_eq!(
        Connection::open(&path)
            .expect("open state")
            .query_row(
                "SELECT projection_state FROM n7_fleet_projection_records",
                [],
                |row| row.get::<_, String>(0)
            )
            .expect("projection state"),
        "conflict"
    );
    assert_eq!(
        transport.events(),
        vec![Event::Capabilities, Event::Apply, Event::Inspect]
    );
    service.shutdown().await.expect("actor shutdown");
}

#[tokio::test]
async fn exact_applied_operation_replay_and_shutdown_are_terminal_at_the_actor_boundary() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("n7-replay-shutdown.sqlite");
    let (store, desired) = fixture(&path);
    let transport = ScriptedTransport::new(&path);
    transport.push_apply(Ok(ApplyResult {
        outcome: ApplyOutcome::Applied,
    }));
    transport.push_matching_inspection();
    let service = start_service(store, transport.clone());
    let operation_id = operation("n7-exact-replay");
    assert_eq!(
        service
            .reconcile(operation_id.clone(), desired.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::Applied
    );
    assert_eq!(
        service
            .reconcile(operation_id, desired.clone())
            .await
            .unwrap(),
        N7ProjectionOutcome::AlreadyApplied
    );
    assert_eq!(
        transport.events(),
        vec![Event::Capabilities, Event::Apply, Event::Inspect]
    );
    service.shutdown().await.expect("actor shutdown");
    assert!(matches!(
        service
            .reconcile(operation("n7-after-shutdown"), desired)
            .await,
        Err(N7ProductionError::ActorUnavailable)
    ));
}
