use async_trait::async_trait;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use nodescale_domain::{
    AuditActor, Generation, InvitationId, InvitationToken, JoinConstraints, JoinSessionId, Network,
    NetworkId, ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_invitation::{CreateInvitationRequest, InvitationService, N4AuthorizationIssuer};
use nodescale_provider::{
    CompatibilityStatus, MutationOutcome, MutationPolicyMode, MutationProvider, Provider,
    ProviderError, ProviderHealth, ProviderMutation, ProviderMutationCapability, ReadOnlyProvider,
    ServerInspection,
};
use nodescale_provider_fake::{
    AsyncFakeMutationProvider, FakeMutationAuthorization, FakeMutationScript, FakeProvider,
};
use nodescale_redemption_ingress::{
    AdmissionLimits, JoinBootstrapConfig, WorkerShutdownError, redemption_router,
    spawn_redemption_worker_with_issuer_and_clock,
};
use nodescale_state::{
    HeadscaleImportConfig, N4CleanupTarget, N4CredentialDispatch, ProviderMutationConfiguration,
    StateError, StateStore, TlsVerificationPolicy,
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    future::Future,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::sync::Notify;
use tower::ServiceExt;
use zeroize::Zeroize;

const FINGERPRINT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixed_now() -> DateTime<Utc> {
    "2026-01-01T00:00:00Z".parse().unwrap()
}

struct ImportedProvider(ProviderInstanceId);

#[async_trait]
impl ReadOnlyProvider for ImportedProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.0
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.0,
            compatibility: CompatibilityStatus::Compatible,
            capabilities: BTreeSet::new(),
            constraints: vec![],
            mutation_allowed: false,
        })
    }

    async fn list_nodes(&self) -> Result<Vec<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(vec![])
    }

    async fn get_node(
        &self,
        _: &nodescale_domain::ProviderIdentity,
    ) -> Result<Option<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(None)
    }

    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        unreachable!("not used by this fixture")
    }
}

#[derive(Clone)]
struct SharedProvider(Arc<AsyncFakeMutationProvider>);

#[async_trait]
impl MutationProvider for SharedProvider {
    type Authorization = FakeMutationAuthorization;

    fn instance_id(&self) -> ProviderInstanceId {
        self.0.instance_id()
    }

    async fn execute_mutation(
        &self,
        authorization: Self::Authorization,
        mutation: ProviderMutation,
    ) -> MutationOutcome {
        self.0.execute_mutation(authorization, mutation).await
    }
}

trait FakeAuthorizationTarget: MutationProvider<Authorization = FakeMutationAuthorization> {}

impl FakeAuthorizationTarget for SharedProvider {}

#[derive(Clone)]
struct DelayedProvider {
    inner: SharedProvider,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl FakeAuthorizationTarget for DelayedProvider {}

#[async_trait]
impl MutationProvider for DelayedProvider {
    type Authorization = FakeMutationAuthorization;

    fn instance_id(&self) -> ProviderInstanceId {
        self.inner.instance_id()
    }

    async fn execute_mutation(
        &self,
        authorization: Self::Authorization,
        mutation: ProviderMutation,
    ) -> MutationOutcome {
        self.started.notify_one();
        self.release.notified().await;
        self.inner.execute_mutation(authorization, mutation).await
    }
}

#[derive(Clone, Copy)]
struct FakeIssuer;

impl<P> N4AuthorizationIssuer<P> for FakeIssuer
where
    P: FakeAuthorizationTarget,
{
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, FakeMutationAuthorization), StateError> {
        let dispatch = store.begin_n4_credential_dispatch(join_session_id, now, actor)?;
        let authorization = FakeMutationAuthorization::new(
            dispatch.network_id,
            dispatch.context.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::CreateJoinCredential],
            chrono::Utc::now() + Duration::minutes(1),
        );
        Ok((dispatch, authorization))
    }

    fn issue_invalidation(
        &self,
        _: &StateStore,
        target: &N4CleanupTarget,
        _now: DateTime<Utc>,
    ) -> Result<FakeMutationAuthorization, StateError> {
        Ok(FakeMutationAuthorization::new(
            target.network_id,
            target.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::InvalidateJoinCredential],
            chrono::Utc::now() + Duration::minutes(1),
        ))
    }
}

async fn fixture(path: &Path) -> (StateStore, Network, SharedProvider) {
    let store = StateStore::open(path).unwrap();
    let mut fake = FakeProvider::compatible("n4b-ingress-service-bridge");
    let instance = Provider::instance_id(&fake);
    let network = Network::new(
        NetworkId::new(),
        "n4b-ingress-service-bridge",
        ProviderKind::Headscale,
        instance,
        fixed_now(),
    )
    .unwrap();
    store
        .import_headscale_network(
            &network,
            &HeadscaleImportConfig::new(
                "https://headscale.example.test",
                instance,
                "secret://vault/nodescale#key",
                "v0.29.3",
                TlsVerificationPolicy::Verify,
            )
            .unwrap(),
            &ImportedProvider(instance),
            fixed_now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
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
                fixed_now() - Duration::minutes(1),
                fixed_now() + Duration::hours(1),
                MutationPolicyMode::Database,
                [
                    ProviderMutationCapability::CreateJoinCredential,
                    ProviderMutationCapability::InvalidateJoinCredential,
                ],
            )
            .unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    Provider::ensure_network_principal(&mut fake, "principal-42").unwrap();
    let provider = AsyncFakeMutationProvider::configured(
        fake,
        network.network_id,
        Generation::initial(),
        true,
        MutationPolicyMode::Database,
    );
    (store, network, SharedProvider(Arc::new(provider)))
}

fn create_request(network: &Network) -> CreateInvitationRequest {
    CreateInvitationRequest {
        network_id: network.network_id,
        provider_instance_id: network.provider_instance_id,
        provider_principal_id: "principal-42".into(),
        roles: Roles::new([Role::Worker]).unwrap(),
        admin_intent: None,
        join_constraints: JoinConstraints::default(),
        actor: AuditActor::system(),
    }
}

async fn post(router: axum::Router, token: &str, source: [u8; 4]) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/redemptions")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"invitation_token":"{token}"}}"#)))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((source, 44000))));
    router.oneshot(request).await.unwrap()
}

#[derive(Deserialize)]
struct BootstrapResponse {
    login_server: String,
    auth_key: String,
}

#[tokio::test]
async fn http_redeems_through_invitation_service_once_and_replay_is_redacted() {
    let temporary = tempfile::tempdir().unwrap();
    let state_path = temporary.path().join("state.db");
    let (store, network, provider) = fixture(&state_path).await;
    let issued = {
        let service = InvitationService::new(&store, &provider, &FakeIssuer);
        service
            .create(create_request(&network), fixed_now())
            .unwrap()
    };
    let invitation_id = issued.view().invitation_id;
    let (_, token) = issued.deliver_token(str::to_owned);

    let backend = spawn_redemption_worker_with_issuer_and_clock(
        store,
        provider.clone(),
        FakeIssuer,
        AdmissionLimits::safe_defaults(),
        Arc::new(|| fixed_now() + Duration::seconds(1)),
    )
    .unwrap();
    let router = redemption_router(
        backend,
        AdmissionLimits::safe_defaults(),
        JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
    )
    .unwrap();

    let success = post(router.clone(), &token, [192, 0, 2, 10]).await;
    assert_eq!(
        success.status(),
        StatusCode::OK,
        "dispatches={} trace={:?} invitation={:?}",
        provider.0.mutation_dispatch_count(),
        provider.0.mutation_trace(),
        StateStore::open(&state_path)
            .unwrap()
            .n4_invitation_view(invitation_id)
            .unwrap()
    );
    assert_eq!(success.headers()[header::CACHE_CONTROL], "no-store");
    let mut body = success
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert!(
        !body
            .windows(token.len())
            .any(|window| window == token.as_bytes())
    );
    let mut bootstrap: BootstrapResponse = serde_json::from_slice(&body).unwrap();
    body.zeroize();
    assert_eq!(bootstrap.login_server, "https://headscale.example.test/");
    assert!(!bootstrap.auth_key.is_empty());

    tokio::time::sleep(std::time::Duration::from_millis(1_050)).await;
    let replay = post(router, &token, [192, 0, 2, 11]).await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        r#"{"error":"not_redeemable"}"#
    );
    assert_eq!(provider.0.mutation_dispatch_count(), 1);

    let inspection = StateStore::open(&state_path).unwrap();
    assert_eq!(
        inspection.n4_invitation_view(invitation_id).unwrap().state,
        nodescale_domain::InvitationState::Consumed
    );
    assert_eq!(inspection.device_count(network.network_id).unwrap(), 0);
    assert_eq!(
        inspection.keryx_binding_count(network.network_id).unwrap(),
        0
    );
    assert_eq!(
        inspection
            .fleet_projection_count(network.network_id)
            .unwrap(),
        0
    );
    let dump = inspection.database_text_dump_for_test().unwrap();
    assert!(!dump.contains(&token));
    assert!(!dump.contains(&bootstrap.auth_key));
    assert!(!dump.contains("192.0.2.10"));
    bootstrap.auth_key.zeroize();
}

#[tokio::test]
async fn independent_ingress_workers_create_exactly_one_provider_credential() {
    let temporary = tempfile::tempdir().unwrap();
    let state_path = temporary.path().join("state.db");
    let (store, network, provider) = fixture(&state_path).await;
    let issued = {
        let service = InvitationService::new(&store, &provider, &FakeIssuer);
        service
            .create(create_request(&network), fixed_now())
            .unwrap()
    };
    let invitation_id = issued.view().invitation_id;
    let (_, token) = issued.deliver_token(str::to_owned);
    drop(store);

    let limits = AdmissionLimits::safe_defaults();
    let clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync> =
        Arc::new(|| fixed_now() + Duration::seconds(1));
    let worker_a = spawn_redemption_worker_with_issuer_and_clock(
        StateStore::open(&state_path).unwrap(),
        provider.clone(),
        FakeIssuer,
        limits,
        clock.clone(),
    )
    .unwrap();
    let worker_b = spawn_redemption_worker_with_issuer_and_clock(
        StateStore::open(&state_path).unwrap(),
        provider.clone(),
        FakeIssuer,
        limits,
        clock,
    )
    .unwrap();
    let bootstrap = JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap();
    let router_a = redemption_router(worker_a, limits, bootstrap.clone()).unwrap();
    let router_b = redemption_router(worker_b, limits, bootstrap).unwrap();

    let (response_a, response_b) = tokio::join!(
        post(router_a, &token, [198, 51, 100, 10]),
        post(router_b, &token, [198, 51, 100, 11]),
    );
    let mut responses = [response_a, response_b];
    responses.sort_by_key(|response| response.status());
    assert_eq!(
        responses
            .iter()
            .map(|response| response.status())
            .collect::<Vec<_>>(),
        [StatusCode::OK, StatusCode::CONFLICT]
    );
    for response in responses {
        let status = response.status();
        let mut body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        if status == StatusCode::OK {
            let mut success: BootstrapResponse = serde_json::from_slice(&body).unwrap();
            success.auth_key.zeroize();
        } else {
            assert_eq!(body, br#"{"error":"not_redeemable"}"#);
        }
        body.zeroize();
    }

    assert_eq!(provider.0.mutation_dispatch_count(), 1);
    assert_eq!(
        StateStore::open(&state_path)
            .unwrap()
            .n4_invitation_view(invitation_id)
            .unwrap()
            .state,
        nodescale_domain::InvitationState::Consumed
    );
}

#[tokio::test]
async fn provider_failures_do_not_become_invitation_oracles() {
    for (script, expected_dispatches) in [
        (FakeMutationScript::BeforeSendUnavailable, 0),
        (FakeMutationScript::AfterApplyResponseLoss, 1),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("state.db");
        let (store, network, provider) = fixture(&state_path).await;
        provider
            .0
            .script(ProviderMutationCapability::CreateJoinCredential, script);
        let issued = {
            let service = InvitationService::new(&store, &provider, &FakeIssuer);
            service
                .create(create_request(&network), fixed_now())
                .unwrap()
        };
        let (_, token) = issued.deliver_token(str::to_owned);
        let backend = spawn_redemption_worker_with_issuer_and_clock(
            store,
            provider.clone(),
            FakeIssuer,
            AdmissionLimits::safe_defaults(),
            Arc::new(|| fixed_now() + Duration::seconds(1)),
        )
        .unwrap();
        let router = redemption_router(
            backend,
            AdmissionLimits::safe_defaults(),
            JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
        )
        .unwrap();

        let response = post(router, &token, [203, 0, 113, 20]).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            r#"{"error":"not_redeemable"}"#
        );
        assert_eq!(provider.0.mutation_dispatch_count(), expected_dispatches);
        let dump = StateStore::open(&state_path)
            .unwrap()
            .database_text_dump_for_test()
            .unwrap();
        assert!(!dump.contains(&token));
    }
}

#[tokio::test]
async fn unknown_token_flood_is_bounded_by_the_worker_queue() {
    let temporary = tempfile::tempdir().unwrap();
    let state_path = temporary.path().join("state.db");
    let (store, _, provider) = fixture(&state_path).await;
    let limits = AdmissionLimits::safe_defaults();
    let backend = spawn_redemption_worker_with_issuer_and_clock(
        store,
        provider.clone(),
        FakeIssuer,
        limits,
        Arc::new(|| fixed_now() + Duration::seconds(1)),
    )
    .unwrap();
    let bootstrap = JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap();
    let routers = [
        redemption_router(backend.clone(), limits, bootstrap.clone()).unwrap(),
        redemption_router(backend.clone(), limits, bootstrap.clone()).unwrap(),
        redemption_router(backend.clone(), limits, bootstrap.clone()).unwrap(),
        redemption_router(backend, limits, bootstrap).unwrap(),
    ];
    let tokens = [
        InvitationToken::generate(InvitationId::new()).expose_for_delivery(str::to_owned),
        InvitationToken::generate(InvitationId::new()).expose_for_delivery(str::to_owned),
        InvitationToken::generate(InvitationId::new()).expose_for_delivery(str::to_owned),
        InvitationToken::generate(InvitationId::new()).expose_for_delivery(str::to_owned),
    ];

    let (a, b, c, d) = tokio::join!(
        post(routers[0].clone(), &tokens[0], [203, 0, 113, 31]),
        post(routers[1].clone(), &tokens[1], [203, 0, 113, 32]),
        post(routers[2].clone(), &tokens[2], [203, 0, 113, 33]),
        post(routers[3].clone(), &tokens[3], [203, 0, 113, 34]),
    );
    let statuses = [a.status(), b.status(), c.status(), d.status()];
    assert!(statuses.contains(&StatusCode::SERVICE_UNAVAILABLE));
    assert!(statuses.iter().all(|status| matches!(
        *status,
        StatusCode::CONFLICT | StatusCode::SERVICE_UNAVAILABLE
    )));
    assert_eq!(provider.0.mutation_dispatch_count(), 0);
}

#[tokio::test]
async fn dropped_completed_handoff_is_revoked_and_worker_shuts_down() {
    let temporary = tempfile::tempdir().unwrap();
    let state_path = temporary.path().join("state.db");
    let (store, network, provider) = fixture(&state_path).await;
    let issued = InvitationService::new(&store, &provider, &FakeIssuer)
        .create(create_request(&network), fixed_now())
        .unwrap();
    let invitation_id = issued.view().invitation_id;
    let (_, token) = issued.deliver_token(str::to_owned);

    let worker = spawn_redemption_worker_with_issuer_and_clock(
        store,
        provider.clone(),
        FakeIssuer,
        AdmissionLimits::safe_defaults(),
        Arc::new(|| fixed_now() + Duration::seconds(1)),
    )
    .unwrap();
    let router = redemption_router(
        Arc::clone(&worker),
        AdmissionLimits::safe_defaults(),
        JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/redemptions")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"invitation_token":"{token}"}}"#)))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 50], 44000))));
    let mut response = Box::pin(router.oneshot(request));
    let waker = Waker::noop();
    assert!(matches!(
        Pin::new(&mut response).poll(&mut Context::from_waker(waker)),
        Poll::Pending
    ));

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if worker.pending_handoffs() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        worker.shutdown_timeout(std::time::Duration::from_millis(20)),
        Err(WorkerShutdownError::TimedOut)
    );
    drop(response);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if StateStore::open(&state_path)
                .unwrap()
                .n4_invitation_view(invitation_id)
                .unwrap()
                .state
                == nodescale_domain::InvitationState::Revoked
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(provider.0.mutation_dispatch_count(), 2);
    worker
        .shutdown_timeout(std::time::Duration::from_secs(2))
        .unwrap();
}

#[tokio::test]
async fn shutdown_deadline_preserves_in_flight_provider_work_then_joins() {
    let temporary = tempfile::tempdir().unwrap();
    let state_path = temporary.path().join("state.db");
    let (store, network, provider) = fixture(&state_path).await;
    let issued = InvitationService::new(&store, &provider, &FakeIssuer)
        .create(create_request(&network), fixed_now())
        .unwrap();
    let (_, token) = issued.deliver_token(str::to_owned);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let delayed = DelayedProvider {
        inner: provider.clone(),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    };
    let worker = spawn_redemption_worker_with_issuer_and_clock(
        store,
        delayed,
        FakeIssuer,
        AdmissionLimits::safe_defaults(),
        Arc::new(|| fixed_now() + Duration::seconds(1)),
    )
    .unwrap();
    let router = redemption_router(
        Arc::clone(&worker),
        AdmissionLimits::safe_defaults(),
        JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
    )
    .unwrap();
    let request = tokio::spawn(async move { post(router, &token, [192, 0, 2, 51]).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .unwrap();

    assert_eq!(
        worker.shutdown_timeout(std::time::Duration::from_millis(20)),
        Err(WorkerShutdownError::TimedOut)
    );
    release.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    worker
        .shutdown_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(provider.0.mutation_dispatch_count(), 1);
}
