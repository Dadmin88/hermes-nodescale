use async_trait::async_trait;
use axum::{
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use nodescale_domain::{InvitationId, InvitationToken};
use nodescale_redemption_ingress::{
    AdmissionLimits, JoinBootstrapConfig, RedemptionAttempt, RedemptionBackend, RedemptionFailure,
    RedemptionHandoff, redemption_router,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

#[derive(Default)]
struct RejectingBackend {
    sources: Mutex<Vec<IpAddr>>,
}

#[async_trait]
impl RedemptionBackend for RejectingBackend {
    async fn redeem(
        &self,
        attempt: RedemptionAttempt,
    ) -> Result<RedemptionHandoff, RedemptionFailure> {
        self.sources.lock().unwrap().push(attempt.source());
        Err(RedemptionFailure::NotRedeemable)
    }
}

struct UnavailableBackend;

#[async_trait]
impl RedemptionBackend for UnavailableBackend {
    async fn redeem(&self, _: RedemptionAttempt) -> Result<RedemptionHandoff, RedemptionFailure> {
        Err(RedemptionFailure::Unavailable)
    }
}

fn canonical_token() -> String {
    InvitationToken::generate(InvitationId::new()).expose_for_delivery(str::to_owned)
}

fn router(backend: Arc<RejectingBackend>) -> axum::Router {
    redemption_router(
        backend,
        AdmissionLimits::safe_defaults(),
        JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
    )
    .unwrap()
    .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 10], 44000))))
}

async fn response(
    router: axum::Router,
    body: String,
    content_type: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("POST").uri("/v1/redemptions");
    if let Some(value) = content_type {
        builder = builder.header(header::CONTENT_TYPE, value);
    }
    router
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn malformed_unknown_oversized_and_wrong_content_type_never_reach_backend() {
    for (body, content_type) in [
        (
            r#"{"invitation_token":"bad"}"#.to_owned(),
            Some("application/json"),
        ),
        (
            format!(
                r#"{{"invitation_token":"{}","network_id":"forbidden"}}"#,
                canonical_token()
            ),
            Some("application/json"),
        ),
        ("x".repeat(257), Some("application/json")),
        (
            format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
            Some("text/plain"),
        ),
    ] {
        let backend = Arc::new(RejectingBackend::default());
        let response = response(router(Arc::clone(&backend)), body, content_type).await;
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
        ));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(backend.sources.lock().unwrap().is_empty());
        assert_eq!(body_text(response).await, r#"{"error":"invalid_request"}"#);
    }
}

#[tokio::test]
async fn forwarded_headers_are_ignored_and_token_state_is_not_exposed() {
    let backend = Arc::new(RejectingBackend::default());
    let token = canonical_token();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/redemptions")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.77")
        .body(Body::from(format!(r#"{{"invitation_token":"{token}"}}"#)))
        .unwrap();
    let response = router(Arc::clone(&backend)).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_text(response).await, r#"{"error":"not_redeemable"}"#);
    assert_eq!(
        backend.sources.lock().unwrap().as_slice(),
        &["192.0.2.10"
            .parse::<IpAddr>()
            .expect("fixed peer IP is valid"),]
    );
}

#[tokio::test]
async fn source_limit_is_charged_before_backend_and_recovers_only_by_refill() {
    let backend = Arc::new(RejectingBackend::default());
    let router = router(Arc::clone(&backend));

    let first = response(
        router.clone(),
        format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
        Some("application/json"),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CONFLICT);

    let second = response(
        router,
        format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
        Some("application/json"),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(
        body_text(second).await,
        r#"{"error":"temporarily_unavailable"}"#
    );
    assert_eq!(backend.sources.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn wrong_content_type_is_charged_before_envelope_rejection() {
    let backend = Arc::new(RejectingBackend::default());
    let router = router(Arc::clone(&backend));

    let malformed = response(
        router.clone(),
        format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
        Some("text/plain"),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    let admitted_again = response(
        router,
        format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
        Some("application/json"),
    )
    .await;
    assert_eq!(admitted_again.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(backend.sources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unavailable_worker_returns_only_a_fixed_retryable_response() {
    let router = redemption_router(
        Arc::new(UnavailableBackend),
        AdmissionLimits::safe_defaults(),
        JoinBootstrapConfig::new("https://headscale.example.test", None).unwrap(),
    )
    .unwrap()
    .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 20], 44000))));
    let response = response(
        router,
        format!(r#"{{"invitation_token":"{}"}}"#, canonical_token()),
        Some("application/json"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_text(response).await,
        r#"{"error":"temporarily_unavailable"}"#
    );
}
