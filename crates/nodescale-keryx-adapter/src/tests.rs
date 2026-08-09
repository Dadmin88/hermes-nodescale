use std::sync::{Arc, Mutex};

use crate::{
    AdapterConstructionError, BindOutcome, ChallengeOutcome, ControlPlaneError,
    NodescaleIdentityControlPlane, RawAuthenticatedDirectContext, RejectionCode,
    TryNodescaleKeryxAdapter,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use keryx_proto::v1::{
    NodescaleIdentityBindDisposition, NodescaleIdentityBindV1,
    NodescaleIdentityChallengeDisposition, NodescaleIdentityChallengeV1,
};
use nodescale_domain::{
    BindingNonce, Generation, KeryxBindingChallengeId, KeryxBindingId, N6BindingChallengeDelivery,
};

const NETWORK_ID: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";
const SESSION_ID: &str = "33333333-3333-4333-8333-333333333333";

#[derive(Clone)]
enum ChallengeReply {
    Issued,
    Rejected(RejectionCode),
    Error,
}

#[derive(Clone)]
enum BindReply {
    Active,
    AlreadyConfirmed,
    Rejected(RejectionCode),
    Error,
}

struct MockControlPlane {
    challenge_reply: ChallengeReply,
    bind_reply: BindReply,
    seen_challenge_sources: Mutex<Vec<String>>,
    seen_bind_sources: Mutex<Vec<String>>,
}

impl MockControlPlane {
    fn new(challenge_reply: ChallengeReply, bind_reply: BindReply) -> Self {
        Self {
            challenge_reply,
            bind_reply,
            seen_challenge_sources: Mutex::new(Vec::new()),
            seen_bind_sources: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl NodescaleIdentityControlPlane for MockControlPlane {
    async fn issue_challenge(
        &self,
        request: crate::ChallengeRequest,
    ) -> Result<ChallengeOutcome, ControlPlaneError> {
        self.seen_challenge_sources.lock().unwrap().push(
            request
                .provenance()
                .authenticated_peer_id()
                .as_str()
                .to_owned(),
        );
        match self.challenge_reply {
            ChallengeReply::Issued => Ok(ChallengeOutcome::issued(
                N6BindingChallengeDelivery::new(
                    KeryxBindingChallengeId::new(),
                    KeryxBindingId::new(),
                    Generation::initial(),
                    BindingNonce::generate(),
                    Utc::now() + Duration::minutes(5),
                    Utc::now(),
                )
                .unwrap(),
            )),
            ChallengeReply::Rejected(code) => Ok(ChallengeOutcome::rejected(code)),
            ChallengeReply::Error => Err(ControlPlaneError::new()),
        }
    }

    async fn bind_authenticated_peer(
        &self,
        request: crate::AuthenticatedBindRequest,
    ) -> Result<BindOutcome, ControlPlaneError> {
        self.seen_bind_sources.lock().unwrap().push(
            request
                .provenance()
                .authenticated_peer_id()
                .as_str()
                .to_owned(),
        );
        match self.bind_reply {
            BindReply::Active => Ok(BindOutcome::active(
                KeryxBindingId::new(),
                Generation::initial(),
                7,
            )),
            BindReply::AlreadyConfirmed => Ok(BindOutcome::already_confirmed(
                KeryxBindingId::new(),
                Generation::initial(),
                7,
            )),
            BindReply::Rejected(code) => Ok(BindOutcome::rejected(code)),
            BindReply::Error => Err(ControlPlaneError::new()),
        }
    }
}

fn context() -> RawAuthenticatedDirectContext {
    RawAuthenticatedDirectContext::new("authenticated-peer", "destination-node", "frame-1")
}

fn challenge() -> NodescaleIdentityChallengeV1 {
    NodescaleIdentityChallengeV1 {
        operation_id: "challenge-1".into(),
        network_id: NETWORK_ID.into(),
        device_id: DEVICE_ID.into(),
        join_session_id: SESSION_ID.into(),
        agent_version: "nodescale-agent:6.0.0".into(),
    }
}

fn bind() -> NodescaleIdentityBindV1 {
    NodescaleIdentityBindV1 {
        operation_id: "bind-1".into(),
        network_id: NETWORK_ID.into(),
        device_id: DEVICE_ID.into(),
        join_session_id: SESSION_ID.into(),
        binding_nonce: BindingNonce::generate().with_encoded(str::to_owned),
        binding_generation: 1,
        agent_version: "nodescale-agent:6.0.0".into(),
    }
}

#[tokio::test]
async fn issued_challenge_uses_authenticated_source_and_only_issued_returns_a_secret() {
    let control_plane = Arc::new(MockControlPlane::new(
        ChallengeReply::Issued,
        BindReply::Active,
    ));
    let adapter = TryNodescaleKeryxAdapter::new(control_plane.clone()).unwrap();

    let result = adapter
        .handle_challenge_for_test(context(), challenge())
        .await;

    assert_eq!(
        result.disposition,
        NodescaleIdentityChallengeDisposition::Issued as i32
    );
    assert!(result.accepted);
    assert!(result.challenge_secret.starts_with("nsbind_"));
    assert_eq!(
        control_plane
            .seen_challenge_sources
            .lock()
            .unwrap()
            .as_slice(),
        ["authenticated-peer"]
    );
}

#[tokio::test]
async fn duplicate_or_rejected_challenge_never_returns_a_secret() {
    for code in [RejectionCode::Duplicate, RejectionCode::Rejected] {
        let adapter = TryNodescaleKeryxAdapter::new(Arc::new(MockControlPlane::new(
            ChallengeReply::Rejected(code),
            BindReply::Active,
        )))
        .unwrap();

        let result = adapter
            .handle_challenge_for_test(context(), challenge())
            .await;

        assert_eq!(
            result.disposition,
            NodescaleIdentityChallengeDisposition::Rejected as i32
        );
        assert!(!result.accepted);
        assert_eq!(result.challenge_secret, "");
        assert_eq!(result.challenge_id, "");
        assert_eq!(result.code, code.as_str());
    }
}

#[tokio::test]
async fn bind_maps_active_already_confirmed_and_rejected_exactly() {
    for (reply, expected_disposition, expected_accepted, expected_code) in [
        (
            BindReply::Active,
            NodescaleIdentityBindDisposition::Active,
            true,
            "",
        ),
        (
            BindReply::AlreadyConfirmed,
            NodescaleIdentityBindDisposition::AlreadyConfirmed,
            true,
            "",
        ),
        (
            BindReply::Rejected(RejectionCode::Rejected),
            NodescaleIdentityBindDisposition::Rejected,
            false,
            "rejected",
        ),
    ] {
        let control_plane = Arc::new(MockControlPlane::new(ChallengeReply::Issued, reply));
        let adapter = TryNodescaleKeryxAdapter::new(control_plane.clone()).unwrap();

        let result = adapter.handle_bind_for_test(context(), bind()).await;

        assert_eq!(result.disposition, expected_disposition as i32);
        assert_eq!(result.accepted, expected_accepted);
        assert_eq!(result.code, expected_code);
        assert_eq!(
            control_plane.seen_bind_sources.lock().unwrap().as_slice(),
            ["authenticated-peer"]
        );
    }
}

#[tokio::test]
async fn absent_authenticated_source_is_rejected_before_the_control_plane() {
    let control_plane = Arc::new(MockControlPlane::new(
        ChallengeReply::Issued,
        BindReply::Active,
    ));
    let adapter = TryNodescaleKeryxAdapter::new(control_plane.clone()).unwrap();

    let result = adapter
        .handle_challenge_for_test(
            RawAuthenticatedDirectContext::new("", "destination-node", "frame-1"),
            challenge(),
        )
        .await;

    assert_eq!(
        result.disposition,
        NodescaleIdentityChallengeDisposition::Rejected as i32
    );
    assert!(!result.accepted);
    assert_eq!(result.code, "invalid_request");
    assert_eq!(result.challenge_secret, "");
    assert!(
        control_plane
            .seen_challenge_sources
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn failures_are_redacted_and_secret_free() {
    let adapter = TryNodescaleKeryxAdapter::new(Arc::new(MockControlPlane::new(
        ChallengeReply::Error,
        BindReply::Error,
    )))
    .unwrap();

    let challenge_result = adapter
        .handle_challenge_for_test(context(), challenge())
        .await;
    assert_eq!(
        challenge_result.disposition,
        NodescaleIdentityChallengeDisposition::Rejected as i32
    );
    assert_eq!(challenge_result.code, "control_plane_error");
    assert_eq!(challenge_result.reason, "request could not be completed");
    assert_eq!(challenge_result.challenge_secret, "");
    assert!(!format!("{challenge_result:?}").contains("synthetic"));

    let bind_result = adapter.handle_bind_for_test(context(), bind()).await;
    assert_eq!(
        bind_result.disposition,
        NodescaleIdentityBindDisposition::Rejected as i32
    );
    assert_eq!(bind_result.code, "control_plane_error");
    assert_eq!(bind_result.reason, "request could not be completed");
    assert_eq!(bind_result.binding_id, "");
}

struct InvalidControlPlane;

#[async_trait]
impl NodescaleIdentityControlPlane for InvalidControlPlane {
    fn validate_configuration(&self) -> Result<(), AdapterConstructionError> {
        Err(AdapterConstructionError::invalid_configuration())
    }

    async fn issue_challenge(
        &self,
        _request: crate::ChallengeRequest,
    ) -> Result<ChallengeOutcome, ControlPlaneError> {
        unreachable!()
    }

    async fn bind_authenticated_peer(
        &self,
        _request: crate::AuthenticatedBindRequest,
    ) -> Result<BindOutcome, ControlPlaneError> {
        unreachable!()
    }
}

#[test]
fn handlers_are_only_available_after_successful_construction() {
    assert!(TryNodescaleKeryxAdapter::new(Arc::new(InvalidControlPlane)).is_err());
    let adapter = TryNodescaleKeryxAdapter::new(Arc::new(MockControlPlane::new(
        ChallengeReply::Issued,
        BindReply::Active,
    )))
    .unwrap();
    let handlers = adapter.direct_control_handlers();
    assert!(handlers.has_nodescale_identity_challenge_handler());
    assert!(handlers.has_nodescale_identity_bind_handler());
}
