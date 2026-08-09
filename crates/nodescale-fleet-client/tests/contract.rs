use std::path::PathBuf;

use nodescale_fleet_client::{
    ApplyError, ApplyOperation, ApplyOutcome, FleetClient, FleetClientError, GeneratedOperation,
    GeneratedState, GeneratedStateKind, InspectSelector, ProjectionDocument, ProjectionGenerations,
    Provenance,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nodescale-fleet-client-{name}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ))
}

fn document() -> ProjectionDocument {
    ProjectionDocument::new(
        "net-a",
        "device-a",
        ProjectionGenerations::new("7", "7", "7"),
        ApplyOperation::Upsert,
        vec![GeneratedOperation::Inventory, GeneratedOperation::Health],
        Provenance::new("net-a", "device-a", "7"),
    )
}

async fn read_frame(stream: &mut tokio::net::UnixStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.expect("frame header");
    let mut payload = vec![0_u8; u32::from_be_bytes(header) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .expect("frame payload");
    payload
}

/// Fleet does not dispatch until the one request frame is followed by EOF.
async fn read_request_after_client_half_close(stream: &mut tokio::net::UnixStream) -> Vec<u8> {
    let payload = read_frame(stream).await;
    let mut trailing = Vec::new();
    stream
        .read_to_end(&mut trailing)
        .await
        .expect("client write-half-close");
    assert!(trailing.is_empty(), "exactly one request frame");
    payload
}

async fn write_frame(stream: &mut tokio::net::UnixStream, document: &str) {
    let payload = document.as_bytes();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("response header");
    stream.write_all(payload).await.expect("response body");
}

#[tokio::test]
async fn capabilities_uses_the_current_v1_kinds_result() {
    let path = socket_path("capabilities");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        assert_eq!(
            read_request_after_client_half_close(&mut stream).await,
            br#"{"schema":"fleet.managed-projection.v1","kind":"capabilities"}"#
        );
        write_frame(
            &mut stream,
            r#"{"schema":"fleet.managed-projection.v1","kind":"capabilities","ok":true,"result":{"kinds":["capabilities","apply","inspect"]}}"#,
        )
        .await;
    });

    let result = FleetClient::new(&path)
        .capabilities()
        .await
        .expect("result");
    server.await.expect("server task");
    std::fs::remove_file(&path).expect("remove socket");

    assert_eq!(
        result.kinds,
        vec![
            nodescale_fleet_client::RequestKind::Capabilities,
            nodescale_fleet_client::RequestKind::Apply,
            nodescale_fleet_client::RequestKind::Inspect,
        ]
    );
}

#[tokio::test]
async fn apply_uses_the_exact_fleet_document_and_outcomes() {
    let path = socket_path("apply");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        assert_eq!(
            read_request_after_client_half_close(&mut stream).await,
            br#"{"schema":"fleet.managed-projection.v1","kind":"apply","document":{"source":"nodescale","network_id":"net-a","device_id":"device-a","projection_generation":"7","membership_generation":"7","binding_generation":"7","content_hash":"8f761b53a7bdba5def68a82521c5900c8566d26b19469203108ffc67cde6ab61","operation":"upsert","generated_operations":["fleet.health","fleet.inventory"],"provenance":{"source":"nodescale","network_id":"net-a","device_id":"device-a","snapshot":"7"}}}"#
        );
        write_frame(
            &mut stream,
            r#"{"schema":"fleet.managed-projection.v1","kind":"apply","ok":true,"result":{"outcome":"already_applied"}}"#,
        )
        .await;
    });

    let result = FleetClient::new(&path)
        .apply(document())
        .await
        .expect("apply result");
    server.await.expect("server task");
    std::fs::remove_file(&path).expect("remove socket");

    assert_eq!(result.outcome, ApplyOutcome::AlreadyApplied);
}

#[test]
fn all_current_fleet_apply_outcomes_decode_exactly() {
    use nodescale_fleet_client::{ApplyOutcome, ApplyResult};

    let cases = [
        ("applied", ApplyOutcome::Applied),
        ("already_applied", ApplyOutcome::AlreadyApplied),
        ("stale", ApplyOutcome::Stale),
        ("gap", ApplyOutcome::Gap),
        ("conflict", ApplyOutcome::Conflict),
    ];
    for (wire_outcome, expected) in cases {
        let result: ApplyResult =
            serde_json::from_str(&format!(r#"{{"outcome":"{wire_outcome}"}}"#))
                .expect("current Fleet outcome");
        assert_eq!(result.outcome, expected);
    }
}

#[test]
fn canonical_content_hash_matches_fleet_python_preimage_and_ascii_json() {
    let document = document();
    assert_eq!(
        document.canonical_content_hash(),
        "8f761b53a7bdba5def68a82521c5900c8566d26b19469203108ffc67cde6ab61"
    );
    assert_eq!(document.content_hash, document.canonical_content_hash());
    assert_eq!(
        nodescale_fleet_client::canonical_content_hash(&document),
        document.canonical_content_hash()
    );

    let unicode = ProjectionDocument::new(
        "nét😀",
        "device-a",
        ProjectionGenerations::new("7", "7", "7"),
        ApplyOperation::Upsert,
        vec![GeneratedOperation::Health, GeneratedOperation::Inventory],
        Provenance::new("nét😀", "device-a", "7"),
    );
    assert_eq!(
        unicode.canonical_content_hash(),
        "eac86d353bfeccc60d37e0a2d5da7b56cf91a10d4b928b67442128e0d9d7ee26"
    );
}

#[tokio::test]
async fn inspect_sends_the_full_selector_and_decodes_authoritative_generated_and_effective_state() {
    let path = socket_path("inspect");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        assert_eq!(
            read_request_after_client_half_close(&mut stream).await,
            br#"{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{"source":"nodescale","network_id":"net-a","device_id":"device-a"}}"#
        );
        write_frame(
            &mut stream,
            r#"{"schema":"fleet.managed-projection.v1","kind":"inspect","ok":true,"result":{"generated":{"state":"active","projection_generation":"7","membership_generation":"7","binding_generation":"7","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_operations":["fleet.health","fleet.inventory"],"provenance":{"source":"nodescale","network_id":"net-a","device_id":"device-a","snapshot":"7"}},"effective":{"state":"active","allowed_operations":["fleet.inventory"],"operator_denied_operations":["fleet.health"]}}}"#,
        )
        .await;
    });

    let result = FleetClient::new(&path)
        .inspect(InspectSelector::new("net-a", "device-a"))
        .await
        .expect("read-back result");
    server.await.expect("server task");
    std::fs::remove_file(&path).expect("remove socket");

    assert_eq!(
        result.generated,
        Some(GeneratedState {
            state: GeneratedStateKind::Active,
            projection_generation: "7".to_owned(),
            membership_generation: "7".to_owned(),
            binding_generation: "7".to_owned(),
            content_hash: "a".repeat(64),
            allowed_operations: vec![GeneratedOperation::Health, GeneratedOperation::Inventory],
            provenance: Provenance::new("net-a", "device-a", "7"),
        })
    );
    assert_eq!(
        result
            .effective
            .expect("effective state")
            .operator_denied_operations,
        vec![GeneratedOperation::Health]
    );
}

#[tokio::test]
#[ignore = "requires NODESCALE_FLEET_CLIENT_LIVE_SOCKET for a disposable real Fleet service"]
async fn real_fleet_dispatches_capabilities_apply_and_inspect_after_client_half_close() {
    let socket = std::env::var_os("NODESCALE_FLEET_CLIENT_LIVE_SOCKET")
        .map(PathBuf::from)
        .expect("live Fleet socket path");
    let client = FleetClient::new(&socket);

    let capabilities = client
        .capabilities()
        .await
        .expect("real Fleet capabilities");
    assert_eq!(
        capabilities.kinds,
        vec![
            nodescale_fleet_client::RequestKind::Capabilities,
            nodescale_fleet_client::RequestKind::Apply,
            nodescale_fleet_client::RequestKind::Inspect,
        ]
    );

    let apply = client.apply(document()).await.expect("real Fleet apply");
    assert_eq!(apply.outcome, ApplyOutcome::Applied);

    let inspected = client
        .inspect(InspectSelector::new("net-a", "device-a"))
        .await
        .expect("real Fleet inspect");
    assert_eq!(
        inspected.generated.expect("durable generated state").state,
        GeneratedStateKind::Active
    );
}

#[tokio::test]
async fn fleet_invalid_request_response_is_a_typed_protocol_rejection_not_ambiguous() {
    let path = socket_path("rejection");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let _ = read_request_after_client_half_close(&mut stream).await;
        write_frame(
            &mut stream,
            r#"{"schema":"fleet.managed-projection.v1","kind":"error","ok":false,"error":"invalid_request"}"#,
        )
        .await;
    });

    let error = FleetClient::new(&path)
        .apply(document())
        .await
        .expect_err("Fleet declared the request invalid");
    server.await.expect("server task");
    std::fs::remove_file(&path).expect("remove socket");

    assert_eq!(error, ApplyError::ProtocolRejected);
}

#[tokio::test]
async fn apply_distinguishes_presend_unavailable_from_postsend_half_close_response_loss() {
    let unavailable = FleetClient::new(socket_path("unavailable"))
        .apply(document())
        .await
        .expect_err("no server is unavailable before send");
    assert_eq!(unavailable, ApplyError::Unavailable);

    let path = socket_path("ambiguous");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let _ = read_request_after_client_half_close(&mut stream).await;
        stream.shutdown().await.expect("drop response");
    });

    let error = FleetClient::new(&path)
        .apply(document())
        .await
        .expect_err("response loss is not a safe failed apply");
    server.await.expect("server task");
    std::fs::remove_file(&path).expect("remove socket");
    assert_eq!(error, ApplyError::Ambiguous);
}

#[tokio::test]
async fn read_only_requests_report_response_loss_after_the_client_half_closes() {
    let capabilities_path = socket_path("capabilities-response-loss");
    let capabilities_listener = UnixListener::bind(&capabilities_path).expect("bind test socket");
    let capabilities_server = tokio::spawn(async move {
        let (mut stream, _) = capabilities_listener.accept().await.expect("accept client");
        let _ = read_request_after_client_half_close(&mut stream).await;
        stream.shutdown().await.expect("drop response");
    });

    let capabilities_error = FleetClient::new(&capabilities_path)
        .capabilities()
        .await
        .expect_err("read-only response loss is safe to report");
    capabilities_server.await.expect("server task");
    std::fs::remove_file(&capabilities_path).expect("remove socket");
    assert_eq!(capabilities_error, FleetClientError::ResponseLost);

    let inspect_path = socket_path("inspect-response-loss");
    let inspect_listener = UnixListener::bind(&inspect_path).expect("bind test socket");
    let inspect_server = tokio::spawn(async move {
        let (mut stream, _) = inspect_listener.accept().await.expect("accept client");
        let _ = read_request_after_client_half_close(&mut stream).await;
        stream.shutdown().await.expect("drop response");
    });

    let inspect_error = FleetClient::new(&inspect_path)
        .inspect(InspectSelector::new("net-a", "device-a"))
        .await
        .expect_err("read-only response loss is safe to report");
    inspect_server.await.expect("server task");
    std::fs::remove_file(&inspect_path).expect("remove socket");
    assert_eq!(inspect_error, FleetClientError::ResponseLost);
}

#[tokio::test]
async fn apply_rejects_an_oversize_frame_before_connecting() {
    let path = socket_path("oversize");
    let document = ProjectionDocument::new(
        "x".repeat(nodescale_fleet_client::MAX_FRAME_BYTES),
        "device-a",
        ProjectionGenerations::new("7", "7", "7"),
        ApplyOperation::Upsert,
        Vec::new(),
        Provenance::new("net-a", "device-a", "7"),
    );
    let error = FleetClient::new(&path)
        .apply(document)
        .await
        .expect_err("oversize request must not be sent");

    assert_eq!(error, ApplyError::RejectedBeforeSend);
}
