use std::{env, error::Error, net::IpAddr, path::PathBuf};

use keryx_proto::v1::{
    NodescaleIdentityBindDisposition, NodescaleIdentityBindV2,
    NodescaleIdentityChallengeDisposition, NodescaleIdentityChallengeV2,
    PublishNodescaleIdentityBindV2Request, PublishNodescaleIdentityChallengeV2Request,
    keryx_relay_client::KeryxRelayClient,
};
use serde_json::json;
use tonic::{
    Request,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

const NODE_ID_METADATA_KEY: &str = "x-keryx-node-id";
const NODE_TOKEN_METADATA_KEY: &str = "x-keryx-node-token";

struct Args {
    target_node_id: String,
    network_id: String,
    device_id: String,
    provider_binding_id: String,
    operation_prefix: String,
    agent_version: String,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut values = std::collections::BTreeMap::new();
    let mut args = env::args().skip(1);
    while let Some(key) = args.next() {
        let value = args.next().ok_or("missing argument value")?;
        values.insert(key, value);
    }
    let mut take = |key: &str| values.remove(key).ok_or_else(|| format!("missing {key}"));
    let parsed = Args {
        target_node_id: take("--target-node-id")?,
        network_id: take("--network-id")?,
        device_id: take("--device-id")?,
        provider_binding_id: take("--provider-binding-id")?,
        operation_prefix: take("--operation-prefix")?,
        agent_version: take("--agent-version")?,
    };
    if !values.is_empty() {
        return Err("unknown arguments".into());
    }
    Ok(parsed)
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{name} is empty").into());
    }
    Ok(value.to_owned())
}

fn authenticated_request<T>(
    value: T,
    node_id: &str,
    node_token: &str,
) -> Result<Request<T>, Box<dyn Error>> {
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        NODE_ID_METADATA_KEY,
        MetadataValue::try_from(node_id.to_owned())?,
    );
    request.metadata_mut().insert(
        NODE_TOKEN_METADATA_KEY,
        MetadataValue::try_from(node_token.to_owned())?,
    );
    Ok(request)
}

async fn relay_channel(endpoint: &str) -> Result<Channel, Box<dyn Error>> {
    let mut builder = Endpoint::from_shared(endpoint.to_owned())?;
    let uri = builder.uri();
    let host = uri.host().ok_or("relay endpoint must include a host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    let secure = uri.scheme_str() == Some("https");
    if !secure && !loopback {
        return Err("remote relay endpoint requires TLS".into());
    }
    if secure {
        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(path) = env::var_os("HERMES_KERYX_REGISTRY_CA_CERT").map(PathBuf::from) {
            tls = tls.ca_certificate(Certificate::from_pem(std::fs::read(path)?));
        }
        builder = builder.tls_config(tls)?;
    }
    Ok(builder.connect().await?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let endpoint = required_env("HERMES_KERYX_RELAY_ENDPOINT")?;
    let node_id = required_env("HERMES_KERYX_NODE_PEER_ID")?;
    let node_token = required_env("HERMES_KERYX_NODE_TOKEN")?;
    let mut client = KeryxRelayClient::new(relay_channel(&endpoint).await?);

    let challenge_operation_id = format!("{}-challenge", args.operation_prefix);
    let challenge = authenticated_request(
        PublishNodescaleIdentityChallengeV2Request {
            target_node_id: args.target_node_id.clone(),
            operation: Some(NodescaleIdentityChallengeV2 {
                operation_id: challenge_operation_id,
                network_id: args.network_id.clone(),
                device_id: args.device_id.clone(),
                provider_binding_id: args.provider_binding_id.clone(),
                agent_version: args.agent_version.clone(),
            }),
        },
        &node_id,
        &node_token,
    )?;
    let challenge = client
        .publish_nodescale_identity_challenge_v2(challenge)
        .await?
        .into_inner()
        .result
        .ok_or("challenge result missing")?;
    if challenge.disposition != NodescaleIdentityChallengeDisposition::Issued as i32
        || !challenge.accepted
        || challenge.challenge_id.is_empty()
        || challenge.challenge_secret.is_empty()
    {
        return Err(format!("challenge rejected: {}", challenge.code).into());
    }

    let bind = authenticated_request(
        PublishNodescaleIdentityBindV2Request {
            target_node_id: args.target_node_id,
            operation: Some(NodescaleIdentityBindV2 {
                operation_id: format!("{}-bind", args.operation_prefix),
                network_id: args.network_id,
                device_id: args.device_id,
                provider_binding_id: args.provider_binding_id,
                binding_nonce: challenge.challenge_secret,
                binding_generation: challenge.binding_generation,
                agent_version: args.agent_version,
            }),
        },
        &node_id,
        &node_token,
    )?;
    let bind = client
        .publish_nodescale_identity_bind_v2(bind)
        .await?
        .into_inner()
        .result
        .ok_or("bind result missing")?;
    if !bind.accepted
        || !matches!(
            bind.disposition,
            value if value == NodescaleIdentityBindDisposition::Active as i32
                || value == NodescaleIdentityBindDisposition::AlreadyConfirmed as i32
        )
    {
        return Err(format!("bind rejected: {}", bind.code).into());
    }
    println!(
        "{}",
        json!({
            "status": "active",
            "authenticated_peer_id": node_id,
            "binding_id": bind.binding_id,
            "generation": bind.generation,
            "revision": bind.revision
        })
    );
    Ok(())
}
