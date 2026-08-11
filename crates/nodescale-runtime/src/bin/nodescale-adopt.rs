use chrono::Utc;
use nodescale_domain::{
    AdoptionChallengeToken, AuditActor, NetworkId, OwnerTrustRootToken, TrustAuthorityId,
};
use nodescale_runtime::{ProviderRuntime, RuntimeConfig, build_provider};
use nodescale_state::{ExistingProviderAdoptionProof, StateStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{env, error::Error, fs, io::Write, net::SocketAddr, path::PathBuf, process::Command};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::TcpListener,
    time::{Duration, timeout},
};

const MAX_PROOF_BYTES: usize = 16 * 1024;

struct Arguments {
    config: PathBuf,
    root_token_file: PathBuf,
    authority_id: TrustAuthorityId,
    provider_node_id: String,
    authorization_operation_id: String,
    proof_operation_id: String,
    listen: SocketAddr,
}

#[derive(Serialize)]
struct ChallengeDelivery<'a> {
    action_id: &'a str,
    challenge: &'a str,
    provider_node_id: &'a str,
    listen: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetProof {
    action_id: String,
    challenge: String,
    provider_node_id: String,
    node_key: String,
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut values = env::args().skip(1);
    let mut config = None;
    let mut root_token_file = None;
    let mut authority_id = None;
    let mut provider_node_id = None;
    let mut authorization_operation_id = None;
    let mut proof_operation_id = None;
    let mut listen = None;
    while let Some(flag) = values.next() {
        let value = values.next().ok_or("every argument requires a value")?;
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(value)),
            "--root-token-file" => root_token_file = Some(PathBuf::from(value)),
            "--authority-id" => authority_id = Some(TrustAuthorityId::parse(&value)?),
            "--provider-node-id" => provider_node_id = Some(value),
            "--authorization-operation-id" => authorization_operation_id = Some(value),
            "--proof-operation-id" => proof_operation_id = Some(value),
            "--listen" => listen = Some(value.parse()?),
            _ => return Err("unknown argument".into()),
        }
    }
    Ok(Arguments {
        config: config.ok_or("--config is required")?,
        root_token_file: root_token_file.ok_or("--root-token-file is required")?,
        authority_id: authority_id.ok_or("--authority-id is required")?,
        provider_node_id: provider_node_id.ok_or("--provider-node-id is required")?,
        authorization_operation_id: authorization_operation_id
            .ok_or("--authorization-operation-id is required")?,
        proof_operation_id: proof_operation_id.ok_or("--proof-operation-id is required")?,
        listen: listen.ok_or("--listen is required")?,
    })
}

fn whois(peer: SocketAddr) -> Result<(String, String), Box<dyn Error>> {
    let output = Command::new("tailscale")
        .args(["whois", "--json", &peer.ip().to_string()])
        .output()?;
    if !output.status.success() || output.stdout.len() > MAX_PROOF_BYTES {
        return Err("controller-side Tailscale WhoIs failed".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let node = value.get("Node").ok_or("WhoIs response omitted Node")?;
    let stable_id = node
        .get("StableID")
        .and_then(Value::as_str)
        .ok_or("WhoIs response omitted Node.StableID")?;
    let node_key = node
        .get("Key")
        .and_then(Value::as_str)
        .ok_or("WhoIs response omitted Node.Key")?;
    Ok((stable_id.to_owned(), node_key.to_owned()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = arguments()?;
    let config = RuntimeConfig::load(&arguments.config)?;
    let network_id = NetworkId::parse(&config.network_id)?;
    #[cfg(unix)]
    if fs::metadata(&arguments.root_token_file)?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err("owner token file must not be accessible by group or others".into());
    }
    let root_text = fs::read_to_string(&arguments.root_token_file)?;
    let root_token: OwnerTrustRootToken = root_text.trim().parse()?;
    let provider = build_provider(&config.provider)?;
    let store = StateStore::open(&config.state_path)?;
    let listener = TcpListener::bind(arguments.listen).await?;
    let action = store.issue_existing_provider_adoption(
        &root_token,
        arguments.authority_id,
        network_id,
        &arguments.provider_node_id,
        &arguments.authorization_operation_id,
        Utc::now(),
    )?;
    let encoded_challenge = action.challenge.with_encoded(str::to_owned);
    println!(
        "{}",
        serde_json::to_string(&ChallengeDelivery {
            action_id: &action.action_id,
            challenge: &encoded_challenge,
            provider_node_id: &action.provider_node_id,
            listen: arguments.listen.to_string(),
        })?
    );
    std::io::stdout().flush()?;

    let (stream, peer) = timeout(Duration::from_secs(300), listener.accept()).await??;
    let mut line = Vec::new();
    timeout(
        Duration::from_secs(10),
        BufReader::new(stream)
            .take(MAX_PROOF_BYTES as u64)
            .read_until(b'\n', &mut line),
    )
    .await??;
    if line.is_empty() || line.len() >= MAX_PROOF_BYTES {
        return Err("target proof payload is empty or oversized".into());
    }
    let target: TargetProof = serde_json::from_slice(&line)?;
    if target.action_id != action.action_id || target.provider_node_id != action.provider_node_id {
        return Err("target proof action or stable node identity mismatched".into());
    }
    let returned_challenge: AdoptionChallengeToken = target.challenge.parse()?;
    let (whois_provider_node_id, whois_node_key) = whois(peer)?;
    if whois_provider_node_id != target.provider_node_id || whois_node_key != target.node_key {
        return Err("target-local evidence and controller WhoIs disagree".into());
    }
    let proof = ExistingProviderAdoptionProof {
        operation_id: arguments.proof_operation_id,
        challenge: returned_challenge,
        target_origin_provider_node_id: whois_provider_node_id.clone(),
        whois_provider_node_id,
        whois_node_key,
        local_provider_node_id: target.provider_node_id,
        local_node_key: target.node_key,
    };
    let confirmation = match &provider {
        ProviderRuntime::Tailscale { provider, .. } => {
            store
                .confirm_existing_provider_adoption(
                    provider,
                    &action,
                    &proof,
                    Utc::now(),
                    AuditActor::system(),
                )
                .await?
        }
        ProviderRuntime::Headscale { .. } => {
            return Err(
                "nodescale-adopt currently supports the frozen Tailscale proof method only".into(),
            );
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "outcome": format!("{:?}", confirmation.outcome).to_lowercase(),
            "device_id": confirmation.device_id.to_string(),
            "provider_binding_id": confirmation.provider_binding_id.to_string(),
        })
    );
    Ok(())
}
