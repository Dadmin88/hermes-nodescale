#[cfg(test)]
use nodescale_runtime::ssh_arguments;
use nodescale_runtime::{launch_adoption_target, target_transport_exited_before_connect};
use serde::Deserialize;
use serde_json::Value;
use std::{env, error::Error, io::Write, net::SocketAddr, process::Command};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::TcpListener,
    time::{Duration, Instant, timeout},
};

const MAX_PREFLIGHT_BYTES: usize = 16 * 1024;

struct Arguments {
    provider_node_id: String,
    listen: SocketAddr,
    ssh_destination: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetPreflight {
    provider_node_id: String,
    node_key: String,
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut values = env::args().skip(1);
    let mut provider_node_id = None;
    let mut listen = None;
    let mut ssh_destination = None;
    while let Some(flag) = values.next() {
        let value = values.next().ok_or("every argument requires a value")?;
        match flag.as_str() {
            "--provider-node-id" => provider_node_id = Some(value),
            "--listen" => listen = Some(value.parse()?),
            "--ssh-destination" => ssh_destination = Some(value),
            _ => return Err("unknown argument".into()),
        }
    }
    Ok(Arguments {
        provider_node_id: provider_node_id.ok_or("--provider-node-id is required")?,
        listen: listen.ok_or("--listen is required")?,
        ssh_destination: ssh_destination.ok_or("--ssh-destination is required")?,
    })
}

fn whois(peer: SocketAddr) -> Result<(String, String), Box<dyn Error>> {
    let output = Command::new("tailscale")
        .args(["whois", "--json", &peer.ip().to_string()])
        .output()?;
    if !output.status.success() || output.stdout.len() > MAX_PREFLIGHT_BYTES {
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

fn target_preflight_agrees(
    expected_provider_node_id: &str,
    target_node_key: &str,
    whois_provider_node_id: &str,
    whois_node_key: &str,
    target_provider_node_id: &str,
) -> bool {
    expected_provider_node_id == target_provider_node_id
        && expected_provider_node_id == whois_provider_node_id
        && target_node_key == whois_node_key
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = arguments()?;
    let listener = TcpListener::bind(arguments.listen).await?;
    println!(
        "{}",
        serde_json::json!({
            "kind": "nodescale.adoption.transport_preflight.v1",
            "listen": arguments.listen.to_string(),
            "provider_node_id": arguments.provider_node_id,
        })
    );
    std::io::stdout().flush()?;
    let delivery = serde_json::to_vec(&serde_json::json!({
        "provider_node_id": arguments.provider_node_id,
        "listen": arguments.listen.to_string(),
    }))?;
    let mut target_process =
        launch_adoption_target(&arguments.ssh_destination, "preflight", &delivery)?;

    let connect_deadline = Instant::now() + Duration::from_secs(60);
    let (stream, peer) = loop {
        if target_transport_exited_before_connect(target_process.try_wait()?) {
            return Err("target transport exited before connecting".into());
        }
        if Instant::now() >= connect_deadline {
            return Err("target transport did not connect before timeout".into());
        }
        match timeout(Duration::from_millis(100), listener.accept()).await {
            Ok(result) => break result?,
            Err(_) => continue,
        }
    };
    let mut line = Vec::new();
    timeout(
        Duration::from_secs(10),
        BufReader::new(stream)
            .take(MAX_PREFLIGHT_BYTES as u64)
            .read_until(b'\n', &mut line),
    )
    .await??;
    if line.is_empty() || line.len() >= MAX_PREFLIGHT_BYTES {
        return Err("target preflight payload is empty or oversized".into());
    }
    let target: TargetPreflight = serde_json::from_slice(&line)?;
    let (whois_provider_node_id, whois_node_key) = whois(peer)?;
    if !target_preflight_agrees(
        &arguments.provider_node_id,
        &target.node_key,
        &whois_provider_node_id,
        &whois_node_key,
        &target.provider_node_id,
    ) {
        return Err("target preflight identity does not agree".into());
    }
    if !target_process.wait()?.success() {
        return Err("target transport preflight failed".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "transport": "ready",
            "provider_node_id": arguments.provider_node_id,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_transport_uses_explicit_destination_and_fixed_helper_without_payload_argv() {
        assert_eq!(
            ssh_arguments("operator-approved-target", "preflight"),
            [
                "-o",
                "BatchMode=yes",
                "--",
                "operator-approved-target",
                "nodescale-adoption-target",
                "preflight",
            ]
        );
    }

    #[test]
    fn target_preflight_requires_exact_three_way_identity_agreement() {
        assert!(target_preflight_agrees(
            "node-1",
            "nodekey:1",
            "node-1",
            "nodekey:1",
            "node-1",
        ));
        assert!(!target_preflight_agrees(
            "node-1",
            "nodekey:1",
            "node-1",
            "nodekey:2",
            "node-1",
        ));
        assert!(!target_preflight_agrees(
            "node-1",
            "nodekey:1",
            "node-2",
            "nodekey:1",
            "node-1",
        ));
    }
}
