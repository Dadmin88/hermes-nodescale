use serde::Deserialize;
use serde_json::Value;
use std::{
    env,
    error::Error,
    io::{Read, Write},
    net::TcpStream,
    process::Command,
    time::Duration,
};

const MAX_INPUT_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    #[serde(default)]
    action_id: Option<String>,
    #[serde(default)]
    challenge: Option<String>,
    provider_node_id: String,
    listen: String,
}

fn payload_matches_mode(mode: &str, delivery: &Delivery) -> bool {
    match mode {
        "preflight" => delivery.action_id.is_none() && delivery.challenge.is_none(),
        "proof" => delivery.action_id.is_some() && delivery.challenge.is_some(),
        _ => false,
    }
}

fn local_identity() -> Result<(String, String), Box<dyn Error>> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()?;
    if !output.status.success() || output.stdout.len() > MAX_INPUT_BYTES as usize {
        return Err("target-local Tailscale status failed".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let local = value.get("Self").ok_or("Tailscale status omitted Self")?;
    let stable_id = local
        .get("ID")
        .and_then(Value::as_str)
        .ok_or("Tailscale status omitted Self.ID")?;
    let node_key = local
        .get("PublicKey")
        .and_then(Value::as_str)
        .ok_or("Tailscale status omitted Self.PublicKey")?;
    Ok((stable_id.to_owned(), node_key.to_owned()))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = env::args().nth(1).ok_or("mode is required")?;
    if !matches!(mode.as_str(), "preflight" | "proof") || env::args().nth(2).is_some() {
        return Err("mode must be preflight or proof".into());
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.is_empty() || input.len() > MAX_INPUT_BYTES as usize {
        return Err("delivery payload is empty or oversized".into());
    }
    let delivery: Delivery = serde_json::from_slice(&input)?;
    if !payload_matches_mode(&mode, &delivery) {
        return Err("delivery payload does not match mode".into());
    }
    let (provider_node_id, node_key) = local_identity()?;
    if provider_node_id != delivery.provider_node_id {
        return Err("target-local stable identity mismatched".into());
    }
    let payload = if mode == "preflight" {
        serde_json::json!({
            "provider_node_id": provider_node_id,
            "node_key": node_key,
        })
    } else {
        serde_json::json!({
            "action_id": delivery.action_id,
            "challenge": delivery.challenge,
            "provider_node_id": provider_node_id,
            "node_key": node_key,
        })
    };
    let mut stream =
        TcpStream::connect_timeout(&delivery.listen.parse()?, Duration::from_secs(20))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    serde_json::to_writer(&mut stream, &payload)?;
    stream.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_rejects_challenge_material() {
        let delivery: Delivery = serde_json::from_str(
            r#"{"provider_node_id":"node-1","listen":"192.0.2.1:1234","challenge":"secret"}"#,
        )
        .unwrap();
        assert!(!payload_matches_mode("preflight", &delivery));
        assert!(!payload_matches_mode("proof", &delivery));
    }
}
