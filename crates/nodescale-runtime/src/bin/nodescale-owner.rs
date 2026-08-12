use chrono::{Duration, Utc};
use nodescale_domain::{
    AuditActor, DeviceId, DeviceTrustAuthorityAdminIntent, DeviceTrustCapability, Generation,
    NetworkId, OwnerTrustRootToken, TrustAuthorityId,
};
use nodescale_runtime::RuntimeConfig;
use nodescale_state::{N5TrustAuthorityConfiguration, N5TrustReason, StateStore};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{env, error::Error, fs, path::PathBuf};

fn value(args: &[String], flag: &str) -> Result<String, Box<dyn Error>> {
    let index = args
        .iter()
        .position(|value| value == flag)
        .ok_or("required argument missing")?;
    Ok(args.get(index + 1).ok_or("argument value missing")?.clone())
}

fn private_token(path: &PathBuf) -> Result<OwnerTrustRootToken, Box<dyn Error>> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err("owner token file must not be accessible by group or others".into());
        }
    }
    Ok(fs::read_to_string(path)?.trim().parse()?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().ok_or("command is required")?.as_str();
    let config = RuntimeConfig::load(value(&args, "--config")?)?;
    let network_id = NetworkId::parse(&config.network_id)?;
    let store = StateStore::open(&config.state_path)?;
    match command {
        "bootstrap" => {
            let token_file = PathBuf::from(value(&args, "--token-file")?);
            let root = store.bootstrap_n5_owner_trust_root(
                network_id,
                "local-owner",
                "nodescale-owner",
                DeviceTrustAuthorityAdminIntent::explicit(),
                Utc::now(),
                AuditActor::system(),
            )?;
            let root_id = root.trust_root_id();
            let authority_id = TrustAuthorityId::new();
            let configuration = N5TrustAuthorityConfiguration::new(
                authority_id,
                network_id,
                "local-owner",
                "nodescale-owner",
                Generation::initial(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::days(3650),
                [
                    DeviceTrustCapability::AdoptExistingProviderDevice,
                    DeviceTrustCapability::ActivateDeviceTrust,
                ],
                Utc::now(),
            )?;
            store.configure_n5_trust_authority(&root, &configuration)?;
            root.expose_for_delivery(|encoded| -> Result<(), Box<dyn Error>> {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                let mut file = options.open(&token_file)?;
                file.write_all(encoded.as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                Ok(())
            })?;
            println!(
                "{}",
                serde_json::json!({
                    "trust_root_id": root_id.to_string(),
                    "authority_id": authority_id.to_string(),
                    "token_file": token_file,
                })
            );
        }
        "expire-adoption" => {
            let root = private_token(&PathBuf::from(value(&args, "--root-token-file")?))?;
            let action_id = value(&args, "--action-id")?;
            let expired = store.expire_existing_provider_adoption(&root, &action_id, Utc::now())?;
            println!(
                "{}",
                serde_json::json!({
                    "action_id": expired.action_id,
                    "action_state": expired.action_state,
                    "provider_node_id": expired.provider_node_id,
                    "observation_adoption_state": expired.observation_adoption_state,
                })
            );
        }
        "trust" => {
            let root = private_token(&PathBuf::from(value(&args, "--root-token-file")?))?;
            let authority_id = TrustAuthorityId::parse(&value(&args, "--authority-id")?)?;
            let device_id = DeviceId::parse(&value(&args, "--device-id")?)?;
            let current = store
                .durable_device_trust(device_id)?
                .ok_or("device trust state is absent")?;
            let authorization = store.issue_device_trust_authorization(
                &root,
                authority_id,
                device_id,
                current.trust_revision,
                DeviceTrustCapability::ActivateDeviceTrust,
                Utc::now(),
            )?;
            let trusted = store.activate_device_trust(
                authorization,
                Utc::now(),
                N5TrustReason::OwnerApproved,
            )?;
            let device = store.activate_trusted_device_membership(
                &root,
                authority_id,
                device_id,
                Utc::now(),
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "device_id": trusted.view.device_id.to_string(),
                    "trust_state": "trusted",
                    "trust_revision": trusted.view.trust_revision.get(),
                    "membership_state": device.membership_state.as_str(),
                })
            );
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
