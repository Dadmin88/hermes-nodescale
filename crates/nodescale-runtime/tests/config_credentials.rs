use nodescale_runtime::{
    ProviderConfig, RuntimeConfig, RuntimeError, TailscaleAuthMode, resolve_systemd_credential,
};
use std::{fs, path::PathBuf};
use tempfile::tempdir;

fn valid_config() -> RuntimeConfig {
    RuntimeConfig {
        state_path: PathBuf::from("/var/lib/nodescale/state.sqlite3"),
        poll_interval_seconds: 30,
        network_id: "11111111-1111-1111-1111-111111111111".into(),
        network_name: "Provider-neutral network".into(),
        provider: ProviderConfig::Tailscale {
            provider_instance_id: "22222222-2222-2222-2222-222222222222".into(),
            tailnet: "example.com".into(),
            credential_reference: "secret://systemd/provider-token".into(),
            auth: TailscaleAuthMode::ApiAccessToken,
        },
        observation_api: None,
    }
}

#[test]
fn strict_toml_loads_reference_only_tailscale_configuration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("runtime.toml");
    fs::write(
        &path,
        r#"
state_path = "/var/lib/nodescale/state.sqlite3"
poll_interval_seconds = 30
network_id = "11111111-1111-1111-1111-111111111111"
network_name = "Provider-neutral network"

[provider]
kind = "tailscale"
provider_instance_id = "22222222-2222-2222-2222-222222222222"
tailnet = "example.com"
credential_reference = "secret://systemd/provider-token"
auth = "api_access_token"
"#,
    )
    .unwrap();

    assert_eq!(RuntimeConfig::load(path).unwrap(), valid_config());
}

#[test]
fn plaintext_and_unknown_configuration_fail_closed() {
    let mut config = valid_config();
    if let ProviderConfig::Tailscale {
        credential_reference,
        ..
    } = &mut config.provider
    {
        *credential_reference = "tskey-api-plaintext".into();
    }
    assert!(matches!(
        config.validate(),
        Err(RuntimeError::CredentialReference)
    ));

    let directory = tempdir().unwrap();
    let path = directory.path().join("runtime.toml");
    fs::write(
        &path,
        r#"
state_path = "/var/lib/nodescale/state.sqlite3"
poll_interval_seconds = 30
network_id = "11111111-1111-1111-1111-111111111111"
network_name = "Provider-neutral network"
unexpected_field = "forbidden"

[provider]
kind = "tailscale"
provider_instance_id = "22222222-2222-2222-2222-222222222222"
tailnet = "example.com"
credential_reference = "secret://systemd/provider-token"
auth = "api_access_token"
"#,
    )
    .unwrap();
    assert!(matches!(
        RuntimeConfig::load(path),
        Err(RuntimeError::ConfigurationParse)
    ));
}

#[test]
fn systemd_credential_resolution_is_bounded_and_reference_selected() {
    let directory = tempdir().unwrap();
    fs::write(directory.path().join("provider-token"), b"generic-secret\n").unwrap();
    assert_eq!(
        resolve_systemd_credential("secret://systemd/provider-token", Some(directory.path()))
            .unwrap(),
        "generic-secret"
    );
    assert!(matches!(
        resolve_systemd_credential("secret://systemd/../escape", Some(directory.path())),
        Err(RuntimeError::CredentialReference)
    ));
    fs::write(directory.path().join("empty"), b"").unwrap();
    assert!(matches!(
        resolve_systemd_credential("secret://systemd/empty", Some(directory.path())),
        Err(RuntimeError::CredentialUnavailable)
    ));
}

#[cfg(unix)]
#[test]
fn systemd_credential_resolution_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    fs::write(directory.path().join("real"), b"generic-secret").unwrap();
    symlink(
        directory.path().join("real"),
        directory.path().join("provider-token"),
    )
    .unwrap();
    assert!(matches!(
        resolve_systemd_credential("secret://systemd/provider-token", Some(directory.path())),
        Err(RuntimeError::CredentialUnavailable)
    ));
}

#[test]
fn packaged_runtime_declares_reproducible_install_and_encrypted_credential_loading() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let unit =
        fs::read_to_string(root.join("packaging/systemd/nodescale-runtime.service")).unwrap();
    assert!(unit.contains(
        "LoadCredentialEncrypted=provider-token:/etc/credstore.encrypted/provider-token"
    ));
    assert!(!unit.contains("\nLoadCredential=provider-token\n"));

    let documentation = fs::read_to_string(root.join("docs/runtime.md")).unwrap();
    assert!(documentation.contains("cargo build -p nodescale-runtime --release --locked"));
    assert!(documentation.contains("groupadd --system nodescale"));
    assert!(documentation.contains("useradd --system --gid nodescale"));
    assert!(documentation.contains("root:nodescale"));
    assert!(documentation.contains("systemctl enable --now nodescale-runtime.service"));
}
