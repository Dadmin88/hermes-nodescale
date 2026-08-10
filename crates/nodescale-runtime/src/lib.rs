//! Minimal restart-safe Nodescale provider reconciliation and N7 projection runtime.

use chrono::Utc;
use nodescale_domain::{
    AuditActor, Network, NetworkId, OperationId, ProviderApiKey, ProviderInstanceId, ProviderKind,
};
use nodescale_fleet_client::FleetClient;
use nodescale_projection::production::{
    N7ProductionError, N7ProjectionOutcome, N7ProjectionService,
};
use nodescale_provider::ReadOnlyProvider;
use nodescale_provider_headscale::{HeadscaleClientOptions, HeadscaleProvider};
use nodescale_provider_tailscale::{TailscaleAuth, TailscaleClientOptions, TailscaleProvider};
use nodescale_state::{
    HeadscaleImportConfig, ReconciliationFailure, StateError, StateStore, TailscaleImportConfig,
    TlsVerificationPolicy,
};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub state_path: PathBuf,
    pub fleet_socket: PathBuf,
    pub poll_interval_seconds: u64,
    pub network_id: String,
    pub network_name: String,
    pub provider: ProviderConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    Tailscale {
        provider_instance_id: String,
        tailnet: String,
        credential_reference: String,
        auth: TailscaleAuthMode,
    },
    Headscale {
        provider_instance_id: String,
        server_url: String,
        compatibility_pin: String,
        credential_reference: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TailscaleAuthMode {
    ApiAccessToken,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime configuration is invalid: {0}")]
    Configuration(&'static str),
    #[error("runtime configuration could not be read")]
    ConfigurationRead,
    #[error("runtime configuration TOML is invalid")]
    ConfigurationParse,
    #[error("systemd credential reference is invalid")]
    CredentialReference,
    #[error("systemd credential is unavailable")]
    CredentialUnavailable,
    #[error("provider construction failed")]
    ProviderConstruction,
    #[error("provider reconciliation failed")]
    Reconciliation,
    #[error("N7 projection failed: {0}")]
    Projection(String),
    #[error(transparent)]
    State(#[from] StateError),
}

impl RuntimeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let text = fs::read_to_string(path).map_err(|_| RuntimeError::ConfigurationRead)?;
        let config: Self = toml::from_str(&text).map_err(|_| RuntimeError::ConfigurationParse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        if !self.state_path.is_absolute() || !self.fleet_socket.is_absolute() {
            return Err(RuntimeError::Configuration(
                "state_path and fleet_socket must be absolute",
            ));
        }
        if !(5..=86_400).contains(&self.poll_interval_seconds) {
            return Err(RuntimeError::Configuration(
                "poll_interval_seconds must be between 5 and 86400",
            ));
        }
        NetworkId::parse(&self.network_id)
            .map_err(|_| RuntimeError::Configuration("network_id is invalid"))?;
        if self.network_name.is_empty()
            || self.network_name.len() > 128
            || self.network_name.trim() != self.network_name
            || self.network_name.chars().any(char::is_control)
        {
            return Err(RuntimeError::Configuration("network_name is invalid"));
        }
        self.provider.validate()
    }

    pub fn network_id(&self) -> Result<NetworkId, RuntimeError> {
        NetworkId::parse(&self.network_id)
            .map_err(|_| RuntimeError::Configuration("network_id is invalid"))
    }
}

impl ProviderConfig {
    fn validate(&self) -> Result<(), RuntimeError> {
        let (instance, reference) = match self {
            Self::Tailscale {
                provider_instance_id,
                credential_reference,
                ..
            }
            | Self::Headscale {
                provider_instance_id,
                credential_reference,
                ..
            } => (provider_instance_id, credential_reference),
        };
        ProviderInstanceId::parse(instance)
            .map_err(|_| RuntimeError::Configuration("provider_instance_id is invalid"))?;
        parse_systemd_credential_reference(reference)?;
        match self {
            Self::Tailscale { tailnet, .. } => {
                TailscaleImportConfig::new(
                    tailnet,
                    ProviderInstanceId::parse(instance).map_err(|_| {
                        RuntimeError::Configuration("provider_instance_id is invalid")
                    })?,
                    reference,
                )
                .map_err(|_| RuntimeError::Configuration("Tailscale configuration is invalid"))?;
            }
            Self::Headscale {
                server_url,
                compatibility_pin,
                ..
            } => {
                HeadscaleImportConfig::new(
                    server_url,
                    ProviderInstanceId::parse(instance).map_err(|_| {
                        RuntimeError::Configuration("provider_instance_id is invalid")
                    })?,
                    reference,
                    compatibility_pin,
                    TlsVerificationPolicy::Verify,
                )
                .map_err(|_| RuntimeError::Configuration("Headscale configuration is invalid"))?;
            }
        }
        Ok(())
    }

    fn instance_id(&self) -> Result<ProviderInstanceId, RuntimeError> {
        let value = match self {
            Self::Tailscale {
                provider_instance_id,
                ..
            }
            | Self::Headscale {
                provider_instance_id,
                ..
            } => provider_instance_id,
        };
        ProviderInstanceId::parse(value)
            .map_err(|_| RuntimeError::Configuration("provider_instance_id is invalid"))
    }

    const fn kind(&self) -> ProviderKind {
        match self {
            Self::Tailscale { .. } => ProviderKind::Tailscale,
            Self::Headscale { .. } => ProviderKind::Headscale,
        }
    }

    fn credential_reference(&self) -> &str {
        match self {
            Self::Tailscale {
                credential_reference,
                ..
            }
            | Self::Headscale {
                credential_reference,
                ..
            } => credential_reference,
        }
    }
}

pub enum ProviderRuntime {
    Tailscale {
        provider: TailscaleProvider,
        import: TailscaleImportConfig,
    },
    Headscale {
        provider: HeadscaleProvider,
        import: HeadscaleImportConfig,
    },
}

impl ProviderRuntime {
    fn provider(&self) -> &dyn ReadOnlyProvider {
        match self {
            Self::Tailscale { provider, .. } => provider,
            Self::Headscale { provider, .. } => provider,
        }
    }

    async fn import(
        &self,
        store: &StateStore,
        network: &Network,
    ) -> Result<(), ReconciliationFailure> {
        match self {
            Self::Tailscale { provider, import } => {
                store
                    .import_tailscale_network(
                        network,
                        import,
                        provider,
                        Utc::now(),
                        AuditActor::system(),
                    )
                    .await
            }
            Self::Headscale { provider, import } => {
                store
                    .import_headscale_network(
                        network,
                        import,
                        provider,
                        Utc::now(),
                        AuditActor::system(),
                    )
                    .await
            }
        }
    }
}

pub fn build_provider(config: &ProviderConfig) -> Result<ProviderRuntime, RuntimeError> {
    let secret = resolve_systemd_credential(config.credential_reference(), None)?;
    let api_key = ProviderApiKey::new(secret).map_err(|_| RuntimeError::CredentialUnavailable)?;
    let instance = config.instance_id()?;
    match config {
        ProviderConfig::Tailscale {
            tailnet,
            credential_reference,
            auth: TailscaleAuthMode::ApiAccessToken,
            ..
        } => {
            let auth = TailscaleAuth::ApiAccessToken(api_key);
            let provider =
                TailscaleProvider::new(tailnet, instance, auth, TailscaleClientOptions::default())
                    .map_err(|_| RuntimeError::ProviderConstruction)?;
            let import = TailscaleImportConfig::new(tailnet, instance, credential_reference)?;
            Ok(ProviderRuntime::Tailscale { provider, import })
        }
        ProviderConfig::Headscale {
            server_url,
            compatibility_pin,
            credential_reference,
            ..
        } => {
            let provider = HeadscaleProvider::new(
                server_url,
                instance,
                api_key,
                HeadscaleClientOptions::default(),
            )
            .map_err(|_| RuntimeError::ProviderConstruction)?;
            let import = HeadscaleImportConfig::new(
                server_url,
                instance,
                credential_reference,
                compatibility_pin,
                TlsVerificationPolicy::Verify,
            )?;
            Ok(ProviderRuntime::Headscale { provider, import })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CycleOutcome {
    pub imported: bool,
    pub observed_nodes: u64,
    pub desired_projections: usize,
    pub applied_or_replayed: usize,
    pub retryable: usize,
    pub conflicts: usize,
}

pub async fn run_cycle(
    store: &StateStore,
    config: &RuntimeConfig,
    provider: &ProviderRuntime,
    projector: &N7ProjectionService<FleetClient>,
) -> Result<CycleOutcome, RuntimeError> {
    let network_id = config.network_id()?;
    let configured_instance = config.provider.instance_id()?;
    let configured_kind = config.provider.kind();
    let imported = match store.network(network_id) {
        Ok(network) => {
            if network.provider_instance_id != configured_instance
                || network.provider_kind != configured_kind
            {
                return Err(RuntimeError::Configuration(
                    "persisted network provider identity does not match config",
                ));
            }
            store
                .reconcile_read_only(
                    network_id,
                    provider.provider(),
                    Utc::now(),
                    AuditActor::system(),
                )
                .await
                .map_err(|_| RuntimeError::Reconciliation)?;
            false
        }
        Err(StateError::NotFound(_)) => {
            let network = Network::new(
                network_id,
                config.network_name.clone(),
                configured_kind,
                configured_instance,
                Utc::now(),
            )
            .map_err(|_| RuntimeError::Configuration("network configuration is invalid"))?;
            provider
                .import(store, &network)
                .await
                .map_err(|_| RuntimeError::Reconciliation)?;
            true
        }
        Err(error) => return Err(error.into()),
    };

    let report = store.reconciliation_report(network_id)?;
    let desired = store.n7_runtime_desired_projections(network_id)?;
    let mut outcome = CycleOutcome {
        imported,
        observed_nodes: report.observed_count,
        desired_projections: desired.len(),
        applied_or_replayed: 0,
        retryable: 0,
        conflicts: 0,
    };
    for desired in desired {
        let operation_id =
            OperationId::parse(format!("runtime-n7-{}", desired.content_digest().as_str()))
                .map_err(|_| {
                    RuntimeError::Projection("invalid deterministic operation ID".into())
                })?;
        match projector
            .reconcile(operation_id, desired)
            .await
            .map_err(|error| RuntimeError::Projection(error.to_string()))?
        {
            N7ProjectionOutcome::Applied | N7ProjectionOutcome::AlreadyApplied => {
                outcome.applied_or_replayed += 1;
            }
            N7ProjectionOutcome::Retryable => outcome.retryable += 1,
            N7ProjectionOutcome::Conflict => outcome.conflicts += 1,
        }
    }
    Ok(outcome)
}

pub fn start_projector(
    state_path: impl AsRef<Path>,
    fleet_socket: impl AsRef<Path>,
) -> Result<N7ProjectionService<FleetClient>, RuntimeError> {
    let store = StateStore::open(state_path)?;
    N7ProjectionService::start(store, FleetClient::new(fleet_socket))
        .map_err(|error| RuntimeError::Projection(error.to_string()))
}

pub fn poll_interval(config: &RuntimeConfig) -> Duration {
    Duration::from_secs(config.poll_interval_seconds)
}

pub async fn shutdown_projector(
    projector: &N7ProjectionService<FleetClient>,
) -> Result<(), RuntimeError> {
    projector
        .shutdown()
        .await
        .map_err(|error: N7ProductionError| RuntimeError::Projection(error.to_string()))
}

pub fn resolve_systemd_credential(
    reference: &str,
    credentials_directory: Option<&Path>,
) -> Result<String, RuntimeError> {
    let name = parse_systemd_credential_reference(reference)?;
    let directory = match credentials_directory {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(
            env::var_os("CREDENTIALS_DIRECTORY").ok_or(RuntimeError::CredentialUnavailable)?,
        ),
    };
    if !directory.is_absolute() {
        return Err(RuntimeError::CredentialUnavailable);
    }
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|_| RuntimeError::CredentialUnavailable)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 4_096 {
        return Err(RuntimeError::CredentialUnavailable);
    }
    let bytes = fs::read(path).map_err(|_| RuntimeError::CredentialUnavailable)?;
    let mut secret = String::from_utf8(bytes).map_err(|_| RuntimeError::CredentialUnavailable)?;
    if secret.ends_with("\r\n") {
        secret.truncate(secret.len() - 2);
    } else if secret.ends_with('\n') {
        secret.pop();
    }
    if secret.is_empty() || secret.len() > 4_096 || secret.chars().any(char::is_whitespace) {
        return Err(RuntimeError::CredentialUnavailable);
    }
    Ok(secret)
}

fn parse_systemd_credential_reference(reference: &str) -> Result<&str, RuntimeError> {
    let name = reference
        .strip_prefix("secret://systemd/")
        .ok_or(RuntimeError::CredentialReference)?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(RuntimeError::CredentialReference);
    }
    Ok(name)
}
