use std::{env, error::Error, path::PathBuf, sync::Arc};

use chrono::Duration;
use nodescale_binding::N6BindingService;
use nodescale_domain::NetworkId;
use nodescale_keryx_adapter::TryNodescaleKeryxAdapter;
use nodescale_runtime::{ProviderConfig, ProviderRuntime, RuntimeConfig, build_provider};
use nodescale_state::StateStore;

fn usage() -> &'static str {
    "usage: nodescale-control-node --config <absolute-runtime.toml>"
}

fn config_path() -> Result<PathBuf, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("--config") {
        return Err(usage().into());
    }
    let path = PathBuf::from(args.next().ok_or_else(|| usage().to_owned())?);
    if args.next().is_some() || !path.is_absolute() {
        return Err(usage().into());
    }
    Ok(path)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = RuntimeConfig::load(&config_path()?)?;
    let provider = build_provider(&config.provider)?;
    let network_id = NetworkId::parse(&config.network_id)?;
    let tailnet = match &config.provider {
        ProviderConfig::Tailscale { tailnet, .. } => tailnet.clone(),
        _ => return Err("V10 control node requires a Tailscale runtime".into()),
    };
    let provider = match provider {
        ProviderRuntime::Tailscale { provider, .. } => provider,
        _ => return Err("V10 control node requires a Tailscale provider".into()),
    };
    let store = StateStore::open(&config.state_path)?;
    let configured =
        store.configured_n5_tailscale_provider_from_runtime(network_id, &tailnet, provider)?;
    let service = Arc::new(N6BindingService::new_tailscale(
        store,
        configured,
        Duration::minutes(10),
    )?);
    let adapter = TryNodescaleKeryxAdapter::new(service)?;
    keryx_relay::run_edge_node_with_direct_control_handlers(adapter.direct_control_handlers())
        .await?;
    Ok(())
}
