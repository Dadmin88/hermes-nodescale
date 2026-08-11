use std::{env, error::Error, path::PathBuf};

use nodescale_domain::{
    DeviceId, KeryxBindingState, MembershipState, NetworkId, Operation, OperationId, Role, Roles,
    n7::{FleetGeneratedGrants, N7FleetDesiredProjection},
};
use nodescale_fleet_client::FleetClient;
use nodescale_projection::production::N7ProjectionService;
use nodescale_runtime::RuntimeConfig;
use nodescale_state::StateStore;

struct Args {
    config: PathBuf,
    fleet_socket: PathBuf,
    device_id: DeviceId,
    operation_id: OperationId,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut values = std::collections::BTreeMap::new();
    let mut args = env::args().skip(1);
    while let Some(key) = args.next() {
        values.insert(key, args.next().ok_or("missing argument value")?);
    }
    let mut take = |key: &str| values.remove(key).ok_or_else(|| format!("missing {key}"));
    let config = PathBuf::from(take("--config")?);
    let fleet_socket = PathBuf::from(take("--fleet-socket")?);
    let device_id = DeviceId::parse(&take("--device-id")?)?;
    let operation_id = OperationId::parse(&take("--operation-id")?)?;
    if !values.is_empty() || !config.is_absolute() || !fleet_socket.is_absolute() {
        return Err("invalid or unknown arguments".into());
    }
    Ok(Args::finish(config, fleet_socket, device_id, operation_id))
}

impl Args {
    fn finish(
        config: PathBuf,
        fleet_socket: PathBuf,
        device_id: DeviceId,
        operation_id: OperationId,
    ) -> Self {
        Self {
            config,
            fleet_socket,
            device_id,
            operation_id,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let config = RuntimeConfig::load(&args.config)?;
    let network_id = NetworkId::parse(&config.network_id)?;
    let store = StateStore::open(&config.state_path)?;
    let device = store.device(args.device_id)?;
    if device.network_id != network_id || device.membership_state != MembershipState::Active {
        return Err("device is not an active member of the configured network".into());
    }
    let trust = store
        .durable_device_trust(args.device_id)?
        .ok_or("device trust is absent")?;
    if trust.trust_state != nodescale_domain::DeviceTrustState::Trusted {
        return Err("device is not trusted".into());
    }
    let binding = store
        .latest_n6_binding(args.device_id)?
        .ok_or("N6 binding is absent")?;
    if binding.state != KeryxBindingState::Active {
        return Err("N6 binding is not active".into());
    }
    let active = store.n6_active_binding_provenance(
        binding.binding_id,
        binding.network_id,
        binding.device_id,
        binding.generation,
    )?;
    let projection_generation = device.generations.fleet_projection;
    let desired = N7FleetDesiredProjection::upsert_from_active_n6_provenance(
        device.network_id,
        device.device_id,
        device.display_name.clone(),
        device.membership_state,
        device.generations.credential,
        projection_generation,
        active,
        Roles::new([Role::Worker])?,
        FleetGeneratedGrants::new([
            Operation::FleetHealth,
            Operation::FleetInventory,
            Operation::FleetMessage,
        ])?,
    )?;
    let service = N7ProjectionService::start(store, FleetClient::new(&args.fleet_socket))?;
    let outcome = service.reconcile(args.operation_id, desired).await?;
    service.shutdown().await?;
    println!(
        "{}",
        serde_json::json!({
            "status": format!("{outcome:?}").to_lowercase(),
            "device_id": args.device_id.to_string(),
            "projection_generation": projection_generation.get()
        })
    );
    Ok(())
}
