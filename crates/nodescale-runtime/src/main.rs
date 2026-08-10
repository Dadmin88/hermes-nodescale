use nodescale_runtime::{
    RuntimeConfig, RuntimeError, build_provider, poll_interval, run_cycle, shutdown_projector,
    start_projector,
};
use nodescale_state::StateStore;
use std::{env, path::PathBuf};
use tokio::{
    signal::unix::{SignalKind, signal},
    time,
};

struct Arguments {
    config: PathBuf,
    once: bool,
}

fn arguments() -> Result<Arguments, RuntimeError> {
    let mut values = env::args_os().skip(1);
    let mut config = None;
    let mut once = false;
    while let Some(value) = values.next() {
        if value == "--config" {
            if config.is_some() {
                return Err(RuntimeError::Configuration("--config may appear only once"));
            }
            config = Some(PathBuf::from(values.next().ok_or(
                RuntimeError::Configuration("--config requires an absolute path"),
            )?));
        } else if value == "--once" {
            once = true;
        } else {
            return Err(RuntimeError::Configuration("unknown command-line argument"));
        }
    }
    let config = config.ok_or(RuntimeError::Configuration("--config is required"))?;
    if !config.is_absolute() {
        return Err(RuntimeError::Configuration("--config must be absolute"));
    }
    Ok(Arguments { config, once })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), RuntimeError> {
    let arguments = arguments()?;
    let config = RuntimeConfig::load(&arguments.config)?;
    let provider = build_provider(&config.provider)?;
    let store = StateStore::open(&config.state_path)?;
    let projector = start_projector(&config.state_path, &config.fleet_socket)?;

    if arguments.once {
        let outcome = run_cycle(&store, &config, &provider, &projector).await;
        shutdown_projector(&projector).await?;
        let outcome = outcome?;
        eprintln!(
            "nodescale cycle complete: imported={} observed={} desired={} applied_or_replayed={} retryable={} conflicts={}",
            outcome.imported,
            outcome.observed_nodes,
            outcome.desired_projections,
            outcome.applied_or_replayed,
            outcome.retryable,
            outcome.conflicts
        );
        return Ok(());
    }

    let mut ticker = time::interval(poll_interval(&config));
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|_| RuntimeError::Configuration("SIGTERM handler unavailable"))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|_| RuntimeError::Configuration("SIGINT handler unavailable"))?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match run_cycle(&store, &config, &provider, &projector).await {
                    Ok(outcome) => eprintln!(
                        "nodescale cycle complete: imported={} observed={} desired={} applied_or_replayed={} retryable={} conflicts={}",
                        outcome.imported,
                        outcome.observed_nodes,
                        outcome.desired_projections,
                        outcome.applied_or_replayed,
                        outcome.retryable,
                        outcome.conflicts
                    ),
                    Err(error) => eprintln!("nodescale cycle failed: {error}"),
                }
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    shutdown_projector(&projector).await
}
