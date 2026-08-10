use nodescale_runtime::{
    ObservationUdsListener, RuntimeConfig, RuntimeError, build_provider, poll_interval, run_cycle,
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

    if arguments.once {
        let outcome = run_cycle(&store, &config, &provider).await?;
        eprintln!(
            "nodescale observation cycle complete: imported={} observed={}",
            outcome.imported, outcome.observed_nodes
        );
        return Ok(());
    }

    let observation_listener = config
        .observation_api
        .as_ref()
        .map(ObservationUdsListener::bind)
        .transpose()?;
    let mut api_ticker = time::interval(std::time::Duration::from_millis(50));
    api_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut ticker = time::interval(poll_interval(&config));
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|_| RuntimeError::Configuration("SIGTERM handler unavailable"))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|_| RuntimeError::Configuration("SIGINT handler unavailable"))?;

    loop {
        tokio::select! {
            _ = api_ticker.tick(), if observation_listener.is_some() => {
                if let Some(listener) = observation_listener.as_ref() {
                    if let Err(error) = listener.serve_available(&store) {
                        eprintln!("nodescale observation API accept failed: {error}");
                    }
                }
            }
            _ = ticker.tick() => {
                match run_cycle(&store, &config, &provider).await {
                    Ok(outcome) => eprintln!(
                        "nodescale observation cycle complete: imported={} observed={}",
                        outcome.imported,
                        outcome.observed_nodes
                    ),
                    Err(error) => eprintln!("nodescale observation cycle failed: {error}"),
                }
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    Ok(())
}
