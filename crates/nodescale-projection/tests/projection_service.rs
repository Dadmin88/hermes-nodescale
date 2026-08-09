//! Narrow lifecycle coverage for the production N7 actor seam.
//!
//! State/Fleet correctness is exercised against the real store by
//! `production_integration`; this file deliberately keeps only the actor's
//! bounded ownership and shutdown contract without recreating a projection DTO.

use std::path::PathBuf;

use nodescale_fleet_client::{
    ApplyError, ApplyResult, Capabilities, FleetClientError, InspectResult, InspectSelector,
    ProjectionDocument,
};
use nodescale_projection::production::{FleetProjectionTransport, N7ProjectionService};
use nodescale_state::StateStore;

struct NeverCalledTransport;

impl FleetProjectionTransport for NeverCalledTransport {
    async fn capabilities(&self) -> Result<Capabilities, FleetClientError> {
        panic!("lifecycle test never sends a Fleet request")
    }

    async fn apply(&self, _document: ProjectionDocument) -> Result<ApplyResult, ApplyError> {
        panic!("lifecycle test never sends a Fleet request")
    }

    async fn inspect(&self, _selector: InspectSelector) -> Result<InspectResult, FleetClientError> {
        panic!("lifecycle test never sends a Fleet request")
    }
}

fn temporary_database_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "nodescale-n7-projection-lifecycle-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos()
    ))
}

#[tokio::test]
async fn actor_start_and_shutdown_owns_the_real_non_sync_state_store() {
    let path = temporary_database_path();
    let store = StateStore::open(&path).expect("open state store");
    let service = N7ProjectionService::start(store, NeverCalledTransport)
        .expect("start bounded single-owner actor");

    service.shutdown().await.expect("shutdown joins actor");
    std::fs::remove_file(path).expect("remove temporary state database");
}
