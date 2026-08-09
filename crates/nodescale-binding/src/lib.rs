//! Production orchestration for Nodescale N6 authenticated Keryx identity binding.
//!
//! The service owns provider-fresh eligibility, durable SQLite transitions, and
//! a dedicated current-thread actor for the intentionally non-`Sync` StateStore.
//! Keryx-specific protobuf and transport handling remain isolated in
//! `nodescale-keryx-adapter`.

mod production;

pub use production::*;
