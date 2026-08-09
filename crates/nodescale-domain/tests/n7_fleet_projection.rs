use chrono::Utc;
use nodescale_domain::n7::{FleetGeneratedGrants, N7FleetDesiredProjection};
use nodescale_domain::{
    AgentVersion, DeviceId, Generation, JoinSessionId, KeryxBindingId, KeryxBindingIdentity,
    MembershipState, NetworkId, Operation, Role, Roles,
};

fn pending_binding(
    network_id: NetworkId,
    device_id: DeviceId,
    binding_generation: Generation,
) -> KeryxBindingIdentity {
    KeryxBindingIdentity::pending(
        KeryxBindingId::new(),
        network_id,
        device_id,
        JoinSessionId::new(),
        binding_generation,
        1,
        Utc::now(),
        AgentVersion::parse("nodescale-agent:7.0.0").unwrap(),
    )
    .unwrap()
}

#[test]
fn desired_projection_rejects_a_pending_binding_at_its_only_public_construction_boundary() {
    let network_id = NetworkId::new();
    let device_id = DeviceId::new();
    let pending = pending_binding(network_id, device_id, Generation::initial());

    assert!(
        N7FleetDesiredProjection::upsert(
            network_id,
            device_id,
            "node-7",
            MembershipState::Pending,
            Generation::new(9).unwrap(),
            Generation::new(7).unwrap(),
            &pending,
            Roles::new([Role::Worker]).unwrap(),
            FleetGeneratedGrants::none(),
        )
        .is_err()
    );
}

#[test]
fn generated_grants_serialize_as_exact_fleet_operations_and_reject_other_spellings() {
    let grants = FleetGeneratedGrants::new([
        Operation::FleetMessage,
        Operation::FleetHealth,
        Operation::FleetInventory,
    ])
    .unwrap();

    assert_eq!(
        serde_json::to_value(&grants).unwrap(),
        serde_json::json!(["fleet.health", "fleet.inventory", "fleet.message"])
    );
    for unsafe_or_enum_spelling in [
        serde_json::json!(["FleetHealth"]),
        serde_json::json!(["fleet.hermes.run"]),
        serde_json::json!(["fleet.health", "fleet.health"]),
    ] {
        assert!(serde_json::from_value::<FleetGeneratedGrants>(unsafe_or_enum_spelling).is_err());
    }
}
