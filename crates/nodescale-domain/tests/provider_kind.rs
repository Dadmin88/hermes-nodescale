use nodescale_domain::ProviderKind;

#[test]
fn tailscale_provider_kind_has_stable_wire_name() {
    let encoded = serde_json::to_string(&ProviderKind::Tailscale).unwrap();
    assert_eq!(encoded, "\"tailscale\"");
    assert_eq!(
        serde_json::from_str::<ProviderKind>(&encoded).unwrap(),
        ProviderKind::Tailscale
    );
}
