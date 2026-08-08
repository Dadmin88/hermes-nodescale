use nodescale_redemption_ingress::{TlsServeConfig, TlsServeConfigError};
use std::net::SocketAddr;

#[test]
fn private_constructor_rejects_public_and_wildcard_binds() {
    for bind in ["0.0.0.0:8443", "8.8.8.8:8443", "[::]:8443"] {
        assert_eq!(
            TlsServeConfig::private_bind(
                bind.parse::<SocketAddr>().unwrap(),
                "certificate.pem",
                "private-key.pem",
            )
            .unwrap_err(),
            TlsServeConfigError::PublicBindRequiresExplicitOptIn
        );
    }
}

#[test]
fn private_constructor_accepts_loopback_and_private_bridge_binds() {
    for bind in ["127.0.0.1:8443", "172.28.0.1:8443", "[fd00::1]:8443"] {
        let parsed = bind.parse::<SocketAddr>().unwrap();
        assert_eq!(
            TlsServeConfig::private_bind(parsed, "certificate.pem", "private-key.pem")
                .unwrap()
                .bind(),
            parsed
        );
    }
}

#[test]
fn public_bind_requires_a_named_opt_in_constructor() {
    let bind = "0.0.0.0:8443".parse::<SocketAddr>().unwrap();
    assert_eq!(
        TlsServeConfig::explicitly_public_bind(bind, "certificate.pem", "private-key.pem")
            .unwrap()
            .bind(),
        bind
    );
}
