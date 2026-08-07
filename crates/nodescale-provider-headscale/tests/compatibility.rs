use nodescale_provider::CompatibilityStatus;
use nodescale_provider_headscale::{PINNED_HEADSCALE_VERSION, classify_version};

#[test]
fn pinned_version_is_compatible_and_unknown_versions_fail_closed() {
    assert_eq!(PINNED_HEADSCALE_VERSION, "0.29.3");
    assert_eq!(
        classify_version("v0.29.3").unwrap(),
        CompatibilityStatus::Compatible
    );
    assert_eq!(
        classify_version("v0.29.2").unwrap(),
        CompatibilityStatus::ReadOnlyDegraded
    );
    assert_eq!(
        classify_version("v0.29.3-dirty").unwrap(),
        CompatibilityStatus::Unsupported
    );
    assert_eq!(
        classify_version("v0.30.0").unwrap(),
        CompatibilityStatus::Unsupported
    );
    assert_eq!(
        classify_version("v0.28.0").unwrap(),
        CompatibilityStatus::Unsupported
    );
    assert!(classify_version("not-a-version").is_err());
}
