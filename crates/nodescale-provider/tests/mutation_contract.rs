use nodescale_provider::MutationTags;
use std::collections::BTreeSet;

#[test]
fn validated_tags_are_closed_deterministic_and_bounded() {
    let tags = MutationTags::new([
        "tag:nodescale-worker".to_owned(),
        "tag:nodescale-admin".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        tags.as_set(),
        &BTreeSet::from([
            "tag:nodescale-admin".to_owned(),
            "tag:nodescale-worker".to_owned(),
        ])
    );
    assert!(MutationTags::new(["tag:worker".to_owned()]).is_err());
    assert!(
        MutationTags::new([
            "tag:nodescale-node".to_owned(),
            "tag:nodescale-worker".to_owned(),
            "tag:nodescale-controller".to_owned(),
            "tag:nodescale-profile-host".to_owned(),
            "tag:nodescale-observer".to_owned(),
        ])
        .is_err()
    );
}
