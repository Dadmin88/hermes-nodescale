use nodescale_domain::*;
use nodescale_state::*;
use tempfile::tempdir;

fn sample_network() -> Network {
    Network::new(
        NetworkId::new(),
        "network-1",
        ProviderKind::Fake,
        ProviderInstanceId::new(),
        chrono::Utc::now(),
    )
    .unwrap()
}

#[test]
fn fresh_migration_and_reopen_preserve_schema_and_generations() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nodescale.db");
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    store
        .advance_membership_generation(
            network.network_id,
            Generation::new(1).unwrap(),
            Generation::new(2).unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened.network_generation(network.network_id).unwrap(),
        Generation::new(2).unwrap()
    );
    assert_eq!(
        reopened
            .network(network.network_id)
            .unwrap()
            .membership_generation,
        Generation::new(2).unwrap()
    );
}

#[test]
fn foreign_keys_and_duplicate_provider_identities_are_rejected() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let mut first = Device::new(
        DeviceId::new(),
        network.network_id,
        "controller-1",
        chrono::Utc::now(),
    )
    .unwrap();
    first.provider_identity = Some(
        ProviderIdentity::new(
            network.provider_instance_id,
            ProviderNodeId::parse("fake-node-0001").unwrap(),
            "stable-key-1",
        )
        .unwrap(),
    );
    store.create_device(&first, AuditActor::system()).unwrap();
    let mut second = Device::new(
        DeviceId::new(),
        network.network_id,
        "worker-1",
        chrono::Utc::now(),
    )
    .unwrap();
    second.provider_identity = first.provider_identity.clone();
    assert!(matches!(
        store.create_device(&second, AuditActor::system()),
        Err(StateError::Conflict(_))
    ));
}

#[test]
fn audited_mutation_rolls_back_as_one_transaction() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let before = store.audit_event_count().unwrap();
    store.set_failpoint(Failpoint::BeforeAuditInsert, true);
    assert!(
        store
            .advance_membership_generation(
                network.network_id,
                Generation::new(1).unwrap(),
                Generation::new(2).unwrap(),
                AuditActor::system()
            )
            .is_err()
    );
    assert_eq!(
        store.network_generation(network.network_id).unwrap(),
        Generation::new(1).unwrap()
    );
    assert_eq!(store.audit_event_count().unwrap(), before);
}

#[test]
fn state_rejects_ungated_active_devices() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let mut device = Device::new(
        DeviceId::new(),
        network.network_id,
        "worker-1",
        chrono::Utc::now(),
    )
    .unwrap();
    device.membership_state = MembershipState::Active;
    assert!(matches!(
        store.create_device(&device, AuditActor::system()),
        Err(StateError::ActivationGated)
    ));
}

#[test]
fn foreign_keys_reject_devices_for_unknown_networks() {
    let store = StateStore::open_in_memory().unwrap();
    let device = Device::new(
        DeviceId::new(),
        NetworkId::new(),
        "worker-1",
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(store.create_device(&device, AuditActor::system()).is_err());
}

#[test]
fn newer_schema_versions_are_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("future.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", SUPPORTED_SCHEMA_VERSION + 1)
        .unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&path),
        Err(StateError::UnsupportedSchema { .. })
    ));
}

#[test]
fn audit_metadata_rejects_secret_bearing_keys() {
    let unsafe_value = serde_json::json!({"binding_nonce": "do-not-log"});
    assert!(matches!(
        SanitizedMetadata::new(unsafe_value),
        Err(StateError::UnsafeAuditMetadata(_))
    ));
    assert!(SanitizedMetadata::new(serde_json::json!({"reason": "operator_request"})).is_ok());
}

#[test]
fn invitation_plaintext_never_persists_or_reaches_audit() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let secret = InvitationSecret::new("never-store-this-value".to_owned()).unwrap();
    let invitation = Invitation::new(
        InvitationId::new(),
        network.network_id,
        Roles::new([Role::Worker]).unwrap(),
        secret.verifier(),
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::hours(1),
        1,
    )
    .unwrap();
    store
        .issue_invitation(&invitation, AuditActor::system())
        .unwrap();
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains("never-store-this-value")
    );
}

#[test]
fn tombstones_and_unrelated_device_generations_survive() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let first = Device::new(
        DeviceId::new(),
        network.network_id,
        "controller-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let second = Device::new(
        DeviceId::new(),
        network.network_id,
        "worker-1",
        chrono::Utc::now(),
    )
    .unwrap();
    store.create_device(&first, AuditActor::system()).unwrap();
    store.create_device(&second, AuditActor::system()).unwrap();
    store
        .advance_device_credential_generation(
            first.device_id,
            Generation::new(1).unwrap(),
            Generation::new(2).unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store
            .device(first.device_id)
            .unwrap()
            .generations
            .credential,
        Generation::new(2).unwrap()
    );
    assert_eq!(
        store
            .device_generations(second.device_id)
            .unwrap()
            .credential,
        Generation::new(1).unwrap()
    );
    store
        .record_revocation(
            &Revocation::requested(
                RevocationId::new(),
                network.network_id,
                first.device_id,
                chrono::Utc::now(),
            ),
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.revocation_state(first.device_id).unwrap(),
        RevocationState::Requested
    );
    assert_eq!(
        store.device(first.device_id).unwrap().membership_state,
        MembershipState::Revoking
    );
}

#[test]
fn join_sessions_are_durable_and_transition_with_audit() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    let now = chrono::Utc::now();
    let invitation = Invitation::new(
        InvitationId::new(),
        network.network_id,
        Roles::new([Role::Worker]).unwrap(),
        InvitationSecret::new("join-session-secret".to_owned())
            .unwrap()
            .verifier(),
        now,
        now + chrono::Duration::hours(1),
        1,
    )
    .unwrap();
    store
        .issue_invitation(&invitation, AuditActor::system())
        .unwrap();
    let session = JoinSession::new(
        JoinSessionId::new(),
        invitation.invitation_id,
        network.network_id,
        now,
        now + chrono::Duration::minutes(10),
    )
    .unwrap();
    store
        .create_join_session(&session, AuditActor::system())
        .unwrap();
    store
        .transition_join_session(
            session.join_session_id,
            JoinSessionState::Created,
            JoinSessionState::InvitationValidated,
            AuditActor::system(),
        )
        .unwrap();
    assert_eq!(
        store.join_session(session.join_session_id).unwrap().state,
        JoinSessionState::InvitationValidated
    );
}

#[test]
fn stale_concurrent_mutation_is_rejected() {
    let store = StateStore::open_in_memory().unwrap();
    let network = sample_network();
    store
        .create_network(&network, AuditActor::system())
        .unwrap();
    store
        .advance_membership_generation(
            network.network_id,
            Generation::new(1).unwrap(),
            Generation::new(2).unwrap(),
            AuditActor::system(),
        )
        .unwrap();
    assert!(matches!(
        store.advance_membership_generation(
            network.network_id,
            Generation::new(1).unwrap(),
            Generation::new(3).unwrap(),
            AuditActor::system()
        ),
        Err(StateError::StaleGeneration { .. })
    ));
}

#[test]
fn n1a_schema_upgrades_transactionally_to_current_schema() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("n1a-upgrade.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at)
             VALUES ('network-1','legacy','creating','headscale','provider-1',1,1,'{}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
             INSERT INTO provider_observations (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,observed_at,normalized_json)
             VALUES ('observation-1','network-1',NULL,'provider-1','node-1','machine-old','2026-01-01T00:00:00Z','{}');
             INSERT INTO provider_observations (observation_id,network_id,device_id,provider_instance_id,provider_node_id,stable_key_fingerprint,observed_at,normalized_json)
             VALUES ('observation-2','network-1',NULL,'provider-1','node-1','machine-new','2026-01-02T00:00:00Z','{}');",
        )
        .unwrap();
    connection
        .pragma_update(None, "user_version", 1_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
}
