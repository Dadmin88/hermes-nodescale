use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, Network, NetworkId, ProviderCredentialId, ProviderCredentialReference,
    ProviderInstanceId, ProviderKind,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, ProviderError, ProviderHealth,
    ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_state::{
    ConfirmedProviderCredentialReference, HeadscaleImportConfig, MutationAuthorizationContext,
    ProviderMutationConfiguration, SUPPORTED_SCHEMA_VERSION, StateError, StateStore,
    TlsVerificationPolicy,
};
use std::collections::BTreeSet;
use tempfile::tempdir;

struct ImportedProvider {
    instance: ProviderInstanceId,
}

#[async_trait::async_trait]
impl ReadOnlyProvider for ImportedProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.instance
    }
    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.instance,
            compatibility: CompatibilityStatus::Compatible,
            capabilities: BTreeSet::new(),
            constraints: vec![],
            mutation_allowed: false,
        })
    }
    async fn list_nodes(&self) -> Result<Vec<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(vec![])
    }
    async fn get_node(
        &self,
        _: &nodescale_domain::ProviderIdentity,
    ) -> Result<Option<nodescale_provider::ProviderNode>, ProviderError> {
        Ok(None)
    }
    async fn provider_health(&self) -> Result<ProviderHealth, ProviderError> {
        unreachable!()
    }
}

fn now() -> DateTime<Utc> {
    "2026-08-07T00:00:00Z".parse().unwrap()
}

async fn imported_store() -> (StateStore, Network, ProviderInstanceId) {
    let store = StateStore::open_in_memory().unwrap();
    let instance = ProviderInstanceId::new();
    let network = Network::new(
        NetworkId::new(),
        "mutation-auth",
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .unwrap();
    let provider = ImportedProvider { instance };
    store
        .import_headscale_network(
            &network,
            &HeadscaleImportConfig::new(
                "https://headscale.example.test",
                instance,
                "secret://vault/nodescale#key",
                "v0.29.3",
                TlsVerificationPolicy::Verify,
            )
            .unwrap(),
            &provider,
            now(),
            AuditActor::system(),
        )
        .await
        .unwrap();
    (store, network, instance)
}

fn configuration(
    instance: ProviderInstanceId,
    capabilities: impl IntoIterator<Item = ProviderMutationCapability>,
) -> ProviderMutationConfiguration {
    ProviderMutationConfiguration::new(
        instance,
        Generation::new(1).unwrap(),
        Generation::new(1).unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "headscale",
        "v0.29.3",
        true,
        false,
        now() - Duration::minutes(1),
        now() + Duration::minutes(5),
        MutationPolicyMode::Database,
        capabilities,
    )
    .unwrap()
}

#[test]
fn v2_read_only_import_remains_non_authorizing_until_explicit_v3_configuration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("v2.db");
    let network = Network::new(
        NetworkId::new(),
        "legacy-v2",
        ProviderKind::Headscale,
        ProviderInstanceId::new(),
        now(),
    )
    .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../migrations/0002_discovery_reconciliation.sql"
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO networks (network_id,name,state,provider_kind,provider_instance_id,membership_generation,policy_generation,record_json,created_at,updated_at) VALUES (?1,?2,'creating','headscale',?3,1,1,?4,?5,?5)",
            rusqlite::params![
                network.network_id.to_string(),
                network.name,
                network.provider_instance_id.to_string(),
                serde_json::to_string(&network).unwrap(),
                now().to_rfc3339(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO membership_generations (network_id,generation,updated_at) VALUES (?1,1,?2)",
            rusqlite::params![network.network_id.to_string(), now().to_rfc3339()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_imports (network_id,provider_instance_id,server_url,opaque_secret_reference,compatibility_pin,tls_verification,read_only,mutation_allowed,compatibility,provider_version) VALUES (?1,?2,'https://headscale.invalid','secret-ref','v0.29.3','verify',1,0,'compatible','v0.29.3')",
            rusqlite::params![
                network.network_id.to_string(),
                network.provider_instance_id.to_string(),
            ],
        )
        .unwrap();
    connection
        .pragma_update(None, "user_version", 2_u32)
        .unwrap();
    drop(connection);

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SUPPORTED_SCHEMA_VERSION);
    assert!(matches!(
        store.issue_mutation_authorization(
            network.network_id,
            network.provider_instance_id,
            ProviderMutationCapability::DeleteNode,
            now(),
        ),
        Err(StateError::MutationAuthorizationDenied(_))
    ));
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            configuration(
                network.provider_instance_id,
                [ProviderMutationCapability::DeleteNode],
            ),
            AuditActor::system(),
        )
        .unwrap();
    assert!(
        store
            .issue_mutation_authorization(
                network.network_id,
                network.provider_instance_id,
                ProviderMutationCapability::DeleteNode,
                now(),
            )
            .is_ok()
    );
}

fn context(
    network: NetworkId,
    instance: ProviderInstanceId,
    capability: ProviderMutationCapability,
) -> MutationAuthorizationContext {
    MutationAuthorizationContext::headscale(
        network,
        instance,
        Generation::new(1).unwrap(),
        Generation::new(1).unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "v0.29.3",
        false,
        capability,
        MutationPolicyMode::Database,
        now(),
    )
}

#[tokio::test]
async fn configured_import_issues_one_exact_authorization_for_each_capability() {
    let (store, network, instance) = imported_store().await;
    let capabilities = [
        ProviderMutationCapability::EnsureNetworkPrincipal,
        ProviderMutationCapability::CreateJoinCredential,
        ProviderMutationCapability::InvalidateJoinCredential,
        ProviderMutationCapability::ReplaceNodeTags,
        ProviderMutationCapability::ExpireNode,
        ProviderMutationCapability::DeleteNode,
        ProviderMutationCapability::ManagePolicy,
    ];
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            configuration(instance, capabilities),
            AuditActor::system(),
        )
        .unwrap();
    for capability in capabilities {
        store
            .issue_mutation_authorization(network.network_id, instance, capability, now())
            .unwrap()
            .validate(context(network.network_id, instance, capability))
            .unwrap();
    }
}

#[tokio::test]
async fn issuance_and_consumption_fail_closed_for_configuration_and_context_mismatches() {
    let (store, network, instance) = imported_store().await;
    assert!(matches!(
        store.issue_mutation_authorization(
            network.network_id,
            instance,
            ProviderMutationCapability::DeleteNode,
            now()
        ),
        Err(StateError::MutationAuthorizationDenied(_))
    ));
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            configuration(instance, [ProviderMutationCapability::DeleteNode]),
            AuditActor::system(),
        )
        .unwrap();
    for actual in [
        context(
            NetworkId::new(),
            instance,
            ProviderMutationCapability::DeleteNode,
        ),
        context(
            network.network_id,
            ProviderInstanceId::new(),
            ProviderMutationCapability::DeleteNode,
        ),
        context(
            network.network_id,
            instance,
            ProviderMutationCapability::ExpireNode,
        ),
        MutationAuthorizationContext::headscale(
            network.network_id,
            instance,
            Generation::new(2).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "v0.29.3",
            false,
            ProviderMutationCapability::DeleteNode,
            MutationPolicyMode::Database,
            now(),
        ),
        MutationAuthorizationContext::headscale(
            network.network_id,
            instance,
            Generation::new(1).unwrap(),
            Generation::new(2).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "v0.29.3",
            false,
            ProviderMutationCapability::DeleteNode,
            MutationPolicyMode::Database,
            now(),
        ),
        MutationAuthorizationContext::headscale(
            network.network_id,
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "v0.29.3",
            false,
            ProviderMutationCapability::DeleteNode,
            MutationPolicyMode::Database,
            now(),
        ),
        MutationAuthorizationContext::headscale(
            network.network_id,
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "v0.29.4",
            false,
            ProviderMutationCapability::DeleteNode,
            MutationPolicyMode::Database,
            now(),
        ),
        MutationAuthorizationContext::headscale(
            network.network_id,
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "v0.29.3",
            true,
            ProviderMutationCapability::DeleteNode,
            MutationPolicyMode::Database,
            now(),
        ),
    ] {
        assert!(
            store
                .issue_mutation_authorization(
                    network.network_id,
                    instance,
                    ProviderMutationCapability::DeleteNode,
                    now()
                )
                .unwrap()
                .validate(actual)
                .is_err()
        );
    }
    assert!(matches!(
        store.replace_provider_mutation_configuration(
            network.network_id,
            Some(Generation::new(2).unwrap()),
            Some(Generation::new(1).unwrap()),
            configuration(instance, [ProviderMutationCapability::DeleteNode]),
            AuditActor::system(),
        ),
        Err(StateError::StaleGeneration { .. })
    ));
    assert!(matches!(
        store.replace_provider_mutation_configuration(
            network.network_id,
            Some(Generation::new(1).unwrap()),
            Some(Generation::new(1).unwrap()),
            configuration(instance, [ProviderMutationCapability::DeleteNode]),
            AuditActor::system(),
        ),
        Err(StateError::Conflict(_))
    ));
    assert!(matches!(
        store.replace_provider_mutation_configuration(
            network.network_id,
            Some(Generation::new(1).unwrap()),
            Some(Generation::new(1).unwrap()),
            configuration(
                ProviderInstanceId::new(),
                [ProviderMutationCapability::DeleteNode],
            ),
            AuditActor::system(),
        ),
        Err(StateError::Conflict(_))
    ));
}

#[tokio::test]
async fn revoked_and_expiry_equality_never_issue_authority() {
    for (revoked, expires_at) in [(true, now() + Duration::minutes(1)), (false, now())] {
        let (store, network, instance) = imported_store().await;
        let configuration = ProviderMutationConfiguration::new(
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "headscale",
            "v0.29.3",
            true,
            revoked,
            now() - Duration::minutes(1),
            expires_at,
            MutationPolicyMode::Database,
            [ProviderMutationCapability::DeleteNode],
        )
        .unwrap();
        store
            .replace_provider_mutation_configuration(
                network.network_id,
                None,
                None,
                configuration,
                AuditActor::system(),
            )
            .unwrap();
        assert!(matches!(
            store.issue_mutation_authorization(
                network.network_id,
                instance,
                ProviderMutationCapability::DeleteNode,
                now(),
            ),
            Err(StateError::MutationAuthorizationDenied(_))
        ));
    }
}

#[tokio::test]
async fn confirmed_credential_references_are_secret_free_and_authority_bound() {
    let (store, network, instance) = imported_store().await;
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            configuration(instance, [ProviderMutationCapability::CreateJoinCredential]),
            AuditActor::system(),
        )
        .unwrap();
    let credential_id = ProviderCredentialId::new();
    let reference = ConfirmedProviderCredentialReference::new(
        credential_id,
        network.network_id,
        instance,
        ProviderCredentialReference::new("provider-ref-42").unwrap(),
        Generation::new(1).unwrap(),
        Generation::new(1).unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now(),
        now() + Duration::minutes(5),
        1,
    )
    .unwrap();
    assert!(!format!("{reference:?}").contains("provider-ref-42"));
    store
        .record_confirmed_provider_credential_reference(&reference, AuditActor::system())
        .unwrap();
    assert_eq!(
        store
            .confirmed_provider_credential_reference(credential_id)
            .unwrap(),
        reference
    );
    assert!(
        store
            .record_confirmed_provider_credential_reference(&reference, AuditActor::system())
            .is_err()
    );

    let wrong_generation = ConfirmedProviderCredentialReference::new(
        ProviderCredentialId::new(),
        network.network_id,
        instance,
        ProviderCredentialReference::new("provider-ref-43").unwrap(),
        Generation::new(2).unwrap(),
        Generation::new(1).unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        now(),
        now() + Duration::minutes(5),
        1,
    )
    .unwrap();
    assert!(matches!(
        store.record_confirmed_provider_credential_reference(
            &wrong_generation,
            AuditActor::system(),
        ),
        Err(StateError::MutationAuthorizationDenied(_))
    ));
}

#[tokio::test]
async fn policy_is_only_configurable_for_database_mode_and_bad_inputs_are_rejected() {
    let (store, network, instance) = imported_store().await;
    assert!(
        ProviderMutationConfiguration::new(
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:UPPER",
            "headscale",
            "v0.29.3",
            true,
            false,
            now(),
            now() + Duration::minutes(1),
            MutationPolicyMode::Database,
            [ProviderMutationCapability::DeleteNode],
        )
        .is_err()
    );
    assert!(
        ProviderMutationConfiguration::new(
            instance,
            Generation::new(1).unwrap(),
            Generation::new(1).unwrap(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "headscale",
            "v0.29.3",
            true,
            false,
            now(),
            now() + Duration::minutes(1),
            MutationPolicyMode::File,
            [ProviderMutationCapability::ManagePolicy],
        )
        .is_err()
    );
    let disabled = ProviderMutationConfiguration::new(
        instance,
        Generation::new(1).unwrap(),
        Generation::new(1).unwrap(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "headscale",
        "v0.29.3",
        false,
        false,
        now(),
        now() + Duration::minutes(1),
        MutationPolicyMode::Database,
        [ProviderMutationCapability::DeleteNode],
    )
    .unwrap();
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            disabled,
            AuditActor::system(),
        )
        .unwrap();
    assert!(
        store
            .issue_mutation_authorization(
                network.network_id,
                instance,
                ProviderMutationCapability::DeleteNode,
                now()
            )
            .is_err()
    );
}
