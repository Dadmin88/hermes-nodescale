use chrono::{Duration, Utc};
use nodescale_domain::{Generation, NetworkId, ProviderCredentialReference, ProviderIdentity};
use nodescale_provider::{
    JoinCredentialRequest, MutationAmbiguity, MutationOutcome, MutationProvider, Provider,
    ProviderMutation, ProviderMutationCapability,
};
use nodescale_provider_fake::{
    AsyncFakeMutationProvider, FakeMutationAuthorization, FakeMutationScript, FakeProvider,
};

fn authorization(provider: &AsyncFakeMutationProvider) -> FakeMutationAuthorization {
    authorization_for(provider, ProviderMutationCapability::EnsureNetworkPrincipal)
}

fn authorization_for(
    provider: &AsyncFakeMutationProvider,
    capability: ProviderMutationCapability,
) -> FakeMutationAuthorization {
    FakeMutationAuthorization::new(
        provider.network_id(),
        provider.instance_id(),
        Generation::initial(),
        [capability],
        Utc::now() + Duration::minutes(1),
    )
}

fn seeded_node_provider(fixture: &str) -> (AsyncFakeMutationProvider, ProviderIdentity) {
    let mut provider = FakeProvider::compatible(fixture);
    let credential = provider
        .create_join_credential(&JoinCredentialRequest::single_use("worker"))
        .unwrap();
    let node = provider.observe_join(&credential, "worker-node").unwrap();
    (AsyncFakeMutationProvider::new(provider), node.identity)
}

#[tokio::test]
async fn fake_before_send_failure_does_not_apply_and_after_apply_is_read_back() {
    let provider = AsyncFakeMutationProvider::new(FakeProvider::compatible("mutation-fake"));
    let authorization = authorization(&provider);
    provider.script(
        ProviderMutationCapability::EnsureNetworkPrincipal,
        FakeMutationScript::BeforeSendUnavailable,
    );
    assert!(matches!(
        provider
            .execute_mutation(
                authorization.clone(),
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into()
                }
            )
            .await,
        MutationOutcome::Unavailable
    ));
    provider.script(
        ProviderMutationCapability::EnsureNetworkPrincipal,
        FakeMutationScript::AfterApplyResponseLoss,
    );
    assert!(matches!(
        provider
            .execute_mutation(
                authorization.clone(),
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker".into()
                }
            )
            .await,
        MutationOutcome::Confirmed { .. }
    ));
    provider.script(
        ProviderMutationCapability::EnsureNetworkPrincipal,
        FakeMutationScript::AfterApplyReadBackUnavailable,
    );
    assert!(matches!(
        provider
            .execute_mutation(
                authorization.clone(),
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker-2".into()
                }
            )
            .await,
        MutationOutcome::Ambiguous {
            reason: MutationAmbiguity::ReadBackUnavailable
        }
    ));
}

#[tokio::test]
async fn fake_create_response_loss_is_ambiguous_and_never_retried() {
    let provider = AsyncFakeMutationProvider::new(FakeProvider::compatible("credential-fake"));
    let authorization = FakeMutationAuthorization::new(
        provider.network_id(),
        provider.instance_id(),
        Generation::initial(),
        [ProviderMutationCapability::CreateJoinCredential],
        Utc::now() + Duration::minutes(1),
    );
    provider.script(
        ProviderMutationCapability::CreateJoinCredential,
        FakeMutationScript::AfterApplyResponseLoss,
    );
    assert!(matches!(
        provider
            .execute_mutation(
                authorization.clone(),
                ProviderMutation::CreateJoinCredential {
                    request: nodescale_provider::JoinCredentialRequest::single_use("worker"),
                }
            )
            .await,
        MutationOutcome::Ambiguous {
            reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable
        }
    ));
}

#[test]
fn fake_configuration_can_be_bound_to_an_explicit_network() {
    let network = NetworkId::new();
    let provider = AsyncFakeMutationProvider::configured(
        FakeProvider::compatible("bound"),
        network,
        Generation::initial(),
        true,
        nodescale_provider::MutationPolicyMode::Database,
    );
    assert_eq!(provider.network_id(), network);
}

#[tokio::test]
async fn fake_db_policy_is_deterministic_idempotent_and_traced_without_secret_material() {
    use nodescale_provider_fake::fake_policy_revision;
    let provider = AsyncFakeMutationProvider::new(FakeProvider::compatible("policy-fake"));
    let authorization = FakeMutationAuthorization::new(
        provider.network_id(),
        provider.instance_id(),
        Generation::initial(),
        [ProviderMutationCapability::ManagePolicy],
        Utc::now() + Duration::minutes(1),
    );
    let mutation = ProviderMutation::ApplyPolicy {
        expected_revision: fake_policy_revision("{}"),
        policy: "{\"acls\":[]}".into(),
    };
    assert!(matches!(
        provider
            .execute_mutation(authorization.clone(), mutation)
            .await,
        MutationOutcome::Confirmed { .. }
    ));
    let repeat = ProviderMutation::ApplyPolicy {
        expected_revision: fake_policy_revision("{\"acls\":[]}"),
        policy: "{\"acls\":[]}".into(),
    };
    assert!(matches!(
        provider
            .execute_mutation(authorization.clone(), repeat)
            .await,
        MutationOutcome::AlreadySatisfied { .. }
    ));
    assert_eq!(provider.mutation_dispatch_count(), 2);
    assert!(
        provider
            .mutation_trace()
            .iter()
            .all(|entry| entry.dispatched && entry.read_back)
    );
}

#[tokio::test]
async fn fake_file_and_unknown_policy_modes_make_zero_writes() {
    for mode in [
        nodescale_provider::MutationPolicyMode::File,
        nodescale_provider::MutationPolicyMode::Unknown,
    ] {
        let provider = AsyncFakeMutationProvider::configured(
            FakeProvider::compatible("policy-denied"),
            NetworkId::new(),
            Generation::initial(),
            true,
            mode,
        );
        let authorization = FakeMutationAuthorization::new(
            provider.network_id(),
            provider.instance_id(),
            Generation::initial(),
            [ProviderMutationCapability::ManagePolicy],
            Utc::now() + Duration::minutes(1),
        );
        assert!(matches!(
            provider
                .execute_mutation(
                    authorization.clone(),
                    ProviderMutation::ApplyPolicy {
                        expected_revision: "ignored".into(),
                        policy: "{}".into()
                    }
                )
                .await,
            MutationOutcome::Unsupported
        ));
        assert_eq!(provider.mutation_dispatch_count(), 0);
    }
}

#[tokio::test]
async fn fake_fifo_old_and_conflict_scripts_cover_every_mutation_family() {
    let principal_provider =
        AsyncFakeMutationProvider::new(FakeProvider::compatible("principal-fifo"));
    let principal_auth = authorization(&principal_provider);
    principal_provider.script(
        ProviderMutationCapability::EnsureNetworkPrincipal,
        FakeMutationScript::AfterApplyReadBackOld,
    );
    assert!(matches!(
        principal_provider
            .execute_mutation(
                principal_auth.clone(),
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker-old".into(),
                },
            )
            .await,
        MutationOutcome::Failed { retryable: true }
    ));
    principal_provider.script(
        ProviderMutationCapability::EnsureNetworkPrincipal,
        FakeMutationScript::AfterApplyReadBackConflict,
    );
    assert!(matches!(
        principal_provider
            .execute_mutation(
                principal_auth.clone(),
                ProviderMutation::EnsureNetworkPrincipal {
                    principal: "worker-conflict".into(),
                },
            )
            .await,
        MutationOutcome::Conflict
    ));

    for (fixture, script) in [
        ("create-old", FakeMutationScript::AfterApplyReadBackOld),
        (
            "create-conflict",
            FakeMutationScript::AfterApplyReadBackConflict,
        ),
    ] {
        let provider = AsyncFakeMutationProvider::new(FakeProvider::compatible(fixture));
        let capability = ProviderMutationCapability::CreateJoinCredential;
        provider.script(capability, script);
        assert!(matches!(
            provider
                .execute_mutation(
                    authorization_for(&provider, capability),
                    ProviderMutation::CreateJoinCredential {
                        request: JoinCredentialRequest::single_use("worker"),
                    },
                )
                .await,
            MutationOutcome::Ambiguous {
                reason: MutationAmbiguity::PotentiallyAppliedSecretUnavailable
            }
        ));
    }

    for (fixture, script, expected_conflict) in [
        (
            "revoke-old",
            FakeMutationScript::AfterApplyReadBackOld,
            false,
        ),
        (
            "revoke-conflict",
            FakeMutationScript::AfterApplyReadBackConflict,
            true,
        ),
    ] {
        let mut inner = FakeProvider::compatible(fixture);
        let issued = inner
            .create_join_credential(&JoinCredentialRequest::single_use("worker"))
            .unwrap();
        let reference = ProviderCredentialReference::new(issued.credential_id.to_string()).unwrap();
        let provider = AsyncFakeMutationProvider::new(inner);
        let capability = ProviderMutationCapability::InvalidateJoinCredential;
        provider.script(capability, script);
        let outcome = provider
            .execute_mutation(
                authorization_for(&provider, capability),
                ProviderMutation::RevokeJoinCredential {
                    credential: reference,
                },
            )
            .await;
        if expected_conflict {
            assert!(matches!(outcome, MutationOutcome::Conflict));
        } else {
            assert!(matches!(
                outcome,
                MutationOutcome::Failed { retryable: true }
            ));
        }
    }

    for (capability, mutation_name) in [
        (ProviderMutationCapability::ReplaceNodeTags, "tags"),
        (ProviderMutationCapability::ExpireNode, "expire"),
        (ProviderMutationCapability::DeleteNode, "delete"),
    ] {
        for (suffix, script, expected_conflict) in [
            ("old", FakeMutationScript::AfterApplyReadBackOld, false),
            (
                "conflict",
                FakeMutationScript::AfterApplyReadBackConflict,
                true,
            ),
        ] {
            let fixture = format!("{mutation_name}-{suffix}");
            let (provider, target) = seeded_node_provider(&fixture);
            provider.script(capability, script);
            let mutation = match capability {
                ProviderMutationCapability::ReplaceNodeTags => ProviderMutation::ReplaceNodeTags {
                    target,
                    tags: ["tag:nodescale-worker".to_owned()].into_iter().collect(),
                },
                ProviderMutationCapability::ExpireNode => ProviderMutation::ExpireNode { target },
                ProviderMutationCapability::DeleteNode => ProviderMutation::DeleteNode { target },
                _ => unreachable!(),
            };
            let outcome = provider
                .execute_mutation(authorization_for(&provider, capability), mutation)
                .await;
            if expected_conflict {
                assert!(matches!(outcome, MutationOutcome::Conflict));
            } else {
                assert!(matches!(
                    outcome,
                    MutationOutcome::Failed { retryable: true }
                ));
            }
        }
    }

    assert_eq!(principal_provider.mutation_dispatch_count(), 2);
    assert_eq!(principal_provider.mutation_trace().len(), 2);
}
