use chrono::{DateTime, Duration, Utc};
use nodescale_domain::{
    AuditActor, Generation, InvitationToken, JoinConstraints, JoinSessionId, Network, NetworkId,
    ProviderInstanceId, ProviderKind, Role, Roles,
};
use nodescale_invitation::{
    CreateInvitationRequest, InvitationService, InvitationServiceError, N4AuthorizationIssuer,
    RedeemInvitationRequest,
};
use nodescale_provider::{
    CompatibilityStatus, MutationPolicyMode, Provider, ProviderError, ProviderHealth,
    ProviderMutationCapability, ReadOnlyProvider, ServerInspection,
};
use nodescale_provider_fake::{
    AsyncFakeMutationProvider, FakeMutationAuthorization, FakeMutationScript, FakeProvider,
};
use nodescale_state::{
    Failpoint, HeadscaleImportConfig, N4CleanupTarget, N4CredentialDispatch, N4PresentedMetadata,
    ProviderMutationConfiguration, StateError, StateStore, TlsVerificationPolicy,
};
use std::collections::BTreeSet;

const FINGERPRINT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn now() -> DateTime<Utc> {
    "2026-01-01T00:00:00Z".parse().expect("fixed timestamp")
}

struct ImportedProvider(ProviderInstanceId);
#[async_trait::async_trait]
impl ReadOnlyProvider for ImportedProvider {
    fn instance_id(&self) -> ProviderInstanceId {
        self.0
    }

    async fn inspect_server(&self) -> Result<ServerInspection, ProviderError> {
        Ok(ServerInspection {
            provider_name: "headscale".into(),
            provider_version: "v0.29.3".into(),
            instance_id: self.0,
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
        unreachable!("not used by invitation fixture")
    }
}

struct FakeIssuer;
impl N4AuthorizationIssuer<AsyncFakeMutationProvider> for FakeIssuer {
    fn begin_create(
        &self,
        store: &StateStore,
        join_session_id: JoinSessionId,
        now: DateTime<Utc>,
        actor: AuditActor,
    ) -> Result<(N4CredentialDispatch, FakeMutationAuthorization), StateError> {
        let dispatch = store.begin_n4_credential_dispatch(join_session_id, now, actor)?;
        let authorization = FakeMutationAuthorization::new(
            dispatch.network_id,
            dispatch.context.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::CreateJoinCredential],
            Utc::now() + Duration::minutes(1),
        );
        Ok((dispatch, authorization))
    }

    fn issue_invalidation(
        &self,
        _: &StateStore,
        target: &N4CleanupTarget,
        _now: DateTime<Utc>,
    ) -> Result<FakeMutationAuthorization, StateError> {
        Ok(FakeMutationAuthorization::new(
            target.network_id,
            target.provider_instance_id,
            Generation::initial(),
            [ProviderMutationCapability::InvalidateJoinCredential],
            Utc::now() + Duration::minutes(1),
        ))
    }
}

async fn fixture(name: &str) -> (StateStore, Network, AsyncFakeMutationProvider, FakeIssuer) {
    fixture_with_provider_controls(name, true, false).await
}

async fn fixture_with_provider_controls(
    name: &str,
    provider_enabled: bool,
    provider_degraded: bool,
) -> (StateStore, Network, AsyncFakeMutationProvider, FakeIssuer) {
    let store = StateStore::open_in_memory().expect("store opens");
    let mut fake = if provider_degraded {
        FakeProvider::degraded(name)
    } else {
        FakeProvider::compatible(name)
    };
    let instance = Provider::instance_id(&fake);
    let network = Network::new(
        NetworkId::new(),
        name,
        ProviderKind::Headscale,
        instance,
        now(),
    )
    .expect("network is valid");
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
            .expect("import config is valid"),
            &ImportedProvider(instance),
            now(),
            AuditActor::system(),
        )
        .await
        .expect("network imports");
    store
        .replace_provider_mutation_configuration(
            network.network_id,
            None,
            None,
            ProviderMutationConfiguration::new(
                instance,
                Generation::initial(),
                Generation::initial(),
                FINGERPRINT,
                "headscale",
                "v0.29.3",
                true,
                false,
                now() - Duration::minutes(1),
                now() + Duration::hours(1),
                MutationPolicyMode::Database,
                [
                    ProviderMutationCapability::CreateJoinCredential,
                    ProviderMutationCapability::InvalidateJoinCredential,
                ],
            )
            .expect("mutation configuration is valid"),
            AuditActor::system(),
        )
        .expect("mutation configuration persists");

    if !provider_degraded {
        Provider::ensure_network_principal(&mut fake, "principal-42").expect("principal exists");
    }
    let provider = AsyncFakeMutationProvider::configured(
        fake,
        network.network_id,
        Generation::initial(),
        provider_enabled,
        MutationPolicyMode::Database,
    );
    (store, network, provider, FakeIssuer)
}

fn create_request(network: &Network) -> CreateInvitationRequest {
    CreateInvitationRequest {
        network_id: network.network_id,
        provider_instance_id: network.provider_instance_id,
        provider_principal_id: "principal-42".into(),
        roles: Roles::new([Role::Worker]).unwrap(),
        admin_intent: None,
        join_constraints: JoinConstraints::default(),
        actor: AuditActor::system(),
    }
}

fn delivered_token(
    service: &InvitationService<'_, AsyncFakeMutationProvider, FakeIssuer>,
    network: &Network,
) -> (nodescale_domain::InvitationId, String) {
    let issued = service.create(create_request(network), now()).unwrap();
    let invitation_id = issued.view().invitation_id;
    let (_, token) = issued.deliver_token(str::to_owned);
    (invitation_id, token)
}

#[tokio::test]
async fn confirmed_redemption_returns_secret_once_and_replay_never_dispatches_again() {
    let (store, network, provider, issuer) = fixture("n4-redemption-success").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (invitation_id, raw_token) = delivered_token(&service, &network);

    let delivery = service
        .redeem(
            RedeemInvitationRequest {
                token: raw_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await
        .expect("credential is confirmed");
    assert!(!format!("{delivery:?}").contains(&raw_token));
    let (receipt, provider_secret) = delivery.deliver_once(str::to_owned);
    assert_eq!(receipt.invitation_id, invitation_id);
    assert_eq!(receipt.max_uses, 1);
    assert_eq!(provider.mutation_dispatch_count(), 1);
    assert!(
        !store
            .database_text_dump_for_test()
            .unwrap()
            .contains(&provider_secret)
    );
    assert_eq!(store.device_count(network.network_id).unwrap(), 0);
    assert_eq!(store.keryx_binding_count(network.network_id).unwrap(), 0);
    assert_eq!(store.fleet_projection_count(network.network_id).unwrap(), 0);

    let replay = service
        .redeem(
            RedeemInvitationRequest {
                token: raw_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(2),
        )
        .await;
    assert_eq!(replay.unwrap_err(), InvitationServiceError::Conflict);
    assert_eq!(provider.mutation_dispatch_count(), 1);
}

#[tokio::test]
async fn lost_create_response_is_ambiguous_nonreplayable_and_returns_no_secret() {
    let (store, network, provider, issuer) = fixture("n4-redemption-ambiguous").await;
    provider.script(
        ProviderMutationCapability::CreateJoinCredential,
        FakeMutationScript::AfterApplyResponseLoss,
    );
    let service = InvitationService::new(&store, &provider, &issuer);
    let (invitation_id, raw_token) = delivered_token(&service, &network);

    let result = service
        .redeem(
            RedeemInvitationRequest {
                token: raw_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await;
    assert_eq!(result.unwrap_err(), InvitationServiceError::Ambiguous);
    assert_eq!(provider.mutation_dispatch_count(), 1);
    assert_eq!(
        service.show(invitation_id).unwrap().state,
        nodescale_domain::InvitationState::Failed
    );

    let replay = service
        .redeem(
            RedeemInvitationRequest {
                token: raw_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(2),
        )
        .await;
    assert_eq!(replay.unwrap_err(), InvitationServiceError::Conflict);
    assert_eq!(provider.mutation_dispatch_count(), 1);
}

#[tokio::test]
async fn confirmed_create_with_local_confirmation_failure_is_immediately_contained() {
    let (store, network, provider, issuer) = fixture("n4-confirm-containment").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (_invitation_id, token) = delivered_token(&service, &network);
    store.set_failpoint(Failpoint::BeforeN4ConfirmationAudit, true);

    let result = service
        .redeem(
            RedeemInvitationRequest {
                token: token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await;

    assert_eq!(result.unwrap_err(), InvitationServiceError::Ambiguous);
    assert_eq!(provider.mutation_dispatch_count(), 2);
    assert_eq!(
        provider
            .mutation_trace()
            .iter()
            .map(|entry| entry.capability)
            .collect::<Vec<_>>(),
        vec![
            ProviderMutationCapability::CreateJoinCredential,
            ProviderMutationCapability::InvalidateJoinCredential,
        ]
    );
}

#[tokio::test]
async fn pre_apply_provider_failures_are_redacted_and_terminal() {
    let scenarios = [
        (
            "n4-unavailable",
            FakeMutationScript::BeforeSendUnavailable,
            InvitationServiceError::ProviderUnavailable,
        ),
        (
            "n4-auth-failed",
            FakeMutationScript::BeforeSendAuthenticationFailed,
            InvitationServiceError::AuthenticationFailed,
        ),
        (
            "n4-rejected",
            FakeMutationScript::BeforeSendRejected,
            InvitationServiceError::ProviderRejected,
        ),
        (
            "n4-conflict",
            FakeMutationScript::BeforeSendConflict,
            InvitationServiceError::ProviderRejected,
        ),
    ];
    for (name, script, expected) in scenarios {
        let (store, network, provider, issuer) = fixture(name).await;
        let service = InvitationService::new(&store, &provider, &issuer);
        let (invitation_id, token) = delivered_token(&service, &network);
        provider.script(ProviderMutationCapability::CreateJoinCredential, script);
        let result = service
            .redeem(
                RedeemInvitationRequest {
                    token: token.parse::<InvitationToken>().unwrap(),
                    presented: N4PresentedMetadata::default(),
                    actor: AuditActor::system(),
                },
                now() + Duration::seconds(1),
            )
            .await;
        assert_eq!(result.unwrap_err(), expected, "scenario {name}");
        assert_eq!(
            service.show(invitation_id).unwrap().state,
            nodescale_domain::InvitationState::Failed,
            "scenario {name}"
        );
    }
}

#[tokio::test]
async fn provider_compatibility_gate_is_reported_without_a_secret() {
    let (store, network, provider, issuer) =
        fixture_with_provider_controls("n4-compatibility", true, true).await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (invitation_id, token) = delivered_token(&service, &network);
    let result = service
        .redeem(
            RedeemInvitationRequest {
                token: token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await;
    assert_eq!(
        result.unwrap_err(),
        InvitationServiceError::CompatibilityBlocked
    );
    assert_eq!(
        service.show(invitation_id).unwrap().state,
        nodescale_domain::InvitationState::Failed
    );
}

#[tokio::test]
async fn revocation_invalidates_the_exact_credential_and_reconciliation_is_conservative() {
    let (store, network, provider, issuer) = fixture("n4-revocation").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (invitation_id, raw_token) = delivered_token(&service, &network);
    let delivery = service
        .redeem(
            RedeemInvitationRequest {
                token: raw_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await
        .unwrap();
    let _ = delivery.deliver_once(|_| ());

    provider.script(
        ProviderMutationCapability::InvalidateJoinCredential,
        FakeMutationScript::AfterApplyReadBackUnavailable,
    );
    let uncertain = service
        .revoke(
            invitation_id,
            now() + Duration::seconds(2),
            AuditActor::system(),
        )
        .await;
    assert_eq!(uncertain.unwrap_err(), InvitationServiceError::Ambiguous);
    let pending = service.show(invitation_id).unwrap();
    assert_eq!(pending.state, nodescale_domain::InvitationState::Revoking);
    assert_eq!(
        pending.cleanup_state,
        nodescale_state::N4CleanupState::Ambiguous
    );

    let reconciled = service
        .revoke(
            invitation_id,
            now() + Duration::seconds(3),
            AuditActor::system(),
        )
        .await
        .expect("already-invalid provider credential reconciles");
    assert_eq!(reconciled.state, nodescale_domain::InvitationState::Revoked);
    assert_eq!(
        reconciled.cleanup_state,
        nodescale_state::N4CleanupState::Confirmed
    );
    assert_eq!(provider.mutation_dispatch_count(), 2);
}

#[tokio::test]
async fn unredeemed_expiry_is_terminal_without_provider_mutation() {
    let (store, network, provider, issuer) = fixture("n4-expiry").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (invitation_id, _) = delivered_token(&service, &network);

    let expired = service
        .expire(
            invitation_id,
            now() + Duration::minutes(16),
            AuditActor::system(),
        )
        .await
        .expect("unredeemed invitation expires locally");
    assert_eq!(expired.state, nodescale_domain::InvitationState::Expired);
    assert_eq!(provider.mutation_dispatch_count(), 0);
}

#[tokio::test]
async fn one_shot_expiry_reconciles_all_due_invitations() {
    let (store, network, provider, issuer) = fixture("n4-expiry-reconciler").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let (first_id, first_token) = delivered_token(&service, &network);
    let (second_id, _) = delivered_token(&service, &network);
    let delivery = service
        .redeem(
            RedeemInvitationRequest {
                token: first_token.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await
        .unwrap();
    delivery.deliver_once(|_| ());

    let report = service
        .expire_due(now() + Duration::minutes(16), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(report.settled.len(), 2);
    assert!(report.pending.is_empty());
    assert_eq!(
        service.show(first_id).unwrap().state,
        nodescale_domain::InvitationState::Expired
    );
    assert_eq!(
        service.show(second_id).unwrap().state,
        nodescale_domain::InvitationState::Expired
    );
    assert_eq!(provider.mutation_dispatch_count(), 2);
}

#[tokio::test]
async fn expiry_reconciliation_does_not_starve_later_invitations() {
    let (store, network, provider, issuer) = fixture("n4-expiry-no-starvation").await;
    let service = InvitationService::new(&store, &provider, &issuer);
    let first = delivered_token(&service, &network);
    let second = delivered_token(&service, &network);
    let (with_credential, local_only) = if first.0.to_string() < second.0.to_string() {
        (first, second)
    } else {
        (second, first)
    };
    let delivery = service
        .redeem(
            RedeemInvitationRequest {
                token: with_credential.1.parse::<InvitationToken>().unwrap(),
                presented: N4PresentedMetadata::default(),
                actor: AuditActor::system(),
            },
            now() + Duration::seconds(1),
        )
        .await
        .unwrap();
    delivery.deliver_once(|_| ());
    provider.script(
        ProviderMutationCapability::InvalidateJoinCredential,
        FakeMutationScript::AfterApplyReadBackUnavailable,
    );

    let report = service
        .expire_due(now() + Duration::minutes(16), AuditActor::system())
        .await
        .unwrap();
    assert_eq!(report.pending.len(), 1);
    assert_eq!(report.pending[0].invitation_id, with_credential.0);
    assert_eq!(report.pending[0].error, InvitationServiceError::Ambiguous);
    assert!(
        report
            .settled
            .iter()
            .any(|view| view.invitation_id == local_only.0)
    );
    assert_eq!(
        service.show(with_credential.0).unwrap().state,
        nodescale_domain::InvitationState::Expiring
    );
    assert_eq!(
        service.show(local_only.0).unwrap().state,
        nodescale_domain::InvitationState::Expired
    );
    assert_eq!(provider.mutation_dispatch_count(), 2);
}
