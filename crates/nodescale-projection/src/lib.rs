//! Production orchestration for N7's authenticated Fleet projection.
//!
//! Desired state is always the canonical `nodescale_domain::n7` value.  This
//! crate owns only the bounded, single-owner sequence that persists the exact
//! desired Fleet read-back and active N6 provenance before capability discovery
//! and dispatches through Fleet's authenticated local UDS adapter.

pub mod production {
    use std::{
        sync::{Mutex, mpsc as std_mpsc},
        thread,
    };

    use chrono::Utc;
    use nodescale_domain::n7::{
        FleetEnrollmentState, FleetProjectionOperation, N7FleetDesiredProjection,
    };
    use nodescale_domain::{Operation, OperationId};
    use nodescale_fleet_client::{
        ApplyError, ApplyOperation, ApplyResult, Capabilities, FleetClient, FleetClientError,
        GeneratedOperation, GeneratedState, GeneratedStateKind, InspectResult, InspectSelector,
        ProjectionDocument, ProjectionGenerations, Provenance, RequestKind,
    };
    use nodescale_state::{
        N7AuthoritativeInspection, N7ProjectionAttemptOutcome, N7ProjectionReservationOutcome,
        N7ProjectionState, N7ProjectionSubmission, N7ProjectionView, StateStore,
    };
    use thiserror::Error;
    use tokio::sync::oneshot;

    const COMMAND_BUFFER: usize = 16;

    /// Narrow transport seam retained solely for deterministic service tests.
    /// Production wiring uses the implementation for `nodescale_fleet_client::FleetClient`.
    #[allow(async_fn_in_trait)]
    pub trait FleetProjectionTransport: Send + 'static {
        async fn capabilities(&self) -> Result<Capabilities, FleetClientError>;
        async fn apply(&self, document: ProjectionDocument) -> Result<ApplyResult, ApplyError>;
        async fn inspect(
            &self,
            selector: InspectSelector,
        ) -> Result<InspectResult, FleetClientError>;
    }

    impl FleetProjectionTransport for FleetClient {
        async fn capabilities(&self) -> Result<Capabilities, FleetClientError> {
            self.capabilities().await
        }

        async fn apply(&self, document: ProjectionDocument) -> Result<ApplyResult, ApplyError> {
            self.apply(document).await
        }

        async fn inspect(
            &self,
            selector: InspectSelector,
        ) -> Result<InspectResult, FleetClientError> {
            self.inspect(selector).await
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum N7ProjectionOutcome {
        Applied,
        AlreadyApplied,
        Retryable,
        Conflict,
    }

    #[derive(Debug, Error, Eq, PartialEq)]
    pub enum N7ProductionError {
        #[error("N7 projection actor is unavailable")]
        ActorUnavailable,
        #[error("Fleet does not advertise the complete managed projection V1 contract")]
        UnsupportedFleet,
        #[error("N7 durable state error: {0}")]
        State(String),
    }

    enum Command {
        Reconcile {
            operation_id: OperationId,
            desired: N7FleetDesiredProjection,
            reply: oneshot::Sender<Result<N7ProjectionOutcome, N7ProductionError>>,
        },
    }

    /// Bounded single-owner lifecycle around a real `StateStore` and Fleet transport.
    ///
    /// A dedicated current-thread runtime owns the non-`Sync` SQLite store. The
    /// bounded command queue prevents unbounded work accumulation; `shutdown`
    /// closes ingress and joins the one owner before returning.
    pub struct N7ProjectionService<T> {
        sender: Mutex<Option<std_mpsc::SyncSender<Command>>>,
        join: Mutex<Option<thread::JoinHandle<()>>>,
        _transport: std::marker::PhantomData<T>,
    }

    impl<T> N7ProjectionService<T>
    where
        T: FleetProjectionTransport,
    {
        pub fn start(store: StateStore, transport: T) -> Result<Self, N7ProductionError> {
            let (sender, receiver) = std_mpsc::sync_channel(COMMAND_BUFFER);
            let join = thread::Builder::new()
                .name("nodescale-n7-projection".into())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("N7 actor runtime must initialize");
                    while let Ok(command) = receiver.recv() {
                        match command {
                            Command::Reconcile {
                                operation_id,
                                desired,
                                reply,
                            } => {
                                let outcome = runtime.block_on(reconcile_one(
                                    &store,
                                    &transport,
                                    operation_id,
                                    desired,
                                ));
                                let _ = reply.send(outcome);
                            }
                        }
                    }
                })
                .map_err(|_| N7ProductionError::ActorUnavailable)?;
            Ok(Self {
                sender: Mutex::new(Some(sender)),
                join: Mutex::new(Some(join)),
                _transport: std::marker::PhantomData,
            })
        }

        pub async fn reconcile(
            &self,
            operation_id: OperationId,
            desired: N7FleetDesiredProjection,
        ) -> Result<N7ProjectionOutcome, N7ProductionError> {
            let sender = self
                .sender
                .lock()
                .map_err(|_| N7ProductionError::ActorUnavailable)?
                .as_ref()
                .cloned()
                .ok_or(N7ProductionError::ActorUnavailable)?;
            let (reply, response) = oneshot::channel();
            sender
                .try_send(Command::Reconcile {
                    operation_id,
                    desired,
                    reply,
                })
                .map_err(|_| N7ProductionError::ActorUnavailable)?;
            response
                .await
                .map_err(|_| N7ProductionError::ActorUnavailable)?
        }

        pub async fn shutdown(&self) -> Result<(), N7ProductionError> {
            self.sender
                .lock()
                .map_err(|_| N7ProductionError::ActorUnavailable)?
                .take();
            let join = self
                .join
                .lock()
                .map_err(|_| N7ProductionError::ActorUnavailable)?
                .take();
            if let Some(join) = join {
                tokio::task::spawn_blocking(move || join.join())
                    .await
                    .map_err(|_| N7ProductionError::ActorUnavailable)?
                    .map_err(|_| N7ProductionError::ActorUnavailable)?;
            }
            Ok(())
        }
    }

    async fn reconcile_one<T>(
        store: &StateStore,
        transport: &T,
        operation_id: OperationId,
        desired: N7FleetDesiredProjection,
    ) -> Result<N7ProjectionOutcome, N7ProductionError>
    where
        T: FleetProjectionTransport,
    {
        let document = projection_document(&desired);
        let desired_body = expected_generated_body(&document, desired.enrollment_state())?;
        let submission = N7ProjectionSubmission::from_canonical(
            operation_id.clone(),
            desired.network_id(),
            desired.device_id(),
            desired.projection_generation(),
            desired_body,
            desired.binding_provenance().binding_id().to_string(),
            desired
                .binding_provenance()
                .authenticated_peer_id()
                .as_str(),
            desired.binding_provenance().binding_generation(),
        )
        .map_err(state_error)?;

        let reserved = store
            .reserve_n7_projection(&submission, Utc::now())
            .map_err(state_error)?;
        let view = match reserved {
            N7ProjectionReservationOutcome::Conflict => return Ok(N7ProjectionOutcome::Conflict),
            N7ProjectionReservationOutcome::Reserved(view)
            | N7ProjectionReservationOutcome::Replayed(view) => view,
        };
        match view.state {
            N7ProjectionState::Applied => return Ok(N7ProjectionOutcome::AlreadyApplied),
            N7ProjectionState::Conflict => return Ok(N7ProjectionOutcome::Conflict),
            N7ProjectionState::Desired | N7ProjectionState::Attempted => {}
        }

        ensure_capabilities(transport).await?;

        // An attempt may have reached Fleet before an earlier response was lost.
        // Always inspect it before considering a new apply, including after restart.
        if view.state == N7ProjectionState::Attempted {
            return inspect_and_recover(
                store,
                transport,
                &operation_id,
                &desired,
                &document,
                view,
                true,
            )
            .await;
        }

        let attempted = store
            .record_n7_projection_dispatch_attempt(
                &operation_id,
                desired.device_id(),
                desired.projection_generation(),
                view.revision,
                Utc::now(),
            )
            .map_err(state_error)?;
        let attempted = match attempted {
            N7ProjectionAttemptOutcome::Recorded(view)
            | N7ProjectionAttemptOutcome::Replayed(view) => view,
        };
        if attempted.state == N7ProjectionState::Applied {
            return Ok(N7ProjectionOutcome::AlreadyApplied);
        }
        if attempted.state == N7ProjectionState::Conflict {
            return Ok(N7ProjectionOutcome::Conflict);
        }
        if attempted.state != N7ProjectionState::Attempted {
            return Err(N7ProductionError::State(
                "N7 attempt was not durable before apply".into(),
            ));
        }

        match transport.apply(document.clone()).await {
            // A typed response is not authoritative completion: read-back remains mandatory.
            Ok(_) | Err(ApplyError::Ambiguous) | Err(ApplyError::ProtocolRejected) => {
                inspect_and_recover(
                    store,
                    transport,
                    &operation_id,
                    &desired,
                    &document,
                    attempted,
                    false,
                )
                .await
            }
            // No request was sent, so retain the durable attempt as retryable evidence.
            Err(ApplyError::Unavailable) | Err(ApplyError::RejectedBeforeSend) => {
                Ok(N7ProjectionOutcome::Retryable)
            }
        }
    }

    async fn ensure_capabilities<T>(transport: &T) -> Result<(), N7ProductionError>
    where
        T: FleetProjectionTransport,
    {
        let capabilities = transport
            .capabilities()
            .await
            .map_err(|error| N7ProductionError::State(format!("Fleet capabilities: {error}")))?;
        if [
            RequestKind::Capabilities,
            RequestKind::Apply,
            RequestKind::Inspect,
        ]
        .into_iter()
        .all(|required| capabilities.kinds.contains(&required))
        {
            Ok(())
        } else {
            Err(N7ProductionError::UnsupportedFleet)
        }
    }

    async fn inspect_and_recover<T>(
        store: &StateStore,
        transport: &T,
        operation_id: &OperationId,
        desired: &N7FleetDesiredProjection,
        document: &ProjectionDocument,
        view: N7ProjectionView,
        retry_dispatch_allowed: bool,
    ) -> Result<N7ProjectionOutcome, N7ProductionError>
    where
        T: FleetProjectionTransport,
    {
        let inspection = match transport
            .inspect(InspectSelector::new(
                desired.network_id().to_string(),
                desired.device_id().to_string(),
            ))
            .await
        {
            Ok(result) => inspection_from_result(result)?,
            Err(FleetClientError::Unavailable) => N7AuthoritativeInspection::unavailable(),
            Err(_) => N7AuthoritativeInspection::unavailable(),
        };
        let recovered = store
            .recover_n7_projection_from_inspection(
                operation_id,
                desired.device_id(),
                desired.projection_generation(),
                view.revision,
                inspection.clone(),
                Utc::now(),
            )
            .map_err(state_error)?;
        match recovered.state {
            N7ProjectionState::Applied => Ok(N7ProjectionOutcome::Applied),
            N7ProjectionState::Conflict => Ok(N7ProjectionOutcome::Conflict),
            N7ProjectionState::Desired | N7ProjectionState::Attempted => {
                match inspection {
                    // No authority read means no new request. A later reconciliation must
                    // begin from the same inspection boundary rather than blindly reapply.
                    N7AuthoritativeInspection::Unavailable => Ok(N7ProjectionOutcome::Retryable),
                    // A durable attempted operation is inspected before every retry. Only an
                    // authoritative missing result permits an append-only replacement attempt.
                    N7AuthoritativeInspection::Missing if retry_dispatch_allowed => {
                        let attempted = store
                            .record_n7_projection_dispatch_attempt(
                                operation_id,
                                desired.device_id(),
                                desired.projection_generation(),
                                recovered.revision,
                                Utc::now(),
                            )
                            .map_err(state_error)?;
                        let attempted = match attempted {
                            N7ProjectionAttemptOutcome::Recorded(view)
                            | N7ProjectionAttemptOutcome::Replayed(view) => view,
                        };
                        if attempted.state != N7ProjectionState::Attempted {
                            return Err(N7ProductionError::State(
                                "N7 retry attempt was not durable before apply".into(),
                            ));
                        }
                        match transport.apply(document.clone()).await {
                            Ok(_)
                            | Err(ApplyError::Ambiguous)
                            | Err(ApplyError::ProtocolRejected) => {
                                // This is the read-back for the newly appended retry attempt.
                                // A second Missing remains retryable; it never recursively turns
                                // one authority response into an unbounded apply loop.
                                let post_inspection = match transport
                                    .inspect(InspectSelector::new(
                                        desired.network_id().to_string(),
                                        desired.device_id().to_string(),
                                    ))
                                    .await
                                {
                                    Ok(result) => inspection_from_result(result)?,
                                    Err(_) => N7AuthoritativeInspection::unavailable(),
                                };
                                let post = store
                                    .recover_n7_projection_from_inspection(
                                        operation_id,
                                        desired.device_id(),
                                        desired.projection_generation(),
                                        attempted.revision,
                                        post_inspection,
                                        Utc::now(),
                                    )
                                    .map_err(state_error)?;
                                match post.state {
                                    N7ProjectionState::Applied => Ok(N7ProjectionOutcome::Applied),
                                    N7ProjectionState::Conflict => {
                                        Ok(N7ProjectionOutcome::Conflict)
                                    }
                                    N7ProjectionState::Desired | N7ProjectionState::Attempted => {
                                        Ok(N7ProjectionOutcome::Retryable)
                                    }
                                }
                            }
                            Err(ApplyError::Unavailable) | Err(ApplyError::RejectedBeforeSend) => {
                                Ok(N7ProjectionOutcome::Retryable)
                            }
                        }
                    }
                    N7AuthoritativeInspection::Missing
                    | N7AuthoritativeInspection::Observed { .. } => {
                        Ok(N7ProjectionOutcome::Retryable)
                    }
                }
            }
        }
    }

    fn inspection_from_result(
        result: InspectResult,
    ) -> Result<N7AuthoritativeInspection, N7ProductionError> {
        match result.generated {
            None => Ok(N7AuthoritativeInspection::missing()),
            Some(generated) => N7AuthoritativeInspection::observed(generated_body(&generated)?)
                .map_err(state_error),
        }
    }

    fn projection_document(desired: &N7FleetDesiredProjection) -> ProjectionDocument {
        ProjectionDocument::new(
            desired.network_id().to_string(),
            desired.device_id().to_string(),
            ProjectionGenerations::new(
                desired.projection_generation().get().to_string(),
                desired.membership_generation().get().to_string(),
                desired
                    .binding_provenance()
                    .binding_generation()
                    .get()
                    .to_string(),
            ),
            apply_operation(desired.operation()),
            desired
                .generated_grants()
                .iter()
                .map(generated_operation)
                .collect(),
            Provenance::new(
                desired.network_id().to_string(),
                desired.device_id().to_string(),
                desired.projection_generation().get().to_string(),
            ),
        )
    }

    fn apply_operation(operation: FleetProjectionOperation) -> ApplyOperation {
        match operation {
            FleetProjectionOperation::Upsert => ApplyOperation::Upsert,
            FleetProjectionOperation::Disable => ApplyOperation::Disable,
            FleetProjectionOperation::Remove => ApplyOperation::Remove,
        }
    }

    fn generated_operation(operation: Operation) -> GeneratedOperation {
        match operation {
            Operation::FleetHealth => GeneratedOperation::Health,
            Operation::FleetInventory => GeneratedOperation::Inventory,
            Operation::FleetMessage => GeneratedOperation::Message,
            _ => unreachable!("canonical N7 grants admit only Fleet non-execution operations"),
        }
    }

    fn expected_generated_body(
        document: &ProjectionDocument,
        enrollment: FleetEnrollmentState,
    ) -> Result<Vec<u8>, N7ProductionError> {
        generated_body_parts(
            generated_state(enrollment),
            &document.projection_generation,
            &document.membership_generation,
            &document.binding_generation,
            &document.content_hash,
            &document.generated_operations,
            &document.provenance,
        )
    }

    fn generated_body(generated: &GeneratedState) -> Result<Vec<u8>, N7ProductionError> {
        generated_body_parts(
            generated.state,
            &generated.projection_generation,
            &generated.membership_generation,
            &generated.binding_generation,
            &generated.content_hash,
            &generated.allowed_operations,
            &generated.provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn generated_body_parts(
        state: GeneratedStateKind,
        projection_generation: &str,
        membership_generation: &str,
        binding_generation: &str,
        content_hash: &str,
        allowed_operations: &[GeneratedOperation],
        provenance: &Provenance,
    ) -> Result<Vec<u8>, N7ProductionError> {
        // A serde_json map is key-canonicalized before StateStore accepts it;
        // every authoritative field Fleet returns is included in this equality proof.
        serde_json::to_vec(&serde_json::json!({
            "state": generated_state_name(state),
            "projection_generation": projection_generation,
            "membership_generation": membership_generation,
            "binding_generation": binding_generation,
            "content_hash": content_hash,
            "allowed_operations": allowed_operations,
            "provenance": provenance,
        }))
        .map_err(|error| N7ProductionError::State(format!("serialize Fleet read-back: {error}")))
    }

    const fn generated_state(enrollment: FleetEnrollmentState) -> GeneratedStateKind {
        match enrollment {
            FleetEnrollmentState::Pending => GeneratedStateKind::Active,
            FleetEnrollmentState::Disabled => GeneratedStateKind::Disabled,
            FleetEnrollmentState::Removed => GeneratedStateKind::Removed,
        }
    }

    const fn generated_state_name(state: GeneratedStateKind) -> &'static str {
        match state {
            GeneratedStateKind::Active => "active",
            GeneratedStateKind::Disabled => "disabled",
            GeneratedStateKind::Removed => "removed",
        }
    }

    fn state_error(error: impl std::fmt::Display) -> N7ProductionError {
        N7ProductionError::State(error.to_string())
    }
}
