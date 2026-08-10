use nodescale_redemption_ingress::{
    AdmissionDecision, AdmissionLimitError, AdmissionLimits, InMemoryAdmissionController,
};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

#[test]
fn defaults_are_bounded_and_start_with_one_attempt() {
    let limits = AdmissionLimits::safe_defaults();
    assert_eq!(limits.request_body_bytes(), 256);
    assert_eq!(limits.argon_concurrency(), 1);
    assert_eq!(limits.provider_create_concurrency(), 1);
    assert!(limits.worker_queue_capacity() <= 4);

    let now = Instant::now();
    let source: IpAddr = "192.0.2.10".parse().unwrap();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();
    assert_eq!(admission.admit(source, now), AdmissionDecision::Allowed);
    assert!(matches!(
        admission.admit(source, now),
        AdmissionDecision::Limited { .. }
    ));
}

#[test]
fn source_capacity_refills_without_exceeding_the_burst() {
    let limits = AdmissionLimits::safe_defaults();
    let refill = limits.source_refill_interval();
    let now = Instant::now();
    let source: IpAddr = "2001:db8::1".parse().unwrap();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();

    assert_eq!(admission.admit(source, now), AdmissionDecision::Allowed);
    assert!(matches!(
        admission.admit(source, now),
        AdmissionDecision::Limited { .. }
    ));
    assert_eq!(
        admission.admit(source, now + refill + Duration::from_millis(1)),
        AdmissionDecision::Allowed
    );
}

#[test]
fn source_rejection_does_not_consume_global_capacity() {
    let limits = AdmissionLimits::bounded(
        256,
        1,
        Duration::from_secs(30),
        2,
        Duration::from_secs(60),
        16,
        1,
    )
    .unwrap()
    .with_initial_tokens(1, 2)
    .unwrap();
    let now = Instant::now();
    let source_a: IpAddr = "192.0.2.10".parse().unwrap();
    let source_b: IpAddr = "192.0.2.11".parse().unwrap();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();

    assert_eq!(admission.admit(source_a, now), AdmissionDecision::Allowed);
    assert!(matches!(
        admission.admit(source_a, now),
        AdmissionDecision::Limited { .. }
    ));
    assert_eq!(admission.admit(source_b, now), AdmissionDecision::Allowed);
}

#[test]
fn global_rejection_does_not_consume_source_capacity() {
    let limits = AdmissionLimits::bounded(
        256,
        1,
        Duration::from_secs(30),
        1,
        Duration::from_secs(1),
        16,
        1,
    )
    .unwrap();
    let now = Instant::now();
    let source_a: IpAddr = "192.0.2.20".parse().unwrap();
    let source_b: IpAddr = "192.0.2.21".parse().unwrap();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();

    assert_eq!(admission.admit(source_a, now), AdmissionDecision::Allowed);
    assert!(matches!(
        admission.admit(source_b, now),
        AdmissionDecision::Limited { .. }
    ));
    assert_eq!(
        admission.admit(source_b, now + Duration::from_secs(1)),
        AdmissionDecision::Allowed
    );
}

#[test]
fn rotating_sources_cannot_allocate_unbounded_state() {
    let limits = AdmissionLimits::safe_defaults();
    let maximum = limits.maximum_tracked_sources();
    let now = Instant::now();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();

    for index in 1..=(maximum + 64) {
        let source = IpAddr::from([198, 51, (index / 255) as u8, (index % 255) as u8]);
        let _ = admission.admit(source, now);
    }

    assert!(admission.tracked_source_count() <= maximum);
}

#[test]
fn stale_sources_do_not_permanently_saturate_tracking_capacity() {
    let source_refill = Duration::from_secs(30);
    let limits = AdmissionLimits::bounded(256, 1, source_refill, 3, Duration::from_secs(1), 2, 1)
        .unwrap()
        .with_initial_tokens(1, 3)
        .unwrap();
    let now = Instant::now();
    let mut admission = InMemoryAdmissionController::new(limits, now).unwrap();

    assert_eq!(
        admission.admit("192.0.2.1".parse().unwrap(), now),
        AdmissionDecision::Allowed
    );
    assert_eq!(
        admission.admit("192.0.2.2".parse().unwrap(), now),
        AdmissionDecision::Allowed
    );
    assert_eq!(admission.tracked_source_count(), 2);

    let after_expiry = now + source_refill;
    assert_eq!(
        admission.admit("192.0.2.3".parse().unwrap(), after_expiry),
        AdmissionDecision::Allowed
    );
    assert_eq!(admission.tracked_source_count(), 2);
}

#[test]
fn configuration_is_bounded_by_hard_safety_ceilings() {
    let custom = AdmissionLimits::bounded(
        512,
        8,
        Duration::from_secs(10),
        32,
        Duration::from_millis(500),
        2_048,
        8,
    )
    .unwrap();
    assert_eq!(custom.request_body_bytes(), 512);
    assert_eq!(custom.maximum_tracked_sources(), 2_048);
    assert_eq!(custom.worker_queue_capacity(), 8);
    assert_eq!(custom.argon_concurrency(), 1);
    assert_eq!(custom.provider_create_concurrency(), 1);

    assert_eq!(
        AdmissionLimits::bounded(
            4_097,
            8,
            Duration::from_secs(10),
            32,
            Duration::from_millis(500),
            2_048,
            8,
        ),
        Err(AdmissionLimitError::OutOfRange("request_body_bytes"))
    );
    assert_eq!(
        AdmissionLimits::bounded(
            512,
            8,
            Duration::ZERO,
            32,
            Duration::from_millis(500),
            2_048,
            8,
        ),
        Err(AdmissionLimitError::OutOfRange("source_refill_interval"))
    );
}
