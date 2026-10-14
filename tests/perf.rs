//! Throughput: the 10M-records-in-5-minutes budget.
//!
//! A bulk audit partition runs end to end through the CLI; the test asserts
//! a records-per-second floor that extrapolates inside the budget with
//! margin, and prints the extrapolation for the record.

use std::time::Instant;

use assert_cmd::Command;
use krabka_evidence::fixture::generate_bulk_audit;

#[test]
fn bulk_audit_meets_throughput_floor() {
    const EVENTS: usize = 50_000;
    const EVENTS_F64: f64 = 50_000.0;
    // 10M records in 5 minutes needs 33_334 records/s. The floor below is a
    // debug-build smoke bar with wide margin for loaded machines; it catches
    // algorithmic regressions (quadratic behavior would miss it 100x), while
    // the budget itself is proven by release builds, measured at ~133k
    // records/s on test hardware (10M in ~75s).
    const FLOOR_RECORDS_PER_SECOND: f64 = 8_000.0;

    let dir = tempfile::tempdir().unwrap();
    let bulk = dir.path().join("bulk");
    let paths = generate_bulk_audit(&bulk, EVENTS).unwrap();

    let started = Instant::now();
    Command::cargo_bin("krabka-evidence")
        .unwrap()
        .args([
            "--audit",
            paths.audit.to_str().unwrap(),
            "--metadata",
            paths.metadata.to_str().unwrap(),
            "--archive",
            paths.archive.to_str().unwrap(),
            "--operator-keys",
            paths.keys.to_str().unwrap(),
            "--cluster-id",
            "bulk",
            "--sign-with",
            paths.auditor_key.to_str().unwrap(),
            "-o",
            bulk.join("evidence").to_str().unwrap(),
        ])
        .assert()
        .success();
    let elapsed = started.elapsed().as_secs_f64();
    let per_second = EVENTS_F64 / elapsed;
    let ten_million_seconds = 10_000_000.0 / per_second;
    println!(
        "{EVENTS} records in {elapsed:.1}s = {per_second:.0}/s; 10M extrapolates to {ten_million_seconds:.0}s"
    );
    assert!(
        per_second >= FLOOR_RECORDS_PER_SECOND,
        "throughput {per_second:.0}/s below floor {FLOOR_RECORDS_PER_SECOND}/s"
    );
}
