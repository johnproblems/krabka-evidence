//! Robustness proofs (#13–#16) against the public ledger readers.
//!
//! Size caps, truncation points, skip counts, and layout mixing are asserted
//! by copying fixture inputs aside, damaging the copies, and reading them
//! back. The shared fixtures stay pristine.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use bytes::BytesMut;
use krabka_evidence::{
    audit::read_audit_ledger,
    finding::{Finding, Note},
    keys::{TrustMaterial, load_trust},
    metadata::read_metadata_ledger,
};
use krabka_protocol::records::{Attributes, Record, RecordBatch};

/// Generate the clean fixtures once per test-file run (shared across threads).
fn fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out =
            std::env::temp_dir().join(format!("krabka-evidence-robust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        Command::cargo_bin("krabka-evidence")
            .expect("the binary builds")
            .args(["fixture", "--scenario", "clean", "--out"])
            .arg(&out)
            .assert()
            .success();
        out
    })
    .clone()
}

fn fixture_trust() -> TrustMaterial {
    let out = fixtures();
    load_trust(&out.join("clean/keys/keys.toml"), &[], &[]).expect("fixture trust loads")
}

/// Copy a ledger directory aside for damage.
fn copy_dir(src: &Path, name: &str) -> PathBuf {
    let out = fixtures();
    let work = out.join(name);
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("probe dir creates");
    for entry in std::fs::read_dir(src).expect("ledger dir reads") {
        let entry = entry.expect("ledger entry reads");
        std::fs::copy(entry.path(), work.join(entry.file_name())).expect("ledger file copies");
    }
    work
}

/// #13: files over `--max-segment-bytes` are refused, not buffered.
#[test]
fn readers_refuse_over_cap_files() {
    let out = fixtures();
    let trust = fixture_trust();
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    let audit_error = read_audit_ledger(
        &out.join("clean/audit"),
        &trust,
        10,
        &mut findings,
        &mut notes,
    )
    .expect_err("a 10-byte cap refuses the audit segments");
    assert!(
        audit_error.to_string().contains("--max-segment-bytes"),
        "the error names the flag: {audit_error}"
    );
    let meta_error =
        read_metadata_ledger(&out.join("clean/metadata"), 10, &mut findings, &mut notes)
            .expect_err("a 10-byte cap refuses the metadata segments");
    assert!(
        meta_error.to_string().contains("--max-segment-bytes"),
        "the error names the flag: {meta_error}"
    );
}

/// #14: undecodable tails are noted with their truncation point.
#[test]
fn readers_note_truncation_points() {
    let out = fixtures();
    let trust = fixture_trust();

    let audit = copy_dir(&out.join("clean/audit"), "trunc-audit");
    let tail = audit.join("00000000000000000013.log");
    let bytes = std::fs::read(&tail).expect("tail segment reads");
    std::fs::write(&tail, &bytes[..bytes.len() - 100]).expect("tail segment truncates");
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    read_audit_ledger(&audit, &trust, 1 << 30, &mut findings, &mut notes)
        .expect("a truncated partition still reads");
    assert!(
        notes
            .iter()
            .any(|note| note.detail.contains("ends mid-batch at byte")),
        "audit truncation is noted: {notes:?}"
    );

    let metadata = copy_dir(&out.join("clean/metadata"), "trunc-meta");
    let segment = metadata.join("00000000000000000000.log");
    let bytes = std::fs::read(&segment).expect("metadata segment reads");
    std::fs::write(&segment, &bytes[..bytes.len() - 50]).expect("metadata segment truncates");
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    read_metadata_ledger(&metadata, 1 << 30, &mut findings, &mut notes)
        .expect("truncated metadata still reads");
    assert!(
        notes
            .iter()
            .any(|note| note.detail.contains("ends mid-batch at byte")),
        "metadata truncation is noted: {notes:?}"
    );
}

/// #15: tombstone and undecodable metadata records are counted, not silent.
#[test]
fn skipped_metadata_records_are_counted() {
    let out = fixtures();
    let metadata = copy_dir(&out.join("clean/metadata"), "skip-meta");
    let tombstone = Record {
        attributes: 0,
        timestamp_delta: 0,
        offset_delta: 0,
        key: None,
        value: None,
        headers: Vec::new(),
    };
    let batch = RecordBatch {
        base_offset: 4,
        partition_leader_epoch: 0,
        attributes: Attributes::default(),
        last_offset_delta: 0,
        base_timestamp: 1_789_434_000_000,
        max_timestamp: 1_789_434_000_000,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records: vec![tombstone],
    };
    let mut buffer = BytesMut::new();
    batch.encode(&mut buffer).expect("test batch encodes");
    std::fs::OpenOptions::new()
        .append(true)
        .open(metadata.join("00000000000000000000.log"))
        .expect("metadata segment opens")
        .write_all(&buffer)
        .expect("tombstone appends");

    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    read_metadata_ledger(&metadata, 1 << 30, &mut findings, &mut notes)
        .expect("metadata with a tombstone still reads");
    assert!(
        notes
            .iter()
            .any(|note| note.detail.contains("were skipped")),
        "skips are counted: {notes:?}"
    );
}

/// #16: an input mixing segments and snapshots says so.
#[test]
fn segments_and_snapshots_mix_is_noted() {
    let out = fixtures();
    let metadata = copy_dir(&out.join("clean/metadata"), "mix-meta");
    std::fs::copy(
        metadata.join("00000000000000000000.log"),
        metadata.join("00000000000000000004.checkpoint"),
    )
    .expect("segment copies as a snapshot");
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    read_metadata_ledger(&metadata, 1 << 30, &mut findings, &mut notes)
        .expect("a mixed input still reads");
    assert!(
        notes
            .iter()
            .any(|note| note.detail.contains("mixes log segments and snapshots")),
        "the mix is noted: {notes:?}"
    );
}
