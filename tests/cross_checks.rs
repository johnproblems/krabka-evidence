//! Correctness proofs (#2–#12) over synthetic ledgers and reader probes.
//!
//! Each test builds the smallest ledger pair that exercises one improvement
//! and asserts the exact finding or note it produces, through the public
//! [`run_cross_checks`](krabka_evidence::checks::run_cross_checks) entry
//! point or the public ledger readers. Nothing here goes through the CLI:
//! these are behavior contracts on the checks themselves.

use std::{io::Write as _, path::PathBuf};

use assert_cmd::Command;
use bytes::{Bytes, BytesMut};
use krabka_audit::{
    event::AuditEventClass,
    ids::{CheckpointCount, RecordCount},
    sink::{HEADER_PREV_HASH, HEADER_SEQ},
    verify::VerifyReport,
};
use krabka_broker::operator_keys::OperatorKeys;
use krabka_evidence::{
    audit::{AdminRow, AuditLedger, AuditRow, ParsedAuditEvent, PrivilegedRow, read_audit_ledger},
    checks::{CheckInputs, run_cross_checks},
    finding::{CheckId, Finding, Note},
    fixture::generate_bulk_audit,
    keys::{TrustMaterial, load_trust},
    metadata::{MetadataLedger, MetadataRow, RelevantRecord},
    timeline::Window,
};
use krabka_metadata::{
    BreakGlassAction, BreakGlassApproval, BreakGlassProposalRecord, PatternType, TopicFreezeRecord,
};
use krabka_protocol::records::{Attributes, Record, RecordBatch, RecordHeader};
use uuid::Uuid;

/// Trust with no keys: signature checks are skipped, isolating the checks.
fn empty_trust() -> TrustMaterial {
    TrustMaterial {
        operators: OperatorKeys::load(&[]).expect("an empty operator set loads"),
        audit: krabka_audit::verify::TrustedKeys::default(),
        worm: krabka_remote_storage::TrustedManifestKeys::from_pairs(Vec::new()),
        has_operators: false,
        has_audit_keys: false,
        has_worm_keys: false,
        operator_count: 0,
        audit_count: 0,
        worm_count: 0,
    }
}

/// Generate the clean fixtures once per test-file run (shared across threads).
fn fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out =
            std::env::temp_dir().join(format!("krabka-evidence-xcheck-{}", std::process::id()));
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

/// Real fixture trust (operator keys provisioned) for signature-path tests.
fn fixture_trust() -> TrustMaterial {
    let out = fixtures();
    load_trust(&out.join("clean/keys/keys.toml"), &[], &[]).expect("fixture trust loads")
}

/// Run every cross-check over synthetic ledgers with the full window.
fn run_checks(
    audit_rows: Vec<AuditRow>,
    meta_rows: Vec<MetadataRow>,
    trust: &TrustMaterial,
    cluster_id: Option<&str>,
) -> (Vec<Finding>, Vec<Note>) {
    let audit = AuditLedger {
        verify_report: VerifyReport {
            records: RecordCount(0),
            checkpoints: CheckpointCount(0),
            ok: true,
            first_break: None,
            losses: Vec::new(),
            unanchored_records: RecordCount(0),
        },
        rows: audit_rows,
        checkpoints_verified: false,
    };
    let metadata = MetadataLedger {
        rows: meta_rows,
        decoded_records: 0,
        coverage_floor: None,
    };
    let window = Window {
        from_ms: i64::MIN,
        to_ms: i64::MAX,
    };
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    run_cross_checks(
        &CheckInputs {
            audit: &audit,
            metadata: &metadata,
            trust,
            window: &window,
            cluster_id,
        },
        &mut findings,
        &mut notes,
    );
    (findings, notes)
}

/// A privileged event with unsigned defaults; tests set what they need.
fn privileged() -> PrivilegedRow {
    PrivilegedRow {
        outcome: "success".to_string(),
        phase: "applied".to_string(),
        action: "delete_topic".to_string(),
        target: "orders".to_string(),
        proposal_id: String::new(),
        principal: "User:alice".to_string(),
        auth_method: "SCRAM".to_string(),
        counterparties: Vec::new(),
        approver_set_fingerprint: String::new(),
        key_id: String::new(),
        signature_hex: String::new(),
        signature_verified: false,
        signed_at_ms: 0,
        reason: String::new(),
    }
}

fn audit_row(offset: i64, time_ms: i64, event: PrivilegedRow) -> AuditRow {
    AuditRow {
        offset,
        time_ms,
        event: ParsedAuditEvent::Privileged(Box::new(event)),
    }
}

fn meta_row(offset: i64, record: RelevantRecord) -> MetadataRow {
    MetadataRow {
        offset,
        source: "test".to_string(),
        record,
    }
}

/// An unconsumed `DeleteTopic` proposal; tests set approvals and consumption.
fn proposal(id: &str) -> BreakGlassProposalRecord {
    BreakGlassProposalRecord {
        proposal_id: id.parse().expect("test proposal ids parse"),
        action: BreakGlassAction::DeleteTopic,
        target: "orders".to_string(),
        proposer: "User:alice".to_string(),
        reason: "test".to_string(),
        created_at_ms: 500,
        expires_at_ms: 5000,
        approvals: Vec::new(),
        consumed_at_ms: 0,
        withdrawn: false,
    }
}

fn approval(principal: &str, at_ms: i64) -> BreakGlassApproval {
    BreakGlassApproval {
        principal: principal.to_string(),
        approved_at_ms: at_ms,
        key_id: String::new(),
        signature: Vec::new(),
    }
}

/// An unsigned freeze of `literal:orders` by alice, stamped at 1000.
fn freeze() -> TopicFreezeRecord {
    TopicFreezeRecord {
        scope: "orders".to_string(),
        pattern_type: PatternType::Literal,
        frozen: true,
        reason: "test".to_string(),
        set_by: "User:alice".to_string(),
        set_at_ms: 1000,
        proposal_id: Uuid::nil(),
        key_id: String::new(),
        signature: Vec::new(),
    }
}

/// #5: a consumed proposal with one approval violates quorum.
#[test]
fn consumed_proposal_needs_two_approvals() {
    let trust = empty_trust();
    let mut single = proposal("33333333-3333-3333-3333-333333333333");
    single.consumed_at_ms = 1500;
    single.approvals = vec![approval("User:bob", 1000)];
    let (findings, _) = run_checks(
        Vec::new(),
        vec![meta_row(0, RelevantRecord::Proposal(single))],
        &trust,
        None,
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.detail.contains("needs two")),
        "quorum finding present: {findings:?}"
    );
}

/// #6: an approval stamped before creation is flagged.
#[test]
fn approval_before_creation_is_flagged() {
    let trust = empty_trust();
    let mut early = proposal("44444444-4444-4444-4444-444444444444");
    early.approvals = vec![approval("User:bob", 100), approval("User:carol", 1000)];
    let (findings, _) = run_checks(
        Vec::new(),
        vec![meta_row(0, RelevantRecord::Proposal(early))],
        &trust,
        None,
    );
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    assert!(
        findings[0].detail.contains("before it was created"),
        "names the violation: {findings:?}"
    );
}

/// #9: a freeze stamp after the event's own emit time is flagged, before any
/// signature work happens (no cluster id, garbage key).
#[test]
fn freeze_stamp_after_emit_is_flagged() {
    let trust = fixture_trust();
    let mut event = privileged();
    event.action = "set_topic_freeze".to_string();
    event.target = "literal:orders".to_string();
    event.phase = "attempted".to_string();
    event.signed_at_ms = 2000;
    event.key_id = "key-1".to_string();
    event.signature_hex = "00".repeat(64);
    let (findings, _) = run_checks(vec![audit_row(0, 1000, event)], Vec::new(), &trust, None);
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    assert_eq!(findings[0].title, "Signature timestamp after emit");
}

/// #2: a signed approve event naming a proposal the metadata log never held
/// is a finding. The signature is not even hex, proving the lookup runs
/// before any decoding.
#[test]
fn approve_event_naming_unknown_proposal_is_flagged() {
    let trust = fixture_trust();
    let mut event = privileged();
    event.phase = "approved".to_string();
    event.action = "delete_topic".to_string();
    event.proposal_id = "55555555-5555-5555-5555-555555555555".to_string();
    event.principal = "User:bob".to_string();
    event.key_id = "key-1".to_string();
    event.signature_hex = "zz".to_string();
    let (findings, _) = run_checks(vec![audit_row(3, 1000, event)], Vec::new(), &trust, None);
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    assert_eq!(findings[0].check, CheckId::AuditedActionNotInMetadata);
    assert!(
        findings[0].detail.contains("no metadata record"),
        "names the violation: {findings:?}"
    );
}

/// #3: a freeze-shaped event with a novel action string still routes to the
/// freeze path when its stamp is nonzero, its proposal empty, and its
/// counterparties empty. The classic action is the control.
#[test]
fn novel_freeze_shaped_action_routes_to_freeze_path() {
    let trust = empty_trust();
    for action in ["set_topic_freeze", "freeze_topic_v2"] {
        let mut event = privileged();
        event.action = action.to_string();
        event.target = "literal:orders".to_string();
        event.principal = "User:alice".to_string();
        event.signed_at_ms = 1000;
        let (findings, _) = run_checks(
            vec![audit_row(0, 1000, event)],
            vec![meta_row(0, RelevantRecord::Freeze(freeze()))],
            &trust,
            None,
        );
        assert!(
            findings.is_empty(),
            "action {action} matches with no findings: {findings:?}"
        );
    }
}

/// #4: a `Partition`-typed resource does not satisfy a `DeleteTopic`
/// proposal, even when the names overlap.
#[test]
fn gated_matching_ignores_wrong_typed_resources() {
    let trust = empty_trust();
    let mut covered = proposal("66666666-6666-6666-6666-666666666666");
    covered.consumed_at_ms = 1500;
    covered.approvals = vec![approval("User:bob", 1000), approval("User:carol", 1100)];
    let admin = AuditRow {
        offset: 7,
        time_ms: 2000,
        event: ParsedAuditEvent::Admin(AdminRow {
            outcome: "success".to_string(),
            principal: "User:alice".to_string(),
            operation: "DeleteTopic".to_string(),
            resources: vec![("Partition".to_string(), "orders-0".to_string())],
        }),
    };
    let (findings, _) = run_checks(
        vec![admin],
        vec![meta_row(0, RelevantRecord::Proposal(covered))],
        &trust,
        None,
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.title == "Gated op without approval"),
        "wrong-typed resources do not cover the op: {findings:?}"
    );
}

/// #7: an expiry sweep of a proposal the input never held is noted; a sweep
/// of a known proposal is silent.
#[test]
fn sweep_of_unknown_proposal_is_noted() {
    let trust = empty_trust();
    let known = "77777777-7777-7777-7777-777777777777";
    let rows = vec![
        meta_row(0, RelevantRecord::Proposal(proposal(known))),
        meta_row(
            1,
            RelevantRecord::DeleteProposal(known.parse().expect("test uuid parses")),
        ),
        meta_row(
            2,
            RelevantRecord::DeleteProposal(
                "88888888-8888-8888-8888-888888888888"
                    .parse()
                    .expect("test uuid parses"),
            ),
        ),
    ];
    let (findings, notes) = run_checks(Vec::new(), rows, &trust, None);
    assert!(findings.is_empty(), "sweeps are notes: {findings:?}");
    let sweeps: Vec<&Note> = notes
        .iter()
        .filter(|note| note.detail.contains("expiry sweep"))
        .collect();
    assert_eq!(
        sweeps.len(),
        1,
        "only the unknown sweep is noted: {notes:?}"
    );
    assert!(
        sweeps[0].detail.contains("compacted away"),
        "the note says why: {notes:?}"
    );
}

/// Run one freeze pair: a record stamped at 1000 by alice against an applied
/// event with the given principal and stamp.
fn freeze_pair_findings(principal: &str, stamp: i64, trust: &TrustMaterial) -> Vec<Finding> {
    let mut event = privileged();
    event.action = "set_topic_freeze".to_string();
    event.target = "literal:orders".to_string();
    event.principal = principal.to_string();
    event.signed_at_ms = stamp;
    run_checks(
        vec![audit_row(0, 1000, event)],
        vec![meta_row(0, RelevantRecord::Freeze(freeze()))],
        trust,
        None,
    )
    .0
}

/// #10: freeze matching requires principal and stamp equality.
#[test]
fn freeze_matching_requires_principal_and_stamp() {
    let trust = empty_trust();
    for (principal, stamp) in [("User:bob", 1000), ("User:alice", 2000)] {
        let findings = freeze_pair_findings(principal, stamp, &trust);
        assert!(
            findings
                .iter()
                .any(|finding| finding.check == CheckId::AppliedWithNoAuditEvent),
            "principal {principal} stamp {stamp} does not match: {findings:?}"
        );
    }
}

/// #11: an audit event stamped before its proposal was created is flagged.
#[test]
fn audit_event_before_proposal_creation_is_flagged() {
    let trust = empty_trust();
    let id = "99999999-9999-9999-9999-999999999999";
    let mut stored = proposal(id);
    stored.created_at_ms = 2000;
    let mut event = privileged();
    event.action = "delete_topic".to_string();
    event.proposal_id = id.to_string();
    let (findings, _) = run_checks(
        vec![audit_row(5, 1000, event)],
        vec![meta_row(0, RelevantRecord::Proposal(stored))],
        &trust,
        None,
    );
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    assert_eq!(findings[0].title, "Audit event predates proposal");
    assert_eq!(findings[0].audit_offset, Some(5));
}

/// #8: a loss marker the verifier never recorded (it broke on the marker's
/// bad seq) is still found from the decoded rows.
#[test]
fn loss_marker_past_verifier_stop_is_found_from_rows() {
    let out = fixtures();
    let work = out.join("loss-probe");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("probe dir creates");
    for name in ["00000000000000000000.log", "00000000000000000013.log"] {
        std::fs::copy(out.join("clean/audit").join(name), work.join(name))
            .expect("audit segment copies");
    }
    let loss = Record {
        attributes: 0,
        timestamp_delta: 0,
        offset_delta: 0,
        key: None,
        value: Some(Bytes::from_static(
            br#"{"records_lost":3,"loss_generation":1}"#,
        )),
        headers: vec![
            RecordHeader {
                key: "event_class".to_string(),
                value: Some(Bytes::from(
                    AuditEventClass::RecordsLost.as_header().as_bytes().to_vec(),
                )),
            },
            RecordHeader {
                key: HEADER_SEQ.to_string(),
                value: Some(Bytes::from_static(b"999")),
            },
            RecordHeader {
                key: HEADER_PREV_HASH.to_string(),
                value: Some(Bytes::from("00".repeat(32))),
            },
        ],
    };
    let batch = RecordBatch {
        base_offset: 17,
        partition_leader_epoch: 0,
        attributes: Attributes::default(),
        last_offset_delta: 0,
        base_timestamp: 1_789_434_000_000,
        max_timestamp: 1_789_434_000_000,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records: vec![loss],
    };
    let mut buffer = BytesMut::new();
    batch.encode(&mut buffer).expect("test batch encodes");
    std::fs::OpenOptions::new()
        .append(true)
        .open(work.join("00000000000000000013.log"))
        .expect("tail segment opens")
        .write_all(&buffer)
        .expect("loss marker appends");

    let trust = fixture_trust();
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    read_audit_ledger(&work, &trust, 1 << 30, &mut findings, &mut notes)
        .expect("a tampered partition still reads");
    let loss = findings
        .iter()
        .find(|finding| finding.title == "Audit declared records lost")
        .expect("the loss marker becomes a finding");
    assert_eq!(loss.audit_offset, Some(17));
    assert!(
        loss.detail.contains("the verifier stopped before it"),
        "the finding says where it came from: {loss:?}"
    );
}

/// #12: a partition with chained data but zero checkpoints gets a no-anchor
/// finding instead of a vacuous pass.
#[test]
fn partition_without_checkpoints_gets_no_anchor_finding() {
    let dir = std::env::temp_dir().join(format!("krabka-evidence-noanchor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = generate_bulk_audit(&dir.join("bulk"), 5).expect("bulk fixtures generate");
    let segment = paths.audit.join("00000000000000000000.log");
    let bytes = std::fs::read(&segment).expect("bulk segment reads");
    let mut cursor: &[u8] = &bytes;
    let mut batch = RecordBatch::decode(&mut cursor).expect("bulk batch decodes");
    assert_eq!(batch.records.len(), 6, "five events plus a checkpoint");
    batch.records.pop();
    batch.last_offset_delta = 4;
    let mut buffer = BytesMut::new();
    batch.encode(&mut buffer).expect("trimmed batch encodes");
    std::fs::write(&segment, buffer.freeze()).expect("trimmed segment writes");

    let trust = load_trust(&paths.keys, &[], &[]).expect("bulk trust loads");
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    read_audit_ledger(&paths.audit, &trust, 1 << 30, &mut findings, &mut notes)
        .expect("an unanchored partition still reads");
    assert!(
        findings
            .iter()
            .any(|finding| finding.title == "Audit chain has no signed anchor"),
        "no-anchor finding present: {findings:?}"
    );
}
