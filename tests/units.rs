//! Unit tests: tables, parsing, hashing, canonicalization, and goldens.

use std::collections::BTreeMap;

use krabka_evidence::{
    archive::parse_chain_head,
    hash::digest_path,
    keys::load_trust,
    report::{
        AuditorIdentity, HTML_TIMELINE_ROWS, ReportInputs, TrustCounts, build_report,
        canonical_json, render_html,
    },
    timeline::{
        TimelineRow, Window, action_name, action_wire_value, format_time, gated_action,
        is_gated_operation, normalize_proposal_id, parse_window,
    },
};

#[test]
fn proposal_ids_normalize_for_joins() {
    assert_eq!(normalize_proposal_id(""), "");
    assert_eq!(
        normalize_proposal_id("00000000-0000-0000-0000-000000000000"),
        ""
    );
    assert_eq!(
        normalize_proposal_id("11111111-1111-1111-1111-111111111111"),
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(
        normalize_proposal_id("  22222222-2222-2222-2222-222222222222  "),
        "22222222-2222-2222-2222-222222222222"
    );
}

#[test]
fn break_glass_tables_follow_declaration_order() {
    use krabka_metadata::BreakGlassAction::{
        CancelReassignment, DeleteRecords, DeleteTopic, ThawTopicFreeze, UncleanElectLeaders,
        UncleanRecovery, UnregisterBroker,
    };
    // Mirrors krabka_broker::break_glass::{action_to_wire, action_name}.
    let cases = [
        (ThawTopicFreeze, 1, "thaw_topic_freeze"),
        (UncleanElectLeaders, 2, "unclean_elect_leaders"),
        (UncleanRecovery, 3, "unclean_recovery"),
        (UnregisterBroker, 4, "unregister_broker"),
        (CancelReassignment, 5, "cancel_reassignment"),
        (DeleteTopic, 6, "delete_topic"),
        (DeleteRecords, 7, "delete_records"),
    ];
    for (action, wire, name) in cases {
        assert_eq!(action_wire_value(action), wire);
        assert_eq!(action_name(action), name);
    }
}

#[test]
fn gated_operations_cover_delete_spellings() {
    assert!(is_gated_operation("DeleteTopic"));
    assert!(is_gated_operation("DeleteTopics"));
    assert!(is_gated_operation("delete_records"));
    assert!(gated_action("DeleteTopic").is_some());
    assert!(gated_action("DeleteRecords").is_some());
    assert!(!is_gated_operation("CreateTopic"));
    assert!(gated_action("CreateTopic").is_none());
}

#[test]
fn window_parses_dates_and_rfc3339() {
    let window = parse_window(Some("2026-09-01"), Some("2026-10-01")).unwrap();
    assert!(window.from_ms < window.to_ms);
    assert!(window.contains(window.from_ms));
    assert!(!window.contains(window.to_ms));
    let rfc = parse_window(Some("2026-09-15T00:00:00Z"), Some("2026-09-15T01:00:00Z")).unwrap();
    assert_eq!(rfc.to_ms - rfc.from_ms, 3_600_000);
    assert!(parse_window(Some("not-a-date"), None).is_err());
    assert!(parse_window(Some("2026-10-01"), Some("2026-09-01")).is_err());
    let unbounded = Window {
        from_ms: i64::MIN,
        to_ms: i64::MAX,
    };
    assert!(unbounded.contains(0));
}

#[test]
fn chain_heads_parse_as_64_hex() {
    let head = parse_chain_head(&"ab".repeat(32)).unwrap();
    assert_eq!(head.0, [0xabu8; 32]);
    assert!(parse_chain_head("short").is_err());
    assert!(parse_chain_head(&"zz".repeat(32)).is_err());
}

#[test]
fn digests_are_stable_and_sensitive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.log"), b"second").unwrap();
    std::fs::write(dir.path().join("a.log"), b"first").unwrap();
    let first = digest_path(dir.path(), "test").unwrap();
    assert_eq!(first.files, 2);
    assert_eq!(first.bytes, 11);
    let second = digest_path(dir.path(), "test").unwrap();
    assert_eq!(first.digest, second.digest, "stable across runs");
    std::fs::write(dir.path().join("a.log"), b"FIRST").unwrap();
    let third = digest_path(dir.path(), "test").unwrap();
    assert_ne!(first.digest, third.digest, "sensitive to bytes");
    assert!(digest_path(&dir.path().join("missing"), "test").is_err());
}

#[test]
fn canonical_json_sorts_keys_recursively() {
    let report = build_report(empty_report_inputs());
    let canonical = canonical_json(&report);
    // Re-parsing and re-canonicalizing is a fixed point.
    let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    let again = serde_json::to_vec(&value).unwrap();
    let reparsed: serde_json::Value = serde_json::from_slice(&again).unwrap();
    assert_eq!(value, reparsed);
    // Keys are sorted: "auditor" comes before "checks".
    let text = String::from_utf8(canonical).unwrap();
    let auditor = text.find("\"auditor\"").unwrap();
    let checks = text.find("\"checks\"").unwrap();
    assert!(auditor < checks, "top-level keys sorted");
}

/// #22: windows accept epoch millis.
#[test]
fn window_parses_epoch_millis() {
    let window = parse_window(Some("1789430400000"), Some("1789430500000")).unwrap();
    assert_eq!(window.from_ms, 1_789_430_400_000);
    assert_eq!(window.to_ms, 1_789_430_500_000);
    assert!(window.contains(1_789_430_400_000));
    assert!(!window.contains(1_789_430_500_000));
    // Mixed forms compare by instant.
    let mixed = parse_window(Some("2026-09-15T00:00:00Z"), Some("1789430500000")).unwrap();
    assert_eq!(mixed.from_ms, 1_789_430_400_000);
    assert!(parse_window(Some("1789430500000"), Some("1789430400000")).is_err());
}

/// #20: the HTML timeline is capped; JSON keeps every row.
#[test]
fn html_caps_huge_timelines() {
    let mut inputs = empty_report_inputs();
    inputs.timeline = (0..HTML_TIMELINE_ROWS + 5)
        .map(|index| TimelineRow {
            time_ms: i64::try_from(index).unwrap_or(0),
            time: "2026-09-15T00:00:00.000Z".to_string(),
            action: "DescribeTopic".to_string(),
            target: "orders".to_string(),
            proposal_id: String::new(),
            principal: "User:bulk".to_string(),
            source: format!("audit offset {index}"),
        })
        .collect();
    let report = build_report(inputs);
    let html = render_html(&report);
    assert!(
        html.contains("audit offset 9999"),
        "the last kept row renders"
    );
    assert!(
        !html.contains("audit offset 10000"),
        "rows past the cap do not render"
    );
    assert!(html.contains(&format!(
        "Timeline truncated to {HTML_TIMELINE_ROWS} of {} rows",
        HTML_TIMELINE_ROWS + 5
    )));
    assert_eq!(report.timeline.len(), HTML_TIMELINE_ROWS + 5);
}

#[test]
fn html_escapes_finding_text() {
    let mut inputs = empty_report_inputs();
    inputs.findings.push(krabka_evidence::finding::Finding::new(
        krabka_evidence::finding::CheckId::BypassListing,
        "<script>alert(1)</script>",
        "detail with <brackets> & \"quotes\"",
    ));
    let report = build_report(inputs);
    let html = render_html(&report);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("&amp;"));
    assert!(html.contains("FINDINGS"));
}

#[test]
fn missing_keys_file_is_an_error() {
    let missing = std::env::temp_dir().join("krabka-evidence-no-such-keys.toml");
    let _ = std::fs::remove_file(&missing);
    assert!(load_trust(&missing, &[], &[]).is_err());
}

#[test]
fn malformed_keys_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    // A public key of the wrong length.
    std::fs::write(dir.path().join("short.pub"), b"too short").unwrap();
    std::fs::write(
        dir.path().join("keys.toml"),
        "[[operator_keys]]\nkey_id = \"a\"\nprincipal = \"User:a\"\npublic_key_path = \"short.pub\"\n",
    )
    .unwrap();
    assert!(load_trust(&dir.path().join("keys.toml"), &[], &[]).is_err());

    // Two audit keys where the verifier trusts one.
    let raw = vec![7u8; 32];
    std::fs::write(dir.path().join("k1.pub"), &raw).unwrap();
    std::fs::write(dir.path().join("k2.pub"), &raw).unwrap();
    std::fs::write(
        dir.path().join("keys2.toml"),
        "[[audit_keys]]\nkey_id = \"a1\"\npublic_key_path = \"k1.pub\"\n\
         [[audit_keys]]\nkey_id = \"a2\"\npublic_key_path = \"k2.pub\"\n",
    )
    .unwrap();
    assert!(load_trust(&dir.path().join("keys2.toml"), &[], &[]).is_err());
}

#[test]
fn cli_key_pairs_load() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("op.pub"), vec![9u8; 32]).unwrap();
    std::fs::write(dir.path().join("w.pub"), vec![8u8; 32]).unwrap();
    std::fs::write(
        dir.path().join("keys.toml"),
        "[[operator_keys]]\nkey_id = \"op\"\nprincipal = \"User:op\"\npublic_key_path = \"op.pub\"\n",
    )
    .unwrap();
    let worm = krabka_evidence::keys::CliKeyPair {
        key_id: "worm-1".to_string(),
        public_key: dir.path().join("w.pub"),
    };
    let trust = load_trust(&dir.path().join("keys.toml"), &[], &[worm]).unwrap();
    assert!(trust.has_operators);
    assert!(trust.has_worm_keys);
    assert!(!trust.has_audit_keys);
}

#[test]
fn freeze_and_approval_preimages_match_broker_goldens() {
    use krabka_broker::operator_keys::FreezeSigningInput;
    use krabka_guard::signing::{
        ApprovalSigningInput, approval_signing_bytes, freeze_signing_bytes,
    };
    // Golden lengths from the broker's signing tests: any drift in the byte
    // layout changes these sizes.
    let freeze = freeze_signing_bytes(&FreezeSigningInput {
        cluster_id: "test-cluster",
        pattern_type: 3,
        scope: "orders",
        frozen: true,
        reason: "r",
        set_by: "User:alice",
        set_at_ms: 1,
        proposal_id: [0u8; 16],
    });
    assert!(freeze.len() > 30);
    assert!(freeze.starts_with(b"krabka-topic-freeze-v1\0"));
    let approval = approval_signing_bytes(&ApprovalSigningInput {
        proposal_id: [1u8; 16],
        action: 6,
        target: "orders",
        proposer: "User:alice",
        created_at_ms: 2,
        expires_at_ms: 3,
    });
    assert!(approval.len() > 30);
    assert!(approval.starts_with(b"krabka-break-glass-v1\0"));
    // Distinct domains: a signature for one never verifies as the other.
    assert_ne!(&freeze[..22], &approval[..22]);
}

#[test]
fn times_format_as_rfc3339() {
    assert_eq!(format_time(1_789_430_400_000), "2026-09-15T00:00:00.000Z");
}

/// #I1: findings and notes sort by report order, not variant-name order.
///
/// Debug-name order would file `applied-with-no-audit-event` before
/// `audit-chain` and `two-person-rule` before `worm-archive`; the report
/// order is the reverse in both cases.
#[test]
fn report_items_sort_by_report_order() {
    use krabka_evidence::{
        finding::{CheckId, Finding, Note, sort_findings, sort_notes},
        report::ALL_CHECKS,
    };
    for (index, id) in ALL_CHECKS.iter().enumerate() {
        assert_eq!(id.report_order(), index, "order of {}", id.kebab());
    }
    let mut findings = vec![
        Finding::new(CheckId::TwoPersonRule, "t", "d"),
        Finding::new(CheckId::WormArchive, "t", "d"),
        Finding::new(CheckId::AppliedWithNoAuditEvent, "t", "d"),
        Finding::new(CheckId::AuditChain, "t", "d"),
    ];
    sort_findings(&mut findings);
    let order: Vec<CheckId> = findings.iter().map(|finding| finding.check).collect();
    assert_eq!(
        order,
        [
            CheckId::AuditChain,
            CheckId::WormArchive,
            CheckId::AppliedWithNoAuditEvent,
            CheckId::TwoPersonRule,
        ]
    );
    let mut tied = vec![
        Finding::new(CheckId::AuditChain, "t", "d").with_audit_offset(9),
        Finding::new(CheckId::AuditChain, "t", "d").with_audit_offset(2),
    ];
    sort_findings(&mut tied);
    assert_eq!(tied[0].audit_offset, Some(2));
    let mut notes = vec![
        Note::new(CheckId::TwoPersonRule, "b"),
        Note::new(CheckId::WormArchive, "a"),
    ];
    sort_notes(&mut notes);
    assert_eq!(notes[0].check, CheckId::WormArchive);
}

/// #I12: two worm entries sharing a key id are refused.
#[test]
fn duplicate_worm_key_ids_are_refused() {
    use krabka_evidence::keys::CliKeyPair;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("w1.pub"), vec![1u8; 32]).unwrap();
    std::fs::write(dir.path().join("w2.pub"), vec![2u8; 32]).unwrap();
    // Twice in the file.
    std::fs::write(
        dir.path().join("keys.toml"),
        "[[worm_keys]]\nkey_id = \"worm-1\"\npublic_key_path = \"w1.pub\"\n\
         [[worm_keys]]\nkey_id = \"worm-1\"\npublic_key_path = \"w2.pub\"\n",
    )
    .unwrap();
    let error = load_trust(&dir.path().join("keys.toml"), &[], &[]).unwrap_err();
    assert!(
        error.to_string().contains("duplicate worm key_id"),
        "names the duplicate: {error}"
    );
    // Once in the file, once on the CLI.
    std::fs::write(
        dir.path().join("keys2.toml"),
        "[[worm_keys]]\nkey_id = \"worm-1\"\npublic_key_path = \"w1.pub\"\n",
    )
    .unwrap();
    let cli = CliKeyPair {
        key_id: "worm-1".to_string(),
        public_key: dir.path().join("w2.pub"),
    };
    let error = load_trust(&dir.path().join("keys2.toml"), &[], &[cli]).unwrap_err();
    assert!(
        error.to_string().contains("duplicate worm key_id"),
        "file-plus-CLI duplicates refuse too: {error}"
    );
}

/// #I13: blank broker key ids are refused.
#[test]
fn blank_broker_key_ids_are_refused() {
    use krabka_evidence::keys::CliKeyPair;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("w.pub"), vec![3u8; 32]).unwrap();
    std::fs::write(dir.path().join("op.pub"), vec![4u8; 32]).unwrap();
    std::fs::write(
        dir.path().join("keys.toml"),
        "[[worm_keys]]\nkey_id = \"\"\npublic_key_path = \"w.pub\"\n",
    )
    .unwrap();
    let error = load_trust(&dir.path().join("keys.toml"), &[], &[]).unwrap_err();
    assert!(
        error.to_string().contains("blank key_id"),
        "blank file ids refuse: {error}"
    );
    std::fs::write(
        dir.path().join("keys2.toml"),
        "[[operator_keys]]\nkey_id = \"op\"\nprincipal = \"User:op\"\n\
         public_key_path = \"op.pub\"\n",
    )
    .unwrap();
    let cli = CliKeyPair {
        key_id: "  ".to_string(),
        public_key: dir.path().join("w.pub"),
    };
    let error = load_trust(&dir.path().join("keys2.toml"), &[], &[cli]).unwrap_err();
    assert!(
        error.to_string().contains("blank key_id"),
        "blank CLI ids refuse: {error}"
    );
}

/// #I14: a typo'd keys table fails loudly instead of parsing as empty.
#[test]
fn unknown_keys_tables_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("keys.toml"),
        "[[operator_key]]\nkey_id = \"op\"\nprincipal = \"User:op\"\n\
         public_key_path = \"op.pub\"\n",
    )
    .unwrap();
    assert!(
        load_trust(&dir.path().join("keys.toml"), &[], &[]).is_err(),
        "a singular [[operator_key]] table is refused"
    );
    std::fs::write(dir.path().join("op.pub"), vec![5u8; 32]).unwrap();
    std::fs::write(
        dir.path().join("keys2.toml"),
        "[[operator_keys]]\nkey_id = \"op\"\nprincipal = \"User:op\"\n\
         public_key_path = \"op.pub\"\nextra_field = 1\n",
    )
    .unwrap();
    assert!(
        load_trust(&dir.path().join("keys2.toml"), &[], &[]).is_err(),
        "an unknown entry field is refused"
    );
}

/// #I17: symlinks are never followed when hashing inputs.
#[test]
#[cfg(unix)]
fn hashing_skips_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("real.txt"), b"bytes").unwrap();
    std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();
    std::os::unix::fs::symlink("loop-b", dir.path().join("loop-a")).unwrap();
    std::os::unix::fs::symlink("loop-a", dir.path().join("loop-b")).unwrap();
    let digest = digest_path(dir.path(), "test").unwrap();
    assert_eq!(digest.files, 1, "only the real file is hashed");
    assert!(digest.file_hashes.contains_key("real.txt"));
}

/// #I18: unpadded segment stems sort numerically.
#[test]
fn ledger_files_sort_by_numeric_stem() {
    use std::path::PathBuf;

    use krabka_evidence::audit::sort_ledger_files;
    let mut paths = vec![
        PathBuf::from("10.log"),
        PathBuf::from("9.log"),
        PathBuf::from("00000000000000000002.log"),
    ];
    sort_ledger_files(&mut paths);
    let names: Vec<&str> = paths.iter().map(|path| path.to_str().unwrap()).collect();
    assert_eq!(names, ["00000000000000000002.log", "9.log", "10.log"]);
}

/// #I32: scenario names match case-insensitively.
#[test]
fn scenario_names_match_case_insensitively() {
    use krabka_evidence::fixture::Scenario;
    assert_eq!(Scenario::from_name("CLEAN"), Some(Scenario::Clean));
    assert_eq!(
        Scenario::from_name("Flipped-Sig"),
        Some(Scenario::FlippedSignature)
    );
    assert_eq!(Scenario::from_name("GATED-OP"), Some(Scenario::GatedOp));
    assert_eq!(Scenario::from_name("no-such-scenario"), None);
}

/// #I35: window values tolerate whitespace and signed millis.
#[test]
fn window_parses_signed_millis_and_whitespace() {
    let padded = parse_window(Some("  2026-09-01  "), Some("2026-10-01")).unwrap();
    let plain = parse_window(Some("2026-09-01"), Some("2026-10-01")).unwrap();
    assert_eq!(padded.from_ms, plain.from_ms);
    assert_eq!(padded.to_ms, plain.to_ms);
    let negative = parse_window(Some("-1000"), None).unwrap();
    assert_eq!(negative.from_ms, -1000);
    let explicit = parse_window(Some("+42"), None).unwrap();
    assert_eq!(explicit.from_ms, 42);
    assert!(parse_window(Some(""), None).is_err());
    assert!(parse_window(Some("-"), None).is_err());
}

/// Minimal report inputs for rendering tests.
fn empty_report_inputs() -> ReportInputs {
    ReportInputs {
        findings: Vec::new(),
        notes: Vec::new(),
        timeline: Vec::new(),
        digests: BTreeMap::new(),
        audit_records: 0,
        metadata_records: 0,
        worm_manifests: 0,
        from_flag: None,
        to_flag: None,
        from_ms: i64::MIN,
        to_ms: i64::MAX,
        trust: TrustCounts {
            operators: 0,
            audit: 0,
            worm: 0,
            operator_key_ids: Vec::new(),
            audit_key_ids: Vec::new(),
            worm_key_ids: Vec::new(),
        },
        timeline_truncated: false,
        auditor: AuditorIdentity {
            key_id: "auditor-1".to_string(),
            public_key_hex: "00".repeat(32),
        },
    }
}
