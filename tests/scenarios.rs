//! PRD success criteria, end to end through the CLI.
//!
//! Each scenario from `prd.md` produces exactly the findings it names, with
//! the right offsets and times, and the clean scenario verifies.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use assert_cmd::Command;
use krabka_evidence::fixture::Scenario;
use serde_json::Value;

fn binary() -> Command {
    Command::cargo_bin("krabka-evidence").expect("the binary builds")
}

/// Generate all fixtures once per test-file run (shared across threads).
fn fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out =
            std::env::temp_dir().join(format!("krabka-evidence-tests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        binary()
            .args(["fixture", "--scenario", "all", "--out"])
            .arg(&out)
            .assert()
            .success();
        out
    })
    .clone()
}

/// Build a pack for one scenario, with extra CLI flags appended.
fn build_pack_with(scenario: &Path, extra: &[&str]) -> (i32, Value, PathBuf) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let evidence = scenario.join(format!("evidence-test-{id}"));
    let _ = std::fs::remove_dir_all(&evidence);
    let output = binary()
        .args([
            "--from",
            "2026-09-01",
            "--to",
            "2026-10-01",
            "--audit",
            scenario.join("audit").to_str().unwrap(),
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            scenario.join("archive").to_str().unwrap(),
            "--operator-keys",
            scenario.join("keys/keys.toml").to_str().unwrap(),
            "--cluster-id",
            "fixture-cluster",
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "-o",
            evidence.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .expect("the binary runs");
    let code = output.status.code().unwrap_or(-1);
    let report: Value =
        serde_json::from_slice(&std::fs::read(evidence.join("report.json")).expect("report.json"))
            .expect("report.json parses");
    (code, report, evidence)
}

/// Build a pack for one scenario; return `(exit_code, report)`.
///
/// Each call writes to its own evidence directory so tests can run in
/// parallel against the shared fixtures.
fn build_pack(scenario: &Path) -> (i32, Value, PathBuf) {
    build_pack_with(scenario, &[])
}

/// Generate the bulk fixtures once per test-file run (shared across threads).
fn bulk_fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out =
            std::env::temp_dir().join(format!("krabka-evidence-tests-bulk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        binary()
            .args(["fixture", "--scenario", "bulk", "--events", "50", "--out"])
            .arg(&out)
            .assert()
            .success();
        out
    })
    .clone()
}

#[test]
fn clean_sequence_reports_clean() {
    let out = fixtures();
    let (code, report, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0, "clean scenario exits 0");
    assert_eq!(report["counts"]["findings"], 0);
    assert_eq!(report["counts"]["audit_records"], 17);
    assert_eq!(report["counts"]["metadata_records"], 4);
    assert_eq!(report["counts"]["worm_manifests"], 2);
    // #19: the report records the keys provisioned for the run.
    assert_eq!(report["trust"]["operators"], 3);
    assert_eq!(report["trust"]["audit"], 1);
    assert_eq!(report["trust"]["worm"], 1);
    // Every check ran and passed.
    for check in report["checks"].as_array().unwrap() {
        assert_eq!(check["status"], "pass", "check {}", check["id"]);
    }
    // The pack verifies.
    binary().args(["verify"]).arg(&pack).assert().success();
}

#[test]
fn deleted_audit_segment_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("missing-audit"));
    assert_eq!(code, 1, "findings exit 1");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "applied-with-no-audit-event");
    assert_eq!(finding["title"], "Applied with no audit event");
    assert_eq!(finding["metadata_offset"], 3);
    // Consumed time of the delete proposal: base + 8 minutes.
    assert_eq!(finding["time_ms"], 1_789_430_880_000i64);
}

#[test]
fn flipped_signature_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("flipped-sig"));
    assert_eq!(code, 1);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "signature-verification");
    assert_eq!(finding["title"], "Signature does not verify");
    assert_eq!(finding["audit_offset"], 1);
}

#[test]
fn approver_change_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("approver-change"));
    assert_eq!(code, 1);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "approver-set-change");
    assert_eq!(finding["title"], "Approver set changed");
    assert_eq!(finding["audit_offset"], 14);
    assert!(finding["detail"].as_str().unwrap().contains("->"));
}

#[test]
fn corrupt_chain_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("corrupt-chain"));
    assert_eq!(code, 1, "findings exit 1");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "audit-chain");
    assert_eq!(finding["title"], "Audit hash chain broken");
    assert_eq!(finding["audit_offset"], 12);
    assert!(
        finding["detail"]
            .as_str()
            .unwrap()
            .contains("checkpoint signature invalid"),
        "names the break: {finding:?}"
    );
}

#[test]
fn worm_tamper_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("worm-tamper"));
    assert_eq!(code, 1, "findings exit 1");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "worm-archive");
    assert_eq!(finding["title"], "WORM archive tamper detected");
    assert!(
        finding["detail"].as_str().unwrap().contains("prev_head"),
        "names the broken link: {finding:?}"
    );
}

#[test]
fn expired_approval_gives_exactly_one_finding() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("expired-approval"));
    assert_eq!(code, 1, "findings exit 1");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "exactly one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["check"], "two-person-rule");
    assert_eq!(finding["title"], "Two-person rule violated");
    assert_eq!(finding["metadata_offset"], 4);
}

#[test]
fn unsigned_events_note_but_stay_clean() {
    let out = fixtures();
    let (code, report, _) = build_pack(&out.join("unsigned"));
    assert_eq!(code, 0, "unsigned scenario exits 0");
    assert_eq!(report["counts"]["findings"], 0);
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|note| note["detail"].as_str().unwrap().contains("no signature")),
        "attested-only records are disclosed: {notes:?}"
    );
}

/// Generate the capture-layout fixtures once (shared across threads).
fn capture_fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out = std::env::temp_dir().join(format!(
            "krabka-evidence-tests-capture-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&out);
        binary()
            .args([
                "fixture",
                "--scenario",
                "clean",
                "--layout",
                "capture",
                "--out",
            ])
            .arg(&out)
            .assert()
            .success();
        out
    })
    .clone()
}

#[test]
fn capture_layout_reports_clean_with_snapshot_note() {
    let out = capture_fixtures();
    let (code, report, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0, "capture-layout clean scenario exits 0");
    assert_eq!(report["counts"]["findings"], 0);
    assert_eq!(report["counts"]["metadata_records"], 4);
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|note| note["detail"].as_str().unwrap().contains("backup snapshot")),
        "the compacted-away history is disclosed: {notes:?}"
    );
    // The pack verifies.
    binary().args(["verify"]).arg(&pack).assert().success();
}

#[test]
fn flipping_one_report_byte_breaks_verify() {
    let out = fixtures();
    let (code, _, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0);
    binary().args(["verify"]).arg(&pack).assert().success();

    // Flip one byte of the JSON payload (not the signature file).
    let report_path = pack.join("report.json");
    let mut bytes = std::fs::read(&report_path).unwrap();
    let position = bytes.iter().position(|byte| *byte == b'a').unwrap();
    bytes[position] ^= 0x01;
    std::fs::write(&report_path, &bytes).unwrap();
    binary().args(["verify"]).arg(&pack).assert().failure();

    // Restore, then flip a byte of the signature instead.
    let (code, _, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0);
    let sig_path = pack.join("report.sig");
    let mut sig = std::fs::read(&sig_path).unwrap();
    sig[0] ^= 0x01;
    std::fs::write(&sig_path, &sig).unwrap();
    binary().args(["verify"]).arg(&pack).assert().failure();
}

#[test]
fn verify_rejects_swapped_input_listing() {
    let out = fixtures();
    // Corrupt one digest in input-files.json: the listing no longer matches
    // report.json, so verify must fail.
    let (code, _, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0);
    let listing_path = pack.join("input-files.json");
    let mut listing: Value =
        serde_json::from_slice(&std::fs::read(&listing_path).unwrap()).unwrap();
    let digest = listing["audit"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    let mut text = digest.as_str().unwrap().to_string();
    text.replace_range(0..1, if &text[0..1] == "0" { "1" } else { "0" });
    *digest = Value::String(text);
    std::fs::write(&listing_path, serde_json::to_vec(&listing).unwrap()).unwrap();
    binary().args(["verify"]).arg(&pack).assert().failure();

    // Restore, then drop a whole slot instead.
    let (code, _, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0);
    let listing_path = pack.join("input-files.json");
    let mut listing: Value =
        serde_json::from_slice(&std::fs::read(&listing_path).unwrap()).unwrap();
    listing.as_object_mut().unwrap().remove("audit");
    std::fs::write(&listing_path, serde_json::to_vec(&listing).unwrap()).unwrap();
    binary().args(["verify"]).arg(&pack).assert().failure();
}

#[test]
fn verify_rehashes_inputs_when_given_them() {
    let out = fixtures();
    let scenario = out.join("clean");
    let (code, _, pack) = build_pack(&scenario);
    assert_eq!(code, 0);
    // Matching inputs re-hash clean.
    binary()
        .args(["verify"])
        .arg(&pack)
        .args(["--audit"])
        .arg(scenario.join("audit"))
        .args(["--metadata"])
        .arg(scenario.join("metadata"))
        .args(["--archive"])
        .arg(scenario.join("archive").to_str().unwrap())
        .assert()
        .success();
    // A different input fails the re-hash.
    binary()
        .args(["verify"])
        .arg(&pack)
        .args(["--audit"])
        .arg(out.join("missing-audit/audit"))
        .assert()
        .failure();
}

/// #18: an archive with no manifests passes vacuously, and says so.
/// #35: `--events 50` writes exactly fifty events plus a checkpoint.
#[test]
fn empty_archive_is_noted_vacuous() {
    let out = bulk_fixtures();
    let (code, report, _) = build_pack(&out.join("bulk"));
    assert_eq!(code, 0, "a vacuous archive stays clean");
    assert_eq!(report["counts"]["audit_records"], 51);
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|note| note["detail"]
            .as_str()
            .unwrap()
            .contains("passed vacuously")),
        "the vacuous pass is disclosed: {notes:?}"
    );
}

/// #21: `--max-timeline-rows` truncates the timeline and notes it.
#[test]
fn max_timeline_rows_truncates_with_note() {
    let out = fixtures();
    let (code, report, _) = build_pack_with(&out.join("clean"), &["--max-timeline-rows", "5"]);
    assert_eq!(code, 0);
    assert_eq!(report["timeline"].as_array().unwrap().len(), 5);
    assert_eq!(report["counts"]["timeline_rows"], 5);
    assert_eq!(report["timeline_truncated"], true);
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|note| note["detail"]
            .as_str()
            .unwrap()
            .contains("timeline truncated to 5 rows")),
        "the truncation is disclosed: {notes:?}"
    );
}

/// #17: an archive that never answers trips the timeout and fails closed.
#[test]
fn archive_timeout_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("blackhole binds");
    let port = listener.local_addr().expect("blackhole has a port").port();
    let contacted = Arc::new(AtomicBool::new(false));
    let flag = contacted.clone();
    std::thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            flag.store(true, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    });
    let out = fixtures();
    let scenario = out.join("clean");
    let evidence = scenario.join("evidence-timeout");
    let endpoint = format!("http://127.0.0.1:{port}");
    let _ = std::fs::remove_dir_all(&evidence);
    let output = binary()
        .args([
            "--audit",
            scenario.join("audit").to_str().unwrap(),
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            "s3://blackhole",
            "--s3-endpoint",
            endpoint.as_str(),
            "--allow-http",
            "--archive-timeout-secs",
            "2",
            "--operator-keys",
            scenario.join("keys/keys.toml").to_str().unwrap(),
            "--cluster-id",
            "fixture-cluster",
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "-o",
            evidence.to_str().unwrap(),
        ])
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2, "timeouts exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timed out after 2s"),
        "the error names the timeout: {stderr}"
    );
    assert!(
        contacted.load(Ordering::SeqCst),
        "the client connected to the endpoint (no credential detour)"
    );
}

/// #23: verify warns when the pack predates the verifier.
#[test]
fn verify_warns_on_tool_version_drift() {
    let out = fixtures();
    let (code, _, pack) = build_pack(&out.join("clean"));
    assert_eq!(code, 0);
    let report_path = pack.join("report.json");
    let mut report: Value = serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    report["tool_version"] = Value::String("0.0.0-drift-test".to_string());
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let output = binary()
        .args(["verify"])
        .arg(&pack)
        .output()
        .expect("the binary runs");
    assert!(!output.status.success(), "the edit breaks the signature");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0.0.0-drift-test"),
        "the drift warning names the pack version: {stderr}"
    );
}

/// Hash every file under `dir` by relative path.
fn tree_hashes(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(top) = stack.pop() {
        for entry in std::fs::read_dir(&top).expect("fixture dir reads") {
            let entry = entry.expect("fixture entry reads");
            if entry.path().is_dir() {
                stack.push(entry.path());
            } else {
                let relative = entry
                    .path()
                    .strip_prefix(dir)
                    .expect("prefix strips")
                    .to_path_buf();
                files.insert(
                    relative,
                    std::fs::read(entry.path()).expect("fixture file reads"),
                );
            }
        }
    }
    files
}

/// #36: `--seed` makes identical fixtures; different seeds differ.
#[test]
fn seed_makes_fixtures_deterministic() {
    let base =
        std::env::temp_dir().join(format!("krabka-evidence-tests-seed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    for (name, seed) in [("one", "s"), ("two", "s"), ("three", "other")] {
        binary()
            .args(["fixture", "--scenario", "clean", "--seed", seed, "--out"])
            .arg(base.join(name))
            .assert()
            .success();
    }
    let one = tree_hashes(&base.join("one/clean"));
    let two = tree_hashes(&base.join("two/clean"));
    let three = tree_hashes(&base.join("three/clean"));
    assert_eq!(one, two, "the same seed reproduces every byte");
    assert_ne!(one, three, "a different seed mints different keys");
}

/// #37: every scenario ships a README describing its tamper.
#[test]
fn every_scenario_ships_a_readme() {
    let out = fixtures();
    for scenario in Scenario::all() {
        let readme = out.join(scenario.dir_name()).join("README.txt");
        let text = std::fs::read_to_string(&readme).unwrap_or_else(|_| panic!("{readme:?} exists"));
        assert!(
            text.contains(scenario.description()),
            "{readme:?} describes its tamper"
        );
    }
}

#[test]
fn unreadable_inputs_exit_2() {
    let out = fixtures();
    let scenario = out.join("clean");
    // Missing audit directory.
    binary()
        .args([
            "--audit",
            "/nonexistent-audit-dir",
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            scenario.join("archive").to_str().unwrap(),
            "--operator-keys",
            scenario.join("keys/keys.toml").to_str().unwrap(),
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "-o",
            scenario.join("evidence-missing").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("hint:"));
    // Missing keys file.
    binary()
        .args([
            "--audit",
            scenario.join("audit").to_str().unwrap(),
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            scenario.join("archive").to_str().unwrap(),
            "--operator-keys",
            "/nonexistent-keys.toml",
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "-o",
            scenario.join("evidence-missing").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("hint:"));
}
