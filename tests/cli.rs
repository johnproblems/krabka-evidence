//! CLI proofs (#25–#34): flags and subcommands through the real binary.
//!
//! Each test runs `krabka-evidence` against the clean fixtures and asserts
//! the exit code plus the exact stdout/stderr contract of one flag.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use serde_json::Value;

fn binary() -> Command {
    Command::cargo_bin("krabka-evidence").expect("the binary builds")
}

/// Generate the clean fixtures once per test-file run (shared across threads).
fn fixtures() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let out =
            std::env::temp_dir().join(format!("krabka-evidence-tests-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        binary()
            .args(["fixture", "--scenario", "clean", "--out"])
            .arg(&out)
            .assert()
            .success();
        out
    })
    .clone()
}

/// One build run: exit code, stdout, stderr, and evidence directory.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    evidence: PathBuf,
}

/// Build a pack, with extra CLI flags appended.
fn build(scenario: &Path, extra: &[&str]) -> Run {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let evidence = scenario.join(format!("evidence-cli-{id}"));
    let _ = std::fs::remove_dir_all(&evidence);
    build_to(scenario, &evidence, "2026-09-01", "2026-10-01", extra)
}

/// Build a pack into a fixed directory with an explicit window.
///
/// The directory is used as-is, so tests can probe reuse behavior.
fn build_to(scenario: &Path, evidence: &Path, from: &str, to: &str, extra: &[&str]) -> Run {
    let output = binary()
        .args([
            "--from",
            from,
            "--to",
            to,
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
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        evidence: evidence.to_path_buf(),
    }
}

fn report_of(evidence: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(evidence.join("report.json")).expect("report.json"))
        .expect("report.json parses")
}

/// #25: `--format json` emits one JSON object; text stays human-readable.
#[test]
fn format_json_emits_machine_readable_summary() {
    let out = fixtures();
    let run = build(&out.join("clean"), &["--format", "json"]);
    assert_eq!(run.code, 0);
    let summary: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    assert_eq!(summary["status"], "clean");
    assert_eq!(summary["findings"], 0);
    assert!(summary["pack"].as_str().unwrap().contains("evidence-cli-"));

    let text = build(&out.join("clean"), &[]);
    assert!(text.stdout.contains("CLEAN"), "text stays readable");
}

/// #26: `--quiet` silences stdout; `--verbose` narrates each phase.
#[test]
fn quiet_silences_and_verbose_narrates() {
    let out = fixtures();
    let quiet = build(&out.join("clean"), &["--quiet"]);
    assert_eq!(quiet.code, 0);
    assert!(quiet.stdout.is_empty(), "quiet prints nothing");

    let verbose = build(&out.join("clean"), &["--verbose"]);
    assert_eq!(verbose.code, 0);
    for phase in ["audit:", "metadata:", "archive:", "digest audit:"] {
        assert!(
            verbose.stderr.contains(phase),
            "verbose narrates {phase}: {}",
            verbose.stderr
        );
    }
}

/// #27: verify prints the per-check table.
#[test]
fn verify_prints_checks_table() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("OK: evidence pack is authentic"),
        "{stdout}"
    );
    for check in [
        "audit-chain: pass",
        "worm-archive: pass",
        "two-person-rule: pass",
    ] {
        assert!(stdout.contains(check), "table holds {check}: {stdout}");
    }
}

/// #28: `verify --fail-on-findings` rejects an authentic pack with findings.
#[test]
fn verify_fail_on_findings_rejects_findings_packs() {
    let out = fixtures();
    // The clean pack passes either way.
    let clean = build(&out.join("clean"), &[]);
    binary()
        .args(["verify"])
        .arg(&clean.evidence)
        .arg("--fail-on-findings")
        .assert()
        .success();
    // A findings pack verifies without the flag but fails with it. The
    // flipped-sig fixtures live in the shared all-scenarios dir.
    let all = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-cli-all-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&all);
    binary()
        .args(["fixture", "--scenario", "flipped-sig", "--out"])
        .arg(&all)
        .assert()
        .success();
    let flawed = build(&all.join("flipped-sig"), &[]);
    assert_eq!(flawed.code, 1);
    binary()
        .args(["verify"])
        .arg(&flawed.evidence)
        .assert()
        .success();
    binary()
        .args(["verify"])
        .arg(&flawed.evidence)
        .arg("--fail-on-findings")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--fail-on-findings"));
}

/// #29: `--only` runs one check and marks the rest not-checked.
#[test]
fn only_filter_runs_one_check() {
    let out = fixtures();
    let run = build(&out.join("clean"), &["--only", "audit-chain"]);
    assert_eq!(run.code, 0);
    let report = report_of(&run.evidence);
    assert_eq!(report["counts"]["findings"], 0);
    assert_eq!(report["counts"]["worm_manifests"], 0, "WORM walk skipped");
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|note| note["detail"]
            .as_str()
            .unwrap()
            .contains("excluded by --only")),
        "excluded checks are disclosed: {notes:?}"
    );
    let checks = report["checks"].as_array().unwrap();
    let skipped = checks
        .iter()
        .filter(|check| check["status"] == "not-checked")
        .count();
    assert_eq!(skipped, 10, "ten checks skipped: {checks:?}");
}

/// #30: `--require-all-checked` fails a filtered run.
#[test]
fn require_all_checked_fails_filtered_runs() {
    let out = fixtures();
    let run = build(
        &out.join("clean"),
        &["--only", "audit-chain", "--require-all-checked"],
    );
    assert_eq!(run.code, 1, "not-checked fails the run");
    assert!(
        run.stderr.contains("--require-all-checked"),
        "the error names the flag: {}",
        run.stderr
    );
}

/// #31: `completions` prints a working shell script.
#[test]
fn completions_print_shell_scripts() {
    for shell in ["bash", "zsh", "fish"] {
        let output = binary()
            .args(["completions", shell])
            .output()
            .expect("the binary runs");
        assert!(output.status.success());
        let script = String::from_utf8_lossy(&output.stdout);
        assert!(
            script.contains("krabka-evidence"),
            "{shell} completions name the binary"
        );
        assert!(script.len() > 1000, "{shell} completions are substantial");
    }
}

/// #32: `--list-checks` names every check.
#[test]
fn list_checks_names_every_check() {
    let output = binary()
        .args(["--list-checks"])
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 11, "one line per check: {stdout}");
    for check in [
        "audit-chain",
        "worm-archive",
        "metadata-coverage",
        "two-person-rule",
    ] {
        assert!(stdout.contains(check), "lists {check}: {stdout}");
    }
}

/// #33: an output nested with an input is refused.
#[test]
fn output_inside_inputs_is_refused() {
    let out = fixtures();
    let scenario = out.join("clean");
    let nested = scenario.join("audit/evidence-nested");
    let output = binary()
        .args([
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
            nested.to_str().unwrap(),
        ])
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to write the pack"),
        "the error names the refusal: {stderr}"
    );
}

/// #34: `keygen` mints a keypair and prints its id and public key.
#[test]
fn keygen_mints_and_prints_keypair() {
    let dir = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-keygen-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("keygen dir creates");
    let prefix = dir.join("auditor");
    let output = binary()
        .args([
            "keygen",
            "--out",
            prefix.to_str().unwrap(),
            "--key-id",
            "test-auditor",
        ])
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let public = std::fs::read(dir.join("auditor.pub")).expect("public key written");
    assert_eq!(public.len(), 32, "raw Ed25519 public key");
    assert!(
        std::fs::metadata(dir.join("auditor.priv.pkcs8")).is_ok(),
        "private key written"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("key_id: test-auditor"), "{stdout}");
    assert!(
        stdout.contains(&hex::encode(&public)),
        "the printed key matches the file: {stdout}"
    );
}

/// #I2: `--format json` says `not-checked` when the gate fails without findings.
#[test]
fn require_failed_json_reports_not_checked() {
    let out = fixtures();
    let run = build(
        &out.join("clean"),
        &[
            "--only",
            "audit-chain",
            "--require-all-checked",
            "--format",
            "json",
        ],
    );
    assert_eq!(run.code, 1);
    let summary: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    assert_eq!(summary["status"], "not-checked");
    assert_eq!(summary["findings"], 0);
}

/// #I3: flag errors say `bad flag` and point at `--help`.
#[test]
fn flag_errors_name_the_flag() {
    let output = binary().output().expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bad flag"), "{stderr}");
    assert!(stderr.contains("hint:"), "{stderr}");

    let output = binary()
        .args(["--only", "no-such-check"])
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bad flag: unknown check"), "{stderr}");
}

/// #I4: a missing auditor pin file is an error, not a mismatch.
#[test]
fn missing_auditor_pin_is_an_error() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--auditor-public-key")
        .arg("/nonexistent-pin.pub")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("cannot read"));
}

/// #I5: verify accepts a hex-encoded auditor pin.
#[test]
fn hex_auditor_pin_verifies() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    let dir =
        std::env::temp_dir().join(format!("krabka-evidence-tests-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("pin dir creates");
    let raw = std::fs::read(out.join("clean/keys/auditor.pub")).expect("auditor.pub reads");
    std::fs::write(dir.join("pin.hex"), format!("{}\n", hex::encode(&raw))).unwrap();
    binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--auditor-public-key")
        .arg(dir.join("pin.hex"))
        .assert()
        .success();
    std::fs::write(dir.join("wrong.hex"), "00".repeat(32)).unwrap();
    binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--auditor-public-key")
        .arg(dir.join("wrong.hex"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("does not match"));
}

/// #I6: the report names its trust roots.
#[test]
fn report_records_trust_key_ids() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    let report = report_of(&run.evidence);
    assert_eq!(
        report["trust"]["operator_key_ids"],
        serde_json::json!(["alice-2026", "bob-2026", "carol-2026"]),
        "operator ids recorded"
    );
    assert_eq!(
        report["trust"]["audit_key_ids"],
        serde_json::json!(["audit-1"])
    );
    assert_eq!(
        report["trust"]["worm_key_ids"],
        serde_json::json!(["worm-1"])
    );
}

/// #I7: an empty window is disclosed, not silently vacuous.
#[test]
fn empty_window_is_noted() {
    let out = fixtures();
    let scenario = out.join("clean");
    let evidence = scenario.join("evidence-cli-empty-window");
    let _ = std::fs::remove_dir_all(&evidence);
    let run = build_to(&scenario, &evidence, "2026-09-15", "2026-09-15", &[]);
    assert_eq!(run.code, 0, "notes do not fail: {}", run.stderr);
    let report = report_of(&run.evidence);
    let notes = report["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|note| note["detail"].as_str().unwrap().contains("window is empty")),
        "the empty window is disclosed: {notes:?}"
    );
}

/// #I9: `..` segments cannot dodge the nesting refusal.
#[test]
fn nesting_refusal_canonicalizes_paths() {
    let out = fixtures();
    let scenario = out.join("clean");
    let nested = scenario.join("audit/evidence-dodge");
    let output = binary()
        .args([
            "--audit",
            scenario.join("audit/../audit").to_str().unwrap(),
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
            nested.to_str().unwrap(),
        ])
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to write the pack"),
        "canonical paths still nest: {stderr}"
    );
}

/// #I10: verify re-hash failures honor `--format json`.
#[test]
fn verify_rehash_mismatch_emits_json() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    // Re-hash the audit slot against the metadata bytes: the digest differs.
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .args(["--format", "json", "--audit"])
        .arg(out.join("clean/metadata"))
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let summary: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is JSON");
    assert_eq!(summary["authentic"], true);
    assert_eq!(summary["rehash"], "mismatch");
    assert_eq!(summary["slot"], "audit");
}

/// #I11: `--quiet` silences the remote-archive skip note.
#[test]
fn quiet_silences_remote_skip_note() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .args(["--archive", "s3://bucket", "--quiet"])
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .args(["--archive", "s3://bucket"])
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be re-hashed"),
        "the note prints without --quiet"
    );
}

/// #I15: rebuilding into a non-empty directory needs `--overwrite`.
#[test]
fn nonempty_output_needs_overwrite() {
    let out = fixtures();
    let scenario = out.join("clean");
    let evidence = scenario.join("evidence-overwrite-probe");
    let _ = std::fs::remove_dir_all(&evidence);
    let first = build_to(&scenario, &evidence, "2026-09-01", "2026-10-01", &[]);
    assert_eq!(first.code, 0, "first build writes: {}", first.stderr);
    let second = build_to(&scenario, &evidence, "2026-09-01", "2026-10-01", &[]);
    assert_eq!(second.code, 2, "reuse is refused");
    assert!(
        second.stderr.contains("not empty"),
        "the error names the fix: {}",
        second.stderr
    );
    let third = build_to(
        &scenario,
        &evidence,
        "2026-09-01",
        "2026-10-01",
        &["--overwrite"],
    );
    assert_eq!(third.code, 0, "overwrite retries cleanly: {}", third.stderr);
}

/// #I16: keygen refuses to clobber without `--force`.
#[test]
fn keygen_needs_force_to_overwrite() {
    let dir = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-keygen-force-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("keygen dir creates");
    let prefix = dir.join("auditor").to_str().unwrap().to_string();
    binary()
        .args(["keygen", "--out"])
        .arg(&prefix)
        .assert()
        .success();
    binary()
        .args(["keygen", "--out"])
        .arg(&prefix)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--force"));
    binary()
        .args(["keygen", "--out"])
        .arg(&prefix)
        .arg("--force")
        .assert()
        .success();
}

/// #I21: a short `report.sig` fails with an explicit reason.
#[test]
fn short_signature_fails_explicitly() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    std::fs::write(run.evidence.join("report.sig"), b"short").unwrap();
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("report.sig is 5 byte(s)"), "{stderr}");
}

/// #I22: a bad `--expect-head` fails before any ledger is read.
#[test]
fn bad_expect_head_fails_fast() {
    let out = fixtures();
    let scenario = out.join("clean");
    let output = binary()
        .args([
            "--audit",
            "/nonexistent-audit-dir",
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
            "--expect-head",
            "xyz",
            "-o",
            scenario.join("evidence-head").to_str().unwrap(),
        ])
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--expect-head"),
        "the flag error wins over the missing input: {stderr}"
    );
}

/// #I23: `--max-timeline-rows 0` is refused.
#[test]
fn zero_timeline_rows_is_refused() {
    let out = fixtures();
    let run = build(&out.join("clean"), &["--max-timeline-rows", "0"]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr
            .contains("--max-timeline-rows must be at least 1"),
        "{}",
        run.stderr
    );
}

/// #I25: verify re-hashes `--operator-keys`.
#[test]
fn verify_rehashes_operator_keys() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--operator-keys")
        .arg(out.join("clean/keys/keys.toml"))
        .assert()
        .success();
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--operator-keys")
        .arg(out.join("clean/keys/auditor.pub"))
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("operator_keys"), "{stderr}");
}

/// #I26: `--list-checks --format json` emits the check table.
#[test]
fn list_checks_json_emits_check_table() {
    let output = binary()
        .args(["--list-checks", "--format", "json"])
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let checks: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is JSON");
    let checks = checks.as_array().unwrap();
    assert_eq!(checks.len(), 11);
    assert_eq!(checks[0]["id"], "audit-chain");
    assert!(checks[0]["title"].as_str().unwrap().contains("Audit"));
}

/// #I27: build `--format json` carries the per-check table.
#[test]
fn build_json_carries_checks_table() {
    let out = fixtures();
    let run = build(&out.join("clean"), &["--format", "json"]);
    assert_eq!(run.code, 0);
    let summary: Value = serde_json::from_str(&run.stdout).expect("stdout is JSON");
    let checks = summary["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 11);
    assert!(
        checks.iter().all(|check| check["status"] == "pass"),
        "clean checks pass: {checks:?}"
    );
}

/// #I28: verify `--format json` carries the per-check table.
#[test]
fn verify_json_carries_checks_table() {
    let out = fixtures();
    let run = build(&out.join("clean"), &[]);
    assert_eq!(run.code, 0);
    let output = binary()
        .args(["verify"])
        .arg(&run.evidence)
        .arg("--format")
        .arg("json")
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let summary: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is JSON");
    assert_eq!(summary["checks"].as_array().unwrap().len(), 11);
}

/// #I29: S3 flags read the environment; explicit flags win.
#[test]
fn s3_flags_read_the_environment() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("blackhole binds");
    let port = listener.local_addr().expect("blackhole has a port").port();
    std::thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    });
    let out = fixtures();
    let scenario = out.join("clean");
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut command = binary();
    command
        .args([
            "--audit",
            scenario.join("audit").to_str().unwrap(),
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            "s3://blackhole",
            "--allow-http",
            "--archive-timeout-secs",
            "3",
            "--operator-keys",
            scenario.join("keys/keys.toml").to_str().unwrap(),
            "--cluster-id",
            "fixture-cluster",
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "--verbose",
            "-o",
            scenario.join("evidence-env").to_str().unwrap(),
        ])
        .env("AWS_REGION", "env-region-1")
        .env("AWS_ENDPOINT_URL_S3", &endpoint)
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
    let output = command.output().expect("the binary runs");
    assert_eq!(output.status.code().unwrap_or(-1), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("region env-region-1"),
        "the region comes from the environment: {stderr}"
    );
    assert!(
        stderr.contains(&endpoint),
        "the endpoint comes from the environment: {stderr}"
    );

    let output = binary()
        .args([
            "--audit",
            scenario.join("audit").to_str().unwrap(),
            "--metadata",
            scenario.join("metadata").to_str().unwrap(),
            "--archive",
            "s3://blackhole",
            "--s3-region",
            "flag-region-9",
            "--allow-http",
            "--archive-timeout-secs",
            "3",
            "--operator-keys",
            scenario.join("keys/keys.toml").to_str().unwrap(),
            "--cluster-id",
            "fixture-cluster",
            "--sign-with",
            scenario.join("keys/auditor.priv.pkcs8").to_str().unwrap(),
            "--verbose",
            "-o",
            scenario.join("evidence-env2").to_str().unwrap(),
        ])
        .env("AWS_REGION", "env-region-1")
        .env("AWS_ENDPOINT_URL_S3", &endpoint)
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("region flag-region-9"),
        "the explicit flag wins over the environment: {stderr}"
    );
}

/// #I30: `--verbose` prints the total elapsed time.
#[test]
fn verbose_prints_elapsed() {
    let out = fixtures();
    let run = build(&out.join("clean"), &["--verbose"]);
    assert_eq!(run.code, 0);
    assert!(run.stderr.contains("elapsed:"), "{}", run.stderr);
}

/// #I31: `fixture --list-scenarios` names every scenario.
#[test]
fn fixture_lists_scenarios() {
    let output = binary()
        .args(["fixture", "--list-scenarios", "--out"])
        .arg("/tmp/krabka-evidence-unused")
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 11, "{stdout}");
    for scenario in ["bypass", "gated-op", "unknown-key"] {
        assert!(stdout.contains(scenario), "lists {scenario}: {stdout}");
    }
}

/// #I32: `fixture --scenario` matches case-insensitively.
#[test]
fn fixture_scenario_matches_case_insensitively() {
    let dir =
        std::env::temp_dir().join(format!("krabka-evidence-tests-case-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    binary()
        .args(["fixture", "--scenario", "CLEAN", "--out"])
        .arg(&dir)
        .assert()
        .success();
    assert!(dir.join("clean/audit").is_dir());
}

/// #I33: `fixture --events 0` is refused.
#[test]
fn fixture_rejects_zero_events() {
    let dir = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-events-{}",
        std::process::id()
    ));
    binary()
        .args(["fixture", "--scenario", "bulk", "--events", "0", "--out"])
        .arg(&dir)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("at least 1"));
}

/// #I36: `--only` is case-insensitive and ignores empty segments.
#[test]
fn only_filter_is_forgiving() {
    let out = fixtures();
    let run = build(
        &out.join("clean"),
        &["--only", "AUDIT-CHAIN,, worm-archive"],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    let report = report_of(&run.evidence);
    let skipped = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["status"] == "not-checked")
        .count();
    assert_eq!(skipped, 9, "two checks ran");
}

/// #I42: `fixture --out` pointing at a file is refused.
#[test]
fn fixture_out_file_is_refused() {
    let dir = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-outfile-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir creates");
    let file = dir.join("a-file");
    std::fs::write(&file, b"not a directory").unwrap();
    binary()
        .args(["fixture", "--scenario", "clean", "--out"])
        .arg(&file)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not a directory"));
}

/// #I43: bulk rejects the capture layout.
#[test]
fn bulk_rejects_capture_layout() {
    let dir = std::env::temp_dir().join(format!(
        "krabka-evidence-tests-bulklayout-{}",
        std::process::id()
    ));
    binary()
        .args([
            "fixture",
            "--scenario",
            "bulk",
            "--layout",
            "capture",
            "--out",
        ])
        .arg(&dir)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not to bulk"));
}
