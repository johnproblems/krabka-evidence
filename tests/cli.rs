//! CLI proofs (#25–#34): flags and subcommands through the real binary.
//!
//! Each test runs `krabka-evidence` against the clean fixtures and asserts
//! the exit code plus the exact stdout/stderr contract of one flag.

use std::path::{Path, PathBuf};

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
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        evidence,
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
