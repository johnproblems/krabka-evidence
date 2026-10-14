//! `krabka-evidence` binary: build and verify signed evidence packs.

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
};

use clap::{CommandFactory, Parser};
use krabka_audit::signing::FileEd25519Signer;
use krabka_evidence::{
    archive::{WormGrading, parse_archive_spec, parse_chain_head, read_archive_ledger},
    audit::{AuditLedger, read_audit_ledger},
    checks::{CheckInputs, run_cross_checks},
    cli::{Cli, Command, OutputFormat},
    error::{EvidenceError, ExitCode},
    finding::{CheckId, CheckStatus, Finding, Note},
    fixture::{FixtureOptions, Scenario, generate_bulk_audit, generate_scenario},
    hash::digest_path,
    keys::{CliKeyPair, TrustMaterial, load_trust},
    metadata::{MetadataLedger, read_metadata_ledger},
    report::{
        ALL_CHECKS, AuditorIdentity, ReportInput, ReportInputs, TrustCounts, build_report,
        canonical_json, verify_pack, write_pack,
    },
    signing::{generate_auditor_key, sign_canonical_bytes},
    timeline::{TimelineRow, Window, build_timeline, parse_window, truncate_timeline},
};

/// Run the CLI.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Verify(args)) => run_verify(&args),
        Some(Command::Keygen(args)) => run_keygen(&args),
        Some(Command::Fixture(args)) => run_fixture(&args).await,
        Some(Command::Completions(args)) => {
            clap_complete::generate(
                args.shell,
                &mut Cli::command(),
                "krabka-evidence",
                &mut std::io::stdout(),
            );
            ExitCode::Clean.into()
        }
        None => run_build(cli.build).await,
    }
}

/// Build a pack from ledger copies.
async fn run_build(args: krabka_evidence::cli::BuildArgs) -> std::process::ExitCode {
    if args.selection.list_checks {
        for id in ALL_CHECKS {
            println!("{} - {}", id.kebab(), id.title());
        }
        return ExitCode::Clean.into();
    }
    let quiet = args.verbosity.quiet;
    let json = matches!(args.verbosity.format, OutputFormat::Json);
    match build_pack(args).await {
        Ok(outcome) => {
            if quiet {
                // The exit code is the answer.
            } else if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": if outcome.findings == 0 { "clean" } else { "findings" },
                        "findings": outcome.findings,
                        "notes": outcome.notes,
                        "pack": outcome.pack,
                        "not_checked": outcome.not_checked,
                    })
                );
            } else if outcome.findings == 0 {
                println!("CLEAN: evidence pack holds no findings");
            } else {
                println!(
                    "FINDINGS: evidence pack holds {} finding(s)",
                    outcome.findings
                );
            }
            if outcome.findings > 0 || outcome.require_failed {
                ExitCode::Findings.into()
            } else {
                ExitCode::Clean.into()
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            if let Some(hint) = error_hint(&error) {
                eprintln!("hint: {hint}");
            }
            ExitCode::Unreadable.into()
        }
    }
}

/// What a build produced.
struct BuildOutcome {
    findings: usize,
    notes: usize,
    pack: String,
    not_checked: usize,
    require_failed: bool,
}

/// Required paths, unwrapped from the CLI options once.
struct LedgerDirs {
    audit: PathBuf,
    metadata: PathBuf,
    archive_raw: String,
    keys: PathBuf,
    out: PathBuf,
    sign_with: PathBuf,
}

/// Validated build inputs shared by every phase.
struct BuildContext {
    window: Window,
    only: Option<HashSet<CheckId>>,
    trust: TrustMaterial,
    dirs: LedgerDirs,
}

impl BuildContext {
    /// Validate flags, load trust, and refuse an output inside an input.
    fn resolve(args: &krabka_evidence::cli::BuildArgs) -> Result<Self, EvidenceError> {
        let window = parse_window(args.from.as_deref(), args.to.as_deref())?;
        let only = parse_only(args.selection.only.as_deref())?;
        let keys = require("--operator-keys", args.operator_keys.clone())?;
        let trust = load_cli_trust(args, &keys)?;
        let dirs = LedgerDirs {
            audit: require("--audit", args.audit.clone())?,
            metadata: require("--metadata", args.metadata.clone())?,
            archive_raw: require("--archive", args.archive.clone())?,
            keys,
            out: require("-o/--output", args.output.clone())?,
            sign_with: require("--sign-with", args.sign_with.clone())?,
        };
        refuse_output_inside_input(
            &dirs.out,
            &[&dirs.audit, &dirs.metadata, &dirs.keys],
            &dirs.archive_raw,
        )?;
        Ok(Self {
            window,
            only,
            trust,
            dirs,
        })
    }
}

/// What step 1 verified and decoded.
struct LedgerOutputs {
    audit: AuditLedger,
    metadata: MetadataLedger,
    worm_manifests: u64,
}

/// Build the pack.
async fn build_pack(args: krabka_evidence::cli::BuildArgs) -> Result<BuildOutcome, EvidenceError> {
    let context = BuildContext::resolve(&args)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    let ledgers = read_ledger_phase(&args, &context, &mut findings, &mut notes).await?;
    let (timeline, truncated) = check_phase(&args, &context, &ledgers, &mut findings, &mut notes);
    finish_pack_phase(
        &args, &context, &ledgers, timeline, truncated, findings, notes,
    )
}

/// Step 1: run the per-ledger verifiers and decode their rows.
async fn read_ledger_phase(
    args: &krabka_evidence::cli::BuildArgs,
    context: &BuildContext,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) -> Result<LedgerOutputs, EvidenceError> {
    let verbose = args.verbosity.verbose;
    let audit = read_audit_ledger(
        &context.dirs.audit,
        &context.trust,
        args.limits.max_segment_bytes,
        findings,
        notes,
    )?;
    if verbose {
        eprintln!("audit: {} record(s) decoded", audit.rows.len());
    }
    let metadata = read_metadata_ledger(
        &context.dirs.metadata,
        args.limits.max_segment_bytes,
        findings,
        notes,
    )?;
    if verbose {
        eprintln!("metadata: {} relevant row(s)", metadata.rows.len());
    }
    let worm_manifests = verify_worm_input(args, context, findings, notes, verbose).await?;
    Ok(LedgerOutputs {
        audit,
        metadata,
        worm_manifests,
    })
}

/// Verify the WORM archive unless `--only` excludes it.
async fn verify_worm_input(
    args: &krabka_evidence::cli::BuildArgs,
    context: &BuildContext,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
    verbose: bool,
) -> Result<u64, EvidenceError> {
    if context
        .only
        .as_ref()
        .is_some_and(|set| !set.contains(&CheckId::WormArchive))
    {
        notes.push(Note::new(
            CheckId::WormArchive,
            "WORM archive NOT CHECKED: excluded by --only",
        ));
        return Ok(0);
    }
    let archive_spec = parse_archive_spec(
        &context.dirs.archive_raw,
        &args.s3_region,
        args.s3_endpoint.clone(),
        args.allow_http,
    )?;
    let expect_head = args
        .expect_head
        .as_deref()
        .map(parse_chain_head)
        .transpose()
        .map_err(|reason| EvidenceError::BadWindow { reason })?;
    let grading = WormGrading {
        deep: args.worm_grading.deep,
        strict_orphans: args.worm_grading.strict_orphans,
        allow_epoch_restarts: args.worm_grading.allow_epoch_restarts,
        expect_head,
    };
    let (worm_report, mut worm_findings, mut worm_notes) = if args.limits.archive_timeout_secs == 0
    {
        read_archive_ledger(&archive_spec, &context.trust, grading).await?
    } else {
        let timeout = std::time::Duration::from_secs(args.limits.archive_timeout_secs);
        tokio::time::timeout(
            timeout,
            read_archive_ledger(&archive_spec, &context.trust, grading),
        )
        .await
        .map_err(|_| {
            EvidenceError::input(
                format!("archive {}", archive_spec.label),
                anyhow::anyhow!(
                    "archive verification timed out after {}s",
                    args.limits.archive_timeout_secs,
                ),
            )
        })??
    };
    if verbose {
        eprintln!(
            "archive: {} manifest(s) over {} partition(s)",
            worm_report.manifests(),
            worm_report.partitions.len(),
        );
    }
    let manifests = worm_report.manifests();
    findings.append(&mut worm_findings);
    notes.append(&mut worm_notes);
    Ok(manifests)
}

/// Steps 2+3: timeline and cross-checks, honoring `--only`.
fn check_phase(
    args: &krabka_evidence::cli::BuildArgs,
    context: &BuildContext,
    ledgers: &LedgerOutputs,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) -> (Vec<TimelineRow>, bool) {
    let timeline_full = build_timeline(&ledgers.audit, &ledgers.metadata);
    let (timeline, truncated) = truncate_timeline(timeline_full, args.limits.max_timeline_rows);
    if truncated {
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            format!(
                "timeline truncated to {} rows (--max-timeline-rows)",
                args.limits.max_timeline_rows,
            ),
        ));
    }
    run_cross_checks(
        &CheckInputs {
            audit: &ledgers.audit,
            metadata: &ledgers.metadata,
            trust: &context.trust,
            window: &context.window,
            cluster_id: args.cluster_id.as_deref(),
        },
        findings,
        notes,
    );
    if let Some(set) = &context.only {
        findings.retain(|finding| set.contains(&finding.check));
        notes.retain(|note| set.contains(&note.check));
        for id in ALL_CHECKS {
            if !set.contains(&id) {
                notes.push(Note::new(id, "NOT CHECKED: excluded by --only".to_string()));
            }
        }
    }
    findings.sort_by_key(finding_order);
    notes.sort_by(|a, b| format!("{:?}", a.check).cmp(&format!("{:?}", b.check)));
    (timeline, truncated)
}

/// Step 4: digest the inputs, sign the report, write the pack.
#[allow(clippy::too_many_arguments)]
fn finish_pack_phase(
    args: &krabka_evidence::cli::BuildArgs,
    context: &BuildContext,
    ledgers: &LedgerOutputs,
    timeline: Vec<TimelineRow>,
    truncated: bool,
    findings: Vec<Finding>,
    notes: Vec<Note>,
) -> Result<BuildOutcome, EvidenceError> {
    let (digests, file_hashes) = digest_inputs(
        &context.dirs.audit,
        &context.dirs.metadata,
        &context.dirs.keys,
        &context.dirs.archive_raw,
    )?;
    if args.verbosity.verbose {
        for (slot, input) in &digests {
            eprintln!("digest {slot}: {}", input.digest);
        }
    }

    let sign_with = &context.dirs.sign_with;
    let signer = FileEd25519Signer::from_pkcs8_file(sign_with, args.auditor_key_id.clone())
        .map_err(|source| {
            EvidenceError::input(
                format!("auditor key {}", sign_with.display()),
                anyhow::anyhow!(source.to_string()),
            )
        })?;
    let report = build_report(ReportInputs {
        findings,
        notes,
        timeline,
        digests,
        audit_records: ledgers.audit.rows.len(),
        metadata_records: ledgers.metadata.rows.len(),
        worm_manifests: ledgers.worm_manifests,
        from_flag: args.from.clone(),
        to_flag: args.to.clone(),
        from_ms: context.window.from_ms,
        to_ms: context.window.to_ms,
        trust: TrustCounts {
            operators: context.trust.operator_count,
            audit: context.trust.audit_count,
            worm: context.trust.worm_count,
        },
        timeline_truncated: truncated,
        auditor: AuditorIdentity {
            key_id: args.auditor_key_id.clone(),
            public_key_hex: hex::encode(signer.public_key()),
        },
    });
    let canonical = canonical_json(&report);
    let signature = sign_canonical_bytes(sign_with, &canonical)?;
    let written = write_pack(&context.dirs.out, &report, &signature, &file_hashes)?;
    if !args.verbosity.quiet && matches!(args.verbosity.format, OutputFormat::Text) {
        for path in &written {
            println!("wrote {}", path.display());
        }
    }
    let not_checked = report
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::NotChecked)
        .count();
    let require_failed = args.selection.require_all_checked && not_checked > 0;
    if require_failed && !args.verbosity.quiet {
        eprintln!("error: {not_checked} check(s) ended not-checked (--require-all-checked)");
    }
    Ok(BuildOutcome {
        findings: report.counts.findings,
        notes: report.counts.notes,
        pack: context.dirs.out.to_string_lossy().to_string(),
        not_checked,
        require_failed,
    })
}

/// Parse `--only` into a check set.
///
/// # Errors
///
/// Returns [`EvidenceError::BadWindow`] when an id is unknown.
fn parse_only(
    only: Option<&str>,
) -> Result<Option<std::collections::HashSet<CheckId>>, EvidenceError> {
    let Some(list) = only else {
        return Ok(None);
    };
    let mut set = std::collections::HashSet::new();
    for raw in list.split(',') {
        let id = raw.trim();
        match CheckId::from_kebab(id) {
            Some(check) => {
                set.insert(check);
            }
            None => {
                return Err(EvidenceError::BadWindow {
                    reason: format!(
                        "unknown check {id:?}; run with --list-checks to see the check ids"
                    ),
                });
            }
        }
    }
    if set.is_empty() {
        return Err(EvidenceError::BadWindow {
            reason: "--only needs at least one check id".to_string(),
        });
    }
    Ok(Some(set))
}

/// Refuse to write the pack inside (or around) its own inputs.
///
/// A pack written into an input directory would be hashed into the next run
/// over that input, and an input inside the pack directory would be hashed
/// into itself.
///
/// # Errors
///
/// Returns [`EvidenceError::BadWindow`] when the output nests with an input.
fn refuse_output_inside_input(
    out_dir: &std::path::Path,
    input_dirs: &[&std::path::Path],
    archive_raw: &str,
) -> Result<(), EvidenceError> {
    let anchor = |path: &std::path::Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        }
    };
    let out = anchor(out_dir);
    let mut inputs: Vec<PathBuf> = input_dirs.iter().map(|path| anchor(path)).collect();
    if !archive_raw.starts_with("s3://") {
        inputs.push(anchor(std::path::Path::new(archive_raw)));
    }
    for input in inputs {
        if out == input || out.starts_with(&input) || input.starts_with(&out) {
            return Err(EvidenceError::BadWindow {
                reason: format!(
                    "refusing to write the pack to {}: it nests with the input {}",
                    out_dir.display(),
                    input.display(),
                ),
            });
        }
    }
    Ok(())
}

/// Suggest the likely fix for an exit-2 failure.
fn error_hint(error: &EvidenceError) -> Option<String> {
    match error {
        EvidenceError::InputUnreadable { context, .. } if context.contains("audit partition") => {
            Some(
                "copy the audit partition directory first; it must hold *.log segments".to_string(),
            )
        }
        EvidenceError::InputUnreadable { context, .. } if context.contains("metadata input") => {
            Some(
                "point --metadata at a segment directory, a snapshot directory, or a \
                 krabka-backup capture holding restore-inputs/"
                    .to_string(),
            )
        }
        EvidenceError::InputUnreadable { context, .. } if context.contains("archive") => Some(
            "point --archive at a local directory or an s3://bucket[/prefix] URL the \
                 ambient AWS chain can read"
                .to_string(),
        ),
        EvidenceError::InputUnreadable { context, .. } if context.contains("auditor key") => {
            Some("mint one with: krabka-evidence keygen --out auditor".to_string())
        }
        EvidenceError::KeysUnreadable { .. } => Some(
            "each public_key_path must hold a raw 32-byte Ed25519 key, resolved \
             against the keys file's directory"
                .to_string(),
        ),
        EvidenceError::BadWindow { .. } => Some(
            "times accept YYYY-MM-DD, RFC 3339, or epoch millis; --from must not be \
             after --to"
                .to_string(),
        ),
        _ => None,
    }
}

/// Sort findings by check, then offsets, for a stable report.
fn finding_order(finding: &Finding) -> (String, i64, i64) {
    (
        format!("{:?}", finding.check),
        finding.audit_offset.unwrap_or(i64::MAX),
        finding.metadata_offset.unwrap_or(i64::MAX),
    )
}

/// Require a build flag.
fn require<T>(flag: &str, value: Option<T>) -> Result<T, EvidenceError> {
    value.ok_or_else(|| EvidenceError::BadWindow {
        reason: format!("{flag} is required to build a report"),
    })
}

/// Load the keys file plus any CLI-supplied broker keys.
fn load_cli_trust(
    args: &krabka_evidence::cli::BuildArgs,
    keys_path: &std::path::Path,
) -> Result<krabka_evidence::keys::TrustMaterial, EvidenceError> {
    if args.worm_key_id.len() != args.worm_public_key.len() {
        return Err(EvidenceError::BadWindow {
            reason: "--worm-key-id and --worm-public-key must pair by position".to_string(),
        });
    }
    let cli_audit_keys = match (&args.audit_key_id, &args.audit_public_key) {
        (Some(key_id), Some(public_key)) => vec![CliKeyPair {
            key_id: key_id.clone(),
            public_key: public_key.clone(),
        }],
        (None, None) => Vec::new(),
        _ => {
            return Err(EvidenceError::BadWindow {
                reason: "--audit-key-id and --audit-public-key must be given together".to_string(),
            });
        }
    };
    let cli_worm_keys: Vec<CliKeyPair> = args
        .worm_key_id
        .iter()
        .zip(&args.worm_public_key)
        .map(|(key_id, public_key)| CliKeyPair {
            key_id: key_id.clone(),
            public_key: public_key.clone(),
        })
        .collect();
    load_trust(keys_path, &cli_audit_keys, &cli_worm_keys)
}

/// Input digests plus per-file hashes, by slot name.
type InputDigests = (
    BTreeMap<String, ReportInput>,
    BTreeMap<String, BTreeMap<String, String>>,
);

/// Hash every input for the pack's digest table.
fn digest_inputs(
    audit_dir: &std::path::Path,
    metadata_dir: &std::path::Path,
    keys_path: &std::path::Path,
    archive_raw: &str,
) -> Result<InputDigests, EvidenceError> {
    let mut digests = BTreeMap::new();
    let mut file_hashes = BTreeMap::new();
    for (slot, given) in [
        ("audit", audit_dir.to_string_lossy().to_string()),
        ("metadata", metadata_dir.to_string_lossy().to_string()),
        ("operator_keys", keys_path.to_string_lossy().to_string()),
    ] {
        let digest = digest_path(&PathBuf::from(&given), slot)?;
        file_hashes.insert(slot.to_string(), digest.file_hashes.clone());
        digests.insert(
            slot.to_string(),
            ReportInput {
                given,
                digest: digest.digest,
                files: digest.files,
                bytes: digest.bytes,
            },
        );
    }
    if archive_raw.starts_with("s3://") {
        digests.insert(
            "archive".to_string(),
            ReportInput {
                given: archive_raw.to_string(),
                digest: format!("remote:{archive_raw}"),
                files: 0,
                bytes: 0,
            },
        );
        file_hashes.insert("archive".to_string(), BTreeMap::new());
    } else {
        let digest = digest_path(&PathBuf::from(archive_raw), "archive")?;
        file_hashes.insert("archive".to_string(), digest.file_hashes.clone());
        digests.insert(
            "archive".to_string(),
            ReportInput {
                given: archive_raw.to_string(),
                digest: digest.digest,
                files: digest.files,
                bytes: digest.bytes,
            },
        );
    }
    Ok((digests, file_hashes))
}

/// Verify a pack.
fn run_verify(args: &krabka_evidence::cli::VerifyArgs) -> std::process::ExitCode {
    let json = matches!(args.output.format, OutputFormat::Json);
    let quiet = args.output.quiet;
    match verify_pack(&args.pack) {
        Ok(pack) => {
            if pack.report.tool_version != env!("CARGO_PKG_VERSION") {
                eprintln!(
                    "warning: pack was written by krabka-evidence {}; this verifier is {}",
                    pack.report.tool_version,
                    env!("CARGO_PKG_VERSION"),
                );
            }
            if !pack.authentic {
                let reason = pack
                    .reason
                    .unwrap_or_else(|| "signature invalid".to_string());
                if !quiet {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({"authentic": false, "reason": reason})
                        );
                    } else {
                        eprintln!("FAIL: {reason}");
                    }
                }
                return ExitCode::Findings.into();
            }
            if let Some(pinned) = &args.auditor_public_key {
                let pinned_bytes = std::fs::read(pinned).unwrap_or_default();
                let embedded =
                    hex::decode(pack.report.auditor.public_key_hex.trim()).unwrap_or_default();
                if pinned_bytes != embedded {
                    if !quiet {
                        eprintln!("FAIL: pack auditor key does not match --auditor-public-key");
                    }
                    return ExitCode::Findings.into();
                }
            }
            if let Some(code) = rehash_verify_inputs(args, &pack.report) {
                return code;
            }
            if args.fail_on_findings && pack.report.counts.findings > 0 {
                if !quiet {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "authentic": true,
                                "findings": pack.report.counts.findings,
                                "failed": "--fail-on-findings",
                            })
                        );
                    } else {
                        eprintln!(
                            "FAIL: pack is authentic but holds {} finding(s) (--fail-on-findings)",
                            pack.report.counts.findings,
                        );
                    }
                }
                return ExitCode::Findings.into();
            }
            if !quiet {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "authentic": true,
                            "findings": pack.report.counts.findings,
                            "notes": pack.report.counts.notes,
                        })
                    );
                } else {
                    println!(
                        "OK: evidence pack is authentic ({} finding(s), {} note(s) inside)",
                        pack.report.counts.findings, pack.report.counts.notes
                    );
                    for check in &pack.report.checks {
                        let word = match check.status {
                            CheckStatus::Pass => "pass",
                            CheckStatus::Finding => "finding",
                            CheckStatus::NotChecked => "not checked",
                        };
                        println!(
                            "  {}: {word} ({} finding(s))",
                            check.id.kebab(),
                            check.findings
                        );
                    }
                }
            }
            ExitCode::Clean.into()
        }
        Err(error) => {
            eprintln!("error: {error}");
            if let Some(hint) = error_hint(&error) {
                eprintln!("hint: {hint}");
            }
            ExitCode::Unreadable.into()
        }
    }
}

/// Re-hash the inputs `verify` was given, comparing with the pack's record.
///
/// Returns the exit code when verification already failed.
fn rehash_verify_inputs(
    args: &krabka_evidence::cli::VerifyArgs,
    report: &krabka_evidence::report::EvidenceReport,
) -> Option<std::process::ExitCode> {
    for (slot, path) in [("audit", &args.audit), ("metadata", &args.metadata)]
        .iter()
        .filter_map(|(slot, path)| path.as_ref().map(|path| (*slot, path)))
    {
        match digest_path(path, slot) {
            Ok(digest) => {
                let expected = report.inputs.get(slot).map(|input| &input.digest);
                if expected != Some(&digest.digest) {
                    eprintln!("FAIL: {slot} input digest differs from the pack's record");
                    return Some(ExitCode::Findings.into());
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                return Some(ExitCode::Unreadable.into());
            }
        }
    }
    if let Some(archive) = &args.archive {
        if archive.starts_with("s3://") {
            eprintln!("note: remote archives cannot be re-hashed; skipping");
        } else {
            match digest_path(&PathBuf::from(archive), "archive") {
                Ok(digest) => {
                    let expected = report.inputs.get("archive").map(|input| &input.digest);
                    if expected != Some(&digest.digest) {
                        eprintln!("FAIL: archive input digest differs from the pack's record");
                        return Some(ExitCode::Findings.into());
                    }
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    return Some(ExitCode::Unreadable.into());
                }
            }
        }
    }
    None
}

/// Mint an auditor key.
fn run_keygen(args: &krabka_evidence::cli::KeygenArgs) -> std::process::ExitCode {
    match generate_auditor_key() {
        Ok(keypair) => {
            let prefix = args.out.to_string_lossy().to_string();
            let private_path = PathBuf::from(format!("{prefix}.priv.pkcs8"));
            let public_path = PathBuf::from(format!("{prefix}.pub"));
            if let Err(error) = std::fs::write(&private_path, &keypair.private_pkcs8)
                .and_then(|()| std::fs::write(&public_path, &keypair.public_key))
            {
                eprintln!("error: cannot write keys: {error}");
                return ExitCode::Unreadable.into();
            }
            println!("wrote {}", private_path.display());
            println!("wrote {}", public_path.display());
            println!("key_id: {}", args.key_id);
            println!("public_key: {}", hex::encode(&keypair.public_key));
            ExitCode::Clean.into()
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::Unreadable.into()
        }
    }
}

/// Generate fixtures.
async fn run_fixture(args: &krabka_evidence::cli::FixtureArgs) -> std::process::ExitCode {
    if args.scenario == "bulk" {
        let out = args.out.join("bulk");
        match generate_bulk_audit(&out, args.events) {
            Ok(paths) => {
                println!("wrote {}", paths.root.display());
                return ExitCode::Clean.into();
            }
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::Unreadable.into();
            }
        }
    }
    if args.layout != "segments" && args.layout != "capture" {
        eprintln!(
            "error: unknown layout {:?}; want segments or capture",
            args.layout
        );
        return ExitCode::Unreadable.into();
    }
    let scenarios: Vec<Scenario> = if args.scenario == "all" {
        Scenario::all().to_vec()
    } else if let Some(scenario) = Scenario::from_name(&args.scenario) {
        vec![scenario]
    } else {
        eprintln!(
            "error: unknown scenario {:?}; want clean, missing-audit, flipped-sig, \
             approver-change, corrupt-chain, expired-approval, unsigned, worm-tamper, \
             bulk, or all",
            args.scenario
        );
        return ExitCode::Unreadable.into();
    };
    let options = FixtureOptions {
        seed: args.seed.clone(),
        capture_layout: args.layout == "capture",
    };
    for scenario in scenarios {
        match generate_scenario(scenario, &args.out, &options).await {
            Ok(paths) => println!("wrote {}", paths.root.display()),
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::Unreadable.into();
            }
        }
    }
    ExitCode::Clean.into()
}
