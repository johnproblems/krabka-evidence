//! Step 4: the signed evidence pack.
//!
//! The pack is a directory holding `report.json` (canonicalized and signed),
//! `report.sig` (the raw 64-byte Ed25519 signature), `report.html` (one
//! section per check), and `input-files.json` (per-file hashes of the local
//! inputs). `verify` re-canonicalizes the JSON, checks the signature, and
//! optionally re-hashes inputs.
//!
//! The report says what was checked and what was not: every check lands in
//! the summary table as pass, finding, or not-checked. It makes no claim
//! about controls outside the ledgers.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    error::EvidenceError,
    finding::{CheckId, CheckStatus, Finding, Note},
    signing::verify_canonical_bytes,
    timeline::TimelineRow,
};

/// Report format marker; bumped when the schema changes.
pub const REPORT_FORMAT: &str = "krabka-evidence-report/1";

/// One input's identity and digest, as recorded in the pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInput {
    /// What the input was given as (path or URL).
    pub given: String,
    /// Hex SHA-256 over the input listing, or `remote:` + label for S3.
    pub digest: String,
    /// How many files were hashed (0 for remote inputs).
    pub files: u64,
    /// Total bytes hashed (0 for remote inputs).
    pub bytes: u64,
}

/// One row of the report's check summary table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSummary {
    /// The check.
    pub id: CheckId,
    /// Human-readable title.
    pub title: String,
    /// Outcome.
    pub status: CheckStatus,
    /// How many findings this check raised.
    pub findings: usize,
}

/// How many keys of each kind were provisioned for the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCounts {
    /// Operator keys.
    pub operators: usize,
    /// Audit checkpoint keys.
    pub audit: usize,
    /// WORM manifest keys.
    pub worm: usize,
}

/// Report counts for the summary header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCounts {
    /// Audit records decoded.
    pub audit_records: usize,
    /// Relevant metadata records decoded.
    pub metadata_records: usize,
    /// WORM manifests verified.
    pub worm_manifests: u64,
    /// Timeline rows.
    pub timeline_rows: usize,
    /// Findings.
    pub findings: usize,
    /// Notes.
    pub notes: usize,
}

/// The auditor key that signed the pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditorIdentity {
    /// Key id from `--auditor-key-id`.
    pub key_id: String,
    /// Hex raw 32-byte public key the signature verifies against.
    pub public_key_hex: String,
}

/// The evidence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Format marker.
    pub format: String,
    /// Generation time as RFC 3339.
    pub generated_at: String,
    /// Tool version.
    pub tool_version: String,
    /// Requested window.
    pub window: ReportWindow,
    /// Inputs and their digests.
    pub inputs: BTreeMap<String, ReportInput>,
    /// One row per check.
    pub checks: Vec<CheckSummary>,
    /// Findings (exit code 1 when non-empty).
    pub findings: Vec<Finding>,
    /// Informational notes.
    pub notes: Vec<Note>,
    /// The unified timeline.
    pub timeline: Vec<TimelineRow>,
    /// Summary counts.
    pub counts: ReportCounts,
    /// Keys provisioned for the run.
    pub trust: TrustCounts,
    /// Whether the timeline was truncated to `--max-timeline-rows`.
    pub timeline_truncated: bool,
    /// The signing auditor.
    pub auditor: AuditorIdentity,
}

/// The requested window, as given and as epoch millis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportWindow {
    /// `--from` as given, if any.
    pub from: Option<String>,
    /// `--to` as given, if any.
    pub to: Option<String>,
    /// Inclusive lower bound in epoch millis.
    pub from_ms: i64,
    /// Exclusive upper bound in epoch millis.
    pub to_ms: i64,
}

/// Everything `build_report` needs.
pub struct ReportInputs {
    /// Findings in check order.
    pub findings: Vec<Finding>,
    /// Notes.
    pub notes: Vec<Note>,
    /// Timeline rows.
    pub timeline: Vec<TimelineRow>,
    /// Input digests by slot (`audit`, `metadata`, `archive`, `operator_keys`).
    pub digests: BTreeMap<String, ReportInput>,
    /// Audit records decoded.
    pub audit_records: usize,
    /// Metadata records decoded.
    pub metadata_records: usize,
    /// WORM manifests verified.
    pub worm_manifests: u64,
    /// Window flags as given.
    pub from_flag: Option<String>,
    /// Window flags as given.
    pub to_flag: Option<String>,
    /// Window bounds.
    pub from_ms: i64,
    /// Window bounds.
    pub to_ms: i64,
    /// Keys provisioned for the run.
    pub trust: TrustCounts,
    /// Whether the timeline was truncated.
    pub timeline_truncated: bool,
    /// Auditor identity.
    pub auditor: AuditorIdentity,
}

/// All checks in report order.
pub const ALL_CHECKS: [CheckId; 11] = [
    CheckId::AuditChain,
    CheckId::AuditLossWindows,
    CheckId::WormArchive,
    CheckId::MetadataCoverage,
    CheckId::AppliedWithNoAuditEvent,
    CheckId::AuditedActionNotInMetadata,
    CheckId::SignatureVerification,
    CheckId::TwoPersonRule,
    CheckId::BypassListing,
    CheckId::ApproverSetChange,
    CheckId::GatedOperationWithoutApproval,
];

/// Assemble the report, grading every check.
///
/// A check with findings grades `finding`; a check named only by notes that
/// say `NOT CHECKED` grades `not-checked`; anything else grades `pass`.
///
/// # Panics
///
/// Panics when the system clock is before the Unix epoch, which cannot
/// happen on a working machine.
#[must_use]
pub fn build_report(inputs: ReportInputs) -> EvidenceReport {
    let mut checks = Vec::with_capacity(ALL_CHECKS.len());
    for id in ALL_CHECKS {
        let finding_count = inputs
            .findings
            .iter()
            .filter(|finding| finding.check == id)
            .count();
        let not_checked = finding_count == 0
            && inputs
                .notes
                .iter()
                .any(|note| note.check == id && note.detail.contains("NOT CHECKED"));
        let status = if finding_count > 0 {
            CheckStatus::Finding
        } else if not_checked {
            CheckStatus::NotChecked
        } else {
            CheckStatus::Pass
        };
        checks.push(CheckSummary {
            id,
            title: id.title().to_string(),
            status,
            findings: finding_count,
        });
    }
    EvidenceReport {
        format: REPORT_FORMAT.to_string(),
        generated_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        window: ReportWindow {
            from: inputs.from_flag,
            to: inputs.to_flag,
            from_ms: inputs.from_ms,
            to_ms: inputs.to_ms,
        },
        inputs: inputs.digests,
        checks,
        counts: ReportCounts {
            audit_records: inputs.audit_records,
            metadata_records: inputs.metadata_records,
            worm_manifests: inputs.worm_manifests,
            timeline_rows: inputs.timeline.len(),
            findings: inputs.findings.len(),
            notes: inputs.notes.len(),
        },
        findings: inputs.findings,
        notes: inputs.notes,
        timeline: inputs.timeline,
        trust: inputs.trust,
        timeline_truncated: inputs.timeline_truncated,
        auditor: inputs.auditor,
    }
}

/// Canonicalize the report: JSON with recursively sorted keys, no whitespace.
///
/// The signature covers exactly these bytes.
#[must_use]
pub fn canonical_json(report: &EvidenceReport) -> Vec<u8> {
    let value = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    let sorted = sort_value(&value);
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// Recursively sort an owned JSON value's object keys.
fn sort_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::with_capacity(map.len());
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sort_value).collect())
        }
        _ => value.clone(),
    }
}

/// Write the evidence pack: `report.json`, `report.sig`, `report.html`,
/// `input-files.json`.
///
/// # Errors
///
/// Returns [`EvidenceError::OutputUnwritable`] when the directory cannot be
/// created or a file cannot be written.
pub fn write_pack(
    out_dir: &Path,
    report: &EvidenceReport,
    signature: &[u8],
    file_hashes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Vec<PathBuf>, EvidenceError> {
    std::fs::create_dir_all(out_dir).map_err(|source| EvidenceError::OutputUnwritable {
        path: out_dir.to_path_buf(),
        source: source.into(),
    })?;
    let pretty = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
    let files = [
        ("report.json", pretty.into_bytes()),
        ("report.sig", signature.to_vec()),
        ("report.html", render_html(report).into_bytes()),
        (
            "input-files.json",
            serde_json::to_vec_pretty(file_hashes).unwrap_or_default(),
        ),
    ];
    let mut written = Vec::with_capacity(files.len());
    for (name, bytes) in files {
        let path = out_dir.join(name);
        std::fs::write(&path, bytes).map_err(|source| EvidenceError::OutputUnwritable {
            path: path.clone(),
            source: source.into(),
        })?;
        written.push(path);
    }
    Ok(written)
}

/// Outcome of verifying a pack.
#[derive(Debug)]
pub struct PackVerification {
    /// The parsed report.
    pub report: EvidenceReport,
    /// Whether the signature verifies.
    pub authentic: bool,
    /// Why not, when inauthentic.
    pub reason: Option<String>,
}

/// Verify a pack's signature against its embedded auditor key.
///
/// Also cross-checks `input-files.json` against the digests `report.json`
/// names, so neither file can be swapped without detection.
///
/// # Errors
///
/// Returns [`EvidenceError::PackUnreadable`] when the pack is missing files
/// or they do not parse. A bad signature or a swapped listing is not an
/// error: it is an inauthentic [`PackVerification`].
pub fn verify_pack(dir: &Path) -> Result<PackVerification, EvidenceError> {
    let unreadable = |reason: String| EvidenceError::PackUnreadable {
        path: dir.to_path_buf(),
        reason,
    };
    let json = std::fs::read(dir.join("report.json"))
        .map_err(|source| unreadable(format!("cannot read report.json: {source}")))?;
    let signature = std::fs::read(dir.join("report.sig"))
        .map_err(|source| unreadable(format!("cannot read report.sig: {source}")))?;
    let listing = std::fs::read(dir.join("input-files.json"))
        .map_err(|source| unreadable(format!("cannot read input-files.json: {source}")))?;
    let report: EvidenceReport = serde_json::from_slice(&json)
        .map_err(|source| unreadable(format!("report.json does not parse: {source}")))?;
    let files: BTreeMap<String, BTreeMap<String, String>> = serde_json::from_slice(&listing)
        .map_err(|source| unreadable(format!("input-files.json does not parse: {source}")))?;
    let listing_mismatch = report.inputs.iter().find_map(|(slot, input)| {
        if input.digest.starts_with("remote:") {
            return None;
        }
        let listed = files.get(slot)?;
        (crate::hash::listing_digest(listed) != input.digest).then(|| {
            format!(
                "input-files.json listing for {slot:?} does not match the digest in report.json"
            )
        })
    });
    if let Some(reason) = listing_mismatch {
        return Ok(inauthentic(report, reason));
    }
    if report
        .inputs
        .iter()
        .any(|(slot, input)| !input.digest.starts_with("remote:") && !files.contains_key(slot))
    {
        return Ok(inauthentic(
            report,
            "input-files.json has no listing for a hashed input".to_string(),
        ));
    }
    if report.format != REPORT_FORMAT {
        return Err(unreadable(format!(
            "report format {:?} is not {REPORT_FORMAT:?}",
            report.format
        )));
    }
    let public_key = hex::decode(report.auditor.public_key_hex.trim())
        .map_err(|_| unreadable("auditor public key is not hex".to_string()))?;
    let canonical = canonical_json(&report);
    if verify_canonical_bytes(&public_key, &canonical, &signature) {
        Ok(PackVerification {
            report,
            authentic: true,
            reason: None,
        })
    } else {
        Ok(inauthentic(
            report,
            "report.sig does not verify over report.json".to_string(),
        ))
    }
}

/// Build an inauthentic verification outcome.
const fn inauthentic(report: EvidenceReport, reason: String) -> PackVerification {
    PackVerification {
        report,
        authentic: false,
        reason: Some(reason),
    }
}

/// Render the human-readable report: one section per check.
#[must_use]
pub fn render_html(report: &EvidenceReport) -> String {
    use std::fmt::Write as _;
    let mut html = String::with_capacity(32 * 1024);
    html.push_str(HTML_HEAD);
    let verdict = if report.counts.findings == 0 {
        "<span class=\"pass\">CLEAN</span>"
    } else {
        "<span class=\"finding\">FINDINGS</span>"
    };
    let _ = writeln!(
        html,
        "<h1>krabka-evidence report: {verdict}</h1>\n<p class=\"meta\">Generated {} by krabka-evidence {} \u{00b7} window {} .. {} \u{00b7} {} finding(s), {} note(s)</p>",
        escape(&report.generated_at),
        escape(&report.tool_version),
        report.window.from.as_deref().unwrap_or("unbounded"),
        report.window.to.as_deref().unwrap_or("unbounded"),
        report.counts.findings,
        report.counts.notes,
    );
    write_summary(&mut html, report);
    write_checks_table(&mut html, report);
    write_inputs_table(&mut html, report);
    for check in &report.checks {
        write_check_section(&mut html, report, check);
    }
    write_timeline(&mut html, report);
    let _ = writeln!(
        html,
        "<p class=\"meta\">Signed by auditor key {} (<code>{}</code>). This report covers only the ledgers listed above; it makes no claim about controls outside them.</p>\n</body></html>",
        escape(&report.auditor.key_id),
        escape(&report.auditor.public_key_hex),
    );
    html
}

/// Static document head and stylesheet.
const HTML_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>krabka-evidence report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.6rem}h2{font-size:1.2rem;border-bottom:1px solid #ccc;padding-bottom:.25rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}th,td{border:1px solid #ccc;padding:.3rem .6rem;text-align:left;font-size:.85rem}
th{background:#f4f4f4}.pass{color:#0a6b0a;font-weight:bold}.finding{color:#a00;font-weight:bold}.not-checked{color:#8a6d00;font-weight:bold}
code{font-size:.8rem}.meta{color:#555;font-size:.85rem}ul{font-size:.9rem}
</style></head><body>
"#;

/// Write the summary-counts section.
fn write_summary(html: &mut String, report: &EvidenceReport) {
    use std::fmt::Write as _;
    html.push_str("<h2>Summary counts</h2>\n<table><tr><th>Audit records</th><th>Metadata records</th><th>WORM manifests</th><th>Timeline rows</th></tr>\n");
    let _ = writeln!(
        html,
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr></table>",
        report.counts.audit_records,
        report.counts.metadata_records,
        report.counts.worm_manifests,
        report.counts.timeline_rows,
    );
}

/// Write the checks overview table.
fn write_checks_table(html: &mut String, report: &EvidenceReport) {
    use std::fmt::Write as _;
    html.push_str(
        "<h2>Checks</h2>\n<table><tr><th>Check</th><th>Status</th><th>Findings</th></tr>\n",
    );
    for check in &report.checks {
        let (class, word) = match check.status {
            CheckStatus::Pass => ("pass", "pass"),
            CheckStatus::Finding => ("finding", "finding"),
            CheckStatus::NotChecked => ("not-checked", "not checked"),
        };
        let _ = writeln!(
            html,
            "<tr><td><a href=\"#{}\">{}</a></td><td class=\"{class}\">{word}</td><td>{}</td></tr>",
            check_anchor(check.id),
            escape(&check.title),
            check.findings,
        );
    }
    html.push_str("</table>\n");
}

/// Write the inputs table.
fn write_inputs_table(html: &mut String, report: &EvidenceReport) {
    use std::fmt::Write as _;
    html.push_str(
        "<h2>Inputs</h2>\n<table><tr><th>Slot</th><th>Given</th><th>Digest</th><th>Files</th><th>Bytes</th></tr>\n",
    );
    for (slot, input) in &report.inputs {
        let _ = writeln!(
            html,
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape(slot),
            escape(&input.given),
            escape(&input.digest),
            input.files,
            input.bytes,
        );
    }
    html.push_str("</table>\n");
}

/// Write one check's section with its findings and notes.
fn write_check_section(html: &mut String, report: &EvidenceReport, check: &CheckSummary) {
    use std::fmt::Write as _;
    let _ = writeln!(
        html,
        "<h2 id=\"{}\">{}</h2>",
        check_anchor(check.id),
        escape(&check.title)
    );
    let findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.check == check.id)
        .collect();
    let notes: Vec<&Note> = report
        .notes
        .iter()
        .filter(|note| note.check == check.id)
        .collect();
    if findings.is_empty() && notes.is_empty() {
        html.push_str("<p>Nothing to report.</p>\n");
        return;
    }
    if !findings.is_empty() {
        html.push_str(
            "<table><tr><th>Finding</th><th>Detail</th><th>Audit off.</th><th>Meta off.</th><th>Time</th></tr>\n",
        );
        for finding in findings {
            let _ = writeln!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&finding.title),
                escape(&finding.detail),
                finding
                    .audit_offset
                    .map_or_else(String::new, |off| off.to_string()),
                finding
                    .metadata_offset
                    .map_or_else(String::new, |off| off.to_string()),
                finding
                    .time_ms
                    .map_or_else(String::new, |time| time.to_string()),
            );
        }
        html.push_str("</table>\n");
    }
    if !notes.is_empty() {
        html.push_str("<ul>\n");
        for note in notes {
            let _ = writeln!(html, "<li>{}</li>", escape(&note.detail));
        }
        html.push_str("</ul>\n");
    }
}

/// Timeline rows rendered into HTML; the JSON pack always holds them all.
pub const HTML_TIMELINE_ROWS: usize = 10_000;

/// Write the timeline table, capped so huge runs stay readable.
fn write_timeline(html: &mut String, report: &EvidenceReport) {
    use std::fmt::Write as _;
    html.push_str(
        "<h2>Timeline</h2>\n<table><tr><th>Time</th><th>Action</th><th>Target</th><th>Proposal</th><th>Principal</th><th>Source</th></tr>\n",
    );
    for row in report.timeline.iter().take(HTML_TIMELINE_ROWS) {
        let _ = writeln!(
            html,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape(&row.time),
            escape(&row.action),
            escape(&row.target),
            escape(&row.proposal_id),
            escape(&row.principal),
            escape(&row.source),
        );
    }
    html.push_str("</table>\n");
    if report.timeline.len() > HTML_TIMELINE_ROWS {
        let _ = writeln!(
            html,
            "<p class=\"meta\">Timeline truncated to {HTML_TIMELINE_ROWS} of {} rows; see report.json for the rest.</p>",
            report.timeline.len(),
        );
    }
    if report.timeline_truncated {
        html.push_str(
            "<p class=\"meta\">The timeline itself was truncated to --max-timeline-rows.</p>\n",
        );
    }
}

/// Anchor id for a check section.
const fn check_anchor(id: CheckId) -> &'static str {
    match id {
        CheckId::AuditChain => "audit-chain",
        CheckId::AuditLossWindows => "audit-loss-windows",
        CheckId::WormArchive => "worm-archive",
        CheckId::MetadataCoverage => "metadata-coverage",
        CheckId::AppliedWithNoAuditEvent => "applied-with-no-audit-event",
        CheckId::AuditedActionNotInMetadata => "audited-action-not-in-metadata",
        CheckId::SignatureVerification => "signature-verification",
        CheckId::TwoPersonRule => "two-person-rule",
        CheckId::BypassListing => "bypass-listing",
        CheckId::ApproverSetChange => "approver-set-change",
        CheckId::GatedOperationWithoutApproval => "gated-operation-without-approval",
    }
}

/// Escape HTML special characters.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
