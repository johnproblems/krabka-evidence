//! Command-line interface.
//!
//! ```sh
//! krabka-evidence --from 2026-09-01 --to 2026-10-01 \
//!   --audit ./audit-partition --metadata ./cluster-metadata \
//!   --archive s3://bucket/tiered --operator-keys keys.toml -o evidence/
//! krabka-evidence verify evidence/
//! ```
//!
//! Exit codes: 0 means clean, 1 means findings, 2 means inputs unreadable.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// One signed report from every ledger.
#[derive(Debug, Parser)]
#[command(name = "krabka-evidence", version, about)]
pub struct Cli {
    /// Report-building flags. Required unless a subcommand is given.
    #[command(flatten)]
    pub build: BuildArgs,
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify an evidence pack's signature (and optionally re-hash inputs).
    Verify(VerifyArgs),
    /// Mint an auditor signing key.
    Keygen(KeygenArgs),
    /// Generate synthetic three-ledger inputs for tests and demos.
    Fixture(FixtureArgs),
    /// Print shell completions.
    Completions(CompletionsArgs),
}

/// Machine-readable or human-readable stdout.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object.
    Json,
}

/// How much the run says.
#[derive(Debug, Args)]
pub struct OutputArgs {
    /// Stdout shape.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,
    /// Print nothing; the exit code is the answer.
    #[arg(long, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Print per-phase progress and input digests to stderr.
    #[arg(long)]
    pub verbose: bool,
}

/// Which checks run.
#[derive(Debug, Args)]
pub struct SelectionArgs {
    /// Run only these checks (comma-separated kebab-case ids).
    #[arg(long, value_name = "CHECKS")]
    pub only: Option<String>,
    /// Exit 1 when any check ends not-checked.
    #[arg(long)]
    pub require_all_checked: bool,
    /// List check ids and exit.
    #[arg(long)]
    pub list_checks: bool,
}

/// Bounds that keep hostile or huge inputs tractable.
#[derive(Debug, Args)]
pub struct LimitsArgs {
    /// Refuse ledger files larger than this many bytes.
    #[arg(long, value_name = "BYTES", default_value = "1073741824")]
    pub max_segment_bytes: u64,
    /// Give up on the archive walk after this many seconds (0 disables).
    #[arg(long, value_name = "SECONDS", default_value = "600")]
    pub archive_timeout_secs: u64,
    /// Keep at most this many timeline rows in the pack.
    #[arg(long, value_name = "ROWS", default_value = "100000")]
    pub max_timeline_rows: usize,
}

/// Build a signed evidence pack from ledger copies.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Window start: YYYY-MM-DD, RFC 3339, or epoch millis. Unbounded when absent.
    #[arg(long)]
    pub from: Option<String>,
    /// Window end (exclusive): YYYY-MM-DD, RFC 3339, or epoch millis. Unbounded when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// Audit partition directory (copied, opened read-only).
    #[arg(long, value_name = "PATH")]
    pub audit: Option<PathBuf>,
    /// Metadata input: segment directory or krabka-backup capture.
    #[arg(long, value_name = "PATH")]
    pub metadata: Option<PathBuf>,
    /// WORM archive: local directory or `<s3://bucket>` URL with optional prefix.
    #[arg(long, value_name = "PATH-OR-URL")]
    pub archive: Option<String>,
    /// TOML file carrying `[[operator_keys]]` (plus `[[audit_keys]]`/`[[worm_keys]]`).
    #[arg(long, value_name = "PATH")]
    pub operator_keys: Option<PathBuf>,
    /// Output directory for the evidence pack.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Write into a non-empty output directory (refused by default).
    #[arg(long)]
    pub overwrite: bool,
    /// Cluster id, required to verify freeze signatures.
    #[arg(long, value_name = "ID")]
    pub cluster_id: Option<String>,
    /// Auditor PKCS#8 key to sign the report with.
    #[arg(long, value_name = "PATH")]
    pub sign_with: Option<PathBuf>,
    /// Key id recorded as the report's signer.
    #[arg(long, value_name = "ID", default_value = "auditor-1")]
    pub auditor_key_id: String,
    /// How to grade what the WORM walk finds.
    #[command(flatten)]
    pub worm_grading: WormGradingArgs,
    /// WORM: expected tip all partitions must reach (64 hex chars).
    #[arg(long, value_name = "HEX")]
    pub expect_head: Option<String>,
    /// Audit checkpoint key id (single, like krabka-audit verify).
    #[arg(long, value_name = "ID", requires = "audit_public_key")]
    pub audit_key_id: Option<String>,
    /// Audit checkpoint public key (raw 32 bytes).
    #[arg(long, value_name = "PATH", requires = "audit_key_id")]
    pub audit_public_key: Option<PathBuf>,
    /// WORM manifest key id. Repeat with --worm-public-key for rotations.
    #[arg(long, value_name = "ID", requires = "worm_public_key")]
    pub worm_key_id: Vec<String>,
    /// WORM manifest public key (raw 32 bytes), paired by position.
    #[arg(long, value_name = "PATH", requires = "worm_key_id")]
    pub worm_public_key: Vec<PathBuf>,
    /// S3 region for --archive s3:// URLs.
    #[arg(
        long,
        value_name = "REGION",
        default_value = "us-east-1",
        env = "AWS_REGION"
    )]
    pub s3_region: String,
    /// Custom S3 endpoint, for example <http://minio:9000>.
    #[arg(long, value_name = "URL", env = "AWS_ENDPOINT_URL_S3")]
    pub s3_endpoint: Option<String>,
    /// Allow plaintext HTTP for S3.
    #[arg(long)]
    pub allow_http: bool,
    /// How much the run says.
    #[command(flatten)]
    pub verbosity: OutputArgs,
    /// Which checks run.
    #[command(flatten)]
    pub selection: SelectionArgs,
    /// Bounds for hostile or huge inputs.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

/// How the run grades what the WORM walk finds.
///
/// Separate because these say nothing about what to read and everything about
/// which states fail the run.
#[derive(Debug, Args)]
pub struct WormGradingArgs {
    /// Download every object and recompute its SHA-256.
    #[arg(long)]
    pub deep: bool,
    /// Grade orphan objects as findings.
    #[arg(long)]
    pub strict_orphans: bool,
    /// Accept chain restarts instead of noting them.
    #[arg(long)]
    pub allow_epoch_restarts: bool,
}

/// Verify an evidence pack.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The evidence pack directory.
    pub pack: PathBuf,
    /// Pin the auditor public key instead of trusting the embedded one.
    #[arg(long, value_name = "PATH")]
    pub auditor_public_key: Option<PathBuf>,
    /// Re-hash this audit input and compare with the pack's digest.
    #[arg(long, value_name = "PATH")]
    pub audit: Option<PathBuf>,
    /// Re-hash this metadata input and compare with the pack's digest.
    #[arg(long, value_name = "PATH")]
    pub metadata: Option<PathBuf>,
    /// Re-hash this keys file and compare with the pack's digest.
    #[arg(long, value_name = "PATH")]
    pub operator_keys: Option<PathBuf>,
    /// Re-hash this archive input and compare with the pack's digest.
    #[arg(long, value_name = "PATH-OR-URL")]
    pub archive: Option<String>,
    /// Exit 1 when the authentic pack holds findings.
    #[arg(long)]
    pub fail_on_findings: bool,
    /// How much the run says.
    #[command(flatten)]
    pub output: OutputArgs,
}

/// Mint an auditor signing key.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Output prefix: writes <prefix>.priv.pkcs8 and <prefix>.pub.
    #[arg(long, value_name = "PREFIX")]
    pub out: PathBuf,
    /// Key id recorded when this key signs a report.
    #[arg(long, value_name = "ID", default_value = "auditor-1")]
    pub key_id: String,
    /// Overwrite existing key files (refused by default).
    #[arg(long)]
    pub force: bool,
}

/// Generate fixture inputs.
#[derive(Debug, Args)]
pub struct FixtureArgs {
    /// Scenario: clean, missing-audit, flipped-sig, approver-change,
    /// corrupt-chain, expired-approval, unsigned, worm-tamper, bypass,
    /// gated-op, unknown-key, bulk, or all.
    #[arg(long, value_name = "NAME", default_value = "all")]
    pub scenario: String,
    /// List scenario names and exit.
    #[arg(long)]
    pub list_scenarios: bool,
    /// Output directory.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Bulk scenario: how many audit events to write.
    #[arg(long, value_name = "N", default_value = "50000")]
    pub events: usize,
    /// Derive all fixture keys from this seed instead of minting randomly.
    #[arg(long, value_name = "SEED")]
    pub seed: Option<String>,
    /// Fixture layout: segments (a .log partition) or capture (a backup
    /// capture with a metadata snapshot).
    #[arg(long, value_name = "LAYOUT", default_value = "segments")]
    pub layout: String,
}

/// Print shell completions.
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to complete.
    pub shell: clap_complete::Shell,
}
