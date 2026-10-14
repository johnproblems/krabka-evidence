//! WORM archive ledger: run the shipped archive verifier.
//!
//! Step 1 runs [`krabka_remote_storage::worm::verify::verify_archive`]
//! unchanged and grades its report the way `krabka-worm-verify` does:
//! tampering and head mismatches are findings, orphans are findings only
//! under `--strict-orphans` (reported either way), and attestation holes
//! (epoch restarts, unsigned manifests) are notes.
//!
//! The archive input is a local directory or an `s3://bucket[/prefix]`
//! URL. S3 credentials come from `AWS_ACCESS_KEY_ID` /
//! `AWS_SECRET_ACCESS_KEY` when both are set, else the backend's own
//! instance/task-role chain; the tool never talks to a live broker.

use std::path::PathBuf;

use krabka_object_store::{ObjectStoreConfig, S3Config, build_object_store};
use krabka_remote_storage::{
    ArchiveVerifyReport, ChainHead, PartitionVerifyReport, VerifyDepth, VerifyRequest,
    verify_archive,
};

use crate::{
    error::EvidenceError,
    finding::{CheckId, Finding, Note},
    keys::TrustMaterial,
};

/// How to open the archive under check.
#[derive(Debug, Clone)]
pub struct ArchiveSpec {
    /// Store configuration for `krabka-object-store`.
    pub config: ObjectStoreConfig,
    /// Key prefix inside the store, when the URL carries one.
    pub prefix: Option<String>,
    /// Human-readable label for the report.
    pub label: String,
}

/// Read static S3 credentials from the environment, if both halves exist.
///
/// The store builder only consults its instance/task-role chain, never the
/// environment — without this, `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
/// would be silently ignored and every credential lookup would hit the
/// metadata server first.
fn ambient_s3_credentials() -> (Option<String>, Option<String>) {
    let key = std::env::var("AWS_ACCESS_KEY_ID").ok();
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
    static_s3_credentials(key.as_deref(), secret.as_deref())
}

/// Keep an S3 credential pair only when both halves are present and non-empty.
fn static_s3_credentials(
    key: Option<&str>,
    secret: Option<&str>,
) -> (Option<String>, Option<String>) {
    match (
        key.filter(|value| !value.is_empty()),
        secret.filter(|value| !value.is_empty()),
    ) {
        (Some(key), Some(secret)) => (Some(key.to_string()), Some(secret.to_string())),
        _ => (None, None),
    }
}

/// Parse `--archive` as a local directory or an `s3://bucket[/prefix]` URL.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the value is neither an
/// existing directory nor a parsable `s3://` URL.
pub fn parse_archive_spec(
    raw: &str,
    region: &str,
    endpoint: Option<String>,
    allow_http: bool,
) -> Result<ArchiveSpec, EvidenceError> {
    if let Some(rest) = raw.strip_prefix("s3://") {
        let (bucket, prefix) = match rest.split_once('/') {
            Some((bucket, prefix)) => (bucket, Some(prefix.trim_matches('/').to_string())),
            None => (rest, None),
        };
        if bucket.is_empty() {
            return Err(EvidenceError::input(
                format!("archive {raw}"),
                anyhow::anyhow!("s3 URL has no bucket"),
            ));
        }
        let prefix = prefix.filter(|prefix| !prefix.is_empty());
        let (access_key_id, secret_access_key) = ambient_s3_credentials();
        return Ok(ArchiveSpec {
            config: ObjectStoreConfig::S3(S3Config {
                bucket: bucket.to_string(),
                prefix: prefix.clone(),
                region: region.to_string(),
                endpoint,
                allow_http,
                access_key_id,
                secret_access_key,
                ..Default::default()
            }),
            prefix,
            label: raw.to_string(),
        });
    }
    let path = PathBuf::from(raw);
    if !path.is_dir() {
        return Err(EvidenceError::input(
            format!("archive {raw}"),
            anyhow::anyhow!("not a directory and not an s3:// URL"),
        ));
    }
    Ok(ArchiveSpec {
        config: ObjectStoreConfig::Local { root: path },
        prefix: None,
        label: raw.to_string(),
    })
}

/// Options grading the WORM report.
#[derive(Debug, Clone, Copy)]
pub struct WormGrading {
    /// Download every object and recompute its SHA-256.
    pub deep: bool,
    /// Grade orphan objects as findings.
    pub strict_orphans: bool,
    /// Accept chain restarts instead of noting them as attestation holes.
    pub allow_epoch_restarts: bool,
    /// Expected tip of every partition, from `--expect-head`.
    pub expect_head: Option<ChainHead>,
}

/// Run the WORM verifier and grade its report.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the archive cannot be
/// listed or a manifest cannot be read. A tampered archive is not an error:
/// it is an `Ok` report with findings.
pub async fn read_archive_ledger(
    spec: &ArchiveSpec,
    trust: &TrustMaterial,
    grading: WormGrading,
) -> Result<(ArchiveVerifyReport, Vec<Finding>, Vec<Note>), EvidenceError> {
    let store = build_object_store(&spec.config).map_err(|source| {
        EvidenceError::input(
            format!("archive {}", spec.label),
            anyhow::anyhow!(source.to_string()),
        )
    })?;
    let request = VerifyRequest {
        prefix: spec.prefix.clone(),
        topic: None,
        partition: None,
        depth: if grading.deep {
            VerifyDepth::Deep
        } else {
            VerifyDepth::Shallow
        },
        // The tip comparison happens in grading, so a tip mismatch is its
        // own outcome and is never reported as tampering.
        expect_head: None,
        allow_epoch_restarts: grading.allow_epoch_restarts,
        externally_authenticated_objects: std::collections::BTreeSet::new(),
    };
    let report = verify_archive(&store, &request, &trust.worm)
        .await
        .map_err(|source| {
            EvidenceError::input(
                format!("archive {}", spec.label),
                anyhow::anyhow!(source.to_string()),
            )
        })?;

    let (findings, notes) = grade_archive_report(&report, grading, trust);
    Ok((report, findings, notes))
}

/// Grade a WORM report the way `krabka-worm-verify` does.
fn grade_archive_report(
    report: &ArchiveVerifyReport,
    grading: WormGrading,
    trust: &TrustMaterial,
) -> (Vec<Finding>, Vec<Note>) {
    let mut findings = Vec::new();
    let mut notes = Vec::new();

    if !trust.has_worm_keys {
        notes.push(Note::new(
            CheckId::WormArchive,
            "WORM manifest signatures NOT CHECKED: no [[worm_keys]] entry and no \
             --worm-public-key; chain positions and object digests were still verified",
        ));
    }

    if let Some(found) = report.first_break() {
        let seq = found
            .seq
            .map_or_else(|| "unknown".to_string(), |seq| seq.0.to_string());
        findings.push(Finding::new(
            CheckId::WormArchive,
            "WORM archive tamper detected",
            format!(
                "TAMPER at {} (seq {seq}): {}",
                found.manifest_key, found.reason
            ),
        ));
        return (findings, notes);
    }

    if let Some(expected) = grading.expect_head
        && let Some(finding) = check_expected_head(report, expected)
    {
        findings.push(finding);
        return (findings, notes);
    }

    if report.partitions.is_empty() {
        notes.push(Note::new(
            CheckId::WormArchive,
            "archive holds no manifests: the WORM check passed vacuously",
        ));
        return (findings, notes);
    }

    let orphans: Vec<&String> = report
        .global_orphan_objects
        .iter()
        .chain(
            report
                .partitions
                .iter()
                .flat_map(|partition| partition.orphan_objects.iter()),
        )
        .collect();
    if !orphans.is_empty() {
        let shown: Vec<&str> = orphans.iter().take(10).map(|key| key.as_str()).collect();
        let detail = format!("ORPHAN objects ({}): {}", orphans.len(), shown.join(", "));
        if grading.strict_orphans {
            findings.push(Finding::new(
                CheckId::WormArchive,
                "WORM orphan objects",
                detail,
            ));
        } else {
            notes.push(Note::new(CheckId::WormArchive, detail));
        }
    }

    for partition in &report.partitions {
        grade_partition(partition, grading, &mut notes);
    }
    if !report.fully_attested() && trust.has_worm_keys {
        let unsigned: u64 = report
            .partitions
            .iter()
            .map(|partition| partition.unsigned_manifests)
            .sum();
        let untrusted: u64 = report
            .partitions
            .iter()
            .map(|partition| partition.untrusted_manifests)
            .sum();
        notes.push(Note::new(
            CheckId::WormArchive,
            format!(
                "INCOMPLETE attestation: {unsigned} unsigned and {untrusted} \
                 untrusted manifest(s)"
            ),
        ));
    }

    (findings, notes)
}

/// Check every partition tip against the `--expect-head` head.
///
/// A mismatch is its own outcome: the chain the archive holds is internally
/// perfect but stops short of the expected head, which is never tampering.
fn check_expected_head(report: &ArchiveVerifyReport, expected: ChainHead) -> Option<Finding> {
    let mismatch = report
        .partitions
        .iter()
        .find(|partition| partition.head != Some(expected));
    if mismatch.is_none() && !report.partitions.is_empty() {
        return None;
    }
    let (name, tip) = mismatch.map_or_else(
        || ("(none found)".to_string(), "none".to_string()),
        |partition| {
            (
                partition.partition_dir.clone(),
                partition
                    .head
                    .map_or_else(|| "none".to_string(), |head| head.to_string()),
            )
        },
    );
    Some(Finding::new(
        CheckId::WormArchive,
        "WORM head mismatch",
        format!(
            "HEAD MISMATCH: expected {expected}, archive tip {tip} \
             (partition {name}): the chain it holds is internally perfect but \
             stops short of the expected head"
        ),
    ))
}

/// Note a partition's attestation holes and offset gaps.
fn grade_partition(partition: &PartitionVerifyReport, grading: WormGrading, notes: &mut Vec<Note>) {
    if !grading.allow_epoch_restarts && partition.epochs.len() > 1 {
        notes.push(Note::new(
            CheckId::WormArchive,
            format!(
                "INCOMPLETE: partition {} holds {} chain runs (epoch restart is an \
                 attestation hole, not evidence of a rewrite)",
                partition.partition_dir,
                partition.epochs.len()
            ),
        ));
    }
    for gap in &partition.offset_gaps {
        notes.push(Note::new(
            CheckId::WormArchive,
            format!(
                "offset gap in partition {}: archive holds up to {} then from {}",
                partition.partition_dir, gap.after, gap.before
            ),
        ));
    }
}

/// Parse a chain head written as 64 hex characters.
///
/// ```
/// use krabka_evidence::archive::parse_chain_head;
///
/// let head = parse_chain_head(&"ab".repeat(32)).unwrap();
/// assert_eq!(head.to_string(), "ab".repeat(32));
/// assert!(parse_chain_head("too short").is_err());
/// assert!(parse_chain_head(&"zz".repeat(32)).is_err());
/// ```
///
/// # Errors
///
/// Returns a message when `text` is not 64 hexadecimal characters.
pub fn parse_chain_head(text: &str) -> Result<ChainHead, String> {
    if text.len() != 64 || !text.chars().all(|char| char.is_ascii_hexdigit()) {
        return Err(format!(
            "expected 64 hex characters, got {} characters",
            text.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "invalid hex".to_string())?;
        bytes[index] = u8::from_str_radix(pair, 16).map_err(|_| "invalid hex".to_string())?;
    }
    Ok(ChainHead(bytes))
}

#[cfg(test)]
mod tests {
    use super::static_s3_credentials;

    #[test]
    fn credential_pairs_need_both_halves() {
        assert_eq!(
            static_s3_credentials(Some("key"), Some("secret")),
            (Some("key".to_string()), Some("secret".to_string()))
        );
        assert_eq!(static_s3_credentials(None, None), (None, None));
        assert_eq!(static_s3_credentials(Some("key"), None), (None, None));
        assert_eq!(
            static_s3_credentials(Some(""), Some("secret")),
            (None, None)
        );
    }
}
