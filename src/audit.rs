//! Audit ledger: run the shipped verifier and decode the partition.
//!
//! Step 1 runs [`krabka_audit::verify::verify_partition_dir`] unchanged and
//! copies its report into ours. Step 2 re-walks the same `*.log` segments
//! with the same framing (sorted filenames, concatenated `RecordBatch`
//! frames, `offset = base_offset + offset_delta`) and parses the OCSF JSON
//! bodies back into timeline rows.
//!
//! When no audit key is configured, checkpoint signatures cannot be checked
//! at all; the report says so explicitly, and the data-record hash links are
//! still re-verified with the public [`krabka_audit::chain`] primitives.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use krabka_audit::{
    Checkpoint,
    chain::{GENESIS_HEAD, chain_hash, from_hex32},
    event::AuditEventClass,
    sink::{AuditError, HEADER_PREV_HASH, HEADER_SEQ},
    verify::{VerifyReport, verify_partition_dir},
};
use krabka_protocol::records::{Record, RecordBatch};

use crate::{
    error::EvidenceError,
    finding::{CheckId, Finding, Note},
    keys::TrustMaterial,
};

/// One decoded audit record with its log offset.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Log offset of the record.
    pub offset: i64,
    /// Broker-emit timestamp in epoch millis (`time` in OCSF).
    pub time_ms: i64,
    /// The parsed event.
    pub event: ParsedAuditEvent,
}

/// An audit record parsed back from its OCSF JSON body.
#[derive(Debug, Clone)]
pub enum ParsedAuditEvent {
    /// A privileged action (OCSF 6003 with a `privileged_action` object).
    Privileged(Box<PrivilegedRow>),
    /// A plain admin operation (OCSF 6003 without one).
    Admin(AdminRow),
    /// A signed chain checkpoint.
    Checkpoint {
        /// Key id that signed the checkpoint.
        key_id: String,
        /// Highest chained seq the checkpoint covers.
        seq_high: u64,
    },
    /// A declared fail-open loss window.
    RecordsLost {
        /// How many records were lost.
        records: u64,
        /// Loss-state generation.
        generation: u64,
    },
    /// Anything else (authn, authz, lifecycle): counted, not cross-checked.
    Other {
        /// The `event_class` header value.
        class: String,
    },
}

/// The two-person-control evidence of one privileged action, parsed from OCSF.
#[derive(Debug, Clone)]
pub struct PrivilegedRow {
    /// `success` or `failure`.
    pub outcome: String,
    /// Lowercase phase name (`attempted`, `applied`, …).
    pub phase: String,
    /// Action name, e.g. `freeze` or `thaw_topic_freeze`.
    pub action: String,
    /// What the action applies to.
    pub target: String,
    /// Proposal id, empty when the action needed no proposal.
    pub proposal_id: String,
    /// The principal that acted.
    pub principal: String,
    /// How the principal authenticated.
    pub auth_method: String,
    /// Approvers, in `KafkaPrincipal` string form.
    pub counterparties: Vec<String>,
    /// Fingerprint of the approver set at approval time.
    pub approver_set_fingerprint: String,
    /// Operator key id, empty when unsigned.
    pub key_id: String,
    /// Lowercase-hex detached signature, empty when unsigned.
    pub signature_hex: String,
    /// Whether the broker verified the signature at admission.
    pub signature_verified: bool,
    /// The operator-signed stamp (`set_at_ms` for freezes, else 0).
    pub signed_at_ms: i64,
    /// Free-text reason.
    pub reason: String,
}

/// One admin operation, parsed from OCSF.
#[derive(Debug, Clone)]
pub struct AdminRow {
    /// `success` or `failure`.
    pub outcome: String,
    /// The principal that acted.
    pub principal: String,
    /// Operation name, e.g. `DeleteTopic`.
    pub operation: String,
    /// Affected resources as `(resource_type, name)` pairs.
    pub resources: Vec<(String, String)>,
}

/// The audit ledger after steps 1 and 2.
#[derive(Debug)]
pub struct AuditLedger {
    /// The shipped verifier's report.
    pub verify_report: VerifyReport,
    /// Every decoded record, in offset order.
    pub rows: Vec<AuditRow>,
    /// Whether checkpoint signatures were verified against a trusted key.
    pub checkpoints_verified: bool,
}

/// Run the audit verifier and decode the partition.
///
/// Segments larger than `max_segment_bytes` are refused outright, so a
/// hostile copy cannot make the tool buffer gigabytes.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the directory cannot be
/// listed or a segment cannot be read. A broken chain is not an error: it
/// is an `Ok` report with findings.
pub fn read_audit_ledger(
    dir: &Path,
    trust: &TrustMaterial,
    max_segment_bytes: u64,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) -> Result<AuditLedger, EvidenceError> {
    let report = verify_partition_dir(dir, &trust.audit).map_err(|source: AuditError| {
        EvidenceError::input(
            format!("audit partition {}", dir.display()),
            anyhow::anyhow!(source.to_string()),
        )
    })?;
    let rows = decode_partition(dir, max_segment_bytes, notes)?;
    if rows.is_empty() {
        notes.push(Note::new(
            CheckId::AuditChain,
            "audit input decoded 0 records: the partition holds no decodable audit events",
        ));
    }

    if report.ok {
        emit_loss_findings(&report, &rows, findings);
        if report.checkpoints.0 == 0 && !rows.is_empty() {
            findings.push(Finding::new(
                CheckId::AuditChain,
                "Audit chain has no signed anchor",
                format!(
                    "the partition holds {} record(s) but no signed checkpoint covers \
                     any of them: the hash links check out, but nothing binds them to \
                     a key",
                    rows.len()
                ),
            ));
        }
        if report.unanchored_records.0 > 0 {
            notes.push(Note::new(
                CheckId::AuditChain,
                format!(
                    "{} trailing audit record(s) are not covered by a signed checkpoint \
                     (unanchored tail)",
                    report.unanchored_records.0
                ),
            ));
        }
        return Ok(AuditLedger {
            verify_report: report,
            rows,
            checkpoints_verified: trust.has_audit_keys,
        });
    }

    if let Some(first_break) = &report.first_break {
        let reason = first_break.reason.clone();
        if reason.contains("no trusted key") && !trust.has_audit_keys {
            // Without a configured audit key the tool cannot check checkpoint
            // signatures at all; that is a coverage gap, not tampering. The
            // data-record hash links, which need no keys, are still checked.
            notes.push(Note::new(
                CheckId::AuditChain,
                format!(
                    "audit checkpoint signatures NOT CHECKED: no [[audit_keys]] entry \
                     and no --audit-public-key (first checkpoint at offset {})",
                    first_break.offset
                ),
            ));
            verify_data_chain(dir, max_segment_bytes, findings)?;
            emit_loss_findings(&report, &rows, findings);
            return Ok(AuditLedger {
                verify_report: report,
                rows,
                checkpoints_verified: false,
            });
        }
        findings.push(
            Finding::new(
                CheckId::AuditChain,
                "Audit hash chain broken",
                format!(
                    "audit chain break at offset {}: {reason}",
                    first_break.offset
                ),
            )
            .with_audit_offset(first_break.offset),
        );
        emit_loss_findings(&report, &rows, findings);
    }

    Ok(AuditLedger {
        verify_report: report,
        rows,
        checkpoints_verified: trust.has_audit_keys,
    })
}

/// Copy declared loss windows into findings, joined with the decoded rows
/// for their loss generations.
///
/// The verifier stops at the first break, so loss markers past a break never
/// reach its report; the decoded rows carry them instead. Offsets the
/// verifier already reported are not duplicated.
fn emit_loss_findings(report: &VerifyReport, rows: &[AuditRow], findings: &mut Vec<Finding>) {
    let generations: HashMap<i64, u64> = rows
        .iter()
        .filter_map(|row| match &row.event {
            ParsedAuditEvent::RecordsLost { generation, .. } => Some((row.offset, *generation)),
            _ => None,
        })
        .collect();
    let reported: std::collections::HashSet<i64> =
        report.losses.iter().map(|loss| loss.offset).collect();
    for loss in &report.losses {
        let generation = generations.get(&loss.offset).copied().unwrap_or(0);
        findings.push(
            Finding::new(
                CheckId::AuditLossWindows,
                "Audit declared records lost",
                format!(
                    "fail-open loss window at audit offset {}: {} record(s) lost \
                     (loss generation {generation})",
                    loss.offset, loss.records.0,
                ),
            )
            .with_audit_offset(loss.offset),
        );
    }
    for row in rows {
        if let ParsedAuditEvent::RecordsLost {
            records,
            generation,
        } = &row.event
            && !reported.contains(&row.offset)
        {
            findings.push(
                Finding::new(
                    CheckId::AuditLossWindows,
                    "Audit declared records lost",
                    format!(
                        "fail-open loss window at audit offset {}: {records} record(s) lost \
                         (loss generation {generation}); the verifier stopped before it",
                        row.offset,
                    ),
                )
                .with_audit_offset(row.offset),
            );
        }
    }
}

/// Re-verify the hash links of chained data records without any keys.
///
/// This mirrors the data-record half of the shipped verifier: `seq` headers
/// must run 0, 1, 2, … and each `prev_hash` must equal the running head
/// `SHA256(prev ‖ seq_be ‖ value)`. Checkpoints are skipped (their
/// signatures need keys); loss markers are chained like data records.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the directory cannot be
/// listed or a segment cannot be read.
fn verify_data_chain(
    dir: &Path,
    max_segment_bytes: u64,
    findings: &mut Vec<Finding>,
) -> Result<(), EvidenceError> {
    let mut expected_seq: u64 = 0;
    let mut head: [u8; 32] = GENESIS_HEAD;
    for (offset, record) in walk_records(dir, max_segment_bytes)?.records {
        let class = header_str(&record, "event_class").unwrap_or_default();
        if class == krabka_audit::checkpoint::EVENT_CLASS_CHECKPOINT {
            continue;
        }
        let value = record.value.as_deref().unwrap_or_default();
        let seq = header_str(&record, HEADER_SEQ).and_then(|text| text.parse::<u64>().ok());
        let prev = header_str(&record, HEADER_PREV_HASH).and_then(|text| from_hex32(&text));
        let (Some(seq), Some(prev)) = (seq, prev) else {
            findings.push(
                Finding::new(
                    CheckId::AuditChain,
                    "Audit hash chain broken",
                    format!("audit record at offset {offset} lacks chained seq/prev_hash headers"),
                )
                .with_audit_offset(offset),
            );
            return Ok(());
        };
        if seq != expected_seq || prev != head {
            findings.push(
                Finding::new(
                    CheckId::AuditChain,
                    "Audit hash chain broken",
                    format!(
                        "audit chain break at offset {offset}: expected seq {expected_seq}, got {seq}"
                    ),
                )
                .with_audit_offset(offset),
            );
            return Ok(());
        }
        head = chain_hash(&prev, seq, value);
        expected_seq += 1;
    }
    Ok(())
}

/// Decode every record of an audit partition into rows.
///
/// Segments that end mid-batch are noted with their truncation point; the
/// shipped verifier has already graded the chain, so decoding is best-effort
/// past that.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the directory cannot be
/// listed or a segment cannot be read.
pub fn decode_partition(
    dir: &Path,
    max_segment_bytes: u64,
    notes: &mut Vec<Note>,
) -> Result<Vec<AuditRow>, EvidenceError> {
    let walk = walk_records(dir, max_segment_bytes)?;
    for truncation in &walk.truncations {
        notes.push(Note::new(
            CheckId::AuditChain,
            format!(
                "audit segment {} ends mid-batch at byte {} ({} byte(s) unread): \
                 records past the corruption are not decoded",
                truncation.segment, truncation.byte, truncation.unread,
            ),
        ));
    }
    let mut rows = Vec::new();
    let mut undecodable: u64 = 0;
    for (offset, record) in &walk.records {
        if let Some(row) = decode_record(record, *offset) {
            rows.push(row);
        } else {
            undecodable += 1;
        }
    }
    if undecodable > 0 {
        notes.push(Note::new(
            CheckId::AuditChain,
            format!(
                "{undecodable} audit record(s) could not be decoded (empty or undecodable \
                 bodies): they are excluded from the timeline and cross-checks"
            ),
        ));
    }
    Ok(rows)
}

/// One segment that ends mid-batch.
#[derive(Debug, Clone)]
pub struct SegmentTruncation {
    /// Segment file name.
    pub segment: String,
    /// Byte offset where decoding stopped.
    pub byte: usize,
    /// Bytes left unread.
    pub unread: usize,
}

/// The result of walking a partition's segments.
#[derive(Debug)]
pub struct SegmentWalk {
    /// Decoded records as `(offset, record)` pairs.
    pub records: Vec<(i64, Record)>,
    /// Segments that end mid-batch.
    pub truncations: Vec<SegmentTruncation>,
}

/// Sort ledger files by numeric stem when both stems parse as base offsets.
///
/// Segment names are usually zero-padded (`00000000000000000013.log`), which
/// sorts the same lexically — but an unpadded `9.log` must still come before
/// `10.log`. Non-numeric names fall back to lexical order.
pub fn sort_ledger_files(paths: &mut [PathBuf]) {
    paths.sort_by(|a, b| match (numeric_stem(a), numeric_stem(b)) {
        (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.cmp(b)),
        _ => a.cmp(b),
    });
}

/// A ledger file's stem as a base offset, when it parses as one.
fn numeric_stem(path: &Path) -> Option<i64> {
    path.file_stem()?.to_str()?.parse::<i64>().ok()
}

/// Walk `*.log` segments in filename order.
///
/// The framing mirrors `verify_partition_dir`: concatenated `RecordBatch`
/// frames, `offset = base_offset + offset_delta`, and an undecodable tail
/// stops the segment (recorded as a truncation).
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the directory cannot be
/// listed, a segment cannot be read, or a segment exceeds `max_segment_bytes`.
fn walk_records(dir: &Path, max_segment_bytes: u64) -> Result<SegmentWalk, EvidenceError> {
    let mut segments: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| {
            EvidenceError::input(
                format!("audit partition {}", dir.display()),
                anyhow::anyhow!("read dir: {source}"),
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
        .collect();
    sort_ledger_files(&mut segments);

    let mut records = Vec::new();
    let mut truncations = Vec::new();
    for segment in segments {
        let size = std::fs::metadata(&segment).map_or(0, |meta| meta.len());
        if size > max_segment_bytes {
            return Err(EvidenceError::input(
                format!("audit partition {}", dir.display()),
                anyhow::anyhow!(
                    "segment {} is {size} bytes, over --max-segment-bytes {max_segment_bytes}",
                    segment.display(),
                ),
            ));
        }
        let bytes = std::fs::read(&segment).map_err(|source| {
            EvidenceError::input(
                format!("audit partition {}", dir.display()),
                anyhow::anyhow!("read segment {}: {source}", segment.display()),
            )
        })?;
        let mut cursor: &[u8] = &bytes;
        while !cursor.is_empty() {
            let Ok(batch) = RecordBatch::decode(&mut cursor) else {
                break;
            };
            for record in &batch.records {
                let offset = batch.base_offset + i64::from(record.offset_delta);
                records.push((offset, record.clone()));
            }
        }
        if !cursor.is_empty() {
            truncations.push(SegmentTruncation {
                segment: segment
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string(),
                byte: bytes.len() - cursor.len(),
                unread: cursor.len(),
            });
        }
    }
    Ok(SegmentWalk {
        records,
        truncations,
    })
}

/// Decode one audit record into a row, or `None` when it carries no body.
fn decode_record(record: &Record, offset: i64) -> Option<AuditRow> {
    let class = header_str(record, "event_class").unwrap_or_default();
    let value = record.value.as_deref().unwrap_or_default();

    if class == krabka_audit::checkpoint::EVENT_CLASS_CHECKPOINT {
        let json: serde_json::Value = serde_json::from_slice(value).ok()?;
        let checkpoint = Checkpoint::from_value(&json)?;
        return Some(AuditRow {
            offset,
            time_ms: checkpoint.time_ms.0,
            event: ParsedAuditEvent::Checkpoint {
                key_id: checkpoint.key_id,
                seq_high: checkpoint.seq_high.0,
            },
        });
    }

    if class == AuditEventClass::RecordsLost.as_header() {
        let json: serde_json::Value = serde_json::from_slice(value).ok()?;
        return Some(AuditRow {
            offset,
            time_ms: 0,
            event: ParsedAuditEvent::RecordsLost {
                records: json.get("records_lost")?.as_u64()?,
                generation: json.get("loss_generation")?.as_u64()?,
            },
        });
    }

    let json: serde_json::Value = serde_json::from_slice(value).ok()?;
    let time_ms = json.get("time")?.as_i64()?;
    if let Some(privileged) = json.get("privileged_action") {
        return Some(AuditRow {
            offset,
            time_ms,
            event: ParsedAuditEvent::Privileged(Box::new(privileged_row(
                &json, privileged, time_ms,
            ))),
        });
    }

    if json.get("class_uid").and_then(serde_json::Value::as_i64) == Some(6003) {
        return Some(AuditRow {
            offset,
            time_ms,
            event: ParsedAuditEvent::Admin(admin_row(&json)),
        });
    }

    Some(AuditRow {
        offset,
        time_ms,
        event: ParsedAuditEvent::Other { class },
    })
}

/// Parse a privileged-action OCSF body.
fn privileged_row(
    json: &serde_json::Value,
    privileged: &serde_json::Value,
    _time_ms: i64,
) -> PrivilegedRow {
    PrivilegedRow {
        outcome: status_str(json),
        phase: get_str(privileged, "phase"),
        action: get_str(privileged, "action"),
        target: get_str(privileged, "target"),
        proposal_id: get_str(privileged, "proposal_id"),
        principal: json
            .pointer("/actor/user/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        auth_method: json
            .pointer("/actor/user/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        counterparties: privileged
            .get("counterparties")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("name")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        approver_set_fingerprint: get_str(privileged, "approver_set_fingerprint"),
        key_id: get_str(privileged, "key_id"),
        signature_hex: get_str(privileged, "signature"),
        signature_verified: privileged
            .get("signature_verified")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        signed_at_ms: privileged
            .get("signed_at_ms")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        reason: json
            .get("status_detail")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

/// Parse an admin-operation OCSF body.
fn admin_row(json: &serde_json::Value) -> AdminRow {
    AdminRow {
        outcome: status_str(json),
        principal: json
            .pointer("/actor/user/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        operation: json
            .pointer("/api/operation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        resources: json
            .get("resources")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        (
                            item.get("type")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            item.get("name")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Read a record header as UTF-8 text.
fn header_str(record: &Record, key: &str) -> Option<String> {
    record
        .headers
        .iter()
        .find(|header| header.key == key)
        .and_then(|header| header.value.as_deref())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string)
}

/// Read a JSON string field, defaulting to empty.
fn get_str(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Map OCSF `status_id` back to the outcome word the sink recorded.
fn status_str(value: &serde_json::Value) -> String {
    match value.get("status_id").and_then(serde_json::Value::as_i64) {
        Some(1) => "success".to_string(),
        Some(_) => "failure".to_string(),
        None => String::new(),
    }
}
