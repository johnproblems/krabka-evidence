//! Metadata ledger: decode `__cluster_metadata` history.
//!
//! The input is either a segment directory (the `__cluster_metadata-0`
//! partition, opened read-only) or a `krabka-backup` capture holding a
//! `cluster-metadata.checkpoint` snapshot. Segment values are KIP-631 frames
//! decoded with [`krabka_metadata::kraft_translate::from_kraft_value`]; the
//! freeze and break-glass records ride Krabka-private `NoOpRecord` carriers
//! (tags 1004–1006) that the same function unwraps.
//!
//! Snapshots compact old records away, so history before a snapshot's end
//! offset is gone. That coverage floor is reported as its own finding,
//! exactly as the PRD requires.

use std::path::{Path, PathBuf};

use krabka_metadata::{
    BreakGlassProposalRecord, MetadataImage, MetadataRecord, TopicFreezeRecord,
    kraft_translate::from_kraft_value,
};
use krabka_protocol::records::RecordBatch;
use uuid::Uuid;

use crate::{
    error::EvidenceError,
    finding::{CheckId, Finding, Note},
};

/// One relevant metadata record with its provenance.
#[derive(Debug, Clone)]
pub struct MetadataRow {
    /// Log offset of the record (snapshot end offset for snapshot rows).
    pub offset: i64,
    /// Segment or snapshot file the record came from.
    pub source: String,
    /// The decoded record.
    pub record: RelevantRecord,
}

/// The metadata records the cross-checks read.
#[derive(Debug, Clone)]
pub enum RelevantRecord {
    /// A freeze entry or a thaw sentinel (`frozen: false`).
    Freeze(TopicFreezeRecord),
    /// One version of a break-glass proposal.
    Proposal(BreakGlassProposalRecord),
    /// Expiry-sweep removal of a proposal.
    DeleteProposal(Uuid),
}

/// The metadata ledger after decoding.
#[derive(Debug)]
pub struct MetadataLedger {
    /// Relevant records, in log order.
    pub rows: Vec<MetadataRow>,
    /// Total metadata records decoded (relevant or not).
    pub decoded_records: u64,
    /// Earliest offset with history, when the input does not start at zero.
    pub coverage_floor: Option<i64>,
}

/// Read a metadata segment directory or backup capture.
///
/// Files larger than `max_segment_bytes` are refused outright, so a hostile
/// copy cannot make the tool buffer gigabytes.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the directory holds no
/// decodable metadata input, cannot be read, or holds a file over the cap.
pub fn read_metadata_ledger(
    dir: &Path,
    max_segment_bytes: u64,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) -> Result<MetadataLedger, EvidenceError> {
    let segments = list_files(dir, "log")?;
    let snapshots = list_files(dir, "checkpoint")?;
    let capture_snapshots = list_capture_snapshots(dir)?;

    if segments.is_empty() && snapshots.is_empty() && capture_snapshots.is_empty() {
        return Err(EvidenceError::input(
            format!("metadata input {}", dir.display()),
            anyhow::anyhow!(
                "no *.log segments, *.checkpoint snapshots, or restore-inputs/ captures"
            ),
        ));
    }

    if !segments.is_empty() && (!snapshots.is_empty() || !capture_snapshots.is_empty()) {
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            "metadata input mixes log segments and snapshots; offsets from the two \
             may overlap, and snapshot rows are cited at their snapshot's end offset",
        ));
    }

    let mut image = MetadataImage::new(Uuid::nil());
    let mut rows = Vec::new();
    let mut decoded_records: u64 = 0;
    let mut skipped_records: u64 = 0;
    let mut coverage_floor: Option<i64> = None;

    for segment in &segments {
        let (mut seg_rows, decoded, skipped) =
            decode_segment(segment, &mut image, max_segment_bytes, notes)?;
        decoded_records += decoded;
        skipped_records += skipped;
        rows.append(&mut seg_rows);
    }
    // A segment dir whose lowest base offset is above zero lost its head to
    // retention or to a partial copy.
    if let Some(lowest) = segments
        .iter()
        .filter_map(|path| path.file_stem()?.to_str()?.parse::<i64>().ok())
        .min()
        && lowest > 0
    {
        coverage_floor = Some(lowest);
    }

    for snapshot in &snapshots {
        let end = snapshot_end_offset(snapshot);
        note_unparsed_snapshot_name(snapshot, notes);
        let (mut snap_rows, decoded, skipped) =
            decode_snapshot(snapshot, &mut image, Some(end), max_segment_bytes, notes)?;
        decoded_records += decoded;
        skipped_records += skipped;
        rows.append(&mut snap_rows);
        // A snapshot holds state, not history: everything before its end is
        // compacted away.
        coverage_floor = Some(coverage_floor.map_or(end, |floor| floor.max(end)));
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            format!(
                "metadata snapshot {} covers state through offset {end}; \
                 per-event history before that offset is compacted away",
                snapshot.display()
            ),
        ));
    }
    for snapshot in &capture_snapshots {
        // Backup snapshots carry no end offset in their name; they hold full
        // state, so cross-checks run against them with the snapshot's own
        // batch offsets, but history they compacted away is invisible. That
        // is a disclosure, not a floor.
        let (mut snap_rows, decoded, skipped) =
            decode_snapshot(snapshot, &mut image, None, max_segment_bytes, notes)?;
        decoded_records += decoded;
        skipped_records += skipped;
        rows.append(&mut snap_rows);
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            format!(
                "metadata input {} is a backup snapshot: state is complete, but \
                 per-event history it compacted away is invisible to the cross-checks",
                snapshot.display()
            ),
        ));
    }

    rows.sort_by_key(|row| row.offset);

    note_empty_ledger(&rows, notes);

    if skipped_records > 0 {
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            format!(
                "metadata input holds {decoded_records} decoded record(s); \
                 {skipped_records} tombstone, control, or undecodable record(s) \
                 were skipped"
            ),
        ));
    }

    if let Some(floor) = coverage_floor {
        findings.push(Finding::new(
            CheckId::MetadataCoverage,
            "Metadata history not available",
            format!("metadata history not available before offset {floor}"),
        ));
    }

    Ok(MetadataLedger {
        rows,
        decoded_records,
        coverage_floor,
    })
}

/// Note a snapshot whose file name carries no parsable end offset.
fn note_unparsed_snapshot_name(snapshot: &Path, notes: &mut Vec<Note>) {
    if snapshot_end_offset_parsed(snapshot).is_none() {
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            format!(
                "metadata snapshot {} carries no parsable end offset in its name; \
                 history before it is treated as fully compacted",
                snapshot.display()
            ),
        ));
    }
}

/// Note a metadata input with no freeze or break-glass records.
fn note_empty_ledger(rows: &[MetadataRow], notes: &mut Vec<Note>) {
    if rows.is_empty() {
        notes.push(Note::new(
            CheckId::MetadataCoverage,
            "metadata input holds no freeze or break-glass records: the cross-checks \
             have nothing to corroborate",
        ));
    }
}

/// Read a metadata file, refusing files over the cap.
fn read_capped(path: &Path, what: &str, max_segment_bytes: u64) -> Result<Vec<u8>, EvidenceError> {
    let size = std::fs::metadata(path).map_or(0, |meta| meta.len());
    if size > max_segment_bytes {
        return Err(EvidenceError::input(
            format!("metadata input {}", path.display()),
            anyhow::anyhow!(
                "{what} {} is {size} bytes, over --max-segment-bytes {max_segment_bytes}",
                path.display(),
            ),
        ));
    }
    std::fs::read(path).map_err(|source| {
        EvidenceError::input(
            format!("metadata {what} {}", path.display()),
            anyhow::anyhow!("read {what}: {source}"),
        )
    })
}

/// Note an undecodable tail, with its truncation point.
fn note_truncation(notes: &mut Vec<Note>, path: &Path, what: &str, byte: usize, unread: usize) {
    notes.push(Note::new(
        CheckId::MetadataCoverage,
        format!(
            "metadata {what} {} ends mid-batch at byte {byte} ({unread} byte(s) unread): \
             records past the corruption are not decoded",
            path.display(),
        ),
    ));
}

/// Decode one `*.log` segment into relevant rows.
fn decode_segment(
    path: &Path,
    image: &mut MetadataImage,
    max_segment_bytes: u64,
    notes: &mut Vec<Note>,
) -> Result<(Vec<MetadataRow>, u64, u64), EvidenceError> {
    let bytes = read_capped(path, "segment", max_segment_bytes)?;
    let source = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let (rows, decoded, skipped, unread) = decode_batches(&bytes, &source, image, None);
    if unread > 0 {
        note_truncation(notes, path, "segment", bytes.len() - unread, unread);
    }
    Ok((rows, decoded, skipped))
}

/// Decode one `*.checkpoint` snapshot into relevant rows.
///
/// Snapshots with a known end offset cite every row there; snapshots without
/// one (backup captures) keep their batches' own offsets.
fn decode_snapshot(
    path: &Path,
    image: &mut MetadataImage,
    end: Option<i64>,
    max_segment_bytes: u64,
    notes: &mut Vec<Note>,
) -> Result<(Vec<MetadataRow>, u64, u64), EvidenceError> {
    let bytes = read_capped(path, "snapshot", max_segment_bytes)?;
    let source = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let (rows, decoded, skipped, unread) = decode_batches(&bytes, &source, image, end);
    if unread > 0 {
        note_truncation(notes, path, "snapshot", bytes.len() - unread, unread);
    }
    Ok((rows, decoded, skipped))
}

/// Decode concatenated `RecordBatch` frames, keeping freeze/proposal rows.
///
/// Returns the relevant rows plus decoded and skipped counts and the
/// undecodable tail's byte length.
fn decode_batches(
    bytes: &[u8],
    source: &str,
    image: &mut MetadataImage,
    snapshot_end: Option<i64>,
) -> (Vec<MetadataRow>, u64, u64, usize) {
    let mut rows = Vec::new();
    let mut decoded: u64 = 0;
    let mut skipped: u64 = 0;
    let mut cursor: &[u8] = bytes;
    while !cursor.is_empty() {
        let Ok(batch) = RecordBatch::decode(&mut cursor) else {
            break;
        };
        for record in &batch.records {
            let Some(value) = record.value.as_deref() else {
                skipped += 1;
                continue;
            };
            let Ok(metadata_record) = from_kraft_value(value, image) else {
                skipped += 1;
                continue;
            };
            decoded += 1;
            image.apply(&metadata_record);
            let offset =
                snapshot_end.unwrap_or_else(|| batch.base_offset + i64::from(record.offset_delta));
            let relevant = match metadata_record {
                MetadataRecord::V1TopicFreeze(entry) => Some(RelevantRecord::Freeze(entry)),
                MetadataRecord::V1BreakGlassProposal(proposal) => {
                    Some(RelevantRecord::Proposal(proposal))
                }
                MetadataRecord::V1DeleteBreakGlassProposal(id) => {
                    Some(RelevantRecord::DeleteProposal(id))
                }
                _ => None,
            };
            if let Some(record) = relevant {
                rows.push(MetadataRow {
                    offset,
                    source: source.to_string(),
                    record,
                });
            }
        }
    }
    (rows, decoded, skipped, cursor.len())
}

/// List `*.{extension}` files directly under `dir`, sorted.
fn list_files(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, EvidenceError> {
    let entries = std::fs::read_dir(dir).map_err(|source| {
        EvidenceError::input(
            format!("metadata input {}", dir.display()),
            anyhow::anyhow!("read dir: {source}"),
        )
    })?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect();
    crate::audit::sort_ledger_files(&mut files);
    Ok(files)
}

/// Find `cluster-metadata.checkpoint` files under `restore-inputs/`, for a
/// `krabka-backup` capture root.
fn list_capture_snapshots(dir: &Path) -> Result<Vec<PathBuf>, EvidenceError> {
    let captures = dir.join("restore-inputs");
    if !captures.is_dir() {
        // Also accept a single capture directory itself.
        if dir.join("manifest.json").is_file() {
            let direct = dir.join("cluster-metadata.checkpoint");
            if direct.is_file() {
                return Ok(vec![direct]);
            }
        }
        return Ok(Vec::new());
    }
    let mut snapshots = Vec::new();
    let entries = std::fs::read_dir(&captures).map_err(|source| {
        EvidenceError::input(
            format!("metadata input {}", dir.display()),
            anyhow::anyhow!("read restore-inputs: {source}"),
        )
    })?;
    let mut capture_dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    capture_dirs.sort();
    for capture in capture_dirs {
        let snapshot = capture.join("cluster-metadata.checkpoint");
        if snapshot.is_file() {
            snapshots.push(snapshot);
        }
    }
    Ok(snapshots)
}

/// Parse the end offset from a `<end:020>-<epoch:010>.checkpoint` name.
fn snapshot_end_offset_parsed(path: &Path) -> Option<i64> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.split('-').next())
        .and_then(|end| end.parse::<i64>().ok())
}

/// Parse the end offset from a `<end:020>-<epoch:010>.checkpoint` name.
///
/// Falls back to `i64::MAX` when the name does not parse, so an unknown
/// snapshot conservatively floors the whole history.
fn snapshot_end_offset(path: &Path) -> i64 {
    snapshot_end_offset_parsed(path).unwrap_or(i64::MAX)
}
