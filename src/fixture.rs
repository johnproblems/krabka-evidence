//! Fixture generator: synthetic three-ledger inputs written with the real encoders.
//!
//! `krabka-evidence fixture` writes the PRD success-criteria scenarios without
//! a live broker: audit segments chained with [`krabka_audit`] itself,
//! metadata segments framed with [`krabka_metadata`]'s KIP-631 translation,
//! and a WORM archive sealed with [`krabka_remote_storage::WormArchiver`].
//! Everything the tool checks in a fixture, it checks with the same code it
//! runs against real copies.
//!
//! Scenarios (all share one layout; only the tamper differs):
//!
//! - `clean`: freeze → break-glass thaw approved by two operators → second
//!   proposal → `DeleteTopic`. No findings.
//! - `missing-audit`: the tail audit segment is deleted, so the consumed
//!   `DeleteTopic` proposal has no audit event. Exactly one finding.
//! - `flipped-sig`: one audit signature byte is flipped and the chain is
//!   re-sealed around it (an attacker who rewrote the chain but could not
//!   forge the operator signature). Exactly one finding.
//! - `approver-change`: one event carries a different approver-set
//!   fingerprint. Exactly one finding.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use chrono::{NaiveDate, TimeZone, Utc};
use krabka_audit::{
    AuditEndpoint, AuditEvent, AuditOutcome, AuditPrincipal, AuditRecord, AuditResource,
    ChainState, Checkpoint, PrivilegedPhase, ProductInfo,
    ids::{EpochMs, Seq},
    signing::FileEd25519Signer,
};
use krabka_broker::operator_keys::{FreezeSigningInput, approver_set_fingerprint};
use krabka_guard::signing::{ApprovalSigningInput, approval_signing_bytes, freeze_signing_bytes};
use krabka_ids::LeaderEpoch;
use krabka_metadata::{
    BreakGlassAction, BreakGlassApproval, BreakGlassProposalRecord, MetadataImage, MetadataRecord,
    PatternType, TopicFreezeRecord, kraft_translate::to_kraft_values,
};
use krabka_object_store::{ObjectStoreConfig, build_object_store};
use krabka_protocol::{
    krabka::freeze::PATTERN_TYPE_LITERAL,
    records::{Record, RecordBatch, RecordHeader},
};
use krabka_remote_storage::{
    ChainHead, ChainStamp, EpochId, MANIFEST_SUFFIX, ManifestSeq, ObjectEntry,
    RemoteLogSegmentDetails, RemoteLogSegmentId, RemoteLogSegmentMetadata, RemoteLogSegmentState,
    Sha256Digest, TopicIdPartition, WormArchiver, WormChainRecord, manifest_head,
    partition_dir_name, segment_file_name,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::EvidenceError,
    keys::{BrokerKeyFileEntry, KeysFile, OperatorKeyFileEntry},
};

/// Cluster id the fixture signs freeze records under.
pub const CLUSTER_ID: &str = "fixture-cluster";
/// Break-glass proposal that authorizes the thaw.
pub const PROPOSAL_THAW: &str = "11111111-1111-1111-1111-111111111111";
/// Break-glass proposal that authorizes the topic deletion.
pub const PROPOSAL_DELETE: &str = "22222222-2222-2222-2222-222222222222";
/// Audit offset of the freeze `Applied` event (the flipped-sig victim).
pub const FREEZE_APPLIED_OFFSET: i64 = 1;
/// Serialized index of the delete proposal's `Applied` event (drift victim).
///
/// Its log offset is one higher: a checkpoint closes the first segment.
pub const DELETE_APPLIED_INDEX: i64 = 13;
/// Audit offset of the delete proposal's `Applied` event.
pub const DELETE_APPLIED_OFFSET: i64 = 14;
/// Metadata offset of the consumed delete proposal (missing-audit citation).
pub const DELETE_PROPOSAL_METADATA_OFFSET: i64 = 3;

/// The tamper a scenario applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// No tamper: the report must be clean.
    Clean,
    /// Delete the tail audit segment.
    MissingAudit,
    /// Flip one audit signature byte, re-sealing the chain around it.
    FlippedSignature,
    /// Change one event's approver-set fingerprint.
    ApproverChange,
    /// Flip a byte at the end of the head audit segment (chain break).
    CorruptChain,
    /// Approve a proposal after it expired (two-person violation).
    ExpiredApproval,
    /// Leave the freeze and one approval unsigned (notes, still clean).
    Unsigned,
    /// Flip a hex digit in a WORM manifest's chain link (tamper).
    WormTamper,
}

impl Scenario {
    /// Parse a scenario name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "clean" => Some(Self::Clean),
            "missing-audit" => Some(Self::MissingAudit),
            "flipped-sig" => Some(Self::FlippedSignature),
            "approver-change" => Some(Self::ApproverChange),
            "corrupt-chain" => Some(Self::CorruptChain),
            "expired-approval" => Some(Self::ExpiredApproval),
            "unsigned" => Some(Self::Unsigned),
            "worm-tamper" => Some(Self::WormTamper),
            _ => None,
        }
    }

    /// All scenarios.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Clean,
            Self::MissingAudit,
            Self::FlippedSignature,
            Self::ApproverChange,
            Self::CorruptChain,
            Self::ExpiredApproval,
            Self::Unsigned,
            Self::WormTamper,
        ]
    }

    /// Directory name for the scenario.
    #[must_use]
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::MissingAudit => "missing-audit",
            Self::FlippedSignature => "flipped-sig",
            Self::ApproverChange => "approver-change",
            Self::CorruptChain => "corrupt-chain",
            Self::ExpiredApproval => "expired-approval",
            Self::Unsigned => "unsigned",
            Self::WormTamper => "worm-tamper",
        }
    }

    /// What the scenario proves, for its `README.txt`.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Clean => "No tamper. The report must be clean (exit 0).",
            Self::MissingAudit => {
                "The tail audit segment is deleted. Exactly one finding: \
                the consumed DeleteTopic proposal has no audit event."
            }
            Self::FlippedSignature => {
                "One audit signature byte is flipped and the hash \
                chain is re-sealed around it. Exactly one finding: the signature \
                does not verify."
            }
            Self::ApproverChange => {
                "One event carries a different approver-set \
                fingerprint. Exactly one finding: the approver set changed."
            }
            Self::CorruptChain => {
                "A byte at the end of the head audit segment is \
                flipped after sealing. Exactly one finding: the audit hash chain \
                is broken."
            }
            Self::ExpiredApproval => {
                "A fifth proposal carries an approval stamped \
                after expiry. Exactly one finding: the two-person rule was violated."
            }
            Self::Unsigned => {
                "The freeze and one approval carry no signature. No \
                findings (exit 0); the report notes the unattested records."
            }
            Self::WormTamper => {
                "A hex digit in a WORM manifest's chain link is \
                flipped. Exactly one finding: archive tampering."
            }
        }
    }
}

/// Options for scenario generation.
#[derive(Debug, Clone, Default)]
pub struct FixtureOptions {
    /// Derive all fixture keys from this seed instead of minting randomly.
    pub seed: Option<String>,
    /// Write metadata as a backup capture instead of log segments.
    pub capture_layout: bool,
}

/// Paths the generator wrote.
#[derive(Debug, Clone)]
pub struct FixturePaths {
    /// Scenario root.
    pub root: PathBuf,
    /// Audit partition directory.
    pub audit: PathBuf,
    /// Metadata segment directory.
    pub metadata: PathBuf,
    /// WORM archive directory.
    pub archive: PathBuf,
    /// Keys file.
    pub keys: PathBuf,
    /// Auditor private key (PKCS#8).
    pub auditor_key: PathBuf,
}

/// Minted fixture signers.
struct FixtureKeys {
    alice: Arc<FileEd25519Signer>,
    bob: Arc<FileEd25519Signer>,
    carol: Arc<FileEd25519Signer>,
    audit: Arc<FileEd25519Signer>,
    worm: Arc<FileEd25519Signer>,
}

/// Generate a bulk audit partition: `events` chained admin operations plus a
/// checkpoint, with minimal metadata and archive inputs alongside.
///
/// Throughput tests use this to prove the 10M-records-in-5-minutes budget.
///
/// # Errors
///
/// Returns [`EvidenceError::OutputUnwritable`] when files cannot be written.
pub fn generate_bulk_audit(out: &Path, events: usize) -> Result<FixturePaths, EvidenceError> {
    let root = out.to_path_buf();
    let audit_dir = root.join("audit");
    let metadata_dir = root.join("metadata");
    let archive_dir = root.join("archive");
    let keys_dir = root.join("keys");
    for dir in [&audit_dir, &metadata_dir, &archive_dir, &keys_dir] {
        std::fs::create_dir_all(dir).map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.clone(),
            source: source.into(),
        })?;
    }
    let keys = mint_keys(None)?;
    write_keys(&keys, &keys_dir, None)?;

    let product = ProductInfo {
        vendor_name: "krabka".to_string(),
        name: "bulk".to_string(),
        version: "0".to_string(),
    };
    let base = base_ms();
    let mut chain = ChainState::new();
    let mut records = Vec::with_capacity(events + 1);
    for index in 0..events {
        let event = AuditEvent::AdminOperation {
            outcome: AuditOutcome::Success,
            principal: AuditPrincipal {
                name: "User:bulk".to_string(),
                auth_method: "SCRAM".to_string(),
            },
            source: AuditEndpoint {
                ip: "10.0.0.9".to_string(),
                port: 9092,
            },
            operation: "DescribeTopic".to_string(),
            resources: vec![AuditResource {
                resource_type: "Topic".to_string(),
                name: "bulk".to_string(),
            }],
            time_ms: base + i64::try_from(index).unwrap_or(0),
        };
        let mut record = AuditRecord::from_event(&event, &product);
        let link = chain.extend(&record.value);
        record.push_chain_headers(link.seq, &link.prev_head);
        records.push(audit_record_to_kafka(
            &record,
            i32::try_from(index).unwrap_or(0),
        ));
    }
    if events > 0 {
        let checkpoint = Checkpoint::signed(
            &keys.audit,
            Seq(u64::try_from(events.saturating_sub(1)).unwrap_or(0)),
            &chain.head(),
            EpochMs(base + i64::try_from(events).unwrap_or(0)),
        );
        records.push(audit_record_to_kafka(
            &checkpoint.to_record(),
            i32::try_from(records.len()).unwrap_or(0),
        ));
    }
    write_batch(&audit_dir, 0, &records, base, base + 60_000)?;

    // Minimal companions: an empty metadata segment and no archive objects.
    std::fs::write(metadata_dir.join("00000000000000000000.log"), []).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: metadata_dir.clone(),
            source: source.into(),
        }
    })?;
    let keys_path = keys_dir.join("keys.toml");
    let auditor_key = keys_dir.join("auditor.priv.pkcs8");
    Ok(FixturePaths {
        root,
        audit: audit_dir,
        metadata: metadata_dir,
        archive: archive_dir,
        keys: keys_path,
        auditor_key,
    })
}

/// Epoch millis of the fixture's midnight: 2026-09-15T00:00:00Z.
#[must_use]
pub fn base_ms() -> i64 {
    NaiveDate::from_ymd_opt(2026, 9, 15)
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map_or(1_757_894_400_000, |midnight| {
            Utc.from_utc_datetime(&midnight).timestamp_millis()
        })
}

/// Generate one scenario under `out/<scenario>`.
///
/// # Errors
///
/// Returns [`EvidenceError::OutputUnwritable`] when files cannot be written.
///
/// # Panics
///
/// Panics when protocol encoding fails, which cannot happen for fixture data.
pub async fn generate_scenario(
    scenario: Scenario,
    out: &Path,
    options: &FixtureOptions,
) -> Result<FixturePaths, EvidenceError> {
    let root = out.join(scenario.dir_name());
    let audit_dir = root.join("audit");
    let metadata_dir = root.join("metadata");
    let archive_dir = root.join("archive");
    let keys_dir = root.join("keys");
    for dir in [&audit_dir, &metadata_dir, &archive_dir, &keys_dir] {
        std::fs::create_dir_all(dir).map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.clone(),
            source: source.into(),
        })?;
    }

    let keys = mint_keys(options.seed.as_deref())?;
    write_keys(&keys, &keys_dir, options.seed.as_deref())?;
    let keys_path = keys_dir.join("keys.toml");

    let unsigned = scenario == Scenario::Unsigned;
    if options.capture_layout {
        write_metadata_capture(&keys, &metadata_dir, unsigned)?;
    } else {
        write_metadata(&keys, &metadata_dir, unsigned)?;
    }
    if scenario == Scenario::ExpiredApproval {
        write_extra_proposal(&keys, &metadata_dir)?;
    }
    write_audit(scenario, &keys, &audit_dir, unsigned)?;
    if scenario == Scenario::MissingAudit {
        let tail = audit_dir.join("00000000000000000013.log");
        std::fs::remove_file(&tail).map_err(|source| EvidenceError::OutputUnwritable {
            path: tail,
            source: source.into(),
        })?;
    }
    if scenario == Scenario::CorruptChain {
        corrupt_audit_head(&audit_dir)?;
    }
    write_archive(&keys, &archive_dir).await?;
    if scenario == Scenario::WormTamper {
        corrupt_manifest_link(&archive_dir)?;
    }
    std::fs::write(root.join("README.txt"), scenario_readme(scenario)).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: root.join("README.txt"),
            source: source.into(),
        }
    })?;

    let auditor_key = keys_dir.join("auditor.priv.pkcs8");
    Ok(FixturePaths {
        root,
        audit: audit_dir,
        metadata: metadata_dir,
        archive: archive_dir,
        keys: keys_path,
        auditor_key,
    })
}

/// The `README.txt` describing one scenario.
fn scenario_readme(scenario: Scenario) -> String {
    format!(
        "krabka-evidence fixture: {}\n\n{}\n\nInputs: audit/ metadata/ archive/ keys/keys.toml\n",
        scenario.dir_name(),
        scenario.description(),
    )
}

/// Mint the fixture's operator and broker keys.
///
/// With a seed, every key derives deterministically from
/// `SHA256(domain ‖ role ‖ seed)`, so two runs with the same seed produce
/// identical fixtures. Without one, keys come from the platform RNG.
fn mint_keys(seed: Option<&str>) -> Result<FixtureKeys, EvidenceError> {
    let mint = |role: &str, key_id: &str| -> Result<Arc<FileEd25519Signer>, EvidenceError> {
        let der = seed.map_or_else(
            || {
                Ok(Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .expect("the platform RNG mints fixture keys")
                    .as_ref()
                    .to_vec())
            },
            |seed| {
                ed25519_pkcs8(&derived_seed(seed, role)).map_err(|source| {
                    EvidenceError::OutputUnwritable {
                        path: Path::new("<fixture-keys>").to_path_buf(),
                        source: anyhow::anyhow!(source.to_string()),
                    }
                })
            },
        )?;
        let signer =
            FileEd25519Signer::from_pkcs8_bytes(&der, key_id.to_string()).map_err(|source| {
                EvidenceError::OutputUnwritable {
                    path: Path::new("<fixture-keys>").to_path_buf(),
                    source: anyhow::anyhow!(source.to_string()),
                }
            })?;
        Ok(Arc::new(signer))
    };
    Ok(FixtureKeys {
        alice: mint("alice", "alice-2026")?,
        bob: mint("bob", "bob-2026")?,
        carol: mint("carol", "carol-2026")?,
        audit: mint("audit", "audit-1")?,
        worm: mint("worm", "worm-1")?,
    })
}

/// Derive a deterministic Ed25519 seed for one fixture role.
fn derived_seed(seed: &str, role: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"krabka-evidence-fixture-key-v1\0");
    hasher.update(role.as_bytes());
    hasher.update([0u8]);
    hasher.update(seed.as_bytes());
    hasher.finalize().into()
}

/// Wrap a 32-byte Ed25519 seed in PKCS#8 v2 DER.
///
/// `ring`'s parser only accepts v2 (seed plus public key), so the public
/// half is derived from the seed and appended under the `[1]` tag, byte for
/// byte as `Ed25519KeyPair::generate_pkcs8` lays it out.
fn ed25519_pkcs8(seed: &[u8; 32]) -> Result<Vec<u8>, ring::error::KeyRejected> {
    let public = Ed25519KeyPair::from_seed_unchecked(seed)?
        .public_key()
        .as_ref()
        .to_vec();
    let mut der = vec![
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(&public);
    Ok(der)
}

/// Write public keys, private keys (fixture-only), and `keys.toml`.
fn write_keys(keys: &FixtureKeys, dir: &Path, seed: Option<&str>) -> Result<(), EvidenceError> {
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(name), bytes).map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.join(name),
            source: source.into(),
        })
    };
    // Public keys are raw 32-byte files, exactly as the broker reads them.
    // Private keys are PKCS#8; they exist so the fixture's tamper variants
    // and demos can re-seal, and are labeled test-only.
    let entries = [
        ("alice", keys.alice.clone()),
        ("bob", keys.bob.clone()),
        ("carol", keys.carol.clone()),
        ("audit", keys.audit.clone()),
        ("worm", keys.worm.clone()),
    ];
    for (name, signer) in &entries {
        write(&format!("{name}.pub"), &signer.public_key())?;
    }
    // The auditor keypair is minted for the fixture so demos and tests can
    // sign reports; operator private halves never touch disk.
    let auditor_der: Vec<u8> = seed.map_or_else(
        || {
            Ok(Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .expect("the platform RNG mints fixture keys")
                .as_ref()
                .to_vec())
        },
        |seed| {
            ed25519_pkcs8(&derived_seed(seed, "auditor")).map_err(|source| {
                EvidenceError::OutputUnwritable {
                    path: dir.to_path_buf(),
                    source: anyhow::anyhow!(source.to_string()),
                }
            })
        },
    )?;
    let auditor = FileEd25519Signer::from_pkcs8_bytes(&auditor_der, "auditor-1".to_string())
        .expect("fixture auditor key is a valid PKCS#8 Ed25519 key");
    std::fs::write(dir.join("auditor.pub"), auditor.public_key()).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: dir.join("auditor.pub"),
            source: source.into(),
        }
    })?;
    std::fs::write(dir.join("auditor.priv.pkcs8"), &auditor_der).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: dir.join("auditor.priv.pkcs8"),
            source: source.into(),
        }
    })?;
    let file = KeysFile {
        operator_keys: [
            ("alice-2026", "User:alice", "alice.pub"),
            ("bob-2026", "User:bob", "bob.pub"),
            ("carol-2026", "User:carol", "carol.pub"),
        ]
        .iter()
        .map(|(key_id, principal, pub_file)| OperatorKeyFileEntry {
            key_id: (*key_id).to_string(),
            principal: (*principal).to_string(),
            public_key_path: PathBuf::from(pub_file),
        })
        .collect(),
        audit_keys: vec![BrokerKeyFileEntry {
            key_id: "audit-1".to_string(),
            public_key_path: PathBuf::from("audit.pub"),
        }],
        worm_keys: vec![BrokerKeyFileEntry {
            key_id: "worm-1".to_string(),
            public_key_path: PathBuf::from("worm.pub"),
        }],
    };
    let toml = toml::to_string_pretty(&file).unwrap_or_default();
    write("keys.toml", toml.as_bytes())?;
    Ok(())
}

/// Approver set the fixture signs under.
fn approvers() -> Vec<String> {
    ["User:alice", "User:bob", "User:carol"]
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

/// Write the metadata segment: freeze → thaw proposal → thaw → delete proposal.
///
/// When `unsigned` is set, the freeze record and the first thaw approval
/// carry no signature (the `unsigned` scenario).
fn write_metadata(keys: &FixtureKeys, dir: &Path, unsigned: bool) -> Result<(), EvidenceError> {
    let base = base_ms();
    let minute = 60_000;
    let records = fixture_metadata_records(keys, base, minute, unsigned);
    let bytes = encode_metadata_batch(&records, 0, base, base + 8 * minute)?;
    std::fs::write(dir.join("00000000000000000000.log"), bytes).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: source.into(),
        }
    })?;
    Ok(())
}

/// Write metadata as a backup capture: `restore-inputs/<id>/` holding a
/// `manifest.json` and a `cluster-metadata.checkpoint` snapshot.
fn write_metadata_capture(
    keys: &FixtureKeys,
    dir: &Path,
    unsigned: bool,
) -> Result<(), EvidenceError> {
    let base = base_ms();
    let minute = 60_000;
    let records = fixture_metadata_records(keys, base, minute, unsigned);
    let bytes = encode_metadata_batch(&records, 0, base, base + 8 * minute)?;
    let capture = dir.join("restore-inputs").join(format!("{base}-fixture"));
    std::fs::create_dir_all(&capture).map_err(|source| EvidenceError::OutputUnwritable {
        path: capture.clone(),
        source: source.into(),
    })?;
    let manifest = serde_json::json!({
        "version": 0u32,
        "capture_id": format!("{base}-fixture"),
        "artifacts": [{"name": "cluster-metadata.checkpoint", "source": "ctrl"}],
    });
    std::fs::write(
        capture.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|source| EvidenceError::OutputUnwritable {
        path: capture.clone(),
        source: source.into(),
    })?;
    std::fs::write(capture.join("cluster-metadata.checkpoint"), bytes).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: capture,
            source: source.into(),
        }
    })?;
    Ok(())
}

/// Append a fifth proposal whose approval is stamped after expiry.
///
/// The approval signature stays valid (`approved_at_ms` is not covered), so
/// the only tripwire is the two-person expiry check.
fn write_extra_proposal(keys: &FixtureKeys, dir: &Path) -> Result<(), EvidenceError> {
    let base = base_ms();
    let minute = 60_000;
    let created = base + 9 * minute;
    let expires = created + 10 * minute;
    let mut proposal = signed_proposal(
        keys,
        "33333333-3333-3333-3333-333333333333"
            .parse::<Uuid>()
            .unwrap_or(Uuid::nil()),
        BreakGlassAction::DeleteRecords,
        "orders-0",
        "User:alice",
        "trim obsolete partition",
        created,
        expires,
        0,
        false,
    );
    // Stamp the first approval an hour after expiry.
    if let Some(first) = proposal.approvals.first_mut() {
        first.approved_at_ms = expires + 60 * minute;
    }
    let bytes = encode_metadata_batch(
        &[MetadataRecord::V1BreakGlassProposal(proposal)],
        4,
        created,
        expires,
    )?;
    let name = if dir.join("restore-inputs").is_dir() {
        // Capture layout: a second snapshot supersedes the first.
        let capture = dir
            .join("restore-inputs")
            .join(format!("{base}-fixture-extra"));
        std::fs::create_dir_all(&capture).map_err(|source| EvidenceError::OutputUnwritable {
            path: capture.clone(),
            source: source.into(),
        })?;
        capture.join("cluster-metadata.checkpoint")
    } else {
        dir.join("00000000000000000004.log")
    };
    std::fs::write(&name, bytes).map_err(|source| EvidenceError::OutputUnwritable {
        path: name,
        source: source.into(),
    })?;
    Ok(())
}

/// Encode metadata records as one `RecordBatch` frame.
fn encode_metadata_batch(
    records: &[MetadataRecord],
    base_offset: i64,
    base_timestamp: i64,
    max_timestamp: i64,
) -> Result<Vec<u8>, EvidenceError> {
    let mut image = MetadataImage::new(Uuid::nil());
    let mut batch_records = Vec::new();
    for record in records {
        let values = to_kraft_values(record, &image).map_err(|source| {
            EvidenceError::input(
                "fixture metadata".to_string(),
                anyhow::anyhow!(source.to_string()),
            )
        })?;
        for value in values {
            batch_records.push(Record {
                attributes: 0,
                timestamp_delta: 0,
                offset_delta: i32::try_from(batch_records.len()).unwrap_or(0),
                key: None,
                value: Some(Bytes::copy_from_slice(&value)),
                headers: Vec::new(),
            });
        }
        image.apply(record);
    }
    let last_delta = i32::try_from(batch_records.len().saturating_sub(1)).unwrap_or(0);
    let batch = RecordBatch {
        base_offset,
        partition_leader_epoch: 0,
        attributes: krabka_protocol::records::Attributes::default(),
        last_offset_delta: last_delta,
        base_timestamp,
        max_timestamp,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records: batch_records,
    };
    let mut buffer = BytesMut::new();
    batch
        .encode(&mut buffer)
        .map_err(|source| EvidenceError::OutputUnwritable {
            path: Path::new("<fixture-metadata>").to_path_buf(),
            source: anyhow::anyhow!(source.to_string()),
        })?;
    Ok(buffer.freeze().to_vec())
}

/// The four metadata records of every scenario.
fn fixture_metadata_records(
    keys: &FixtureKeys,
    base: i64,
    minute: i64,
    unsigned: bool,
) -> [MetadataRecord; 4] {
    let thaw_id = PROPOSAL_THAW.parse::<Uuid>().unwrap_or(Uuid::nil());
    let delete_id = PROPOSAL_DELETE.parse::<Uuid>().unwrap_or(Uuid::nil());
    let freeze = signed_freeze(
        &keys.alice,
        "alice-2026",
        "orders",
        true,
        "incident-42 hold writes",
        "User:alice",
        base,
        Uuid::nil(),
        !unsigned,
    );
    let thaw_proposal = signed_proposal(
        keys,
        thaw_id,
        BreakGlassAction::ThawTopicFreeze,
        "literal:orders",
        "User:alice",
        "thaw after incident-42",
        base + minute,
        base + minute + 24 * 60 * minute,
        base + 4 * minute,
        unsigned,
    );
    let thaw = signed_freeze(
        &keys.bob,
        "bob-2026",
        "orders",
        false,
        "thaw after incident-42",
        "User:bob",
        base + 4 * minute,
        thaw_id,
        true,
    );
    let delete_proposal = signed_proposal(
        keys,
        delete_id,
        BreakGlassAction::DeleteTopic,
        "orders",
        "User:alice",
        "remove obsolete topic",
        base + 5 * minute,
        base + 5 * minute + 24 * 60 * minute,
        base + 8 * minute,
        false,
    );
    [
        MetadataRecord::V1TopicFreeze(freeze),
        MetadataRecord::V1BreakGlassProposal(thaw_proposal),
        MetadataRecord::V1TopicFreeze(thaw),
        MetadataRecord::V1BreakGlassProposal(delete_proposal),
    ]
}

/// Build a signed freeze record (or thaw sentinel when `frozen` is false).
#[allow(clippy::too_many_arguments)]
fn signed_freeze(
    signer: &FileEd25519Signer,
    key_id: &str,
    scope: &str,
    frozen: bool,
    reason: &str,
    set_by: &str,
    set_at_ms: i64,
    proposal_id: Uuid,
    sign: bool,
) -> TopicFreezeRecord {
    let (key_id, signature) = if sign {
        (
            key_id.to_string(),
            signer.sign(&freeze_signing_bytes(&FreezeSigningInput {
                cluster_id: CLUSTER_ID,
                pattern_type: PATTERN_TYPE_LITERAL,
                scope,
                frozen,
                reason,
                set_by,
                set_at_ms,
                proposal_id: *proposal_id.as_bytes(),
            })),
        )
    } else {
        (String::new(), Vec::new())
    };
    TopicFreezeRecord {
        scope: scope.to_string(),
        pattern_type: PatternType::Literal,
        frozen,
        reason: reason.to_string(),
        set_by: set_by.to_string(),
        set_at_ms,
        proposal_id,
        key_id,
        signature,
    }
}

/// Build a proposal with two approvals (bob, carol), consumed at `consumed_at`.
#[allow(clippy::too_many_arguments)]
fn signed_proposal(
    keys: &FixtureKeys,
    proposal_id: Uuid,
    action: BreakGlassAction,
    target: &str,
    proposer: &str,
    reason: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
    consumed_at_ms: i64,
    unsigned_bob: bool,
) -> BreakGlassProposalRecord {
    let wire = crate::timeline::action_wire_value(action);
    let message = approval_signing_bytes(&ApprovalSigningInput {
        proposal_id: *proposal_id.as_bytes(),
        action: wire,
        target,
        proposer,
        created_at_ms,
        expires_at_ms,
    });
    let approvals = [
        (
            keys.bob.clone(),
            "User:bob",
            created_at_ms + 60_000,
            unsigned_bob,
        ),
        (
            keys.carol.clone(),
            "User:carol",
            created_at_ms + 120_000,
            false,
        ),
    ]
    .iter()
    .map(|(signer, principal, approved_at_ms, unsigned)| {
        let (key_id, signature) = if *unsigned {
            (String::new(), Vec::new())
        } else {
            (
                format!("{}-2026", principal.split(':').nth(1).unwrap_or("x")),
                signer.sign(&message),
            )
        };
        BreakGlassApproval {
            principal: (*principal).to_string(),
            approved_at_ms: *approved_at_ms,
            key_id,
            signature,
        }
    })
    .collect();
    BreakGlassProposalRecord {
        proposal_id,
        action,
        target: target.to_string(),
        proposer: proposer.to_string(),
        reason: reason.to_string(),
        created_at_ms,
        expires_at_ms,
        approvals,
        consumed_at_ms,
        withdrawn: false,
    }
}

/// Write the audit partition in two segments, applying the scenario tamper.
///
/// When `unsigned` is set, the freeze events and the first thaw approval
/// carry no signature (the `unsigned` scenario).
fn write_audit(
    scenario: Scenario,
    keys: &FixtureKeys,
    dir: &Path,
    unsigned: bool,
) -> Result<(), EvidenceError> {
    let base = base_ms();
    let minute = 60_000;
    let fingerprint = approver_set_fingerprint(&approvers());
    let drifted = approver_set_fingerprint(
        &["User:alice", "User:bob", "User:dave"]
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    );
    let events = plan_audit_events(keys, &fingerprint);

    // Scenario tampers, applied to the OCSF JSON before chaining so the hash
    // chain stays consistent around them.
    let product = ProductInfo {
        vendor_name: "krabka".to_string(),
        name: "fixture".to_string(),
        version: "0".to_string(),
    };
    let mut serialized: Vec<AuditRecord> = events
        .iter()
        .map(|event| AuditRecord::from_event(event, &product))
        .collect();
    if scenario == Scenario::FlippedSignature {
        let victim = usize::try_from(FREEZE_APPLIED_OFFSET).unwrap_or(0);
        flip_signature_hex(&mut serialized[victim])?;
    }
    if scenario == Scenario::ApproverChange {
        let victim = usize::try_from(DELETE_APPLIED_INDEX).unwrap_or(0);
        set_fingerprint(&mut serialized[victim], &drifted)?;
    }
    if unsigned {
        // The freeze and the first thaw approval go out unattested.
        for index in [0, 1, 3] {
            strip_signature(&mut serialized[index])?;
        }
    }

    // Chain and split into two segments: offsets 0..=11, then 12..=15.
    // Deltas are relative to each segment's base offset. A checkpoint closes
    // each segment, so every scenario input is fully anchored.
    let mut chain = ChainState::new();
    let mut seg0: Vec<Record> = Vec::new();
    let mut seg1: Vec<Record> = Vec::new();
    for (index, record) in serialized.iter_mut().enumerate() {
        let link = chain.extend(&record.value);
        record.push_chain_headers(link.seq, &link.prev_head);
        if index < 12 {
            seg0.push(audit_record_to_kafka(
                record,
                i32::try_from(index).unwrap_or(0),
            ));
        } else {
            seg1.push(audit_record_to_kafka(
                record,
                i32::try_from(index - 12).unwrap_or(0),
            ));
        }
        if index == 11 {
            push_checkpoint(
                keys,
                &chain,
                11,
                EpochMs(base + 7 * minute + 30_000),
                &mut seg0,
            );
        }
    }
    push_checkpoint(
        keys,
        &chain,
        serialized.len().saturating_sub(1),
        EpochMs(base + 9 * minute),
        &mut seg1,
    );

    write_batch(dir, 0, &seg0, base, base + 7 * minute)?;
    write_batch(dir, 13, &seg1, base + 8 * minute, base + 9 * minute)?;
    Ok(())
}

/// Append a checkpoint covering `seq_high` to a segment's records.
fn push_checkpoint(
    keys: &FixtureKeys,
    chain: &ChainState,
    seq_high: usize,
    at: EpochMs,
    segment: &mut Vec<Record>,
) {
    let checkpoint = Checkpoint::signed(
        &keys.audit,
        Seq(u64::try_from(seq_high).unwrap_or(0)),
        &chain.head(),
        at,
    );
    segment.push(audit_record_to_kafka(
        &checkpoint.to_record(),
        i32::try_from(segment.len()).unwrap_or(0),
    ));
}

/// Pre-signed fixture signatures, decoded from hex once.
struct PlannedSignatures {
    freeze: Vec<u8>,
    thaw: Vec<u8>,
    thaw_bob: Vec<u8>,
    thaw_carol: Vec<u8>,
    delete_bob: Vec<u8>,
    delete_carol: Vec<u8>,
}

/// Sign every fixture message the audit events carry.
fn planned_signatures(keys: &FixtureKeys) -> PlannedSignatures {
    let base = base_ms();
    let minute = 60_000;
    let thaw_id = PROPOSAL_THAW.parse::<Uuid>().unwrap_or(Uuid::nil());
    let delete_id = PROPOSAL_DELETE.parse::<Uuid>().unwrap_or(Uuid::nil());
    let freeze = keys.alice.sign(&freeze_signing_bytes(&FreezeSigningInput {
        cluster_id: CLUSTER_ID,
        pattern_type: PATTERN_TYPE_LITERAL,
        scope: "orders",
        frozen: true,
        reason: "incident-42 hold writes",
        set_by: "User:alice",
        set_at_ms: base,
        proposal_id: [0u8; 16],
    }));
    let thaw = keys.bob.sign(&freeze_signing_bytes(&FreezeSigningInput {
        cluster_id: CLUSTER_ID,
        pattern_type: PATTERN_TYPE_LITERAL,
        scope: "orders",
        frozen: false,
        reason: "thaw after incident-42",
        set_by: "User:bob",
        set_at_ms: base + 4 * minute,
        proposal_id: *thaw_id.as_bytes(),
    }));
    let (thaw_bob, thaw_carol) = approval_pair(keys, thaw_id, BreakGlassAction::ThawTopicFreeze);
    let (delete_bob, delete_carol) = approval_pair(keys, delete_id, BreakGlassAction::DeleteTopic);
    PlannedSignatures {
        freeze,
        thaw,
        thaw_bob,
        thaw_carol,
        delete_bob,
        delete_carol,
    }
}

/// The fifteen audit events of every scenario, in offset order.
fn plan_audit_events(keys: &FixtureKeys, fingerprint: &str) -> Vec<AuditEvent> {
    let sigs = planned_signatures(keys);
    let mut events = freeze_audit_events(&sigs, fingerprint);
    events.extend(thaw_audit_events(&sigs, fingerprint));
    events.extend(thaw_record_audit_events(&sigs, fingerprint));
    events.extend(delete_audit_events(&sigs, fingerprint));
    events
}

/// Offsets 0..=1: the freeze.
fn freeze_audit_events(sigs: &PlannedSignatures, fingerprint: &str) -> Vec<AuditEvent> {
    let base = base_ms();
    let second = 1_000;
    let nil_id = Uuid::nil().to_string();
    vec![
        // 0: freeze Attempted.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Attempted,
            action: "set_topic_freeze",
            target: "literal:orders",
            proposal: &nil_id,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "alice-2026",
            signature: sigs.freeze.clone(),
            verified: true,
            signed_at_ms: base,
            reason: "incident-42 hold writes",
            time_ms: base + second,
            fingerprint,
        }),
        // 1: freeze Applied (flipped-sig victim).
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Applied,
            action: "set_topic_freeze",
            target: "literal:orders",
            proposal: &nil_id,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "alice-2026",
            signature: sigs.freeze.clone(),
            verified: true,
            signed_at_ms: base,
            reason: "incident-42 hold writes",
            time_ms: base + 5 * second,
            fingerprint,
        }),
    ]
}

/// Offsets 2..=6: the thaw proposal lifecycle.
fn thaw_audit_events(sigs: &PlannedSignatures, fingerprint: &str) -> Vec<AuditEvent> {
    let base = base_ms();
    let minute = 60_000;
    let second = 1_000;
    vec![
        // 2: thaw proposal Proposed.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Proposed,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "thaw after incident-42",
            time_ms: base + minute + 5 * second,
            fingerprint,
        }),
        // 3..4: approvals.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Approved,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:bob"),
            parties: fixture_counterparties(&["User:bob"]),
            key_id: "bob-2026",
            signature: sigs.thaw_bob.clone(),
            verified: true,
            signed_at_ms: 0,
            reason: "second pair of eyes",
            time_ms: base + 2 * minute + 5 * second,
            fingerprint,
        }),
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Approved,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:carol"),
            parties: fixture_counterparties(&["User:bob", "User:carol"]),
            key_id: "carol-2026",
            signature: sigs.thaw_carol.clone(),
            verified: true,
            signed_at_ms: 0,
            reason: "second pair of eyes",
            time_ms: base + 3 * minute + 5 * second,
            fingerprint,
        }),
        // 5..6: thaw Consumed + Applied.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Consumed,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:bob"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "running the thaw",
            time_ms: base + 4 * minute + 5 * second,
            fingerprint,
        }),
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Applied,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:bob"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "running the thaw",
            time_ms: base + 4 * minute + 6 * second,
            fingerprint,
        }),
    ]
}

/// Offsets 7..=8: the thaw record on the freeze path.
fn thaw_record_audit_events(sigs: &PlannedSignatures, fingerprint: &str) -> Vec<AuditEvent> {
    let base = base_ms();
    let minute = 60_000;
    let second = 1_000;
    vec![
        // 7..8: thaw record Attempted + Applied (freeze path).
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Attempted,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:bob"),
            parties: Vec::new(),
            key_id: "bob-2026",
            signature: sigs.thaw.clone(),
            verified: true,
            signed_at_ms: base + 4 * minute,
            reason: "thaw after incident-42",
            time_ms: base + 4 * minute + 7 * second,
            fingerprint,
        }),
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Applied,
            action: "thaw_topic_freeze",
            target: "literal:orders",
            proposal: PROPOSAL_THAW,
            actor: fixture_principal("User:bob"),
            parties: Vec::new(),
            key_id: "bob-2026",
            signature: sigs.thaw.clone(),
            verified: true,
            signed_at_ms: base + 4 * minute,
            reason: "thaw after incident-42",
            time_ms: base + 4 * minute + 10 * second,
            fingerprint,
        }),
    ]
}

/// Offsets 9..=14: the delete proposal and `DeleteTopic`.
fn delete_audit_events(sigs: &PlannedSignatures, fingerprint: &str) -> Vec<AuditEvent> {
    let base = base_ms();
    let minute = 60_000;
    let second = 1_000;
    vec![
        // 9: delete proposal Proposed.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Proposed,
            action: "delete_topic",
            target: "orders",
            proposal: PROPOSAL_DELETE,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "remove obsolete topic",
            time_ms: base + 5 * minute + 5 * second,
            fingerprint,
        }),
        // 10..11: approvals.
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Approved,
            action: "delete_topic",
            target: "orders",
            proposal: PROPOSAL_DELETE,
            actor: fixture_principal("User:bob"),
            parties: fixture_counterparties(&["User:bob"]),
            key_id: "bob-2026",
            signature: sigs.delete_bob.clone(),
            verified: true,
            signed_at_ms: 0,
            reason: "second pair of eyes",
            time_ms: base + 6 * minute + 5 * second,
            fingerprint,
        }),
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Approved,
            action: "delete_topic",
            target: "orders",
            proposal: PROPOSAL_DELETE,
            actor: fixture_principal("User:carol"),
            parties: fixture_counterparties(&["User:bob", "User:carol"]),
            key_id: "carol-2026",
            signature: sigs.delete_carol.clone(),
            verified: true,
            signed_at_ms: 0,
            reason: "second pair of eyes",
            time_ms: base + 7 * minute + 5 * second,
            fingerprint,
        }),
        // 12..13: delete Consumed + Applied (drift victim is 13).
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Consumed,
            action: "delete_topic",
            target: "orders",
            proposal: PROPOSAL_DELETE,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "running the delete",
            time_ms: base + 8 * minute + 5 * second,
            fingerprint,
        }),
        privileged_event(PrivilegedParams {
            phase: PrivilegedPhase::Applied,
            action: "delete_topic",
            target: "orders",
            proposal: PROPOSAL_DELETE,
            actor: fixture_principal("User:alice"),
            parties: Vec::new(),
            key_id: "",
            signature: Vec::new(),
            verified: false,
            signed_at_ms: 0,
            reason: "running the delete",
            time_ms: base + 8 * minute + 6 * second,
            fingerprint,
        }),
        // 14: the gated DeleteTopic admin operation.
        AuditEvent::AdminOperation {
            outcome: AuditOutcome::Success,
            principal: fixture_principal("User:alice"),
            source: fixture_endpoint(),
            operation: "DeleteTopic".to_string(),
            resources: vec![AuditResource {
                resource_type: "Topic".to_string(),
                name: "orders".to_string(),
            }],
            time_ms: base + 8 * minute + 30 * second,
        },
    ]
}

/// Fields of one privileged fixture event.
struct PrivilegedParams<'a> {
    phase: PrivilegedPhase,
    action: &'a str,
    target: &'a str,
    proposal: &'a str,
    actor: AuditPrincipal,
    parties: Vec<AuditPrincipal>,
    key_id: &'a str,
    signature: Vec<u8>,
    verified: bool,
    signed_at_ms: i64,
    reason: &'a str,
    time_ms: i64,
    fingerprint: &'a str,
}

/// Build one privileged fixture event.
fn privileged_event(params: PrivilegedParams<'_>) -> AuditEvent {
    AuditEvent::PrivilegedAction {
        outcome: AuditOutcome::Success,
        phase: params.phase,
        action: params.action.to_string(),
        target: params.target.to_string(),
        proposal_id: params.proposal.to_string(),
        principal: params.actor,
        counterparties: params.parties,
        approver_set_fingerprint: params.fingerprint.to_string(),
        key_id: params.key_id.to_string(),
        signature: params.signature,
        signature_verified: params.verified,
        signed_at_ms: params.signed_at_ms,
        source: fixture_endpoint(),
        reason: params.reason.to_string(),
        time_ms: params.time_ms,
    }
}

/// The fixture's broker endpoint.
fn fixture_endpoint() -> AuditEndpoint {
    AuditEndpoint {
        ip: "10.0.0.8".to_string(),
        port: 9092,
    }
}

/// The fixture's authenticated principal.
fn fixture_principal(name: &str) -> AuditPrincipal {
    AuditPrincipal {
        name: name.to_string(),
        auth_method: "SCRAM".to_string(),
    }
}

/// The fixture's counterparty list.
fn fixture_counterparties(names: &[&str]) -> Vec<AuditPrincipal> {
    names
        .iter()
        .map(|name| AuditPrincipal {
            name: (*name).to_string(),
            auth_method: String::new(),
        })
        .collect()
}

/// Sign the fixture's approval messages for one proposal.
fn approval_pair(
    keys: &FixtureKeys,
    proposal_id: Uuid,
    action: BreakGlassAction,
) -> (Vec<u8>, Vec<u8>) {
    let (wire, target, proposer, created, expires) = match action {
        BreakGlassAction::ThawTopicFreeze => (
            1,
            "literal:orders",
            "User:alice",
            base_ms() + 60_000,
            base_ms() + 60_000 + 24 * 3_600_000,
        ),
        _ => (
            6,
            "orders",
            "User:alice",
            base_ms() + 300_000,
            base_ms() + 300_000 + 24 * 3_600_000,
        ),
    };
    let message = approval_signing_bytes(&ApprovalSigningInput {
        proposal_id: *proposal_id.as_bytes(),
        action: wire,
        target,
        proposer,
        created_at_ms: created,
        expires_at_ms: expires,
    });
    (keys.bob.sign(&message), keys.carol.sign(&message))
}

/// Flip the first hex digit of a record's OCSF signature.
fn flip_signature_hex(record: &mut AuditRecord) -> Result<(), EvidenceError> {
    let mut json: serde_json::Value = serde_json::from_slice(&record.value).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: Path::new("<fixture>").to_path_buf(),
            source: source.into(),
        }
    })?;
    let signature = json
        .pointer_mut("/privileged_action/signature")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let mut chars: Vec<char> = signature.chars().collect();
    if chars.is_empty() {
        return Err(EvidenceError::OutputUnwritable {
            path: Path::new("<fixture>").to_path_buf(),
            source: anyhow::anyhow!("fixture victim has no signature to flip"),
        });
    }
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let flipped: String = chars.into_iter().collect();
    json["privileged_action"]["signature"] = serde_json::Value::String(flipped);
    record.value = serde_json::to_vec(&json).unwrap_or_default();
    Ok(())
}

/// Strip a record's OCSF key and signature, leaving it unattested.
fn strip_signature(record: &mut AuditRecord) -> Result<(), EvidenceError> {
    let mut json: serde_json::Value = serde_json::from_slice(&record.value).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: Path::new("<fixture>").to_path_buf(),
            source: source.into(),
        }
    })?;
    json["privileged_action"]["key_id"] = serde_json::Value::String(String::new());
    json["privileged_action"]["signature"] = serde_json::Value::String(String::new());
    record.value = serde_json::to_vec(&json).unwrap_or_default();
    Ok(())
}

/// Replace a record's OCSF approver-set fingerprint.
fn set_fingerprint(record: &mut AuditRecord, fingerprint: &str) -> Result<(), EvidenceError> {
    let mut json: serde_json::Value = serde_json::from_slice(&record.value).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: Path::new("<fixture>").to_path_buf(),
            source: source.into(),
        }
    })?;
    json["privileged_action"]["approver_set_fingerprint"] =
        serde_json::Value::String(fingerprint.to_string());
    record.value = serde_json::to_vec(&json).unwrap_or_default();
    Ok(())
}

/// Flip the first hex digit of `text`, keeping it valid hex.
///
/// Tamper helpers use this so the corrupted document still parses: the
/// failure must come from the cryptography, never from the codec.
fn flip_hex_head(text: &str) -> Option<String> {
    let mut flipped = text.as_bytes().to_vec();
    let head = flipped.iter_mut().find(|byte| byte.is_ascii_hexdigit())?;
    *head = if *head == b'0' { b'1' } else { b'0' };
    String::from_utf8(flipped).ok()
}

/// Corrupt the head audit segment after sealing: flip one hex digit in the
/// closing checkpoint's signature.
///
/// The checkpoint is the last record of the head segment, so the flip lands
/// at the end of the file. Framing stays intact, so the shipped verifier
/// reads the record and reports a signature break at offset 12 instead of
/// stopping at an undecodable tail.
fn corrupt_audit_head(dir: &Path) -> Result<(), EvidenceError> {
    let segment = dir.join("00000000000000000000.log");
    let unwritable = |source: anyhow::Error| EvidenceError::OutputUnwritable {
        path: segment.clone(),
        source,
    };
    let bytes = std::fs::read(&segment).map_err(|source| unwritable(source.into()))?;
    let mut cursor: &[u8] = &bytes;
    let mut batch = RecordBatch::decode(&mut cursor)
        .map_err(|_| unwritable(anyhow::anyhow!("head segment does not decode")))?;
    let Some(last) = batch.records.last_mut() else {
        return Err(unwritable(anyhow::anyhow!("head segment holds no records")));
    };
    let value = last.value.as_deref().unwrap_or_default();
    let mut json: serde_json::Value =
        serde_json::from_slice(value).map_err(|source| unwritable(source.into()))?;
    let signature = json
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unwritable(anyhow::anyhow!("checkpoint holds no signature")))?;
    let flipped = flip_hex_head(signature)
        .ok_or_else(|| unwritable(anyhow::anyhow!("checkpoint signature holds no hex")))?;
    json["signature"] = serde_json::Value::String(flipped);
    let rewritten = serde_json::to_vec(&json).map_err(|source| unwritable(source.into()))?;
    last.value = Some(Bytes::copy_from_slice(&rewritten));
    let mut buffer = BytesMut::new();
    batch
        .encode(&mut buffer)
        .map_err(|_| unwritable(anyhow::anyhow!("tampered batch does not encode")))?;
    std::fs::write(&segment, buffer.freeze()).map_err(|source| unwritable(source.into()))?;
    Ok(())
}

/// Corrupt the WORM archive after sealing: flip one hex digit in the newest
/// manifest's `prev_head` chain link.
///
/// The JSON still parses, so the verifier reads the manifest and reports a
/// chain break instead of an unreadable archive.
fn corrupt_manifest_link(dir: &Path) -> Result<(), EvidenceError> {
    let mut manifests = Vec::new();
    collect_manifests(dir, &mut manifests)?;
    manifests.sort();
    let Some(victim) = manifests.pop() else {
        return Err(EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!("archive holds no manifests"),
        });
    };
    let unwritable = |source: anyhow::Error| EvidenceError::OutputUnwritable {
        path: victim.clone(),
        source,
    };
    let bytes = std::fs::read(&victim).map_err(|source| unwritable(source.into()))?;
    let mut json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|source| unwritable(source.into()))?;
    let prev_head = json
        .get("body")
        .and_then(|body| body.get("chain"))
        .and_then(|chain| chain.get("prev_head"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unwritable(anyhow::anyhow!("manifest holds no prev_head link")))?;
    let flipped = flip_hex_head(prev_head)
        .ok_or_else(|| unwritable(anyhow::anyhow!("prev_head holds no hex")))?;
    json["body"]["chain"]["prev_head"] = serde_json::Value::String(flipped);
    // Compact JSON, exactly as the archiver writes it.
    let rewritten = serde_json::to_vec(&json).map_err(|source| unwritable(source.into()))?;
    std::fs::write(&victim, rewritten).map_err(|source| unwritable(source.into()))?;
    Ok(())
}

/// Collect every `*.manifest` file under `dir`.
fn collect_manifests(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), EvidenceError> {
    let entries = std::fs::read_dir(dir).map_err(|source| EvidenceError::OutputUnwritable {
        path: dir.to_path_buf(),
        source: source.into(),
    })?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_manifests(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext == MANIFEST_SUFFIX.trim_start_matches('.'))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Convert a sink-ready audit record into a protocol record.
fn audit_record_to_kafka(record: &AuditRecord, offset_delta: i32) -> Record {
    Record {
        attributes: 0,
        timestamp_delta: 0,
        offset_delta,
        key: None,
        value: Some(Bytes::copy_from_slice(&record.value)),
        headers: record
            .headers
            .iter()
            .map(|(key, value)| RecordHeader {
                key: key.clone(),
                value: Some(Bytes::copy_from_slice(value)),
            })
            .collect(),
    }
}

/// Encode one batch and write it as `<base:020>.log`.
fn write_batch(
    dir: &Path,
    base_offset: i64,
    records: &[Record],
    base_timestamp: i64,
    max_timestamp: i64,
) -> Result<(), EvidenceError> {
    let batch = RecordBatch {
        base_offset,
        partition_leader_epoch: 0,
        attributes: krabka_protocol::records::Attributes::default(),
        last_offset_delta: i32::try_from(records.len()).unwrap_or(1) - 1,
        base_timestamp,
        max_timestamp,
        producer_id: -1,
        producer_epoch: -1,
        base_sequence: -1,
        records: records.to_vec(),
    };
    let mut buffer = BytesMut::new();
    batch
        .encode(&mut buffer)
        .map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!(source.to_string()),
        })?;
    let name = format!("{base_offset:020}.log");
    std::fs::write(dir.join(name), buffer.freeze()).map_err(|source| {
        EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: source.into(),
        }
    })?;
    Ok(())
}

/// Write a two-segment WORM archive sealed with the fixture's worm key.
async fn write_archive(keys: &FixtureKeys, dir: &Path) -> Result<(), EvidenceError> {
    use object_store::ObjectStoreExt as _;
    let store = build_object_store(&ObjectStoreConfig::Local {
        root: dir.to_path_buf(),
    })
    .map_err(|source| EvidenceError::OutputUnwritable {
        path: dir.to_path_buf(),
        source: anyhow::anyhow!(source.to_string()),
    })?;
    let archiver = WormArchiver::new(Some(keys.worm.clone()));
    let topic_id = Uuid::from_u128(0x000d_e500_0000_0000_0000_0000_0000_0000);
    let partition = TopicIdPartition::new(topic_id, "orders", 0);
    let mut prev_head = ChainHead::GENESIS;
    let epoch = EpochId(Uuid::from_u128(0x00e9_0c00_0000_0000_0000_0000_0000_0000));
    for (index, start) in [0_i64, 100].iter().enumerate() {
        let end = start + 99;
        let segment_id =
            RemoteLogSegmentId::new(partition.clone(), Uuid::from_u128(index as u128 + 1));
        let mut epochs = BTreeMap::new();
        epochs.insert(LeaderEpoch(0), *start);
        let log_body = format!("segment-{index}-log-body").into_bytes();
        let index_body = format!("segment-{index}-index").into_bytes();
        let size = i32::try_from(log_body.len() + index_body.len()).unwrap_or(0);
        let details =
            RemoteLogSegmentDetails::new(size, RemoteLogSegmentState::CopySegmentFinished, epochs);
        let metadata = RemoteLogSegmentMetadata::new(
            segment_id,
            *start,
            end,
            base_ms() + *start,
            1,
            base_ms() + end,
            details,
        )
        .map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!(source.to_string()),
        })?;
        let part_dir = format!("archive/{}", partition_dir_name(&metadata));
        let log_key = format!("{part_dir}/{}", segment_file_name(&metadata, ".log"));
        let index_key = format!("{part_dir}/{}", segment_file_name(&metadata, ".index"));
        let mut entries = Vec::new();
        for (suffix, key, body) in [
            (".log", log_key, &log_body),
            (".index", index_key, &index_body),
        ] {
            entries.push(put_archive_object(&store, dir, suffix, &key, body).await?);
        }
        let stamped = metadata.clone().with_custom_metadata(
            WormChainRecord::request(ChainStamp {
                epoch_id: epoch,
                seq: ManifestSeq(index as u64),
                prev_head,
            })
            .to_custom_metadata(),
        );
        let sealed =
            archiver
                .seal(&stamped, entries)
                .map_err(|source| EvidenceError::OutputUnwritable {
                    path: dir.to_path_buf(),
                    source: anyhow::anyhow!(source.to_string()),
                })?;
        let manifest_key = format!(
            "{part_dir}/{}",
            segment_file_name(&metadata, MANIFEST_SUFFIX)
        );
        store
            .put(
                &object_store::path::Path::from(manifest_key.as_str()),
                object_store::PutPayload::from_bytes(sealed.bytes.clone()),
            )
            .await
            .map_err(|source| EvidenceError::OutputUnwritable {
                path: dir.to_path_buf(),
                source: anyhow::anyhow!(source.to_string()),
            })?;
        prev_head = manifest_head(&sealed.manifest.body);
    }
    Ok(())
}

/// Put one archive object and build its manifest entry with a SHA-256 digest.
async fn put_archive_object(
    store: &Arc<dyn object_store::ObjectStore>,
    dir: &Path,
    suffix: &str,
    key: &str,
    body: &[u8],
) -> Result<ObjectEntry, EvidenceError> {
    use object_store::ObjectStoreExt as _;
    store
        .put(
            &object_store::path::Path::from(key),
            object_store::PutPayload::from_bytes(Bytes::copy_from_slice(body)),
        )
        .await
        .map_err(|source| EvidenceError::OutputUnwritable {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!(source.to_string()),
        })?;
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(ObjectEntry {
        suffix: suffix.to_string(),
        key: key.to_string(),
        size_bytes: body.len() as u64,
        sha256: Sha256Digest(digest),
        e_tag: None,
        version_id: None,
        create_precondition: false,
    })
}
