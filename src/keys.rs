//! Trust material: operator keys plus the audit and WORM verifier keys.
//!
//! The keys file carries the same `[[operator_keys]]` table that
//! `krabka-guard freeze list --verify-signatures --operator-keys` takes, so
//! one file serves both tools. It may additionally carry `[[audit_keys]]`
//! and `[[worm_keys]]` tables for the checkpoint and manifest signatures,
//! which are broker keys rather than operator keys:
//!
//! ```toml
//! [[operator_keys]]
//! key_id = "alice-2026"
//! principal = "User:alice"
//! public_key_path = "alice.pub"
//!
//! [[audit_keys]]
//! key_id = "audit-1"
//! public_key_path = "audit.pub"
//!
//! [[worm_keys]]
//! key_id = "worm-1"
//! public_key_path = "worm.pub"
//! ```
//!
//! Relative `public_key_path` values resolve against the directory holding
//! the keys file. Each public key file holds a raw 32-byte Ed25519 key.
//!
//! The audit verifier trusts a single checkpoint key, mirroring
//! `krabka-audit verify --key-id --public-key`; the WORM verifier accepts
//! several, mirroring `krabka-worm-verify`'s repeatable flags.

use std::path::{Path, PathBuf};

use krabka_audit::verify::TrustedKeys as AuditTrustedKeys;
use krabka_broker::operator_keys::{OperatorKeyEntry, OperatorKeys};
use krabka_remote_storage::TrustedManifestKeys;
use serde::{Deserialize, Serialize};

use crate::error::EvidenceError;

/// One `[[operator_keys]]` entry in the keys file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorKeyFileEntry {
    /// Stable identifier that signed records name.
    pub key_id: String,
    /// The principal this key speaks for, e.g. `User:alice`.
    pub principal: String,
    /// Path to the raw 32-byte Ed25519 public key.
    pub public_key_path: PathBuf,
}

/// One `[[audit_keys]]` or `[[worm_keys]]` entry: a broker key with no
/// principal binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerKeyFileEntry {
    /// Stable identifier that checkpoints or manifests name.
    pub key_id: String,
    /// Path to the raw 32-byte Ed25519 public key.
    pub public_key_path: PathBuf,
}

/// The parsed keys file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeysFile {
    /// Operator keys, the same table the broker and `krabka-guard` read.
    #[serde(default)]
    pub operator_keys: Vec<OperatorKeyFileEntry>,
    /// Audit checkpoint keys (broker keys). At most one is used.
    #[serde(default)]
    pub audit_keys: Vec<BrokerKeyFileEntry>,
    /// WORM manifest keys (broker keys).
    #[serde(default)]
    pub worm_keys: Vec<BrokerKeyFileEntry>,
}

/// A `--key-id` / `--public-key` pair from the CLI.
#[derive(Debug, Clone)]
pub struct CliKeyPair {
    /// The key id the pair is trusted under.
    pub key_id: String,
    /// Path to the raw 32-byte public key.
    pub public_key: PathBuf,
}

/// All loaded trust material for a run.
#[derive(Debug, Default)]
pub struct TrustMaterial {
    /// Operator keys with principal bindings.
    pub operators: OperatorKeys,
    /// Audit checkpoint keys.
    pub audit: AuditTrustedKeys,
    /// WORM manifest keys.
    pub worm: TrustedManifestKeys,
    /// Whether any operator key is provisioned.
    pub has_operators: bool,
    /// Whether any audit key is provisioned.
    pub has_audit_keys: bool,
    /// Whether any worm key is provisioned.
    pub has_worm_keys: bool,
    /// Count of provisioned operator keys.
    pub operator_count: usize,
    /// Count of provisioned audit keys (0 or 1).
    pub audit_count: usize,
    /// Count of provisioned worm keys.
    pub worm_count: usize,
}

/// Load the keys file and any CLI-supplied broker keys.
///
/// # Errors
///
/// Returns [`EvidenceError::KeysUnreadable`] when the file cannot be read or
/// parsed, when a public key file is missing or malformed, when more than
/// one audit key is configured, or when two operator entries share a
/// `key_id` or principal.
pub fn load_trust(
    keys_path: &Path,
    cli_audit_keys: &[CliKeyPair],
    cli_worm_keys: &[CliKeyPair],
) -> Result<TrustMaterial, EvidenceError> {
    let raw =
        std::fs::read_to_string(keys_path).map_err(|source| EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: source.into(),
        })?;
    let parsed: KeysFile =
        toml::from_str(&raw).map_err(|source| EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: source.into(),
        })?;
    if parsed.operator_keys.is_empty()
        && parsed.audit_keys.is_empty()
        && parsed.worm_keys.is_empty()
        && cli_audit_keys.is_empty()
        && cli_worm_keys.is_empty()
    {
        return Err(EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: anyhow::anyhow!(
                "no [[operator_keys]], [[audit_keys]], or [[worm_keys]] entries"
            ),
        });
    }
    let base = keys_path.parent().unwrap_or_else(|| Path::new("."));

    let mut operator_entries = Vec::with_capacity(parsed.operator_keys.len());
    for entry in &parsed.operator_keys {
        operator_entries.push(OperatorKeyEntry {
            key_id: entry.key_id.clone(),
            principal: entry.principal.clone(),
            public_key_path: base.join(&entry.public_key_path),
        });
    }
    let operators =
        OperatorKeys::load(&operator_entries).map_err(|source| EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: source.into(),
        })?;

    let mut audit_pairs = read_pairs(base, &parsed.audit_keys, "audit", keys_path)?;
    for pair in cli_audit_keys {
        audit_pairs.push((
            pair.key_id.clone(),
            read_raw_key(&pair.public_key, keys_path, "audit", &pair.key_id)?,
        ));
    }
    if audit_pairs.len() > 1 {
        return Err(EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: anyhow::anyhow!(
                "at most one audit key is supported; configure one [[audit_keys]] entry"
            ),
        });
    }
    let audit = audit_pairs
        .into_iter()
        .next()
        .map(|(key_id, key)| AuditTrustedKeys::single(key_id, key))
        .unwrap_or_default();

    let mut worm_pairs = read_pairs(base, &parsed.worm_keys, "worm", keys_path)?;
    for pair in cli_worm_keys {
        worm_pairs.push((
            pair.key_id.clone(),
            read_raw_key(&pair.public_key, keys_path, "worm", &pair.key_id)?,
        ));
    }
    let worm = TrustedManifestKeys::from_pairs(worm_pairs);

    Ok(TrustMaterial {
        has_operators: !operators.is_empty(),
        has_audit_keys: !parsed.audit_keys.is_empty() || !cli_audit_keys.is_empty(),
        has_worm_keys: !parsed.worm_keys.is_empty() || !cli_worm_keys.is_empty(),
        operator_count: operators.len(),
        audit_count: usize::from(!parsed.audit_keys.is_empty() || !cli_audit_keys.is_empty()),
        worm_count: parsed.worm_keys.len() + cli_worm_keys.len(),
        operators,
        audit,
        worm,
    })
}

/// Read the raw keys of one file table.
fn read_pairs(
    base: &Path,
    entries: &[BrokerKeyFileEntry],
    kind: &str,
    keys_path: &Path,
) -> Result<Vec<(String, Vec<u8>)>, EvidenceError> {
    let mut pairs = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = base.join(&entry.public_key_path);
        let bytes = read_raw_key(&path, keys_path, kind, &entry.key_id)?;
        pairs.push((entry.key_id.clone(), bytes));
    }
    Ok(pairs)
}

/// Read one raw 32-byte Ed25519 public key file.
fn read_raw_key(
    path: &Path,
    keys_path: &Path,
    kind: &str,
    key_id: &str,
) -> Result<Vec<u8>, EvidenceError> {
    let bytes = std::fs::read(path).map_err(|source| EvidenceError::KeysUnreadable {
        path: keys_path.to_path_buf(),
        source: anyhow::anyhow!(
            "{kind} key {key_id:?}: cannot read {}: {source}",
            path.display()
        ),
    })?;
    if bytes.len() != 32 {
        return Err(EvidenceError::KeysUnreadable {
            path: keys_path.to_path_buf(),
            source: anyhow::anyhow!(
                "{kind} key {key_id:?}: {} holds {} bytes; a raw Ed25519 public key is 32 bytes",
                path.display(),
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}
