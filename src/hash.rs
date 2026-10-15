//! Input hashing: bind the evidence pack to the bytes it was built from.
//!
//! Every local input is walked in sorted order, every file is hashed with
//! SHA-256, and the input digest is the SHA-256 over the
//! `relative-path ‖ hex-digest` listing. `verify` re-hashes the inputs it is
//! given and compares against the digests the pack names.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::error::EvidenceError;

/// The digest of one input.
#[derive(Debug, Clone)]
pub struct InputDigest {
    /// Hex SHA-256 over the sorted `path ‖ file-digest` listing.
    pub digest: String,
    /// How many files were hashed.
    pub files: u64,
    /// Total bytes hashed.
    pub bytes: u64,
    /// Per-file digests keyed by `/`-separated relative path.
    pub file_hashes: BTreeMap<String, String>,
}

/// Hash one input: a file or a directory walked recursively.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the path is missing or a
/// file cannot be read.
pub fn digest_path(root: &Path, context: &str) -> Result<InputDigest, EvidenceError> {
    if root.is_file() {
        let (digest, bytes) = hash_file(root, context)?;
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let mut file_hashes = BTreeMap::new();
        file_hashes.insert(name, digest);
        let listing = listing_digest(&file_hashes);
        return Ok(InputDigest {
            digest: listing,
            files: 1,
            bytes,
            file_hashes,
        });
    }
    if !root.is_dir() {
        return Err(EvidenceError::input(
            context.to_string(),
            anyhow::anyhow!("{} is not a file or directory", root.display()),
        ));
    }
    let mut files = Vec::new();
    collect_files(root, root, &mut files, context)?;
    files.sort();
    let mut file_hashes = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    for relative in &files {
        let absolute = root.join(relative);
        let (digest, bytes) = hash_file(&absolute, context)?;
        total_bytes += bytes;
        file_hashes.insert(relative.clone(), digest);
    }
    Ok(InputDigest {
        digest: listing_digest(&file_hashes),
        files: files.len() as u64,
        bytes: total_bytes,
        file_hashes,
    })
}

/// The digest over a sorted `path -> hex-digest` listing.
///
/// Shared by [`digest_path`] and pack verification, so a swapped
/// `input-files.json` cannot pass.
#[must_use]
pub fn listing_digest(file_hashes: &BTreeMap<String, String>) -> String {
    let mut listing = Sha256::new();
    for (relative, digest) in file_hashes {
        listing.update(relative.as_bytes());
        listing.update([0u8]);
        listing.update(digest.as_bytes());
        listing.update([0u8]);
    }
    hex::encode(listing.finalize())
}

/// Collect `/`-separated relative file paths under `dir`.
fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
    context: &str,
) -> Result<(), EvidenceError> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| {
            EvidenceError::input(
                context.to_string(),
                anyhow::anyhow!("read dir {}: {source}", dir.display()),
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        // Never follow symlinks: a cyclic link would recurse forever, and a
        // link to a fifo or a file outside the input must not be hashed.
        let file_type = std::fs::symlink_metadata(&path)
            .map_err(|source| {
                EvidenceError::input(
                    context.to_string(),
                    anyhow::anyhow!("stat {}: {source}", path.display()),
                )
            })?
            .file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(root, &path, out, context)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).map_err(|source| {
                EvidenceError::input(context.to_string(), anyhow::anyhow!(source.to_string()))
            })?;
            out.push(
                relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(())
}

/// Hash one file with a streaming read.
fn hash_file(path: &Path, context: &str) -> Result<(String, u64), EvidenceError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|source| {
        EvidenceError::input(
            context.to_string(),
            anyhow::anyhow!("read {}: {source}", path.display()),
        )
    })?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut bytes: u64 = 0;
    let mut buffer = vec![0u8; 65536];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| {
            EvidenceError::input(
                context.to_string(),
                anyhow::anyhow!("read {}: {source}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}
