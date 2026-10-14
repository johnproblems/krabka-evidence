//! The auditor's signing key.
//!
//! The report key is a separate auditor key the cluster never sees (PRD open
//! question, resolved for the safer default): reports are signed with an
//! Ed25519 PKCS#8 key that lives on the auditor's machine. Signing and
//! verification run through the same [`krabka_audit::signing`] code path the
//! cluster uses for its own signatures, over one domain-separated preimage:
//!
//! ```text
//! b"krabka-evidence-report-v1\0" ‖ canonical-report-json
//! ```

use std::path::Path;

use krabka_audit::signing::{FileEd25519Signer, verify_signature};
use ring::{rand::SystemRandom, signature::Ed25519KeyPair};

use crate::error::EvidenceError;

/// Domain separator for report signatures.
pub const REPORT_DOMAIN: &[u8] = b"krabka-evidence-report-v1\0";

/// A minted auditor keypair.
pub struct AuditorKeypair {
    /// PKCS#8 DER private key.
    pub private_pkcs8: Vec<u8>,
    /// Raw 32-byte public key.
    pub public_key: Vec<u8>,
}

/// Mint a fresh auditor keypair.
///
/// # Errors
///
/// Returns [`EvidenceError::OutputUnwritable`] when the platform RNG fails,
/// which in practice cannot happen.
pub fn generate_auditor_key() -> Result<AuditorKeypair, EvidenceError> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| {
        EvidenceError::OutputUnwritable {
            path: Path::new("<rng>").to_path_buf(),
            source: anyhow::anyhow!("the platform RNG refused to mint a key"),
        }
    })?;
    let signer = FileEd25519Signer::from_pkcs8_bytes(pkcs8.as_ref(), "auditor".to_string())
        .map_err(|source| EvidenceError::OutputUnwritable {
            path: Path::new("<rng>").to_path_buf(),
            source: anyhow::anyhow!(source.to_string()),
        })?;
    Ok(AuditorKeypair {
        private_pkcs8: pkcs8.as_ref().to_vec(),
        public_key: signer.public_key(),
    })
}

/// Sign canonical report bytes with the PKCS#8 key at `path`.
///
/// # Errors
///
/// Returns [`EvidenceError::InputUnreadable`] when the key cannot be read or
/// is not a valid PKCS#8 Ed25519 key.
pub fn sign_canonical_bytes(path: &Path, canonical: &[u8]) -> Result<Vec<u8>, EvidenceError> {
    let signer =
        FileEd25519Signer::from_pkcs8_file(path, "auditor".to_string()).map_err(|source| {
            EvidenceError::input(
                format!("auditor key {}", path.display()),
                anyhow::anyhow!(source.to_string()),
            )
        })?;
    Ok(signer.sign(&signing_message(canonical)))
}

/// Verify canonical report bytes against a raw 32-byte public key.
#[must_use]
pub fn verify_canonical_bytes(public_key: &[u8], canonical: &[u8], signature: &[u8]) -> bool {
    verify_signature(public_key, &signing_message(canonical), signature)
}

/// The domain-separated message a report signature covers.
#[must_use]
pub fn signing_message(canonical: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(REPORT_DOMAIN.len() + canonical.len());
    message.extend_from_slice(REPORT_DOMAIN);
    message.extend_from_slice(canonical);
    message
}
