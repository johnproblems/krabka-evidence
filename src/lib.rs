//! krabka-evidence: one signed report from every ledger.
//!
//! An offline command-line tool that answers one question: *did every
//! dangerous thing that happened go through the controls, and can we prove
//! it?* It runs the three single-ledger verifiers, cross-checks the ledgers
//! against each other, and emits one signed HTML + JSON evidence pack.
//!
//! Krabka crates are used as libraries, pinned to release tags (see
//! `Cargo.toml`): the audit verifier and OCSF model from `krabka-audit`, the
//! freeze/approval preimages from `krabka-guard`, the operator trust set from
//! `krabka-broker`, the WORM verifier from `krabka-remote-storage`, and the
//! metadata record model from `krabka-metadata`.

pub mod archive;
pub mod audit;
pub mod checks;
pub mod cli;
pub mod error;
pub mod finding;
pub mod fixture;
pub mod hash;
pub mod keys;
pub mod metadata;
pub mod report;
pub mod signing;
pub mod timeline;

pub use error::EvidenceError;
