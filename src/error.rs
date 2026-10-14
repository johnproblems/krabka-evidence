//! Error types with the PRD exit-code mapping.
//!
//! Exit codes: `0` means clean, `1` means findings, `2` means inputs
//! unreadable. [`EvidenceError`] is always an exit-2 failure: something the
//! tool needed to read was missing or malformed. Findings are not errors;
//! they are data in the report.

use std::path::PathBuf;

/// Failures that stop a run before it can produce a report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// An input file or directory could not be read or parsed.
    #[error("input unreadable: {context}: {source}")]
    InputUnreadable {
        /// Which input failed and why it was needed.
        context: String,
        /// The underlying failure.
        #[source]
        source: anyhow::Error,
    },
    /// The operator-keys file could not be parsed or loaded.
    #[error("cannot load operator keys from {}: {source}", path.display())]
    KeysUnreadable {
        /// The keys file that failed to load.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: anyhow::Error,
    },
    /// The evidence pack exists but is malformed.
    #[error("cannot read evidence pack at {}: {reason}", path.display())]
    PackUnreadable {
        /// The pack directory.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// The output directory could not be written.
    #[error("cannot write output to {}: {source}", path.display())]
    OutputUnwritable {
        /// The output directory.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: anyhow::Error,
    },
    /// The time window is malformed (`--from` after `--to`, unparsable date).
    #[error("bad time window: {reason}")]
    BadWindow {
        /// What was wrong with the window.
        reason: String,
    },
}

impl EvidenceError {
    /// Build an [`EvidenceError::InputUnreadable`] from any error value.
    #[must_use]
    pub fn input(context: impl Into<String>, source: impl Into<anyhow::Error>) -> Self {
        Self::InputUnreadable {
            context: context.into(),
            source: source.into(),
        }
    }
}

/// The process exit code for a finished run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Clean report (or a verification that passed).
    Clean = 0,
    /// The report holds findings (or a verification failed).
    Findings = 1,
    /// Inputs were unreadable.
    Unreadable = 2,
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        Self::from(code as u8)
    }
}
