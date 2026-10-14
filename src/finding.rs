//! The unified finding type.
//!
//! Every per-ledger result and every cross-check normalizes into a
//! [`Finding`] (something the auditor must look at) or a [`Note`]
//! (something the report records without failing the run).

use serde::{Deserialize, Serialize};

/// Stable check identifiers. Each one is one row in the report's check table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CheckId {
    /// Audit hash chain and checkpoint signatures (`krabka-audit verify`).
    AuditChain,
    /// Declared fail-open loss windows in the audit partition.
    AuditLossWindows,
    /// WORM manifest chain, signatures, and objects (`krabka-worm-verify`).
    WormArchive,
    /// Metadata history coverage for the requested window.
    MetadataCoverage,
    /// Metadata freeze/break-glass act with no audit event.
    AppliedWithNoAuditEvent,
    /// Audit `Applied` event with no metadata record.
    AuditedActionNotInMetadata,
    /// Operator signature verification on events and records.
    SignatureVerification,
    /// Two-person rule: distinct approvers, approval before expiry.
    TwoPersonRule,
    /// Bypassed phases and audit-only recovery.
    BypassListing,
    /// Approver-set fingerprint drift within the window.
    ApproverSetChange,
    /// Gated admin operation with no break-glass consumption before it.
    GatedOperationWithoutApproval,
}

impl CheckId {
    /// Parse a kebab-case check id from `--only`.
    #[must_use]
    pub const fn from_kebab(text: &str) -> Option<Self> {
        match text.as_bytes() {
            b"audit-chain" => Some(Self::AuditChain),
            b"audit-loss-windows" => Some(Self::AuditLossWindows),
            b"worm-archive" => Some(Self::WormArchive),
            b"metadata-coverage" => Some(Self::MetadataCoverage),
            b"applied-with-no-audit-event" => Some(Self::AppliedWithNoAuditEvent),
            b"audited-action-not-in-metadata" => Some(Self::AuditedActionNotInMetadata),
            b"signature-verification" => Some(Self::SignatureVerification),
            b"two-person-rule" => Some(Self::TwoPersonRule),
            b"bypass-listing" => Some(Self::BypassListing),
            b"approver-set-change" => Some(Self::ApproverSetChange),
            b"gated-operation-without-approval" => Some(Self::GatedOperationWithoutApproval),
            _ => None,
        }
    }

    /// Human-readable title for the report.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AuditChain => "Audit hash chain and checkpoints",
            Self::AuditLossWindows => "Declared audit loss windows",
            Self::WormArchive => "WORM archive integrity",
            Self::MetadataCoverage => "Metadata history coverage",
            Self::AppliedWithNoAuditEvent => "Applied with no audit event",
            Self::AuditedActionNotInMetadata => "Audited action not in metadata",
            Self::SignatureVerification => "Signature verification",
            Self::TwoPersonRule => "Two-person rule",
            Self::BypassListing => "Bypassed controls",
            Self::ApproverSetChange => "Approver set changes",
            Self::GatedOperationWithoutApproval => "Gated operations without approval",
        }
    }

    /// Kebab-case id, mirroring [`CheckId::from_kebab`].
    ///
    /// ```
    /// use krabka_evidence::finding::CheckId;
    ///
    /// assert_eq!(CheckId::WormArchive.kebab(), "worm-archive");
    /// assert_eq!(CheckId::from_kebab("worm-archive"), Some(CheckId::WormArchive));
    /// assert_eq!(CheckId::from_kebab("no-such-check"), None);
    /// ```
    #[must_use]
    pub const fn kebab(self) -> &'static str {
        match self {
            Self::AuditChain => "audit-chain",
            Self::AuditLossWindows => "audit-loss-windows",
            Self::WormArchive => "worm-archive",
            Self::MetadataCoverage => "metadata-coverage",
            Self::AppliedWithNoAuditEvent => "applied-with-no-audit-event",
            Self::AuditedActionNotInMetadata => "audited-action-not-in-metadata",
            Self::SignatureVerification => "signature-verification",
            Self::TwoPersonRule => "two-person-rule",
            Self::BypassListing => "bypass-listing",
            Self::ApproverSetChange => "approver-set-change",
            Self::GatedOperationWithoutApproval => "gated-operation-without-approval",
        }
    }
}

/// One thing the auditor must look at. Any finding flips the exit code to 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The check that raised this finding.
    pub check: CheckId,
    /// Short title, e.g. `Applied with no audit event`.
    pub title: String,
    /// Full detail, including both sides' offsets where applicable.
    pub detail: String,
    /// Audit offset cited, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_offset: Option<i64>,
    /// Metadata offset cited, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_offset: Option<i64>,
    /// Event time in epoch millis, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<i64>,
}

impl Finding {
    /// Build a finding with no citations; use the `with_*` helpers to add them.
    #[must_use]
    pub fn new(check: CheckId, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            check,
            title: title.into(),
            detail: detail.into(),
            audit_offset: None,
            metadata_offset: None,
            time_ms: None,
        }
    }

    /// Cite an audit offset.
    #[must_use]
    pub const fn with_audit_offset(mut self, offset: i64) -> Self {
        self.audit_offset = Some(offset);
        self
    }

    /// Cite a metadata offset.
    #[must_use]
    pub const fn with_metadata_offset(mut self, offset: i64) -> Self {
        self.metadata_offset = Some(offset);
        self
    }

    /// Cite an event time.
    #[must_use]
    pub const fn with_time_ms(mut self, time_ms: i64) -> Self {
        self.time_ms = Some(time_ms);
        self
    }
}

/// Informational record: in the report, but not a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// The check this note belongs to.
    pub check: CheckId,
    /// Human-readable text.
    pub detail: String,
}

impl Note {
    /// Build a note.
    #[must_use]
    pub fn new(check: CheckId, detail: impl Into<String>) -> Self {
        Self {
            check,
            detail: detail.into(),
        }
    }
}

/// Outcome of one check for the report's summary table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    /// The check ran and found nothing.
    Pass,
    /// The check ran and raised findings.
    Finding,
    /// The check could not run (missing keys, missing history).
    NotChecked,
}
