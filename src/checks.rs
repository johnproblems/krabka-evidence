//! Step 3: the cross-ledger checks.
//!
//! Each finding cites both sides by offset. Signature preimages are built
//! with `krabka-guard`'s own [`krabka_guard::signing`] functions and verified
//! against the broker's [`krabka_broker::operator_keys::OperatorKeys`], so
//! this tool checks bytes the same way the cluster does.

use std::collections::{BTreeMap, BTreeSet};

use krabka_broker::operator_keys::FreezeSigningInput;
use krabka_guard::signing::{ApprovalSigningInput, approval_signing_bytes, freeze_signing_bytes};
use krabka_metadata::{BreakGlassAction, BreakGlassProposalRecord, TopicFreezeRecord};
use krabka_protocol::krabka::freeze::{PATTERN_TYPE_LITERAL, PATTERN_TYPE_PREFIXED};

use crate::{
    audit::{AuditLedger, AuditRow, ParsedAuditEvent, PrivilegedRow},
    finding::{CheckId, Finding, Note},
    keys::TrustMaterial,
    metadata::{MetadataLedger, RelevantRecord},
    timeline::{
        Window, action_name, action_wire_value, freeze_target_name, gated_action,
        is_gated_operation, normalize_proposal_id,
    },
};

/// Freeze/thaw audit action names from `set_topic_freeze/response.rs`.
const SET_FREEZE_ACTION: &str = "set_topic_freeze";
const THAW_ACTION: &str = "thaw_topic_freeze";

/// Inputs to the cross-checks.
pub struct CheckInputs<'a> {
    /// The decoded audit ledger.
    pub audit: &'a AuditLedger,
    /// The decoded metadata ledger.
    pub metadata: &'a MetadataLedger,
    /// Loaded trust material.
    pub trust: &'a TrustMaterial,
    /// The requested window.
    pub window: &'a Window,
    /// The cluster id, required to verify freeze signatures.
    pub cluster_id: Option<&'a str>,
}

/// Run all seven cross-checks, appending findings and notes.
pub fn run_cross_checks(
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) {
    check_applied_with_no_audit_event(inputs, findings);
    check_audited_action_not_in_metadata(inputs, findings);
    check_signatures(inputs, findings, notes);
    check_two_person_rule(inputs, findings);
    check_bypass_listing(inputs, findings);
    check_approver_set_change(inputs, findings);
    check_gated_operations(inputs, findings, notes);
}

/// Every metadata freeze or break-glass act has an audit `PrivilegedAction`
/// with the same proposal id and target.
///
/// Corroboration is phase-aware: a freeze needs an `applied` freeze-path
/// event (an `attempted` alone is exactly the fail-open gap), and a consumed
/// proposal needs a `consumed` or `applied` event (an approval proves the
/// approval, not the act).
fn check_applied_with_no_audit_event(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>) {
    let window = inputs.window;
    for row in &inputs.metadata.rows {
        match &row.record {
            RelevantRecord::Freeze(entry) => {
                if !window.contains(entry.set_at_ms) {
                    continue;
                }
                let target = freeze_target_name(&entry.scope, entry.pattern_type);
                let proposal = normalize_proposal_id(&entry.proposal_id.to_string());
                let matched = inputs.audit.rows.iter().any(|audit_row| {
                    matches!(&audit_row.event, ParsedAuditEvent::Privileged(event)
                        if is_freeze_path_event(event)
                            && event.target == target
                            && normalize_proposal_id(&event.proposal_id) == proposal
                            && event.principal == entry.set_by
                            && event.signed_at_ms == entry.set_at_ms
                            && event.phase == "applied")
                });
                if !matched {
                    findings.push(
                        Finding::new(
                            CheckId::AppliedWithNoAuditEvent,
                            "Applied with no audit event",
                            format!(
                                "metadata {} at offset {} has no audit PrivilegedAction \
                                 (target {target:?}, proposal {})",
                                if entry.frozen { "freeze" } else { "thaw" },
                                row.offset,
                                display_proposal(&proposal),
                            ),
                        )
                        .with_metadata_offset(row.offset)
                        .with_time_ms(entry.set_at_ms),
                    );
                }
            }
            RelevantRecord::Proposal(proposal) => {
                if proposal.consumed_at_ms == 0 || !window.contains(proposal.consumed_at_ms) {
                    continue;
                }
                let proposal_id = normalize_proposal_id(&proposal.proposal_id.to_string());
                let action = action_name(proposal.action);
                let matched = inputs.audit.rows.iter().any(|audit_row| {
                    matches!(&audit_row.event, ParsedAuditEvent::Privileged(event)
                        if normalize_proposal_id(&event.proposal_id) == proposal_id
                            && event.action == action
                            && event.target == proposal.target
                            && (event.phase == "consumed" || event.phase == "applied"))
                });
                if !matched {
                    findings.push(
                        Finding::new(
                            CheckId::AppliedWithNoAuditEvent,
                            "Applied with no audit event",
                            format!(
                                "consumed break-glass proposal {} ({}, target {:?}) at \
                                 metadata offset {} has no audit event",
                                proposal.proposal_id, action, proposal.target, row.offset,
                            ),
                        )
                        .with_metadata_offset(row.offset)
                        .with_time_ms(proposal.consumed_at_ms),
                    );
                }
            }
            RelevantRecord::DeleteProposal(_) => {}
        }
    }
}

/// Every audit `Applied` event has a matching metadata record.
fn check_audited_action_not_in_metadata(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>) {
    for row in &inputs.audit.rows {
        let ParsedAuditEvent::Privileged(event) = &row.event else {
            continue;
        };
        if event.phase != "applied" || event.outcome != "success" {
            continue;
        }
        if !inputs.window.contains(row.time_ms) {
            continue;
        }
        if is_freeze_path_event(event) {
            let proposal = normalize_proposal_id(&event.proposal_id);
            let matched = inputs.metadata.rows.iter().any(|meta_row| {
                matches!(&meta_row.record, RelevantRecord::Freeze(entry)
                    if freeze_target_name(&entry.scope, entry.pattern_type) == event.target
                        && entry.set_by == event.principal
                        && entry.set_at_ms == event.signed_at_ms
                        && normalize_proposal_id(&entry.proposal_id.to_string()) == proposal)
            });
            if !matched {
                findings.push(
                    Finding::new(
                        CheckId::AuditedActionNotInMetadata,
                        "Audited action not in metadata",
                        format!(
                            "audit {} at offset {} (target {:?}, signed stamp {}) has no \
                             matching metadata freeze record: forged or replayed event",
                            event.action, row.offset, event.target, event.signed_at_ms,
                        ),
                    )
                    .with_audit_offset(row.offset)
                    .with_time_ms(row.time_ms),
                );
            }
            continue;
        }
        let proposal = normalize_proposal_id(&event.proposal_id);
        if proposal.is_empty() {
            continue;
        }
        let stored = inputs
            .metadata
            .rows
            .iter()
            .find_map(|meta_row| match &meta_row.record {
                RelevantRecord::Proposal(stored)
                    if normalize_proposal_id(&stored.proposal_id.to_string()) == proposal
                        && action_name(stored.action) == event.action =>
                {
                    Some(stored)
                }
                _ => None,
            });
        let Some(stored) = stored else {
            findings.push(
                Finding::new(
                    CheckId::AuditedActionNotInMetadata,
                    "Audited action not in metadata",
                    format!(
                        "audit {} {} at offset {} (proposal {}) has no matching metadata \
                         proposal: forged or replayed event",
                        event.action, event.phase, row.offset, proposal,
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
            continue;
        };
        if row.time_ms < stored.created_at_ms {
            findings.push(
                Finding::new(
                    CheckId::AuditedActionNotInMetadata,
                    "Audit event predates proposal",
                    format!(
                        "audit {} {} at offset {} is stamped {} but proposal {} was \
                         created at {}: forged or replayed event",
                        event.action,
                        event.phase,
                        row.offset,
                        row.time_ms,
                        proposal,
                        stored.created_at_ms,
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
        }
    }
}

/// Verify every operator signature on both ledgers.
#[allow(clippy::too_many_lines)]
fn check_signatures(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>, notes: &mut Vec<Note>) {
    if !inputs.trust.has_operators {
        notes.push(Note::new(
            CheckId::SignatureVerification,
            "operator signatures NOT CHECKED: no [[operator_keys]] entries",
        ));
        return;
    }
    if inputs.cluster_id.is_none() {
        notes.push(Note::new(
            CheckId::SignatureVerification,
            "freeze signatures NOT CHECKED: the freeze preimage covers the cluster id, \
             and no --cluster-id was given (approval signatures were still checked)",
        ));
    }

    let mut unsigned_freezes = 0u64;
    let mut unsigned_approvals = 0u64;

    for row in &inputs.metadata.rows {
        match &row.record {
            RelevantRecord::Freeze(entry) => {
                verify_freeze_record(entry, row.offset, inputs, findings, &mut unsigned_freezes);
            }
            RelevantRecord::Proposal(proposal) => {
                verify_proposal_approvals(
                    proposal,
                    row.offset,
                    inputs,
                    findings,
                    &mut unsigned_approvals,
                );
            }
            RelevantRecord::DeleteProposal(_) => {}
        }
    }

    for row in &inputs.audit.rows {
        let ParsedAuditEvent::Privileged(event) = &row.event else {
            continue;
        };
        if event.outcome != "success" || event.phase == "refused" {
            continue;
        }
        if is_freeze_path_event(event) {
            verify_freeze_event(event, row, inputs, findings, &mut unsigned_freezes);
        } else if is_approve_event(event) {
            verify_approve_event(event, row, inputs, findings, &mut unsigned_approvals);
        }
        // Gated-transition events (proposed/consumed/applied on proposals)
        // are unsigned by design: the approvers are named on the proposal's
        // own approve events.
    }

    if unsigned_freezes > 0 {
        notes.push(Note::new(
            CheckId::SignatureVerification,
            format!(
                "{unsigned_freezes} freeze record(s)/event(s) carry no signature \
                 (attested only: the broker's word is all that stands behind them)"
            ),
        ));
    }
    if unsigned_approvals > 0 {
        notes.push(Note::new(
            CheckId::SignatureVerification,
            format!("{unsigned_approvals} approval(s) carry no signature (attested only)"),
        ));
    }
}

/// Verify one metadata freeze record's detached signature.
fn verify_freeze_record(
    entry: &TopicFreezeRecord,
    offset: i64,
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    unsigned: &mut u64,
) {
    if entry.key_id.is_empty() || entry.signature.is_empty() {
        if entry.key_id.is_empty() && entry.signature.is_empty() {
            *unsigned += 1;
        } else {
            findings.push(
                malformed_signature(CheckId::SignatureVerification, "metadata freeze record")
                    .with_metadata_offset(offset)
                    .with_time_ms(entry.set_at_ms),
            );
        }
        return;
    }
    let Some(cluster_id) = inputs.cluster_id else {
        return;
    };
    let pattern_type = pattern_wire(entry.pattern_type);
    let message = freeze_signing_bytes(&FreezeSigningInput {
        cluster_id,
        pattern_type,
        scope: &entry.scope,
        frozen: entry.frozen,
        reason: &entry.reason,
        set_by: &entry.set_by,
        set_at_ms: entry.set_at_ms,
        proposal_id: *entry.proposal_id.as_bytes(),
    });
    grade_signature(
        inputs,
        &entry.key_id,
        &entry.set_by,
        &message,
        &entry.signature,
        "metadata freeze record",
        Some(offset),
        None,
        entry.set_at_ms,
        findings,
    );
}

/// Verify one audit freeze/thaw event's detached signature.
///
/// The event carries every preimage field except the cluster id: the action
/// (`set_topic_freeze` vs `thaw_topic_freeze`) says whether the scope froze,
/// the target parses as `"<pattern>:<scope>"`, and `signed_at_ms` is the
/// operator's stamp. This is the re-verification from the audit topic alone
/// that KFC-9 claims.
fn verify_freeze_event(
    event: &PrivilegedRow,
    row: &AuditRow,
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    unsigned: &mut u64,
) {
    if event.key_id.is_empty() || event.signature_hex.is_empty() {
        if event.key_id.is_empty() && event.signature_hex.is_empty() {
            *unsigned += 1;
        } else {
            findings.push(
                malformed_signature(CheckId::SignatureVerification, "audit freeze event")
                    .with_audit_offset(row.offset)
                    .with_time_ms(row.time_ms),
            );
        }
        return;
    }
    if event.signed_at_ms > row.time_ms {
        findings.push(
            Finding::new(
                CheckId::SignatureVerification,
                "Signature timestamp after emit",
                format!(
                    "audit freeze event at offset {} carries an operator stamp {} after \
                     its own emit time {}: forged or replayed event",
                    row.offset, event.signed_at_ms, row.time_ms,
                ),
            )
            .with_audit_offset(row.offset)
            .with_time_ms(row.time_ms),
        );
    }
    let Some(cluster_id) = inputs.cluster_id else {
        return;
    };
    let (Some(pattern_type), Some(scope)) = parse_freeze_target(&event.target) else {
        findings.push(
            Finding::new(
                CheckId::SignatureVerification,
                "Signature does not verify",
                format!(
                    "audit freeze event at offset {} has target {:?}, which is not \
                     \"<pattern>:<scope>\": the signed bytes cannot be rebuilt",
                    row.offset, event.target,
                ),
            )
            .with_audit_offset(row.offset)
            .with_time_ms(row.time_ms),
        );
        return;
    };
    let proposal_id = parse_proposal_bytes(&event.proposal_id);
    let message = freeze_signing_bytes(&FreezeSigningInput {
        cluster_id,
        pattern_type,
        scope: &scope,
        frozen: event.action == SET_FREEZE_ACTION,
        reason: &event.reason,
        set_by: &event.principal,
        set_at_ms: event.signed_at_ms,
        proposal_id,
    });
    let Ok(signature) = hex::decode(event.signature_hex.trim()) else {
        findings.push(
            Finding::new(
                CheckId::SignatureVerification,
                "Signature does not verify",
                format!(
                    "audit freeze event at offset {} carries a signature that is not hex",
                    row.offset,
                ),
            )
            .with_audit_offset(row.offset)
            .with_time_ms(row.time_ms),
        );
        return;
    };
    grade_signature(
        inputs,
        &event.key_id,
        &event.principal,
        &message,
        &signature,
        "audit freeze event",
        None,
        Some(row.offset),
        row.time_ms,
        findings,
    );
}

/// Verify every approval on one metadata proposal.
fn verify_proposal_approvals(
    proposal: &BreakGlassProposalRecord,
    offset: i64,
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    unsigned: &mut u64,
) {
    for approval in &proposal.approvals {
        if approval.key_id.is_empty() || approval.signature.is_empty() {
            if approval.key_id.is_empty() && approval.signature.is_empty() {
                *unsigned += 1;
            } else {
                findings.push(
                    malformed_signature(CheckId::SignatureVerification, "break-glass approval")
                        .with_metadata_offset(offset)
                        .with_time_ms(approval.approved_at_ms),
                );
            }
            continue;
        }
        let message = approval_message(proposal);
        grade_signature(
            inputs,
            &approval.key_id,
            &approval.principal,
            &message,
            &approval.signature,
            &format!(
                "approval by {} on proposal {}",
                approval.principal, proposal.proposal_id
            ),
            Some(offset),
            None,
            approval.approved_at_ms,
            findings,
        );
    }
}

/// Verify one audit approve event's detached approval signature.
///
/// The proposal fields come from the metadata log, which is authoritative;
/// the event contributes the signer's key and bytes.
fn verify_approve_event(
    event: &PrivilegedRow,
    row: &AuditRow,
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    unsigned: &mut u64,
) {
    if event.key_id.is_empty() || event.signature_hex.is_empty() {
        if event.key_id.is_empty() && event.signature_hex.is_empty() {
            *unsigned += 1;
        } else {
            findings.push(
                malformed_signature(CheckId::SignatureVerification, "audit approve event")
                    .with_audit_offset(row.offset)
                    .with_time_ms(row.time_ms),
            );
        }
        return;
    }
    let proposal_id = normalize_proposal_id(&event.proposal_id);
    let proposal = inputs
        .metadata
        .rows
        .iter()
        .find_map(|meta_row| match &meta_row.record {
            RelevantRecord::Proposal(stored)
                if normalize_proposal_id(&stored.proposal_id.to_string()) == proposal_id =>
            {
                Some(stored)
            }
            _ => None,
        });
    let Some(proposal) = proposal else {
        // An approve event for a proposal the metadata log never held is a
        // forged or replayed event — but only inside the window, since
        // snapshots compact old proposals away.
        if inputs.window.contains(row.time_ms) {
            findings.push(
                Finding::new(
                    CheckId::AuditedActionNotInMetadata,
                    "Audited action not in metadata",
                    format!(
                        "audit approve event at offset {} names proposal {}, which has \
                         no metadata record: forged or replayed event",
                        row.offset, proposal_id,
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
        }
        return;
    };
    let Ok(signature) = hex::decode(event.signature_hex.trim()) else {
        findings.push(
            Finding::new(
                CheckId::SignatureVerification,
                "Signature does not verify",
                format!(
                    "audit approve event at offset {} carries a signature that is not hex",
                    row.offset,
                ),
            )
            .with_audit_offset(row.offset)
            .with_time_ms(row.time_ms),
        );
        return;
    };
    let message = approval_message(proposal);
    grade_signature(
        inputs,
        &event.key_id,
        &event.principal,
        &message,
        &signature,
        "audit approve event",
        None,
        Some(row.offset),
        row.time_ms,
        findings,
    );
}

/// Grade one detached signature: unknown key and bad signature are findings.
#[allow(clippy::too_many_arguments)]
fn grade_signature(
    inputs: &CheckInputs<'_>,
    key_id: &str,
    principal: &str,
    message: &[u8],
    signature: &[u8],
    what: &str,
    metadata_offset: Option<i64>,
    audit_offset: Option<i64>,
    time_ms: i64,
    findings: &mut Vec<Finding>,
) {
    if inputs.trust.operators.get(key_id).is_none() {
        let mut finding = Finding::new(
            CheckId::SignatureVerification,
            "Unknown key",
            format!("{what} names key_id {key_id:?}, which is not in the operator trust set"),
        )
        .with_time_ms(time_ms);
        if let Some(offset) = metadata_offset {
            finding = finding.with_metadata_offset(offset);
        }
        if let Some(offset) = audit_offset {
            finding = finding.with_audit_offset(offset);
        }
        findings.push(finding);
        return;
    }
    if !inputs
        .trust
        .operators
        .verify(key_id, principal, message, signature)
    {
        let mut finding = Finding::new(
            CheckId::SignatureVerification,
            "Signature does not verify",
            format!(
                "{what} signed by key_id {key_id:?} does not verify for principal \
                 {principal:?} over the canonical preimage"
            ),
        )
        .with_time_ms(time_ms);
        if let Some(offset) = metadata_offset {
            finding = finding.with_metadata_offset(offset);
        }
        if let Some(offset) = audit_offset {
            finding = finding.with_audit_offset(offset);
        }
        findings.push(finding);
    }
}

/// A half-signed record: a key with no signature or a signature with no key.
fn malformed_signature(check: CheckId, what: &str) -> Finding {
    Finding::new(
        check,
        "Signature does not verify",
        format!("{what} carries a key id without a signature, or a signature without a key id"),
    )
}

/// Build the canonical approval bytes for a proposal with guard's function.
fn approval_message(proposal: &BreakGlassProposalRecord) -> Vec<u8> {
    approval_signing_bytes(&ApprovalSigningInput {
        proposal_id: *proposal.proposal_id.as_bytes(),
        action: action_wire_value(proposal.action),
        target: &proposal.target,
        proposer: &proposal.proposer,
        created_at_ms: proposal.created_at_ms,
        expires_at_ms: proposal.expires_at_ms,
    })
}

/// Approvers are distinct from the proposer, and approval comes before the
/// proposal expires.
fn check_two_person_rule(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>) {
    for row in &inputs.metadata.rows {
        let RelevantRecord::Proposal(proposal) = &row.record else {
            continue;
        };
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for approval in &proposal.approvals {
            check_approval_timing(proposal, approval, row.offset, &mut seen, findings);
        }
        check_consumption(proposal, row.offset, seen.len(), findings);
    }
}

/// Grade one approval: timing, self-approval, and duplicates.
fn check_approval_timing<'a>(
    proposal: &BreakGlassProposalRecord,
    approval: &'a krabka_metadata::BreakGlassApproval,
    offset: i64,
    seen: &mut BTreeSet<&'a str>,
    findings: &mut Vec<Finding>,
) {
    if approval.approved_at_ms < proposal.created_at_ms {
        findings.push(two_person(
            &format!(
                "{} approved proposal {} at {} before it was created at {} \
                 (metadata offset {offset})",
                approval.principal,
                proposal.proposal_id,
                approval.approved_at_ms,
                proposal.created_at_ms,
            ),
            offset,
            approval.approved_at_ms,
        ));
    }
    if approval.principal == proposal.proposer {
        findings.push(two_person(
            &format!(
                "proposer {} approved their own proposal {} at metadata offset {offset}",
                proposal.proposer, proposal.proposal_id,
            ),
            offset,
            approval.approved_at_ms,
        ));
    }
    if !seen.insert(approval.principal.as_str()) {
        findings.push(two_person(
            &format!(
                "{} approved proposal {} twice (metadata offset {offset})",
                approval.principal, proposal.proposal_id,
            ),
            offset,
            approval.approved_at_ms,
        ));
    }
    if approval.approved_at_ms > proposal.expires_at_ms {
        findings.push(two_person(
            &format!(
                "{} approved proposal {} at {} after it expired at {} \
                 (metadata offset {offset})",
                approval.principal,
                proposal.proposal_id,
                approval.approved_at_ms,
                proposal.expires_at_ms,
            ),
            offset,
            approval.approved_at_ms,
        ));
    }
}

/// Grade a consumed proposal: quorum, expiry, and withdrawal.
fn check_consumption(
    proposal: &BreakGlassProposalRecord,
    offset: i64,
    approvals: usize,
    findings: &mut Vec<Finding>,
) {
    if proposal.consumed_at_ms <= 0 {
        return;
    }
    if approvals < 2 {
        findings.push(two_person(
            &format!(
                "proposal {} was consumed with {approvals} distinct approval(s); the \
                 two-person rule needs two (metadata offset {offset})",
                proposal.proposal_id,
            ),
            offset,
            proposal.consumed_at_ms,
        ));
    }
    if proposal.consumed_at_ms > proposal.expires_at_ms {
        findings.push(two_person(
            &format!(
                "proposal {} was consumed at {} after it expired at {} \
                 (metadata offset {offset})",
                proposal.proposal_id, proposal.consumed_at_ms, proposal.expires_at_ms,
            ),
            offset,
            proposal.consumed_at_ms,
        ));
    }
    if proposal.withdrawn {
        findings.push(two_person(
            &format!(
                "proposal {} was consumed after being withdrawn (metadata offset {offset})",
                proposal.proposal_id,
            ),
            offset,
            proposal.consumed_at_ms,
        ));
    }
}

/// Build a two-person-rule finding with the standard citations.
fn two_person(detail: &str, offset: i64, time_ms: i64) -> Finding {
    Finding::new(
        CheckId::TwoPersonRule,
        "Two-person rule violated",
        detail.to_string(),
    )
    .with_metadata_offset(offset)
    .with_time_ms(time_ms)
}

/// List every `Bypassed` phase and every audit-only unclean recovery, with
/// the reason text.
fn check_bypass_listing(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>) {
    for row in &inputs.audit.rows {
        let ParsedAuditEvent::Privileged(event) = &row.event else {
            continue;
        };
        if !inputs.window.contains(row.time_ms) {
            continue;
        }
        if event.phase.eq_ignore_ascii_case("bypassed") {
            findings.push(
                Finding::new(
                    CheckId::BypassListing,
                    "Gated action bypassed approval",
                    format!(
                        "audit {} at offset {} ran BYPASSED without an approval: {}",
                        event.action, row.offset, event.reason,
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
        }
        let action = event.action.to_ascii_lowercase();
        let reason = event.reason.to_ascii_lowercase();
        if action.contains("unclean") && reason.contains("audit-only") {
            findings.push(
                Finding::new(
                    CheckId::BypassListing,
                    "Unclean recovery ran audit-only",
                    format!(
                        "audit {} at offset {} ran with background_unclean_recovery=audit-only: {}",
                        event.action, row.offset, event.reason,
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
        }
    }
    for row in &inputs.metadata.rows {
        let RelevantRecord::Proposal(proposal) = &row.record else {
            continue;
        };
        if proposal.action == BreakGlassAction::UncleanRecovery
            && proposal.consumed_at_ms > 0
            && inputs.window.contains(proposal.consumed_at_ms)
            && proposal.reason.to_ascii_lowercase().contains("audit-only")
        {
            findings.push(
                Finding::new(
                    CheckId::BypassListing,
                    "Unclean recovery ran audit-only",
                    format!(
                        "unclean-recovery proposal {} consumed at metadata offset {} \
                         with audit-only recovery: {}",
                        proposal.proposal_id, row.offset, proposal.reason,
                    ),
                )
                .with_metadata_offset(row.offset)
                .with_time_ms(proposal.consumed_at_ms),
            );
        }
    }
}

/// Report when `approver_set_fingerprint` changes within the window.
fn check_approver_set_change(inputs: &CheckInputs<'_>, findings: &mut Vec<Finding>) {
    let mut ordered: Vec<(&AuditRow, &PrivilegedRow)> = inputs
        .audit
        .rows
        .iter()
        .filter_map(|row| match &row.event {
            ParsedAuditEvent::Privileged(event)
                if inputs.window.contains(row.time_ms)
                    && !event.approver_set_fingerprint.is_empty() =>
            {
                Some((row, event.as_ref()))
            }
            _ => None,
        })
        .collect();
    ordered.sort_by_key(|(row, _)| (row.time_ms, row.offset));
    let mut changes: Vec<(String, String, i64, i64)> = Vec::new();
    let mut current: Option<&str> = None;
    for (row, event) in ordered {
        match current {
            None => current = Some(event.approver_set_fingerprint.as_str()),
            Some(fingerprint) if fingerprint == event.approver_set_fingerprint => {}
            Some(before) => {
                changes.push((
                    before.to_string(),
                    event.approver_set_fingerprint.clone(),
                    row.offset,
                    row.time_ms,
                ));
                current = Some(event.approver_set_fingerprint.as_str());
            }
        }
    }
    for (before, after, offset, time_ms) in changes {
        findings.push(
            Finding::new(
                CheckId::ApproverSetChange,
                "Approver set changed",
                format!(
                    "approver_set_fingerprint changed mid-window at audit offset {offset}: \
                     {before} -> {after}"
                ),
            )
            .with_audit_offset(offset)
            .with_time_ms(time_ms),
        );
    }
}

/// A gated `AdminOperation` that succeeded must have a break-glass
/// `Consumed` before it.
fn check_gated_operations(
    inputs: &CheckInputs<'_>,
    findings: &mut Vec<Finding>,
    notes: &mut Vec<Note>,
) {
    // Latest consumed state per proposal id.
    let mut consumed: BTreeMap<String, &BreakGlassProposalRecord> = BTreeMap::new();
    for row in &inputs.metadata.rows {
        if let RelevantRecord::Proposal(proposal) = &row.record
            && proposal.consumed_at_ms > 0
            && !proposal.withdrawn
        {
            consumed.insert(
                normalize_proposal_id(&proposal.proposal_id.to_string()),
                proposal,
            );
        }
    }
    for row in &inputs.audit.rows {
        let ParsedAuditEvent::Admin(event) = &row.event else {
            continue;
        };
        if event.outcome != "success" || !is_gated_operation(&event.operation) {
            continue;
        }
        if !inputs.window.contains(row.time_ms) {
            continue;
        }
        let Some(wanted) = gated_action(&event.operation) else {
            continue;
        };
        let names: Vec<&str> = event
            .resources
            .iter()
            .filter(|(resource_type, _)| gated_resource_type(wanted, resource_type))
            .map(|(_, name)| name.as_str())
            .collect();
        let covered = consumed.values().any(|proposal| {
            proposal.action == wanted
                && proposal.consumed_at_ms <= row.time_ms
                && names.iter().any(|name| proposal_covers(proposal, name))
        });
        if !covered {
            findings.push(
                Finding::new(
                    CheckId::GatedOperationWithoutApproval,
                    "Gated op without approval",
                    format!(
                        "gated {} at audit offset {} succeeded with no break-glass \
                         consumption before it (resources: {})",
                        event.operation,
                        row.offset,
                        names.join(","),
                    ),
                )
                .with_audit_offset(row.offset)
                .with_time_ms(row.time_ms),
            );
        }
    }
    note_unknown_deletes(inputs, notes);
}

/// Whether a resource type can carry a gated operation's target.
///
/// `DeleteTopic` names `Topic` resources; `DeleteRecords` names `Partition`
/// resources (`topic-partition`) and, for whole-topic trims, `Topic` ones.
/// Anything else on the event is context, not the target.
fn gated_resource_type(action: BreakGlassAction, resource_type: &str) -> bool {
    match action {
        BreakGlassAction::DeleteTopic => resource_type == "Topic",
        BreakGlassAction::DeleteRecords => resource_type == "Partition" || resource_type == "Topic",
        _ => false,
    }
}

/// Note expiry-sweep deletions of proposals the input never held.
///
/// Sweeps routinely remove proposals that retention already compacted away,
/// so an unknown id is a note, not a finding — but the auditor should see
/// it.
fn note_unknown_deletes(inputs: &CheckInputs<'_>, notes: &mut Vec<Note>) {
    let known: BTreeSet<String> = inputs
        .metadata
        .rows
        .iter()
        .filter_map(|row| match &row.record {
            RelevantRecord::Proposal(proposal) => {
                Some(normalize_proposal_id(&proposal.proposal_id.to_string()))
            }
            _ => None,
        })
        .collect();
    for row in &inputs.metadata.rows {
        if let RelevantRecord::DeleteProposal(id) = &row.record
            && !known.contains(normalize_proposal_id(&id.to_string()).as_str())
        {
            notes.push(Note::new(
                CheckId::MetadataCoverage,
                format!(
                    "expiry sweep at metadata offset {} removed proposal {}, which has \
                     no record in this input (compacted away or never present)",
                    row.offset, id,
                ),
            ));
        }
    }
}

/// Whether a proposal's target authorizes an operation on `resource`.
///
/// Targets name a topic, a `topic-partition` pair, a freeze scope, or a
/// broker id; a target covers the resource when it names it exactly, or when
/// the resource extends the target past a `-` partition separator.
fn proposal_covers(proposal: &BreakGlassProposalRecord, resource: &str) -> bool {
    if proposal.target == resource {
        return true;
    }
    resource
        .rsplit_once('-')
        .is_some_and(|(topic, _)| proposal.target == topic)
}

/// Whether an audit event is on the freeze path.
///
/// `set_topic_freeze` is only ever a freeze event, but `thaw_topic_freeze`
/// is both the freeze path's thaw action and the break-glass action name, so
/// the action alone does not route a thaw. The freeze path always carries
/// the record's `set_at_ms` as its signed stamp (signed or not), while
/// proposal-path events carry the zero `NO_SIGNED_STAMP`. The last arm
/// future-proofs the routing: any privileged event with a nonzero stamp,
/// no proposal, and no counterparties is freeze-shaped whatever its action
/// string says.
fn is_freeze_path_event(event: &PrivilegedRow) -> bool {
    event.action == SET_FREEZE_ACTION
        || (event.action == THAW_ACTION && event.signed_at_ms != 0)
        || (event.signed_at_ms != 0
            && normalize_proposal_id(&event.proposal_id).is_empty()
            && event.counterparties.is_empty())
}

/// Whether an audit event is a signed approve event.
///
/// Approve events carry the approval's key and signature with the approver
/// as actor; transition events (proposed/consumed/applied) are unsigned by
/// design and name no counterparty by themselves.
fn is_approve_event(event: &PrivilegedRow) -> bool {
    !is_freeze_path_event(event)
        && !event.proposal_id.is_empty()
        && (!event.key_id.is_empty()
            || !event.signature_hex.is_empty()
            || !event.counterparties.is_empty())
}

/// Render a normalized proposal id, spelling the empty one.
fn display_proposal(proposal: &str) -> String {
    if proposal.is_empty() {
        "(none)".to_string()
    } else {
        proposal.to_string()
    }
}

/// Map a metadata pattern type to its wire value.
const fn pattern_wire(pattern: krabka_metadata::PatternType) -> i8 {
    match pattern {
        krabka_metadata::PatternType::Literal => PATTERN_TYPE_LITERAL,
        krabka_metadata::PatternType::Prefixed => PATTERN_TYPE_PREFIXED,
    }
}

/// Parse a `"<pattern>:<scope>"` freeze target.
fn parse_freeze_target(target: &str) -> (Option<i8>, Option<String>) {
    let (pattern, scope) = target.split_once(':').unwrap_or(("", target));
    let wire = match pattern {
        "literal" => Some(PATTERN_TYPE_LITERAL),
        "prefixed" => Some(PATTERN_TYPE_PREFIXED),
        _ => None,
    };
    (wire, Some(scope.to_string()))
}

/// Parse a proposal id into the 16 bytes the preimages cover.
///
/// Empty and nil spellings become the nil UUID, matching unsigned freezes.
fn parse_proposal_bytes(raw: &str) -> [u8; 16] {
    normalize_proposal_id(raw)
        .parse::<uuid::Uuid>()
        .map_or([0u8; 16], |id| *id.as_bytes())
}
