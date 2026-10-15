//! The unified timeline: one row per privileged happening.
//!
//! Step 2 turns each ledger into rows of `(time, action, target,
//! proposal_id, principal, source)` from audit `PrivilegedAction` events,
//! metadata freeze/break-glass records, and gated `AdminOperation` events.
//! The cross-checks join on these rows; the report prints them.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    audit::{AdminRow, AuditLedger, ParsedAuditEvent, PrivilegedRow},
    error::EvidenceError,
    metadata::{MetadataLedger, RelevantRecord},
};

/// The `--from` / `--to` window as epoch millis, half-open `[from_ms, to_ms)`.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// Inclusive lower bound.
    pub from_ms: i64,
    /// Exclusive upper bound.
    pub to_ms: i64,
}

impl Window {
    /// Whether `time_ms` falls inside the window.
    #[must_use]
    pub const fn contains(self, time_ms: i64) -> bool {
        time_ms >= self.from_ms && time_ms < self.to_ms
    }
}

/// Parse the `--from` / `--to` flags.
///
/// Each accepts `YYYY-MM-DD` (UTC midnight), RFC 3339, or epoch millis.
/// Both default to unbounded.
///
/// ```
/// use krabka_evidence::timeline::parse_window;
///
/// let window = parse_window(Some("2026-09-01"), Some("2026-10-01")).unwrap();
/// assert!(window.from_ms < window.to_ms);
/// assert!(window.contains(window.from_ms));
/// assert!(!window.contains(window.to_ms));
///
/// let millis = parse_window(Some("1789430400000"), None).unwrap();
/// assert_eq!(millis.from_ms, 1_789_430_400_000);
/// assert!(parse_window(Some("not-a-date"), None).is_err());
/// ```
///
/// # Errors
///
/// Returns [`EvidenceError::BadWindow`] when a value does not parse or
/// `--from` is after `--to`.
pub fn parse_window(from: Option<&str>, to: Option<&str>) -> Result<Window, EvidenceError> {
    let from_ms = match from {
        Some(text) => parse_time(text)?,
        None => i64::MIN,
    };
    let to_ms = match to {
        Some(text) => parse_time(text)?,
        None => i64::MAX,
    };
    if from_ms > to_ms {
        return Err(EvidenceError::BadWindow {
            reason: "--from is after --to".to_string(),
        });
    }
    Ok(Window { from_ms, to_ms })
}

/// Parse one time flag value: `YYYY-MM-DD`, RFC 3339, or epoch millis.
///
/// Surrounding whitespace is ignored, and millis may carry a leading sign
/// (negative values are pre-1970 instants).
fn parse_time(text: &str) -> Result<i64, EvidenceError> {
    let text = text.trim();
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        let midnight = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| EvidenceError::BadWindow {
                reason: format!("bad date {text:?}"),
            })?;
        return Ok(midnight.and_utc().timestamp_millis());
    }
    if let Ok(moment) = text.parse::<DateTime<Utc>>() {
        return Ok(moment.timestamp_millis());
    }
    let digits = text.strip_prefix('+').unwrap_or(text);
    let digits = digits.strip_prefix('-').unwrap_or(digits);
    if !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(millis) = text.parse::<i64>()
    {
        return Ok(millis);
    }
    Err(EvidenceError::BadWindow {
        reason: format!("{text:?} is neither YYYY-MM-DD, RFC 3339, nor epoch millis"),
    })
}

/// Truncate a timeline to `max` rows, reporting whether rows were dropped.
///
/// The earliest rows are kept: an auditor reading a truncated timeline sees
/// the window's start, and the report says the tail is missing.
#[must_use]
pub fn truncate_timeline(rows: Vec<TimelineRow>, max: usize) -> (Vec<TimelineRow>, bool) {
    if rows.len() > max {
        (rows.into_iter().take(max).collect(), true)
    } else {
        (rows, false)
    }
}

/// One timeline row for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRow {
    /// Event time in epoch millis.
    pub time_ms: i64,
    /// Event time as RFC 3339.
    pub time: String,
    /// Action name.
    pub action: String,
    /// What the action applies to.
    pub target: String,
    /// Proposal id, empty when none.
    pub proposal_id: String,
    /// The principal that acted.
    pub principal: String,
    /// Where the row came from, e.g. `audit offset 12`.
    pub source: String,
}

/// Build the unified timeline from both ledgers, sorted by `(time, source)`.
#[must_use]
pub fn build_timeline(audit: &AuditLedger, metadata: &MetadataLedger) -> Vec<TimelineRow> {
    let mut rows = Vec::new();
    for row in &audit.rows {
        match &row.event {
            ParsedAuditEvent::Privileged(event) => {
                rows.push(privileged_timeline_row(row.offset, row.time_ms, event));
            }
            ParsedAuditEvent::Admin(event) => {
                if is_gated_operation(&event.operation) {
                    rows.push(admin_timeline_row(row.offset, row.time_ms, event));
                }
            }
            ParsedAuditEvent::Checkpoint { .. }
            | ParsedAuditEvent::RecordsLost { .. }
            | ParsedAuditEvent::Other { .. } => {}
        }
    }
    for row in &metadata.rows {
        match &row.record {
            RelevantRecord::Freeze(entry) => rows.push(TimelineRow {
                time_ms: entry.set_at_ms,
                time: format_time(entry.set_at_ms),
                action: if entry.frozen {
                    "set_topic_freeze".to_string()
                } else {
                    "thaw_topic_freeze".to_string()
                },
                target: freeze_target_name(&entry.scope, entry.pattern_type),
                proposal_id: normalize_proposal_id(&entry.proposal_id.to_string()),
                principal: entry.set_by.clone(),
                source: format!("metadata offset {} ({})", row.offset, row.source),
            }),
            RelevantRecord::Proposal(proposal) => rows.push(TimelineRow {
                time_ms: proposal.consumed_at_ms.max(proposal.created_at_ms),
                time: format_time(proposal.consumed_at_ms.max(proposal.created_at_ms)),
                action: action_name(proposal.action),
                target: proposal.target.clone(),
                proposal_id: normalize_proposal_id(&proposal.proposal_id.to_string()),
                principal: proposal.proposer.clone(),
                source: format!("metadata offset {} ({})", row.offset, row.source),
            }),
            RelevantRecord::DeleteProposal(_) => {}
        }
    }
    rows.sort_by(|a, b| (a.time_ms, &a.source).cmp(&(b.time_ms, &b.source)));
    rows
}

/// Whether an admin operation name is a gated one.
///
/// The conservative set from the PRD: topic and record deletion, in either
/// singular or plural spelling.
#[must_use]
pub fn is_gated_operation(operation: &str) -> bool {
    let folded = folded_operation(operation);
    folded.contains("deletetopic") || folded.contains("deleterecord")
}

/// Map a gated admin operation to the break-glass action that authorizes it.
#[must_use]
pub fn gated_action(operation: &str) -> Option<krabka_metadata::BreakGlassAction> {
    use krabka_metadata::BreakGlassAction::{DeleteRecords, DeleteTopic};
    let folded = folded_operation(operation);
    if folded.contains("deletetopic") {
        Some(DeleteTopic)
    } else if folded.contains("deleterecord") {
        Some(DeleteRecords)
    } else {
        None
    }
}

/// Lowercase an operation name to alphanumerics for stem matching.
fn folded_operation(operation: &str) -> String {
    operation
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The broker's one spelling of a break-glass action.
///
/// This mirrors `krabka_broker::break_glass::action_name`, which is
/// `pub(crate)`; the table is asserted against declaration order in tests.
#[must_use]
pub fn action_name(action: krabka_metadata::BreakGlassAction) -> String {
    use krabka_metadata::BreakGlassAction::{
        CancelReassignment, DeleteRecords, DeleteTopic, ThawTopicFreeze, UncleanElectLeaders,
        UncleanRecovery, UnregisterBroker,
    };
    match action {
        ThawTopicFreeze => "thaw_topic_freeze",
        UncleanElectLeaders => "unclean_elect_leaders",
        UncleanRecovery => "unclean_recovery",
        UnregisterBroker => "unregister_broker",
        CancelReassignment => "cancel_reassignment",
        DeleteTopic => "delete_topic",
        DeleteRecords => "delete_records",
    }
    .to_string()
}

/// The wire value of a break-glass action, in declaration order from 1.
///
/// This mirrors `krabka_broker::break_glass::action_to_wire`, which is
/// `pub(crate)`; zero names no action.
#[must_use]
pub const fn action_wire_value(action: krabka_metadata::BreakGlassAction) -> i8 {
    use krabka_metadata::BreakGlassAction::{
        CancelReassignment, DeleteRecords, DeleteTopic, ThawTopicFreeze, UncleanElectLeaders,
        UncleanRecovery, UnregisterBroker,
    };
    match action {
        ThawTopicFreeze => 1,
        UncleanElectLeaders => 2,
        UncleanRecovery => 3,
        UnregisterBroker => 4,
        CancelReassignment => 5,
        DeleteTopic => 6,
        DeleteRecords => 7,
    }
}

/// Normalize a proposal id for joins: lowercase, with nil UUIDs as empty.
///
/// Freeze audit events carry the nil UUID string where the event model says
/// "empty when the action needed no proposal"; both spellings join.
///
/// ```
/// use krabka_evidence::timeline::normalize_proposal_id;
///
/// assert_eq!(normalize_proposal_id(""), "");
/// assert_eq!(
///     normalize_proposal_id("00000000-0000-0000-0000-000000000000"),
///     ""
/// );
/// assert_eq!(
///     normalize_proposal_id("  22222222-2222-2222-2222-222222222222  "),
///     "22222222-2222-2222-2222-222222222222"
/// );
/// ```
#[must_use]
pub fn normalize_proposal_id(raw: &str) -> String {
    let folded = raw.trim().to_ascii_lowercase();
    if folded.is_empty() || folded == "00000000-0000-0000-0000-000000000000" {
        String::new()
    } else {
        folded
    }
}

/// The `"<pattern>:<scope>"` target the broker builds for freeze scopes.
///
/// ```
/// use krabka_evidence::timeline::freeze_target_name;
/// use krabka_metadata::PatternType;
///
/// assert_eq!(
///     freeze_target_name("orders", PatternType::Literal),
///     "literal:orders"
/// );
/// assert_eq!(
///     freeze_target_name("pay", PatternType::Prefixed),
///     "prefixed:pay"
/// );
/// ```
#[must_use]
pub fn freeze_target_name(scope: &str, pattern: krabka_metadata::PatternType) -> String {
    format!("{}:{scope}", pattern_name(pattern))
}

/// The broker's pattern spelling: `literal` or `prefixed`.
#[must_use]
pub const fn pattern_name(pattern: krabka_metadata::PatternType) -> &'static str {
    match pattern {
        krabka_metadata::PatternType::Literal => "literal",
        krabka_metadata::PatternType::Prefixed => "prefixed",
    }
}

/// Format epoch millis as RFC 3339, or the raw number when out of range.
///
/// ```
/// use krabka_evidence::timeline::format_time;
///
/// assert_eq!(format_time(1_789_430_400_000), "2026-09-15T00:00:00.000Z");
/// ```
#[must_use]
pub fn format_time(time_ms: i64) -> String {
    DateTime::from_timestamp_millis(time_ms).map_or_else(
        || time_ms.to_string(),
        |moment| moment.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

/// One timeline row for a privileged audit event.
fn privileged_timeline_row(offset: i64, time_ms: i64, event: &PrivilegedRow) -> TimelineRow {
    TimelineRow {
        time_ms,
        time: format_time(time_ms),
        action: format!("{}.{}", event.action, event.phase),
        target: event.target.clone(),
        proposal_id: normalize_proposal_id(&event.proposal_id),
        principal: event.principal.clone(),
        source: format!("audit offset {offset}"),
    }
}

/// One timeline row for a gated admin operation.
fn admin_timeline_row(offset: i64, time_ms: i64, event: &AdminRow) -> TimelineRow {
    let target = event
        .resources
        .iter()
        .map(|(_, name)| name.clone())
        .collect::<Vec<_>>()
        .join(",");
    TimelineRow {
        time_ms,
        time: format_time(time_ms),
        action: event.operation.clone(),
        target,
        proposal_id: String::new(),
        principal: event.principal.clone(),
        source: format!("audit offset {offset}"),
    }
}
