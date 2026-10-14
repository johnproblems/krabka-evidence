# The eleven checks

Every run grades the same eleven checks. A check with findings grades
`finding`; a check named only by notes containing `NOT CHECKED` grades
`not-checked`; anything else grades `pass`. Any finding flips the exit code
to 1. (`--only` restricts the run; `--require-all-checked` fails it when any
check ends `not-checked`. List them with `--list-checks`.)

## `audit-chain` — Audit hash chain and checkpoints

Runs `krabka-audit`'s `verify_partition_dir` unchanged over the copied
partition, then re-walks the same `*.log` segments with the same framing to
decode the rows the cross-checks read.

Findings:

- **Audit hash chain broken** — the first break, cited by audit offset:
  a `seq`/`prev_hash` mismatch, an undecodable record, a malformed
  checkpoint, a checkpoint signature that does not verify, or a checkpoint
  whose head or `seq_high` disagrees with the recomputed chain.
- **Audit chain has no signed anchor** — the partition holds records but no
  signed checkpoint covers any of them. The hash links check out, but
  nothing binds them to a key.

Notes: checkpoint signatures `NOT CHECKED` when no audit key is configured
(the data-record hash links are still re-verified without keys);
unanchored-tail counts; segment truncation points
(`ends mid-batch at byte N`).

## `audit-loss-windows` — Declared audit loss windows

Copies the verifier's declared fail-open loss windows into findings, joined
with the decoded rows for their loss generations.

Findings:

- **Audit declared records lost** — offset, record count, and loss
  generation. Markers past the point where the verifier stopped are found
  from the decoded rows instead, and the finding says so
  (`the verifier stopped before it`).

## `worm-archive` — WORM archive integrity

Runs `krabka-remote-storage`'s `verify_archive` unchanged (shallow by
default, `--deep` recomputes every object digest) and grades the report the
way `krabka-worm-verify` does. The walk stops at the first break per
partition, so one finding names the first tamper.

Findings:

- **WORM archive tamper detected** — manifest key, chain position, and the
  verifier's reason (bad link, bad signature, digest mismatch).
- **WORM head mismatch** — only with `--expect-head`: every partition tip
  must equal the expected head. A mismatch is its own outcome: the chain
  held is internally perfect but stops short, which is never tampering.
- **WORM orphan objects** — only with `--strict-orphans`; otherwise noted.

Notes: manifest signatures `NOT CHECKED` without worm keys (chain positions
and object digests are still verified); empty archives
(`passed vacuously`); epoch restarts unless `--allow-epoch-restarts`;
offset gaps; unsigned/untrusted manifest counts.

## `metadata-coverage` — Metadata history coverage

Grades what history the metadata input actually holds. Snapshots compact
old records away, so a coverage floor — history known to be missing — is a
finding, not silence.

Findings:

- **Metadata history not available** — `before offset N`: a segment dir
  whose lowest base offset is above zero (retention or a partial copy), or
  a `*.checkpoint` snapshot whose end offset floors the history.

Notes: per-snapshot compaction ranges; backup captures
(`restore-inputs/`), whose state is complete but whose compacted history is
invisible; inputs mixing segments and snapshots (offsets may overlap);
tombstone/control/undecodable skip counts; truncation points; timeline
truncation to `--max-timeline-rows`.

## `applied-with-no-audit-event` — Applied with no audit event

Every metadata freeze or consumed break-glass proposal needs a matching
audit event. Corroboration is phase-aware: a freeze needs an `applied`
freeze-path event (an `attempted` alone is the fail-open gap), and a
consumed proposal needs a `consumed` or `applied` event (an approval proves
the approval, not the act). Freeze matching requires target, proposal,
principal/`set_by`, and operator stamp equality.

Findings:

- **Applied with no audit event** — cited by metadata offset and consumed
  time. On the fixture's `missing-audit` scenario this is the consumed
  `DeleteTopic` proposal at metadata offset 3.

## `audited-action-not-in-metadata` — Audited action not in metadata

The reverse direction: every successful in-window audit `applied` event
needs a matching metadata record, or it is forged or replayed. Signed
approve events naming a proposal the metadata log never held are findings
too — but only inside the window, since snapshots compact old proposals
away.

Findings:

- **Audited action not in metadata** — cited by audit offset.
- **Audit event predates proposal** — the event's emit time is before the
  proposal's creation.

## `signature-verification` — Signature verification

Re-verifies every operator signature on both ledgers with `krabka-guard`'s
own preimage functions against the broker's `OperatorKeys`: metadata
freeze records, metadata approvals, audit freeze events (whose preimage
fields are rebuilt from the event alone), and audit approve events (whose
proposal fields come from the metadata log, which is authoritative).

Findings:

- **Signature does not verify** — bad bytes, non-hex audit signatures,
  half-signed records (a key without a signature or vice versa), and
  freeze targets that do not parse as `<pattern>:<scope>`.
- **Unknown key** — the record names a `key_id` outside the trust set.
- **Signature timestamp after emit** — a freeze event's operator stamp is
  after its own broker-emit time.

Notes: operator signatures `NOT CHECKED` without operator keys; freeze
signatures `NOT CHECKED` without `--cluster-id` (the preimage covers it;
approvals are still checked); attested-only counts for records that carry
no signature at all.

## `two-person-rule` — Two-person rule

Grades each proposal's approvals: approvers differ from the proposer and
from each other, approvals land between creation and expiry, and
consumption needs at least two distinct approvals.

Findings (all titled **Two-person rule violated**):

- approval before creation; proposer self-approval; double approval;
  approval after expiry; consumption with fewer than two distinct
  approvals; consumption after expiry; consumption after withdrawal.

## `bypass-listing` — Bypassed controls

Lists what ran outside the controls, with reason text.

Findings:

- **Gated action bypassed approval** — an audit event with phase
  `bypassed`.
- **Unclean recovery ran audit-only** — an audit unclean-recovery event
  with `audit-only` recovery, or a consumed unclean-recovery proposal
  whose reason says `audit-only`.

## `approver-set-change` — Approver set changes

Orders privileged events by `(time_ms, offset)` and reports every change
of `approver_set_fingerprint` within the window.

Findings:

- **Approver set changed** — cited by audit offset, showing
  `before -> after`.

## `gated-operation-without-approval` — Gated operations without approval

A succeeded gated `AdminOperation` (`DeleteTopic`, `DeleteRecords`) needs
a break-glass consumption of the matching action before it. Matching
filters resources by type (`Topic` for topic deletion; `Partition` or
`Topic` for record deletion — anything else on the event is context, not
the target), and a target covers a resource when it names it exactly or
names its topic past a `-` partition separator. Withdrawn proposals
authorize nothing.

Findings:

- **Gated op without approval** — cited by audit offset, with the
  filtered resource list.

Related note (filed under `metadata-coverage`): expiry sweeps removing
proposals the input never held, which retention routinely compacts away.
