# Threat model

What `krabka-evidence` proves, what it assumes, and where an attacker can
still hide. Read this before trusting a pack.

## What the tool proves

Given a set of ledger copies and a set of trust roots, a clean pack
proves, for the requested window:

1. **Each copy is internally intact.** The audit hash chain recomputes and
   its checkpoints verify; the WORM manifest chain recomputes, its
   signatures verify, and its object digests match; the metadata frames
   decode.
2. **The acts went through the controls.** Every freeze and every consumed
   proposal has corroborating audit evidence; every gated deletion had a
   prior break-glass consumption; approvals satisfy the two-person rule;
   nothing ran `bypassed` or audit-only without being listed.
3. **Nobody forged operator intent.** Every operator signature re-verifies
   against the provisioned keys, over preimages built by the broker's own
   functions.
4. **The pack itself is intact.** `verify` re-checks the auditor signature
   over the canonical report and cross-checks `input-files.json` against
   the digests in `report.json`, so neither file can be swapped silently.

The fixture scenarios pin the adversarial cases: `flipped-sig` (an
attacker who rewrote the audit chain but could not forge the operator
signature), `corrupt-chain` (a broken checkpoint signature),
`worm-tamper` (a rewritten manifest link), `approver-change` (a drifted
approver set), `missing-audit` (a deleted tail segment).

## Trust roots (assumed, not proven)

- **The keys file.** Nothing authenticates it — no checksum, no
  signature. Whoever controls `keys.toml` and its `*.pub` files controls
  what "verified" means. Distribute it out of band and protect it like a
  root CA bundle.
- **The auditor key.** `verify` trusts the key embedded in the pack
  unless `--auditor-public-key` pins the expected one. Always pin across
  trust boundaries. A compromised auditor key can sign arbitrary packs;
  rotation is a re-run, not a revocation list.
- **The copies.** The tool checks the bytes it is given. Tampering that
  happened *before* the copy (on the broker, in transit to the copy) is
  out of scope by construction — the digests bind the pack to the copies,
  not to the live cluster.
- **The window.** Findings only fire inside `--from`/`--to`. A clean pack
  for September says nothing about August; check `report.json`'s `window`
  before citing a pack.

## Known blind spots (disclosed in-report, not silent)

- **Snapshot-compacted history.** Snapshots hold state, not events. Acts
  that happened before a snapshot's end offset are invisible; the report
  carries a *metadata history not available* finding or a backup-snapshot
  note, and approve events for compacted-away proposals only fire inside
  the window.
- **Unanchored tails.** Records past the last signed checkpoint are noted
  but not findings; a partition with data and *zero* checkpoints is a
  finding (*no signed anchor*).
- **Unsigned records.** Signatures the broker never collected (or that
  predate signing) are counted as attested-only notes. The broker's word
  is all that stands behind them.
- **Missing keys.** Checks without keys grade `not-checked`, never pass.
  `--require-all-checked` turns that into a failure for CI gates.

## Out of scope

- **Live cluster state and broker config.** Quorum health, `failure_mode`,
  `background_unclean_recovery`, ACLs, and anything outside the three
  ledgers are not read. The report lists what was checked; do not cite it
  for what it did not read.
- **Availability and freshness.** The tool cannot tell a stale copy from a
  fresh one, or a partial copy from a complete one, except where offsets
  betray it (coverage floors, truncation notes, offset gaps).
- **Key management.** Rotation, revocation, HSM storage, and principal
  onboarding/offboarding live wherever the operator keeps them; the tool
  consumes the resulting files.
- **Transport.** S3 reads rely on the ambient AWS chain and TLS (or
  `--allow-http` for test endpoints, which is exactly as unsafe as it
  sounds).

## Residual risks, ranked

1. A substituted keys file silently redefines "verified." (Mitigation:
   out-of-band distribution; the report records key *counts*, not key
   identities — compare those against expectation.)
2. A compromised or unpinned auditor key yields packs that verify but
   lie. (Mitigation: `--auditor-public-key`; offline auditor keys.)
3. Pre-copy tampering on a live system. (Mitigation: copy from quorum
   reads; cross-check digests across independent copies.)
4. Window-scoped blindness: findings outside `--from`/`--to` never fire.
   (Mitigation: bounded, overlapping audit windows; the pack records its
   window.)
