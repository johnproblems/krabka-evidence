# Changelog

All notable changes to `krabka-evidence`. Versions are `0.x` until the
pack format (`FORMAT.md`) stabilizes.

## [Unreleased]

### Added

- Eleven checks with stable kebab-case ids (`--list-checks`), each one
  row in the report's check table (`docs/CHECKS.md`).
- Phase-aware corroboration: freezes need `applied` freeze-path events,
  consumed proposals need `consumed`/`applied` events.
- Generalized freeze-path routing (nonzero stamp, empty proposal, no
  counterparties) for forward compatibility with new freeze actions.
- Two-person quorum: consumed proposals need two distinct approvals;
  approvals before creation, after expiry, and after withdrawal flagged.
- Signed in-window approve events naming missing proposals are findings;
  audit events predating proposal creation are flagged; freeze stamps
  after emit are flagged.
- Freeze matching requires principal and operator-stamp equality.
- Gated-operation matching filters resources by type.
- Expiry sweeps of unknown proposals are noted.
- No-anchor finding for partitions with data but zero checkpoints; loss
  markers past an early verifier stop are found from decoded rows.
- `--max-segment-bytes` caps every ledger file; truncation points noted
  with byte offsets; metadata skip counts and segment/snapshot mixing
  noted.
- `--archive-timeout-secs`, `--max-timeline-rows` (with truncation notes),
  epoch-millis window values, tool-drift warnings on `verify`, and
  `hint:` lines on every exit-2 error.
- `--format json|text`, `--quiet`/`--verbose`, `verify` checks table,
  `verify --fail-on-findings`, `--only`, `--require-all-checked`,
  `completions`, output-inside-input refusal, `keygen --key-id` with
  printed public key.
- Fixture scenarios: `corrupt-chain`, `expired-approval`, `unsigned`,
  `worm-tamper`; `fixture --scenario bulk --events N`; `--seed`
  determinism; `--layout capture`; per-scenario `README.txt`.
- Pack format: `report.json` + `report.sig` + `report.html` +
  `input-files.json`, canonical-JSON Ed25519 signing under
  `krabka-evidence-report-v1`, listing cross-checks in `verify`
  (`docs/FORMAT.md`).
- Operator, checks, format, and threat-model docs; README findings guide
  and troubleshooting.

Baseline (never released as a tag): offline three-ledger evidence packs
(audit, metadata, WORM), phase-aware cross-checks, signed HTML + JSON
output, `verify`, `keygen`, and the four PRD fixture scenarios (`clean`,
`missing-audit`, `flipped-sig`, `approver-change`).
