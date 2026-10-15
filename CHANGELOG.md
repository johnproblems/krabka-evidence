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

### Added (improvement batch)

- Fixture scenarios `bypass`, `gated-op`, and `unknown-key`, each with
  exactly one finding; `fixture --list-scenarios`; case-insensitive
  scenario names; per-scenario `README.txt` files now state the expected
  exit code and finding; bulk fixtures honor `--seed`; `--events 0` and
  bulk-with-capture-layout are refused; `--out` pointing at a file is
  refused.
- `--overwrite` for builds into non-empty output directories;
  `keygen --force` against clobbering; `verify --operator-keys` re-hashes
  the keys input; `--list-checks --format json`; per-check tables in build
  and verify JSON; `verify --auditor-public-key` accepts 64-char hex pins;
  `--s3-region` reads `AWS_REGION` and `--s3-endpoint` reads
  `AWS_ENDPOINT_URL_S3` (explicit flags win); `--verbose` prints the S3
  endpoint resolution and the total elapsed time.
- Report `trust` records the provisioned key ids, not just counts; build
  JSON reports `not-checked` when `--require-all-checked` fails a
  finding-free run; findings and notes sort by report order.
- `docs/OUTPUT-JSON.md` specifies every `--format json` shape;
  `docs/CHECKS.md` documents per-check window scoping.

### Changed (improvement batch)

- Flag errors are `bad flag` (missing flags, unknown `--only` ids, bad
  `--expect-head`, output nesting) instead of `bad time window`;
  `--expect-head` is validated before any ledger is read; `--only` is
  case-insensitive and ignores empty segments; `--max-timeline-rows 0` is
  refused; window values tolerate whitespace and signed millis; empty
  windows are noted in the report.
- Bypass matching (`bypassed` phases, `audit-only` reasons) ignores case;
  input hashing never follows symlinks; ledger segments walk in numeric
  order; undecodable audit records and empty ledgers are noted instead of
  silent; unparsable snapshot names are disclosed; a short `report.sig`
  fails with an explicit reason; verify re-hash failures honor JSON and
  `--quiet`; the nesting refusal canonicalizes paths first.
- The keys file is parsed strictly (unknown tables/fields fail), and
  duplicate worm key ids and blank key ids are refused.

Baseline (never released as a tag): offline three-ledger evidence packs
(audit, metadata, WORM), phase-aware cross-checks, signed HTML + JSON
output, `verify`, `keygen`, and the four PRD fixture scenarios (`clean`,
`missing-audit`, `flipped-sig`, `approver-change`).
