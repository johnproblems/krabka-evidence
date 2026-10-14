# Operator's guide

How to prepare inputs, provision keys, run the tool, and read the result.
For what each check means, see [CHECKS.md](CHECKS.md); for the pack layout,
see [FORMAT.md](FORMAT.md).

## Inputs: copies, never live state

The tool never talks to a broker and never writes to its inputs — but it
does assume the inputs are a **consistent set of copies**:

- `--audit`: a copy of the audit partition directory (`*.log` segments).
- `--metadata`: a copy of the `__cluster_metadata-0` partition directory,
  a directory of `*.checkpoint` snapshots, or a `krabka-backup` capture
  root (one holding `restore-inputs/`).
- `--archive`: a local WORM directory, or `s3://bucket[/prefix]`.
- `--operator-keys`: the TOML keys file (below).

Copy first, then run. The report digests every local input
(`input-files.json`), so `verify --audit … --metadata … --archive …` can
later prove the pack was built from exactly those bytes. The output
directory must not nest with any input — the run is refused otherwise.

## Keys

One TOML file carries every trust root. Operator keys bind key ids to
principals; audit and WORM keys are broker keys with no principal:

```toml
[[operator_keys]]
key_id = "alice-2026"
principal = "User:alice"
public_key_path = "alice.pub"   # raw 32 bytes, relative to this file

[[audit_keys]]                  # at most one
key_id = "audit-1"
public_key_path = "audit.pub"

[[worm_keys]]                   # several allowed (rotations)
key_id = "worm-1"
public_key_path = "worm.pub"
```

Broker keys can also come from flags: `--audit-key-id` with
`--audit-public-key` (single), and repeatable `--worm-key-id` with
`--worm-public-key`, paired by position. Missing keys never fail the run;
the affected checks grade `not-checked` and say so (`NOT CHECKED` notes).

The report key is separate: mint it with `keygen --out auditor
--key-id auditor-1`, keep `auditor.priv.pkcs8` offline, and pass
`--sign-with auditor.priv.pkcs8`. `verify` trusts the auditor key
embedded in the pack unless `--auditor-public-key` pins the expected
`auditor.pub` — pin it whenever the pack crosses a trust boundary.

## S3 archives

`--archive s3://bucket[/prefix]` reads through the ambient AWS chain
(environment, shared config, instance role — exactly as
`krabka-worm-verify`). `--s3-region` defaults to `us-east-1`;
`--s3-endpoint` points at compatible stores (MinIO, LocalStack), with
`--allow-http` for plaintext endpoints. Remote archives are never hashed:
their `report.json` digest reads `remote:<url>`, and re-hashing one is
skipped with a note.

## Exit codes and output

| Code | Meaning |
|---|---|
| 0 | Clean (or, for `verify`, authentic) |
| 1 | Findings — or, for `verify --fail-on-findings`, an authentic pack that holds findings, or `--require-all-checked` with checks left `not-checked` |
| 2 | Unreadable inputs/keys/pack, bad flags, archive timeout |

`--format json` emits one summary object (`status`, `findings`, `notes`,
`pack`, `not_checked`); `--quiet` prints nothing and lets the exit code
answer; `--verbose` narrates each phase and every input digest to stderr.
Every exit-2 error is followed by a `hint:` line with the fix.

## Windows and time

`--from`/`--to` accept `YYYY-MM-DD`, RFC 3339, or epoch millis; both are
optional (unbounded when absent) and `--to` is exclusive. Dates are UTC
midnights. Cross-checks only fire inside the window, so an unbounded run
over retained history can surface ancient drift — scope the window to the
period under audit.

## Limits for hostile or huge inputs

| Flag | Default | Effect |
|---|---|---|
| `--max-segment-bytes` | 1 GiB | Refuse any ledger file over this size |
| `--archive-timeout-secs` | 600 | Give up on the archive walk after this long (`0` disables) |
| `--max-timeline-rows` | 100,000 | Keep the earliest rows; note the truncation |

Release builds verify roughly 130k audit records/s (10M records in about
75 seconds), so the caps above are about containment, not throughput.

## WORM grading

- `--deep` downloads every object and recomputes its SHA-256 (shallow
  checks manifests, links, signatures, and sizes).
- `--strict-orphans` grades orphan objects as findings instead of notes.
- `--allow-epoch-restarts` accepts chain restarts silently instead of
  noting them as attestation holes.
- `--expect-head <64 hex>` requires every partition tip to equal the
  given head. A mismatch is reported as its own outcome, never as
  tampering.

## A full run

```sh
krabka-evidence --from 2026-09-01 --to 2026-10-01 \
  --audit ./audit-partition --metadata ./cluster-metadata \
  --archive s3://bucket/tiered --operator-keys keys.toml \
  --cluster-id prod --sign-with auditor.priv.pkcs8 \
  --auditor-key-id auditor-1 -o evidence/

krabka-evidence verify evidence/ --auditor-public-key auditor.pub \
  --audit ./audit-partition --metadata ./cluster-metadata
```

Practicing without a cluster: `fixture --scenario all --out /tmp/demo`
writes all eight scenarios (see each `README.txt`); `--scenario bulk
--events N` writes volume; `--seed` reproduces fixtures byte for byte;
`--layout capture` writes the metadata input as a backup capture.
