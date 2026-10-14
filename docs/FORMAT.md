# Pack format

A pack is a directory with four files. `verify` re-checks all of them
without a broker.

| File | Contents |
|---|---|
| `report.json` | The report, pretty-printed JSON (schema below) |
| `report.sig` | Raw 64-byte Ed25519 signature over the canonical report |
| `report.html` | The same report as standalone readable HTML |
| `input-files.json` | Per-file SHA-256 of every hashed local input, by slot |

## `report.json`

Top-level keys (in the struct's declaration order; the wire order is
irrelevant — see canonicalization):

- `format`: always `"krabka-evidence-report/1"`. `verify` refuses anything
  else.
- `generated_at`: RFC 3339 generation time.
- `tool_version`: the `krabka-evidence` version that wrote the pack.
  `verify` warns when it differs from its own.
- `window`: `from`/`to` as given (or null when unbounded) plus
  `from_ms`/`to_ms` epoch bounds.
- `inputs`: one entry per slot (`audit`, `metadata`, `archive`,
  `operator_keys`): `given` (path or URL as passed), `digest` (hex
  SHA-256 over the input listing, or `remote:<url>` for S3 archives,
  which are never hashed), `files`, `bytes`.
- `checks`: one row per check in report order: kebab-case `id`,
  human-readable `title`, `status` (`pass`, `finding`, or `not-checked`),
  and the finding count.
- `findings`: each with `check` (kebab-case id), `title`, `detail`, and
  optional `audit_offset`, `metadata_offset`, `time_ms` citations.
- `notes`: each with `check` and `detail`. Notes record coverage limits
  without failing the run.
- `timeline`: every row `(time_ms, time, action, target, proposal_id,
  principal, source)`, earliest first. `--max-timeline-rows` truncates
  here (default 100,000); the JSON always holds every kept row.
- `counts`: `audit_records`, `metadata_records`, `worm_manifests`,
  `timeline_rows`, `findings`, `notes`.
- `trust`: keys provisioned for the run: `operators`, `audit`, `worm`
  counts.
- `timeline_truncated`: whether `--max-timeline-rows` dropped rows.
- `auditor`: the signing key — `key_id` from `--auditor-key-id` and the
  raw 32-byte Ed25519 `public_key_hex` the signature verifies against.

Check ids and finding titles are stable identifiers; see
[CHECKS.md](CHECKS.md) for what each one means.

## Canonical JSON and signing

`report.json` on disk is pretty-printed for humans. The signature covers
the canonical form: the report serialized to JSON with every object's keys
sorted recursively, then encoded compactly (no whitespace). The signed
message is the domain separator

```
krabka-evidence-report-v1\0
```

followed by the canonical bytes, signed with Ed25519. The domain keeps a
report signature from verifying as any other Krabka signature, and the
recursive key sort keeps verification independent of pretty-printing.

The auditor key is a PKCS#8 Ed25519 key the cluster never sees (mint one
with `keygen`). Re-verification needs only the pack: `verify` parses
`report.json`, re-canonicalizes it, and checks `report.sig` against the
embedded `auditor.public_key_hex` — unless `--auditor-public-key` pins a
different key, which is then compared byte for byte first.

## `input-files.json`

`{slot: {relative/path: sha256hex}}` for every local input, plus the keys
file. The `digest` recorded in `report.json` for a slot is the SHA-256
over that slot's listing (`path\0digest\0` pairs in sorted order), so the
two files commit to each other: `verify` recomputes each listing digest
and fails the pack when a listing is missing or no longer matches. Remote
(`s3://`) archives cannot be re-hashed; `verify --archive s3://…` says so
and skips.

## `report.html`

One section per check plus the timeline table, fully standalone (no
external assets). The HTML timeline renders the first 10,000 rows with a
caption pointing at `report.json` for the rest; the JSON timeline itself
is complete subject only to `--max-timeline-rows`.

## What `verify` checks, in order

1. `report.json` parses and `input-files.json` parses.
2. Every hashed input has a listing, and every listing digest matches
   `report.json`.
3. `format` is the supported marker.
4. `report.sig` verifies over the canonical bytes (against the pinned key
   when `--auditor-public-key` is given, else the embedded one).
5. Any `--audit`/`--metadata`/`--archive` inputs given are re-hashed and
   compared with the pack's digests.
6. With `--fail-on-findings`, an authentic pack holding findings still
   fails.

The tool-drift warning (pack version vs. verifier version) prints before
any of this, so it shows even for packs that no longer verify.
