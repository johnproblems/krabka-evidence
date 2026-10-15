# Machine-readable output

Every `--format json` shape the tool prints, with its exit code. The JSON
always goes to stdout; warnings, hints, and `--verbose` narration stay on
stderr, so `krabka-evidence … --format json | jq …` never trips over
logging. (`--quiet` prints nothing at all.) For the pack schema itself,
see [FORMAT.md](FORMAT.md).

## Build

`krabka-evidence --format json …` prints one summary object:

```json
{
  "status": "clean",
  "findings": 0,
  "notes": 2,
  "pack": "evidence/",
  "not_checked": 0,
  "checks": [
    {"id": "audit-chain", "title": "Audit hash chain and checkpoints",
     "status": "pass", "findings": 0}
  ]
}
```

- `status` is `clean` (exit 0), `findings` (exit 1), or `not-checked`
  (exit 1): the last means the pack holds no findings but
  `--require-all-checked` failed the run because some check ended
  `not-checked`.
- `checks` is the full per-check table in report order: kebab-case `id`,
  human-readable `title`, `status` (`pass`, `finding`, or `not-checked`),
  and the finding count.

## Verify

`krabka-evidence verify evidence/ --format json` prints:

```json
{"authentic": true, "findings": 1, "notes": 2, "checks": [ … ]}
```

with the same per-check table as a build. Exit 0. With
`--fail-on-findings`, an authentic pack holding findings prints

```json
{"authentic": true, "findings": 1, "failed": "--fail-on-findings"}
```

and exits 1. An inauthentic pack prints

```json
{"authentic": false, "reason": "report.sig does not verify over report.json"}
```

and exits 1.

When `--audit` / `--metadata` / `--operator-keys` / `--archive` re-hash
an input, a digest mismatch prints

```json
{"authentic": true, "rehash": "mismatch", "slot": "audit"}
```

(exit 1), and an unreadable input prints

```json
{"authentic": true, "rehash": "error", "slot": "audit", "reason": "…"}
```

(exit 2). `slot` is `audit`, `metadata`, `operator_keys`, or `archive`.
In text mode the same outcomes print `FAIL:` / `error:` lines to stderr.

## `--list-checks`

`krabka-evidence --list-checks --format json` prints the check table:

```json
[
  {"id": "audit-chain", "title": "Audit hash chain and checkpoints"},
  {"id": "audit-loss-windows", "title": "Declared audit loss windows"}
]
```

eleven entries in report order. Text mode prints one `id - title` line
per check instead.
