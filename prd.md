# krabka-evidence: one signed report from every ledger

## Summary and novelty check

krabka-evidence is an offline command-line tool. You give it a time window and copies of the cluster's records, and it answers one question: *did every dangerous thing that happened go through the controls, and can we prove it?* The output is one HTML and JSON report, signed by the tool's key, that an auditor can re-verify without a broker.

```sh
krabka-evidence --from 2026-09-01 --to 2026-10-01 \
  --audit ./audit-partition --metadata ./cluster-metadata \
  --archive s3://bucket/tiered --operator-keys keys.toml -o evidence/
```

**Why this needs a new tool.** Krabka keeps several tamper-evident records of the same events. Each one has its own verifier, and each verifier only checks that its own chain is intact:

| Ledger | What it records | Existing check |
| --- | --- | --- |
| Audit log (`__krabka_audit`) | Logins, denials, admin ops, and privileged actions with the operator's signature | `krabka-audit verify`: hash chain and checkpoint signatures only |
| Metadata log (`__cluster_metadata`) | Freeze and break-glass records, the source of truth | `krabka-guard break-glass list --verify`: proposals currently in the log |
| WORM archive | Signed manifest chain over tiered segments | `krabka-worm-verify` |

None of them checks the ledgers *against each other*, and that comparison is where the real gaps show up:

- **Missing audit events.** Audit defaults to `FailOpen`, so a privileged action can be applied while its audit event is lost. Only a comparison with the metadata log shows that.
- **Unchecked signatures.** Audit's own design says an auditor "can re-verify who set every freeze from the audit topic alone". But `krabka-audit verify` does not check operator signatures on each action; it checks the chain.
- **Approver list drift.** Each event carries `approver_set_fingerprint`. Nobody reports when that fingerprint changes during a window.

**Novelty check.** I found no cross-ledger or evidence-pack tool in krabka-broker's 24 crates, its KFCs (3, 5 and 9 each add a single-ledger verifier), its open issues, the krabka-cli plugins, or the admin UI.

## Goals, non-goals, success criteria

**Goals**

- Run every existing single-ledger verifier for the window and include their results.
- Run the cross-ledger checks described under "How it works".
- Produce an `evidence/` folder:
  - `report.html` for people
  - `report.json` for machines
  - copies of the inputs' hashes
  - `report.sig`, an Ed25519 signature over the JSON
- Provide `krabka-evidence verify evidence/` so an auditor can check the pack itself.
- Exit codes: 0 means clean, 1 means findings, 2 means inputs unreadable. This lets it run on a schedule in CI.
- Work entirely offline from copied directories or a `krabka-backup` capture. It never connects to a live broker.

**Non-goals**

- Mapping findings to specific compliance controls (FedRAMP, SOC 2). The report uses plain names, and mappings can be added as templates later.
- Monitoring live clusters. This is a periodic, after-the-fact check.
- Fixing anything it finds.

**Success criteria**

- On a three-node test cluster, the following each produce exactly one finding with the right offset and time:
  - A freeze, then a break-glass thaw approved by two operators, then a `DeleteTopic`, gives a clean report.
  - The same sequence with one audit segment deleted gives a "metadata action with no audit event" finding.
  - An event with its signature bytes flipped gives a "signature does not verify" finding.
  - A change of approver list mid-window gives an "approver set changed" finding.
- Flipping one byte of the report makes `krabka-evidence verify` fail.
- One month of audit data with 10 million records takes under 5 minutes.

## How it works

**Inputs.** krabka-evidence takes four inputs, all copied first and opened read-only:

- **The audit partition directory**, read with `krabka_audit::verify_partition_dir` and the crate's decoder.
- **The `__cluster_metadata-0` segments**, or a `krabka-backup` capture. These are decoded with the `krabka-metadata` crate, because the private records are positional wincode.
- **The tiered archive**, checked with `krabka_remote_storage::verify_archive`.
- **A TOML file of operator public keys**, in the same format `krabka-guard list --verify` already takes.

All the krabka crates come in as git dependencies pinned to a release tag, since they are not on crates.io.

**Step 1: per-ledger checks.** Run the three existing verifiers and copy their results into the report:

- audit chain breaks, declared `RecordsLost` windows, and the unanchored tail
- WORM tamper, head mismatch, and orphan objects

**Step 2: build one timeline.** Turn each ledger into rows of `(time, action, target, proposal_id, principal, source)`:

- `PrivilegedAction` events from audit
- `TopicFreezeRecord` and break-glass records (metadata tags 1004–1006) from the metadata log
- `AdminOperation` events for gated operations such as `DeleteTopic` and `DeleteRecords`

**Step 3: cross-checks.** Each finding cites both sides by offset.

| Check | Finding |
| --- | --- |
| Every metadata freeze or break-glass act has an audit `PrivilegedAction` with the same proposal id and target | "Applied with no audit event" (a fail-open loss or a gap) |
| Every audit `Applied` event has a matching metadata record | "Audited action not in metadata" (a forged or replayed event) |
| Each event's `signature` verifies against the operator keys, over the preimage krabka-guard defines | "Signature does not verify" or "unknown key" |
| Approvers are distinct from the proposer, and approval comes before the proposal expires | "Two-person rule violated" |
| Any `Bypassed` phase, or `background_unclean_recovery=audit-only` activity | Listed, with the reason text |
| `approver_set_fingerprint` changes within the window | "Approver set changed", with before and after |
| A gated `AdminOperation` succeeded with no break-glass `Consumed` before it | "Gated op without approval" |

**Step 4: report.** One page per check, with summary counts at the top and every row linked to its offsets. The JSON is canonicalized and signed. `verify` re-hashes the inputs it names and checks the signature.

## Build plan, risks, open questions

**Build plan (about 20 hours)**

1. **Spike first.** Set up the git dependencies and decode the audit partition and the metadata segments from a local test cluster into one printed timeline. (4 h)
2. Wrap the three existing verifiers and normalize their results into one finding type. (3 h)
3. Implement the cross-checks, including signature preimages copied from `krabka-guard`'s signing code, not rewritten. (6 h)
4. Write the canonical JSON, the HTML template, the signing, and `verify`. (3 h)
5. Write a fixture script that boots a cluster, runs the success-criteria sequences, and tampers with copies of the data; then add tests. (4 h)

**Risks**

| Risk | Mitigation |
| --- | --- |
| Metadata snapshots compact old records away, so history may be gone | Read segments when present. Otherwise read a series of `krabka-backup` captures, and report "history not available before offset N" as its own finding. |
| Unpublished crate APIs change with near-daily releases | Pin to a release tag. CI checks that the newest tag still builds. |
| Signature preimages are subtle (`signed_at_ms` vs `time_ms`, proposals signing `created_at_ms` and `expires_at_ms`) | Call krabka-guard's own preimage functions as a library. Never re-implement the byte layout. |
| Calling a report "compliance evidence" overstates it | The report says what was checked and what was not. It makes no claim about controls outside the ledgers. |

**Open questions**

- Should the report key be a krabka operator key, or a separate auditor key the cluster never sees? The separate key seems right.
- Should KFC-2 witness and KFC-8 clock-skew signals go in a v2? A large clock skew during a signed action weakens its timestamp.

## Sources

- [`crates/audit/src/event.rs`](https://github.com/krabka-io/krabka-broker/blob/main/crates/audit/src/event.rs): `PrivilegedAction` fields and the stated re-verification intent
- [`crates/audit/src/verify.rs`](https://github.com/krabka-io/krabka-broker/blob/main/crates/audit/src/verify.rs): what `krabka-audit verify` covers
- [KFC-9: topic write-freeze and break-glass](https://github.com/krabka-io/krabka-broker/blob/main/docs/KFCs/KFC-9-topic-write-freeze-and-break-glass-workflows.md)
- [KFC-5: WORM archive integrity manifests](https://github.com/krabka-io/krabka-broker/blob/main/docs/KFCs/KFC-5-worm-archive-integrity-manifests.md)
- [Configuration reference, `[audit]`](https://github.com/krabka-io/krabka-broker/blob/main/docs/config-reference.md)
- [Persisted formats](https://github.com/krabka-io/krabka-broker/blob/main/docs/persisted_formats.md)
