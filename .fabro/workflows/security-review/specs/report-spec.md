# Deterministic security report and canonical bundle

The completed canonical bundle is the source of truth for one security scan. `render_report.py` validates that bundle and derives every presentation artifact from it. No model writes or rewrites the final report.

## Canonical files

- `scan-manifest.json` identifies the scan, target, revision, request, completion status, counts, and canonical file set.
- `candidate-ledger.jsonl` contains every unique candidate after deduplication. Each record has a rank and one disposition: `reportable`, `rejected`, `deferred`, or `verification-incomplete`. Candidates beyond a work budget remain in this ledger.
- `findings.json` contains only the reportable subset. It is the authoritative finding list.
- `coverage.json` records what the scan examined, skipped, deferred, or could not complete.
- `panel-votes.jsonl` contains one record for each dispatched panel, repanel, or red-team vote. Each record preserves the exact claim and cited evidence shown to that verifier, plus its verdict and reasoning when it completed.

The JSON Schema contracts for these records are in `schemas/`. The deterministic renderer also checks cross-file rules that JSON Schema cannot express.

## Derived files

The renderer creates only these presentation artifacts from the five canonical files:

- `CLAUDE-SECURITY-RESULTS.md` for people.
- `CLAUDE-SECURITY-RESULTS.jsonl` for finding consumers and CI gates.
- `CLAUDE-SECURITY-REVISION-<tag>.json` for compatibility with current revision consumers.

SARIF is not generated. It can be added later as another deterministic view of the same canonical data.

## Required relationships

A reportable ledger record must match one entry in `findings.json`. Every reported finding must have a complete initial three-lens panel and at least two `TRUE_POSITIVE` votes. Deferred candidates must not appear in `findings.json`. Manifest counts must match the canonical records.

`findingId` identifies the same root vulnerability across scans. `occurrenceId` identifies that finding in one Fabro run. The Markdown and JSONL views copy both IDs from `findings.json`.

Severity describes impact. Confidence describes certainty. A two-of-three panel limits confidence to `medium`. Only a unanimous panel can produce `high` confidence.

A scan is `partial` when work was deferred, verification was incomplete, a research result was unusable, or verification status is `unverified`. The report must show this status and its reasons.

## Rendering safety

The renderer rejects invalid stable IDs, unsafe repository paths, control characters, duplicate identities, inconsistent vote claims, and inconsistent cross-file counts. It escapes model-authored text before placing it in Markdown. Code excerpts use Markdown code blocks.

Findings are derived from source and history review. The workflow does not attest whether agents executed commands.
