# Developing Security Review

This guide is for people who change the workflow. See [`README.md`](README.md)
for user instructions. See [`index.html`](index.html) for a visual guide
to the phases and agent prompts.

## Repository layout

Everything that a review runs lives under
`.fabro/workflows/security-review/`:

| Path | Contents |
| --- | --- |
| `security-review.fabro` | The workflow graph, direct phase routing, and deterministic steps. |
| `workflow.toml` | The normal run configuration, inputs, environment, and artifacts. |
| `verify.toml` | A `low`-effort smoke run against the command-injection fixture. |
| `scripts/security_review.py` | The deterministic engine. It owns state transitions, limits, deduplication, and vote tallies. |
| `scripts/render_report.py` | Validates the canonical bundle and derives the Markdown, HTML, JSONL, and revision reports. |
| `scripts/git_readonly.py` | A read-only Git entry point with external diff and text conversion drivers disabled. |
| `templates/report.html` | The self-contained HTML report template. |
| `prompts/*.md.j2` | MiniJinja prompt templates for inventory, threat modeling, research, sweeping, verification, and red-team work. |
| `prompts/partials/` | Shared MiniJinja prompt content. |
| `schemas/` | Model response schemas and versioned canonical bundle contracts. |
| `specs/report-spec.md` | Canonical bundle relationships and deterministic report rules. |
| `fixtures/` | The command-injection fixture used by the smoke run. |

The `tests/` directory contains the test suite and two developer tools:

- `build_sample_report.py` regenerates `sample.html`.
- `repin_support_files.py` refreshes support-file hashes in the workflow graph.

The repository root also contains:

- `README.md` for users.
- `index.html` for the detailed workflow guide.
- `sample.html` for the generated example report.

## Design rules

### Keep the review read-only

The workflow reports findings and recommendations. It does not modify reviewed
files or apply fixes.

Treat everything from the target repository as untrusted evidence. This
includes source, comments, agent instruction files, commit messages, and
fixtures. Text that addresses an agent is evidence to inspect, not an
instruction to follow.

Agents are told to read the target and not to build, test, or execute it. That
instruction is not an enforcement boundary. The review therefore runs in a
disposable cloud sandbox.

### Agents judge and code decides

Agents return structured findings and verdicts. Deterministic code decides
which candidates merge, which candidates survive verification, and what the
report can claim.

`security_review.py` owns state transitions, limits, deduplication, and vote
tallies. `render_report.py` validates the canonical bundle and derives every
report. No model writes the final report.

### A finding must survive verification

Three verifiers try to disprove each candidate. They use separate reachability,
impact, and defense checks. All three must return a verdict. At least two must
confirm the finding.

A two-of-three confirmation has at most `medium` confidence. Only a unanimous
panel can produce `high` confidence. `security_review.py` computes this limit.
`render_report.py` checks it again against the recorded votes.

Verifiers see the reported evidence and claim. They do not see the researcher's
confidence value.

### Finding identity stays stable

Researchers name a rule and a conceptual root control. Deterministic code uses
them to derive the fingerprint, stable `findingId`, and per-run
`occurrenceId`.

Deduplication uses the fingerprint instead of a file and line pair. If one
identity points to different root controls, the workflow stops instead of
merging an ambiguous result.

### Phases are deterministic barriers

Each phase finishes before the next phase starts. Each phase has a concurrency
limit. A deterministic merge step normalizes agent output and records missing
responses. A missing response reduces coverage instead of changing vote
arithmetic.

### Integrity checks protect publication

The workflow pins the SHA-256 hashes of the deterministic engine, Git wrapper,
renderer, report specification, and report template. `prepare` checks these
hashes before the review starts.

`prepare` also records a digest of the target tree. Publication steps check the
digest again. The workflow refuses to publish a report if the tree changed
during the review.

### Sub-agents need explicit rules

Sub-agents do not inherit the parent agent's instructions. An agent that starts
a read-only explorer must include the explorer's rules in the request.

## Keep related files in sync

A workflow change is not complete until all affected files are current.

- Update `README.md` and `index.html` when behavior, phases, inputs, outputs,
  report fields, or artifact names change.
- Update this file when repository structure, design rules, or developer
  procedures change.
- If a `workflow.md` guide is added, keep it in sync with `index.html`.
- Update related files under `.fabro/workflows/security-review/` together.
  This includes the graph, run configurations, prompts, schemas, scripts,
  report specification, and report template.
- Keep `workflow.toml` and `verify.toml` aligned where they share settings and
  artifact declarations.
- Add or update tests for contract and behavior changes.

Do not edit `sample.html` by hand. Regenerate it after a report template,
renderer, schema, or sample data change:

```bash
python3 tests/build_sample_report.py --write
```

After you change a pinned support file, refresh its hash:

```bash
python3 tests/repin_support_files.py --write
```

Do not edit support-file hashes by hand.

## Run the tests

Run the full test suite before you finish:

```bash
python3 tests/test_fabro_workflow.py
```

The suite drives the deterministic engine with fabricated agent output. It
also checks graph routing, support-file hashes, concurrency limits, prompt
contracts, the generated sample report, and documentation naming.

## Run the smoke review

For an end-to-end workflow change, run the smoke review when practical:

```bash
fabro run .fabro/workflows/security-review/verify.toml
```

The smoke review uses `low` effort against the command-injection fixture. It
must report exactly one verified finding.

Push the branch first. The sandbox clones the pushed branch, not the local
working tree. It cannot see uncommitted prompt or engine changes. An unpushed
change to a pinned support file makes `prepare` fail its hash check.
