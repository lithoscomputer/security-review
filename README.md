# security-review

A Fabro workflow that puts a team of agents to work as security researchers on
a repository: partition it into components, threat-model each one, hunt for
vulnerabilities across a component × category matrix, sweep the gaps, and then
try hard to disprove every candidate. Only findings that survive an adversarial
panel are reported.

The review is read-only. It produces a completed scan bundle and deterministic
reports, never a code change.

## Running a review

```bash
fabro run .fabro/workflows/security-review/workflow.toml
```

Inputs (`-I name=value`, all optional):

| Input | Values | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | `scan`, `changes`, `commit` | `scan` | Review the tree, a branch's diff, or one commit. |
| `effort` | `low`, `medium`, `high`, `max` | `medium` | How much work the run does. See below. |
| `scope` | comma-separated paths | Empty (whole target) | Limit the review to these directories or files. |
| `base` | a Git revision | Empty (auto-detect) | `changes` mode: what to diff against. Auto-detection tries the upstream, then `origin/HEAD`, `origin/main`, `origin/master`, `main`, and `master`. |
| `range` | `base..HEAD` | Empty (use `base`) | `changes` mode: an explicit two-sided range instead of `base`. |
| `commit` | a Git revision | Empty | `commit` mode: the required commit to review against its parent. |
| `focus` | `attack-surface`, `none` | Empty (automatic) | Spend the effort on production code an attacker can reach, treating tests, fixtures, generated code, and vendored trees as background. Automatic selection uses repository size. |

Effort sets how much work happens, not how carefully any one agent thinks. The
verification panel is three voters at every tier — that is what the report's
confidence figures are calibrated against. Agent roles use fixed Sonnet/Opus
routing; the effort tier changes the amount of work.

| Tier | Shape |
| --- | --- |
| `low` | One researcher over the whole target, then the panel. No inventory, threat model, or sweep. |
| `medium` | Inventory, a threat model per component, one researcher per component × category, one sweep, the panel. A diff of at most 5 files and 300 changed lines, or a scope of at most 5 files, collapses to the single-researcher shape instead. |
| `high` | As `medium` with a wider inventory (24 components), two researchers per cell, and two sweeps. |
| `max` | As `high`, plus an adversarial round: marginal 2-of-3 keeps are repanelled and every survivor faces a red-team refuter. |

A run writes `CLAUDE-SECURITY-<timestamp>/` with five canonical files:
`scan-manifest.json`, `candidate-ledger.jsonl`, `findings.json`,
`coverage.json`, and `panel-votes.jsonl`. Deterministic code derives
`CLAUDE-SECURITY-RESULTS.md`, `CLAUDE-SECURITY-RESULTS.jsonl`, and
`CLAUDE-SECURITY-REVISION-<tag>.json` from those files. No model authors the
final report. SARIF is not generated. The directory carries its own
`.gitignore`, so nothing in it reaches a commit unless you delete that file.

Each finding has three IDs. `F1`, `F2`, and so on are short display labels for
one report. `findingId` is derived from the target, rule, and root-control
identity, so it stays the same when a finding moves to another line or appears
in a later run. `occurrenceId` combines that stable identity with the Fabro run
ID, so it names one occurrence in one scan. The JSONL also carries the full
primary fingerprint used for deterministic deduplication.

Reviews are nondeterministic: running them regularly builds coverage over time.
This complements SAST, dependency scanning, and code review; it does not
replace them.

## Layout

Everything the workflow runs lives under
`.fabro/workflows/security-review/`:

| Path | Contents |
| --- | --- |
| `security-review.fabro` | The graph: the phases, their gates, and the deterministic steps between them. |
| `workflow.toml` | Run configuration: inputs, environment, artifacts. |
| `verify.toml` | A `low`-effort run against the fixture, for smoke-testing the workflow. |
| `scripts/security_review.py` | The deterministic engine. Every state transition, cap, deduplication, and vote tally lives here, outside the agents. |
| `scripts/render_report.py` | Validates the canonical bundle and derives the Markdown report, findings JSONL, and revision stamp. |
| `scripts/git_readonly.py` | A read-only Git entry point with external diff and textconv drivers disabled. |
| `prompts/` | One prompt per agent role: inventory, threat model, research, sweep, verify, and redteam. |
| `schemas/` | The model response schemas and the versioned canonical bundle contracts. |
| `specs/report-spec.md` | The canonical bundle relationships and deterministic rendering rules. |
| `fixtures/` | A deliberate command-injection fixture the smoke run expects to find. |

`tests/test_fabro_workflow.py` holds the workflow's tests. The `workflows/`,
`agents/`, `skills/`, `hooks/`, and `scripts/` directories at the repository
root are reference material and are not part of the workflow.

## Testing

```bash
python3 tests/test_fabro_workflow.py
```

The tests drive the deterministic engine directly with fabricated agent output,
so a full run is never needed to check the arithmetic. They also pin static
contracts a run would only reveal expensively: the graph's routing and its
support-file hashes, the concurrency caps, and what each prompt must and must
not say.

For an end-to-end check, `verify.toml` reviews the command-injection fixture at
`low` effort and should report exactly one verified finding:

```bash
fabro run .fabro/workflows/security-review/verify.toml
```

Push first. The sandbox clones the repository, so a run reviews the pushed
branch — not your working tree. Uncommitted prompt or engine changes are
invisible to it, and an unpushed change to a pinned support file fails
`prepare` on its hash.

## How it holds together

**Agents judge; code decides.** Agents read code and return structured
findings or verdicts. Every consequence — which candidates merge, which
survive the panel, what the report may claim — is computed in
`security_review.py`, where it can be tested and cannot be talked out of.

**A finding earns its place.** Researchers propose; three verifiers each take a
different refutation lens (reachability, impact, defenses) and try to disprove
it. Two must confirm, and all three must return. A 2-of-3 keep is capped at
`medium` confidence in the report, and only a unanimous panel earns `high` —
`render_report.py` enforces that ceiling regardless of what the report says.
Verifiers see only what the reporter claimed, never the reporter's own
confidence, so the panel cannot be anchored by it.

**Finding identity is stable.** Researchers name a rule and a conceptual root
control. Deterministic code derives the fingerprint, stable `findingId`, and
per-run `occurrenceId`. Deduplication uses that fingerprint instead of a
file-and-line tuple. If one identity points at different root controls, the
workflow stops rather than merging an ambiguous result.

**The repository is data, never instruction.** Everything the review reads —
source, comments, `CLAUDE.md`, commit messages, fixtures — is evidence under
examination. Text that addresses an agent is a finding to report
(`prompt-injection`), not a direction to follow.

**Each phase finishes before the next begins**, with a concurrency cap per
phase. A phase's agent outputs are merged by a deterministic step that
normalizes them and records what failed to return, so a missing agent degrades
the run's coverage instead of corrupting its arithmetic.

**Support files are pinned.** Before anything runs, `prepare` verifies the
SHA-256 of the engine, the Git wrapper, the renderer, and the report spec
against hashes recorded in the graph. Editing one of those files means
updating its pin in `security-review.fabro`; a test enforces that they match.

**Nothing tampered gets published.** `prepare` records a digest of the whole
tree, and the publication steps re-verify it. A source tree that changed
mid-review is refused rather than reported on.

**The sandbox is the boundary.** Agents are instructed to read rather than
build, test, or execute, and nothing enforces that instruction, so a review
runs in a disposable cloud sandbox with the repository cloned into it. The
report says as much rather than claiming that nothing ran.

**Sub-agents inherit no instructions.** An agent that dispatches a read-only
explorer must state the explorer's rules inside the dispatched question
itself.
