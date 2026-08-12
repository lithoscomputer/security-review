# Security Review

Security Review runs an adversarial, read-only security review of a Git
repository. A team of agents maps the target, looks for vulnerabilities, and
tries to disprove each candidate. Only findings that pass a three-voter
verification panel reach the report.

This project is a workflow for [Fabro](https://fabro.sh/). Fabro is required to
run it.

## Before you run

The included run configuration uses a Daytona cloud sandbox. Before your first
review:

1. Install and configure Fabro with the
   [Fabro Quick Start](https://docs.fabro.sh/getting-started/quick-start).
2. Configure the
   [Fabro Daytona integration](https://docs.fabro.sh/integrations/daytona).
3. Configure GitHub access in Fabro. It is required for private repository
   cloning and checkpoint storage.
4. Run `fabro doctor` and fix any reported configuration errors.

Copy the complete
[`.fabro/workflows/security-review/`](.fabro/workflows/security-review/)
directory into the repository that you want to review. Keep the same path. If
you are using this repository as the target, the files are already in place.

Commit and push the workflow files and the code that you want to review. The
sandbox clones the current repository and branch. It cannot see uncommitted
work.

## Run your first review

Run these commands from the root of the target repository:

```bash
fabro preflight .fabro/workflows/security-review/workflow.toml
fabro run .fabro/workflows/security-review/workflow.toml
```

The default run reviews the full pushed tree at `medium` effort.

For a smaller first run, choose one path and use `low` effort:

```bash
fabro run \
  -I effort=low \
  -I scope=src/auth \
  .fabro/workflows/security-review/workflow.toml
```

## Choose what to review

Pass inputs with `-I name=value`. You can repeat `-I`.

| Input | Values | Default | Purpose |
| --- | --- | --- | --- |
| `mode` | `scan`, `changes`, `commit` | `scan` | Review the pushed tree, a set of changes, or one commit. |
| `effort` | `low`, `medium`, `high`, `max` | `medium` | Set how much research the workflow performs. |
| `scope` | comma-separated paths | Whole target | Limit the review to named files or directories. |
| `component_guidance` | Free text | Empty | Guide how the inventory agent groups and prioritizes components. |
| `research_guidance` | Free text | Empty | Give each researcher a tip about what to watch for. |
| `base` | Git revision | Auto-detected | In `changes` mode, compare the current revision with this revision. |
| `range` | `base..HEAD` | Empty | In `changes` mode, review an explicit two-sided revision range. |
| `commit` | Git revision | Empty | In `commit` mode, review this commit against its parent. |
| `focus` | `attack-surface`, `none` | Automatic | Focus on reachable production code, or turn that focus off. |

For example:

```bash
# Review changes since origin/main.
fabro run \
  -I mode=changes \
  -I base=origin/main \
  .fabro/workflows/security-review/workflow.toml

# Review one commit.
fabro run \
  -I mode=commit \
  -I commit=abc1234 \
  .fabro/workflows/security-review/workflow.toml

# Review two directories at high effort.
fabro run \
  -I effort=high \
  -I scope=src/auth,src/session \
  .fabro/workflows/security-review/workflow.toml

# Guide component planning and vulnerability research.
fabro run \
  -I component_guidance='Keep the API and background workers separate' \
  -I research_guidance='Watch tenant IDs passed into background jobs' \
  .fabro/workflows/security-review/workflow.toml
```

When `base` is empty, the workflow tries the branch upstream, then
`origin/HEAD`, `origin/main`, `origin/master`, `main`, and `master`.

Guidance is advisory. `component_guidance` cannot change the hard `scope`,
component cap, completeness rules, or skipped-component rules. It has no effect
when a low-effort or small-target run skips inventory. `research_guidance` goes
to each researcher as a lead to verify, not as evidence. Verification and
red-team agents do not receive it. Supplied guidance is recorded in the
canonical `scan-manifest.json` request.

## Choose an effort level

Effort changes the amount of work. It does not change how carefully one agent
reasons. Every level uses three verification voters.

| Level | Work performed |
| --- | --- |
| `low` | One researcher reviews the whole target, followed by the verification panel. |
| `medium` | The default. The workflow builds an inventory and threat models, assigns research by component and category, performs a gap sweep, and runs the panel. Small diffs and scopes use the `low` shape. |
| `high` | Expands the inventory, uses two researchers for each component and category, and performs two gap sweeps. |
| `max` | Adds a second panel for marginal findings and a red-team refuter for every survivor. |

All agent stages use Kimi K3. Inventory and threat-modeling agents use low
reasoning. Researchers, gap sweeps, and verification agents use high reasoning.
If the selected Kimi provider fails, the run configuration tries Moonshot and
OpenRouter before it falls back to `claude-opus-5`.

Each agent attempt has a fixed timeout. Fan-out phases also have a concurrency
cap:

| Phase | Timeout per attempt | Concurrency cap |
| --- | --- | --- |
| Inventory | 60 minutes | 1 |
| Threat models | 120 minutes | 12 |
| Researchers | 180 minutes | 24 |
| Sweeps | 180 minutes | 12 |
| Panel | 120 minutes | 24 |
| Repanel | 120 minutes | 24 |
| Red team | 180 minutes | 24 |

The workflow also has a four-hour stall timeout. Any workflow event resets
that timer.

Use `low` for a quick or narrow check. Use `medium` for a routine repository
review. Use `high` or `max` when you want more independent coverage and accept
the added time and model use.

## Read the results

A completed run writes a `SECURITY-REVIEW-<timestamp>/` directory. Start with
`SECURITY-REVIEW-RESULTS.html`. It is a self-contained report that you can open
locally. You can search its findings and filter them by component, severity,
and difficulty. See [`sample.html`](sample.html) for an example built from
fictional findings.

| File | Purpose |
| --- | --- |
| `SECURITY-REVIEW-RESULTS.html` | Self-contained report for people. |
| `SECURITY-REVIEW-RESULTS.md` | Plain-text report for terminals and code review. |
| `SECURITY-REVIEW-RESULTS.jsonl` | One finding per line for scripts and CI. |

The complete published layout is:

```text
SECURITY-REVIEW-<timestamp>/
├── .gitignore
├── SECURITY-REVIEW-RESULTS.html
├── SECURITY-REVIEW-RESULTS.md
├── SECURITY-REVIEW-RESULTS.jsonl
├── evidence/
│   ├── scan-manifest.json
│   ├── candidate-ledger.jsonl
│   ├── findings.json
│   ├── coverage.json
│   └── panel-votes.jsonl
└── metadata/
    ├── revision.json
    ├── state.json
    └── scan-meta.json
```

`evidence/` is the canonical evidence bundle. Deterministic code validates it
and derives every report. `metadata/` records the reviewed revision and the
workflow state used to produce the reports. No model writes the final report.
SARIF is not generated.

The result directory contains its own `.gitignore`. Results do not enter a
commit unless you remove that file. Fabro publishes all security-review
artifacts under this one result directory.

### Ratings and finding IDs

- Severity describes the impact if an attacker exploits a finding.
- Difficulty describes the access, knowledge, and effort needed for
  exploitation. `LOW` difficulty is the worse case.
- A finding confirmed by two of three voters has at most `medium` confidence.
  Only unanimous confirmation can produce `high` confidence.
- `F1`, `F2`, and similar labels identify findings within one report.
  `findingId` stays stable across runs when the same root issue moves.
  `occurrenceId` identifies one appearance in one run.

## Limits and safety

The workflow does not edit the reviewed files or apply fixes. Reports can
include remediation recommendations. Fabro can create its normal run and
metadata branches to store checkpoints.

Repository content is untrusted evidence. The agents are told to read it, not
to follow instructions found in it. They are also told not to build, test, or
execute the target. That instruction is not an enforcement boundary, so the
review runs in a disposable cloud sandbox.

Reviews are nondeterministic. A later run can find something that an earlier
run missed. An empty report means that the run found no panel-verified finding;
it does not prove that the target has no vulnerabilities. Use this workflow
with SAST, dependency scanning, and code review.

## More documentation

- [`index.html`](index.html) explains each workflow phase and shows the
  agent prompts.
- [`sample.html`](sample.html) shows the generated HTML report with fictional
  data.
- [`DEVELOPING.md`](DEVELOPING.md) covers repository structure, design rules,
  tests, and release checks.
