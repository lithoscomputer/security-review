# Security Review

Security Review runs an adversarial, read-only security review of a Git
repository. A team of agents maps the target, looks for vulnerabilities, and
tries to disprove each candidate. Only findings that pass a three-voter
verification panel reach the report.

This project holds two workflows for [Fabro](https://fabro.sh/). Fabro is
required to run them.

| Workflow | Takes | Produces |
| --- | --- | --- |
| `security-review` | A repository | A report of verified findings |
| `suggest-security-patches` | One finding from that report | A reviewed patch, as a draft pull request |

The review is read-only. The patch workflow writes to its sandbox checkout and
opens a pull request, so it has a different trust model — see
[Suggest security patches](#suggest-security-patches) before you run it.

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
| `base` | Git revision | Auto-detected | In `changes` mode, compare the current revision with this revision. |
| `range` | `base..HEAD` | Empty | In `changes` mode, review an explicit two-sided revision range. |
| `commit` | Git revision | Empty | In `commit` mode, review this commit against its parent. |
| `focus` | `attack-surface`, `none` | Automatic | Focus on reachable production code, or turn that focus off. |

The main run configuration clones the complete Git history. This lets change
and commit scans resolve older revisions without fetching during the review.

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
```

When `base` is empty, the workflow tries the branch upstream, then
`origin/HEAD`, `origin/main`, `origin/master`, `main`, and `master`.

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
| Duplicate review | 120 minutes | 1 |

The workflow also has a four-hour stall timeout. Any workflow event resets
that timer.

A deterministic stage failure stops the run at that failed stage. Agent
failures that the workflow tolerates reduce recorded coverage. An inventory
failure falls back to a whole-target review plan.

After verification, one advisory duplicate review compares surviving findings
by root cause. It never deletes a finding from the canonical evidence. The
reports move confirmed duplicates to an appendix and keep their primary
finding in the headline counts. If this agent fails or returns an invalid
answer, the workflow publishes every verified finding as a primary.

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

The workflow uses a closed taxonomy of 55 rule slugs grouped under 12 display
categories. Researchers choose a `ruleId`; deterministic code derives the
category from its first segment. The schema, prompt, renderer, and
`schemas/taxonomy.json` must agree before a run starts.

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

## Suggest security patches

The second workflow takes one finding from a report and produces a fix, opened
as a **draft pull request** against the branch the run cloned, one finding per
run. It needs no human input unless planning finds a product decision that
materially changes the safe patch.

One agent plans the fix and a second reviews and repairs that plan before any
code changes. The reviewed plan states the observable security objective that
the current patched code must enforce. Either planning agent asks the owner
directly only when a product decision materially changes the safe patch, then
incorporates the answer before it finishes. The run remains blocked until that
question is answered or canceled. After implementation, six agents review the
patch in parallel:
exploit closure, new attack paths, compatibility and behavior, completeness and
evidence, design economy, and performance and lifetime. A consolidator returns
`clean`, `fix`, or `decline`. Blocking findings control that outcome. Directly
related residual risks are recorded separately and do not cause a fix or
decline. A finding blocks only when the current patched code violates the
approved security objective, or the patch creates or worsens a concrete risk.

One `fix` result permits one focused fixup. All six review lanes then run again.
A second blocking result declines the patch. Every product calls the result a
**reviewed patch** — never verified or tested. A failed stage exits the run and
cannot publish a patch.

All agent stages use GPT Sol. Planning and consolidation use `max` reasoning;
implementation and review use `high`; fixup uses `xhigh`. The fallback order is
Opus, then Moonshot Kimi K3, then OpenRouter Kimi K3. Kimi K3 does not support
`xhigh`, so only Opus is an effective fallback during fixup.

### Run it

Build the goal from a report, then run:

```bash
python3 .fabro/workflows/suggest-security-patches/scripts/make_goal.py \
  SECURITY-REVIEW-20260826-101500 F3 > finding.json

fabro run \
  --goal-file finding.json \
  .fabro/workflows/suggest-security-patches/workflow.toml
```

`make_goal.py` refuses anything the run would refuse later, so problems surface
at your terminal instead of after a sandbox starts.

The finding travels as the run's goal, not as an input. Fabro renders the goal
as a template, so a finding whose text contains `{{`, `{%`, or `{#` cannot be
passed through unchanged; `make_goal.py` names the field and offset and stops.
Do not edit the finding to get around this — that changes the evidence the
patch is judged against. Patch such a finding by hand.

### What you get

A completed run opens a draft pull request whose diff is the fix alone, and
writes a `SECURITY-PATCH-<timestamp>/` bundle you collect with
`fabro artifact cp <RUN_ID>`:

| File | Purpose |
| --- | --- |
| `PATCH.md` | The note to read first: what changed, what review established, and that no tests were run. |
| `patch.diff` | The reviewed diff, byte-faithful, if you would rather apply it yourself. |
| `verdict.json` | The canonical record: review lanes, blocking findings, residual risks, consolidation, review round, claims, base commit, and patch SHA-256. |
| `DECLINED.md` | Written instead when no patch was earned, with the blocking review result and the reason. |

A declined run opens no pull request. The note carries the consolidated reason
and the report's original recommendation so you still have somewhere to start.

### It runs no tests

By design. Review confidence rests on reading the change and its callers, never
on a test run, and every product says so in those words. Wire your own
verification — a test suite, a linter, or a type checker — into the clean route
between `merge_consolidation` and `finalize`, with failure routed to `no_patch`.

### Before you point it at a repository

This workflow writes to its sandbox checkout and publishes. Three things follow
from that, and none of them are optional reading.

**Use it only on repositories you trust.** It inherits the trust model of a
maintainer fixing their own code. Fabro embeds a `contents: write` installation
token in the sandbox's git origin URL — it needs one to push checkpoints — and
any process in that sandbox can read it. Untrusted repository content plus an
agent that reads it is exactly the prompt-injection setup that turns into a
pushed branch. Point the read-only `security-review` workflow at code you do
not trust; point this one only at code you own.

**Narrow the installation, and protect the target.** Scope the Fabro GitHub App
installation used for these runs to the target repository alone, so the minted
token reaches nothing else, and enable branch and tag protection so a rogue ref
cannot become a release path. The draft pull request plus your review is the
merge gate.

**A draft pull request is not private.** The shipped `workflow.toml` opens one
on every successful run — that is what the workflow is for — which means a run
against a **public** repository discloses the patch and the finding the moment
it publishes. Nothing in the sandbox can detect repository visibility, so this
is yours to get right. For a public repository, or a finding under embargo, use
the artifacts-only configuration instead:

```bash
fabro run --goal-file finding.json \
  .fabro/workflows/suggest-security-patches/workflow-embargo.toml
```

It disables pull-request creation *and* run-branch and metadata-branch pushing,
because disabling the pull request alone would not hold an embargo: Fabro
pushes the run branch after every checkpoint. Nothing leaves the sandbox but
the artifacts. Apply the patch and open the pull request yourself when
disclosure is acceptable. If a finding's evidence quotes a live credential,
rotate it first and do not run with pull-request creation enabled.

### Known gap: repository hooks at checkpoint

Fabro's checkpoint commit runs repository git hooks. `[run.checkpoint]
skip_git_hooks = true` — set in every configuration here — becomes
`git commit --no-verify`, which does not suppress `post-commit`. Checkpoints
run after every node, so a generator that installs a hook has it execute at its
own node's checkpoint, before any later node could restore anything. No
workflow can close this from inside; it is filed upstream as
[fabro-sh/fabro#809](https://github.com/fabro-sh/fabro/issues/809).

The engine reports what it sees — it repoints `core.hooksPath` at a directory
it owns, checks it at every deterministic node, and records deviations in
`PATCH.md` and `verdict.json` — but treat that as a signal, not a control. The
trusted-repository rule above is the control.

### Attempts stay in the run branch

Fabro commits and pushes every node's state, so the original patch and any
fixup remain in `fabro/run/<id>` history. A decline restores the final tree to
the base without rewriting that history. The pull request's final diff is only
the reviewed patch and equals `patch.diff`, but earlier attempts remain visible
to anyone reading the branch. If an attempt must never leave the sandbox, use
the artifacts-only configuration.

## More documentation

- [`index.html`](index.html) explains each workflow phase and shows the
  agent prompts.
- [`sample.html`](sample.html) shows the generated HTML report with fictional
  data.
- [`DEVELOPING.md`](DEVELOPING.md) covers repository structure, design rules,
  tests, and release checks.
