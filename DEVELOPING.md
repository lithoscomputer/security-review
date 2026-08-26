# Developing Security Review

This guide is for people who change the workflows. See [`README.md`](README.md)
for user instructions. See [`index.html`](index.html) for a visual guide
to the phases and agent prompts.

This repository holds two workflows. `security-review` reviews a repository and
reports findings. `suggest-security-patches` takes one of those findings and
produces a fix. They share conventions and a repository, not code: each
directory is self-contained, so either can be copied into a target repository
on its own.

## Repository layout

Everything that a review runs lives under
`.fabro/workflows/security-review/`:

| Path | Contents |
| --- | --- |
| `security-review.fabro` | The workflow graph, direct phase routing, and deterministic steps. |
| `workflow.toml` | The normal run configuration. It clones full history for arbitrary revision inputs. |
| `verify.toml` | A `low`-effort smoke run against the current command-injection fixture. It keeps Fabro's shallow-clone default. |
| `scripts/security_review.py` | The deterministic engine. It owns state transitions, limits, deduplication, and vote tallies. |
| `scripts/render_report.py` | Validates the canonical bundle and derives the Markdown, HTML, JSONL, and revision reports. |
| `scripts/git_readonly.py` | A read-only Git entry point with external diff and text conversion drivers disabled. |
| `templates/report.html` | The self-contained HTML report template. |
| `prompts/*.md.j2` | MiniJinja prompt templates for inventory, threat modeling, research, sweeping, verification, and red-team work. |
| `prompts/partials/` | Shared MiniJinja prompt content. |
| `schemas/` | Model response schemas and versioned canonical bundle contracts. |
| `specs/report-spec.md` | Canonical bundle relationships and deterministic report rules. |
| `fixtures/` | The command-injection fixture used by the smoke run. |

Everything the patch workflow runs lives under
`.fabro/workflows/suggest-security-patches/`:

| Path | Contents |
| --- | --- |
| `suggest-security-patches.fabro` | The workflow graph, routing, and deterministic steps. |
| `workflow.toml` | The normal run configuration. Opens a draft pull request. |
| `workflow-embargo.toml` | Artifacts-only: no pull request, no branch pushes. For public repositories and embargoed findings. |
| `verify.toml` | A smoke run against the command-injection fixture. Publishes nothing. |
| `scripts/suggest_patches.py` | The deterministic engine. It owns routing, the changed set, restoration, diff capture, and the products. |
| `scripts/make_goal.py` | Builds and validates the goal file from a report, before any run starts. |
| `scripts/git_readonly.py` | The read-only Git entry point, duplicated from the scan workflow. |
| `prompts/*.md.j2` | Generator, verifier, and adversarial prompts. |
| `prompts/partials/` | Shared prompt content, **duplicated** from the scan workflow so the directory installs alone. The copies may diverge; no test asserts they match. |
| `schemas/` | The finding input contract, the three agent contracts, and the `verdict.json` record contract. |
| `specs/patch-spec.md` | What the products are and the rules the engine follows. |
| `fixtures/` | The command-injection fixture and the finding that points at it. |

The `tests/` directory contains both test suites and two developer tools:

- `build_sample_report.py` regenerates `sample.html`.
- `repin_support_files.py` refreshes support-file hashes in both workflow
  graphs.

The repository root also contains:

- `README.md` for users.
- `index.html` for the detailed workflow guide.
- `sample.html` for the generated example report.

## Design rules

### Keep the review read-only

The `security-review` workflow reports findings and recommendations. It does
not modify reviewed files or apply fixes.

`suggest-security-patches` is the deliberate exception: its generator edits the
sandbox checkout, and its result is published. That difference is why it needs
integrity rules the review does not — see "The patch workflow does not trust
its own tree" below. The rule to hold onto is that the *review* stays read-only,
so it remains the workflow you can point at code you do not trust.

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

The graph uses `on_failure="exit"`. A failed node stops unless an explicit
recovery edge matches. Keep `outcome=succeeded` on each non-default conditional
edge so stale context cannot become a recovery route. An unconditional default
edge is safe because Fabro skips it after a failure. Inventory is the exception:
its explicit failure edge records the fallback before the workflow continues.

### Integrity checks protect publication

The workflow pins the SHA-256 hashes of the deterministic engine, Git wrapper,
renderer, report specification, and report template. `prepare` checks these
hashes before the review starts.

`prepare` also records a digest of the target tree. Publication steps check the
digest again. The workflow refuses to publish a report if the tree changed
during the review.

### The patch workflow does not trust its own tree

The generator can write anywhere in the checkout, so nothing downstream of it
takes the tree at face value.

Paths are compared exactly as Git spells them, read NUL-delimited
(`git diff --name-status -z`, `git ls-files -z`). Do not trim them or rewrite
separators before comparing: `a\b.py` and `a/b.py` are different files on
Linux, surrounding whitespace is a legal part of a name, and normalizing would
let a path the reviewer never looked at satisfy the check for one it did. The
read-only Git wrapper is strict for a related reason — its hardening flags are
positional, so `--textconv` and `--no-index` are refused outright, and bare
filesystem operands are rejected because `git diff` enters no-index mode on its
own when handed two paths.

The changed set comes from Git — `git diff <base>..HEAD --name-status` — never
from the generator's `changedFiles`. Fabro checkpoints after every node, which
means it has already staged and committed the generator's work before the
engine looks; a staged (`--cached`) diff would be empty. The verifier's
`reviewedPaths` is cross-checked against that derived set, and a disagreement
stops the run rather than delivering bytes nobody reviewed.

The delivered bytes must be the reviewed bytes, and the expected value has to
live somewhere the agents cannot reach. Every node is followed by a checkpoint
that commits whatever the tree holds, reviewers included, so a reviewer that
wrote to the tree would otherwise have its writes folded into the patch after
review had already passed. The change is fingerprinted when review begins and
the fingerprint is emitted into **Fabro's run context** as `review_pin` —
server-side, outside the sandbox — and read back by `finalize` through
`stdin_source`. `finalize` trusts the pin over the state file and refuses to
publish if the two disagree.

The base commit is trusted the same way, and for a sharper reason. `prepare`
emits `patch_base` into context, and `pin_review`, `revise`, and `no_patch`
each read it back through `stdin_source`. A base forged in the state file makes
a real change measure as empty, which routes to a decline; a decline that
restored to that forged base would leave the change in the run branch and hand
publication a non-empty diff, so a declined run would open a pull request for
an unreviewed patch. `assess_change` spends its stdin on the
generator's output, so rather than read a base from the state file it reads
none and runs no Git at all: it records what the generator said. Every
measurement — the changed set, the protected-path check, the fingerprint, and
which way the run goes — belongs to `pin_review`, from the trusted base.

That distinction is the point, and it is easy to undo by accident: the engine's
state file lives in the checkout the generator can write, so **nothing that
decides what gets published may be trusted from it**. The two merge steps do
run an early fingerprint check against the state file; it is named
`advisory_diff_check` and commented as a convenience, not a boundary. Keep it
that way. Note the residual, too: the claims text and summary in the products
are still state-derived, bounded only by the fact that routing runs on
context flags Fabro holds. `stdin_source` carries one key, which is why there
is not a second trusted channel.

Support files are re-checked at every deterministic node, not once. Each node's
`script` line repeats the SHA-256 check before running the engine, because a
check in `prepare` would not survive the generator's node. A patch touching the
workflow's own directory declines the unit; `fixtures/` is the one exception,
since the smoke run's whole job is to patch one and a fixture decides nothing.
The engine's own `runtime/` is dropped from the changed set entirely — it is
bookkeeping, neither part of the patch nor evidence of tampering.

Restoration never rewrites history. Fabro pushes the run branch after every
checkpoint, so `reset --hard` would strand the local branch behind its remote.
Both the revision round and the decline path restore in place with
`git restore --source=<base> --staged --worktree` and `git clean -fdx`, letting
the next checkpoint record the restoration as a forward commit. A decline then
asserts the content matches the base and no untracked file survives; that
invariant is the only thing between a rejected attempt and an opened pull
request, because Fabro skips pull-request creation exactly when the final diff
is empty.

Repository hooks at checkpoint remain an open gap
([fabro-sh/fabro#809](https://github.com/fabro-sh/fabro/issues/809)). The
engine reports hook deviations; it cannot prevent them. Do not write code or
documentation that implies otherwise.

### Products say what they are

The patch workflow runs no tests, so no product may call a result "verified" or
"tested" without qualification. The label is **reviewed patch**. In
`verdict.json`, review confidence (`claims`) and testing (`untested`,
`testsRun`) are separate fields, and `PATCH.md` leads with the absence of tests
rather than burying it. A test asserts this.

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
- Update related files under a workflow's directory together. This includes the
  graph, run configurations, prompts, schemas, scripts, specifications, and any
  template.
- Keep a workflow's run configurations aligned where they share settings and
  artifact declarations. The patch workflow has three — `workflow.toml`,
  `workflow-embargo.toml`, and `verify.toml` — and tests assert the settings
  that must hold in all of them.
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

Do not edit support-file hashes by hand. The tool covers both graphs. The patch
workflow pins the same files once per deterministic node, so one edit to its
engine rewrites several lines; that repetition is the point, not an accident.

## Run the tests

Run both suites before you finish:

```bash
python3 tests/test_fabro_workflow.py
python3 tests/test_suggest_security_patches.py
```

The first drives the review engine with fabricated agent output. It also checks
graph routing, support-file hashes, concurrency limits, prompt contracts, the
generated sample report, and documentation naming.

The second builds a throwaway repository shaped like the sandbox — including
Fabro's commit-after-every-node checkpoint, which several behaviours depend on
— and drives the patch engine through it with fabricated agent output. It
covers the changed-set matrix, the tampering rules, the claim arithmetic, the
owner-question budget, delivery, and the decline invariant, plus the graph and
configuration contracts.

Both graphs should also parse:

```bash
fabro validate .fabro/workflows/security-review/security-review.fabro
fabro validate .fabro/workflows/suggest-security-patches/suggest-security-patches.fabro
```

`validate` checks structure, not attribute names — it accepts an attribute that
does not exist. When you add or change a node attribute, confirm it against the
Fabro source or `docs/public/reference/dot-language.mdx` rather than trusting a
clean validation.

## Run the smoke runs

For an end-to-end change, run the smoke run for the workflow you touched:

```bash
fabro run .fabro/workflows/security-review/verify.toml

fabro run \
  --goal-file .fabro/workflows/suggest-security-patches/fixtures/finding-command-injection.json \
  .fabro/workflows/suggest-security-patches/verify.toml
```

The smoke review uses `low` effort against the command-injection fixture. It
must report exactly one verified finding.

The smoke patch run must produce a reviewed patch in the artifacts and open no
pull request. It patches this repository's own fixture, which is why
`fixtures/` is exempt from the rule against a patch touching the workflow's
directory.

Push the branch first. The sandbox clones the pushed branch, not the local
working tree. It cannot see uncommitted prompt or engine changes. An unpushed
change to a pinned support file makes the first deterministic node fail its
hash check.
