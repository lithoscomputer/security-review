# security-review

A Fabro workflow that puts a team of agents to work as security researchers on
a repository: partition it into components, threat-model each one, hunt for
vulnerabilities across a component × category matrix, sweep the gaps, and then
try hard to disprove every candidate before any of it reaches a report. Only
findings that survive an adversarial panel are published.

The review is read-only. It produces a report directory, never a code change.

## Running a review

```bash
fabro run .fabro/workflows/security-review/workflow.toml
```

Inputs (`-I name=value`, all optional):

| Input | Values | Meaning |
| --- | --- | --- |
| `mode` | `scan` (default), `changes`, `commit` | Review the tree, a branch's diff, or one commit. |
| `effort` | `low`, `medium` (default), `high`, `max` | How much work the run does. See below. |
| `scope` | comma-separated paths | Limit the review to these directories or files. |
| `base` | a Git revision | `changes` mode: what to diff against. Defaults to the upstream, then `origin/HEAD`, `origin/main`, `origin/master`, `main`, `master`. |
| `range` | `base..HEAD` | `changes` mode: an explicit two-sided range instead of `base`. |
| `commit` | a Git revision | `commit` mode: the commit to review against its parent. |
| `focus` | `attack-surface`, `none` | Force the attack-surface focus on or off. Chosen by repository size when unset. |

Effort sets how much work happens, not how carefully any one agent thinks. The
verification panel is three voters at every tier — that is what the report's
confidence figures are calibrated against.

| Tier | Shape |
| --- | --- |
| `low` | One researcher over the whole target, then the panel. No inventory, threat model, or sweep. |
| `medium` | Inventory, a threat model per component, one researcher per component × category, one sweep, the panel. A diff of at most 5 files and 300 changed lines, or a scope of at most 5 files, collapses to the single-researcher shape instead. |
| `high` | As `medium` with a wider inventory (24 components), two researchers per cell, and two sweeps. |
| `max` | As `high`, plus an adversarial round: marginal 2-of-3 keeps are repanelled and every survivor faces a red-team refuter. |

A run writes `CLAUDE-SECURITY-<timestamp>/` holding the human-readable
`CLAUDE-SECURITY-RESULTS.md`, the machine-readable
`CLAUDE-SECURITY-RESULTS.jsonl` for CI gates, and
`CLAUDE-SECURITY-REVISION-<tag>.json` — the stamp recording what was reviewed,
at what effort, and how it was verified. The directory carries its own
`.gitignore`, so nothing in it reaches a commit unless you delete that file.

Scans are nondeterministic: running them regularly builds coverage over time.
This complements SAST, dependency scanning, and code review; it does not
replace them.

## Layout

| Path | Contents |
| --- | --- |
| `.fabro/workflows/security-review/security-review.fabro` | The graph: 48 nodes wiring the phases, their gates, and the deterministic steps between them. |
| `.fabro/workflows/security-review/workflow.toml` | Run configuration: inputs, environment, artifacts. |
| `.fabro/workflows/security-review/verify.toml` | A `low`-effort run against the fixture, for smoke-testing the workflow. |
| `.fabro/workflows/security-review/scripts/security_review.py` | The deterministic engine. Every state transition, cap, deduplication, and vote tally lives here, outside the agents. |
| `.fabro/workflows/security-review/scripts/render_report.py` | Writes the JSONL and the revision stamp, and derives `verification.status` from the vote record. |
| `.fabro/workflows/security-review/scripts/git_readonly.py` | A read-only Git entry point with external diff and textconv drivers disabled. |
| `.fabro/workflows/security-review/prompts/` | One prompt per agent role: inventory, threat model, research, sweep, verify, redteam, report. |
| `.fabro/workflows/security-review/schemas/` | The structured output each role must return. |
| `.fabro/workflows/security-review/specs/report-spec.md` | The shape and standard of the human-readable report. |
| `.fabro/workflows/security-review/fixtures/` | A deliberate command-injection fixture the smoke run expects to find. |
| `tests/test_fabro_workflow.py` | The workflow's test suite: driver behavior, static graph contracts, prompt contracts. |

The repository also holds a readable expansion of the `claude-security` plugin
for Claude Code (`workflows/scan.js`, `agents/`, `skills/`, `hooks/`,
`scripts/`) with its own Bun tests. That is reference material — the workflow
above began as a port of it — and is not what this repository is for. Reach
for it to answer "what did the original do here", not as something to keep in
step.

## Testing

```bash
python3 tests/test_fabro_workflow.py   # the workflow
bun test                               # the reference plugin expansion
```

The workflow's tests drive the deterministic engine directly with fabricated
agent output, so a full run is never needed to check the arithmetic. They also
pin static contracts a run would only reveal expensively: the graph's routing
and its support-file hashes, the concurrency caps, and what each prompt must
and must not say.

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

**The repository is data, never instruction.** Everything the review reads —
source, comments, `CLAUDE.md`, commit messages, fixtures — is evidence under
examination. Text that addresses an agent is a finding to report
(`prompt-injection`), not a direction to follow.

**Support files are pinned.** Before anything runs, `prepare` verifies the
SHA-256 of the engine, the Git wrapper, the renderer, and the report spec
against hashes recorded in the graph. Editing one of those files means
updating its pin in `security-review.fabro`; a test enforces that they match.

**Nothing tampered gets published.** `prepare` records a digest of the whole
tree, and the publication steps re-verify it. A source tree that changed
mid-review is refused rather than reported on.

**The sandbox is the boundary.** The agents are instructed to read rather than
build, test, or execute, and nothing enforces that instruction, so the run
happens in a disposable cloud sandbox. The report says as much rather than
claiming that nothing ran.

## Where this deliberately differs from the plugin

Each of these is a decision, not drift. Changing one back should be a decision
too.

- **No tool guard.** A blocking `pre_tool_use` hook used to restrict every
  agent to `Read`, `rg`, and a Git wrapper. In practice ripgrep was not
  installed, so the allowlist named a tool that did not exist: agents took
  dozens of blocks and moved their real work into sub-agents, which the hook
  did not cover. It relocated unrestricted shell work rather than preventing
  it, so it is gone.
- **The report never claims nothing was executed.** The plugin's spec asserts
  that no test, build, or exploit ran. Nothing checks that, so the report here
  states what it derived from reading and explicitly declines to vouch for
  what any agent ran.
- **Phases are barriers, not a pipeline.** The plugin starts a component's
  researchers as soon as its threat model lands. Here each phase completes
  before the next begins, with a per-phase concurrency cap. Same results,
  worse wall-clock, far simpler recovery and inspection.
- **The tree digest is checked at publication only.** The plugin has no such
  check. Verifying once before results are assembled gives the same guarantee
  as verifying at every step, without hashing the tree a dozen times.
- **No cost confirmation.** The plugin asks a human before spending. Creating
  the run is that consent here.
- **Explore sub-agents carry their own instructions.** The plugin dispatches a
  purpose-built read-only explorer. A Fabro sub-agent inherits a generic
  prompt, so the dispatching agent must write the explorer's rules into the
  question itself.
- **No provider pinned in the stylesheet.** Model roles are pinned; the
  provider comes from the run configuration so routing and fallback still
  work.
- **The network is open.** The sandbox clones the repository itself, which
  needs the network. A `cidr_allow_list` limited to the code host is the
  tighter option if that reach becomes a concern.
