# Fabro security-review workflow vs. claude-security plugin — gap report

Date: 2026-07-29
Compared: `.fabro/workflows/security-review/` (the port) against `workflows/scan.js`,
`agents/`, `skills/claude-security/`, and `scripts/` (the plugin expansion).

## Summary

The core scan engine is a faithful port. Every numeric threshold, the dedup and
vote arithmetic, the panel rules, the max-effort adversarial round, the result
contract, and the report renderer match the plugin exactly. The renderer
(`render_report.py`) and the report spec are byte-identical on both sides, and
the graph pins every support file by SHA-256 (all pins verified current).

The gaps cluster in three places:

1. **The `focus` (attack-surface) feature is wired but inert** — its semantics
   never reach any agent prompt.
2. **Failure handling is harsher than the plugin in two spots** — a dead
   inventory agent or report author aborts the whole run instead of degrading.
3. **Capability trims that are plausible Fabro adaptations but are not written
   down anywhere** — no explore subagent, output token caps, a fuller candidate
   object shown to verifiers, and a new range-check duty for verifiers.

Everything else is either confirmed parity or a clear improvement (deterministic
target resolution, enforced read-only guards, stricter input normalization).

## What maps to what

| Plugin | Fabro port |
| --- | --- |
| Skill/job recipes (target resolution, sizing, scan-meta) | `security_review.py prepare` |
| `scan.js` orchestration (phases, retries, tallies) | `security-review.fabro` graph + `security_review.py` merge/plan/tally commands |
| Agent frontmatter prompts (`agents/*.md`) | `prompts/*.md` |
| `scan.js` structured-output schemas | `schemas/*.json` |
| Agent tool declarations (`tools:` frontmatter) | `tool_guard.py` blocking hook + `git_readonly.py` |
| Security Lead writes RESULTS.md per report spec | `report_author` node + `prompts/report.md` |
| `render_report.py`, `specs/report-spec.md` | Identical copies, loaded via `renderer.render()` |

## Confirmed parity

- Caps and thresholds: candidate cap 400, verification cap 45, small diff
  5 files / 300 lines, small scope 5 files, components 12 / 24 expanded,
  researchers per cell 1 / 2, sweeps 0 / 1 / 2 + secrets sweep when focus is
  set on a `scan`-mode run, effort tiers and `medium` default.
- The four category lenses, the managed-language regex and the
  `memory-and-unsafe` pruning, the three verification lenses.
- Dedup key `(file, line, category)`, max-severity/max-confidence merge, the
  mergeable field list, ranking by severity → reports → confidence, and the
  `unreviewed_candidate_sites = unverifiedByCap + droppedUniqueCandidates`
  arithmetic.
- Panel rules: exactly 3 voters, keep needs 3 returned and ≥2 TRUE_POSITIVE;
  max effort repanels only 2/3 keeps, red-teams every survivor, and an
  incomplete adversarial round never overturns the first panel. Vote counting
  matches (the parity test pins 7 votes for the 3+3+1 case).
- Kept-then-rejected renumbering to F1..Fn, findings/votes/coverage result
  shape, `exploit_scenario` falling back to `rationale`.
- One inventory correction round, then accept-with-unaccounted or fall back to
  a single whole-repository component; the same `inventoryFallback` reasons;
  the same whole-target-skip and traversal rejections; completeness outcomes
  `checked`/`partial`/`not-checkable`/`not-applicable` including the
  "empty topLevelDirs but subdirectory paths" case.
- Changes/commit resolution: same base-ref default order (upstream,
  `origin/HEAD`, `origin/main`, `origin/master`, `main`, `master`),
  merge-base ranges, binary-row diffs treated as "not small", empty diff/scope
  short-circuits with no scan.
- Retry budget: `max_retries=2` per agent node mirrors the two-retry
  `runAgentWithRetry` wrapper; missing researchers degrade to
  `researchers_returned < researchers_dispatched` in both.
- Model/effort assignments match the plugin agent frontmatter: inventory
  sonnet/medium, threat model opus/medium, research and verification
  opus/xhigh, report author opus/xhigh (pinned by a test).

## Gaps (ordered by importance)

### 1. `focus=attack-surface` is accepted but its meaning never reaches agents — HIGH

In the plugin, `attackSurfacePrompt` is appended to the inventory,
threat-model, research, and non-secrets sweep prompts: *"focus on the attack
surface: production code that handles input, requests, files, credentials, or
executes anything. Treat test files, fixtures, mocks, snapshots, generated
code, build output, vendored copies, and third-party dependency trees as
background… not as things to audit"* (`workflows/scan.js:689`).

In the port, `focus` flows into the appended `target` JSON as the bare string
`"attack-surface"` and nothing more. No prompt file mentions focus or attack
surface (verified by grep). So passing `--focus attack-surface` today changes
exactly one thing: whether the secrets sweep runs.

Two related losses:

- The secrets sweep ask drops the plugin's emphasis: *"for this pass the
  fixtures ARE in scope, since a real key committed to a test file is a real
  leak"* → the port says only "including tests, fixtures, and configuration".
- The plugin's Security Lead auto-sets focus for any large repository (the
  scan-codebase recipe's size gauge). The port has no size-based defaulting,
  so a large-monorepo run audits tests and vendored trees by default.

**Fix:** add the attack-surface paragraph to `inventory.md`,
`threat-model.md`, `research.md`, and `sweep.md`, keyed off the target's
`focus` field, and keep the secrets sweep exempt as the plugin does.

### 2. Inventory or report-author failure aborts the run — MEDIUM

- Plugin: if the inventory agent dies after retries, the scan falls back to a
  single whole-repository component and continues
  (`inventoryFallback: "inventory-failed"`). Port: the graph routes
  `inventory -> abort` on any non-success outcome, so a dead inventory kills
  the run. The fallback exists in `merge_inventory` but is only reachable when
  the node *succeeds* with unusable output.
- `report_author` has `max_retries=0` (every other agent node has 2) and
  routes to `abort` on failure. A flaky report author discards a run after all
  the expensive research and panel work is done. The plugin's Lead would just
  retry writing the report.

**Fix:** route inventory failure to `plan_matrix` with the
`inventory-failed` fallback recorded, and give `report_author` the same
`max_retries=2` as its peers.

### 3. Researchers and verifiers lost the explore subagent — MEDIUM

Plugin `scan-researcher` and `scan-verifier` can dispatch
`claude-security:explore` (a read-only code-mapping specialist) and are told to
use it for caller graphs and cross-file flows. The port's prompts forbid
subagents and the tool guard blocks them. Likely a Fabro platform constraint,
but it reduces depth on large components and is not documented as a deliberate
trade anywhere in the port.

### 4. Mid-run tree change aborts the scan; the digest is expensive — LOW/MEDIUM

`assert_workspace_unchanged` hashes every repository file before each
deterministic step (~10 times per run) and raises if anything changed. The
plugin runs against the live tree and just records `dirty` in the stamp.

- Fail-closed is a sound choice for a sandboxed cloud run.
- For a local run on a working tree, a single incidental file save mid-scan
  destroys the entire run with no report.
- Cost: a full-tree SHA-256 pass per step is O(repository) each time.

Worth documenting as intentional, and possibly skipping (or downgrading to a
warning recorded in coverage) when the run is not in a disposable clone.

### 5. Output token caps can silently shrink findings-dense results — LOW

The port sets `max_tokens`: 5000 (inventory, threat model), 7000 (research,
sweep), 3000 (verdict), 10000 (report). The plugin has no explicit caps, and
its own 400-candidate cap shows large result sets are expected. A researcher
with many findings can exceed 7000 tokens, burn its `output_retries`, and be
counted as "did not return" — losing all of its findings, not just the
overflow. Same concern for a 24-component inventory at 5000. The new 10 MB
stdin limit on merges is aligned with Fabro's transport (per the recent
commit) but is also a failure mode the plugin does not have.

### 6. Verifiers see more of the claim, and get one new duty — LOW

- The plugin's `formatFindingClaim` deliberately shows verifiers a subset:
  file, line, category, severity, title, rationale, evidence, snippet, symbol,
  and the report count. It withholds the reporter's confidence, impact,
  exploit scenario, and recommendation. The port passes the whole candidate
  object (including `confidence`, `reporters`, `id`) into the verification
  job. That extra context can anchor a panel that is supposed to be
  adversarial.
- `verify.md` and `redteam.md` add: for a change scan, confirm the range
  *introduces or exposes* the finding. The plugin enforces
  "change-introduced" only at research time; its verifier prompt never
  mentions the range. This is defensible — arguably better — but it changes
  what the panel kills, and it is an undocumented deviation.

### 7. Inventory correction feedback is much thinner — LOW

The plugin's rejection resend names the missing directories in a fenced block,
explains the component-cap rule, and coaches ("use broad shared-parent paths
where a per-directory listing would be long", "this is your one correction").
The port sends one compact sentence listing the problems. Same protocol, lower
odds the second answer is complete. The port also adds schema-error-based
corrections the plugin does not have (fine, mild improvement).

### 8. Unknown effort tier is coerced silently — LOW

`scan.js` logs `unknown effort "X" -- using medium`. `prepare` silently
defaults. It also validates `mode` strictly (raises) while `effort` is
silent — inconsistent. One-line fix: print the same notice.

### 9. Plugin surface deliberately not ported — INFORMATIONAL

These are absent by design and look justified, but the port has no document
saying so:

- **suggest-patches job** (patch-generator, patch-verifier, `patch_artifacts.py`,
  patch-spec): the port is scan-only, consistent with its read-only goal.
- **Front-desk menu, cost confirmation, kickoff/delivery messaging, banner
  hook**: replaced by Fabro's run lifecycle — creating the run is the consent.
  Note the flip side: the plugin refuses a bare invocation; the port's
  defaults (`mode=scan`, `effort=medium`) make a bare run a full whole-tree
  scan.
- **Pull-request search**: needs `gh` and the network; the port blocks the
  network entirely (improvement).

## Deviations that are improvements (justified)

- **Deterministic target resolution.** `prepare` computes diff stats, scope
  counts, and top-level directories from git itself, so the plugin's whole
  "rejected size" machinery (`diffSizeRejected`, `scopeSizeRejected`,
  `topLevelRejected` for mangled Lead-transcribed values) becomes structurally
  impossible; the coverage fields are kept and hardwired null so the shared
  renderer and spec still work.
- **Enforced read-only.** The plugin's researchers get full Bash and are told
  not to write/build/fetch. The port enforces it: blocking `pre_tool_use`
  guard (fail-closed), an rg allowlist with option validation, the
  `git_readonly.py` wrapper (subcommand + option allowlist, no shell), network
  mode `block`, `GITHUB_TOKEN`/`GH_TOKEN` blanked, and the report author
  limited to reading run inputs and writing exactly one file.
- **Supply-chain pinning.** The graph verifies SHA-256 of the driver, guard,
  wrapper, renderer, and spec before running (pins verified current; a test
  enforces them).
- **Stricter finding normalization.** Path-safety normalization, `line >= 1`,
  category slugification (better dedup: "SQL Injection" and "sql-injection"
  now merge; the plugin's key would not), text caps.
- **Edge-case fixes.** Root commit handled via the empty-tree hash (the
  plugin's `<sha>^` fails on a root commit); explicit two-sided `--range`
  input; report-directory name collision suffix; an empty target creates no
  report directory at all (the plugin creates it before the workflow runs and
  leaves an empty stub behind on an empty diff).
- **Recorded models.** scan-meta records the actual models/provider; the
  plugin writes `model: null`.
- **Run-dir retention.** The port calls `renderer.render()` and deliberately
  skips `remove_run_dir`, keeping scratch records in the sandbox while the
  artifacts filter exports only the final bundle. Equivalent user-facing
  products; better auditability.

## Neutral structural deviations

- **Barriers instead of pipelining.** The plugin pipelines per item (a
  component's researchers start as soon as its threat model lands; a
  candidate's repanel/red-team follows its own panel). The port runs each
  phase as a full barrier with per-phase `max_parallel` (4/8/3/12/12/4).
  Results are identical; wall-clock is worse on wide runs.
- **Provider pinning.** The stylesheet pins `provider: openrouter`; the plugin
  inherits the user's session models. Environment choice.
- **Additive fields.** `coverage.invalidResearchResults`, `coverage.range`,
  and the provisional `verification` object in `final.json` are new; the
  shared renderer ignores unknown fields, so nothing breaks.

## Nits

- `top_level_directories()` misses a tracked top-level gitlink (a submodule at
  the root): the plugin's `write_scan_meta.py` counts a tracked path that is a
  directory; the port only counts paths containing `/`.
- The plugin's inventory correction adds the cap-overflow warning whenever
  components overflow; the port adds it only when directories are also
  unaccounted.
- The plugin logs rich diagnostics for every decision (pinned by its test
  suite); the port's deterministic steps print terse one-liners. Cosmetic, but
  some plugin log lines carry user-facing meaning (for example the collapsed
  shape explanation) that only survives in the port's coverage record.

## Suggested order of work

1. Port the attack-surface prompt text and the secrets-sweep emphasis (gap 1).
2. Wire inventory failure to the whole-repo fallback; give `report_author`
   retries (gap 2).
3. Decide and document: explore subagent (gap 3), workspace-digest policy
   (gap 4), token caps (gap 5), verifier claim subset + range duty (gap 6).
4. Small fixes: correction-feedback wording (7), effort warning (8),
   submodule top-level edge (nits).
