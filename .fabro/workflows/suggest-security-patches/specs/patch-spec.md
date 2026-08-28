# Patch products specification

What one `suggest-security-patches` run leaves behind, and the rules the
deterministic engine follows to produce it. Agents plan, review the plan,
implement, review in seven lanes, consolidate, and perform at most one fixup.
`suggest_patches.py` owns routing and writes every product.

This mirrors the scan workflow's `report-spec.md`: the model judges, the code
decides, so no reviewed byte and no confidence claim is ever re-typed by a
model on its way to a person.

## The two deliverables

A run delivers through two channels, and they carry different things.

| Channel | Carries | Written by |
| --- | --- | --- |
| The pull request | The fix itself, as the run branch's final diff | Fabro's publish stage, from the committed tree |
| `SECURITY-PATCH-<ts>/` | The record: what was claimed, on what evidence, against which base | This engine, checkpoint-excluded so it never enters the diff |

The products directory is excluded from checkpoints, so the pull request's diff
holds only the fix. The directory reaches the operator as run artifacts
(`fabro artifact cp <RUN_ID>`), not through the branch.

## The products

| File | Content |
| --- | --- |
| `patch.diff` | The reviewed diff, byte-faithful. |
| `verdict.json` | The canonical record, versioned by `recordVersion`. |
| `PATCH.md` | The note a person reads: what changed, what review established, and — first, not buried — that no tests were run. |
| `DECLINED.md` | Written instead of `PATCH.md` when no patch was earned: the blocking claim, the reason, the rejected attempt's diffstat, and the report's original recommendation. |

### `patch.diff` — the byte contract

Captured with exactly:

```
git diff --binary --full-index --no-ext-diff --no-textconv \
  --src-prefix=a/ --dst-prefix=b/ <base> HEAD
```

`--binary` and `--full-index` keep binary and mode changes faithful; the
`--no-ext-diff` and `--no-textconv` pair stops a repository from pointing the
diff at a command or filter of its choosing. `GIT_EXTERNAL_DIFF` is cleared in
the environment for the same reason. The bytes are hashed into
`verdict.json.patchSha256`, which ties the reviewed content, the artifact, and
the pull request's change together.

### `verdict.json` — the canonical record

Shaped by `schemas/verdict-record.schema.json`. The fields that carry the most
weight:

| Field | Meaning |
| --- | --- |
| `status` | `patch_written`, `declined`, or `skipped_stale` |
| `base` | The 40-hex commit every reviewed byte applies to |
| `patchSha256` | SHA-256 of `patch.diff`, or null on a decline |
| `claims` | Review confidence only: `targeted`, `noNewVulnerability`, `behaviourUnchanged`, each `{state, evidence}` |
| `reviewLanes` | The latest seven focused review results, with blocking findings separate from residual risks |
| `consolidation` | The final `clean`, `fix`, or `decline` decision, verified blocking findings, and recorded residual risks |
| `reviewRound` | `1` initially or `2` after the one allowed fixup |
| `untested` | Always `true` |
| `testsRun` | Always the same sentence — this workflow runs no tests |
| `changedPaths` | The engine's Git-derived changed set, in name-status form |
| `reviewedPaths` | The completeness review's touched paths, cross-checked against the engine's set |
| `reviewedDiffSha256` | SHA-256 of the change as it stood when review began |
| `tamperingSignals` | Anything the integrity checks noticed, even on a successful run |

**Review confidence and testing are separate fields, deliberately.** A
`behaviourUnchanged` of `CONFIDENT` means confident *from reading the change and
its callers*. It never means runtime behaviour was checked, because nothing here
runs the project. Any product that blurs the two is wrong.

## Rules the engine follows

**The workflow plans before it edits.** Planning and plan review are mandatory.
Each planning agent asks the owner directly only when repository evidence and
project instructions cannot resolve a decision that materially changes the
safe patch. The answer returns to that agent, which incorporates it into the
complete plan. The plan states the observable security objective that the
current patched code must enforce. An unanswered question leaves the run
blocked until the owner answers or cancels it. The engine confirms that
planning left the checkout at the trusted base. If no safe plan exists, the run
declines.

**The changed set comes from Git, never from an implementer.** Fabro checkpoints
after every node — it stages and commits the tree before the next node starts —
so by the time the engine looks, the implementer's work is a commit and a staged
diff would be empty. The set is derived from `git diff <base>..HEAD
--name-status`. The implementer's `changedFiles` is advisory and never the
record.

**The completeness review's paths must match.** The comparison is exact. The
reviewer reports every path the change touches as a bare repository-relative
path. A disagreement or empty list stops the run.

Both sides are read NUL-delimited (`git diff --name-status -z`,
`git ls-files -z`). A filename may contain a space, a tab, or a newline, and
splitting Git's human-readable output on whitespace would corrupt precisely the
paths an attacker would choose.

**The delivered bytes must be the reviewed bytes, and the expected value must
live where agents cannot reach it.** Every node is followed by a checkpoint
that commits whatever the tree holds — a reviewer's writes included. Reviewers
are told to inspect and not modify, but an instruction is not a control:
without one, a reviewer's own checkpoint could fold new content into the patch
*after* review had passed on it.

So the change is fingerprinted with SHA-256 the moment review begins, and the
fingerprint is emitted into **Fabro's run context** as the `review_pin`, along
with the base commit. That distinction is the whole point: this engine's state
file lives in the checkout the implementers can write, so a fingerprint stored
only there could be rewritten to match a change made afterwards. Run context is
held by the Fabro server, outside the sandbox, and reaches `finalize` through
`stdin_source`.

**Every step whose outcome can reach publication reads the base from the run
context.** `prepare` emits `patch_base`; `check_plan_clean`, `pin_review`, and
`no_patch` each take it back through `stdin_source`. This is not
belt-and-braces. A base
forged in the state file makes a real change measure as no change at all, which
routes the run to a decline — and a decline that restored to that same forged
base would leave the change sitting in the run branch, giving publication a
non-empty diff to open a pull request from. A declined run would publish an
unreviewed patch. The trusted base is what makes a decline real.

`assess_change` spends its single `stdin_source` on an implementer's output, so
it could only obtain a base by reading the state file. It therefore obtains
none: it records the summary and refusal and performs no trusted measurement.
Every publication measurement belongs to `pin_review`,
which reads the trusted base and decides where the run goes through one routing
key. There is no step left that measures the tree against a value an agent
could choose.

`finalize` therefore trusts the pin over the state file. It refuses to publish
if the state file's base or fingerprint disagrees with the pin — a disagreement
means the file was edited during the run — and it derives the patch from the
pinned base and checks the result against the pinned fingerprint. A mismatch
stops the run; nothing is published. Earlier review checks
read the state file instead and are labelled in the code as advisory: they fail
fast on an honest mistake and are not a boundary.

**What remains state-derived.** The claims text, review summaries, the
completeness review's `reviewedPaths`, and the finding fields are read from the
state file, so a reviewer agent that wrote to the checkout could make a product
misreport them. (The published `changedPaths` is not among them: it comes from
the pin, so what a reader is told the patch touches is derived from the trusted
base.) A reviewer forging its own claim record is in any case forging something
it already controls through its review result. The bound on that is
routing: whether a run reaches `finalize` at all is decided by context flags
Fabro holds server-side, so a declined review cannot be edited into
a published patch — only the wording of an already-passing one. Closing this
fully would need a second trusted channel into `finalize`, and `stdin_source`
carries exactly one.

**A patch touching the workflow's own support directory is declined.** No
legitimate fix edits the engine that judges it. This rule cannot cover `.git/`,
whose contents are never tracked and so appear in neither the diff nor
`git status`; hook and repository configuration is inspected directly instead.

**One fixup is allowed.** Seven review lanes run in parallel: exploit closure,
new attack paths, compatibility and behavior, user-facing behavior, patch
completeness and evidence, design economy, and performance and lifetime. One consolidator returns
`clean`, `fix`, or `decline`. Blocking findings alone control that outcome.
Residual risks are recorded follow-up and do not cause a fix or decline. A
`fix` updates the current patch in place and runs all seven lanes again. A
verified second-round finding declines the patch. A server-side `fixup_used`
flag prevents a second repair cycle. A finding is blocking only when the
current patched code violates the approved security objective under supported
execution, the patch creates or worsens a concrete risk, or it creates or
worsens a concrete user-facing defect. Rollout, migration, stale-version,
historical-state, retirement, and defense-in-depth work are residual unless
that objective requires them.

**Restoration never rewrites history.** Fabro pushes the run branch after every
checkpoint, so a `reset --hard` would leave the local branch behind its pushed
remote and the next non-force push would fail as non-fast-forward. The decline
path restores the base tree in place —
`git restore --source=<base> --staged --worktree -- .` then
`git clean -fdx` (excluding only the engine's own runtime state) —
and lets the next checkpoint record the restoration as a forward commit.

**A decline must prove an empty tree.** After restoring, the engine asserts
that the working tree and index hold exactly the base content and that no
leftover file survives, including ignored files. The sweep is `git clean -fdx`,
excluding only the engine's own runtime state, and the check that follows uses
`git ls-files --others` *without* `--exclude-standard` so an ignored leftover
cannot pass unseen. That invariant is the only thing
standing between a rejected attempt and an opened pull request, because Fabro
skips pull-request creation exactly when the final diff is empty.

**A rejected attempt is not kept.** Its diffstat survives in `DECLINED.md` so a
person can size what was tried; the change itself does not, because it was
rejected. Note that Fabro's run-branch history still holds the attempt and its
restoration as commits — that is a platform property this workflow accepts and
documents rather than one it can remove.

## What the engine refuses

The run stops, with a message naming the problem, when: the goal is not one
finding object; a finding id is malformed; a `file` path is absolute or escapes
the repository; a pinned support file changed during the run; the completeness
review's paths disagree with the derived set; the delivered diff is empty at
`finalize`; or a decline cannot prove a clean tree. A refusal is corrected and
the run repeated — never worked around.
