# Patch products specification

What one `suggest-security-patches` run leaves behind, and the rules the
deterministic engine follows to produce it. Agents generate, review, and attack
the change; `suggest_patches.py` decides everything that follows from what they
return and writes every file. No model writes a product.

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
| `untested` | Always `true` |
| `testsRun` | Always the same sentence — this workflow runs no tests |
| `changedPaths` | The engine's Git-derived changed set, in name-status form |
| `reviewedPaths` | The verifier's own list of touched paths, cross-checked against the engine's set |
| `reviewedDiffSha256` | SHA-256 of the change as it stood when review began |
| `tamperingSignals` | Anything the integrity checks noticed, even on a successful run |

**Review confidence and testing are separate fields, deliberately.** A
`behaviourUnchanged` of `CONFIDENT` means confident *from reading the change and
its callers*. It never means runtime behaviour was checked, because nothing here
runs the project. Any product that blurs the two is wrong.

## Rules the engine follows

**The changed set comes from Git, never from the generator.** Fabro checkpoints
after every node — it stages and commits the tree before the next node starts —
so by the time the engine looks, the generator's work is a commit and a staged
diff would be empty. The set is derived from `git diff <base>..HEAD
--name-status`. The generator's `changedFiles` is context for the reviewer and
is never the record.

**The verifier's paths must match, and silence is not agreement.** The
comparison is unconditional and exact: the verifier reports every path the
change touches as a bare repository-relative path, and a disagreement — or an
empty list, or a summary phrase in place of paths — stops the run. A check that
skipped itself when the reviewer said nothing would pass exactly the cases it
exists to catch.

Both sides are read NUL-delimited (`git diff --name-status -z`,
`git ls-files -z`). A filename may contain a space, a tab, or a newline, and
splitting Git's human-readable output on whitespace would corrupt precisely the
paths an attacker would choose.

**The delivered bytes must be the reviewed bytes.** Every node is followed by a
checkpoint that commits whatever the tree holds — a reviewer's writes included.
Reviewers are told to inspect and not modify, but an instruction is not a
control: without one, a reviewer's own checkpoint could fold new content into
the patch *after* review had passed on it. So the change is fingerprinted with
SHA-256 the moment review begins, and that fingerprint is re-checked before the
verdict is read, before the adversarial result is read, and once more at
delivery. A mismatch stops the run; nothing is published.

**A patch touching the workflow's own support directory is declined.** No
legitimate fix edits the engine that judges it. This rule cannot cover `.git/`,
whose contents are never tracked and so appear in neither the diff nor
`git status`; hook and repository configuration is inspected directly instead.

**Restoration never rewrites history.** Fabro pushes the run branch after every
checkpoint, so a `reset --hard` would leave the local branch behind its pushed
remote and the next non-force push would fail as non-fast-forward. Both the
revision round and the decline path restore the base tree in place —
`git restore --source=<base> --staged --worktree -- .` then `git clean -fd` —
and let the next checkpoint record the restoration as a forward commit.

**A decline must prove an empty tree.** After restoring, the engine asserts
that the working tree and index hold exactly the base content and that no
leftover file survives — ignored files included, since `git clean -fd` alone
would keep them and a "fresh" attempt would inherit whatever a rejected one
left in a cache or build directory. The sweep is `git clean -fdx`, excluding
only the engine's own runtime state, and the check that follows uses
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
the repository; a pinned support file changed during the run; the verifier's
paths disagree with the derived set; the delivered diff is empty at
`finalize`; or a decline cannot prove a clean tree. A refusal is corrected and
the run repeated — never worked around.
