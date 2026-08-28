#!/usr/bin/env python3
"""Deterministic engine for the Fabro suggest-security-patches workflow.

One run takes one security finding and produces one reviewed patch, delivered
as a draft pull request, or stops before a usable patch exists. Agents plan,
implement, review, consolidate, and fix the change; this program owns routing,
the authoritative changed set, workspace restoration, diff capture, integrity
checks, and the products.

The implementers write to the checkout, so nothing here trusts the tree. The
changed set comes from Git, never from an implementer's account of it, and
the support files this engine reads are hash-checked on every invocation.

Python 3.9-compatible. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


WORKFLOW_ROOT = Path(".fabro/workflows/suggest-security-patches")
CONTROL_DIR = WORKFLOW_ROOT / "runtime"
STATE_PATH = CONTROL_DIR / "state.json"

# Fabro resolves stdin_source before starting a command and enforces this same
# ceiling. Keep the direct-input guard aligned with that transport.
MAX_STDIN_BYTES = 30 * 1024 * 1024

FINDING_ID_PATTERN = re.compile(r"^F[0-9]{1,9}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
# A finding carrying these fails at run creation, not here: Fabro renders the
# goal as a MiniJinja template. make_goal.py refuses them up front; this is the
# backstop for a goal that reached the sandbox by another route.
TEMPLATE_DELIMITERS = ("{{", "{%", "{#")

# The implementers have write access to the checkout, so no legitimate fix touches
# the engine that judges it. The fixtures are the exception: the smoke run's
# whole job is to patch one, and a fixture decides nothing.
PROTECTED_PREFIX = ".fabro/workflows/suggest-security-patches/"
PROTECTED_EXCEPTION = PROTECTED_PREFIX + "fixtures/"
# The engine's own bookkeeping. It is gitignored and checkpoint-excluded in
# every shipped configuration, but a target repository can always be missing
# that fence, and the engine's state is neither part of the patch nor evidence
# of tampering. Drop it before anything else looks at the changed set.
RUNTIME_PREFIX = PROTECTED_PREFIX + "runtime/"

CLAIM_KEYS = ("targeted", "noNewVulnerability", "behaviourUnchanged")
CLAIM_LABELS = {
    "targeted": "TARGETED",
    "noNewVulnerability": "NO_NEW_VULNERABILITY",
    "behaviourUnchanged": "BEHAVIOUR_UNCHANGED",
}

REVIEW_LANES = (
    (
        "review_exploit_closure",
        "output.review_exploit_closure",
        "exploit-closure",
    ),
    (
        "review_new_attack_paths",
        "output.review_new_attack_paths",
        "new-attack-paths",
    ),
    (
        "review_compatibility",
        "output.review_compatibility",
        "compatibility-behavior",
    ),
    (
        "review_user_facing_behavior",
        "output.review_user_facing_behavior",
        "user-facing-behavior",
    ),
    (
        "review_completeness",
        "output.review_completeness",
        "patch-completeness-evidence",
    ),
    (
        "review_design_economy",
        "output.review_design_economy",
        "design-economy",
    ),
    (
        "review_performance_lifetime",
        "output.review_performance_lifetime",
        "performance-lifetime",
    ),
)

# This workflow runs no tests. The sentence is fixed so no product can imply
# otherwise, and it stays separate from review confidence in every record.
TESTS_RUN_TEXT = "none — this workflow runs no tests"

# The diff contract. Every reviewed byte reaches patch.diff and the
# pull request unchanged, CRLF and non-UTF-8 files included.
DIFF_FLAGS = (
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)

PRODUCTS_PREFIX = "SECURITY-PATCH-"
MAX_REVIEW_FIXUPS = 4


class WorkflowDataError(RuntimeError):
    """A condition the run must stop on, named for the operator."""


# ── Basics ────────────────────────────────────────────────────────────────


def root() -> Path:
    return Path.cwd().resolve()


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def clean_text(value: Any, cap: int = 4000) -> str:
    if not isinstance(value, str):
        return ""
    text = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > cap:
        text = text[:cap].rstrip() + "…"
    return text


def one_line(value: Any, cap: int = 500) -> str:
    text = clean_text(value, cap)
    return " ".join(text.split())


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    temporary.write_text(text + "\n", encoding="utf-8")
    os.replace(temporary, path)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise WorkflowDataError(f"{path} is missing") from error
    except json.JSONDecodeError as error:
        raise WorkflowDataError(f"{path} is not valid JSON: {error}") from error


def load_state() -> Dict[str, Any]:
    value = read_json(STATE_PATH)
    if not isinstance(value, dict):
        raise WorkflowDataError(f"{STATE_PATH} must contain a JSON object")
    return value


def save_state(state: Mapping[str, Any]) -> None:
    write_json(STATE_PATH, dict(state))


def emit(**updates: Any) -> None:
    print(
        json.dumps(
            {"context_updates": updates},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def read_stdin_text() -> str:
    payload = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(payload) > MAX_STDIN_BYTES:
        raise WorkflowDataError("input exceeds the transport limit")
    return payload.decode("utf-8", "replace")


def parse_agent_json(raw: str, label: str) -> Dict[str, Any]:
    """Read one agent's structured result.

    Fabro validates against the node's output schema before we see it, so a
    parse failure here means the node did not produce its schema at all.
    """
    text = raw.strip()
    if not text:
        raise WorkflowDataError(f"the {label} node returned nothing")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise WorkflowDataError(
            f"the {label} node did not return JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise WorkflowDataError(f"the {label} node must return a JSON object")
    return value


# ── Git ───────────────────────────────────────────────────────────────────


def git(*arguments: str, check: bool = False) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_EXTERNAL_DIFF": "",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(root()), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise WorkflowDataError(f"could not run Git: {error}") from error
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise WorkflowDataError(
            f"git {' '.join(arguments)} failed"
            + (f": {one_line(detail, 2000)}" if detail else "")
        )
    return result


def git_text(*arguments: str, check: bool = False) -> Optional[str]:
    result = git(*arguments, check=check)
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace").rstrip("\r\n")


def resolve_head() -> str:
    value = git_text("rev-parse", "HEAD", check=True)
    if not value or not COMMIT_PATTERN.match(value):
        raise WorkflowDataError("HEAD did not resolve to a commit")
    return value


def worktree_is_clean() -> bool:
    """True when nothing is unstaged or untracked.

    After a Fabro checkpoint this is the normal state: the checkpoint stages
    and commits everything. A dirty tree here means something wrote after it.
    """
    status = git_text("status", "--porcelain")
    return status is not None and status.strip() == ""


def changed_entries(base: str) -> List[Tuple[str, List[str]]]:
    """The authoritative changed set: (status, paths) per entry.

    Derived from committed history, because Fabro checkpoints after every node:
    by the time this runs, the implementer's work is a commit, and a staged diff
    would be empty.

    Read NUL-delimited. A filename may contain spaces, tabs, or newlines, and
    splitting Git's human-readable output on whitespace would corrupt exactly
    the paths an attacker would choose.
    """
    result = git(
        "diff",
        "--name-status",
        "--find-renames=50%",
        "--no-ext-diff",
        "--no-textconv",
        "-z",
        f"{base}..HEAD",
        check=True,
    )
    tokens = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    entries: List[Tuple[str, List[str]]] = []
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        if not status:
            continue
        # Rename and copy entries carry two paths; everything else carries one.
        wanted = 2 if status[0] in ("R", "C") else 1
        paths = tokens[index : index + wanted]
        index += wanted
        if len(paths) < wanted or not all(paths):
            raise WorkflowDataError(
                f"Git reported a {status!r} change with no path"
            )
        if all(is_engine_runtime(path) for path in paths):
            continue
        entries.append((status, paths))
    return entries


def is_engine_runtime(path: str) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.startswith(RUNTIME_PREFIX)


def display_entries(entries: Sequence[Tuple[str, List[str]]]) -> List[str]:
    """Name-status form, for the record a person reads."""
    return [f"{status} {' -> '.join(paths)}" for status, paths in entries]


def entry_paths(entries: Sequence[Tuple[str, List[str]]]) -> List[str]:
    paths: List[str] = []
    for _, entry in entries:
        paths.extend(entry)
    return paths


# Paths are compared exactly as Git spells them. No trimming, no separator
# rewriting: on Linux `a\b.py` and `a/b.py` are two different files, and
# leading or trailing whitespace is a legal part of a filename. Normalizing
# here would let two distinct paths compare equal, which is the whole thing the
# comparison exists to prevent. (`is_engine_runtime` normalizes on purpose —
# matching liberally is right when the answer is "refuse", wrong when the
# answer is "these agree".)


def diffstat(base: str) -> str:
    value = git_text(
        "diff",
        "--stat",
        "--no-ext-diff",
        "--no-textconv",
        f"{base}..HEAD",
    )
    return clean_text(value or "", 4000)


def diff_bytes(base: str) -> bytes:
    """The change, under the one command contract every product uses."""
    return git("diff", *DIFF_FLAGS, base, "HEAD", check=True).stdout


def capture_diff(base: str, destination: Path) -> bytes:
    """Write the reviewed diff byte-faithfully and return its bytes."""
    payload = diff_bytes(base)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return payload


def read_trusted_base() -> str:
    """The base commit, from the run context rather than from the state file.

    `prepare` emits it into Fabro's context, which the server holds outside the
    sandbox. Every step whose outcome can reach publication reads it from here:
    the state file lives in the checkout the implementers can write, and a forged
    base there is enough to make a real change look like no change at all.
    """
    value = read_stdin_text().strip()
    if not COMMIT_PATTERN.match(value):
        raise WorkflowDataError(
            "the trusted base commit did not reach this step. It is carried in "
            "the run context, so a missing or malformed value means the node "
            "was wired without its stdin_source"
        )
    if git("rev-parse", "--verify", "--quiet", value + "^{commit}").returncode != 0:
        raise WorkflowDataError(f"the trusted base {value[:12]}… is not a commit here")
    return value


def build_review_pin(base: str, payload: bytes, entries: Sequence[str]) -> str:
    """The trusted anchor for everything delivered.

    Emitted into Fabro's run context, which lives on the server: unlike this
    program's state file, it sits outside the checkout and no agent in the
    sandbox can reach it. `finalize` reads it back through `stdin_source` and
    trusts it over anything on disk.
    """
    return json.dumps(
        {
            "base": base,
            "review_commit": resolve_head(),
            "diff_sha256": sha256_bytes(payload),
            "changed": list(entries),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_review_pin(raw: str) -> Dict[str, str]:
    text = raw.strip()
    if not text:
        raise WorkflowDataError(
            "the review pin did not reach this step. It is carried in the run "
            "context, so a missing pin means the node was wired without its "
            "stdin_source, not that a patch is merely unverified"
        )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise WorkflowDataError(f"the review pin is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise WorkflowDataError("the review pin must be a JSON object")
    changed = value.get("changed")
    pin = {
        "base": str(value.get("base", "")),
        "review_commit": str(value.get("review_commit", "")),
        "diff_sha256": str(value.get("diff_sha256", "")),
        "changed": [entry for entry in changed if isinstance(entry, str)]
        if isinstance(changed, list)
        else [],
    }
    if not COMMIT_PATTERN.match(pin["base"]):
        raise WorkflowDataError("the review pin carries no base commit")
    if not re.fullmatch(r"[0-9a-f]{64}", pin["diff_sha256"]):
        raise WorkflowDataError("the review pin carries no diff fingerprint")
    return pin


def assert_pinned_bytes(pin: Mapping[str, str]) -> bytes:
    """Confirm the tree still holds exactly the change that was reviewed.

    Every node is followed by a checkpoint that commits whatever the tree
    holds, reviewers included. A reviewer is told to inspect and not modify,
    but an instruction is not a control: without this check, a reviewer's own
    checkpoint would fold its writes into the patch after review had passed on
    it. The expected value comes from the run context rather than from this
    program's state file, because the state file lives in the checkout the
    agents can write.
    """
    payload = diff_bytes(pin["base"])
    actual = sha256_bytes(payload)
    if actual != pin["diff_sha256"]:
        raise WorkflowDataError(
            "the change is not what was reviewed (expected "
            f"{pin['diff_sha256'][:12]}…, found {actual[:12]}…). Something "
            "wrote to the tree after review, so nothing is delivered."
        )
    return payload


def advisory_diff_check(state: Mapping[str, Any], stage: str) -> None:
    """An early, best-effort version of the check `finalize` makes for real.

    This one reads the expected fingerprint from the state file, which an agent
    with write access to the checkout could rewrite alongside the change it is
    smuggling. It is therefore a convenience that fails fast on an honest
    mistake, never a boundary. The boundary is `assert_pinned_bytes`, whose
    expected value comes from the run context.
    """
    expected = state.get("reviewed_diff_sha256")
    if not expected:
        return
    if sha256_bytes(diff_bytes(state["base"])) != expected:
        raise WorkflowDataError(
            f"{stage}: the change is not what was reviewed. Something wrote to "
            "the tree after the change was fingerprinted."
        )


def restore_base_tree(base: str) -> None:
    """Return the tree to the base without moving HEAD.

    Fabro pushes the run branch after every checkpoint, so a `reset --hard`
    would leave the local branch behind its pushed remote and the next
    non-force push would fail as non-fast-forward. Restoring in place lets the
    next checkpoint record the restoration as a forward commit instead.
    """
    git("restore", "--source", base, "--staged", "--worktree", "--", ".", check=True)
    # `-x` removes ignored files too. Without it a rejected attempt could leave
    # a build artifact, cache, or anything else the repository ignores, and the
    # next "fresh" attempt would inherit it. `-e` keeps the engine's own state,
    # which is the one thing here that must survive the sweep.
    git("clean", "-fdx", "-e", RUNTIME_PREFIX.rstrip("/"), check=True)


def leftover_paths() -> List[str]:
    """Untracked files after a restore, ignored ones included.

    `--exclude-standard` is deliberately absent: an ignored leftover is exactly
    the kind a `git status` check would miss and a later stage would inherit.
    The engine's own runtime state is the only expected survivor.
    """
    result = git("ls-files", "--others", "-z")
    tokens = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    return [
        token
        for token in tokens
        if token.strip() and not is_engine_runtime(token)
    ]


def content_matches_base(base: str) -> bool:
    """True when the working tree and index hold exactly the base content.

    HEAD is deliberately not part of this: restoration happens in place and
    only becomes a commit at Fabro's next checkpoint, so immediately after a
    restore HEAD still points at the attempt. What matters is that the content
    the next checkpoint will commit is the base content — that is what makes
    the run's final diff empty and keeps Fabro from opening a pull request.
    """
    worktree = git("diff", "--quiet", "--no-ext-diff", "--no-textconv", base)
    index = git("diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv", base)
    return worktree.returncode == 0 and index.returncode == 0


# ── Integrity ─────────────────────────────────────────────────────────────


def hook_configuration_report() -> Dict[str, Any]:
    """What the repository's hook configuration looks like right now.

    Defense in depth only. The control that actually stops a repository hook
    from running during a checkpoint is Fabro's own commit invocation; see
    fabro-sh/fabro#809. Nothing here can be ordered early enough to prevent a
    hook installed during an agent node from firing at that node's checkpoint,
    so this reports rather than promises.
    """
    configured = git_text("config", "--local", "--get", "core.hooksPath")
    hooks_directory = root() / ".git" / "hooks"
    live: List[str] = []
    if hooks_directory.is_dir():
        for entry in sorted(hooks_directory.iterdir()):
            if entry.is_file() and os.access(entry, os.X_OK):
                live.append(entry.name)
    return {
        "core_hooks_path": configured or None,
        "executable_hooks_in_git_hooks": live,
    }


def neutralize_hooks() -> Dict[str, Any]:
    """Point hooks at an empty directory this engine owns, and report drift."""
    owned = (CONTROL_DIR / "empty-hooks").resolve()
    owned.mkdir(parents=True, exist_ok=True)
    before = hook_configuration_report()
    git("config", "--local", "core.hooksPath", str(owned))
    deviation: List[str] = []
    configured = before.get("core_hooks_path")
    if configured and configured != str(owned):
        deviation.append(f"core.hooksPath pointed at {one_line(configured, 200)}")
    if before.get("executable_hooks_in_git_hooks"):
        names = ", ".join(before["executable_hooks_in_git_hooks"])
        deviation.append(f"executable hooks present in .git/hooks: {names}")
    return {"deviation": deviation, "hooks_path": str(owned)}


# Support-file integrity is checked by each node's graph-embedded script line,
# before this program is invoked at all. It is deliberately not re-checked
# here: an engine that verifies itself proves nothing, and a helper that looked
# like the control would be worse than none.


def guard(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run at the top of every deterministic node after prepare.

    Re-asserts hook configuration and records any deviation into state, so the
    products can say what was seen even when the run still succeeds.
    """
    current = state if state is not None else load_state()
    outcome = neutralize_hooks()
    if outcome["deviation"]:
        signals = list(current.get("tampering_signals") or [])
        signals.extend(outcome["deviation"])
        current["tampering_signals"] = signals[:20]
    return current


def protected_path_violations(paths: Sequence[str]) -> List[str]:
    violations: List[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        if is_engine_runtime(normalized):
            continue
        if normalized.startswith(PROTECTED_PREFIX) and not normalized.startswith(
            PROTECTED_EXCEPTION
        ):
            violations.append(path)
    return violations


# ── Finding input ─────────────────────────────────────────────────────────


def normalize_repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowDataError("the finding's `file` is missing")
    candidate = value.strip().replace("\\", "/")
    if candidate.startswith("/"):
        raise WorkflowDataError("the finding's `file` must be repository-relative")
    parts = PurePosixPath(candidate).parts
    if any(part == ".." for part in parts):
        raise WorkflowDataError("the finding's `file` must not escape the repository")
    normalized = str(PurePosixPath(*[p for p in parts if p not in (".",)]))
    if not normalized or normalized == ".":
        raise WorkflowDataError("the finding's `file` is not a usable path")
    return normalized


def validate_finding(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkflowDataError(
            "the goal must be one JSON finding object — free text is not supported; "
            "use scripts/make_goal.py to build it from a report"
        )
    identifier = value.get("id")
    if not isinstance(identifier, str) or not FINDING_ID_PATTERN.match(identifier):
        raise WorkflowDataError(
            "the finding's `id` must look like F1 — the only report-derived value "
            "this workflow acts on"
        )
    title = value.get("title")
    if not isinstance(title, str) or not title.strip():
        raise WorkflowDataError("the finding's `title` is missing")
    finding = {
        "id": identifier,
        "title": one_line(title, 500),
        "file": normalize_repo_path(value.get("file")),
    }
    line = value.get("line")
    if isinstance(line, int) and line > 0:
        finding["line"] = line
    for key, cap in (
        ("snippet", 4000),
        ("symbol", 500),
        ("impact", 20000),
        ("description", 40000),
        ("recommendation", 20000),
        ("severity", 40),
        ("ruleId", 200),
        ("findingId", 200),
    ):
        text = value.get(key)
        if isinstance(text, str) and text.strip():
            finding[key] = clean_text(text, cap)
    return finding


def locate_at_head(finding: Mapping[str, Any]) -> Tuple[bool, str]:
    """Confirm the flagged code still exists at HEAD, by content.

    Line numbers drift, so they are a hint. The snippet and symbol are what
    identify the code. A finding whose code has since changed is declined
    rather than patched blind.
    """
    path = finding["file"]
    blob = git_text("show", f"HEAD:./{path}")
    if blob is None:
        return False, f"{path} does not exist at HEAD"

    snippet = finding.get("snippet")
    symbol = finding.get("symbol")
    if snippet:
        needle = " ".join(str(snippet).split())
        haystack = " ".join(blob.split())
        if needle and needle in haystack:
            if symbol and symbol not in blob:
                return False, (
                    f"the flagged line is still in {path}, but {symbol} is not — "
                    "the code moved out of the function the report named"
                )
            return True, f"located by snippet in {path}"
        return False, (
            f"the flagged line from the report is no longer in {path} — "
            "it was rewritten after the scan"
        )
    if symbol:
        if symbol in blob:
            return True, f"located by symbol {symbol} in {path}"
        return False, f"{symbol} is no longer in {path}"

    line = finding.get("line")
    if isinstance(line, int) and 0 < line <= len(blob.splitlines()):
        return True, (
            f"{path} exists at HEAD and reaches line {line}; the finding carried "
            "neither a snippet nor a symbol, so the location is unverified"
        )
    return False, (
        f"{path} exists but the finding carried no snippet, symbol, or usable "
        "line to locate the flagged code"
    )


# ── Products ──────────────────────────────────────────────────────────────


def products_directory(state: Mapping[str, Any]) -> Path:
    name = state.get("products_dir")
    if not isinstance(name, str) or not name.startswith(PRODUCTS_PREFIX):
        raise WorkflowDataError("the products directory was never named")
    return root() / name


def claim_lines(claims: Mapping[str, Any]) -> List[str]:
    lines: List[str] = []
    for key in CLAIM_KEYS:
        claim = claims.get(key) if isinstance(claims, Mapping) else None
        if not isinstance(claim, Mapping):
            continue
        state = str(claim.get("state", "")).strip() or "UNSURE"
        evidence = one_line(claim.get("evidence"), 500)
        lines.append(f"- **{CLAIM_LABELS[key]}** — {state}: {evidence}")
    return lines


def review_lane_lines(lanes: Mapping[str, Any]) -> List[str]:
    lines: List[str] = []
    for _, _, lane in REVIEW_LANES:
        result = lanes.get(lane) if isinstance(lanes, Mapping) else None
        if not isinstance(result, Mapping):
            continue
        summary = one_line(result.get("summary"), 500) or "no summary"
        findings = result.get("findings")
        count = len(findings) if isinstance(findings, list) else 0
        label = lane.replace("-", " ").title()
        lines.append(f"- **{label}** — {count} finding(s): {summary}")
    return lines


def write_patch_note(
    state: Mapping[str, Any],
    directory: Path,
    record: Mapping[str, Any],
) -> None:
    finding = state["finding"]
    lines = [
        f"# Reviewed patch for {finding['id']}: {finding['title']}",
        "",
        "**No tests were run.** This workflow runs none; every claim below rests "
        "on code review by independent agents, not on a test run. Read the diff "
        "before you merge it.",
        "",
        f"- Finding: `{finding['id']}` — {finding['title']}",
        f"- Flagged code: `{finding['file']}`"
        + (f":{finding['line']}" if finding.get("line") else ""),
        f"- Applies to base commit: `{record['base']}`",
        f"- Patch bytes (SHA-256): `{record.get('patchSha256') or 'n/a'}`",
        "",
        "## What the change does",
        "",
        clean_text(record.get("summary"), 4000) or "_no summary returned_",
        "",
        "## What review established",
        "",
    ]
    lines.extend(claim_lines(record.get("claims") or {}))
    lines.extend(["", "## Review lanes", ""])
    lines.extend(review_lane_lines(record.get("reviewLanes") or {}))
    consolidation = record.get("consolidation") or {}
    lines.extend(
        [
            "",
            f"- Tests run: {TESTS_RUN_TEXT}",
            "",
            "## Consolidation",
            "",
            clean_text(consolidation.get("summary"), 4000) or "_not recorded_",
            "",
        ]
    )
    pending_findings = consolidation.get("findings") or []
    if pending_findings:
        lines.extend(
            [
                f"**Pending fixes:** {len(pending_findings)} review finding(s) remain. Review them before merging.",
                "",
            ]
        )
    lines.extend(["## Changed files", ""])
    for entry in record.get("changedPaths") or []:
        lines.append(f"- `{entry}`")
    stat = record.get("diffstat")
    if stat:
        lines.extend(["", "```", stat, "```"])
    signals = state.get("tampering_signals") or []
    if signals:
        lines.extend(["", "## Integrity signals", ""])
        for signal in signals:
            lines.append(f"- {signal}")
    lines.extend(
        [
            "",
            "## Applying it outside the pull request",
            "",
            "```bash",
            f"git apply {directory.name}/patch.diff",
            "```",
            "",
        ]
    )
    (directory / "PATCH.md").write_text("\n".join(lines), encoding="utf-8")


def write_decline_note(
    state: Mapping[str, Any],
    directory: Path,
    record: Mapping[str, Any],
) -> None:
    finding = state["finding"]
    lines = [
        f"# No patch for {finding['id']}: {finding['title']}",
        "",
        clean_text(record.get("declineReason"), 4000)
        or "The run ended without a reviewed patch.",
        "",
        f"- Finding: `{finding['id']}` — {finding['title']}",
        f"- Flagged code: `{finding['file']}`"
        + (f":{finding['line']}" if finding.get("line") else ""),
        f"- Base commit: `{record['base']}`",
        f"- Status: `{record['status']}`",
        "",
    ]
    claims = record.get("claims") or {}
    if claims:
        lines.extend(["## What review established", ""])
        lines.extend(claim_lines(claims))
        lines.append("")
    stat = record.get("diffstat")
    if stat:
        lines.extend(
            [
                "## The attempt that was rejected",
                "",
                "The change itself is not kept — it was rejected. Its shape was:",
                "",
                "```",
                stat,
                "```",
                "",
            ]
        )
    recommendation = record.get("recommendation")
    if recommendation:
        lines.extend(
            [
                "## The report's original recommendation",
                "",
                clean_text(recommendation, 4000),
                "",
            ]
        )
    signals = state.get("tampering_signals") or []
    if signals:
        lines.extend(["## Integrity signals", ""])
        for signal in signals:
            lines.append(f"- {signal}")
        lines.append("")
    (directory / "DECLINED.md").write_text("\n".join(lines), encoding="utf-8")


def build_record(state: Mapping[str, Any], status: str) -> Dict[str, Any]:
    finding = state["finding"]
    record: Dict[str, Any] = {
        "recordVersion": 2,
        "id": finding["id"],
        "title": finding["title"],
        "status": status,
        "base": state["base"],
        "untested": True,
        "testsRun": TESTS_RUN_TEXT,
        "summary": state.get("summary"),
        "claims": state.get("claims"),
        "reviewedPaths": state.get("reviewed_paths") or [],
        "changedPaths": state.get("changed_paths") or [],
        "diffstat": state.get("diffstat"),
        "adversarial": state.get("adversarial"),
        "reviewLanes": state.get("review_lanes"),
        "consolidation": state.get("consolidation"),
        "reviewRound": state.get("review_round", 0),
        "declineReason": state.get("decline_reason"),
        "recommendation": finding.get("recommendation"),
        "revisionUsed": bool(state.get("revision_used")),
        "patchSha256": state.get("patch_sha256"),
        "reviewedDiffSha256": state.get("reviewed_diff_sha256"),
        "tamperingSignals": state.get("tampering_signals") or [],
    }
    return record


# ── Commands ──────────────────────────────────────────────────────────────


def prepare(args: argparse.Namespace) -> None:
    raw = read_stdin_text()
    for delimiter in TEMPLATE_DELIMITERS:
        if delimiter in raw:
            raise WorkflowDataError(
                f"the goal contains the template delimiter {delimiter!r}. Fabro "
                "renders the goal as a template, so such a finding cannot be "
                "passed through unchanged. Build the goal with make_goal.py, "
                "which refuses these up front — never hand-edit the finding, "
                "because that changes the evidence"
            )
    try:
        parsed = json.loads(raw.strip() or "null")
    except json.JSONDecodeError as error:
        raise WorkflowDataError(
            "the goal is not JSON. This workflow takes one finding object from a "
            f"report's SECURITY-REVIEW-RESULTS.jsonl: {error}"
        ) from error

    finding = validate_finding(parsed)
    base = resolve_head()
    hooks = neutralize_hooks()

    state: Dict[str, Any] = {
        "finding": finding,
        "base": base,
        "products_dir": f"{PRODUCTS_PREFIX}{now_stamp()}",
        "revision_used": False,
        "fixup_count": 0,
        "review_round": 0,
        "tampering_signals": hooks["deviation"],
    }

    located, reason = locate_at_head(finding)
    if not located:
        state["status"] = "skipped_stale"
        state["decline_reason"] = (
            f"The finding is stale: {reason}. Nothing was patched, because a patch "
            "written against code the scan never saw is a guess. Re-scan the "
            "current tree and patch from that report."
        )
        save_state(state)
        emit(finding_located=False, finding_id=finding["id"], patch_base=base)
        return

    state["status"] = "planning"
    state["location_reason"] = reason
    save_state(state)
    emit(
        finding_located=True,
        finding_id=finding["id"],
        patch_base=base,
        fixup_count=0,
        fixup_used=False,
    )


def route_plan() -> None:
    state = guard()
    result = parse_agent_json(read_stdin_text(), "review-plan")
    decline = clean_text(result.get("declineReason"), 2000)

    if decline:
        state["status"] = "declined"
        state["decline_reason"] = f"Plan review declined the patch: {decline}"
        save_state(state)
        emit(plan_next="decline")
        return

    state["approved_plan"] = result
    state["status"] = "implementing"
    save_state(state)
    emit(plan_next="implement")


def check_plan_clean() -> None:
    state = guard()
    base = read_trusted_base()
    state["base"] = base
    leftovers = leftover_paths()
    if not content_matches_base(base) or leftovers:
        state["status"] = "declined"
        state["decline_reason"] = (
            "Planning changed the checkout. Planning and plan review are "
            "read-only, so the run declined before implementation."
        )
        save_state(state)
        emit(plan_tree_clean=False)
        return
    save_state(state)
    emit(plan_tree_clean=True)


def assess_change() -> None:
    """Read an implementer's account before the trusted Git measurement.

    This step spends its single `stdin_source` on the implementer's output, so it
    could only get a base commit by reading the state file — and the state file
    is in the checkout the implementer can write. A forged base there would make
    a real change measure as empty, and every decision drawn from it would be
    the attacker's to choose. So this step draws none: it records what the
    implementer said, and `pin_review` measures the tree against the base carried
    in the run context.
    """
    state = guard()
    if state.get("status") == "skipped_stale":
        raise WorkflowDataError("a stale finding reached assess-change")

    result = parse_agent_json(read_stdin_text(), "implementation")

    refusal = clean_text(result.get("refusal"), 2000)
    summary = clean_text(result.get("summary"), 4000)
    behaviour_change = clean_text(result.get("behaviourChange"), 2000)
    if summary:
        state["summary"] = summary
    if behaviour_change:
        state["behaviour_change"] = behaviour_change
    if not worktree_is_clean():
        # Fabro's checkpoint stages and commits everything before this runs, so
        # a dirty tree means something wrote afterwards.
        state["tampering_signals"] = list(state.get("tampering_signals") or []) + [
            "the working tree was not clean after the implementer's checkpoint"
        ]

    if refusal and not state.get("reviewed_diff_sha256"):
        state["status"] = "declined"
        state["decline_reason"] = f"The implementer refused: {refusal}"
        save_state(state)
        emit(declined=True)
        return

    if refusal:
        state["fixup_stopped_reason"] = f"The fixup agent stopped: {refusal}"

    state["status"] = "measuring"
    save_state(state)
    emit(declined=False)


def pin_review() -> None:
    """Measure the change against the trusted base, then pin it.

    Every decision that can reach publication is made here, from the base
    commit `prepare` put into Fabro's run context — never from the state file
    in the writable checkout. That covers what the change contains, whether it
    touches anything it must not, whether there is a change at all, and the
    fingerprint `finalize` will hold the delivered bytes to.

    The implementer's own account is read from the state file. It cannot
    decide what is published.
    """
    state = guard()
    base = read_trusted_base()
    if state.get("base") != base:
        state["tampering_signals"] = list(state.get("tampering_signals") or []) + [
            f"the recorded base disagreed with the trusted base {base[:12]}…"
        ]
    state["base"] = base

    entries = changed_entries(base)
    state["changed_paths"] = display_entries(entries)
    state["changed_path_set"] = sorted(set(entry_paths(entries)))
    state["diffstat"] = diffstat(base)

    violations = protected_path_violations(entry_paths(entries))
    if violations:
        state["status"] = "declined"
        state["decline_reason"] = (
            "The attempt changed this workflow's own support files "
            f"({', '.join(violations[:5])}). No legitimate fix edits the engine "
            "that judges it, so the unit is declined and the change discarded."
        )
        state["tampering_signals"] = list(state.get("tampering_signals") or []) + [
            f"patch touched protected paths: {', '.join(violations[:5])}"
        ]
        save_state(state)
        emit(pin_next="decline")
        return

    payload = diff_bytes(base) if entries else b""
    if not entries or not payload.strip():
        state["status"] = "declined"
        state["decline_reason"] = (
            "Measured against the run's own base commit, the attempt changed "
            "nothing. The implementer's account: "
            + (clean_text(state.get("summary"), 2000) or "no summary returned")
        )
        save_state(state)
        emit(pin_next="decline")
        return

    fingerprint = sha256_bytes(payload)
    if state.get("reviewed_diff_sha256") == fingerprint:
        state["status"] = "finalizing"
        state["fixup_stopped_reason"] = (
            "The latest fixup left the patch unchanged. Pending review "
            "findings remain recorded for the pull request."
        )
        save_state(state)
        emit(pin_next="finalize")
        return

    state["status"] = "reviewing"
    state["reviewed_diff_sha256"] = fingerprint
    state["review_lanes"] = None
    state["consolidation"] = None
    save_state(state)
    emit(
        pin_next="review",
        review_pin=build_review_pin(base, payload, state["changed_paths"]),
    )


def parse_review_results(raw: str) -> Dict[str, Dict[str, Any]]:
    try:
        results = json.loads(raw)
    except json.JSONDecodeError as error:
        raise WorkflowDataError(f"parallel review results are not JSON: {error}") from error
    if not isinstance(results, list):
        raise WorkflowDataError("parallel review results must be an array")

    by_id: Dict[str, Dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        branch_id = result.get("id")
        if isinstance(branch_id, str):
            if branch_id in by_id:
                raise WorkflowDataError(f"parallel review repeated {branch_id}")
            by_id[branch_id] = result

    lanes: Dict[str, Dict[str, Any]] = {}
    for branch_id, output_key, lane in REVIEW_LANES:
        result = by_id.get(branch_id)
        if result is None or result.get("status") != "succeeded":
            raise WorkflowDataError(f"required review did not succeed: {branch_id}")
        context = result.get("context_updates")
        output = context.get(output_key) if isinstance(context, dict) else None
        if not isinstance(output, dict):
            raise WorkflowDataError(f"required review has no output: {branch_id}")
        findings = output.get("findings")
        residual_risks = output.get("residualRisks")
        if not isinstance(findings, list) or not isinstance(residual_risks, list):
            raise WorkflowDataError(f"required review output is malformed: {branch_id}")
        lanes[lane] = {
            "summary": clean_text(output.get("summary"), 4000),
            "findings": findings,
            "residualRisks": residual_risks,
        }
        if lane == "patch-completeness-evidence":
            reviewed = output.get("reviewedPaths")
            if not isinstance(reviewed, list) or not reviewed:
                raise WorkflowDataError("the completeness review returned no paths")
            lanes[lane]["reviewedPaths"] = reviewed
    return lanes


def record_reviews() -> None:
    state = guard()
    advisory_diff_check(state, "review fan-out")
    lanes = parse_review_results(read_stdin_text())

    completeness = lanes["patch-completeness-evidence"]
    reviewed = [
        path
        for path in completeness["reviewedPaths"]
        if isinstance(path, str) and path
    ]
    reviewed_set = set(reviewed)
    derived_set = set(state.get("changed_path_set") or [])
    if reviewed_set != derived_set:
        only_reviewer = sorted(reviewed_set - derived_set)[:5]
        only_engine = sorted(derived_set - reviewed_set)[:5]
        raise WorkflowDataError(
            "the completeness review covered a different path set "
            f"(reviewer only: {only_reviewer}; change only: {only_engine})"
        )

    round_number = int(state.get("fixup_count", 0)) + 1
    state["review_round"] = round_number
    state["review_lanes"] = lanes
    state["reviewed_paths"] = reviewed
    state["status"] = "consolidating"
    save_state(state)
    emit(review_round=round_number, reviews_recorded=True)


def merge_consolidation() -> None:
    state = guard()
    advisory_diff_check(state, "review consolidation")
    result = parse_agent_json(read_stdin_text(), "review consolidation")
    outcome = str(result.get("outcome", "")).strip().lower()
    summary = clean_text(result.get("summary"), 4000)
    findings = result.get("findings")
    residual_risks = result.get("residualRisks")
    if (
        outcome not in ("clean", "fix")
        or not isinstance(findings, list)
        or not isinstance(residual_risks, list)
    ):
        raise WorkflowDataError("review consolidation returned an invalid outcome")
    if outcome == "clean" and findings:
        raise WorkflowDataError("a clean consolidation cannot retain findings")
    if outcome == "fix" and not findings:
        raise WorkflowDataError(f"a {outcome} consolidation must retain findings")

    state["consolidation"] = {
        "outcome": outcome,
        "summary": summary,
        "findings": findings,
        "residualRisks": residual_risks,
    }
    verified_lanes = {
        finding.get("lane")
        for finding in findings
        if isinstance(finding, Mapping) and isinstance(finding.get("lane"), str)
    }
    lanes = state.get("review_lanes") or {}

    def claim(*lane_names: str) -> Dict[str, str]:
        lane_results = (
            [lanes.get(lane) for lane in lane_names]
            if isinstance(lanes, Mapping)
            else []
        )
        evidence = one_line(
            " ".join(
                one_line(result.get("summary"), 1000)
                for result in lane_results
                if isinstance(result, Mapping)
            ),
            1000,
        ) or summary
        return {
            "state": (
                "NOT_CONFIDENT"
                if any(lane in verified_lanes for lane in lane_names)
                else "CONFIDENT"
            ),
            "evidence": evidence,
        }

    state["claims"] = {
        "targeted": claim("patch-completeness-evidence"),
        "noNewVulnerability": claim("new-attack-paths"),
        "behaviourUnchanged": claim(
            "compatibility-behavior", "user-facing-behavior"
        ),
    }
    state["adversarial"] = {
        "introducesNewAttackPath": "new-attack-paths" in verified_lanes,
        "reasoning": claim("new-attack-paths")["evidence"],
        "attackPath": None,
    }

    if outcome == "clean":
        state["status"] = "finalizing"
        save_state(state)
        emit(review_next="clean")
        return

    state["objections"] = findings
    if int(state.get("fixup_count", 0)) >= MAX_REVIEW_FIXUPS:
        state["status"] = "finalizing"
        save_state(state)
        emit(review_next="finalize")
        return

    state["status"] = "awaiting_review_fixup"
    save_state(state)
    emit(review_next="fix")


def mark_fixup() -> None:
    state = guard()
    fixup_count = int(state.get("fixup_count", 0)) + 1
    if fixup_count > MAX_REVIEW_FIXUPS:
        raise WorkflowDataError("the review fixup limit was exceeded")
    state["fixup_count"] = fixup_count
    state["revision_used"] = True
    state["status"] = "fixing_review_findings"
    save_state(state)
    emit(fixup_count=fixup_count, fixup_used=True)


def finalize() -> None:
    state = guard()
    # The pin arrives from the run context, not from the state file, and
    # everything published is derived from it. A state file that disagrees with
    # it has been edited, which is a stop rather than a decline.
    pin = parse_review_pin(read_stdin_text())
    if state.get("base") != pin["base"]:
        raise WorkflowDataError(
            "the recorded base does not match the pinned base, so the state "
            "file was changed during the run; nothing is delivered"
        )
    if state.get("reviewed_diff_sha256") != pin["diff_sha256"]:
        raise WorkflowDataError(
            "the recorded fingerprint does not match the pinned fingerprint, "
            "so the state file was changed during the run; nothing is delivered"
        )

    base = pin["base"]
    payload = assert_pinned_bytes(pin)
    if not payload.strip():
        raise WorkflowDataError(
            "the change produced an empty diff at the point of delivery"
        )

    directory = products_directory(state)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "patch.diff").write_bytes(payload)

    state["base"] = base
    state["patch_sha256"] = sha256_bytes(payload)
    state["reviewed_diff_sha256"] = pin["diff_sha256"]
    # The published record's changed set comes from the pin, so what a reader
    # is told the patch touches is derived from the trusted base rather than
    # from a file in the checkout.
    if pin["changed"]:
        state["changed_paths"] = pin["changed"]
    state["status"] = "patch_written"

    record = build_record(state, "patch_written")
    write_json(directory / "verdict.json", record)
    write_patch_note(state, directory, record)
    save_state(state)

    print(
        f"suggest_patches.py: reviewed patch for {state['finding']['id']} "
        f"written to {directory.name}/ ({len(payload)} bytes, "
        f"sha256 {state['patch_sha256'][:12]}…)"
    )
    emit(patch_written=True)


def no_patch() -> None:
    state = guard()
    # The base comes from the run context, never from the state file. With a
    # forged base this step would "restore" to a tree that still held the
    # rejected change, report a clean decline, and leave publication a
    # non-empty diff to open a pull request from — a declined run publishing an
    # unreviewed patch. The trusted base is what makes the decline real.
    base = read_trusted_base()
    if state.get("base") != base:
        state["tampering_signals"] = list(state.get("tampering_signals") or []) + [
            f"the recorded base disagreed with the trusted base {base[:12]}…"
        ]
    state["base"] = base
    status = state.get("status")
    if status not in ("declined", "skipped_stale"):
        state["status"] = status = "declined"
    if not state.get("decline_reason"):
        state["decline_reason"] = "The run ended without a reviewed patch."

    restore_base_tree(base)
    leftovers = leftover_paths()
    if not content_matches_base(base) or leftovers:
        # This invariant is what keeps a declined run from opening a pull
        # request: Fabro skips PR creation only when the final diff is empty.
        raise WorkflowDataError(
            "the workspace did not return to the base revision on decline, so a "
            "pull request could still be opened for work that was rejected"
            + (f" (left behind: {', '.join(leftovers[:5])})" if leftovers else "")
        )

    directory = products_directory(state)
    directory.mkdir(parents=True, exist_ok=True)
    record = build_record(state, status)
    write_json(directory / "verdict.json", record)
    write_decline_note(state, directory, record)
    save_state(state)

    print(
        f"suggest_patches.py: no patch for {state['finding']['id']} — "
        f"{one_line(state['decline_reason'], 300)}"
    )
    emit(patch_written=False)


# ── Entry point ───────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("prepare")
    for name in (
        "route-plan",
        "check-plan-clean",
        "assess-change",
        "pin-review",
        "record-reviews",
        "merge-consolidation",
        "mark-fixup",
        "finalize",
        "no-patch",
    ):
        subparsers.add_parser(name)
    return parser


def main(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)
    commands = {
        "prepare": lambda: prepare(args),
        "route-plan": route_plan,
        "check-plan-clean": check_plan_clean,
        "assess-change": assess_change,
        "pin-review": pin_review,
        "record-reviews": record_reviews,
        "merge-consolidation": merge_consolidation,
        "mark-fixup": mark_fixup,
        "finalize": finalize,
        "no-patch": no_patch,
    }
    try:
        commands[args.command]()
    except WorkflowDataError as error:
        print(f"suggest_patches.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
