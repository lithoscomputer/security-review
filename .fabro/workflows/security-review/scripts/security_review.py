#!/usr/bin/env python3
"""Deterministic scan engine for the Fabro security-review workflow.

Scan agents return validated JSON in their final messages. Fabro passes those
results directly to deterministic merge commands over standard input. This
program owns state transitions after Fabro's native agent retries, plus
normalization, caps, deduplication, vote arithmetic, coverage records, and
final artifact rendering.

Python 3.9-compatible. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


WORKFLOW_ROOT = Path(".fabro/workflows/security-review")
CONTROL_DIR = WORKFLOW_ROOT / "runtime"
STATE_PATH = CONTROL_DIR / "state.json"
RENDERER_PATH = WORKFLOW_ROOT / "scripts/render_report.py"

CANDIDATE_CAP = 400
VERIFICATION_CAP = 45
SMALL_DIFF_MAX_FILES = 5
SMALL_DIFF_MAX_LINES = 300
SMALL_SCOPE_MAX_FILES = 5
MAX_COMPONENTS_DEFAULT = 12
# Above this many files a tree is too large to read whole, so a full scan
# focuses on the attack surface. The plugin has its Security Lead judge this
# from a `git ls-files` count ("a few hundred files or fewer counts as small");
# with no Lead here, the same gauge becomes a number.
LARGE_REPOSITORY_FILES = 500
MAX_COMPONENTS_EXPANDED = 24
# Fabro resolves stdin_source before starting a command and enforces this same
# ceiling. Keep the driver's direct-input guard aligned with that transport.
MAX_STDIN_BYTES = 30 * 1024 * 1024
MAX_RESULT_TEXT = 8000

EFFORT_TIERS = ("low", "medium", "high", "max")
SCAN_MODES = ("scan", "changes", "commit")
VERIFICATION_LENSES = ("REACHABILITY", "IMPACT", "DEFENSES")
CATEGORY_LENSES = (
    (
        "injection-and-input",
        "injection and input handling: SQL/command/code injection, XSS, XXE, "
        "deserialization, template injection, ReDoS, path traversal from user "
        "input, and prompt injection",
    ),
    (
        "auth-and-access",
        "authentication and authorization: auth bypass, missing or wrong "
        "authorization checks, IDOR, privilege escalation, CSRF, SSRF, open "
        "redirect, and race conditions in access decisions",
    ),
    (
        "memory-and-unsafe",
        "memory and unsafe operations: buffer overflows, out-of-bounds access, "
        "use-after-free, integer overflow, type confusion, unsafe FFI, and "
        "unchecked unsafe blocks",
    ),
    (
        "crypto-and-secrets",
        "cryptography and secrets: weak or misused crypto, weak randomness, "
        "key/nonce reuse, timing side channels, hardcoded secrets, and "
        "credential handling and exposure",
    ),
)
MANAGED_LANGUAGE_RE = re.compile(
    r"^(python|javascript|typescript|node(\.js)?|ruby|php|java|kotlin|scala|"
    r"c#|csharp|\.net|elixir|erlang|clojure|dart|perl|lua|r|shell|bash|sql|"
    r"html|css)$",
    re.IGNORECASE,
)
LANGUAGE_JOIN_WORD_RE = re.compile(r"^(and|with|plus|or)$", re.IGNORECASE)
SAFE_REV_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._/@{}^~:+-]{0,399}$")
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
CONFIDENCE_RANK = SEVERITY_RANK
MERGEABLE_FINDING_FIELDS = (
    "evidence",
    "impact",
    "exploitScenario",
    "recommendation",
    "snippet",
    "symbol",
    "cweId",
)
PHASE_OUTPUT_KEYS = {
    "threat": "output.threat_model",
    "research": "output.researcher",
    "sweep": "output.sweeper",
    "panel": "output.panel_verifier",
    "repanel": "output.repanel_verifier",
    "redteam": "output.redteam_verifier",
}
PHASE_JOB_KEYS = {
    "threat": "threat_jobs",
    "research": "research_jobs",
    "sweep": "sweep_jobs",
    "panel": "verification_jobs",
    "repanel": "repanel_jobs",
    "redteam": "redteam_jobs",
}
ENSEMBLE_BATCHES = {
    "research-a": (
        "research",
        "research_jobs_a",
        "output.researcher_a",
    ),
    "research-b": (
        "research",
        "research_jobs_b",
        "output.researcher_b",
    ),
    "panel-a": (
        "panel",
        "verification_jobs_a",
        "output.panel_verifier_a",
    ),
    "panel-b": (
        "panel",
        "verification_jobs_b",
        "output.panel_verifier_b",
    ),
    "panel-c": (
        "panel",
        "verification_jobs_c",
        "output.panel_verifier_c",
    ),
    "repanel-a": (
        "repanel",
        "repanel_jobs_a",
        "output.repanel_verifier_a",
    ),
    "repanel-b": (
        "repanel",
        "repanel_jobs_b",
        "output.repanel_verifier_b",
    ),
    "repanel-c": (
        "repanel",
        "repanel_jobs_c",
        "output.repanel_verifier_c",
    ),
}
VERIFICATION_SLOT_BY_LENS = {
    "REACHABILITY": "a",
    "IMPACT": "b",
    "DEFENSES": "c",
}


class WorkflowDataError(RuntimeError):
    """A deterministic workflow-data failure."""


def root() -> Path:
    return Path.cwd().resolve()


def clean_text(value: Any, cap: int = 4000) -> str:
    text = str("" if value is None else value)
    text = "".join(
        character
        if character in "\n\t" or ord(character) >= 0x20
        else " "
        for character in text
    )
    if len(text) > cap:
        return text[:cap] + f"...[+{len(text) - cap} chars]"
    return text


def one_line(value: Any, cap: int = 500) -> str:
    return (
        clean_text(value, cap)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )


def boolean_input(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise WorkflowDataError(f"{name} must be true or false, got {value!r}")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def read_json(path: Path, required: bool = True) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            raise WorkflowDataError(f"required file is missing: {path}")
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        if required:
            raise WorkflowDataError(f"could not read JSON from {path}: {error}") from error
        return None


def load_state() -> Dict[str, Any]:
    value = read_json(STATE_PATH)
    if not isinstance(value, dict):
        raise WorkflowDataError(f"{STATE_PATH} must contain a JSON object")
    return value


def save_state(state: Mapping[str, Any]) -> None:
    copy = dict(state)
    write_json(STATE_PATH, copy)
    run_dir = copy.get("run_dir")
    if isinstance(run_dir, str) and run_dir:
        write_json(Path(run_dir) / "state.json", copy)


def emit(**updates: Any) -> None:
    print(
        json.dumps(
            {"context_updates": updates},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def git(
    *arguments: str,
    check: bool = False,
    input_bytes: Optional[bytes] = None,
) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(root()), *arguments],
            input=input_bytes,
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


def inside_git_worktree() -> bool:
    return git_text("rev-parse", "--is-inside-work-tree") == "true"


def validate_revision(value: str, field: str) -> str:
    text = value.strip()
    if not SAFE_REV_RE.fullmatch(text):
        raise WorkflowDataError(
            f"{field} must be one conservative Git revision token, got {value!r}"
        )
    return text


def resolve_commit(value: str, field: str) -> str:
    revision = validate_revision(value, field)
    resolved = git_text(
        "rev-parse",
        "--verify",
        "--quiet",
        revision + "^{commit}",
    )
    if not resolved:
        raise WorkflowDataError(
            f"{field} {value!r} does not resolve to a commit in this checkout; "
            "the workflow does not fetch missing refs"
        )
    return resolved


def parse_two_sided_range(raw: str) -> Tuple[str, str, str]:
    text = raw.strip()
    separator = "..." if "..." in text else ".."
    if separator not in text:
        raise WorkflowDataError(
            "range must be explicit and two-sided, such as base..HEAD"
        )
    left, right = text.split(separator, 1)
    if not left or not right or ".." in left or ".." in right:
        raise WorkflowDataError(
            "range must contain exactly two Git revision tokens"
        )
    return (
        validate_revision(left, "range start"),
        separator,
        validate_revision(right, "range end"),
    )


def default_base_ref() -> str:
    candidates: List[str] = []
    upstream = git_text(
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
    )
    if upstream and SAFE_REV_RE.fullmatch(upstream):
        candidates.append(upstream)
    candidates.extend(
        ["origin/HEAD", "origin/main", "origin/master", "main", "master"]
    )
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if git_text(
            "rev-parse",
            "--verify",
            "--quiet",
            candidate + "^{commit}",
        ):
            return candidate
    raise WorkflowDataError(
        "changes mode could not resolve a base ref. Supply --base or an explicit "
        "two-sided --range; the workflow does not fetch"
    )


def empty_tree_hash() -> str:
    result = git("hash-object", "-t", "tree", "--stdin", check=True, input_bytes=b"")
    value = result.stdout.decode("ascii", "replace").strip()
    if not value:
        raise WorkflowDataError("Git did not return the empty-tree object id")
    return value


def parse_scope(raw: str) -> List[str]:
    entries = [entry.strip().replace("\\", "/") for entry in raw.split(",")]
    entries = [entry for entry in entries if entry]
    if entries and all(entry in (".", "./") for entry in entries):
        return []
    normalized: List[str] = []
    for entry in entries:
        candidate = normalize_repo_path(entry)
        if candidate is None:
            raise WorkflowDataError(f"scope path is unsafe: {entry!r}")
        if candidate != "." and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def normalize_repo_path(value: Any) -> Optional[str]:
    text = str("" if value is None else value).strip().replace("\\", "/")
    repository = root().as_posix().rstrip("/")
    if text == repository:
        return "."
    if text.startswith(repository + "/"):
        text = text[len(repository) + 1 :]
    while text.startswith("./"):
        text = text[2:]
    text = re.sub(r"/+$", "", text)
    if not text:
        return "."
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def normalize_coverage_path(value: Any) -> Optional[str]:
    normalized = normalize_repo_path(value)
    if normalized is None:
        return None
    if (
        normalized == "."
        or re.fullmatch(r"\*+", normalized)
        or normalized.startswith("**/")
    ):
        return ""
    normalized = re.sub(r"(/+(\*+|\.))+/*$", "", normalized)
    return normalized.rstrip("/")


def decode_z_paths(raw: bytes) -> List[str]:
    return [
        item.decode("utf-8", "surrogateescape").replace("\\", "/")
        for item in raw.split(b"\0")
        if item
    ]


def tracked_files(scopes: Sequence[str] = ()) -> List[str]:
    if not inside_git_worktree():
        return []
    arguments = ["ls-files", "-z"]
    if scopes:
        arguments.extend(["--", *scopes])
    result = git(*arguments, check=True)
    return sorted(decode_z_paths(result.stdout))


def repository_file_count() -> int:
    """The scan target's file count, by the plugin's gauge: tracked files in a
    worktree, otherwise a recursive listing."""
    if inside_git_worktree():
        return len(tracked_files())
    return len(repo_files())


def is_generated_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    top = normalized.split("/", 1)[0]
    if top.startswith("CLAUDE-SECURITY-"):
        return True
    generated = (
        ".fabro/blobs",
        ".fabro/workflows/security-review/runtime",
        ".fabro/workflows/security-review/reports",
    )
    return any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in generated
    )


def repo_files() -> List[str]:
    listing = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if listing.returncode == 0:
        return sorted(
            path
            for path in decode_z_paths(listing.stdout)
            if not is_generated_path(path)
        )

    paths: List[str] = []
    skipped_directories = {
        ".git",
        ".cache",
        ".venv",
        "dist",
        "node_modules",
        "target",
    }
    for current, directories, files in os.walk(root()):
        directories[:] = [
            name
            for name in directories
            if name not in skipped_directories
            and not name.startswith("CLAUDE-SECURITY-")
        ]
        for name in files:
            relative = (Path(current) / name).relative_to(root()).as_posix()
            if not is_generated_path(relative):
                paths.append(relative)
    return sorted(paths)


def diff_stats(
    revision_range: str,
    scopes: Sequence[str],
) -> Tuple[List[str], Optional[int]]:
    suffix = ["--", *scopes] if scopes else ["--"]
    names = git(
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "-z",
        revision_range,
        *suffix,
        check=True,
    )
    files = decode_z_paths(names.stdout)
    numstat = git(
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--numstat",
        revision_range,
        *suffix,
        check=True,
    )
    total = 0
    for raw_line in numstat.stdout.decode("utf-8", "replace").splitlines():
        columns = raw_line.split("\t", 2)
        if (
            len(columns) < 3
            or not columns[0].isdigit()
            or not columns[1].isdigit()
        ):
            return files, None
        total += int(columns[0]) + int(columns[1])
    return files, total


def workspace_digest() -> str:
    digest = hashlib.sha256()
    for relative in repo_files():
        digest.update(relative.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        path = root() / relative
        try:
            stat_result = path.lstat()
        except FileNotFoundError:
            digest.update(b"MISSING\0")
            continue
        digest.update(str(stat_result.st_mode).encode("ascii"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(os.readlink(path).encode("utf-8", "surrogateescape"))
        elif path.is_file():
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def assert_workspace_unchanged(state: Mapping[str, Any]) -> None:
    """Refuse to publish results derived from a tampered source tree.

    Tamper evidence behind the read-only tool guard: an agent that finds a
    way to write could shape what the verifiers and the report see. Checked
    only at the publication gates (final-tally and render-report) — one
    full-tree digest there gives the same guarantee as checking at every
    deterministic step, without the repeated O(repository) hashing.
    """
    expected = state.get("workspace_digest")
    actual = workspace_digest()
    if not isinstance(expected, str) or actual != expected:
        raise WorkflowDataError(
            "the reviewed source tree changed during the scan; refusing "
            "to publish results derived from it"
        )


def worktree_dirty() -> Optional[bool]:
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status.returncode != 0:
        return None
    for raw_entry in status.stdout.split(b"\0"):
        if not raw_entry:
            continue
        entry = raw_entry.decode("utf-8", "surrogateescape")
        path = entry[3:].split(" -> ")[-1] if len(entry) >= 4 else entry
        if not is_generated_path(path):
            return True
    return False


def revision_record(
    mode: str,
    target_commit: Optional[str],
    base: Optional[str],
    merge_base: Optional[str],
    parent: Optional[str],
    revision_range: Optional[str],
) -> Dict[str, Any]:
    if not inside_git_worktree():
        return {"versioned": False}
    head = git_text("rev-parse", "HEAD")
    branch = git_text("symbolic-ref", "--short", "-q", "HEAD")
    if mode == "commit":
        return {
            "versioned": True,
            "commit": target_commit,
            "parent": parent,
            "branch": branch,
            "dirty": False,
            "range": revision_range,
        }
    revision: Dict[str, Any] = {
        "versioned": True,
        "commit": target_commit or head,
        "branch": branch,
        "dirty": worktree_dirty(),
    }
    if mode == "changes":
        revision.update(
            {
                "base": base,
                "merge_base": merge_base,
                "range": revision_range,
            }
        )
    return revision


def top_level_directories() -> Optional[List[str]]:
    if inside_git_worktree():
        names = set()
        for path in tracked_files():
            top, separator, _rest = path.partition("/")
            if separator and top:
                names.add(top)
            elif path and (root() / path).is_dir():
                # A tracked top-level path that is a directory: a gitlink
                # (submodule) lists this way in git ls-files.
                names.add(path)
        return sorted(
            name for name in names if not name.startswith("CLAUDE-SECURITY-")
        )
    try:
        return sorted(
            entry.name
            for entry in os.scandir(root())
            if entry.is_dir(follow_symlinks=False)
            and entry.name != ".git"
            and not entry.name.startswith("CLAUDE-SECURITY-")
        )
    except OSError:
        return None


def unique_report_dir() -> Tuple[Path, str]:
    stem = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"CLAUDE-SECURITY-{stem}"
    candidate = root() / name
    suffix = 1
    while candidate.exists():
        name = f"CLAUDE-SECURITY-{stem}-{suffix}"
        candidate = root() / name
        suffix += 1
    candidate.mkdir(parents=False)
    return candidate, name


def common_target(state: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "mode": state.get("mode"),
        "scope": state.get("scope") or [],
        "range": state.get("range"),
        "changedFileCount": state.get("diff_files"),
        "changedLineCount": state.get("diff_lines"),
        "focus": state.get("focus"),
        "scanRoot": str(root()),
        "gitWrapper": (
            "python3 .fabro/workflows/security-review/scripts/git_readonly.py"
        ),
    }


def prepare(args: argparse.Namespace) -> None:
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    mode = args.mode.strip().lower()
    if mode not in SCAN_MODES:
        raise WorkflowDataError(
            f"mode must be one of {', '.join(SCAN_MODES)}, got {args.mode!r}"
        )
    ensemble_enabled = boolean_input(args.ensemble, "ensemble")
    effort = args.effort if args.effort in EFFORT_TIERS else "medium"
    if args.effort and args.effort not in EFFORT_TIERS:
        print(
            f'unknown effort "{one_line(args.effort, 60)}" -- using medium '
            f"(tiers: {', '.join(EFFORT_TIERS)})"
        )
    focus_input = args.focus.strip().lower()
    if focus_input == "attack-surface":
        focus = "attack-surface"
    elif focus_input in {"none", "off", "whole-tree"}:
        focus = None
    else:
        if focus_input:
            print(
                f'unknown focus "{one_line(args.focus, 60)}" -- choosing by '
                "repository size (values: attack-surface, none)"
            )
        # A change or commit scan is never focused: the range already says
        # what to read, so an "only production code" filter would contradict
        # the only-what-changed instruction.
        if mode == "scan":
            file_count = repository_file_count()
            if file_count > LARGE_REPOSITORY_FILES:
                focus = "attack-surface"
                print(
                    f"large repository ({file_count} files): focusing on the "
                    "attack surface -- production code that handles input, "
                    "requests, files, credentials, or executes anything. "
                    "Tests, fixtures, generated code, build output, and "
                    "vendored trees are background, and a secrets pass keeps "
                    "fixtures in scope"
                )
            else:
                focus = None
                print(
                    f"small repository ({file_count} files): reading the "
                    "whole tree, no attack-surface focus"
                )
        else:
            focus = None
    scope = parse_scope(args.scope)
    base_input = args.base.strip()
    commit_input = args.commit.strip()
    range_input = args.range.strip()

    revision_range: Optional[str] = None
    base: Optional[str] = None
    merge_base: Optional[str] = None
    target_commit: Optional[str] = None
    parent: Optional[str] = None
    changed_files: List[str] = []
    diff_lines: Optional[int] = None
    scope_file_count: Optional[int] = None

    if mode == "scan":
        if base_input or commit_input or range_input:
            raise WorkflowDataError(
                "scan mode does not accept base, commit, or range inputs"
            )
        if scope:
            if inside_git_worktree():
                scope_file_count = len(tracked_files(scope))
            else:
                scope_file_count = len(
                    [
                        path
                        for path in repo_files()
                        if any(
                            path == item
                            or path.startswith(item.rstrip("/") + "/")
                            for item in scope
                        )
                    ]
                )
    elif mode == "changes":
        if not inside_git_worktree():
            raise WorkflowDataError("changes mode requires a Git worktree")
        if commit_input:
            raise WorkflowDataError(
                "changes mode does not accept commit; use mode=commit"
            )
        if range_input and base_input:
            raise WorkflowDataError(
                "changes mode accepts either base or an explicit range, not both"
            )
        if range_input:
            left, separator, right = parse_two_sided_range(range_input)
            left_commit = resolve_commit(left, "range start")
            target_commit = resolve_commit(right, "range end")
            revision_range = f"{left}{separator}{right}"
            base = left
            if separator == "...":
                merge_base = git_text("merge-base", left_commit, target_commit)
                if not merge_base:
                    raise WorkflowDataError(
                        "the explicit range endpoints have no merge base"
                    )
            else:
                merge_base = left_commit
        else:
            base = validate_revision(
                base_input or default_base_ref(),
                "base",
            )
            base_commit = resolve_commit(base, "base")
            target_commit = resolve_commit("HEAD", "HEAD")
            merge_base = git_text("merge-base", base_commit, target_commit)
            if not merge_base:
                raise WorkflowDataError(
                    f"base {base!r} and HEAD have no merge base"
                )
            revision_range = f"{merge_base}..HEAD"
        changed_files, diff_lines = diff_stats(revision_range, scope)
    else:
        if not inside_git_worktree():
            raise WorkflowDataError("commit mode requires a Git worktree")
        if not commit_input:
            raise WorkflowDataError("commit mode requires a commit input")
        if base_input or range_input:
            raise WorkflowDataError(
                "commit mode accepts commit only; base and range are not used"
            )
        target_commit = resolve_commit(commit_input, "commit")
        parent = git_text(
            "rev-parse",
            "--verify",
            "--quiet",
            target_commit + "^",
        )
        revision_range = f"{parent or empty_tree_hash()}..{target_commit}"
        changed_files, diff_lines = diff_stats(revision_range, scope)

    diff_file_count = (
        len(changed_files) if mode in {"changes", "commit"} else None
    )
    empty_diff = mode in {"changes", "commit"} and diff_file_count == 0
    empty_scope = (
        mode == "scan" and scope_file_count is not None and scope_file_count == 0
    )
    small_diff = (
        effort == "medium"
        and diff_file_count is not None
        and 0 < diff_file_count <= SMALL_DIFF_MAX_FILES
        and diff_lines is not None
        and diff_lines <= SMALL_DIFF_MAX_LINES
    )
    small_scope = (
        effort == "medium"
        and scope_file_count is not None
        and 0 < scope_file_count <= SMALL_SCOPE_MAX_FILES
    )
    collapsed = (
        "small-diff" if small_diff else ("small-scope" if small_scope else None)
    )
    use_single = effort == "low" or collapsed is not None
    use_inventory = not use_single
    whole_tree_inventory = (
        use_inventory and mode == "scan" and not scope
    )
    top_level_dirs = top_level_directories() if mode == "scan" and not scope else None
    empty_target = empty_diff or empty_scope

    state: Dict[str, Any] = {
        "version": 3,
        "root": str(root()),
        "products_dir": None,
        "products_rel": None,
        "run_dir": None,
        "mode": mode,
        "effort": effort,
        "ensemble_enabled": ensemble_enabled,
        "focus": focus,
        "scope": scope,
        "range": revision_range,
        "base": base,
        "merge_base": merge_base,
        "commit": target_commit,
        "parent": parent,
        "changed_files": changed_files,
        "diff_files": diff_file_count,
        "diff_lines": diff_lines,
        "scope_files": scope_file_count,
        "empty_diff": empty_diff,
        "empty_scope": empty_scope,
        "collapsed": collapsed,
        "use_single": use_single,
        "use_inventory": use_inventory,
        "whole_tree_inventory": whole_tree_inventory,
        "max_components": (
            MAX_COMPONENTS_EXPANDED
            if effort in {"high", "max"}
            else MAX_COMPONENTS_DEFAULT
        ),
        "researchers_per_cell": 2 if effort in {"high", "max"} else 1,
        "base_sweeps": (
            0 if use_single else (2 if effort in {"high", "max"} else 1)
        ),
        "secrets_sweep": bool(focus) and mode == "scan",
        "top_level_dirs": top_level_dirs if whole_tree_inventory else None,
        "top_level_rejected": (
            "the top-level directory list could not be computed"
            if whole_tree_inventory and top_level_dirs is None
            else None
        ),
        "completeness": (
            "not-checkable"
            if whole_tree_inventory and top_level_dirs is None
            else ("checked" if whole_tree_inventory else "not-applicable")
        ),
        "unaccounted_top_level_dirs": [],
        "inventory_rejected": [],
        "inventory_fallback": None,
        "inventory_attempt": 0,
        "components": None,
        "skipped_components": [],
        "dropped_components": [],
        "pruned_buckets": [],
        "adversarial_casualties": [],
        "phase_results": {},
        "phase_jobs": {},
    }

    if empty_target:
        save_state(state)
        reason = (
            "the committed range has no changed files"
            if empty_diff
            else "the scope resolves to no tracked files"
        )
        print(f"Nothing to scan: {reason}")
        emit(
            empty_target=True,
            empty_reason=reason,
            mode=mode,
            effort=effort,
            ensemble_enabled=ensemble_enabled,
        )
        return

    products_dir, products_rel = unique_report_dir()
    run_dir = products_dir / ".claude-security-run"
    run_dir.mkdir()
    (products_dir / ".gitignore").write_text("*\n", encoding="utf-8")
    (run_dir / ".gitignore").write_text("*\n", encoding="utf-8")
    state["products_dir"] = products_dir.as_posix()
    state["products_rel"] = products_rel
    state["run_dir"] = run_dir.as_posix()

    revision = revision_record(
        mode,
        target_commit,
        base,
        merge_base,
        parent,
        revision_range,
    )
    scan_meta = {
        "scan_root": str(root()),
        "run_dir": run_dir.as_posix(),
        "flow": "scan" if mode == "scan" else "changes",
        "agent": "fabro:security-review",
        "mode": mode,
        "scope": scope,
        "effort": effort,
        "model_strategy": "ensemble" if ensemble_enabled else "standard",
        "model": {
            "provider": "openrouter",
            "inventory": "sonnet",
            "scan": (
                "ensemble-a/b/c/d" if ensemble_enabled else "opus"
            ),
        },
        "revision": revision,
        "revision_source": "self-reported",
        "top_level_dirs": top_level_dirs,
        "range": revision_range,
    }
    write_json(run_dir / "scan-meta.json", scan_meta)
    state["workspace_digest"] = workspace_digest()
    save_state(state)

    inventory_assignment = {
        "scanRoot": str(root()),
        "target": common_target(state),
        "maxComponents": state["max_components"],
        "topLevelDirectories": state["top_level_dirs"],
        "wholeTreeCompletenessRequired": whole_tree_inventory,
    }
    if collapsed == "small-diff":
        print(
            f"small diff ({diff_file_count} file"
            f"{'' if diff_file_count == 1 else 's'}"
            + (f", {diff_lines} lines" if diff_lines is not None else "")
            + f" changed): running the single-researcher shape at {effort} "
            "instead of the full component matrix -- proportionate to the "
            "change, still panel-verified"
        )
    elif collapsed == "small-scope":
        print(
            f"small scope ({scope_file_count} file"
            f"{'' if scope_file_count == 1 else 's'}): running the "
            f"single-researcher shape at {effort} instead of the full "
            "component matrix -- proportionate to the scope, still "
            "panel-verified"
        )
    elif use_single:
        print("low effort: one whole-repository component")
    shape = "single-researcher" if use_single else "component-matrix"
    print(f"Prepared {effort} {mode} security review using the {shape} shape")
    if ensemble_enabled:
        print(
            "ensemble input: enabling neutral model slots A/B/C/D across "
            "research, verification, and report synthesis"
        )
    emit(
        empty_target=False,
        use_inventory=use_inventory,
        effort=effort,
        ensemble_enabled=ensemble_enabled,
        mode=mode,
        inventory_assignment=inventory_assignment,
        products_dir=products_rel,
    )


def string_list(
    value: Any,
    cap: int = 200,
    item_cap: int = 1000,
) -> Optional[List[str]]:
    if not isinstance(value, list):
        return None
    result: List[str] = []
    for item in value[:cap]:
        if not isinstance(item, str):
            return None
        result.append(clean_text(item, item_cap))
    return result


def normalize_inventory(
    raw: Any,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], List[str]]:
    errors: List[str] = []
    unsafe_paths: List[str] = []
    if not isinstance(raw, dict):
        return [], [], ["inventory result is not an object"], unsafe_paths
    raw_components = raw.get("components")
    raw_skipped = raw.get("securityScanSkippedComponents")
    if not isinstance(raw_components, list):
        errors.append("components is not an array")
        raw_components = []
    if not isinstance(raw_skipped, list):
        errors.append("securityScanSkippedComponents is not an array")
        raw_skipped = []

    components: List[Dict[str, Any]] = []
    for index, item in enumerate(raw_components):
        if not isinstance(item, dict):
            errors.append(f"component {index + 1} is not an object")
            continue
        name = one_line(item.get("name"), 120).strip()
        language = one_line(item.get("language"), 120).strip()
        raw_paths = item.get("paths")
        if not name or not language or not isinstance(raw_paths, list):
            errors.append(
                f"component {index + 1} is missing name, language, or paths"
            )
            continue
        paths: List[str] = []
        for raw_path in raw_paths:
            normalized = normalize_repo_path(raw_path)
            if normalized is None:
                unsafe_paths.append(one_line(raw_path, 300))
                continue
            if normalized not in paths:
                paths.append(normalized)
        if not paths:
            errors.append(f"component {name} has no usable paths")
            continue
        components.append(
            {
                "name": name,
                "paths": paths,
                "language": language,
                "role": one_line(item.get("role") or "", 500),
                "internetFacing": bool(item.get("internetFacing", False)),
            }
        )

    skipped: List[Dict[str, Any]] = []
    for index, item in enumerate(raw_skipped):
        if not isinstance(item, dict):
            errors.append(f"skipped entry {index + 1} is not an object")
            continue
        name = one_line(item.get("name"), 120).strip()
        reason = one_line(item.get("reason"), 500).strip()
        raw_paths = item.get("paths")
        if not name or not reason or not isinstance(raw_paths, list):
            errors.append(
                f"skipped entry {index + 1} is missing name, reason, or paths"
            )
            continue
        paths: List[str] = []
        for raw_path in raw_paths:
            normalized = normalize_repo_path(raw_path)
            if normalized is None:
                unsafe_paths.append(one_line(raw_path, 300))
                continue
            if normalized not in paths:
                paths.append(normalized)
        if not paths:
            errors.append(f"skipped entry {name} has no usable paths")
            continue
        skipped.append({"name": name, "paths": paths, "reason": reason})
    return components, skipped, errors, unsafe_paths


def flatten_paths(entries: Iterable[Mapping[str, Any]]) -> List[str]:
    paths: List[str] = []
    for entry in entries:
        raw = entry.get("paths")
        if isinstance(raw, list):
            paths.extend(str(path) for path in raw)
    return paths


def path_accounts_for(path: str, directory: str, skipped: bool) -> bool:
    coverage = normalize_coverage_path(path)
    target = normalize_repo_path(directory)
    if coverage is None or target is None:
        return False
    if skipped:
        return bool(coverage) and (
            coverage == target
            or target.startswith(coverage.rstrip("/") + "/")
        )
    return (
        coverage == ""
        or coverage == target
        or coverage.startswith(target.rstrip("/") + "/")
        or target.startswith(coverage.rstrip("/") + "/")
    )


def inventory_feedback(
    whole_target_skip: bool,
    unaccounted: Sequence[str],
    overflow: int,
    max_components: int,
    component_count: int,
    other_problems: Sequence[str],
) -> str:
    """The plugin's correction resend, translated for the appended context."""
    parts = [
        "YOUR PREVIOUS ANSWER WAS REJECTED and must be resubmitted COMPLETE:"
    ]
    if whole_target_skip:
        parts.append(
            "* A securityScanSkippedComponents entry names the whole scan "
            'target ("." or the repository root). A skip must NAME the '
            'directories it skips -- skipping "everything else" says nothing '
            "about what was left out. If most of the tree is genuinely out "
            "of scope, list those directories (or their common parents) as "
            "separate skip entries, each with its reason."
        )
    if unaccounted:
        preview = ", ".join(one_line(name, 200) for name in unaccounted[:40])
        if len(unaccounted) > 40:
            preview += f" [+{len(unaccounted) - 40} more]"
        parts.append(
            "* It accounted for only part of the scan target. These "
            "top-level directories appeared in NO component's paths and NO "
            "securityScanSkippedComponents entry:\n"
            "<untrusted-directories>\n"
            f"{preview}\n"
            "</untrusted-directories>"
        )
    if overflow:
        parts.append(
            f"* Only your first {max_components} components are used (you "
            f"returned {component_count}), so coverage placed in the "
            "components beyond that cap does not count -- merge components "
            "rather than exceeding it."
        )
    parts.extend(f"* {one_line(problem, 1000)}" for problem in other_problems)
    parts.append(
        "Return the COMPLETE inventory again -- every component AND every "
        "skipped entry, not just the missing ones -- so that every top-level "
        "directory of the target lands in one of the two lists. A directory "
        "that does not warrant scanning goes in "
        "securityScanSkippedComponents with a one-line reason; nothing may "
        "be simply left out."
    )
    parts.append(
        "This is your one correction: your next answer is used as it "
        "stands. Any top-level directory it still leaves out of both lists "
        "is recorded in the report as unaccounted for -- so account for as "
        "much of the tree as you honestly can, using broad shared-parent "
        "paths where a per-directory listing would be long."
    )
    return "\n\n".join(parts)


def merge_inventory(state: Dict[str, Any], raw: Any) -> Dict[str, Any]:
    defaults = {
        "inventory_done": False,
        "inventory_correction": False,
        "inventory_feedback": "",
    }
    if not isinstance(raw, dict):
        state["inventory_fallback"] = "inventory-failed"
        state["components"] = None
        state["skipped_components"] = []
        defaults["inventory_done"] = True
        return defaults

    components, skipped, schema_errors, unsafe_paths = normalize_inventory(raw)
    if schema_errors and not components:
        state["inventory_fallback"] = "empty-partition"
        state["components"] = None
        state["skipped_components"] = []
        defaults["inventory_done"] = True
        return defaults

    state["inventory_attempt"] = int(state.get("inventory_attempt", 0)) + 1
    attempt = int(state["inventory_attempt"])
    max_components = int(state["max_components"])
    kept = components[:max_components]
    overflow = max(0, len(components) - len(kept))
    top_dirs = state.get("top_level_dirs")
    whole_target_skip = any(
        normalize_coverage_path(path) == ""
        for path in flatten_paths(skipped)
    )
    scanned_paths = flatten_paths(kept)
    skipped_paths = [
        path
        for path in flatten_paths(skipped)
        if normalize_coverage_path(path) != ""
    ]
    unaccounted: List[str] = []
    if isinstance(top_dirs, list) and kept:
        for directory in top_dirs:
            scanned = any(
                path_accounts_for(path, directory, False)
                for path in scanned_paths
            )
            explicitly_skipped = any(
                path_accounts_for(path, directory, True)
                for path in skipped_paths
            )
            if not scanned and not explicitly_skipped:
                unaccounted.append(directory)

    unsafe_problem = (
        "paths with parent traversal or an absolute outside path account "
        "for nothing: " + ", ".join(unsafe_paths[:40])
        if unsafe_paths
        else None
    )
    problems = list(schema_errors)
    if whole_target_skip:
        problems.append(
            "a securityScanSkippedComponents entry names the whole scan target"
        )
    if unsafe_problem:
        problems.append(unsafe_problem)
    if unaccounted:
        problems.append(
            f"{len(unaccounted)} top-level directories are neither scanned nor "
            "skipped: " + ", ".join(unaccounted[:40])
        )
    if unaccounted and overflow:
        problems.append(
            f"only the first {max_components} of {len(components)} components "
            "count toward coverage"
        )
    if problems:
        state.setdefault("inventory_rejected", []).append(
            f"attempt {attempt}: "
            + "; ".join(one_line(problem, 1000) for problem in problems)
        )

    if components and problems and attempt < 2:
        feedback = inventory_feedback(
            whole_target_skip=whole_target_skip,
            unaccounted=unaccounted,
            overflow=overflow,
            max_components=max_components,
            component_count=len(components),
            other_problems=(
                list(schema_errors)
                + ([unsafe_problem] if unsafe_problem else [])
            ),
        )
        defaults["inventory_correction"] = True
        defaults["inventory_feedback"] = feedback
        state["inventory_feedback"] = feedback
        return defaults

    unusable = whole_target_skip or (
        not scanned_paths and bool(unsafe_paths)
    )
    if not components:
        state["inventory_fallback"] = "empty-partition"
        state["components"] = None
        state["skipped_components"] = []
    elif unusable:
        state["inventory_fallback"] = "incomplete-partition"
        state["components"] = None
        state["skipped_components"] = []
        state["unaccounted_top_level_dirs"] = []
    else:
        state["components"] = kept
        state["skipped_components"] = skipped
        state["dropped_components"] = [
            component["name"] for component in components[max_components:]
        ]
        state["unaccounted_top_level_dirs"] = unaccounted
        if unaccounted:
            state["completeness"] = "partial"
        if (
            isinstance(top_dirs, list)
            and not top_dirs
            and any("/" in path for path in scanned_paths + skipped_paths)
        ):
            state["completeness"] = "not-checkable"
            state["top_level_rejected"] = (
                "topLevelDirs was empty, but the inventory names paths inside "
                "subdirectories"
            )
    state.pop("inventory_feedback", None)
    defaults["inventory_done"] = True
    return defaults


def inventory_failed() -> None:
    state = load_state()
    state["inventory_fallback"] = "inventory-failed"
    state["components"] = None
    state["skipped_components"] = []
    state.pop("inventory_feedback", None)
    save_state(state)
    print(
        "Inventory agent failed after native retries; scanning the whole "
        "target as one component"
    )
    emit(inventory_fallback="inventory-failed")


def artifact_key(index: int, name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    slug = slug or "component"
    suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    return f"{index:03d}-{slug}-{suffix}"


def set_phase_jobs(
    state: Dict[str, Any],
    phase: str,
    jobs: Sequence[Mapping[str, Any]],
) -> None:
    values = [dict(job) for job in jobs]
    state.setdefault("phase_jobs", {})[phase] = values
    state.setdefault("phase_results", {}).setdefault(phase, {})


def phase_jobs_context(
    state: Mapping[str, Any],
    phase: str,
    jobs: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    del state
    key = PHASE_JOB_KEYS[phase]
    # Fabro's parallel handler requires the context value itself to be an
    # array. Fabro offloads large values and hydrates them before `for_each`;
    # a user-authored file:// reference is only a string and is not hydrated.
    return {key: [dict(job) for job in jobs]}


def fallback_component(state: Mapping[str, Any]) -> Dict[str, Any]:
    paths = list(state.get("scope") or ["."])
    return {
        "name": "repository",
        "paths": paths,
        "language": "mixed",
        "role": "whole scan target",
        "internetFacing": False,
    }


def plan_matrix() -> None:
    state = load_state()
    components = state.get("components")
    if not isinstance(components, list) or not components:
        components = [fallback_component(state)]
    max_components = int(state["max_components"])
    dropped = components[max_components:]
    if dropped:
        state["dropped_components"] = [
            one_line(component.get("name"), 120)
            for component in dropped
            if isinstance(component, dict)
        ]
    planned: List[Dict[str, Any]] = []
    target = common_target(state)
    for index, component in enumerate(components[:max_components], 1):
        if not isinstance(component, dict):
            continue
        name = one_line(component.get("name"), 120)
        key = artifact_key(index, name)
        planned.append(
            {
                "name": name,
                "paths": list(component.get("paths") or ["."]),
                "language": one_line(component.get("language") or "mixed", 120),
                "role": one_line(component.get("role") or "", 500),
                "internetFacing": bool(component.get("internetFacing", False)),
                "artifact_key": key,
                "job_id": f"threat:{key}",
                "target": target,
            }
        )
    state["planned_components"] = planned
    run_threat = not bool(state["use_single"]) and bool(planned)
    state["run_threat_models"] = run_threat
    updates: Dict[str, Any] = {"run_threat_models": run_threat}
    if run_threat:
        set_phase_jobs(state, "threat", planned)
        updates.update(phase_jobs_context(state, "threat", planned))
    else:
        build_cells(state)
        updates.update(research_sweep_updates(state))
    save_state(state)
    fallback = state.get("inventory_fallback")
    if fallback:
        print(
            f"inventory fallback ({fallback}): scanning the whole target "
            "as one component so nothing goes unscanned"
        )
    skipped = state.get("skipped_components") or []
    if skipped:
        print(
            "inventory: not scanned, by the componentizer's account "
            f"({len(skipped)}): "
            + "; ".join(
                f"{entry.get('name')} -- {entry.get('reason')}"
                for entry in skipped
                if isinstance(entry, dict)
            )
        )
    dropped_names = state.get("dropped_components") or []
    if dropped_names:
        print(
            f"inventory cap: keeping {len(planned)} of "
            f"{len(planned) + len(dropped_names)} components, dropped: "
            + ", ".join(dropped_names)
        )
    print(
        f"Planned {len(planned)} component(s): "
        + ", ".join(component["name"] for component in planned)
    )
    emit(**updates)


def split_languages(description: Any) -> List[str]:
    words = re.split(r"[/,+&()\s]+", str(description or ""))
    return [
        word.strip()
        for word in words
        if word.strip() and not LANGUAGE_JOIN_WORD_RE.match(word.strip())
    ]


def managed_only(component: Mapping[str, Any]) -> bool:
    languages = split_languages(component.get("language"))
    return bool(languages) and all(
        MANAGED_LANGUAGE_RE.match(language) for language in languages
    )


def normalize_threat_model(value: Any) -> Optional[Dict[str, List[str]]]:
    if not isinstance(value, dict):
        return None
    entry_points = string_list(value.get("entryPoints"))
    sinks = string_list(value.get("sinks"))
    hot_files = string_list(value.get("hotFiles"))
    assumptions = string_list(value.get("assumptions", []))
    boundaries = string_list(value.get("trustBoundaries", []))
    if (
        entry_points is None
        or sinks is None
        or hot_files is None
        or assumptions is None
        or boundaries is None
    ):
        return None
    return {
        "entryPoints": entry_points,
        "sinks": sinks,
        "assumptions": assumptions,
        "trustBoundaries": boundaries,
        "hotFiles": hot_files,
    }


def build_cells(state: Dict[str, Any]) -> None:
    components = state.get("planned_components")
    if not isinstance(components, list):
        raise WorkflowDataError("planned components are missing")
    threat_results = (
        state.get("phase_results", {}).get("threat", {})
        if isinstance(state.get("phase_results"), dict)
        else {}
    )
    research_jobs: List[Dict[str, Any]] = []
    research_jobs_by_slot: Dict[str, List[Dict[str, Any]]] = {
        "a": [],
        "b": [],
    }
    pruned: List[str] = []
    passes = int(state["researchers_per_cell"])
    target = common_target(state)

    for component in components:
        if not isinstance(component, dict):
            continue
        model = normalize_threat_model(
            threat_results.get(component.get("job_id"))
            if isinstance(threat_results, dict)
            else None
        )
        lenses = list(CATEGORY_LENSES)
        if managed_only(component):
            lenses = [
                lens for lens in lenses if lens[0] != "memory-and-unsafe"
            ]
            pruned.append(f"{component['name']}:memory-and-unsafe")
        if state["use_single"]:
            combined = "; ".join(lens for _, lens in lenses)
            assignments = [
                (
                    "all",
                    "every category at once — you are the only research pass, "
                    "so map the attack surface briefly and hunt breadth-first "
                    "for the highest-severity, most reachable issues across: "
                    + combined,
                    1,
                )
            ]
        else:
            assignments = [
                (key, lens, pass_number)
                for key, lens in lenses
                for pass_number in range(1, passes + 1)
            ]
        for key, lens, pass_number in assignments:
            suffix = (
                f":{pass_number}"
                if passes > 1 and key != "all"
                else ""
            )
            job_id = (
                f"research:{component['artifact_key']}:{key}"
                + (f":{pass_number}" if suffix else "")
            )
            job = {
                "name": f"{component['name']}:{key}{suffix}",
                "job_id": job_id,
                "kind": "research",
                "component": {
                    "name": component["name"],
                    "paths": component["paths"],
                    "language": component["language"],
                    "role": component.get("role", ""),
                },
                "lens": lens,
                "threatModel": model,
                "target": target,
            }
            research_jobs.append(job)
            if state.get("ensemble_enabled"):
                slot = "a" if pass_number % 2 else "b"
                research_jobs_by_slot[slot].append(job)

    covered_paths = ", ".join(
        path
        for component in components
        if isinstance(component, dict)
        for path in component.get("paths", [])
    )
    sweep_asks = [
        "Look for entry points and dangerous sinks outside the covered paths: "
        "scripts, configuration, CI definitions, migrations, admin tooling, "
        "and glue code.",
        "Look for vulnerabilities between components: a value validated in "
        "one and trusted in another, a boundary each side assumes the other "
        "checks, or inconsistent checks across paths to the same sink.",
    ][: int(state["base_sweeps"])]
    sweep_jobs: List[Dict[str, Any]] = []
    for index, ask in enumerate(sweep_asks, 1):
        sweep_jobs.append(
            {
                "name": f"sweep:{index}",
                "job_id": f"sweep:{index}",
                "kind": "sweep",
                "ask": ask,
                "coveredPaths": clean_text(covered_paths, MAX_RESULT_TEXT),
                "target": target,
            }
        )
    if state["secrets_sweep"]:
        sweep_jobs.append(
            {
                "name": "sweep:secrets",
                "job_id": "sweep:secrets",
                "kind": "sweep",
                "ask": (
                    "Look for hardcoded secrets, credentials, tokens, and "
                    "private keys anywhere in the target, including tests, "
                    "fixtures, and configuration. For this pass the fixtures "
                    "ARE in scope: a real key committed to a test file is a "
                    "real leak."
                ),
                "coveredPaths": clean_text(covered_paths, MAX_RESULT_TEXT),
                "target": target,
            }
        )
    state["research_jobs"] = research_jobs
    state["research_jobs_a"] = research_jobs_by_slot["a"]
    state["research_jobs_b"] = research_jobs_by_slot["b"]
    state["sweep_jobs"] = sweep_jobs
    state["pruned_buckets"] = pruned
    state["run_research"] = bool(research_jobs)
    state["run_ensemble_research"] = bool(
        state.get("ensemble_enabled") and research_jobs
    )
    state["run_standard_research"] = bool(
        not state.get("ensemble_enabled") and research_jobs
    )
    state["run_sweeps"] = bool(sweep_jobs)
    set_phase_jobs(state, "research", research_jobs)
    set_phase_jobs(state, "sweep", sweep_jobs)
    for bucket in pruned:
        print(f"{bucket}: skipped (managed language)")


def research_sweep_updates(state: Mapping[str, Any]) -> Dict[str, Any]:
    research_jobs = list(state.get("research_jobs") or [])
    sweep_jobs = list(state.get("sweep_jobs") or [])
    updates: Dict[str, Any] = {
        "run_research": bool(research_jobs),
        "run_ensemble_research": bool(
            state.get("run_ensemble_research")
        ),
        "run_standard_research": bool(
            state.get("run_standard_research")
        ),
        "run_sweeps": bool(sweep_jobs),
    }
    if research_jobs:
        if state.get("ensemble_enabled"):
            updates["research_jobs_a"] = list(
                state.get("research_jobs_a") or []
            )
            updates["research_jobs_b"] = list(
                state.get("research_jobs_b") or []
            )
        else:
            updates.update(phase_jobs_context(state, "research", research_jobs))
    if sweep_jobs:
        updates.update(phase_jobs_context(state, "sweep", sweep_jobs))
    return updates


def zip_cells() -> None:
    state = load_state()
    build_cells(state)
    save_state(state)
    print(
        f"Planned {len(state['research_jobs'])} researcher(s) and "
        f"{len(state['sweep_jobs'])} sweep(s)"
    )
    emit(**research_sweep_updates(state))


def normalize_category(value: Any) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "-",
        one_line(value, 120).lower(),
    ).strip("-")


def normalize_finding(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    path = normalize_repo_path(value.get("file"))
    line = value.get("line")
    severity = one_line(value.get("severity"), 20).upper()
    confidence = one_line(value.get("confidence"), 20).upper()
    category = normalize_category(value.get("category"))
    title = one_line(value.get("title"), 300).strip()
    rationale = clean_text(value.get("rationale"), 4000).strip()
    if (
        path is None
        or path == "."
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
        or severity not in SEVERITY_RANK
        or confidence not in CONFIDENCE_RANK
        or not category
        or not title
        or not rationale
    ):
        return None
    preconditions = string_list(
        value.get("preconditions", []),
        cap=50,
        item_cap=1000,
    )
    return {
        "file": path,
        "line": line,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "rationale": rationale,
        "evidence": clean_text(value.get("evidence"), 8000),
        "snippet": clean_text(value.get("snippet"), 2000),
        "symbol": one_line(value.get("symbol"), 500),
        "impact": clean_text(value.get("impact"), 4000),
        "exploitScenario": clean_text(value.get("exploitScenario"), 4000),
        "preconditions": preconditions or [],
        "recommendation": clean_text(value.get("recommendation"), 4000),
        "cweId": one_line(value.get("cweId"), 50),
    }


def normalize_findings_result(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        return None
    findings: List[Dict[str, Any]] = []
    for raw in value["findings"]:
        finding = normalize_finding(raw)
        if finding is not None:
            findings.append(finding)
    return {"findings": findings}


def normalize_verdict(value: Any) -> Optional[Dict[str, str]]:
    if not isinstance(value, dict):
        return None
    verdict = value.get("verdict")
    reasoning = clean_text(value.get("reasoning"), 4000)
    if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
        return None
    if not isinstance(value.get("reasoning"), str):
        return None
    return {"verdict": verdict, "reasoning": reasoning}


def normalize_phase_result(phase: str, value: Any) -> Optional[Any]:
    if phase == "threat":
        return normalize_threat_model(value)
    if phase in {"research", "sweep"}:
        return normalize_findings_result(value)
    if phase in {"panel", "repanel", "redteam"}:
        return normalize_verdict(value)
    raise WorkflowDataError(f"unknown merge phase: {phase}")


def read_merge_input() -> Any:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise WorkflowDataError(
            f"merge input exceeds the {MAX_STDIN_BYTES}-byte limit"
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WorkflowDataError(f"merge stdin is not valid JSON: {error}") from error


def merge_phase(
    state: Dict[str, Any],
    phase: str,
    raw_results: Any,
    *,
    jobs: Optional[Sequence[Mapping[str, Any]]] = None,
    output_key: Optional[str] = None,
) -> Dict[str, Any]:
    if phase not in PHASE_OUTPUT_KEYS:
        raise WorkflowDataError(f"unknown parallel merge phase: {phase}")
    if not isinstance(raw_results, list):
        raise WorkflowDataError("parallel merge input must be a JSON array")
    if jobs is None:
        jobs = (
            state.get("phase_jobs", {}).get(phase)
            if isinstance(state.get("phase_jobs"), dict)
            else None
        )
    if not isinstance(jobs, list):
        raise WorkflowDataError(f"{phase} merge jobs are missing from state")
    result_map = state.setdefault("phase_results", {}).setdefault(phase, {})
    if not isinstance(result_map, dict):
        raise WorkflowDataError(f"{phase} result accumulator is invalid")
    selected_output_key = output_key or PHASE_OUTPUT_KEYS[phase]

    for position, branch in enumerate(raw_results):
        if position >= len(jobs) or not isinstance(branch, dict):
            continue
        branch_index = branch.get("index")
        if (
            branch_index is not None
            and (
                isinstance(branch_index, bool)
                or not isinstance(branch_index, int)
                or branch_index != position
            )
        ):
            continue
        updates = branch.get("context_updates")
        if not isinstance(updates, dict):
            continue
        value = updates.get(selected_output_key)
        normalized = normalize_phase_result(phase, value)
        if normalized is None:
            continue
        job = jobs[position]
        if not isinstance(job, dict):
            continue
        job_id = job.get("job_id")
        if isinstance(job_id, str) and job_id:
            result_map.setdefault(job_id, normalized)

    return {f"{phase}_results_merged": len(result_map)}


def merge(phase: str) -> None:
    state = load_state()
    raw = read_merge_input()
    if phase == "inventory":
        updates = merge_inventory(state, raw)
        print(
            "Merged inventory output"
            + (
                " -- rejected once, correction requested"
                if updates.get("inventory_correction")
                else ""
            )
        )
    else:
        updates = merge_phase(state, phase, raw)
        print(
            f"Merged {phase}: "
            f"{updates[f'{phase}_results_merged']} result(s) recorded"
        )
    save_state(state)
    emit(**updates)


def merge_ensemble(batch: str) -> None:
    phase, jobs_key, output_key = ENSEMBLE_BATCHES[batch]
    state = load_state()
    jobs = state.get(jobs_key)
    if not isinstance(jobs, list):
        raise WorkflowDataError(
            f"{batch} merge jobs are missing from state"
        )
    updates = merge_phase(
        state,
        phase,
        read_merge_input(),
        jobs=jobs,
        output_key=output_key,
    )
    save_state(state)
    print(
        f"Merged ensemble batch {batch}: "
        f"{updates[f'{phase}_results_merged']} total {phase} result(s) "
        "recorded"
    )
    emit(**updates)


def finding_key(finding: Mapping[str, Any]) -> Tuple[str, int, str]:
    return (
        str(finding.get("file", "")).strip(),
        int(finding.get("line") or 0),
        str(finding.get("category", "")).strip().lower(),
    )


def rank_key(finding: Mapping[str, Any]) -> Tuple[int, int]:
    return (
        -SEVERITY_RANK.get(str(finding.get("severity")), 0),
        -CONFIDENCE_RANK.get(str(finding.get("confidence")), 0),
    )


def verification_claim(candidate: Mapping[str, Any]) -> Dict[str, Any]:
    """The subset of a candidate a verifier is shown.

    Mirrors the plugin's formatFindingClaim: the reporter's claim and its
    cited evidence only. The reporter's confidence, impact story, exploit
    scenario, and recommendation are withheld — they could anchor a panel
    that must default to FALSE_POSITIVE.
    """
    return {
        "file": candidate.get("file"),
        "line": candidate.get("line"),
        "category": candidate.get("category"),
        "severityAsReported": candidate.get("severity"),
        "title": candidate.get("title"),
        "rationale": candidate.get("rationale"),
        "evidenceAsCited": candidate.get("evidence") or "(none)",
        "snippetAsQuoted": candidate.get("snippet") or "(none)",
        "symbol": candidate.get("symbol") or "(none)",
        "reports": int(candidate.get("reports") or 1),
    }


def dedup_rank() -> None:
    state = load_state()
    research_jobs = list(state.get("research_jobs") or [])
    sweep_jobs = list(state.get("sweep_jobs") or [])
    jobs = research_jobs + sweep_jobs
    phase_results = state.get("phase_results") or {}
    research_results = (
        phase_results.get("research", {})
        if isinstance(phase_results, dict)
        else {}
    )
    sweep_results = (
        phase_results.get("sweep", {})
        if isinstance(phase_results, dict)
        else {}
    )
    raw_candidates: List[Dict[str, Any]] = []
    returned = 0
    invalid_results: List[str] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        phase = "sweep" if job.get("kind") == "sweep" else "research"
        source = sweep_results if phase == "sweep" else research_results
        raw = source.get(job.get("job_id")) if isinstance(source, dict) else None
        normalized = normalize_findings_result(raw)
        if normalized is None:
            invalid_results.append(one_line(job.get("name"), 200))
            continue
        returned += 1
        component = (
            job.get("component", {}).get("name", "repository")
            if isinstance(job.get("component"), dict)
            else "sweep"
        )
        for finding in normalized["findings"]:
            copy = dict(finding)
            copy["component"] = one_line(component, 120)
            raw_candidates.append(copy)

    ranked = sorted(raw_candidates, key=rank_key)
    capped = ranked[:CANDIDATE_CAP]
    candidates_dropped = max(0, len(raw_candidates) - len(capped))
    by_key: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    for report in capped:
        key = finding_key(report)
        existing = by_key.get(key)
        if existing is None:
            merged = dict(report)
            merged["reports"] = 1
            merged["reporters"] = [report["component"]]
            by_key[key] = merged
            continue
        existing["reports"] += 1
        if report["component"] not in existing["reporters"]:
            existing["reporters"].append(report["component"])
        if (
            SEVERITY_RANK[report["severity"]]
            > SEVERITY_RANK[existing["severity"]]
        ):
            existing["severity"] = report["severity"]
        if (
            CONFIDENCE_RANK[report["confidence"]]
            > CONFIDENCE_RANK[existing["confidence"]]
        ):
            existing["confidence"] = report["confidence"]
        for field in MERGEABLE_FINDING_FIELDS:
            if not existing.get(field) and report.get(field):
                existing[field] = report[field]

    capped_keys = {finding_key(report) for report in capped}
    dropped_unique = {
        finding_key(report)
        for report in ranked[CANDIDATE_CAP:]
        if finding_key(report) not in capped_keys
    }
    deduplicated = list(by_key.values())
    deduplicated.sort(
        key=lambda finding: (
            -SEVERITY_RANK.get(finding["severity"], 0),
            -int(finding.get("reports", 0)),
            -CONFIDENCE_RANK.get(finding["confidence"], 0),
        )
    )
    for index, candidate in enumerate(deduplicated, 1):
        candidate["id"] = f"F{index}"

    candidates_for_verification = deduplicated[:VERIFICATION_CAP]
    verification_jobs: List[Dict[str, Any]] = []
    verification_jobs_by_slot: Dict[str, List[Dict[str, Any]]] = {
        "a": [],
        "b": [],
        "c": [],
    }
    for candidate in candidates_for_verification:
        for lens in VERIFICATION_LENSES:
            lower_lens = lens.lower()
            job = {
                "name": f"{candidate['id']}:{lower_lens}",
                "job_id": f"panel:{candidate['id']}:{lower_lens}",
                "candidate_id": candidate["id"],
                "finding": verification_claim(candidate),
                "lens": lens,
                "target": common_target(state),
            }
            verification_jobs.append(job)
            if state.get("ensemble_enabled"):
                verification_jobs_by_slot[
                    VERIFICATION_SLOT_BY_LENS[lens]
                ].append(job)

    state["raw_candidate_count"] = len(raw_candidates)
    state["candidates_dropped_by_cap"] = candidates_dropped
    state["dropped_unique_candidate_count"] = len(dropped_unique)
    state["deduplicated_candidates"] = deduplicated
    state["verification_candidates"] = candidates_for_verification
    state["unverified_by_cap"] = max(
        0,
        len(deduplicated) - len(candidates_for_verification),
    )
    state["verification_jobs"] = verification_jobs
    state["verification_jobs_a"] = verification_jobs_by_slot["a"]
    state["verification_jobs_b"] = verification_jobs_by_slot["b"]
    state["verification_jobs_c"] = verification_jobs_by_slot["c"]
    state["run_panel"] = bool(verification_jobs)
    state["run_ensemble_panel"] = bool(
        state.get("ensemble_enabled") and verification_jobs
    )
    state["run_standard_panel"] = bool(
        not state.get("ensemble_enabled") and verification_jobs
    )
    state["researchers_dispatched"] = len(jobs)
    state["researchers_returned"] = returned
    state["invalid_research_results"] = invalid_results
    set_phase_jobs(state, "panel", verification_jobs)
    save_state(state)
    updates: Dict[str, Any] = {
        "run_panel": bool(verification_jobs),
        "run_ensemble_panel": bool(state.get("run_ensemble_panel")),
        "run_standard_panel": bool(state.get("run_standard_panel")),
    }
    if verification_jobs:
        if state.get("ensemble_enabled"):
            for slot in ("a", "b", "c"):
                updates[f"verification_jobs_{slot}"] = list(
                    state.get(f"verification_jobs_{slot}") or []
                )
        else:
            updates.update(
                phase_jobs_context(state, "panel", verification_jobs)
            )
    if invalid_results:
        print(
            f"research: {len(invalid_results)} of {len(jobs)} research "
            "agent(s) did not return a usable result"
        )
    if candidates_dropped:
        print(
            f"candidates: {len(raw_candidates)} exceed the cap of "
            f"{CANDIDATE_CAP}; keeping the highest-severity {CANDIDATE_CAP} "
            "-- the report will say so"
        )
    if state["unverified_by_cap"]:
        print(
            f"verification cap: {state['unverified_by_cap']} lower-ranked "
            "candidate(s) will not be verified or reported -- the stamp "
            "records them as unreviewed_candidate_sites"
        )
    print(
        f"Candidates: {len(raw_candidates)} raw -> "
        f"{len(deduplicated)} deduplicated; "
        f"{len(verification_jobs)} panel vote(s)"
    )
    emit(**updates)


def phase_vote(
    state: Mapping[str, Any],
    phase: str,
    job: Mapping[str, Any],
) -> Optional[Dict[str, str]]:
    phase_results = state.get("phase_results")
    if not isinstance(phase_results, dict):
        return None
    results = phase_results.get(phase)
    if not isinstance(results, dict):
        return None
    return normalize_verdict(results.get(job.get("job_id")))


def collect_votes(
    state: Mapping[str, Any],
    phase: str,
    jobs: Sequence[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    votes: List[Dict[str, str]] = []
    for job in jobs:
        vote = phase_vote(state, phase, job)
        if vote is not None:
            votes.append(vote)
    return votes


def tally() -> None:
    state = load_state()
    candidates = state.get("verification_candidates") or []
    jobs = state.get("verification_jobs") or []
    reviewed: List[Dict[str, Any]] = []
    panel_vote_count = 0
    repanel_jobs: List[Dict[str, Any]] = []
    repanel_jobs_by_slot: Dict[str, List[Dict[str, Any]]] = {
        "a": [],
        "b": [],
        "c": [],
    }

    for candidate in candidates:
        candidate_jobs = [
            job
            for job in jobs
            if isinstance(job, dict)
            and job.get("candidate_id") == candidate.get("id")
        ]
        votes = collect_votes(state, "panel", candidate_jobs)
        true_votes = sum(
            vote["verdict"] == "TRUE_POSITIVE" for vote in votes
        )
        panel = {
            "true": true_votes,
            "false": len(votes) - true_votes,
            "voters": len(votes),
        }
        panel_vote_count += len(votes)
        kept = len(votes) == 3 and true_votes >= 2
        reviewed.append({"candidate": candidate, "panel": panel, "kept": kept})
        if state["effort"] == "max" and kept and true_votes == 2:
            for lens in VERIFICATION_LENSES:
                lower_lens = lens.lower()
                job = {
                    "name": f"repanel:{candidate['id']}:{lower_lens}",
                    "job_id": f"repanel:{candidate['id']}:{lower_lens}",
                    "candidate_id": candidate["id"],
                    "finding": verification_claim(candidate),
                    "lens": lens,
                    "target": common_target(state),
                }
                repanel_jobs.append(job)
                if state.get("ensemble_enabled"):
                    repanel_jobs_by_slot[
                        VERIFICATION_SLOT_BY_LENS[lens]
                    ].append(job)

    state["reviewed"] = reviewed
    state["panel_vote_count"] = panel_vote_count
    state["repanel_jobs"] = repanel_jobs
    state["repanel_jobs_a"] = repanel_jobs_by_slot["a"]
    state["repanel_jobs_b"] = repanel_jobs_by_slot["b"]
    state["repanel_jobs_c"] = repanel_jobs_by_slot["c"]
    state["max_effort"] = state["effort"] == "max"
    state["run_repanel"] = bool(repanel_jobs)
    state["run_ensemble_repanel"] = bool(
        state.get("ensemble_enabled") and repanel_jobs
    )
    state["run_standard_repanel"] = bool(
        not state.get("ensemble_enabled") and repanel_jobs
    )
    set_phase_jobs(state, "repanel", repanel_jobs)
    save_state(state)
    updates: Dict[str, Any] = {
        "max_effort": state["max_effort"],
        "run_repanel": bool(repanel_jobs),
        "run_ensemble_repanel": bool(state.get("run_ensemble_repanel")),
        "run_standard_repanel": bool(state.get("run_standard_repanel")),
    }
    if repanel_jobs:
        if state.get("ensemble_enabled"):
            for slot in ("a", "b", "c"):
                updates[f"repanel_jobs_{slot}"] = list(
                    state.get(f"repanel_jobs_{slot}") or []
                )
        else:
            updates.update(
                phase_jobs_context(state, "repanel", repanel_jobs)
            )
    print(
        f"Panel returned {panel_vote_count} vote(s) for "
        f"{len(reviewed)} candidate(s)"
    )
    emit(**updates)


def adversarial_plan() -> None:
    state = load_state()
    reviewed = state.get("reviewed") or []
    repanel_jobs = state.get("repanel_jobs") or []
    casualties = list(state.get("adversarial_casualties") or [])
    panel_vote_count = int(state.get("panel_vote_count", 0))

    for record in reviewed:
        if not isinstance(record, dict) or not record.get("kept"):
            continue
        panel = record.get("panel") or {}
        candidate = record.get("candidate") or {}
        candidate_id = candidate.get("id")
        if panel.get("true") != 2:
            continue
        jobs = [
            job
            for job in repanel_jobs
            if isinstance(job, dict)
            and job.get("candidate_id") == candidate_id
        ]
        votes = collect_votes(state, "repanel", jobs)
        true_votes = sum(
            vote["verdict"] == "TRUE_POSITIVE" for vote in votes
        )
        repanel = {
            "true": true_votes,
            "false": len(votes) - true_votes,
            "voters": len(votes),
        }
        panel_vote_count += len(votes)
        record["adversarial"] = {"repanel": repanel}
        if len(votes) != 3:
            casualties.append(
                f"{candidate_id}: repanel incomplete "
                f"({len(votes)}/3 voters returned) — first-panel verdict stands"
            )
        elif true_votes < 2:
            record["kept"] = False
            casualties.append(
                f"{candidate_id}: dropped on repanel "
                f"({true_votes}/{len(votes)})"
            )

    redteam_jobs: List[Dict[str, Any]] = []
    for record in reviewed:
        if not isinstance(record, dict) or not record.get("kept"):
            continue
        candidate = record["candidate"]
        redteam_jobs.append(
            {
                "name": f"redteam:{candidate['id']}",
                "job_id": f"redteam:{candidate['id']}",
                "candidate_id": candidate["id"],
                "finding": verification_claim(candidate),
                "target": common_target(state),
            }
        )
    state["reviewed"] = reviewed
    state["redteam_jobs"] = redteam_jobs
    state["run_redteam"] = bool(redteam_jobs)
    state["panel_vote_count"] = panel_vote_count
    state["adversarial_casualties"] = casualties
    set_phase_jobs(state, "redteam", redteam_jobs)
    save_state(state)
    updates: Dict[str, Any] = {"run_redteam": bool(redteam_jobs)}
    if redteam_jobs:
        updates.update(phase_jobs_context(state, "redteam", redteam_jobs))
    emit(**updates)


def confidence_sort_key(record: Mapping[str, Any]) -> Tuple[int, int]:
    candidate = record.get("candidate") or {}
    return (
        -SEVERITY_RANK.get(candidate.get("severity"), 0),
        -CONFIDENCE_RANK.get(candidate.get("confidence"), 0),
    )


def coverage_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    planned = state.get("planned_components") or []
    return {
        "droppedComponents": state.get("dropped_components") or [],
        "skippedComponents": state.get("skipped_components") or [],
        "components": [
            {"name": component.get("name"), "paths": component.get("paths")}
            for component in planned
            if isinstance(component, dict)
        ],
        "effort": state.get("effort"),
        "focus": state.get("focus") or "whole-tree",
        "diffFiles": state.get("diff_files"),
        "diffLines": state.get("diff_lines"),
        "diffSizeRejected": None,
        "scopeFiles": state.get("scope_files"),
        "scopeSizeRejected": None,
        "collapsed": state.get("collapsed"),
        "completenessCheckOutcome": state.get("completeness"),
        "topLevelCount": (
            len(state["top_level_dirs"])
            if isinstance(state.get("top_level_dirs"), list)
            else None
        ),
        "topLevelRejected": state.get("top_level_rejected"),
        "unaccountedTopLevelDirs": (
            state.get("unaccounted_top_level_dirs") or []
        ),
        "inventoryRejected": state.get("inventory_rejected") or [],
        "inventoryFallback": state.get("inventory_fallback"),
        "emptyDiff": bool(state.get("empty_diff")),
        "emptyScope": bool(state.get("empty_scope")),
        "mode": state.get("mode"),
        "scope": state.get("scope") or None,
        "range": state.get("range"),
        "researchersPerCell": state.get("researchers_per_cell"),
        "researchersDispatched": int(
            state.get("researchers_dispatched", 0)
        ),
        "researchersReturned": int(state.get("researchers_returned", 0)),
        "prunedBuckets": state.get("pruned_buckets") or [],
        "adversarialCasualties": (
            state.get("adversarial_casualties") or []
        ),
        "candidatesDroppedByCap": int(
            state.get("candidates_dropped_by_cap", 0)
        ),
        "unverifiedByCap": int(state.get("unverified_by_cap", 0)),
        "invalidResearchResults": (
            state.get("invalid_research_results") or []
        ),
    }


def verification_status(
    findings: Sequence[Mapping[str, Any]],
    votes: Mapping[str, Any],
) -> Tuple[str, Optional[str]]:
    dispatched = int(votes.get("researchers_dispatched", 0))
    returned = int(votes.get("researchers_returned", 0))
    if dispatched and returned == 0:
        return (
            "unverified",
            f"{dispatched} research agent(s) were dispatched but none returned",
        )
    rounds = votes.get("rounds")
    if not isinstance(rounds, dict):
        rounds = {}
    incomplete: List[str] = []
    for finding in findings:
        record = rounds.get(finding.get("id"))
        panel = record.get("panel") if isinstance(record, dict) else None
        if not isinstance(panel, dict) or panel.get("voters") != 3:
            incomplete.append(str(finding.get("id")))
    if incomplete:
        return "unverified", "incomplete panel rounds: " + ", ".join(incomplete)
    if (
        not findings
        and int(votes.get("candidates", 0)) > 0
        and not any(
            isinstance(record, dict)
            and isinstance(record.get("panel"), dict)
            and record["panel"].get("voters") == 3
            for record in rounds.values()
        )
    ):
        return (
            "unverified",
            "candidates were recorded but no three-voter panel completed",
        )
    return "verified", None


def assemble_final(state: Dict[str, Any]) -> Dict[str, Any]:
    reviewed = state.get("reviewed") or []
    casualties = list(state.get("adversarial_casualties") or [])
    panel_vote_count = int(state.get("panel_vote_count", 0))

    if state.get("effort") == "max":
        jobs = state.get("redteam_jobs") or []
        jobs_by_id = {
            job["candidate_id"]: job
            for job in jobs
            if isinstance(job, dict) and isinstance(job.get("candidate_id"), str)
        }
        for record in reviewed:
            if not isinstance(record, dict) or not record.get("kept"):
                continue
            candidate_id = record["candidate"]["id"]
            job = jobs_by_id.get(candidate_id)
            vote = phase_vote(state, "redteam", job) if job else None
            adversarial = record.setdefault("adversarial", {})
            adversarial["redteam"] = (
                vote["verdict"] if vote else "no-vote"
            )
            if vote:
                panel_vote_count += 1
                if vote["verdict"] != "TRUE_POSITIVE":
                    record["kept"] = False
                    casualties.append(
                        f"{candidate_id}: refuted by red team — "
                        f"{one_line(vote['reasoning'], 200)}"
                    )
            else:
                casualties.append(
                    f"{candidate_id}: red-team refuter returned no vote after "
                    "retries — first-panel verdict stands"
                )

    kept = sorted(
        [
            record
            for record in reviewed
            if isinstance(record, dict) and record.get("kept")
        ],
        key=confidence_sort_key,
    )
    rejected = [
        record
        for record in reviewed
        if isinstance(record, dict) and not record.get("kept")
    ]
    for index, record in enumerate(kept + rejected, 1):
        record["candidate"]["id"] = f"F{index}"

    rounds: Dict[str, Any] = {}
    for record in reviewed:
        candidate_id = record["candidate"]["id"]
        round_record: Dict[str, Any] = {"panel": record.get("panel")}
        if record.get("adversarial") is not None:
            round_record["adversarial"] = record["adversarial"]
        rounds[candidate_id] = round_record

    findings = [
        {
            "id": record["candidate"]["id"],
            "title": record["candidate"]["title"],
            "impact": record["candidate"].get("impact") or "",
            "file": record["candidate"]["file"],
            "line": int(record["candidate"]["line"]),
            "description": record["candidate"]["rationale"],
            "exploit_scenario": (
                record["candidate"].get("exploitScenario")
                or record["candidate"]["rationale"]
            ),
            "preconditions": record["candidate"].get("preconditions") or [],
            "category": record["candidate"]["category"],
            "severity": record["candidate"]["severity"],
            "confidence": record["candidate"]["confidence"],
            "recommendation": (
                record["candidate"].get("recommendation") or ""
            ),
            "cwe_id": record["candidate"].get("cweId") or None,
            "snippet": record["candidate"].get("snippet") or "",
            "symbol": record["candidate"].get("symbol") or "",
        }
        for record in kept
    ]
    votes = {
        "candidates": int(state.get("raw_candidate_count", 0)),
        "candidates_deduped": len(
            state.get("deduplicated_candidates") or []
        ),
        "panel_votes": panel_vote_count,
        "researchers_dispatched": int(
            state.get("researchers_dispatched", 0)
        ),
        "researchers_returned": int(state.get("researchers_returned", 0)),
        "unreviewed_candidate_sites": (
            int(state.get("unverified_by_cap", 0))
            + int(state.get("dropped_unique_candidate_count", 0))
        ),
        "rounds": rounds,
    }
    coverage = coverage_from_state(state)
    coverage["adversarialCasualties"] = casualties
    status, reason = verification_status(findings, votes)
    return {
        "findings": findings,
        "votes": votes,
        "coverage": coverage,
        "verification": {"status": status, "reason": reason},
    }


def write_final_files(
    state: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    run_dir = Path(str(state["run_dir"]))
    write_json(run_dir / "findings.json", result["findings"])
    write_json(run_dir / "votes.json", result["votes"])
    write_json(run_dir / "coverage.json", result["coverage"])
    write_json(run_dir / "final.json", result)


def final_tally() -> None:
    state = load_state()
    assert_workspace_unchanged(state)
    result = assemble_final(state)
    state["adversarial_casualties"] = result["coverage"][
        "adversarialCasualties"
    ]
    state["final"] = result
    save_state(state)
    write_final_files(state, result)
    for casualty in result["coverage"]["adversarialCasualties"]:
        print(casualty)
    print(
        f"Verified result: {len(result['findings'])} finding(s) kept of "
        f"{len(state.get('reviewed') or [])} reviewed "
        f"({result['votes']['unreviewed_candidate_sites']} unreviewed); "
        f"provisional status {result['verification']['status']}"
    )
    emit(
        kept_count=len(result["findings"]),
        provisional_verification_status=result["verification"]["status"],
        report_run_dir=state["run_dir"],
        products_dir=state["products_rel"],
        run_ensemble_report=bool(state.get("ensemble_enabled")),
        run_standard_report=not bool(state.get("ensemble_enabled")),
    )


def load_renderer() -> Any:
    path = (root() / RENDERER_PATH).resolve()
    if not path.is_file():
        raise WorkflowDataError(
            f"the original deterministic renderer is missing: {RENDERER_PATH}"
        )
    spec = importlib.util.spec_from_file_location(
        "claude_security_render_report",
        path,
    )
    if spec is None or spec.loader is None:
        raise WorkflowDataError("could not load the original report renderer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_report() -> None:
    state = load_state()
    assert_workspace_unchanged(state)
    run_dir = str(state["run_dir"])
    products_rel = str(state["products_rel"])
    renderer = load_renderer()
    try:
        findings, verification, tag = renderer.render(run_dir, products_rel)
    except Exception as error:
        raise WorkflowDataError(
            f"the original report renderer refused the report: {error}"
        ) from error
    stamp_name = f"CLAUDE-SECURITY-REVISION-{tag}.json"
    state["stamp_path"] = f"{products_rel}/{stamp_name}"
    state["verification_status"] = verification.get("status")
    state["finding_count"] = len(findings)
    save_state(state)
    print(
        f"Wrote {products_rel}/CLAUDE-SECURITY-RESULTS.md, "
        f"CLAUDE-SECURITY-RESULTS.jsonl, and {stamp_name}; "
        "scratch records retained in the cloud sandbox"
    )
    emit(
        report_path=f"{products_rel}/CLAUDE-SECURITY-RESULTS.md",
        stamp_path=state["stamp_path"],
        verification_status=verification.get("status"),
        finding_count=len(findings),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--mode", default="scan")
    prepare_parser.add_argument("--effort", default="medium")
    prepare_parser.add_argument("--ensemble", default="true")
    prepare_parser.add_argument("--scope", default="")
    prepare_parser.add_argument("--base", default="")
    prepare_parser.add_argument("--commit", default="")
    prepare_parser.add_argument("--range", default="")
    prepare_parser.add_argument("--focus", default="")

    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument(
        "phase",
        choices=("inventory", *PHASE_OUTPUT_KEYS.keys()),
    )
    merge_ensemble_parser = subparsers.add_parser("merge-ensemble")
    merge_ensemble_parser.add_argument(
        "batch",
        choices=tuple(ENSEMBLE_BATCHES),
    )

    for name in (
        "inventory-failed",
        "plan-matrix",
        "zip-cells",
        "dedup-rank",
        "tally",
        "adversarial-plan",
        "final-tally",
        "render-report",
    ):
        subparsers.add_parser(name)
    return parser


def main(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)
    commands = {
        "prepare": lambda: prepare(args),
        "merge": lambda: merge(args.phase),
        "merge-ensemble": lambda: merge_ensemble(args.batch),
        "inventory-failed": inventory_failed,
        "plan-matrix": plan_matrix,
        "zip-cells": zip_cells,
        "dedup-rank": dedup_rank,
        "tally": tally,
        "adversarial-plan": adversarial_plan,
        "final-tally": final_tally,
        "render-report": render_report,
    }
    try:
        commands[args.command]()
    except WorkflowDataError as error:
        print(f"security_review.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
