#!/usr/bin/env python3
"""Fail-closed tool policy for the Fabro security-review workflow.

Fabro currently exposes the full native tool set to API-backed workflow agents.
This blocking pre_tool_use hook supplies the role-specific boundary that the
original plugin gets from its agent tool declarations.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Sequence


WORKFLOW_ROOT = Path(".fabro/workflows/security-review")
GIT_WRAPPER = (WORKFLOW_ROOT / "scripts/git_readonly.py").as_posix()
STATE_PATH = WORKFLOW_ROOT / "runtime/state.json"
REPORT_SPEC = WORKFLOW_ROOT / "specs/report-spec.md"

READ_TOOLS = {"read_file", "read_many_files", "list_dir", "grep", "glob"}
SOURCE_NODES = {
    "inventory",
    "threat_model",
    "researcher",
    "sweeper",
    "panel_verifier",
    "repanel_verifier",
    "redteam_verifier",
}
GIT_NODES = SOURCE_NODES - {"inventory"}
REPORT_NODE = "report_author"
TOOL_ALIASES = {
    "Bash": "shell",
    "Glob": "glob",
    "Grep": "grep",
    "Read": "read_file",
    "Write": "write_file",
    "shell_command": "shell",
    "Agent": "background_agent",
    "TaskOutput": "agent_output",
    "TaskStop": "stop_agent",
    "SendMessage": "message_agent",
}
SUBAGENT_SPAWN_TOOLS = {"spawn_agent", "background_agent"}
SUBAGENT_CONTROL_TOOLS = {
    "send_input",
    "wait",
    "close_agent",
    "agent_output",
    "stop_agent",
    "message_agent",
}
SUBAGENT_TOOLS = SUBAGENT_SPAWN_TOOLS | SUBAGENT_CONTROL_TOOLS
SHELL_META_RE = re.compile(r"[\n\r;&|><`]|[$][(]")
RG_FLAG_OPTIONS = {
    "--case-sensitive",
    "--count",
    "--count-matches",
    "--files",
    "--files-with-matches",
    "--files-without-match",
    "--fixed-strings",
    "--heading",
    "--ignore-case",
    "--json",
    "--line-number",
    "--no-config",
    "--no-heading",
    "--stats",
    "--word-regexp",
    "-F",
    "-c",
    "-i",
    "-l",
    "-n",
    "-s",
    "-w",
}
RG_VALUE_OPTIONS = {
    "--after-context",
    "--before-context",
    "--context",
    "--glob",
    "--max-count",
    "--max-filesize",
    "--type",
    "--type-not",
    "-A",
    "-B",
    "-C",
    "-T",
    "-g",
    "-m",
    "-t",
}
RG_ATTACHED_VALUE_OPTIONS = ("-A", "-B", "-C", "-T", "-g", "-m", "-t")


class GuardError(RuntimeError):
    """A blocked tool request."""


def block(reason: str) -> int:
    print(json.dumps({"decision": "block", "reason": reason}))
    return 2


def proceed() -> int:
    print(json.dumps({"decision": "proceed"}))
    return 0


def load_context() -> Mapping[str, Any]:
    context_path = os.environ.get("FABRO_HOOK_CONTEXT")
    if not context_path:
        raise GuardError("FABRO_HOOK_CONTEXT is missing")
    try:
        value = json.loads(Path(context_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuardError(f"could not read the hook context: {error}") from error
    if not isinstance(value, dict):
        raise GuardError("hook context is not a JSON object")
    return value


def load_state() -> Mapping[str, Any]:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuardError(f"could not read workflow state: {error}") from error
    if not isinstance(value, dict):
        raise GuardError("workflow state is not a JSON object")
    return value


def within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def resolve_path(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw:
        raise GuardError("tool path is missing")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve(strict=False)


def is_generated_source_path(path: Path, repository: Path) -> bool:
    if not within(path, repository):
        return True
    relative = path.relative_to(repository)
    if not relative.parts:
        return False
    top = relative.parts[0]
    if top == ".git" or top.startswith("CLAUDE-SECURITY-"):
        return True
    denied = (
        PurePosixPath(".fabro/blobs"),
        PurePosixPath(".fabro/workflows/security-review/runtime"),
        PurePosixPath(".fabro/workflows/security-review/reports"),
    )
    relative_posix = PurePosixPath(relative.as_posix())
    return any(
        relative_posix == prefix or prefix in relative_posix.parents
        for prefix in denied
    )


def iter_tool_paths(tool_name: str, tool_input: Mapping[str, Any]) -> Iterable[Path]:
    if tool_name == "read_file":
        yield resolve_path(tool_input.get("file_path"))
        return
    if tool_name == "read_many_files":
        values = tool_input.get("paths")
        if not isinstance(values, list) or not values:
            raise GuardError("read_many_files paths are missing")
        for value in values:
            yield resolve_path(value)
        return
    if tool_name == "list_dir":
        raw = tool_input.get("path", tool_input.get("dir_path", "."))
        yield resolve_path(raw)
        return
    if tool_name in {"grep", "glob"}:
        raw = tool_input.get("path", ".")
        yield resolve_path(raw)
        pattern = tool_input.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise GuardError(f"{tool_name} pattern is missing")
        if ".." in PurePosixPath(pattern.replace("\\", "/")).parts:
            raise GuardError(f"{tool_name} pattern contains parent traversal")
        return
    raise GuardError(f"unsupported read tool: {tool_name}")


def allow_source_read(tool_name: str, tool_input: Mapping[str, Any]) -> None:
    repository = Path.cwd().resolve()
    for path in iter_tool_paths(tool_name, tool_input):
        if is_generated_source_path(path, repository):
            raise GuardError(
                "scan agents may read repository source only; Git metadata, "
                "workflow runtime, blobs, and report directories are excluded"
            )


def allow_report_read(tool_name: str, tool_input: Mapping[str, Any]) -> None:
    state = load_state()
    run_dir = resolve_path(state.get("run_dir"))
    repository = Path.cwd().resolve()
    allowed_files = {
        (repository / STATE_PATH).resolve(strict=False),
        (repository / REPORT_SPEC).resolve(strict=False),
    }
    for path in iter_tool_paths(tool_name, tool_input):
        if path not in allowed_files and not within(path, run_dir):
            raise GuardError(
                "report author may read only the report inputs, workflow state, "
                "and report specification"
            )


def allow_report_write(tool_name: str, tool_input: Mapping[str, Any]) -> None:
    if tool_name != "write_file":
        raise GuardError("report author may use write_file only")
    state = load_state()
    run_dir = resolve_path(state.get("run_dir"))
    expected = (run_dir / "CLAUDE-SECURITY-RESULTS.md").resolve(strict=False)
    actual = resolve_path(tool_input.get("file_path"))
    if actual != expected:
        raise GuardError(
            "report author may write only .claude-security-run/"
            "CLAUDE-SECURITY-RESULTS.md"
        )
    if not isinstance(tool_input.get("content"), str):
        raise GuardError("report content is missing")


def allow_subagent(tool_name: str, tool_input: Mapping[str, Any]) -> None:
    """Read-only explore helpers for research and verification nodes.

    Child sessions fall under this same guard only on Fabro builds that
    propagate tool hooks to subagent sessions (fabro-sh/fabro#681). On older
    builds a child runs unguarded, behind only its task instructions and the
    publication-gate workspace digest — an accepted interim state.
    """
    if tool_name in SUBAGENT_SPAWN_TOOLS:
        task = tool_input.get("task", tool_input.get("prompt"))
        if not isinstance(task, str) or not task.strip():
            raise GuardError("subagent task is missing")


def allow_git_wrapper(command: Any) -> None:
    if not isinstance(command, str) or not command:
        raise GuardError("shell command is missing")
    if SHELL_META_RE.search(command):
        raise GuardError("read-only Git command contains shell metacharacters")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as error:
        raise GuardError(f"could not parse Git wrapper command: {error}") from error
    if len(tokens) < 3 or tokens[:2] != ["python3", GIT_WRAPPER]:
        raise GuardError("shell access must use the restricted Git wrapper")
    if tokens[2] not in {"blame", "diff", "log", "show"}:
        raise GuardError("restricted Git wrapper subcommand is not allowed")


def validate_search_path(raw: str) -> None:
    if raw == "-" or "\0" in raw:
        raise GuardError("ripgrep may search repository paths only")
    path = resolve_path(raw)
    repository = Path.cwd().resolve()
    if is_generated_source_path(path, repository):
        raise GuardError(
            "ripgrep may search repository source only; Git metadata, "
            "workflow runtime, blobs, and report directories are excluded"
        )


def validate_rg_option_value(option: str, value: str) -> None:
    if not value or "\0" in value:
        raise GuardError(f"ripgrep option {option} has an invalid value")
    if option in {"--glob", "-g"}:
        parts = PurePosixPath(value.lstrip("!").replace("\\", "/")).parts
        if ".." in parts:
            raise GuardError("ripgrep glob contains parent traversal")
    if option in {
        "--after-context",
        "--before-context",
        "--context",
        "--max-count",
        "-A",
        "-B",
        "-C",
        "-m",
    } and not value.isdigit():
        raise GuardError(f"ripgrep option {option} requires an integer")


def allow_ripgrep(command: Any) -> None:
    if not isinstance(command, str) or not command:
        raise GuardError("ripgrep command is missing")
    if SHELL_META_RE.search(command):
        raise GuardError("ripgrep command contains shell metacharacters")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as error:
        raise GuardError(f"could not parse ripgrep command: {error}") from error
    if not tokens or tokens[0] != "rg":
        raise GuardError("shell access must use ripgrep or the restricted Git wrapper")

    positional: list[str] = []
    files_mode = False
    index = 1
    options_done = False
    while index < len(tokens):
        token = tokens[index]
        if options_done:
            positional.append(token)
            index += 1
            continue
        if token == "--":
            options_done = True
            index += 1
            continue
        if token in RG_FLAG_OPTIONS:
            files_mode = files_mode or token == "--files"
            index += 1
            continue
        if token in RG_VALUE_OPTIONS:
            if index + 1 >= len(tokens):
                raise GuardError(f"ripgrep option {token} is missing its value")
            validate_rg_option_value(token, tokens[index + 1])
            index += 2
            continue
        matched_attached = False
        for prefix in RG_ATTACHED_VALUE_OPTIONS:
            if token.startswith(prefix) and token != prefix:
                validate_rg_option_value(prefix, token[len(prefix) :])
                matched_attached = True
                break
        if matched_attached:
            index += 1
            continue
        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option not in RG_VALUE_OPTIONS:
                raise GuardError(f"ripgrep option {option} is not allowed")
            validate_rg_option_value(option, value)
            index += 1
            continue
        if token.startswith("-"):
            raise GuardError(f"ripgrep option {token} is not allowed")
        positional.append(token)
        index += 1

    if files_mode:
        search_paths = positional
    else:
        if not positional:
            raise GuardError("ripgrep search pattern is missing")
        search_paths = positional[1:]
    for path in search_paths or ["."]:
        validate_search_path(path)


def handle(context: Mapping[str, Any]) -> None:
    node_id = str(context.get("node_id") or "")
    raw_tool_name = str(context.get("tool_name") or "")
    tool_name = TOOL_ALIASES.get(raw_tool_name, raw_tool_name)
    tool_input = context.get("tool_input")
    if not isinstance(tool_input, dict):
        raise GuardError("tool input is not a JSON object")

    if node_id in SOURCE_NODES:
        if tool_name in READ_TOOLS:
            allow_source_read(tool_name, tool_input)
            return
        if tool_name == "shell":
            command = tool_input.get("command")
            if isinstance(command, str) and re.match(r"^\s*rg(?:\s|$)", command):
                allow_ripgrep(command)
                return
            if node_id in GIT_NODES:
                allow_git_wrapper(command)
                return
        if tool_name in SUBAGENT_TOOLS and node_id in GIT_NODES:
            allow_subagent(tool_name, tool_input)
            return
        raise GuardError(
            "scan agents are read-only and may use only repository reads, "
            "searches, the restricted Git wrapper, and read-only explore "
            "subagents"
        )

    if node_id == REPORT_NODE:
        if tool_name in READ_TOOLS:
            allow_report_read(tool_name, tool_input)
            return
        allow_report_write(tool_name, tool_input)
        return

    raise GuardError(f"agent tool use is not allowed from workflow node {node_id!r}")


def main() -> int:
    try:
        handle(load_context())
    except GuardError as error:
        return block(str(error))
    except Exception as error:  # Fail closed on an unexpected guard defect.
        return block(f"security-review tool guard failed closed: {error}")
    return proceed()


if __name__ == "__main__":
    sys.exit(main())
