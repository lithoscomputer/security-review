#!/usr/bin/env python3
"""Restricted read-only Git entry point for security-review agents.

The workflow tool hook permits agent shell access only through this wrapper.
The wrapper does not invoke a shell, ignores global Git configuration, disables
external diff helpers, and accepts only the history-reading subcommands needed
by the original security-review plugin.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence


ALLOWED_SUBCOMMANDS = {
    "blame",
    "diff",
    "log",
    "show",
}
# The hardening flags this wrapper adds are positional: Git lets a later flag
# override an earlier one, so an argument that re-enables what we disabled must
# be refused outright rather than merely not requested.
#   --textconv / --ext-diff re-enable driver commands a repository can choose.
#   --no-index makes diff read any two paths on the filesystem, repository or
#   not, which is the whole boundary this wrapper exists to hold.
FORBIDDEN_ARGUMENTS = {
    "--config-env",
    "--exec-path",
    "--ext-diff",
    "--no-index",
    "--output",
    "--paginate",
    "--textconv",
    "--upload-pack",
    "--write",
    "-c",
}
MAX_ARGUMENTS = 200
MAX_ARGUMENT_LENGTH = 4096


class GitWrapperError(RuntimeError):
    """A rejected wrapper request."""


def validate_arguments(argv: Sequence[str]) -> List[str]:
    if not argv:
        raise GitWrapperError(
            "usage: git_readonly.py <diff|show|log|blame> [arguments]"
        )
    if len(argv) > MAX_ARGUMENTS:
        raise GitWrapperError("too many Git arguments")

    subcommand = argv[0]
    if subcommand not in ALLOWED_SUBCOMMANDS:
        raise GitWrapperError(f"Git subcommand is not allowed: {subcommand!r}")

    validated: List[str] = []
    for argument in argv[1:]:
        if "\0" in argument or "\n" in argument or "\r" in argument:
            raise GitWrapperError("Git arguments cannot contain control characters")
        if len(argument) > MAX_ARGUMENT_LENGTH:
            raise GitWrapperError("a Git argument exceeds the length limit")
        option_name = argument.split("=", 1)[0]
        if option_name in FORBIDDEN_ARGUMENTS:
            raise GitWrapperError(f"Git option is not allowed: {option_name!r}")
        validated.append(argument)
    return [subcommand, *validated]


def build_command(argv: Sequence[str]) -> List[str]:
    subcommand, *arguments = validate_arguments(argv)
    command = ["git", "-C", str(Path.cwd().resolve()), subcommand]
    if subcommand in {"diff", "log", "show"}:
        command.extend(["--no-ext-diff", "--no-textconv"])
    command.extend(arguments)
    return command


def main(argv: Sequence[str]) -> int:
    try:
        command = build_command(argv)
    except GitWrapperError as error:
        print(f"git_readonly.py: {error}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            # An inherited external diff driver would run a command of the
            # repository's choosing; --no-ext-diff covers the flag, this covers
            # the environment.
            "GIT_EXTERNAL_DIFF": "",
        }
    )
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        print(f"git_readonly.py: could not run Git: {error}", file=sys.stderr)
        return 2
    return int(result.returncode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
