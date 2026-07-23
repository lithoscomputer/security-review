# security-review

A workbench for reading, testing, and refactoring the multi-agent security
scan that ships with the `claude-security` plugin for Claude Code. The
plugin's scan workflow is distributed minified; this repository holds a
readable expansion of it, plus a Bun test suite and Biome tooling that lock
its observable behavior so the expansion can be edited safely.

The upstream source is
[`anthropics/claude-plugins-official`](https://github.com/anthropics/claude-plugins-official/blob/main/plugins/claude-security/workflows/scan.js).

## Layout

| Path | Contents |
| --- | --- |
| `workflows/scan.js` | Readable expansion of the shipped scan workflow: inventory, threat model, research matrix, sweeps, and a three-lens adversarial verification panel. |
| `workflows/README.md` | The workflow JavaScript runtime: the host-provided globals (`args`, `log`, `phase`, `agent`, `parallel`, `pipeline`) that workflow files run against. |
| `agents/` | Subagent definitions the plugin dispatches: the Security Lead orchestrator, scan inventory/researcher/verifier, patch generator/verifier, and explore. |
| `skills/claude-security/` | The plugin's front-desk skill, role file, and job recipes (scan-codebase, scan-changes, suggest-patches). |
| `hooks/` | The plugin's menu banner hook. |
| `tests/` | Bun tests that pin the scan workflow's observable behavior. |
| `scripts/` | `biome-workflows.js`, which formats and lints workflow files. |

## Running the tests

Requires [Bun](https://bun.sh).

```bash
bun install
bun test        # run the test suite
bun run lint    # Biome checks for scripts/, tests/, and workflows/
bun run format  # apply Biome formatting
```

## How the workflow is tested

Workflow files are not ordinary modules: the host evaluates them inside an
async function with injected globals, so `workflows/scan.js` ends with a
top-level `return scan(args, log, phase, agent, pipeline, parallel);` (the
runtime is documented in `workflows/README.md`). The test loader
(`tests/load-scan.js`) strips that entrypoint line, imports the remainder as an
ES module, and drives the exported `scan()` with in-memory fakes of the runtime
globals (`tests/scan-fixture.js`).

The tests treat the workflow as a black box: they assert dispatched agent
labels, prompts, schemas, phase order, log output, and the returned
findings/votes/coverage result. Because `scan.js` carries the entrypoint line,
`scripts/biome-workflows.js` applies the same strip-format-reattach step before
running Biome on it.

## Editing the workflow

Keep the tests green: they lock the workflow's contract — exact log strings,
agent labels, prompt contents, retry sequencing, and result shapes. Behavior
changes should land as deliberate test updates, not incidental drift.
