# Workflow JavaScript runtime

Workflow files run in a host-provided JavaScript context rather than as ordinary
standalone Node.js or Bun modules. The host evaluates the workflow inside an
async function and injects the globals documented below. Consequently,
top-level `await` and `return` are valid, and none of these globals need to be
imported.

The following TypeScript-style declarations summarize the runtime API. They are
documentation only:

```ts
type JsonSchema = Record<string, unknown>;

interface AgentOptions {
	label?: string;
	phase?: string;
	schema?: JsonSchema;
	model?: string;
	effort?: "low" | "medium" | "high" | "xhigh" | "max";
	isolation?: "worktree";
	agentType?: string;
}

declare const args: unknown;

declare function log(message: string): void;

declare function phase(title: string): void;

declare function agent(
	prompt: string,
	options?: AgentOptions,
): Promise<string | object | null>;

declare function parallel<T>(
	tasks: Array<() => T | Promise<T>>,
): Promise<Array<T | null>>;

type PipelineStage = (
	previousResult: unknown,
	originalItem: unknown,
	index: number,
) => unknown | Promise<unknown>;

declare function pipeline(
	items: unknown[],
	...stages: PipelineStage[]
): Promise<Array<unknown | null>>;
```

## `args`

```ts
declare const args: unknown;
```

`args` is the value supplied as the workflow's `args` input, unchanged. It is
`undefined` when the caller does not supply a value.

Pass arrays and objects as JSON values instead of JSON-encoding them into a
string. Workflow code should still validate `args` before using it because the
caller controls its type and contents.

```js
const input =
	args && typeof args === "object" && !Array.isArray(args) ? args : {};
```

## `log`

```ts
declare function log(message: string): void;
```

`log` emits a progress message in the workflow UI. It is intended for concise
status updates, not structured return data.

```js
log(`Reviewing ${files.length} files`);
```

## `phase`

```ts
declare function phase(title: string): void;
```

`phase` starts a progress group. Subsequent `agent()` calls appear under that
phase until another phase starts.

Because the current phase is shared state, concurrent work should set
`AgentOptions.phase` on each `agent()` call instead of calling `phase()` from
inside `parallel()` tasks or `pipeline()` stages.

```js
phase("Inventory");

await agent("Inventory the repository.", {
	label: "inventory",
	phase: "Inventory",
});
```

## `agent`

```ts
declare function agent(
	prompt: string,
	options?: AgentOptions,
): Promise<string | object | null>;
```

`agent` starts a subagent with the supplied prompt.

- Without `options.schema`, it resolves to the subagent's final response as a
  string.
- With `options.schema`, the subagent must produce structured output and the
  promise resolves to the validated object. No additional JSON parsing is
  needed.
- It resolves to `null` if the user skips the subagent or the subagent stops
  after terminal API failures.

The options are:

| Option | Signature | Meaning |
| --- | --- | --- |
| `label` | `string` | Overrides the task label shown in the progress UI. |
| `phase` | `string` | Assigns the task to a progress group. Prefer this form for concurrent calls. |
| `schema` | `Record<string, unknown>` | A JSON Schema describing and enforcing structured output. |
| `model` | `string` | Overrides the inherited session model for this call. |
| `effort` | `"low" \| "medium" \| "high" \| "xhigh" \| "max"` | Overrides the inherited reasoning effort for this call. |
| `isolation` | `"worktree"` | Runs the subagent in a temporary Git worktree. Use this for concurrently mutating agents that could conflict. |
| `agentType` | `string` | Selects a registered custom subagent type instead of the default workflow subagent. |

Example with structured output:

```js
const result = await agent("Classify the target.", {
	label: "classify",
	phase: "Analysis",
	agentType: "general-purpose",
	effort: "medium",
	schema: {
		type: "object",
		required: ["classification"],
		properties: {
			classification: {
				type: "string",
				enum: ["safe", "unsafe"],
			},
		},
	},
});

if (result === null) {
	return { classification: "unknown" };
}
```

## `parallel`

```ts
declare function parallel<T>(
	tasks: Array<() => T | Promise<T>>,
): Promise<Array<T | null>>;
```

`parallel` runs an array of task functions concurrently and waits for every task
before resolving. Pass functions, not promises, so the host controls when each
task starts.

Results retain task order. If a task throws, its result is `null`; the
`parallel()` call itself continues to collect the other results.

```js
const results = await parallel([
	() => agent("Review authentication.", { phase: "Review" }),
	() => agent("Review authorization.", { phase: "Review" }),
]);

const completedResults = results.filter(Boolean);
```

## `pipeline`

```ts
type PipelineStage = (
	previousResult: unknown,
	originalItem: unknown,
	index: number,
) => unknown | Promise<unknown>;

declare function pipeline(
	items: unknown[],
	...stages: PipelineStage[]
): Promise<Array<unknown | null>>;
```

`pipeline` sends each item through every stage in sequence while processing
different items concurrently. There is no cross-item barrier between stages:
one item can enter a later stage while another item is still in an earlier one.

Each stage receives:

1. `previousResult`: the input item for the first stage, then the preceding
   stage's result.
2. `originalItem`: the unchanged item supplied in `items`.
3. `index`: the item's index in `items`.

Results retain input order. If a stage throws or returns `null`, that item
becomes `null` and its remaining stages are skipped.

```js
const reviews = await pipeline(
	files,
	(file, _originalFile, index) =>
		agent(`Review ${file}.`, {
			label: `review:${index + 1}`,
			phase: "Review",
		}),
	(review, file) => ({
		file,
		review,
	}),
);
```

Use `pipeline()` when every item moves through the same sequence of stages. Use
`parallel()` when independent tasks must all finish before the workflow can
continue.
