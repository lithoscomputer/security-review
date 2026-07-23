export function createScanArgs(overrides = {}) {
	return {
		scanRoot: "/workspace/project",
		runDir: "/workspace/run",
		mode: "scan",
		effort: "medium",
		topLevelDirs: ["src"],
		...overrides,
	};
}

export function createFinding(overrides = {}) {
	return {
		file: "src/server.ts",
		line: 20,
		category: "command-injection",
		severity: "HIGH",
		confidence: "HIGH",
		title: "Untrusted command reaches exec",
		rationale: "A request parameter is passed to exec.",
		evidence: "src/server.ts:20 exec(request.query.command)",
		snippet: "exec(request.query.command)",
		symbol: "runCommand",
		impact: "Arbitrary command execution",
		exploitScenario: "An attacker controls the command parameter.",
		preconditions: ["The endpoint is reachable."],
		recommendation: "Use an argument-vector API.",
		cweId: "CWE-78",
		...overrides,
	};
}

export function createScanFixture({
	args = createScanArgs(),
	responseForAgent = respondWithDefaults,
} = {}) {
	const calls = {
		agent: [],
		log: [],
		parallel: [],
		phase: [],
		pipeline: [],
	};
	const log = (message) => {
		calls.log.push(message);
	};
	const phase = (title) => {
		calls.phase.push(title);
	};
	const agent = async (prompt, options) => {
		const call = {
			prompt,
			options,
		};
		calls.agent.push(call);
		return responseForAgent({
			...call,
			calls,
		});
	};
	const pipeline = async (items, ...stages) => {
		calls.pipeline.push({
			items: structuredClone(items),
			stageCount: stages.length,
		});
		return stages.reduce(
			async (valuesPromise, stage) =>
				Promise.all((await valuesPromise).map((value) => stage(value))),
			Promise.resolve(items),
		);
	};
	const parallel = async (tasks) => {
		calls.parallel.push({
			taskCount: tasks.length,
			everyTaskIsFunction: tasks.every((task) => typeof task === "function"),
		});
		return Promise.all(tasks.map((task) => task()));
	};

	return {
		args,
		calls,
		log,
		phase,
		agent,
		pipeline,
		parallel,
	};
}

export function respondWithDefaults({ options }) {
	if (options.label.startsWith("inventory")) {
		return {
			components: [
				{
					name: "web",
					paths: ["src"],
					language: "TypeScript",
					role: "HTTP API",
					internetFacing: true,
				},
			],
			securityScanSkippedComponents: [],
		};
	}
	if (options.label.startsWith("model:")) {
		return {
			entryPoints: ["src/server.ts:10"],
			sinks: ["src/server.ts:20"],
			assumptions: [],
			trustBoundaries: [],
			hotFiles: ["src/server.ts"],
		};
	}
	if (
		options.label.startsWith("research:") ||
		options.label.startsWith("sweep:")
	) {
		return {
			findings: [],
		};
	}
	if (
		options.label.startsWith("panel:") ||
		options.label.startsWith("repanel:") ||
		options.label.startsWith("redteam:")
	) {
		return {
			verdict: "TRUE_POSITIVE",
			reasoning: "The source and sink are reachable.",
		};
	}
	throw new Error(`Unexpected agent call: ${options.label}`);
}

export function createFindingResponder({
	finding = createFinding(),
	sourceLabel = "research:web:injection-and-input",
	panelVerdicts = ["TRUE_POSITIVE", "TRUE_POSITIVE", "TRUE_POSITIVE"],
	repanelVerdicts = ["TRUE_POSITIVE", "TRUE_POSITIVE", "TRUE_POSITIVE"],
	redteamVerdict = "TRUE_POSITIVE",
} = {}) {
	return (call) => {
		const { label } = call.options;
		if (label === sourceLabel) {
			return {
				findings: [structuredClone(finding)],
			};
		}

		const panelMatch = label.match(/^panel:[^:]+:v([1-3])/);
		if (panelMatch) {
			return createVerdictResponse(panelVerdicts[Number(panelMatch[1]) - 1]);
		}

		const repanelMatch = label.match(/^repanel:[^:]+:v([1-3])/);
		if (repanelMatch) {
			return createVerdictResponse(
				repanelVerdicts[Number(repanelMatch[1]) - 1],
			);
		}

		if (label.startsWith("redteam:")) {
			return createVerdictResponse(redteamVerdict);
		}
		return respondWithDefaults(call);
	};
}

export function createComponents(count) {
	return Array.from(
		{
			length: count,
		},
		(_value, index) => ({
			name: `component-${index + 1}`,
			paths: [`component-${index + 1}`],
			language: "TypeScript",
			role: `Component ${index + 1}`,
		}),
	);
}

export function createUniqueFindings(count) {
	return Array.from(
		{
			length: count,
		},
		(_value, index) =>
			createFinding({
				file: `src/file-${index + 1}.ts`,
				line: index + 1,
				title: `Finding ${index + 1}`,
			}),
	);
}

export function createDuplicateFindings(count) {
	return Array.from(
		{
			length: count,
		},
		() => createFinding(),
	);
}

export function runScan(scan, fixture) {
	return scan(
		fixture.args,
		fixture.log,
		fixture.phase,
		fixture.agent,
		fixture.pipeline,
		fixture.parallel,
	);
}

function createVerdictResponse(verdict) {
	return verdict
		? {
				verdict,
				reasoning: `Verifier returned ${verdict}.`,
			}
		: null;
}
