import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";

describe("scan dependency injection", () => {
	test("uses JSON-encoded args to short-circuit an empty diff", async () => {
		const scan = await loadScan();
		const logMessages = [];
		const failIfCalled = () => {
			throw new Error("The empty-diff path must not dispatch work.");
		};

		const result = await scan(
			JSON.stringify({
				scanRoot: "/workspace/project",
				runDir: "/workspace/run",
				mode: "audit",
				effort: "high",
				range: "main..HEAD",
				diffFileCount: "0",
				diffLineCount: "0",
			}),
			(message) => logMessages.push(message),
			failIfCalled,
			failIfCalled,
			failIfCalled,
			failIfCalled,
		);

		expect(result.coverage).toMatchObject({
			effort: "high",
			mode: "audit",
			range: "main..HEAD",
			diffFiles: 0,
			diffLines: 0,
			emptyDiff: true,
			researchersDispatched: 0,
			researchersReturned: 0,
		});
		expect(logMessages).toEqual([
			"the range main..HEAD contains no changed files -- there is no diff to scan",
		]);
	});

	test("calls the injected log for a bare invocation", async () => {
		const scan = await loadScan();
		const logMessages = [];
		const failIfCalled = () => {
			throw new Error("A bare invocation must not dispatch work.");
		};

		const result = await scan(
			{},
			(message) => logMessages.push(message),
			failIfCalled,
			failIfCalled,
			failIfCalled,
			failIfCalled,
		);

		expect(result).toMatchObject({
			started: false,
			reason: "no-args",
		});
		expect(logMessages).toEqual([
			"scan.js was started with no scan settings (a bare invocation) -- nothing to scan; directing the user to the /claude-security menu",
		]);
	});

	test("announces each full-scan phase through the injected phase function", async () => {
		const scan = await loadScan();
		const fixture = createFullScanFixture();

		await scan(
			fixture.args,
			fixture.log,
			fixture.phase,
			fixture.agent,
			fixture.pipeline,
			fixture.parallel,
		);

		expect(fixture.calls.phase).toEqual([
			"Inventory",
			"Threat model",
			"Sweep",
			"Panel",
		]);
	});

	test("dispatches prompts through the injected agent and consumes its responses", async () => {
		const scan = await loadScan();
		const fixture = createFullScanFixture();

		const result = await scan(
			fixture.args,
			fixture.log,
			fixture.phase,
			fixture.agent,
			fixture.pipeline,
			fixture.parallel,
		);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"inventory",
			"model:web",
			"research:web:injection-and-input",
			"research:web:auth-and-access",
			"research:web:crypto-and-secrets",
			"sweep:1",
			"panel:F1:v1",
			"panel:F1:v2",
			"panel:F1:v3",
		]);
		expect(fixture.calls.agent[0]).toMatchObject({
			options: {
				phase: "Inventory",
				agentType: "claude-security:scan-inventory",
			},
		});
		expect(fixture.calls.agent[0].prompt).toContain(
			"Partition the repository at /workspace/project",
		);
		expect(fixture.calls.agent[1].prompt).toContain("name: web");
		expect(fixture.calls.agent[2].prompt).toContain(
			"entry points: src/server.ts:10",
		);
		expect(fixture.calls.agent[6].prompt).toContain("file: src/server.ts");
		expect(result.findings).toEqual([
			{
				id: "F1",
				title: "Untrusted command reaches exec",
				impact: "Arbitrary command execution",
				file: "src/server.ts",
				line: 20,
				description: "A request parameter is passed to exec.",
				// biome-ignore lint/style/useNamingConvention: Workflow result contract uses snake_case.
				exploit_scenario: "An attacker controls the command parameter.",
				preconditions: ["The endpoint is reachable."],
				category: "command-injection",
				severity: "HIGH",
				confidence: "HIGH",
				recommendation: "Use an argument-vector API.",
				// biome-ignore lint/style/useNamingConvention: Workflow result contract uses snake_case.
				cwe_id: "CWE-78",
				snippet: "exec(request.query.command)",
				symbol: "runCommand",
			},
		]);
	});

	test("passes components and candidates through the injected pipeline", async () => {
		const scan = await loadScan();
		const fixture = createFullScanFixture();

		const result = await scan(
			fixture.args,
			fixture.log,
			fixture.phase,
			fixture.agent,
			fixture.pipeline,
			fixture.parallel,
		);

		expect(fixture.calls.pipeline).toHaveLength(2);
		expect(fixture.calls.pipeline[0]).toEqual({
			items: [
				{
					name: "web",
					paths: ["src"],
					language: "TypeScript",
					role: "HTTP API",
					internetFacing: true,
				},
			],
			stageCount: 2,
		});
		expect(fixture.calls.pipeline[1]).toMatchObject({
			items: [
				{
					id: "F1",
					file: "src/server.ts",
					line: 20,
					component: "web",
					reports: 1,
					reporters: ["web"],
				},
			],
			stageCount: 2,
		});
		expect(result.findings).toHaveLength(1);
		expect(result.votes.panel_votes).toBe(3);
	});

	test("runs research, sweep, and panel tasks through the injected parallel", async () => {
		const scan = await loadScan();
		const fixture = createFullScanFixture();

		const result = await scan(
			fixture.args,
			fixture.log,
			fixture.phase,
			fixture.agent,
			fixture.pipeline,
			fixture.parallel,
		);

		expect(fixture.calls.parallel).toEqual([
			{
				taskCount: 3,
				everyTaskIsFunction: true,
			},
			{
				taskCount: 1,
				everyTaskIsFunction: true,
			},
			{
				taskCount: 3,
				everyTaskIsFunction: true,
			},
		]);
		expect(result.coverage.researchersDispatched).toBe(4);
		expect(result.coverage.researchersReturned).toBe(4);
		expect(result.votes.panel_votes).toBe(3);
	});
});

function createFullScanFixture() {
	const calls = {
		agent: [],
		log: [],
		parallel: [],
		phase: [],
		pipeline: [],
	};
	const finding = {
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
	};
	const log = (message) => {
		calls.log.push(message);
	};
	const phase = (title) => {
		calls.phase.push(title);
	};
	const agent = async (prompt, options) => {
		calls.agent.push({
			prompt,
			options,
		});
		if (options.label === "inventory") {
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
		if (options.label === "model:web") {
			return {
				entryPoints: ["src/server.ts:10"],
				sinks: ["src/server.ts:20"],
				assumptions: [],
				trustBoundaries: [],
				hotFiles: ["src/server.ts"],
			};
		}
		if (options.label === "research:web:injection-and-input") {
			return {
				findings: [finding],
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
		if (options.label.startsWith("panel:")) {
			return {
				verdict: "TRUE_POSITIVE",
				reasoning: "The source and sink are reachable.",
			};
		}
		throw new Error(`Unexpected agent call: ${options.label}`);
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
		args: {
			scanRoot: "/workspace/project",
			runDir: "/workspace/run",
			mode: "scan",
			effort: "medium",
			topLevelDirs: ["src"],
		},
		calls,
		log,
		phase,
		agent,
		pipeline,
		parallel,
	};
}
