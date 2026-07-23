import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import { createScanArgs, createScanFixture, runScan } from "./scan-fixture.js";

describe("scan effort shapes", () => {
	test("low effort runs one whole-repository researcher without inventory or sweeps", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "low",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"research:repository:all",
		]);
		expect(fixture.calls.parallel).toEqual([
			{
				taskCount: 1,
				everyTaskIsFunction: true,
			},
			{
				taskCount: 0,
				everyTaskIsFunction: true,
			},
		]);
		expect(fixture.calls.phase).toEqual(["Panel"]);
		expect(result.coverage).toMatchObject({
			effort: "low",
			collapsed: null,
			researchersPerCell: 1,
			researchersDispatched: 1,
			researchersReturned: 1,
			components: [
				{
					name: "repository",
					paths: ["."],
				},
			],
		});
	});

	test("a small medium-effort diff collapses to one researcher", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				range: "main..HEAD",
				diffFileCount: 3,
				diffLineCount: 120,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"research:repository:all",
		]);
		expect(fixture.calls.agent[0].prompt).toContain(
			"scanning ONLY the change described here: main..HEAD",
		);
		expect(result.coverage).toMatchObject({
			effort: "medium",
			collapsed: "small-diff",
			diffFiles: 3,
			diffLines: 120,
			researchersDispatched: 1,
			researchersReturned: 1,
		});
	});

	test("a small medium-effort scope collapses to one researcher", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				scope: "src",
				scopeFileCount: 4,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"research:repository:all",
		]);
		expect(fixture.calls.agent[0].prompt).toContain(
			"The scan is scoped to these directories: src",
		);
		expect(result.coverage).toMatchObject({
			effort: "medium",
			collapsed: "small-scope",
			scope: "src",
			scopeFiles: 4,
			researchersDispatched: 1,
			researchersReturned: 1,
		});
	});

	test("high effort doubles each category cell and runs two sweeps", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "high",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"inventory",
			"model:web",
			"research:web:injection-and-input:1",
			"research:web:injection-and-input:2",
			"research:web:auth-and-access:1",
			"research:web:auth-and-access:2",
			"research:web:crypto-and-secrets:1",
			"research:web:crypto-and-secrets:2",
			"sweep:1",
			"sweep:2",
		]);
		expect(fixture.calls.parallel).toEqual([
			{
				taskCount: 6,
				everyTaskIsFunction: true,
			},
			{
				taskCount: 2,
				everyTaskIsFunction: true,
			},
		]);
		expect(result.coverage).toMatchObject({
			effort: "high",
			researchersPerCell: 2,
			researchersDispatched: 8,
			researchersReturned: 8,
		});
	});

	test("max effort uses the expanded research shape", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toEqual([
			"inventory",
			"model:web",
			"research:web:injection-and-input:1",
			"research:web:injection-and-input:2",
			"research:web:auth-and-access:1",
			"research:web:auth-and-access:2",
			"research:web:crypto-and-secrets:1",
			"research:web:crypto-and-secrets:2",
			"sweep:1",
			"sweep:2",
		]);
		expect(result.coverage).toMatchObject({
			effort: "max",
			researchersPerCell: 2,
			researchersDispatched: 8,
			researchersReturned: 8,
			adversarialCasualties: [],
		});
	});
});

describe("scan attack-surface shape", () => {
	test("attack-surface mode adds a secrets sweep that includes fixtures", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				focus: "attack-surface",
			}),
		});

		const result = await runScan(scan, fixture);
		const researchCall = fixture.calls.agent.find(
			({ options }) => options.label === "research:web:injection-and-input",
		);
		const regularSweepCall = fixture.calls.agent.find(
			({ options }) => options.label === "sweep:1",
		);
		const secretsSweepCall = fixture.calls.agent.find(
			({ options }) => options.label === "sweep:secrets",
		);

		expect(fixture.calls.agent.map(({ options }) => options.label)).toContain(
			"sweep:secrets",
		);
		expect(researchCall.prompt).toContain("focus on the attack surface");
		expect(regularSweepCall.prompt).toContain("focus on the attack surface");
		expect(secretsSweepCall.prompt).toContain(
			"including tests, fixtures, and configuration",
		);
		expect(secretsSweepCall.prompt).not.toContain(
			"focus on the attack surface",
		);
		expect(result.coverage).toMatchObject({
			focus: "attack-surface",
			researchersDispatched: 5,
			researchersReturned: 5,
		});
	});
});
