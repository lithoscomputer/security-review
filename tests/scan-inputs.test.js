import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import { createScanArgs, createScanFixture, runScan } from "./scan-fixture.js";

describe("scan input validation", () => {
	test("treats malformed JSON args as a bare invocation", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: "{not-json",
		});

		const result = await runScan(scan, fixture);

		expect(result).toMatchObject({
			started: false,
			reason: "no-args",
		});
		expect(fixture.calls.agent).toEqual([]);
		expect(fixture.calls.pipeline).toEqual([]);
		expect(fixture.calls.parallel).toEqual([]);
	});

	test("falls back to medium for an unknown effort", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "extreme",
				range: "main..HEAD",
				diffFileCount: 0,
				diffLineCount: 0,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.effort).toBe("medium");
		expect(result.coverage.emptyDiff).toBe(true);
	});

	test("rejects settings without both required paths", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: {
				scanRoot: "/workspace/project",
				effort: "low",
			},
		});

		await expect(runScan(scan, fixture)).rejects.toThrow(
			"scan.js requires scanRoot and runDir",
		);
		expect(fixture.calls.agent).toEqual([]);
	});

	test("does not collapse a diff with invalid size counts", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				range: "main..HEAD",
				diffFileCount: "many",
				diffLineCount: -1,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage).toMatchObject({
			diffFiles: null,
			diffLines: null,
			collapsed: null,
			emptyDiff: false,
		});
		expect(result.coverage.diffSizeRejected).toContain(
			'"diffFileCount":"many"',
		);
		expect(result.coverage.diffSizeRejected).toContain('"diffLineCount":-1');
		expect(
			fixture.calls.agent.some(({ options }) => options.label === "inventory"),
		).toBe(true);
	});

	test("does not collapse a scope with an invalid file count", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				scope: "src",
				scopeFileCount: "many",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage).toMatchObject({
			scope: "src",
			scopeFiles: null,
			collapsed: null,
			emptyScope: false,
		});
		expect(result.coverage.scopeSizeRejected).toContain(
			'"scopeFileCount":"many"',
		);
		expect(
			fixture.calls.agent.some(({ options }) => options.label === "inventory"),
		).toBe(true);
	});

	test("short-circuits a scope containing no tracked files", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				scope: "src",
				scopeFileCount: 0,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toEqual([]);
		expect(result.coverage).toMatchObject({
			scope: "src",
			scopeFiles: 0,
			emptyDiff: false,
			emptyScope: true,
			researchersDispatched: 0,
			researchersReturned: 0,
		});
		expect(fixture.calls.agent).toEqual([]);
		expect(fixture.calls.pipeline).toEqual([]);
		expect(fixture.calls.parallel).toEqual([]);
	});
});
