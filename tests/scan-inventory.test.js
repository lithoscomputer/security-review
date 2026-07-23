import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import {
	createComponents,
	createScanArgs,
	createScanFixture,
	respondWithDefaults,
	runScan,
} from "./scan-fixture.js";

describe("scan inventory handling", () => {
	test("rejects an incomplete inventory and accepts its corrected retry", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				topLevelDirs: ["src", "ops"],
			}),
			responseForAgent: (call) => {
				if (call.options.label === "inventory") {
					return {
						components: [
							{
								name: "web",
								paths: ["src"],
								language: "TypeScript",
							},
						],
						securityScanSkippedComponents: [],
					};
				}
				if (call.options.label === "inventory:complete1") {
					return {
						components: [
							{
								name: "web",
								paths: ["src"],
								language: "TypeScript",
							},
						],
						securityScanSkippedComponents: [
							{
								name: "operations",
								paths: ["ops"],
								reason: "Deployment-only scripts",
							},
						],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(
			fixture.calls.agent
				.filter(({ options }) => options.label.startsWith("inventory"))
				.map(({ options }) => options.label),
		).toEqual(["inventory", "inventory:complete1"]);
		expect(result.coverage.inventoryRejected).toHaveLength(1);
		expect(result.coverage.inventoryRejected[0]).toContain(
			"1 of 2 top-level directories neither scanned nor explicitly skipped",
		);
		expect(result.coverage.completenessCheckOutcome).toBe("checked");
		expect(result.coverage.unaccountedTopLevelDirs).toEqual([]);
	});

	test("preserves explicitly skipped directories in coverage", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				topLevelDirs: ["src", "docs"],
			}),
			responseForAgent: (call) => {
				if (call.options.label === "inventory") {
					return {
						components: [
							{
								name: "web",
								paths: ["src"],
								language: "TypeScript",
							},
						],
						securityScanSkippedComponents: [
							{
								name: "documentation",
								paths: ["docs"],
								reason: "No executable code",
							},
						],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.skippedComponents).toEqual([
			{
				name: "documentation",
				paths: ["docs"],
				reason: "No executable code",
			},
		]);
		expect(result.coverage.completenessCheckOutcome).toBe("checked");
		expect(result.coverage.unaccountedTopLevelDirs).toEqual([]);
	});

	test("does not let parent traversal satisfy top-level coverage", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label.startsWith("inventory")) {
					return {
						components: [
							{
								name: "escaped",
								paths: ["../src"],
								language: "TypeScript",
							},
						],
						securityScanSkippedComponents: [],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.inventoryRejected).toHaveLength(2);
		expect(result.coverage.inventoryRejected[0]).toContain(
			'path with a ".." segment',
		);
		expect(result.coverage.completenessCheckOutcome).toBe("partial");
		expect(result.coverage.unaccountedTopLevelDirs).toEqual(["src"]);
	});

	test("falls back to the repository when a corrected inventory still skips the whole target", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label.startsWith("inventory")) {
					return {
						components: [
							{
								name: "web",
								paths: ["src"],
								language: "TypeScript",
							},
						],
						securityScanSkippedComponents: [
							{
								name: "everything-else",
								paths: ["."],
								reason: "Out of scope",
							},
						],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.inventoryRejected).toHaveLength(2);
		expect(result.coverage.inventoryFallback).toBe("incomplete-partition");
		expect(result.coverage.components).toEqual([
			{
				name: "repository",
				paths: ["."],
			},
		]);
		expect(result.coverage.skippedComponents).toEqual([]);
	});

	test("caps medium-effort inventory at twelve components", async () => {
		const scan = await loadScan();
		const components = createComponents(14);
		const fixture = createScanFixture({
			args: createScanArgs({
				topLevelDirs: undefined,
			}),
			responseForAgent: (call) => {
				if (call.options.label === "inventory") {
					return {
						components,
						securityScanSkippedComponents: [],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.components).toHaveLength(12);
		expect(result.coverage.droppedComponents).toEqual([
			"component-13",
			"component-14",
		]);
		expect(
			fixture.calls.agent.some(
				({ options }) => options.label === "model:component-13",
			),
		).toBe(false);
	});

	test("raises the component cap to twenty-four for expanded effort", async () => {
		const scan = await loadScan();
		const components = createComponents(26);
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "high",
				topLevelDirs: undefined,
			}),
			responseForAgent: (call) => {
				if (call.options.label === "inventory") {
					return {
						components,
						securityScanSkippedComponents: [],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.coverage.components).toHaveLength(24);
		expect(result.coverage.droppedComponents).toEqual([
			"component-25",
			"component-26",
		]);
		expect(
			fixture.calls.agent.some(
				({ options }) => options.label === "model:component-25",
			),
		).toBe(false);
	});
});
