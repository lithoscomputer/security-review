import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import {
	createScanArgs,
	createScanFixture,
	respondWithDefaults,
	runScan,
} from "./scan-fixture.js";

afterEach(() => {
	mock.restore();
});

describe("scan agent reliability", () => {
	test("retries an agent that initially returns no result", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "inventory") {
					return null;
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(
			fixture.calls.agent.slice(0, 2).map(({ options }) => options.label),
		).toEqual(["inventory", "inventory:retry1"]);
		expect(result.coverage.inventoryFallback).toBeNull();
		expect(result.coverage.components).toEqual([
			{
				name: "web",
				paths: ["src"],
			},
		]);
	});

	test("falls back after an inventory agent exhausts both retries", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label.startsWith("inventory")) {
					return null;
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(
			fixture.calls.agent
				.filter(({ options }) => options.label.startsWith("inventory"))
				.map(({ options }) => options.label),
		).toEqual(["inventory", "inventory:retry1", "inventory:retry2"]);
		expect(result.coverage.inventoryFallback).toBe("inventory-failed");
		expect(result.coverage.components).toEqual([
			{
				name: "repository",
				paths: ["."],
			},
		]);
	});

	test("records a researcher that remains missing after retries", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label.startsWith("research:web:auth-and-access")) {
					return null;
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(
			fixture.calls.agent
				.filter(({ options }) =>
					options.label.startsWith("research:web:auth-and-access"),
				)
				.map(({ options }) => options.label),
		).toEqual([
			"research:web:auth-and-access",
			"research:web:auth-and-access:retry1",
			"research:web:auth-and-access:retry2",
		]);
		expect(result.coverage.researchersDispatched).toBe(4);
		expect(result.coverage.researchersReturned).toBe(3);
		expect(result.votes.researchers_dispatched).toBe(4);
		expect(result.votes.researchers_returned).toBe(3);
	});

	test("propagates an error thrown by an injected agent", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "low",
			}),
			responseForAgent: (call) => {
				if (call.options.label.startsWith("research:")) {
					throw new Error("agent exploded");
				}
				return respondWithDefaults(call);
			},
		});

		await expect(runScan(scan, fixture)).rejects.toThrow("agent exploded");
	});
});

function makeRetryDelaysImmediate() {
	spyOn(globalThis, "setTimeout").mockImplementation((callback) => {
		callback();
		return 0;
	});
}
