import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import {
	createFindingResponder,
	createScanArgs,
	createScanFixture,
	runScan,
} from "./scan-fixture.js";

afterEach(() => {
	mock.restore();
});

describe("scan panel decisions", () => {
	test("rejects a candidate when the panel votes false positive", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			responseForAgent: createFindingResponder({
				panelVerdicts: ["FALSE_POSITIVE", "FALSE_POSITIVE", "FALSE_POSITIVE"],
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toEqual([]);
		expect(result.votes.rounds.F1.panel).toEqual({
			true: 0,
			false: 3,
			voters: 3,
		});
		expect(result.votes.panel_votes).toBe(3);
	});

	test("keeps a candidate on a two-to-one true-positive vote", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			responseForAgent: createFindingResponder({
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toHaveLength(1);
		expect(result.votes.rounds.F1.panel).toEqual({
			true: 2,
			false: 1,
			voters: 3,
		});
		expect(result.votes.panel_votes).toBe(3);
	});

	test("rejects a candidate when fewer than three panel voters return", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			responseForAgent: createFindingResponder({
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", null],
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toEqual([]);
		expect(result.votes.rounds.F1.panel).toEqual({
			true: 2,
			false: 0,
			voters: 2,
		});
		expect(
			fixture.calls.agent
				.filter(({ options }) => options.label.startsWith("panel:F1:v3"))
				.map(({ options }) => options.label),
		).toEqual(["panel:F1:v3", "panel:F1:v3:retry1", "panel:F1:v3:retry2"]);
	});
});

describe("scan max-effort verification", () => {
	test("keeps a marginal panel result after repanel and red-team confirmation", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
				repanelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
				redteamVerdict: "TRUE_POSITIVE",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toHaveLength(1);
		expect(result.votes.rounds.F1).toEqual({
			panel: {
				true: 2,
				false: 1,
				voters: 3,
			},
			adversarial: {
				repanel: {
					true: 2,
					false: 1,
					voters: 3,
				},
				redteam: "TRUE_POSITIVE",
			},
		});
		expect(result.votes.panel_votes).toBe(7);
		expect(result.coverage.adversarialCasualties).toEqual([]);
	});

	test("drops a marginal candidate when its repanel reverses the result", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
				repanelVerdicts: ["TRUE_POSITIVE", "FALSE_POSITIVE", "FALSE_POSITIVE"],
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toEqual([]);
		expect(result.votes.rounds.F1.adversarial).toEqual({
			repanel: {
				true: 1,
				false: 2,
				voters: 3,
			},
			redteam: null,
		});
		expect(
			fixture.calls.agent.some(({ options }) =>
				options.label.startsWith("redteam:"),
			),
		).toBe(false);
		expect(result.coverage.adversarialCasualties[0]).toContain(
			"dropped on repanel (1/3)",
		);
	});

	test("drops a unanimous panel result when the red team refutes it", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				redteamVerdict: "FALSE_POSITIVE",
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toEqual([]);
		expect(result.votes.rounds.F1.adversarial).toEqual({
			repanel: null,
			redteam: "FALSE_POSITIVE",
		});
		expect(
			fixture.calls.agent.some(({ options }) =>
				options.label.startsWith("repanel:"),
			),
		).toBe(false);
		expect(result.coverage.adversarialCasualties[0]).toContain(
			"refuted by red team",
		);
		expect(result.votes.panel_votes).toBe(4);
	});

	test("keeps the first-panel result when the repanel is incomplete", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
				repanelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", null],
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toHaveLength(1);
		expect(result.votes.rounds.F1.adversarial).toEqual({
			repanel: {
				true: 2,
				false: 0,
				voters: 2,
			},
			redteam: "TRUE_POSITIVE",
		});
		expect(result.coverage.adversarialCasualties[0]).toContain(
			"repanel incomplete (2/3 voters returned)",
		);
		expect(result.votes.panel_votes).toBe(6);
	});

	test("keeps the first-panel result when the red team returns no vote", async () => {
		const scan = await loadScan();
		makeRetryDelaysImmediate();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				redteamVerdict: null,
			}),
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toHaveLength(1);
		expect(result.votes.rounds.F1.adversarial).toEqual({
			repanel: null,
			redteam: "no-vote",
		});
		expect(
			fixture.calls.agent
				.filter(({ options }) => options.label.startsWith("redteam:F1"))
				.map(({ options }) => options.label),
		).toEqual(["redteam:F1", "redteam:F1:retry1", "redteam:F1:retry2"]);
		expect(result.coverage.adversarialCasualties[0]).toContain(
			"red-team refuter returned no vote after retries",
		);
		expect(result.votes.panel_votes).toBe(3);
	});

	test("keeps the first-panel result when adversarial verification throws", async () => {
		const scan = await loadScan();
		const findingResponder = createFindingResponder({
			sourceLabel: "research:web:injection-and-input:1",
		});
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: (call) => {
				if (call.options.label === "redteam:F1") {
					throw new Error("red team exploded");
				}
				return findingResponder(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.findings).toHaveLength(1);
		expect(result.votes.rounds.F1.adversarial).toEqual({
			incomplete: true,
		});
		expect(result.coverage.adversarialCasualties[0]).toContain(
			"adversarial pass failed (red team exploded)",
		);
	});
});

function makeRetryDelaysImmediate() {
	spyOn(globalThis, "setTimeout").mockImplementation((callback) => {
		callback();
		return 0;
	});
}
