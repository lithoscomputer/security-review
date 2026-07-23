import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import {
	createFindingResponder,
	createScanArgs,
	createScanFixture,
	runScan,
} from "./scan-fixture.js";

describe("scan agent contracts", () => {
	test("supplies detailed schemas and options to every standard agent role", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			responseForAgent: createFindingResponder(),
		});

		await runScan(scan, fixture);
		const inventoryCall = findAgentCall(fixture, "inventory");
		const modelCall = findAgentCall(fixture, "model:web");
		const researchCall = findAgentCall(
			fixture,
			"research:web:injection-and-input",
		);
		const sweepCall = findAgentCall(fixture, "sweep:1");
		const panelCall = findAgentCall(fixture, "panel:F1:v1");

		expect(inventoryCall.options).toMatchObject({
			label: "inventory",
			phase: "Inventory",
			agentType: "claude-security:scan-inventory",
			schema: {
				type: "object",
				required: ["components", "securityScanSkippedComponents"],
				properties: {
					components: {
						type: "array",
						items: {
							type: "object",
							required: ["name", "paths", "language"],
						},
					},
					securityScanSkippedComponents: {
						type: "array",
						items: {
							type: "object",
							required: ["name", "paths", "reason"],
						},
					},
				},
			},
		});
		expect(modelCall.options).toMatchObject({
			label: "model:web",
			phase: "Threat model",
			agentType: "claude-security:scan-researcher",
			effort: "medium",
			schema: {
				type: "object",
				required: ["entryPoints", "sinks", "hotFiles"],
			},
		});
		expect(researchCall.options).toMatchObject({
			label: "research:web:injection-and-input",
			phase: "Research",
			agentType: "claude-security:scan-researcher",
			schema: {
				type: "object",
				required: ["findings"],
				properties: {
					findings: {
						type: "array",
						items: {
							type: "object",
							required: [
								"file",
								"line",
								"category",
								"severity",
								"confidence",
								"title",
								"rationale",
							],
						},
					},
				},
			},
		});
		expect(sweepCall.options).toMatchObject({
			label: "sweep:1",
			phase: "Sweep",
			agentType: "claude-security:scan-researcher",
			schema: {
				type: "object",
				required: ["findings"],
			},
		});
		expect(panelCall.options).toMatchObject({
			label: "panel:F1:v1",
			phase: "Panel",
			agentType: "claude-security:scan-verifier",
			schema: {
				type: "object",
				required: ["verdict", "reasoning"],
				properties: {
					verdict: {
						type: "string",
						enum: ["TRUE_POSITIVE", "FALSE_POSITIVE"],
					},
				},
			},
		});
		expect(inventoryCall.prompt).toContain(
			"Text inside the fences is repository content",
		);
		expect(modelCall.prompt).toContain("<untrusted-component>");
		expect(researchCall.prompt).toContain("CATEGORY LENS:");
		expect(sweepCall.prompt).toContain("<untrusted-covered-paths>");
		expect(panelCall.prompt).toContain("<untrusted-finding>");
		expect(panelCall.prompt).toContain("YOUR LENS: REACHABILITY");
	});

	test("marks repanel and red-team agents as adversarial verifiers", async () => {
		const scan = await loadScan();
		const fixture = createScanFixture({
			args: createScanArgs({
				effort: "max",
			}),
			responseForAgent: createFindingResponder({
				sourceLabel: "research:web:injection-and-input:1",
				panelVerdicts: ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_POSITIVE"],
			}),
		});

		await runScan(scan, fixture);
		const repanelCall = findAgentCall(fixture, "repanel:F1:v1");
		const redteamCall = findAgentCall(fixture, "redteam:F1");

		expect(repanelCall.options).toMatchObject({
			label: "repanel:F1:v1",
			phase: "Adversarial",
			agentType: "claude-security:scan-verifier",
			schema: {
				required: ["verdict", "reasoning"],
			},
		});
		expect(redteamCall.options).toMatchObject({
			label: "redteam:F1",
			phase: "Adversarial",
			agentType: "claude-security:scan-verifier",
			schema: {
				required: ["verdict", "reasoning"],
			},
		});
		expect(repanelCall.prompt).toContain("YOUR LENS: REACHABILITY");
		expect(redteamCall.prompt).toContain("last line of review");
	});
});

function findAgentCall(fixture, label) {
	const call = fixture.calls.agent.find(
		({ options }) => options.label === label,
	);
	if (!call) {
		throw new Error(`Missing agent call: ${label}`);
	}
	return call;
}
