import { describe, expect, test } from "bun:test";
import { loadScan } from "./load-scan.js";
import {
	createDuplicateFindings,
	createFinding,
	createScanFixture,
	createUniqueFindings,
	respondWithDefaults,
	runScan,
} from "./scan-fixture.js";

describe("scan candidate processing", () => {
	test("deduplicates reports, merges fields, and ranks the strongest finding first", async () => {
		const scan = await loadScan();
		const lowerSeverityReport = createFinding({
			severity: "LOW",
			confidence: "HIGH",
			impact: "",
			exploitScenario: "",
			evidence: "Supplemental evidence",
			snippet: "exec(userInput)",
			recommendation: "Merged recommendation",
		});
		const higherSeverityReport = createFinding({
			severity: "HIGH",
			confidence: "LOW",
			evidence: "",
			snippet: "",
			recommendation: "",
			cweId: null,
		});
		const mediumFinding = createFinding({
			file: "src/other.ts",
			line: 30,
			category: "path-traversal",
			severity: "MEDIUM",
			title: "Traversal reaches a file read",
		});
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "research:web:injection-and-input") {
					return {
						findings: [lowerSeverityReport],
					};
				}
				if (call.options.label === "research:web:auth-and-access") {
					return {
						findings: [higherSeverityReport, mediumFinding],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.votes.candidates).toBe(3);
		expect(result.votes.candidates_deduped).toBe(2);
		expect(fixture.calls.pipeline[1].items[0]).toMatchObject({
			file: "src/server.ts",
			line: 20,
			severity: "HIGH",
			confidence: "HIGH",
			reports: 2,
			reporters: ["web"],
			evidence: "Supplemental evidence",
			recommendation: "Merged recommendation",
		});
		expect(result.findings).toHaveLength(2);
		expect(result.findings[0]).toMatchObject({
			id: "F1",
			title: "Untrusted command reaches exec",
			severity: "HIGH",
			confidence: "HIGH",
			snippet: "exec(userInput)",
			recommendation: "Merged recommendation",
			// biome-ignore lint/style/useNamingConvention: Workflow result contract uses snake_case.
			cwe_id: "CWE-78",
		});
		expect(result.findings[1]).toMatchObject({
			id: "F2",
			title: "Traversal reaches a file read",
			severity: "MEDIUM",
		});
	});

	test("accepts a finding produced by the sweep", async () => {
		const scan = await loadScan();
		const sweepFinding = createFinding({
			file: "scripts/deploy.ts",
			line: 8,
			title: "Deployment argument reaches a shell",
		});
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "sweep:1") {
					return {
						findings: [sweepFinding],
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(fixture.calls.pipeline[1].items[0]).toMatchObject({
			file: "scripts/deploy.ts",
			line: 8,
			component: "sweep",
		});
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({
			title: "Deployment argument reaches a shell",
			file: "scripts/deploy.ts",
			line: 8,
		});
	});

	test("caps raw candidates at four hundred before deduplication", async () => {
		const scan = await loadScan();
		const duplicateFindings = createDuplicateFindings(402);
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "research:web:injection-and-input") {
					return {
						findings: duplicateFindings,
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.votes.candidates).toBe(402);
		expect(result.votes.candidates_deduped).toBe(1);
		expect(result.coverage.candidatesDroppedByCap).toBe(2);
		expect(fixture.calls.pipeline[1].items[0].reports).toBe(400);
		expect(result.votes.unreviewed_candidate_sites).toBe(0);
	});

	test("verifies only the first forty-five unique candidates", async () => {
		const scan = await loadScan();
		const uniqueFindings = createUniqueFindings(47);
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "research:web:injection-and-input") {
					return {
						findings: uniqueFindings,
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.votes.candidates).toBe(47);
		expect(result.votes.candidates_deduped).toBe(47);
		expect(
			fixture.calls.agent.filter(({ options }) =>
				options.label.startsWith("panel:"),
			),
		).toHaveLength(135);
		expect(result.findings).toHaveLength(45);
		expect(result.votes.panel_votes).toBe(135);
		expect(result.votes.unreviewed_candidate_sites).toBe(2);
		expect(result.coverage.unverifiedByCap).toBe(2);
	});

	test("counts unique candidates dropped by the cap as unreviewed sites", async () => {
		const scan = await loadScan();
		const uniqueFindings = createUniqueFindings(402);
		const fixture = createScanFixture({
			responseForAgent: (call) => {
				if (call.options.label === "research:web:injection-and-input") {
					return {
						findings: uniqueFindings,
					};
				}
				return respondWithDefaults(call);
			},
		});

		const result = await runScan(scan, fixture);

		expect(result.votes.candidates).toBe(402);
		expect(result.votes.candidates_deduped).toBe(400);
		expect(result.coverage.candidatesDroppedByCap).toBe(2);
		expect(result.coverage.unverifiedByCap).toBe(355);
		expect(result.votes.unreviewed_candidate_sites).toBe(357);
		expect(result.findings).toHaveLength(45);
	});
});
