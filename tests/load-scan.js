import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const workflowEntrypoint =
	"return scan(args, log, phase, agent, pipeline, parallel);";
const workflowPath = resolve(import.meta.dir, "../workflows/scan.js");

export async function loadScan() {
	const source = await Bun.file(workflowPath).text();
	const trimmedSource = source.trimEnd();
	if (!trimmedSource.endsWith(workflowEntrypoint)) {
		throw new Error(`Expected the host entrypoint "${workflowEntrypoint}".`);
	}

	const moduleSource = `${trimmedSource
		.slice(0, -workflowEntrypoint.length)
		.trimEnd()}\n`;
	const temporaryDirectory = await mkdtemp(
		join(tmpdir(), "security-review-scan-test-"),
	);
	const modulePath = join(temporaryDirectory, "scan.mjs");
	try {
		await Bun.write(modulePath, moduleSource);
		const workflowModule = await import(pathToFileURL(modulePath).href);
		if (typeof workflowModule.scan !== "function") {
			throw new Error("The workflow does not export scan().");
		}
		return workflowModule.scan;
	} finally {
		await rm(temporaryDirectory, {
			recursive: true,
		});
	}
}
