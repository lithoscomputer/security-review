#!/usr/bin/env bun

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { $ } from "bun";

const { values } = parseArgs({
	args: Bun.argv.slice(2),
	options: {
		write: {
			type: "boolean",
			default: false,
		},
	},
});

const projectRoot = resolve(import.meta.dir, "..");
const biomeExecutable = `${projectRoot}/node_modules/.bin/biome`;
const workflowGlob = new Bun.Glob("workflows/**/*.js");
const workflowPaths = [];
const textDecoder = new TextDecoder();
const workflowEntrypoint =
	"return scan(args, log, phase, agent, pipeline, parallel);";
const temporaryRoot = (Bun.env.TMPDIR || "/tmp").replace(/\/+$/, "");

for await (const path of workflowGlob.scan({
	cwd: projectRoot,
	onlyFiles: true,
})) {
	workflowPaths.push(path);
}
workflowPaths.sort();

if (workflowPaths.length === 0) {
	console.error("No JavaScript workflow files found.");
	process.exitCode = 1;
}

for (const path of workflowPaths) {
	try {
		const absolutePath = `${projectRoot}/${path}`;
		const source = await Bun.file(absolutePath).text();
		const moduleSource = removeWorkflowEntrypoint(source);
		const formattedModuleSource = await formatStandardJavaScript(
			moduleSource,
			path,
		);
		const formattedSource = addWorkflowEntrypoint(formattedModuleSource);
		if (values.write) {
			if (formattedSource !== source) {
				await Bun.write(absolutePath, formattedSource);
				console.log(`Formatted ${path}`);
			}
			continue;
		}

		if (formattedSource !== source) {
			console.error(`${path}: not formatted; run "bun run format".`);
			process.exitCode = 1;
		}

		if (!(await lintStandardJavaScript(moduleSource, path))) {
			process.exitCode = 1;
		}
	} catch (error) {
		console.error(
			`${path}: ${error instanceof Error ? error.message : String(error)}`,
		);
		process.exitCode = 1;
	}
}

async function formatStandardJavaScript(source, path) {
	const result =
		await $`echo ${source} | ${biomeExecutable} format --stdin-file-path ${path}`
			.cwd(projectRoot)
			.quiet()
			.nothrow();
	if (result.exitCode !== 0) {
		const diagnostic = textDecoder.decode(result.stderr).trimEnd();
		throw new Error(diagnostic || "Biome could not format the workflow.");
	}
	return textDecoder.decode(result.stdout);
}

async function lintStandardJavaScript(source, path) {
	if (!temporaryRoot.startsWith("/") || temporaryRoot === "/") {
		throw new Error("The temporary directory root is not safe to use.");
	}
	const temporaryDirectory = (
		await $`mktemp -d ${`${temporaryRoot}/security-review-biome.XXXXXX`}`
			.quiet()
			.text()
	).trim();
	if (
		!temporaryDirectory.startsWith(`${temporaryRoot}/security-review-biome.`)
	) {
		throw new Error("Could not create a safe temporary lint directory.");
	}

	try {
		const temporaryPath = `${temporaryDirectory}/${path}`;
		const temporaryParent = temporaryPath.slice(
			0,
			temporaryPath.lastIndexOf("/"),
		);
		await $`mkdir -p ${temporaryParent}`.quiet();
		await Bun.write(temporaryPath, source);

		const result =
			await $`${biomeExecutable} lint --config-path ${`${projectRoot}/biome.json`} ${path}`
				.cwd(temporaryDirectory)
				.quiet()
				.nothrow();
		const diagnostic = [
			textDecoder.decode(result.stdout).trimEnd(),
			textDecoder.decode(result.stderr).trimEnd(),
		]
			.filter(Boolean)
			.join("\n");
		if (diagnostic) {
			console.error(diagnostic);
		}
		return result.exitCode === 0;
	} finally {
		await $`rm -r -- ${temporaryDirectory}`.quiet().nothrow();
	}
}

function removeWorkflowEntrypoint(source) {
	const trimmedSource = source.trimEnd();
	if (!trimmedSource.endsWith(workflowEntrypoint)) {
		throw new Error(`Expected the host entrypoint "${workflowEntrypoint}".`);
	}
	return `${trimmedSource.slice(0, -workflowEntrypoint.length).trimEnd()}\n`;
}

function addWorkflowEntrypoint(source) {
	return `${source.trimEnd()}\n\n${workflowEntrypoint}\n`;
}
