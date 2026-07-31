"""Source data for the example report rendered into `sample.html`.

These findings describe a fictional product. They exist to exercise every part
of the report template -- each severity, each difficulty, a multi-paragraph
body, ordered exploit steps, several recommendations, and one excerpt whose
source contains characters that must not escape a script element.
"""

from __future__ import annotations


TARGET_IDENTITY_MATERIAL = "git-origin\0example.com/acme/portal"
SCAN_ID = "sample-security-review-001"
STARTED_AT = "2026-07-30T14:58:00+00:00"
COMPLETED_AT = "2026-07-30T15:04:05+00:00"
REVISION = {
    "versioned": True,
    "commit": "a6894bca75ce4f1d8b0e2c37519adf60c4831b7e",
    "branch": "main",
    "dirty": False,
}
REQUEST = {
    "mode": "scan",
    "scope": [],
    "range": None,
    "base": None,
    "commit": None,
    "effort": "high",
    "focus": "attack-surface",
}
COMPONENTS = (
    {
        "name": "Web application",
        "paths": ["app/routes", "app/services", "app/graphql"],
    },
    {"name": "Report worker", "paths": ["src/reports"]},
    {"name": "Job execution", "paths": ["src/events", "src/storage"]},
    {"name": "Command-line client", "paths": ["src/telemetry"]},
    {"name": "Release automation", "paths": [".github/workflows"]},
)
SKIPPED_COMPONENTS = (
    {
        "name": "Generated assets",
        "paths": ["public/build", "app/generated"],
        "reason": (
            "Generated output; reviewed through its source templates and build "
            "configuration."
        ),
    },
    {
        "name": "Vendored fixtures",
        "paths": ["tests/fixtures/vendor"],
        "reason": "Third-party test data with no production execution path.",
    },
)
RESEARCHERS_PER_CELL = 2
RESEARCHERS_DISPATCHED = 43
RESEARCHERS_RETURNED = 43


def code(language: str, first_line: int, highlight: int, text: str):
    """Build an excerpt the way the engine reads one from the reviewed tree."""
    lines = []
    for offset, line in enumerate(text.split("\n")):
        number = first_line + offset
        entry = {"number": number, "text": line}
        if number == highlight:
            entry["highlight"] = True
        lines.append(entry)
    return {
        "language": language,
        "first_line": first_line,
        "lines": lines,
    }


FINDINGS = (
    {
        "ruleId": "command-injection.shell-command",
        "anchor": "report-export-command",
        "title": "Shell command injection in report export",
        "severity": "HIGH",
        "difficulty": "LOW",
        "confidence": "high",
        "reports": 3,
        "reporters": ["Report worker", "Job execution", "sweep"],
        "file": "src/reports/export.ts",
        "line": 118,
        "symbol": "renderReport",
        "cwe_id": "CWE-78",
        "description": (
            "The report worker inserts a user-controlled filename into a shell "
            "command. Shell metacharacters can start a second command with the "
            "worker's privileges."
        ),
        "evidence": [
            "src/reports/export.ts:114 takes the display name from the export request and only replaces spaces in it.",
            "src/reports/export.ts:117 interpolates that value into a command string, so it is no longer one argument.",
            "src/reports/export.ts:118 passes the string to exec, which starts a shell, giving semicolons and command substitutions their control meaning.",
            "No call between line 114 and line 118 validates the value or escapes it for a shell.",
        ],
        "impact": (
            "An attacker can execute commands in the report worker, read another "
            "queued export that shares the worker, and alter generated artifacts."
        ),
        "exploit_scenarios": [
            "An editor names a report quarterly; cp /work/input.json "
            "/work/public/leak.json and starts an export.",
            "The worker runs the injected copy command and publishes the copied "
            "input with the normal export artifacts.",
        ],
        "preconditions": [
            "An authenticated member can create or rename a report.",
            "The report reaches the asynchronous export worker.",
        ],
        "recommendations": [
            "Call the renderer directly with a fixed executable and an argument "
            "array.",
            "Generate server-side filenames and keep the display name outside "
            "filesystem paths.",
            "Add a regression test with shell metacharacters and command "
            "substitutions.",
        ],
        "snippet": "await exec(command, { cwd: jobDirectory });",
        "code": code(
            "TypeScript",
            114,
            118,
            'const outputName = request.reportName.replaceAll(" ", "_");\n'
            "const outputPath = `/work/output/${outputName}.pdf`;\n"
            "\n"
            "const command = `render-report ${inputPath} -o ${outputPath}`;\n"
            "await exec(command, { cwd: jobDirectory });\n"
            "\n"
            "return publishArtifact(outputPath);",
        ),
    },
    {
        "ruleId": "improper-authorization.event-replay",
        "anchor": "artifact-event-destination",
        "title": "Cross-tenant artifact overwrite through event replay",
        "severity": "HIGH",
        "difficulty": "HIGH",
        "confidence": "high",
        "reports": 2,
        "reporters": ["Job execution", "sweep"],
        "file": "src/events/artifact_created.rs",
        "line": 87,
        "symbol": "handle_artifact_created",
        "cwe_id": "CWE-862",
        "description": (
            "The artifact processor trusts tenant and storage identifiers from a "
            "signed but replayable internal event. It does not bind the "
            "destination to the originating build."
        ),
        "evidence": [
            "src/events/artifact_created.rs:82 authenticates the event at the queue boundary, and nothing after it re-checks authority.",
            "src/events/artifact_created.rs:85 builds the destination key from the event's own tenant identifier and object key.",
            "src/events/artifact_created.rs:87 writes to that key without consulting the build record that produced the artifact.",
            "The signature covers the payload but not the fields a replay changes, so a captured event can be redirected to another tenant.",
        ],
        "impact": (
            "A compromised worker can replace downloadable build output across a "
            "tenant boundary and create a software supply-chain path."
        ),
        "exploit_scenarios": [
            "An attacker extracts a worker event key, captures a valid artifact "
            "event, and changes the tenant and object key fields.",
            "The processor accepts the replay and writes attacker-controlled "
            "bytes over a release artifact in another workspace.",
        ],
        "preconditions": [
            "Access to an internal worker event key or a compromised worker.",
            "Knowledge of a target tenant and artifact object key.",
        ],
        "recommendations": [
            "Sign the complete event envelope and reject duplicate event "
            "identifiers.",
            "Resolve tenant ownership from the build record instead of the event "
            "payload.",
            "Use conditional storage writes and immutable release artifact "
            "versions.",
        ],
        "snippet": "store.put(&destination, event.bytes).await?;",
        "code": code(
            "Rust",
            82,
            87,
            "verify_event_signature(&event.signature, &event.payload)?;\n"
            "\n"
            "let destination = format!(\n"
            '    "tenants/{}/artifacts/{}", event.tenant_id, event.object_key\n'
            ");\n"
            "store.put(&destination, event.bytes).await?;\n"
            "mark_complete(event.build_id).await?;",
        ),
    },
    {
        "ruleId": "idor.tenant-scope",
        "anchor": "document-download-lookup",
        "title": "Document download omits tenant authorization",
        "severity": "MEDIUM",
        "difficulty": "MEDIUM",
        "confidence": "high",
        "reports": 2,
        "reporters": ["Web application", "sweep"],
        "file": "app/routes/api.documents.$id.ts",
        "line": 43,
        "symbol": "loader",
        "cwe_id": "CWE-639",
        "description": (
            "The document download route queries by document ID alone. Other "
            "document routes include the active tenant in the query."
        ),
        "evidence": [
            "app/routes/api.documents.$id.ts:39 authenticates the caller through requireUser.",
            "app/routes/api.documents.$id.ts:43 queries by document ID alone, with no tenant predicate.",
            "app/routes/api.documents.$id.ts:46 streams whatever record the query returned.",
        ],
        "impact": (
            "An authenticated user who learns a document ID can download a "
            "private document from another tenant."
        ),
        "exploit_scenarios": [
            "A former contractor retains a copied document link after moving to "
            "a different workspace.",
            "The route authenticates the contractor but does not verify that the "
            "current workspace owns the document.",
        ],
        "preconditions": [
            "A valid account.",
            "Knowledge of a document identifier from another tenant.",
        ],
        "recommendations": [
            "Query by both document ID and active tenant ID.",
            "Move tenant-owned record lookup into one shared authorization "
            "helper.",
            "Add negative tests that use a valid ID from a different tenant.",
        ],
        "snippet": "where: { id: documentId },",
        "code": code(
            "TypeScript",
            39,
            43,
            "const user = await requireUser(request);\n"
            "const documentId = params.id;\n"
            "\n"
            "const document = await db.document.findUnique({\n"
            "  where: { id: documentId },\n"
            "});\n"
            "\n"
            "return streamStoredDocument(document);",
        ),
    },
    {
        "ruleId": "cleartext-transmission.object-storage-endpoint",
        "anchor": "storage-endpoint-scheme",
        "title": "Custom object-storage endpoint permits plaintext transport",
        "severity": "MEDIUM",
        "difficulty": "HIGH",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Job execution"],
        "file": "src/storage/client.rs",
        "line": 60,
        "symbol": "build_client",
        "cwe_id": "CWE-319",
        "description": (
            "A deployment can configure an HTTP object-storage endpoint. The "
            "client sends storage credentials and artifact data without "
            "enforcing TLS."
        ),
        "evidence": [
            "src/storage/client.rs:59 reads a deployment-supplied endpoint from configuration.",
            "src/storage/client.rs:60 accepts that endpoint URL verbatim, with no branch rejecting an http:// scheme.",
            "src/storage/client.rs:63 attaches storage credentials to the client built from it, so they travel over whatever transport was configured.",
        ],
        "impact": (
            "A network-positioned attacker can observe storage credentials and "
            "artifact contents, then read or replace stored artifacts."
        ),
        "exploit_scenarios": [
            "An operator copies an internal HTTP endpoint from a development "
            "environment into production.",
            "A compromised host on the service network captures the signed "
            "storage requests and artifact data.",
        ],
        "preconditions": [
            "A custom HTTP endpoint is configured.",
            "Access to the storage network path.",
        ],
        "recommendations": [
            "Reject non-HTTPS endpoints by default.",
            "Require a clearly named development-only override for plaintext "
            "transport.",
            "Emit a startup failure that names the unsafe setting and affected "
            "endpoint.",
        ],
        "snippet": "builder = builder.endpoint_url(endpoint);",
        "code": code(
            "Rust",
            57,
            60,
            "let mut builder = S3Client::builder().region(config.region);\n"
            "\n"
            "if let Some(endpoint) = &config.endpoint {\n"
            "    builder = builder.endpoint_url(endpoint);\n"
            "}\n"
            "\n"
            "builder.credentials_provider(config.credentials).build()",
        ),
    },
    {
        "ruleId": "weak-randomness.recovery-token",
        "anchor": "recovery-token-source",
        "title": "Recovery tokens use a predictable random source",
        "severity": "MEDIUM",
        "difficulty": "MEDIUM",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/services/recovery.server.ts",
        "line": 72,
        "symbol": "createRecoveryToken",
        "cwe_id": "CWE-338",
        "description": (
            "Account recovery tokens are generated with a seeded pseudo-random "
            "generator intended for simulations, not secrets."
        ),
        "evidence": [
            "app/services/recovery.server.ts:68 defines the token alphabet.",
            "app/services/recovery.server.ts:72 draws every character from seedRandom, a generator seeded once at process start.",
            "Nothing in the module reads the operating system's cryptographic random source.",
        ],
        "impact": (
            "An attacker can predict a recovery token in favorable conditions "
            "and take control of a target account."
        ),
        "exploit_scenarios": [
            "An attacker requests recovery for their own account after a known "
            "deployment time and observes the token.",
            "They reconstruct the generator state, predict a nearby token, and "
            "submit it for a known administrator email.",
        ],
        "preconditions": [
            "Knowledge of a target email address.",
            "Enough timing information or observed output to narrow generator "
            "state.",
        ],
        "recommendations": [
            "Generate tokens with the operating system cryptographic random "
            "source.",
            "Store only a keyed hash of each token and rotate it after one use.",
            "Rate-limit recovery creation and verification per account and "
            "source.",
        ],
        "snippet": "alphabet[Math.floor(seedRandom() * alphabet.length)]",
        "code": code(
            "TypeScript",
            68,
            72,
            'const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";\n'
            "\n"
            "export function createRecoveryToken() {\n"
            "  return Array.from({ length: 10 }, () =>\n"
            "    alphabet[Math.floor(seedRandom() * alphabet.length)]\n"
            '  ).join("");\n'
            "}",
        ),
    },
    {
        "ruleId": "user-enumeration.sign-in-response",
        "anchor": "sign-in-failure-detail",
        "title": "Authentication errors reveal workspace membership",
        "severity": "LOW",
        "difficulty": "LOW",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/services/authentication.server.ts",
        "line": 135,
        "symbol": "authenticate",
        "cwe_id": "CWE-204",
        "description": (
            "Sign-in responses distinguish unknown emails, disabled accounts, "
            "and valid accounts with incorrect passwords."
        ),
        "evidence": [
            "app/services/authentication.server.ts:132 returns a distinct message when no account uses the address.",
            "app/services/authentication.server.ts:135 returns a distinct message when the account is disabled.",
            "app/services/authentication.server.ts:137 returns a third message for a wrong password, so the response itself reports account state.",
        ],
        "impact": (
            "An attacker can identify customer users and account status, which "
            "improves phishing and credential-stuffing campaigns."
        ),
        "exploit_scenarios": [
            "An attacker submits a small list of executives to the sign-in "
            "endpoint.",
            "Different errors identify active users, who then receive tailored "
            "password-reset phishing.",
        ],
        "preconditions": [
            "Public access to the sign-in form.",
            "A candidate list of email addresses.",
        ],
        "recommendations": [
            "Return one generic response for all failed sign-in states.",
            "Keep detailed reasons in protected security logs.",
            "Apply account- and network-aware abuse controls.",
        ],
        "snippet": 'return fail("This account has been disabled");',
        "code": code(
            "TypeScript",
            131,
            135,
            "const account = await findAccount(email);\n"
            'if (!account) return fail("No account uses this email");\n'
            "\n"
            "if (account.disabledAt) {\n"
            '  return fail("This account has been disabled");\n'
            "}\n"
            'if (!verify(password, account.hash)) return fail("Wrong password");',
        ),
    },
    {
        "ruleId": "insufficient-logging.role-change",
        "anchor": "membership-role-update",
        "title": "Role changes are not recorded in the audit trail",
        "severity": "LOW",
        "difficulty": "MEDIUM",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/services/memberships.server.ts",
        "line": 204,
        "symbol": "changeMemberRole",
        "cwe_id": "CWE-778",
        "description": (
            "Workspace role changes update membership state but do not create a "
            "durable audit event."
        ),
        "evidence": [
            "app/services/memberships.server.ts:200 checks that the actor administers the workspace.",
            "app/services/memberships.server.ts:204 writes the new role and the function returns.",
            "No call in this path records an audit event, though the invitation and removal paths in the same module do.",
        ],
        "impact": (
            "A malicious or compromised administrator can change privileges with "
            "limited durable evidence, delaying response to later abuse."
        ),
        "exploit_scenarios": [
            "A compromised workspace administrator promotes an accomplice, "
            "accesses restricted reports, and restores the prior role.",
            "The membership table shows only the final role, and no audit event "
            "records the temporary elevation.",
        ],
        "preconditions": [
            "Workspace administrator access.",
            "Ability to change another member's role.",
        ],
        "recommendations": [
            "Write an immutable audit event in the same transaction as each role "
            "change.",
            "Record actor, subject, old role, new role, workspace, request ID, "
            "and timestamp.",
            "Alert on owner changes and rapid privilege elevation followed by "
            "demotion.",
        ],
        "snippet": "data: { role: nextRole },",
        "code": code(
            "TypeScript",
            200,
            204,
            "await requireWorkspaceAdmin(actor, workspaceId);\n"
            "\n"
            "return db.membership.update({\n"
            "  where: { workspaceId_userId: { workspaceId, userId } },\n"
            "  data: { role: nextRole },\n"
            "});",
        ),
    },
    {
        "ruleId": "open-redirect.host-allowlist",
        "anchor": "post-login-redirect-check",
        "title": "Encoded hostnames bypass the redirect allowlist",
        "severity": "LOW",
        "difficulty": "MEDIUM",
        "confidence": "medium",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/services/redirects.server.ts",
        "line": 50,
        "symbol": "safeRedirect",
        "cwe_id": "CWE-601",
        "description": (
            "The post-login redirect check compares an encoded hostname string "
            "before the URL parser applies canonical form."
        ),
        "evidence": [
            "app/services/redirects.server.ts:48 returns relative paths unchanged, which is safe.",
            "app/services/redirects.server.ts:50 tests the raw string for a trusted domain substring, before any parsing.",
            "app/services/redirects.server.ts:51 parses the URL only afterwards, so the check never sees the canonical host.",
        ],
        "impact": (
            "An attacker can send a signed-in user from the login flow to an "
            "attacker-controlled page that appears to originate from the product."
        ),
        "exploit_scenarios": [
            "An attacker sends a login link with a crafted returnTo value.",
            "After authentication, the user lands on a look-alike page that "
            "requests a second credential or recovery code.",
        ],
        "preconditions": [
            "A victim follows an attacker-provided sign-in link.",
            "The victim completes sign-in.",
        ],
        "recommendations": [
            "Parse once, normalize the hostname, and compare exact host values.",
            "Prefer relative application paths over absolute redirect URLs.",
            "Add tests for encoded separators, trailing dots, Unicode, and mixed "
            "case.",
        ],
        "snippet": 'if (returnTo.includes(".acme.example")) {',
        "code": code(
            "TypeScript",
            47,
            50,
            "export function safeRedirect(returnTo: string) {\n"
            '  if (returnTo.startsWith("/")) return returnTo;\n'
            "\n"
            '  if (returnTo.includes(".acme.example")) {\n'
            "    return new URL(returnTo).toString();\n"
            "  }\n"
            '  return "/dashboard";\n'
            "}",
        ),
    },
    {
        "ruleId": "insecure-file-permissions.telemetry-spool",
        "anchor": "telemetry-spool-location",
        "title": "Telemetry files use shared temporary storage",
        "severity": "LOW",
        "difficulty": "LOW",
        "confidence": "medium",
        "reports": 1,
        "reporters": ["Command-line client"],
        "file": "src/telemetry/spool.rs",
        "line": 37,
        "symbol": "spool_path",
        "cwe_id": "CWE-377",
        "description": (
            "The CLI writes diagnostic events to a predictable directory in the "
            "system temporary location instead of a user-private application "
            "directory."
        ),
        "evidence": [
            "src/telemetry/spool.rs:36 resolves the shared system temporary directory.",
            "src/telemetry/spool.rs:37 joins a fixed directory name onto it, so the location is predictable.",
            "src/telemetry/spool.rs:38 names each file after its event ID, so the filenames are predictable too.",
        ],
        "impact": (
            "Local users may observe limited developer activity metadata or "
            "disrupt diagnostic uploads on shared hosts."
        ),
        "exploit_scenarios": [
            "A developer runs the CLI on a shared build host.",
            "Another local user monitors predictable spool filenames and learns "
            "repository path and command metadata.",
        ],
        "preconditions": [
            "Multiple untrusted users share a host.",
            "Local temporary storage permits observation.",
        ],
        "recommendations": [
            "Store telemetry under the user's private application data "
            "directory.",
            "Create files with owner-only permissions and unpredictable names.",
            "Document the fields retained in local telemetry records.",
        ],
        "snippet": '.join("acme-telemetry")',
        "code": code(
            "Rust",
            35,
            37,
            "fn spool_path(event_id: &str) -> PathBuf {\n"
            "    std::env::temp_dir()\n"
            '        .join("acme-telemetry")\n'
            '        .join(format!("{event_id}.json"))\n'
            "}",
        ),
    },
    {
        "ruleId": "unpinned-dependency.release-action",
        "anchor": "release-action-reference",
        "title": "Release workflow uses an unpinned third-party action",
        "severity": "LOW",
        "difficulty": "HIGH",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Release automation"],
        "file": ".github/workflows/release.yml",
        "line": 34,
        "symbol": "release job",
        "cwe_id": "CWE-829",
        "description": (
            "The release workflow references a third-party action by a mutable "
            "version tag while granting access to release credentials."
        ),
        "evidence": [
            ".github/workflows/release.yml:34 references the action by the mutable tag v3 rather than a commit digest.",
            ".github/workflows/release.yml:36 passes the release token to that same step.",
            "Environment approval gates the job but does not make the referenced action content immutable.",
        ],
        "impact": (
            "A compromised action version could access release tokens, alter "
            "packages, or change build provenance."
        ),
        "exploit_scenarios": [
            "An attacker compromises the action publisher and moves the version "
            "tag to malicious code.",
            "The next approved release runs that code with package publication "
            "permissions.",
        ],
        "preconditions": [
            "Compromise of the third-party action or its release process.",
            "An approved release after the tag changes.",
        ],
        "recommendations": [
            "Pin the action to a reviewed full commit digest.",
            "Use automated updates that show the digest change in a pull "
            "request.",
            "Keep release credentials behind environment approval and least "
            "privilege.",
        ],
        "snippet": "- uses: vendor/publish-artifact@v3",
        "code": code(
            "YAML",
            30,
            34,
            "jobs:\n"
            "  release:\n"
            "    environment: production\n"
            "    steps:\n"
            "      - uses: vendor/publish-artifact@v3\n"
            "        with:\n"
            "          token: ${{ secrets.RELEASE_TOKEN }}",
        ),
    },
    {
        "ruleId": "prompt-injection.workflow-generator",
        "anchor": "workflow-generator-context",
        "title": "Repository text reaches a workflow-generating model prompt",
        "severity": "LOW",
        "difficulty": "HIGH",
        "confidence": "low",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/services/workflow-generator.server.ts",
        "line": 95,
        "symbol": "generateWorkflow",
        "cwe_id": None,
        "description": (
            "The workflow assistant includes repository text in a model prompt "
            "and can propose executable workflow steps."
        ),
        "evidence": [
            "app/services/workflow-generator.server.ts:91 collects README and issue text from the repository.",
            "app/services/workflow-generator.server.ts:95 interpolates that text between instruction markers, which are prose rather than a boundary the model must honor.",
            "app/services/workflow-generator.server.ts:99 asks the model for a workflow object built from that prompt.",
        ],
        "impact": (
            "Repository text can shape a generated workflow draft, and an "
            "approved draft runs the steps it contains."
        ),
        "exploit_scenarios": [
            "Repository text tells the model to ignore the user request and add "
            "a step that uploads environment data.",
            "A reviewer overlooks the added step and approves the generated "
            "workflow.",
        ],
        "preconditions": [
            "Attacker-controlled text enters a repository document included in "
            "context.",
            "A user generates and approves a workflow without detecting the "
            "added step.",
        ],
        "recommendations": [
            "Treat repository content as untrusted data and label its origin in "
            "the prompt.",
            "Restrict generated steps to an allowlist and show a "
            "security-focused diff before approval.",
            "Run adversarial tests against production model settings, tools, and "
            "approval flows.",
        ],
        "snippet": "${context}",
        "code": code(
            "TypeScript",
            91,
            95,
            "const context = await collectRepositoryContext(repository);\n"
            "\n"
            "const prompt = `${SYSTEM_INSTRUCTIONS}\n"
            "<repository-context>\n"
            "${context}\n"
            "</repository-context>\n"
            "Request: ${userRequest}`;\n"
            "\n"
            "return model.generateObject({ prompt, schema: workflowSchema });",
        ),
    },
    {
        "ruleId": "error-message-disclosure.graphql-formatter",
        "anchor": "graphql-error-passthrough",
        "title": "Database details appear in client error responses",
        "severity": "LOW",
        "difficulty": "LOW",
        "confidence": "high",
        "reports": 1,
        "reporters": ["Web application"],
        "file": "app/graphql/error-format.ts",
        "line": 28,
        "symbol": "formatError",
        "cwe_id": "CWE-209",
        "description": (
            "The GraphQL error formatter returns the original database message "
            "for selected query failures."
        ),
        "evidence": [
            "app/graphql/error-format.ts:27 branches on the error being a database error.",
            "app/graphql/error-format.ts:28 returns the driver's own message to the client, which can name constraints and columns.",
            "app/graphql/error-format.ts:30 shows the generic response the other failure paths use.",
        ],
        "impact": (
            "Authenticated users can learn internal table and constraint names "
            "that are not part of the public API."
        ),
        "exploit_scenarios": [
            "A user submits conflicting object values to mutations and records "
            "the returned database constraints.",
            "The schema details guide later testing for authorization and "
            "injection weaknesses.",
        ],
        "preconditions": [
            "An authenticated account.",
            "Ability to submit a mutation that violates a constraint.",
        ],
        "recommendations": [
            "Map database failures to stable public error codes and generic "
            "messages.",
            "Keep original errors in access-controlled server logs with a "
            "request ID.",
            "Add response tests that reject table, column, and constraint names.",
        ],
        "snippet": 'return { message: cause.message, code: "INVALID_INPUT" };',
        "code": code(
            "TypeScript",
            24,
            28,
            "export function formatError(error: GraphQLError) {\n"
            "  const cause = error.originalError;\n"
            "\n"
            "  if (cause instanceof DatabaseError) {\n"
            '    return { message: cause.message, code: "INVALID_INPUT" };\n'
            "  }\n"
            '  return { message: "Request failed", code: "INTERNAL" };\n'
            "}",
        ),
    },
)
