import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { Refused, validateNativeGateEvidence } from "./release-controller-contract.mjs";

export const PROBE_POLICY = Object.freeze({
  schema: "hfs.native-capability-probe/v1",
  purpose: "NATIVE_CAPABILITY_PROBE",
  controllerRepository: "Ronmel71/hfs-approval-controller",
  controllerRef: "refs/heads/main",
  workflow: ".github/workflows/native-capability-probe.yml",
  probeScript: "scripts/native-capability-probe.mjs",
  reviewer: "Ronmel71",
  reviewerId: 321374159,
  maxLifetimeSeconds: 30 * 60,
  targets: Object.freeze({
    image: Object.freeze({
      environment: "production-image-publication",
      environmentId: 27579543667,
      protectedJobName: "Native capability probe · image",
    }),
    deploy: Object.freeze({
      environment: "production-host-deployment",
      environmentId: 27579657157,
      protectedJobName: "Native capability probe · deploy",
    }),
  }),
});

const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const refuse = (code) => { throw new Refused(code); };
const required = (name) => process.env[name] || refuse("PROBE_CONFIGURATION");

function exactKeys(value, expected, code) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) refuse(code);
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function probeBinding(request) {
  return createHash("sha256").update(stable({
    schema: request.schema,
    purpose: request.purpose,
    target: request.target,
    nonce: request.nonce,
    createdAtEpoch: request.createdAtEpoch,
    expiresAtEpoch: request.expiresAtEpoch,
    controller: request.controller,
  })).digest("hex");
}

export function finalizeProbeRequest(request) {
  const copy = structuredClone(request);
  copy.requestId = probeBinding(copy);
  return copy;
}

export function probeRunTitle(request) {
  return `Native capability probe · ${request.target} · ${request.requestId} · ${request.nonce}`;
}

export function validateProbeRequest(request, { nowEpoch = Math.floor(Date.now() / 1000), inventory = [] } = {}) {
  exactKeys(request, ["schema", "purpose", "target", "requestId", "nonce", "createdAtEpoch", "expiresAtEpoch", "controller", "run"], "PROBE_FIELDS");
  const targetPolicy = PROBE_POLICY.targets[request.target];
  if (!targetPolicy || request.schema !== PROBE_POLICY.schema || request.purpose !== PROBE_POLICY.purpose) refuse("PROBE_PURPOSE");
  if (!SHA64.test(request.requestId) || !SHA64.test(request.nonce)) refuse("PROBE_IDENTIFIER");
  exactKeys(request.controller, ["repository", "ref", "head", "workflow", "workflowBlob", "probeScript", "probeScriptBlob"], "PROBE_CONTROLLER_FIELDS");
  if (request.controller.repository !== PROBE_POLICY.controllerRepository || request.controller.ref !== PROBE_POLICY.controllerRef ||
      request.controller.workflow !== PROBE_POLICY.workflow || request.controller.probeScript !== PROBE_POLICY.probeScript ||
      !SHA40.test(request.controller.head) || !SHA40.test(request.controller.workflowBlob) || !SHA40.test(request.controller.probeScriptBlob)) {
    refuse("PROBE_CONTROLLER_PIN");
  }
  exactKeys(request.run, ["id", "attempt", "event", "repository", "ref", "head", "actor", "actorId", "triggeringActor", "triggeringActorId", "pullRequestCount"], "PROBE_RUN_FIELDS");
  if (!RUN_ID.test(String(request.run.id)) || request.run.attempt !== 1 || request.run.event !== "workflow_dispatch" ||
      request.run.repository !== PROBE_POLICY.controllerRepository || request.run.ref !== PROBE_POLICY.controllerRef ||
      request.run.head !== request.controller.head || request.run.actor !== PROBE_POLICY.reviewer ||
      request.run.actorId !== PROBE_POLICY.reviewerId || request.run.triggeringActor !== PROBE_POLICY.reviewer ||
      request.run.triggeringActorId !== PROBE_POLICY.reviewerId || request.run.pullRequestCount !== 0) refuse("PROBE_RUN");
  if (!Number.isSafeInteger(request.createdAtEpoch) || !Number.isSafeInteger(request.expiresAtEpoch) ||
      request.createdAtEpoch > nowEpoch || request.expiresAtEpoch <= nowEpoch ||
      request.expiresAtEpoch - request.createdAtEpoch > PROBE_POLICY.maxLifetimeSeconds) refuse("PROBE_FRESHNESS");
  if (request.requestId !== probeBinding(request)) refuse("PROBE_REQUEST_ID");
  if (!Array.isArray(inventory)) refuse("PROBE_INVENTORY");
  const matches = inventory.filter((entry) => isObject(entry) && entry.requestId === request.requestId &&
    entry.nonce === request.nonce && entry.target === request.target);
  if (matches.length !== 1 || String(matches[0].runId) !== String(request.run.id) || matches[0].attempt !== 1) refuse("PROBE_REPLAY");
  return Object.freeze({ target: request.target, requestId: request.requestId, environment: targetPolicy.environment });
}

function runFields(run) {
  return {
    id: String(run.id),
    attempt: run.run_attempt,
    event: run.event,
    repository: run.repository?.full_name,
    ref: `refs/heads/${run.head_branch}`,
    head: run.head_sha,
    actor: run.actor?.login,
    actorId: run.actor?.id,
    triggeringActor: run.triggering_actor?.login,
    triggeringActorId: run.triggering_actor?.id,
    pullRequestCount: run.pull_requests?.length,
  };
}

function dispatchRequestFields() {
  return {
    schema: PROBE_POLICY.schema,
    purpose: PROBE_POLICY.purpose,
    target: required("HFS_PROBE_TARGET"),
    requestId: "0".repeat(64),
    nonce: required("HFS_PROBE_NONCE"),
    createdAtEpoch: Number(required("HFS_PROBE_CREATED_AT_EPOCH")),
    expiresAtEpoch: Number(required("HFS_PROBE_EXPIRES_AT_EPOCH")),
    controller: {
      repository: PROBE_POLICY.controllerRepository,
      ref: PROBE_POLICY.controllerRef,
      head: required("HFS_PROBE_CONTROLLER_HEAD"),
      workflow: PROBE_POLICY.workflow,
      workflowBlob: required("HFS_PROBE_WORKFLOW_BLOB"),
      probeScript: PROBE_POLICY.probeScript,
      probeScriptBlob: required("HFS_PROBE_SCRIPT_BLOB"),
    },
  };
}

function buildRequest(run) {
  return finalizeProbeRequest({
    ...dispatchRequestFields(),
    run: runFields(run),
  });
}

async function githubResponse(path) {
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${PROBE_POLICY.controllerRepository}${path}`, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${required("GH_TOKEN")}`,
        "User-Agent": "hfs-native-capability-probe",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    refuse("PROBE_API_NETWORK");
  }
  return response;
}

async function getJson(path, code = "PROBE_API") {
  const response = await githubResponse(path);
  if (response.status !== 200) refuse([401, 403, 404, 429].includes(response.status) ? `${code}_HTTP_${response.status}` : `${code}_RESPONSE`);
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) refuse(`${code}_CONTENT_TYPE`);
  try {
    return await response.json();
  } catch {
    refuse(`${code}_JSON`);
  }
}

async function stablePagedInventory(path, key, code) {
  const records = [];
  const ids = new Set();
  let total;
  let firstPageIds;
  for (let page = 1; page <= 10; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const result = await getJson(`${path}${separator}per_page=100&page=${page}`);
    if (!Number.isSafeInteger(result.total_count) || !Array.isArray(result[key])) refuse(code);
    if (total === undefined) total = result.total_count;
    if (result.total_count !== total) refuse(`${code}_DRIFT`);
    if (page === 1) firstPageIds = result[key].map((record) => record.id);
    for (const record of result[key]) {
      if (!Number.isSafeInteger(record.id) || ids.has(record.id)) refuse(code);
      ids.add(record.id);
      records.push(record);
    }
    if (result[key].length < 100) {
      if (ids.size !== total) refuse(`${code}_INCOMPLETE`);
      const confirm = await getJson(`${path}${separator}per_page=100&page=1`);
      if (confirm.total_count !== total || !Array.isArray(confirm[key]) ||
          JSON.stringify(confirm[key].map((record) => record.id)) !== JSON.stringify(firstPageIds)) refuse(`${code}_DRIFT`);
      return { total_count: total, records };
    }
  }
  refuse(`${code}_INCOMPLETE`);
}

async function completeRunInventory() {
  return (await stablePagedInventory("/actions/runs?event=workflow_dispatch&branch=main", "workflow_runs", "PROBE_INVENTORY")).records;
}

async function completeAttemptJobInventory(runId) {
  const result = await stablePagedInventory(`/actions/runs/${runId}/attempts/1/jobs`, "jobs", "PROBE_JOB_INVENTORY");
  return { total_count: result.total_count, jobs: result.records };
}

function assertProviderRun(run) {
  if (!isObject(run) || run.repository?.full_name !== PROBE_POLICY.controllerRepository || run.repository?.private !== false ||
      run.repository?.fork !== false || run.head_repository?.full_name !== PROBE_POLICY.controllerRepository ||
      run.head_repository?.fork !== false || run.path?.split("@")[0] !== PROBE_POLICY.workflow ||
      run.head_branch !== "main" || run.event !== "workflow_dispatch" || run.run_attempt !== 1 ||
      !Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) refuse("PROBE_RUN_PROVENANCE");
}

async function currentRequest() {
  const runId = required("GITHUB_RUN_ID");
  const [run, runs] = await Promise.all([
    getJson(`/actions/runs/${runId}`),
    completeRunInventory(),
  ]);
  assertProviderRun(run);
  const request = buildRequest(run);
  if (request.requestId !== required("HFS_PROBE_REQUEST_ID") || run.display_title !== probeRunTitle(request)) refuse("PROBE_REQUEST_ID");
  const inventory = runs.filter((candidate) => candidate.display_title === probeRunTitle(request)).map((candidate) => ({
    requestId: request.requestId,
    nonce: request.nonce,
    target: request.target,
    runId: String(candidate.id),
    attempt: candidate.run_attempt,
  }));
  validateProbeRequest(request, { inventory });
  return { request, run };
}

function validateSource(source, request) {
  const workflow = source.workflow;
  const script = source.script;
  if (workflow?.type !== "file" || workflow?.path !== PROBE_POLICY.workflow || workflow?.sha !== request.controller.workflowBlob ||
      script?.type !== "file" || script?.path !== PROBE_POLICY.probeScript || script?.sha !== request.controller.probeScriptBlob) {
    refuse("PROBE_SOURCE");
  }
}

export async function classifyAdminReadResponse(response) {
  if (response.status === 403) return "ADMIN_READ_BLOCKED";
  if (response.status !== 200) return `ADMIN_READ_BLOCKED_HTTP_${response.status}`;
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) return "ADMIN_READ_BLOCKED_CONTENT_TYPE";
  let protection;
  try {
    protection = await response.json();
  } catch {
    return "ADMIN_READ_BLOCKED_JSON";
  }
  if (protection?.enforce_admins?.enabled !== true || protection?.allow_force_pushes?.enabled !== false ||
      protection?.allow_deletions?.enabled !== false) return "ADMIN_READ_POLICY_MISMATCH";
  return "ADMIN_READ_PASS";
}

async function adminReadCapability() {
  return classifyAdminReadResponse(await githubResponse("/branches/main/protection"));
}

async function verifyNativeProbe(request, run) {
  const targetPolicy = PROBE_POLICY.targets[request.target] || refuse("PROBE_PURPOSE");
  const [approvals, jobInventory, environment, workflow, script, adminRead] = await Promise.all([
    getJson(`/actions/runs/${run.id}/approvals`),
    completeAttemptJobInventory(run.id),
    getJson(`/environments/${encodeURIComponent(targetPolicy.environment)}`),
    getJson(`/contents/${PROBE_POLICY.workflow}?ref=${request.controller.head}`),
    getJson(`/contents/${PROBE_POLICY.probeScript}?ref=${request.controller.head}`),
    adminReadCapability(),
  ]);
  validateSource({ workflow, script }, request);
  const evidence = validateNativeGateEvidence(request, {
    run,
    approvals,
    jobInventory,
    environment,
    expectedEnvironmentId: targetPolicy.environmentId,
    expectedEnvironmentName: targetPolicy.environment,
    expectedProtectedJobName: targetPolicy.protectedJobName,
  });
  return { ...evidence, adminRead };
}

function summary(line) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`, "utf8");
}

async function cli(argv) {
  try {
    if (argv.length !== 3 || !["request-id", "validate-request", "verify-native-probe"].includes(argv[2])) refuse("PROBE_USAGE");
    if (argv[2] === "request-id") {
      const request = finalizeProbeRequest({ ...dispatchRequestFields(), run: {} });
      process.stdout.write(`${request.requestId}\n`);
      return 0;
    }
    const { request, run } = await currentRequest();
    if (argv[2] === "validate-request") {
      process.stdout.write(`NATIVE_PROBE_REQUEST_VALID target=${request.target} request_id=${request.requestId}\n`);
      return 0;
    }
    const result = await verifyNativeProbe(request, run);
    const line = `NATIVE_PROBE_PASS target=${request.target} environment=${result.environment} environment_id=${result.environmentId} reviewer_id=${result.reviewerId} run_id=${run.id} head=${request.controller.head} attempt=1 approval_not_before=${result.approvalNotBeforeEpoch} approval_not_after=${result.approvalNotAfterEpoch} admin_read=${result.adminRead} release_ready=false authorization=false`;
    process.stdout.write(`${line}\n`);
    summary(`- ${line}`);
    summary("- This is native capability evidence only. It is not release approval, RELEASE_READY, publication authorization, deploy authorization, or a consumable release marker.");
    return 0;
  } catch (error) {
    process.stderr.write(`NATIVE_PROBE_REFUSED code=${error instanceof Refused ? error.code : "PROBE_INTERNAL"}\n`);
    return 78;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await cli(process.argv);
