import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import {
  Refused,
  validateMainProtectionEvidence,
  validateNativeGateEvidence,
} from "./release-controller-contract.mjs";

export const CONNECTIVITY_POLICY = Object.freeze({
  schema: "hfs.host-connectivity-only/v1",
  purpose: "HOST_CONNECTIVITY_ONLY",
  controllerRepository: "Ronmel71/hfs-approval-controller",
  controllerRef: "refs/heads/main",
  workflow: ".github/workflows/host-connectivity-only.yml",
  guard: "scripts/host-connectivity-only.mjs",
  executor: "scripts/host-connectivity-only.sh",
  reviewer: "Ronmel71",
  reviewerId: 321374159,
  environment: "production-host-deployment",
  environmentId: 27579657157,
  protectedJobName: "Native approval · HOST_CONNECTIVITY_ONLY",
  remoteHelperSha256: "1889dea8df10f9dfd11f51fe845703758577b0f1af4ac6960fd5f846db4b0351",
  maxLifetimeSeconds: 30 * 60,
});

const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const refuse = (code) => { throw new Refused(code); };
const required = (name) => process.env[name] || refuse("CONNECTIVITY_CONFIGURATION");

function exactKeys(value, expected, code) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) refuse(code);
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function requestBinding(request) {
  return createHash("sha256").update(stable({
    schema: request.schema,
    purpose: request.purpose,
    nonce: request.nonce,
    createdAtEpoch: request.createdAtEpoch,
    expiresAtEpoch: request.expiresAtEpoch,
    controller: request.controller,
    remoteHelperSha256: request.remoteHelperSha256,
  })).digest("hex");
}

export function finalizeConnectivityRequest(request) {
  const copy = structuredClone(request);
  copy.requestId = requestBinding(copy);
  return copy;
}

export function connectivityRunTitle(request) {
  return `Host connectivity only · ${request.requestId} · ${request.nonce}`;
}

export function validateConnectivityRequest(request, { nowEpoch = Math.floor(Date.now() / 1000), inventory = [] } = {}) {
  exactKeys(request, ["schema", "purpose", "requestId", "nonce", "createdAtEpoch", "expiresAtEpoch", "controller", "remoteHelperSha256", "run"], "CONNECTIVITY_FIELDS");
  if (request.schema !== CONNECTIVITY_POLICY.schema || request.purpose !== CONNECTIVITY_POLICY.purpose) refuse("CONNECTIVITY_PURPOSE");
  if (!SHA64.test(request.requestId) || !SHA64.test(request.nonce)) refuse("CONNECTIVITY_IDENTIFIER");
  if (request.remoteHelperSha256 !== CONNECTIVITY_POLICY.remoteHelperSha256) refuse("CONNECTIVITY_HELPER_PIN");
  exactKeys(request.controller, ["repository", "ref", "head", "workflow", "workflowBlob", "guard", "guardBlob", "executor", "executorBlob"], "CONNECTIVITY_CONTROLLER_FIELDS");
  if (request.controller.repository !== CONNECTIVITY_POLICY.controllerRepository ||
      request.controller.ref !== CONNECTIVITY_POLICY.controllerRef ||
      request.controller.workflow !== CONNECTIVITY_POLICY.workflow ||
      request.controller.guard !== CONNECTIVITY_POLICY.guard ||
      request.controller.executor !== CONNECTIVITY_POLICY.executor ||
      !SHA40.test(request.controller.head) || !SHA40.test(request.controller.workflowBlob) ||
      !SHA40.test(request.controller.guardBlob) || !SHA40.test(request.controller.executorBlob)) {
    refuse("CONNECTIVITY_CONTROLLER_PIN");
  }
  exactKeys(request.run, ["id", "attempt", "event", "repository", "ref", "head", "actor", "actorId", "triggeringActor", "triggeringActorId", "pullRequestCount"], "CONNECTIVITY_RUN_FIELDS");
  if (!RUN_ID.test(String(request.run.id)) || request.run.attempt !== 1 || request.run.event !== "workflow_dispatch" ||
      request.run.repository !== CONNECTIVITY_POLICY.controllerRepository || request.run.ref !== CONNECTIVITY_POLICY.controllerRef ||
      request.run.head !== request.controller.head || request.run.actor !== CONNECTIVITY_POLICY.reviewer ||
      request.run.actorId !== CONNECTIVITY_POLICY.reviewerId || request.run.triggeringActor !== CONNECTIVITY_POLICY.reviewer ||
      request.run.triggeringActorId !== CONNECTIVITY_POLICY.reviewerId || request.run.pullRequestCount !== 0) refuse("CONNECTIVITY_RUN");
  if (!Number.isSafeInteger(request.createdAtEpoch) || !Number.isSafeInteger(request.expiresAtEpoch) ||
      request.createdAtEpoch > nowEpoch || request.expiresAtEpoch <= nowEpoch ||
      request.expiresAtEpoch - request.createdAtEpoch > CONNECTIVITY_POLICY.maxLifetimeSeconds) refuse("CONNECTIVITY_FRESHNESS");
  if (request.requestId !== requestBinding(request)) refuse("CONNECTIVITY_REQUEST_ID");
  if (!Array.isArray(inventory)) refuse("CONNECTIVITY_INVENTORY");
  const matches = inventory.filter((entry) => isObject(entry) && entry.requestId === request.requestId &&
    entry.nonce === request.nonce && entry.purpose === request.purpose);
  if (matches.length !== 1 || String(matches[0].runId) !== String(request.run.id) || matches[0].attempt !== 1) refuse("CONNECTIVITY_REPLAY");
  return Object.freeze({ purpose: request.purpose, requestId: request.requestId });
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
    schema: CONNECTIVITY_POLICY.schema,
    purpose: required("HFS_CONNECTIVITY_PURPOSE"),
    requestId: "0".repeat(64),
    nonce: required("HFS_CONNECTIVITY_NONCE"),
    createdAtEpoch: Number(required("HFS_CONNECTIVITY_CREATED_AT_EPOCH")),
    expiresAtEpoch: Number(required("HFS_CONNECTIVITY_EXPIRES_AT_EPOCH")),
    controller: {
      repository: CONNECTIVITY_POLICY.controllerRepository,
      ref: CONNECTIVITY_POLICY.controllerRef,
      head: required("HFS_CONNECTIVITY_CONTROLLER_HEAD"),
      workflow: CONNECTIVITY_POLICY.workflow,
      workflowBlob: required("HFS_CONNECTIVITY_WORKFLOW_BLOB"),
      guard: CONNECTIVITY_POLICY.guard,
      guardBlob: required("HFS_CONNECTIVITY_GUARD_BLOB"),
      executor: CONNECTIVITY_POLICY.executor,
      executorBlob: required("HFS_CONNECTIVITY_EXECUTOR_BLOB"),
    },
    remoteHelperSha256: required("HFS_CONNECTIVITY_REMOTE_HELPER_SHA256"),
  };
}

function buildRequest(run) {
  return finalizeConnectivityRequest({ ...dispatchRequestFields(), run: runFields(run) });
}

async function githubResponse(path, { token = required("GH_TOKEN"), errorPrefix = "CONNECTIVITY_API" } = {}) {
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${CONNECTIVITY_POLICY.controllerRepository}${path}`, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "hfs-host-connectivity-only",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    refuse(`${errorPrefix}_NETWORK`);
  }
  if (response.status !== 200) {
    refuse([401, 403, 404, 429].includes(response.status) ? `${errorPrefix}_HTTP_${response.status}` : `${errorPrefix}_RESPONSE`);
  }
  return response;
}

async function getJson(path, options) {
  const errorPrefix = options?.errorPrefix ?? "CONNECTIVITY_API";
  const response = await githubResponse(path, options);
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) refuse(`${errorPrefix}_CONTENT_TYPE`);
  try {
    return await response.json();
  } catch {
    refuse(`${errorPrefix}_JSON`);
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
  return (await stablePagedInventory("/actions/runs?event=workflow_dispatch&branch=main", "workflow_runs", "CONNECTIVITY_INVENTORY")).records;
}

async function completeAttemptJobInventory(runId) {
  const result = await stablePagedInventory(`/actions/runs/${runId}/attempts/1/jobs`, "jobs", "CONNECTIVITY_JOB_INVENTORY");
  return { total_count: result.total_count, jobs: result.records };
}

function assertProviderRun(run) {
  if (!isObject(run) || run.repository?.full_name !== CONNECTIVITY_POLICY.controllerRepository || run.repository?.private !== false ||
      run.repository?.fork !== false || run.head_repository?.full_name !== CONNECTIVITY_POLICY.controllerRepository ||
      run.head_repository?.fork !== false || run.path?.split("@")[0] !== CONNECTIVITY_POLICY.workflow ||
      run.head_branch !== "main" || run.event !== "workflow_dispatch" || run.run_attempt !== 1 ||
      run.actor?.login !== CONNECTIVITY_POLICY.reviewer || run.actor?.id !== CONNECTIVITY_POLICY.reviewerId ||
      run.triggering_actor?.login !== CONNECTIVITY_POLICY.reviewer || run.triggering_actor?.id !== CONNECTIVITY_POLICY.reviewerId ||
      !Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) refuse("CONNECTIVITY_RUN_PROVENANCE");
}

async function currentRequest() {
  const runId = required("GITHUB_RUN_ID");
  const [run, runs] = await Promise.all([getJson(`/actions/runs/${runId}`), completeRunInventory()]);
  assertProviderRun(run);
  const request = buildRequest(run);
  if (request.requestId !== required("HFS_CONNECTIVITY_REQUEST_ID") || run.display_title !== connectivityRunTitle(request)) refuse("CONNECTIVITY_REQUEST_ID");
  const inventory = runs.filter((candidate) => candidate.display_title === connectivityRunTitle(request)).map((candidate) => ({
    requestId: request.requestId,
    nonce: request.nonce,
    purpose: request.purpose,
    runId: String(candidate.id),
    attempt: candidate.run_attempt,
  }));
  validateConnectivityRequest(request, { inventory });
  return { request, run };
}

function validateSource(source, request) {
  for (const [name, path, sha] of [
    ["workflow", CONNECTIVITY_POLICY.workflow, request.controller.workflowBlob],
    ["guard", CONNECTIVITY_POLICY.guard, request.controller.guardBlob],
    ["executor", CONNECTIVITY_POLICY.executor, request.controller.executorBlob],
  ]) {
    if (source[name]?.type !== "file" || source[name]?.path !== path || source[name]?.sha !== sha) refuse("CONNECTIVITY_SOURCE");
  }
}

export function validateConnectivityGateEvidence(request, { branchProtection, ...evidence } = {}) {
  const native = validateNativeGateEvidence(request, {
    ...evidence,
    expectedEnvironmentId: CONNECTIVITY_POLICY.environmentId,
    expectedEnvironmentName: CONNECTIVITY_POLICY.environment,
    expectedProtectedJobName: CONNECTIVITY_POLICY.protectedJobName,
    controllerRepository: CONNECTIVITY_POLICY.controllerRepository,
    reviewer: CONNECTIVITY_POLICY.reviewer,
    reviewerId: CONNECTIVITY_POLICY.reviewerId,
  });
  return Object.freeze({ ...native, ...validateMainProtectionEvidence(branchProtection) });
}

async function verifyNativeGate(request, run) {
  const protectionToken = process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN || refuse("CONNECTIVITY_ADMIN_READ_TOKEN_UNCONFIGURED");
  const [approvals, jobInventory, environment, workflow, guard, executor, protection] = await Promise.all([
    getJson(`/actions/runs/${run.id}/approvals`),
    completeAttemptJobInventory(run.id),
    getJson(`/environments/${encodeURIComponent(CONNECTIVITY_POLICY.environment)}`),
    getJson(`/contents/${CONNECTIVITY_POLICY.workflow}?ref=${request.controller.head}`),
    getJson(`/contents/${CONNECTIVITY_POLICY.guard}?ref=${request.controller.head}`),
    getJson(`/contents/${CONNECTIVITY_POLICY.executor}?ref=${request.controller.head}`),
    getJson("/branches/main/protection", { token: protectionToken, errorPrefix: "CONNECTIVITY_PROTECTION" }),
  ]);
  validateSource({ workflow, guard, executor }, request);
  return validateConnectivityGateEvidence(request, { run, approvals, jobInventory, environment, branchProtection: protection });
}

function summary(line) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`, "utf8");
}

export async function cli(argv) {
  try {
    if (argv.length !== 3 || !["request-id", "validate-request", "verify-native-gate"].includes(argv[2])) refuse("CONNECTIVITY_USAGE");
    if (argv[2] === "request-id") {
      process.stdout.write(`${finalizeConnectivityRequest({ ...dispatchRequestFields(), run: {} }).requestId}\n`);
      return 0;
    }
    const { request, run } = await currentRequest();
    if (argv[2] === "validate-request") {
      process.stdout.write(`HOST_CONNECTIVITY_REQUEST_VALID request_id=${request.requestId}\n`);
      return 0;
    }
    const result = await verifyNativeGate(request, run);
    const line = `HOST_CONNECTIVITY_GATE_PASS environment=${result.environment} environment_id=${result.environmentId} reviewer_id=${result.reviewerId} run_id=${run.id} head=${request.controller.head} attempt=1 connectivity_only=true deploy_authorization=false`;
    process.stdout.write(`${line}\n`);
    summary(`- ${line}`);
    summary("- This gate authorizes only the bounded read-only connectivity check in this run. It is not deploy, publication, install, rollback, or release authorization.");
    return 0;
  } catch (error) {
    process.stderr.write(`HOST_CONNECTIVITY_GATE_REFUSED code=${error instanceof Refused ? error.code : "CONNECTIVITY_INTERNAL"}\n`);
    return 78;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await cli(process.argv);
