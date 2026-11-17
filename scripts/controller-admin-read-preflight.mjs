import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import {
  Refused,
  validateMainProtectionEvidence,
  validateNativeGateEvidence,
} from "./release-controller-contract.mjs";

export const ADMIN_READ_POLICY = Object.freeze({
  schema: "hfs.controller-admin-read-preflight/v1",
  purpose: "CONTROLLER_ADMIN_READ_PREFLIGHT",
  controllerRepository: "Ronmel71/hfs-approval-controller",
  controllerRef: "refs/heads/main",
  workflow: ".github/workflows/controller-admin-read-preflight.yml",
  script: "scripts/controller-admin-read-preflight.mjs",
  reviewer: "Ronmel71",
  reviewerId: 321374159,
  maxLifetimeSeconds: 30 * 60,
  targets: Object.freeze({
    image: Object.freeze({
      environment: "production-image-publication",
      environmentId: 27579543667,
      protectedJobName: "Administration-read preflight · image",
    }),
    deploy: Object.freeze({
      environment: "production-host-deployment",
      environmentId: 27579657157,
      protectedJobName: "Administration-read preflight · deploy",
    }),
  }),
});

const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const refuse = (code) => { throw new Refused(code); };
const required = (name) => process.env[name] || refuse("ADMIN_READ_CONFIGURATION");

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
    target: request.target,
    nonce: request.nonce,
    createdAtEpoch: request.createdAtEpoch,
    expiresAtEpoch: request.expiresAtEpoch,
    controller: request.controller,
  })).digest("hex");
}

export function finalizeAdminReadRequest(request) {
  const copy = structuredClone(request);
  copy.requestId = requestBinding(copy);
  return copy;
}

export function adminReadRunTitle(request) {
  return `Administration-read preflight · ${request.target} · ${request.requestId} · ${request.nonce}`;
}

export function validateAdminReadRequest(request, { nowEpoch = Math.floor(Date.now() / 1000), inventory = [] } = {}) {
  exactKeys(request, ["schema", "purpose", "target", "requestId", "nonce", "createdAtEpoch", "expiresAtEpoch", "controller", "run"], "ADMIN_READ_FIELDS");
  const targetPolicy = ADMIN_READ_POLICY.targets[request.target];
  if (!targetPolicy || request.schema !== ADMIN_READ_POLICY.schema || request.purpose !== ADMIN_READ_POLICY.purpose) refuse("ADMIN_READ_PURPOSE");
  if (!SHA64.test(request.requestId) || !SHA64.test(request.nonce)) refuse("ADMIN_READ_IDENTIFIER");
  exactKeys(request.controller, ["repository", "ref", "head", "workflow", "workflowBlob", "script", "scriptBlob"], "ADMIN_READ_CONTROLLER_FIELDS");
  if (request.controller.repository !== ADMIN_READ_POLICY.controllerRepository || request.controller.ref !== ADMIN_READ_POLICY.controllerRef ||
      request.controller.workflow !== ADMIN_READ_POLICY.workflow || request.controller.script !== ADMIN_READ_POLICY.script ||
      !SHA40.test(request.controller.head) || !SHA40.test(request.controller.workflowBlob) || !SHA40.test(request.controller.scriptBlob)) {
    refuse("ADMIN_READ_CONTROLLER_PIN");
  }
  exactKeys(request.run, ["id", "attempt", "event", "repository", "ref", "head", "actor", "actorId", "triggeringActor", "triggeringActorId", "pullRequestCount"], "ADMIN_READ_RUN_FIELDS");
  if (!RUN_ID.test(String(request.run.id)) || request.run.attempt !== 1 || request.run.event !== "workflow_dispatch" ||
      request.run.repository !== ADMIN_READ_POLICY.controllerRepository || request.run.ref !== ADMIN_READ_POLICY.controllerRef ||
      request.run.head !== request.controller.head || request.run.actor !== ADMIN_READ_POLICY.reviewer ||
      request.run.actorId !== ADMIN_READ_POLICY.reviewerId || request.run.triggeringActor !== ADMIN_READ_POLICY.reviewer ||
      request.run.triggeringActorId !== ADMIN_READ_POLICY.reviewerId || request.run.pullRequestCount !== 0) refuse("ADMIN_READ_RUN");
  if (!Number.isSafeInteger(request.createdAtEpoch) || !Number.isSafeInteger(request.expiresAtEpoch) ||
      request.createdAtEpoch > nowEpoch || request.expiresAtEpoch <= nowEpoch ||
      request.expiresAtEpoch - request.createdAtEpoch > ADMIN_READ_POLICY.maxLifetimeSeconds) refuse("ADMIN_READ_FRESHNESS");
  if (request.requestId !== requestBinding(request)) refuse("ADMIN_READ_REQUEST_ID");
  if (!Array.isArray(inventory)) refuse("ADMIN_READ_INVENTORY");
  const matches = inventory.filter((entry) => isObject(entry) && entry.requestId === request.requestId &&
    entry.nonce === request.nonce && entry.target === request.target);
  if (matches.length !== 1 || String(matches[0].runId) !== String(request.run.id) || matches[0].attempt !== 1) refuse("ADMIN_READ_REPLAY");
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
    schema: ADMIN_READ_POLICY.schema,
    purpose: ADMIN_READ_POLICY.purpose,
    target: required("HFS_ADMIN_READ_TARGET"),
    requestId: "0".repeat(64),
    nonce: required("HFS_ADMIN_READ_NONCE"),
    createdAtEpoch: Number(required("HFS_ADMIN_READ_CREATED_AT_EPOCH")),
    expiresAtEpoch: Number(required("HFS_ADMIN_READ_EXPIRES_AT_EPOCH")),
    controller: {
      repository: ADMIN_READ_POLICY.controllerRepository,
      ref: ADMIN_READ_POLICY.controllerRef,
      head: required("HFS_ADMIN_READ_CONTROLLER_HEAD"),
      workflow: ADMIN_READ_POLICY.workflow,
      workflowBlob: required("HFS_ADMIN_READ_WORKFLOW_BLOB"),
      script: ADMIN_READ_POLICY.script,
      scriptBlob: required("HFS_ADMIN_READ_SCRIPT_BLOB"),
    },
  };
}

function buildRequest(run) {
  return finalizeAdminReadRequest({ ...dispatchRequestFields(), run: runFields(run) });
}

async function githubResponse(path, { token = required("GH_TOKEN"), errorPrefix = "ADMIN_READ_API" } = {}) {
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${ADMIN_READ_POLICY.controllerRepository}${path}`, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "hfs-controller-admin-read-preflight",
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
  const errorPrefix = options?.errorPrefix ?? "ADMIN_READ_API";
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
  return (await stablePagedInventory("/actions/runs?event=workflow_dispatch&branch=main", "workflow_runs", "ADMIN_READ_INVENTORY")).records;
}

async function completeAttemptJobInventory(runId) {
  const result = await stablePagedInventory(`/actions/runs/${runId}/attempts/1/jobs`, "jobs", "ADMIN_READ_JOB_INVENTORY");
  return { total_count: result.total_count, jobs: result.records };
}

function assertProviderRun(run) {
  if (!isObject(run) || run.repository?.full_name !== ADMIN_READ_POLICY.controllerRepository || run.repository?.private !== false ||
      run.repository?.fork !== false || run.head_repository?.full_name !== ADMIN_READ_POLICY.controllerRepository ||
      run.head_repository?.fork !== false || run.path?.split("@")[0] !== ADMIN_READ_POLICY.workflow ||
      run.head_branch !== "main" || run.event !== "workflow_dispatch" || run.run_attempt !== 1 ||
      !Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) refuse("ADMIN_READ_RUN_PROVENANCE");
}

async function currentRequest() {
  const runId = required("GITHUB_RUN_ID");
  const [run, runs] = await Promise.all([getJson(`/actions/runs/${runId}`), completeRunInventory()]);
  assertProviderRun(run);
  const request = buildRequest(run);
  if (request.requestId !== required("HFS_ADMIN_READ_REQUEST_ID") || run.display_title !== adminReadRunTitle(request)) refuse("ADMIN_READ_REQUEST_ID");
  const inventory = runs.filter((candidate) => candidate.display_title === adminReadRunTitle(request)).map((candidate) => ({
    requestId: request.requestId,
    nonce: request.nonce,
    target: request.target,
    runId: String(candidate.id),
    attempt: candidate.run_attempt,
  }));
  validateAdminReadRequest(request, { inventory });
  return { request, run };
}

function validateSource(source, request) {
  if (source.workflow?.type !== "file" || source.workflow?.path !== ADMIN_READ_POLICY.workflow ||
      source.workflow?.sha !== request.controller.workflowBlob || source.script?.type !== "file" ||
      source.script?.path !== ADMIN_READ_POLICY.script || source.script?.sha !== request.controller.scriptBlob) {
    refuse("ADMIN_READ_SOURCE");
  }
}

export async function readMainProtection() {
  const token = process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN || refuse("ADMIN_READ_TOKEN_UNCONFIGURED");
  return getJson("/branches/main/protection", { token, errorPrefix: "ADMIN_READ_PROTECTION" });
}

export function validateAdminReadEvidence(request, { branchProtection, ...evidence } = {}) {
  const target = ADMIN_READ_POLICY.targets[request.target] || refuse("ADMIN_READ_PURPOSE");
  const native = validateNativeGateEvidence(request, {
    ...evidence,
    expectedEnvironmentId: target.environmentId,
    expectedEnvironmentName: target.environment,
    expectedProtectedJobName: target.protectedJobName,
  });
  return Object.freeze({ ...native, ...validateMainProtectionEvidence(branchProtection) });
}

async function verifyAdminRead(request, run) {
  const target = ADMIN_READ_POLICY.targets[request.target] || refuse("ADMIN_READ_PURPOSE");
  const [approvals, jobInventory, environment, workflow, script, protection] = await Promise.all([
    getJson(`/actions/runs/${run.id}/approvals`),
    completeAttemptJobInventory(run.id),
    getJson(`/environments/${encodeURIComponent(target.environment)}`),
    getJson(`/contents/${ADMIN_READ_POLICY.workflow}?ref=${request.controller.head}`),
    getJson(`/contents/${ADMIN_READ_POLICY.script}?ref=${request.controller.head}`),
    readMainProtection(),
  ]);
  validateSource({ workflow, script }, request);
  return validateAdminReadEvidence(request, {
    run,
    approvals,
    jobInventory,
    environment,
    branchProtection: protection,
  });
}

function summary(line) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`, "utf8");
}

export async function cli(argv) {
  try {
    if (argv.length !== 3 || !["request-id", "validate-request", "verify-admin-read"].includes(argv[2])) refuse("ADMIN_READ_USAGE");
    if (argv[2] === "request-id") {
      process.stdout.write(`${finalizeAdminReadRequest({ ...dispatchRequestFields(), run: {} }).requestId}\n`);
      return 0;
    }
    const { request, run } = await currentRequest();
    if (argv[2] === "validate-request") {
      process.stdout.write(`ADMIN_READ_REQUEST_VALID target=${request.target} request_id=${request.requestId}\n`);
      return 0;
    }
    const result = await verifyAdminRead(request, run);
    const line = `ADMIN_READ_PREFLIGHT_PASS target=${request.target} environment=${result.environment} environment_id=${result.environmentId} reviewer_id=${result.reviewerId} run_id=${run.id} head=${request.controller.head} attempt=1 enforce_admins=true allow_force_pushes=false allow_deletions=false credential_read=true release_ready=false authorization=false`;
    process.stdout.write(`${line}\n`);
    summary(`- ${line}`);
    summary("- This proves only the reviewed credential read. It is not release approval, publication authorization, deploy authorization, or a consumable release marker.");
    return 0;
  } catch (error) {
    process.stderr.write(`ADMIN_READ_PREFLIGHT_REFUSED code=${error instanceof Refused ? error.code : "ADMIN_READ_INTERNAL"}\n`);
    return 78;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await cli(process.argv);
