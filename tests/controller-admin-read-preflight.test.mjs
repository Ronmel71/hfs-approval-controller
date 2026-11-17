import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it } from "node:test";
import { validateRequest } from "../scripts/release-controller-contract.mjs";
import { validateProbeRequest } from "../scripts/native-capability-probe.mjs";
import {
  ADMIN_READ_POLICY,
  adminReadRunTitle,
  cli,
  finalizeAdminReadRequest,
  readMainProtection,
  validateAdminReadEvidence,
  validateAdminReadRequest,
} from "../scripts/controller-admin-read-preflight.mjs";

const now = 2_000_000_000;
const sha = (character, length = 64) => character.repeat(length);
const workflow = readFileSync(new URL("../.github/workflows/controller-admin-read-preflight.yml", import.meta.url), "utf8");
const script = readFileSync(new URL("../scripts/controller-admin-read-preflight.mjs", import.meta.url), "utf8");
const harmlessWorkflow = readFileSync(new URL("../.github/workflows/native-capability-probe.yml", import.meta.url));
const deployWorkflow = readFileSync(new URL("../.github/workflows/release-deploy-only.yml", import.meta.url));
const stageWorkflow = readFileSync(new URL("../.github/workflows/stage-only-review.yml", import.meta.url));
const gitBlob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
const originalFetch = globalThis.fetch;
const originalStdoutWrite = process.stdout.write;
const originalStderrWrite = process.stderr.write;

function fixture(target = "image") {
  return finalizeAdminReadRequest({
    schema: ADMIN_READ_POLICY.schema,
    purpose: ADMIN_READ_POLICY.purpose,
    target,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 120,
    expiresAtEpoch: now + 600,
    controller: {
      repository: ADMIN_READ_POLICY.controllerRepository,
      ref: ADMIN_READ_POLICY.controllerRef,
      head: sha("b", 40),
      workflow: ADMIN_READ_POLICY.workflow,
      workflowBlob: sha("c", 40),
      script: ADMIN_READ_POLICY.script,
      scriptBlob: sha("d", 40),
    },
    run: {
      id: target === "image" ? "888000111" : "888000222",
      attempt: 1,
      event: "workflow_dispatch",
      repository: ADMIN_READ_POLICY.controllerRepository,
      ref: ADMIN_READ_POLICY.controllerRef,
      head: sha("b", 40),
      actor: ADMIN_READ_POLICY.reviewer,
      actorId: ADMIN_READ_POLICY.reviewerId,
      triggeringActor: ADMIN_READ_POLICY.reviewer,
      triggeringActorId: ADMIN_READ_POLICY.reviewerId,
      pullRequestCount: 0,
    },
  });
}

function options(request) {
  return {
    nowEpoch: now,
    inventory: [{
      requestId: request.requestId,
      nonce: request.nonce,
      target: request.target,
      runId: request.run.id,
      attempt: 1,
    }],
  };
}

function evidence(request) {
  const target = ADMIN_READ_POLICY.targets[request.target];
  const runUrl = `https://api.github.com/repos/${ADMIN_READ_POLICY.controllerRepository}/actions/runs/${request.run.id}`;
  return {
    nowEpoch: now,
    run: {
      id: Number(request.run.id),
      run_attempt: 1,
      event: "workflow_dispatch",
      head_branch: "main",
      head_sha: request.controller.head,
      repository: { full_name: ADMIN_READ_POLICY.controllerRepository },
      status: "in_progress",
      conclusion: null,
      created_at: new Date((now - 100) * 1000).toISOString(),
    },
    approvals: [{
      state: "approved",
      user: { login: ADMIN_READ_POLICY.reviewer, id: ADMIN_READ_POLICY.reviewerId },
      environments: [{ name: target.environment, id: target.environmentId }],
    }],
    jobInventory: {
      total_count: 2,
      jobs: [
        {
          id: 900001,
          run_id: Number(request.run.id),
          run_attempt: 1,
          head_sha: request.controller.head,
          head_branch: "main",
          run_url: runUrl,
          name: "validate-request",
          status: "completed",
          conclusion: "success",
          created_at: new Date((now - 100) * 1000).toISOString(),
          started_at: new Date((now - 95) * 1000).toISOString(),
          completed_at: new Date((now - 90) * 1000).toISOString(),
        },
        {
          id: 900002,
          run_id: Number(request.run.id),
          run_attempt: 1,
          head_sha: request.controller.head,
          head_branch: "main",
          run_url: runUrl,
          name: target.protectedJobName,
          status: "in_progress",
          conclusion: null,
          created_at: new Date((now - 89) * 1000).toISOString(),
          started_at: new Date((now - 60) * 1000).toISOString(),
          completed_at: null,
        },
      ],
    },
    environment: {
      id: target.environmentId,
      name: target.environment,
      can_admins_bypass: false,
      protection_rules: [
        {
          type: "required_reviewers",
          prevent_self_review: false,
          reviewers: [{ type: "User", reviewer: { login: ADMIN_READ_POLICY.reviewer, id: ADMIN_READ_POLICY.reviewerId } }],
        },
        { type: "branch_policy" },
      ],
      deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
    },
    branchProtection: {
      enforce_admins: { enabled: true },
      allow_force_pushes: { enabled: false },
      allow_deletions: { enabled: false },
    },
  };
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

async function runVerifyAdminReadCli({
  protection = evidence(fixture()).branchProtection,
  protectionStatus = 200,
  omitToken = false,
  mutateEvidence = () => {},
  mutateSource = () => {},
} = {}) {
  const nowEpoch = Math.floor(Date.now() / 1000);
  const request = finalizeAdminReadRequest({
    ...fixture(),
    createdAtEpoch: nowEpoch - 120,
    expiresAtEpoch: nowEpoch + 600,
  });
  const native = evidence(request);
  native.nowEpoch = nowEpoch;
  native.run.created_at = new Date((nowEpoch - 100) * 1000).toISOString();
  Object.assign(native.jobInventory.jobs[0], {
    created_at: new Date((nowEpoch - 100) * 1000).toISOString(),
    started_at: new Date((nowEpoch - 95) * 1000).toISOString(),
    completed_at: new Date((nowEpoch - 90) * 1000).toISOString(),
  });
  Object.assign(native.jobInventory.jobs[1], {
    created_at: new Date((nowEpoch - 89) * 1000).toISOString(),
    started_at: new Date((nowEpoch - 60) * 1000).toISOString(),
  });
  mutateEvidence(native);
  const providerRun = {
    ...native.run,
    repository: { full_name: ADMIN_READ_POLICY.controllerRepository, private: false, fork: false },
    head_repository: { full_name: ADMIN_READ_POLICY.controllerRepository, fork: false },
    path: `${ADMIN_READ_POLICY.workflow}@${request.controller.head}`,
    actor: { login: request.run.actor, id: request.run.actorId },
    triggering_actor: { login: request.run.triggeringActor, id: request.run.triggeringActorId },
    pull_requests: [],
    display_title: adminReadRunTitle(request),
  };
  const source = (path, shaValue) => ({ type: "file", path, sha: shaValue });
  const sources = {
    workflow: source(ADMIN_READ_POLICY.workflow, request.controller.workflowBlob),
    script: source(ADMIN_READ_POLICY.script, request.controller.scriptBlob),
  };
  mutateSource(sources);
  const env = {
    GH_TOKEN: "synthetic-workflow-token",
    GITHUB_RUN_ID: request.run.id,
    HFS_ADMIN_READ_TARGET: request.target,
    HFS_ADMIN_READ_NONCE: request.nonce,
    HFS_ADMIN_READ_CREATED_AT_EPOCH: String(request.createdAtEpoch),
    HFS_ADMIN_READ_EXPIRES_AT_EPOCH: String(request.expiresAtEpoch),
    HFS_ADMIN_READ_CONTROLLER_HEAD: request.controller.head,
    HFS_ADMIN_READ_WORKFLOW_BLOB: request.controller.workflowBlob,
    HFS_ADMIN_READ_SCRIPT_BLOB: request.controller.scriptBlob,
    HFS_ADMIN_READ_REQUEST_ID: request.requestId,
    ...(omitToken ? {} : { HFS_CONTROLLER_ADMIN_READ_TOKEN: "synthetic-admin-read-token" }),
  };
  Object.assign(process.env, env);
  if (omitToken) delete process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN;

  globalThis.fetch = async (url) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(`/repos/${ADMIN_READ_POLICY.controllerRepository}`, "");
    if (path === `/actions/runs/${request.run.id}`) return jsonResponse(providerRun);
    if (path === "/actions/runs" && parsed.searchParams.get("event") === "workflow_dispatch") {
      return jsonResponse({ total_count: 1, workflow_runs: [providerRun] });
    }
    if (path === `/actions/runs/${request.run.id}/approvals`) return jsonResponse(native.approvals);
    if (path === `/actions/runs/${request.run.id}/attempts/1/jobs`) return jsonResponse(native.jobInventory);
    if (path === `/environments/${encodeURIComponent(ADMIN_READ_POLICY.targets.image.environment)}`) return jsonResponse(native.environment);
    if (path === `/contents/${ADMIN_READ_POLICY.workflow}`) return jsonResponse(sources.workflow);
    if (path === `/contents/${ADMIN_READ_POLICY.script}`) return jsonResponse(sources.script);
    if (path === "/branches/main/protection") {
      return protectionStatus === 200 ? jsonResponse(protection) : new Response(null, { status: protectionStatus });
    }
    throw new Error(`unexpected mocked provider request: ${url}`);
  };

  let stdout = "";
  let stderr = "";
  process.stdout.write = (chunk) => { stdout += String(chunk); return true; };
  process.stderr.write = (chunk) => { stderr += String(chunk); return true; };
  try {
    const exitCode = await cli(["node", "controller-admin-read-preflight.mjs", "verify-admin-read"]);
    return { exitCode, stdout, stderr };
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
    for (const key of Object.keys(env)) delete process.env[key];
    delete process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN;
  }
}

afterEach(() => {
  delete process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN;
  globalThis.fetch = originalFetch;
  process.stdout.write = originalStdoutWrite;
  process.stderr.write = originalStderrWrite;
});

describe("Administration-read request contract", () => {
  it("pins only the two real environment names and IDs", () => {
    assert.deepEqual(Object.keys(ADMIN_READ_POLICY.targets), ["image", "deploy"]);
    assert.deepEqual(
      Object.values(ADMIN_READ_POLICY.targets).map(({ environment, environmentId }) => ({ environment, environmentId })),
      [
        { environment: "production-image-publication", environmentId: 27579543667 },
        { environment: "production-host-deployment", environmentId: 27579657157 },
      ],
    );
  });

  it("accepts a fresh unique exact-source request for each fixed target", () => {
    for (const target of ["image", "deploy"]) {
      const request = fixture(target);
      assert.equal(validateAdminReadRequest(request, options(request)).target, target);
      assert.equal(adminReadRunTitle(request), `Administration-read preflight · ${target} · ${request.requestId} · ${request.nonce}`);
    }
  });

  for (const [name, mutate, code] of [
    ["free-text target", (request) => { request.target = "production-image-publication"; }, "ADMIN_READ_PURPOSE"],
    ["wrong workflow source", (request) => { request.controller.workflow = ".github/workflows/release-image-only.yml"; }, "ADMIN_READ_CONTROLLER_PIN"],
    ["wrong script source", (request) => { request.controller.script = "scripts/release-controller-preflight.mjs"; }, "ADMIN_READ_CONTROLLER_PIN"],
    ["changed controller head", (request) => { request.controller.head = sha("e", 40); }, "ADMIN_READ_RUN"],
    ["attempt two", (request) => { request.run.attempt = 2; }, "ADMIN_READ_RUN"],
    ["other actor", (request) => { request.run.actor = "attacker"; }, "ADMIN_READ_RUN"],
    ["overlong lifetime", (request) => { request.expiresAtEpoch = request.createdAtEpoch + 1801; }, "ADMIN_READ_FRESHNESS"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      mutate(request);
      const rebound = finalizeAdminReadRequest(request);
      assert.throws(() => validateAdminReadRequest(rebound, options(rebound)), new RegExp(code));
    });
  }

  it("rejects missing, duplicate, and rerun inventory", () => {
    const request = fixture();
    const exact = options(request).inventory[0];
    assert.throws(() => validateAdminReadRequest(request, { nowEpoch: now, inventory: [] }), /ADMIN_READ_REPLAY/);
    assert.throws(() => validateAdminReadRequest(request, { nowEpoch: now, inventory: [exact, { ...exact, runId: "888000999" }] }), /ADMIN_READ_REPLAY/);
    assert.throws(() => validateAdminReadRequest(request, { nowEpoch: now, inventory: [{ ...exact, attempt: 2 }] }), /ADMIN_READ_REPLAY/);
  });

  it("cannot satisfy either harmless-probe or release contracts", () => {
    const request = fixture();
    assert.throws(() => validateProbeRequest(request, { nowEpoch: now, inventory: [] }), /PROBE_PURPOSE/);
    assert.throws(() => validateRequest(request, { nowEpoch: now, inventory: [] }), /CONTRACT_FIELDS/);
  });
});

describe("shared native and main-protection evidence", () => {
  it("accepts authentic native evidence plus the exact protected-main policy", () => {
    for (const target of ["image", "deploy"]) {
      const request = fixture(target);
      const result = validateAdminReadEvidence(request, evidence(request));
      assert.equal(result.environment, ADMIN_READ_POLICY.targets[target].environment);
      assert.equal(result.enforceAdmins, true);
      assert.equal(result.allowForcePushes, false);
      assert.equal(result.allowDeletions, false);
    }
  });

  for (const [name, mutate, code] of [
    ["wrong environment", (item) => { item.environment.id += 1; }, "NATIVE_ENVIRONMENT"],
    ["wrong reviewer", (item) => { item.approvals[0].user.id = 1; }, "NATIVE_APPROVAL"],
    ["wrong protected job", (item) => { item.jobInventory.jobs[1].name += " copy"; }, "NATIVE_JOB_IDENTITY"],
    ["attempt two evidence", (item) => { item.run.run_attempt = 2; }, "NATIVE_RUN"],
    ["admins not enforced", (item) => { item.branchProtection.enforce_admins.enabled = false; }, "NATIVE_MAIN_PROTECTION"],
    ["force push allowed", (item) => { item.branchProtection.allow_force_pushes.enabled = true; }, "NATIVE_MAIN_PROTECTION"],
    ["deletion allowed", (item) => { item.branchProtection.allow_deletions.enabled = true; }, "NATIVE_MAIN_PROTECTION"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      const item = evidence(request);
      mutate(item);
      assert.throws(() => validateAdminReadEvidence(request, item), new RegExp(code));
    });
  }
});

describe("isolated Administration-read provider call", () => {
  it("runs the real verify-admin-read CLI boundary and fails closed on provider or native drift", async () => {
    const pass = await runVerifyAdminReadCli();
    assert.equal(pass.exitCode, 0, pass.stderr);
    assert.match(pass.stdout, /^ADMIN_READ_PREFLIGHT_PASS .*enforce_admins=true allow_force_pushes=false allow_deletions=false/m);
    assert.equal(pass.stderr, "");

    for (const [name, options, code] of [
      ["raw policy drift", { protection: { ...evidence(fixture()).branchProtection, enforce_admins: { enabled: false } } }, "NATIVE_MAIN_PROTECTION"],
      ["malformed provider response", { protection: { protected: true } }, "NATIVE_MAIN_PROTECTION"],
      ["denied provider response", { protectionStatus: 403 }, "ADMIN_READ_PROTECTION_HTTP_403"],
      ["missing dedicated token", { omitToken: true }, "ADMIN_READ_TOKEN_UNCONFIGURED"],
      ["wrong native evidence", { mutateEvidence: (item) => { item.approvals[0].user.id = 1; } }, "NATIVE_APPROVAL"],
      ["wrong source evidence", { mutateSource: (sourceItems) => { sourceItems.script.sha = sha("e", 40); } }, "ADMIN_READ_SOURCE"],
    ]) {
      const refusal = await runVerifyAdminReadCli(options);
      assert.equal(refusal.exitCode, 78, name);
      assert.equal(refusal.stdout, "", name);
      assert.match(refusal.stderr, new RegExp(`^ADMIN_READ_PREFLIGHT_REFUSED code=${code}$`, "m"), name);
    }
  });

  it("uses the dedicated token only for the fixed read-only protection GET", async () => {
    process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN = "synthetic-admin-read-token";
    globalThis.fetch = async (url, init) => {
      assert.equal(url, "https://api.github.com/repos/Ronmel71/hfs-approval-controller/branches/main/protection");
      assert.equal(init.method, "GET");
      assert.equal(init.redirect, "error");
      assert.ok(init.signal instanceof AbortSignal);
      assert.equal(init.headers.Authorization, "Bearer synthetic-admin-read-token");
      return new Response(JSON.stringify(evidence(fixture()).branchProtection), { status: 200, headers: { "content-type": "application/json" } });
    };
    assert.equal((await readMainProtection()).enforce_admins.enabled, true);
  });

  it("fails closed for missing credential, denial, non-JSON, and malformed JSON", async () => {
    await assert.rejects(readMainProtection(), /ADMIN_READ_TOKEN_UNCONFIGURED/);
    process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN = "synthetic-admin-read-token";
    for (const [response, code] of [
      [new Response(null, { status: 401 }), "ADMIN_READ_PROTECTION_HTTP_401"],
      [new Response(null, { status: 403 }), "ADMIN_READ_PROTECTION_HTTP_403"],
      [new Response(null, { status: 404 }), "ADMIN_READ_PROTECTION_HTTP_404"],
      [new Response(null, { status: 429 }), "ADMIN_READ_PROTECTION_HTTP_429"],
      [new Response("not-json", { status: 200, headers: { "content-type": "text/plain" } }), "ADMIN_READ_PROTECTION_CONTENT_TYPE"],
      [new Response("{", { status: 200, headers: { "content-type": "application/json" } }), "ADMIN_READ_PROTECTION_JSON"],
    ]) {
      globalThis.fetch = async () => response;
      await assert.rejects(readMainProtection(), new RegExp(code));
    }
    globalThis.fetch = async () => { throw new Error("synthetic timeout"); };
    await assert.rejects(readMainProtection(), /ADMIN_READ_PROTECTION_NETWORK/);
  });
});

describe("manual protected workflow isolation", () => {
  it("is manual-only, main-only, first-attempt, actor-bound, and fixed-target", () => {
    assert.match(workflow, /^on:\n  workflow_dispatch:/m);
    assert.doesNotMatch(workflow, /^  (push|pull_request|pull_request_target|schedule|repository_dispatch):/m);
    assert.match(workflow, /type: choice\n\s+options:\n\s+- image\n\s+- deploy/);
    assert.equal(workflow.match(/github\.ref == 'refs\/heads\/main'/g)?.length, 2);
    assert.equal(workflow.match(/github\.run_attempt == 1/g)?.length, 2);
    assert.equal(workflow.match(/github\.actor == 'Ronmel71'/g)?.length, 2);
    assert.equal(workflow.match(/github\.triggering_actor == 'Ronmel71'/g)?.length, 2);
  });

  it("exposes the one permitted credential only inside the protected step", () => {
    const [unprotected, protectedJob] = workflow.split("  protected-readback:");
    assert.doesNotMatch(unprotected, /HFS_CONTROLLER_ADMIN_READ_TOKEN|secrets\./);
    assert.equal(workflow.match(/secrets\.HFS_CONTROLLER_ADMIN_READ_TOKEN/g)?.length, 1);
    assert.match(protectedJob, /environment: \$\{\{ inputs\.target == 'image' && 'production-image-publication' \|\| 'production-host-deployment' \}\}/);
    assert.doesNotMatch(workflow, /permissions:(?:.|\n)*?\bwrite\b/);
  });

  it("has no alternate credential, write, release, artifact, private-source, or live executor path", () => {
    assert.doesNotMatch(workflow + script, /HFS_PRIVATE_SOURCE|HFS_GHCR|DEPLOY_|ghcr\.io|hfs-selger-app|WireGuard|SSH|Supabase|upload-artifact|outputs:/i);
    assert.doesNotMatch(script, /method:\s*"(?:POST|PUT|PATCH|DELETE)"/);
    assert.match(script, /ADMIN_READ_PREFLIGHT_PASS/);
    assert.match(script, /credential_read=true release_ready=false authorization=false/);
    assert.doesNotMatch(script, /RELEASE_CONTROLLER_REQUEST_VALID|RELEASE_CONTROLLER_NATIVE_APPROVAL_VERIFIED|NATIVE_PROBE_PASS/);
  });

  it("preserves every out-of-scope protected workflow required by the issue byte-for-byte", () => {
    assert.equal(gitBlob(deployWorkflow), "b0acaad341f5394e2b4a83bea253208f6a092936");
    assert.equal(gitBlob(stageWorkflow), "8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4");
    assert.equal(gitBlob(harmlessWorkflow), "0162b90496b366c1370cb28546e6e46e1955d0dd");
  });
});
