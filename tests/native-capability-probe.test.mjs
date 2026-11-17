import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { validateNativeGateEvidence, validateRequest } from "../scripts/release-controller-contract.mjs";
import {
  PROBE_POLICY,
  classifyAdminReadResponse,
  finalizeProbeRequest,
  probeRunTitle,
  validateProbeRequest,
} from "../scripts/native-capability-probe.mjs";

const now = 2_000_000_000;
const sha = (character, length = 64) => character.repeat(length);
const workflow = readFileSync(new URL("../.github/workflows/native-capability-probe.yml", import.meta.url), "utf8");
const script = readFileSync(new URL("../scripts/native-capability-probe.mjs", import.meta.url), "utf8");
const deployWorkflow = readFileSync(new URL("../.github/workflows/release-deploy-only.yml", import.meta.url));
const gitBlob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");

function fixture(target = "image") {
  return finalizeProbeRequest({
    schema: PROBE_POLICY.schema,
    purpose: PROBE_POLICY.purpose,
    target,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 120,
    expiresAtEpoch: now + 600,
    controller: {
      repository: PROBE_POLICY.controllerRepository,
      ref: PROBE_POLICY.controllerRef,
      head: sha("b", 40),
      workflow: PROBE_POLICY.workflow,
      workflowBlob: sha("c", 40),
      probeScript: PROBE_POLICY.probeScript,
      probeScriptBlob: sha("d", 40),
    },
    run: {
      id: target === "image" ? "777000111" : "777000222",
      attempt: 1,
      event: "workflow_dispatch",
      repository: PROBE_POLICY.controllerRepository,
      ref: PROBE_POLICY.controllerRef,
      head: sha("b", 40),
      actor: PROBE_POLICY.reviewer,
      actorId: PROBE_POLICY.reviewerId,
      triggeringActor: PROBE_POLICY.reviewer,
      triggeringActorId: PROBE_POLICY.reviewerId,
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
  const target = PROBE_POLICY.targets[request.target];
  const runUrl = `https://api.github.com/repos/${PROBE_POLICY.controllerRepository}/actions/runs/${request.run.id}`;
  return {
    expectedEnvironmentId: target.environmentId,
    expectedEnvironmentName: target.environment,
    expectedProtectedJobName: target.protectedJobName,
    nowEpoch: now,
    run: {
      id: Number(request.run.id),
      run_attempt: 1,
      event: "workflow_dispatch",
      head_branch: "main",
      head_sha: request.controller.head,
      repository: { full_name: PROBE_POLICY.controllerRepository },
      status: "in_progress",
      conclusion: null,
      created_at: new Date((now - 100) * 1000).toISOString(),
    },
    approvals: [{
      state: "approved",
      user: { login: PROBE_POLICY.reviewer, id: PROBE_POLICY.reviewerId },
      environments: [{ name: target.environment, id: target.environmentId }],
    }],
    jobInventory: {
      total_count: 2,
      jobs: [
        {
          id: 800001,
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
          id: 800002,
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
          reviewers: [{ type: "User", reviewer: { login: PROBE_POLICY.reviewer, id: PROBE_POLICY.reviewerId } }],
        },
        { type: "branch_policy" },
      ],
      deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
    },
  };
}

describe("native capability probe request", () => {
  it("uses only the two fixed purpose-specific environments and IDs", () => {
    assert.deepEqual(Object.keys(PROBE_POLICY.targets), ["image", "deploy"]);
    assert.deepEqual(
      Object.values(PROBE_POLICY.targets).map(({ environment, environmentId }) => ({ environment, environmentId })),
      [
        { environment: "production-image-publication", environmentId: 27579543667 },
        { environment: "production-host-deployment", environmentId: 27579657157 },
      ],
    );
  });

  it("accepts a fresh unique exact-source request for each selector", () => {
    for (const target of ["image", "deploy"]) {
      const request = fixture(target);
      assert.equal(validateProbeRequest(request, options(request)).target, target);
      assert.equal(probeRunTitle(request), `Native capability probe · ${target} · ${request.requestId} · ${request.nonce}`);
    }
  });

  for (const [name, mutate, code] of [
    ["free-text target", (request) => { request.target = "production-image-publication"; }, "PROBE_PURPOSE"],
    ["changed controller head", (request) => { request.controller.head = sha("e", 40); }, "PROBE_RUN"],
    ["changed workflow path", (request) => { request.controller.workflow = ".github/workflows/release-image-only.yml"; }, "PROBE_CONTROLLER_PIN"],
    ["attempt two", (request) => { request.run.attempt = 2; }, "PROBE_RUN"],
    ["other actor", (request) => { request.run.actor = "attacker"; }, "PROBE_RUN"],
    ["other triggering actor", (request) => { request.run.triggeringActorId = 1; }, "PROBE_RUN"],
    ["overlong lifetime", (request) => { request.expiresAtEpoch = request.createdAtEpoch + 1801; }, "PROBE_FRESHNESS"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      mutate(request);
      const rebound = finalizeProbeRequest(request);
      assert.throws(() => validateProbeRequest(rebound, options(rebound)), new RegExp(code));
    });
  }

  it("rejects missing, duplicate, and rerun request inventory", () => {
    const request = fixture();
    const exact = options(request).inventory[0];
    assert.throws(() => validateProbeRequest(request, { nowEpoch: now, inventory: [] }), /PROBE_REPLAY/);
    assert.throws(() => validateProbeRequest(request, { nowEpoch: now, inventory: [exact, { ...exact, runId: "777000999" }] }), /PROBE_REPLAY/);
    assert.throws(() => validateProbeRequest(request, { nowEpoch: now, inventory: [{ ...exact, attempt: 2 }] }), /PROBE_REPLAY/);
  });

  it("cannot satisfy the release request contract", () => {
    const request = fixture();
    assert.throws(() => validateRequest(request, { nowEpoch: now, inventory: [] }), /CONTRACT_FIELDS/);
  });
});

describe("shared native gate evidence", () => {
  it("accepts timestamp-free approval only as a bounded interval for both fixed targets", () => {
    for (const target of ["image", "deploy"]) {
      const request = fixture(target);
      const result = validateNativeGateEvidence(request, evidence(request));
      assert.equal(result.environment, PROBE_POLICY.targets[target].environment);
      assert.equal(result.reviewerId, PROBE_POLICY.reviewerId);
      assert.equal(result.approvalNotBeforeEpoch, now - 100);
      assert.equal(result.approvalNotAfterEpoch, now - 60);
      assert.equal("approvedAtEpoch" in result, false);
    }
  });

  for (const [name, mutate, code] of [
    ["missing job evidence", (item) => { item.jobInventory.jobs.pop(); item.jobInventory.total_count = 1; }, "NATIVE_JOB_INVENTORY"],
    ["incomplete job inventory", (item) => { item.jobInventory.total_count = 3; }, "NATIVE_JOB_INVENTORY"],
    ["changed gated job", (item) => { item.jobInventory.jobs[1].name += " copy"; }, "NATIVE_JOB_IDENTITY"],
    ["wrong job attempt", (item) => { item.jobInventory.jobs[1].run_attempt = 2; }, "NATIVE_JOB_PROVENANCE"],
    ["wrong environment ID", (item) => { item.approvals[0].environments[0].id += 1; }, "NATIVE_APPROVAL"],
    ["wrong reviewer ID", (item) => { item.approvals[0].user.id = 1; }, "NATIVE_APPROVAL"],
    ["self-review prevention drift", (item) => { item.environment.protection_rules[0].prevent_self_review = true; }, "NATIVE_REVIEW_POLICY"],
    ["late gated job", (item) => { item.jobInventory.jobs[1].started_at = new Date((now + 601) * 1000).toISOString(); }, "NATIVE_JOB_ORDER"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      const item = evidence(request);
      mutate(item);
      assert.throws(() => validateNativeGateEvidence(request, item), new RegExp(code));
    });
  }

  it("reports an ephemeral GITHUB_TOKEN protection denial distinctly without inventing protection", async () => {
    assert.equal(await classifyAdminReadResponse(new Response(null, { status: 403 })), "ADMIN_READ_BLOCKED");
    assert.equal(await classifyAdminReadResponse(new Response(null, { status: 404 })), "ADMIN_READ_BLOCKED_HTTP_404");
    const weak = new Response(JSON.stringify({ protected: true }), { status: 200, headers: { "content-type": "application/json" } });
    assert.equal(await classifyAdminReadResponse(weak), "ADMIN_READ_POLICY_MISMATCH");
    assert.doesNotMatch(script, /branchProtection\s*=\s*\{|protected:\s*true/);
  });
});

describe("manual harmless workflow", () => {
  it("is manual-only, main-only, first-attempt, actor-bound, and uses an enumerated selector", () => {
    assert.match(workflow, /^on:\n  workflow_dispatch:/m);
    assert.doesNotMatch(workflow, /^  (push|pull_request|pull_request_target|schedule|repository_dispatch):/m);
    assert.match(workflow, /type: choice\n\s+options:\n\s+- image\n\s+- deploy/);
    assert.equal(workflow.match(/github\.ref == 'refs\/heads\/main'/g)?.length, 2);
    assert.equal(workflow.match(/github\.run_attempt == 1/g)?.length, 2);
    assert.equal(workflow.match(/github\.actor == 'Ronmel71'/g)?.length, 2);
    assert.equal(workflow.match(/github\.triggering_actor == 'Ronmel71'/g)?.length, 2);
  });

  it("maps only the selector to the exact two environment names", () => {
    assert.match(workflow, /environment: \$\{\{ inputs\.target == 'image' && 'production-image-publication' \|\| 'production-host-deployment' \}\}/);
    assert.doesNotMatch(workflow, /environment:\s*\$\{\{\s*inputs\.(?:environment|name|path)/);
  });

  it("has two read-only jobs and no credential, private-source, artifact, release, or output path", () => {
    assert.match(workflow, /permissions:\n  actions: read\n  contents: read/);
    assert.match(workflow, /  validate-request:/);
    assert.match(workflow, /  native-probe:/);
    assert.doesNotMatch(workflow + script, /secrets\.|HFS_PRIVATE_SOURCE|HFS_GHCR|DEPLOY_|ghcr\.io|hfs-selger-app|WireGuard|SSH|Supabase|upload-artifact|outputs:/i);
    assert.doesNotMatch(workflow, /permissions:(?:.|\n)*?\bwrite\b/);
    assert.doesNotMatch(script, /method:\s*"(?:POST|PUT|PATCH|DELETE)"/);
  });

  it("emits only non-authorizing capability status and preserves the dormant deploy workflow byte-for-byte", () => {
    assert.match(script, /NATIVE_PROBE_PASS/);
    assert.match(script, /release_ready=false authorization=false/);
    assert.doesNotMatch(script, /RELEASE_CONTROLLER_REQUEST_VALID|RELEASE_CONTROLLER_NATIVE_APPROVAL_VERIFIED/);
    assert.equal(gitBlob(deployWorkflow), "b0acaad341f5394e2b4a83bea253208f6a092936");
  });
});
