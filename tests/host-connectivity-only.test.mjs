import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  CONNECTIVITY_POLICY,
  connectivityRunTitle,
  finalizeConnectivityRequest,
  validateConnectivityGateEvidence,
  validateConnectivityRequest,
} from "../scripts/host-connectivity-only.mjs";

const workflow = readFileSync(new URL("../.github/workflows/host-connectivity-only.yml", import.meta.url), "utf8");
const guard = readFileSync(new URL("../scripts/host-connectivity-only.mjs", import.meta.url), "utf8");
const executor = readFileSync(new URL("../scripts/host-connectivity-only.sh", import.meta.url), "utf8");
const now = 2_000_000_000;
const sha = (character, length = 64) => character.repeat(length);

function fixture() {
  return finalizeConnectivityRequest({
    schema: CONNECTIVITY_POLICY.schema,
    purpose: CONNECTIVITY_POLICY.purpose,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 120,
    expiresAtEpoch: now + 600,
    controller: {
      repository: CONNECTIVITY_POLICY.controllerRepository,
      ref: CONNECTIVITY_POLICY.controllerRef,
      head: sha("b", 40),
      workflow: CONNECTIVITY_POLICY.workflow,
      workflowBlob: sha("c", 40),
      guard: CONNECTIVITY_POLICY.guard,
      guardBlob: sha("d", 40),
      executor: CONNECTIVITY_POLICY.executor,
      executorBlob: sha("e", 40),
    },
    remoteHelperSha256: CONNECTIVITY_POLICY.remoteHelperSha256,
    run: {
      id: "777000452",
      attempt: 1,
      event: "workflow_dispatch",
      repository: CONNECTIVITY_POLICY.controllerRepository,
      ref: CONNECTIVITY_POLICY.controllerRef,
      head: sha("b", 40),
      actor: CONNECTIVITY_POLICY.reviewer,
      actorId: CONNECTIVITY_POLICY.reviewerId,
      triggeringActor: CONNECTIVITY_POLICY.reviewer,
      triggeringActorId: CONNECTIVITY_POLICY.reviewerId,
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
      purpose: request.purpose,
      runId: request.run.id,
      attempt: 1,
    }],
  };
}

function evidence(request) {
  const runUrl = `https://api.github.com/repos/${CONNECTIVITY_POLICY.controllerRepository}/actions/runs/${request.run.id}`;
  return {
    nowEpoch: now,
    run: {
      id: Number(request.run.id),
      run_attempt: 1,
      event: "workflow_dispatch",
      head_branch: "main",
      head_sha: request.controller.head,
      repository: { full_name: CONNECTIVITY_POLICY.controllerRepository },
      status: "in_progress",
      conclusion: null,
      created_at: new Date((now - 100) * 1000).toISOString(),
    },
    approvals: [{
      state: "approved",
      user: { login: CONNECTIVITY_POLICY.reviewer, id: CONNECTIVITY_POLICY.reviewerId },
      environments: [{ name: CONNECTIVITY_POLICY.environment, id: CONNECTIVITY_POLICY.environmentId }],
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
          name: CONNECTIVITY_POLICY.protectedJobName,
          status: "in_progress",
          conclusion: null,
          created_at: new Date((now - 89) * 1000).toISOString(),
          started_at: new Date((now - 60) * 1000).toISOString(),
          completed_at: null,
        },
      ],
    },
    environment: {
      id: CONNECTIVITY_POLICY.environmentId,
      name: CONNECTIVITY_POLICY.environment,
      can_admins_bypass: false,
      protection_rules: [
        {
          type: "required_reviewers",
          prevent_self_review: false,
          reviewers: [{ type: "User", reviewer: { login: CONNECTIVITY_POLICY.reviewer, id: CONNECTIVITY_POLICY.reviewerId } }],
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

describe("host connectivity request", () => {
  it("accepts only one fresh exact-source one-use connectivity request", () => {
    const request = fixture();
    assert.equal(validateConnectivityRequest(request, options(request)).purpose, "HOST_CONNECTIVITY_ONLY");
    assert.equal(connectivityRunTitle(request), `Host connectivity only · ${request.requestId} · ${request.nonce}`);
  });

  for (const [name, mutate, code] of [
    ["other purpose", (request) => { request.purpose = "RELEASE_DEPLOY_ONLY"; }, "CONNECTIVITY_PURPOSE"],
    ["other controller repository", (request) => { request.controller.repository = "attacker/repository"; }, "CONNECTIVITY_CONTROLLER_PIN"],
    ["changed workflow pin", (request) => { request.controller.workflowBlob = sha("f", 40); }, "CONNECTIVITY_REQUEST_ID"],
    ["changed executor path", (request) => { request.controller.executor = "scripts/release-deploy-only.sh"; }, "CONNECTIVITY_CONTROLLER_PIN"],
    ["changed helper SHA", (request) => { request.remoteHelperSha256 = sha("f"); }, "CONNECTIVITY_HELPER_PIN"],
    ["other ref", (request) => { request.run.ref = "refs/heads/feature"; }, "CONNECTIVITY_RUN"],
    ["attempt two", (request) => { request.run.attempt = 2; }, "CONNECTIVITY_RUN"],
    ["other actor", (request) => { request.run.actor = "attacker"; }, "CONNECTIVITY_RUN"],
    ["other triggering actor", (request) => { request.run.triggeringActorId = 1; }, "CONNECTIVITY_RUN"],
    ["overlong lifetime", (request) => { request.expiresAtEpoch = request.createdAtEpoch + 1801; }, "CONNECTIVITY_FRESHNESS"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      mutate(request);
      assert.throws(() => validateConnectivityRequest(request, options(request)), new RegExp(code));
    });
  }

  it("rejects missing, duplicate, and rerun inventory", () => {
    const request = fixture();
    const exact = options(request).inventory[0];
    assert.throws(() => validateConnectivityRequest(request, { nowEpoch: now, inventory: [] }), /CONNECTIVITY_REPLAY/);
    assert.throws(() => validateConnectivityRequest(request, { nowEpoch: now, inventory: [exact, { ...exact, runId: "777000999" }] }), /CONNECTIVITY_REPLAY/);
    assert.throws(() => validateConnectivityRequest(request, { nowEpoch: now, inventory: [{ ...exact, attempt: 2 }] }), /CONNECTIVITY_REPLAY/);
  });
});

describe("host connectivity native gate", () => {
  it("accepts the exact genuine production-host-deployment review evidence", () => {
    const request = fixture();
    const result = validateConnectivityGateEvidence(request, evidence(request));
    assert.equal(result.environment, "production-host-deployment");
    assert.equal(result.environmentId, 27579657157);
    assert.equal(result.reviewerId, 321374159);
    assert.equal(result.enforceAdmins, true);
  });

  it("refuses at the final gate when a request that was initially fresh expires during tool setup", () => {
    const request = fixture();
    assert.equal(validateConnectivityRequest(request, options(request)).purpose, "HOST_CONNECTIVITY_ONLY");
    const afterSetup = evidence(request);
    afterSetup.nowEpoch = request.expiresAtEpoch;
    assert.throws(() => validateConnectivityGateEvidence(request, afterSetup), /NATIVE_APPROVAL_FRESHNESS/);
  });

  for (const [name, mutate, code] of [
    ["missing native approval", (item) => { item.approvals = []; }, "NATIVE_APPROVAL_COUNT"],
    ["wrong environment ID", (item) => { item.environment.id += 1; }, "NATIVE_ENVIRONMENT"],
    ["wrong reviewer", (item) => { item.approvals[0].user.id = 1; }, "NATIVE_APPROVAL"],
    ["admin bypass", (item) => { item.environment.can_admins_bypass = true; }, "NATIVE_ENVIRONMENT"],
    ["unprotected main", (item) => { item.branchProtection.enforce_admins.enabled = false; }, "NATIVE_MAIN_PROTECTION"],
    ["rerun job", (item) => { item.jobInventory.jobs[1].run_attempt = 2; }, "NATIVE_JOB_PROVENANCE"],
    ["other protected job", (item) => { item.jobInventory.jobs[1].name = "Release deploy only"; }, "NATIVE_JOB_IDENTITY"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      const item = evidence(request);
      mutate(item);
      assert.throws(() => validateConnectivityGateEvidence(request, item), new RegExp(code));
    });
  }
});

describe("manual read-only connectivity workflow", () => {
  it("is manual-only, exact-repository/main/actor/attempt/purpose bound, and non-concurrent", () => {
    assert.match(workflow, /^on:\n  workflow_dispatch:/m);
    assert.doesNotMatch(workflow, /^  (push|pull_request|pull_request_target|schedule|repository_dispatch):/m);
    assert.equal(workflow.match(/github\.repository == 'Ronmel71\/hfs-approval-controller'/g)?.length, 2);
    assert.equal(workflow.match(/github\.ref == 'refs\/heads\/main'/g)?.length, 2);
    assert.equal(workflow.match(/github\.run_attempt == 1/g)?.length, 2);
    assert.equal(workflow.match(/github\.actor == 'Ronmel71'/g)?.length, 2);
    assert.equal(workflow.match(/github\.triggering_actor == 'Ronmel71'/g)?.length, 2);
    assert.equal(workflow.match(/inputs\.purpose == 'HOST_CONNECTIVITY_ONLY'/g)?.length, 2);
    assert.match(workflow, /cancel-in-progress: false/);
  });

  it("validates exact pinned source before the genuine native environment gate and before host secrets", () => {
    const preGate = workflow.slice(workflow.indexOf("  validate-request:"), workflow.indexOf("  connectivity-check:"));
    const protectedJob = workflow.slice(workflow.indexOf("  connectivity-check:"));
    assert.match(preGate, /persist-credentials: false/);
    assert.match(preGate, /git rev-parse HEAD:\.github\/workflows\/host-connectivity-only\.yml/);
    assert.match(preGate, /git rev-parse HEAD:scripts\/host-connectivity-only\.mjs/);
    assert.match(preGate, /git rev-parse HEAD:scripts\/host-connectivity-only\.sh/);
    assert.doesNotMatch(preGate, /secrets\.|DEPLOY_|wg-quick|\bssh\b/);
    assert.match(protectedJob, /needs: validate-request/);
    assert.match(protectedJob, /environment: production-host-deployment/);
    assert.ok(protectedJob.indexOf("apt-get install --yes wireguard-tools") < protectedJob.indexOf("verify-native-gate"));
    assert.ok(protectedJob.indexOf("verify-native-gate") < protectedJob.indexOf("DEPLOY_WIREGUARD_CONFIG"));
    assert.ok(protectedJob.lastIndexOf("HFS_CONNECTIVITY_EXPIRES_AT_EPOCH: ${{ inputs.expires_at_epoch }}") > protectedJob.indexOf("verify-native-gate"));
  });

  it("references only the five host transport secrets plus the existing Administration reader", () => {
    const secrets = [...workflow.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((match) => match[1]);
    assert.deepEqual([...new Set(secrets)].sort(), [
      "DEPLOY_SSH_KEY",
      "DEPLOY_SSH_KNOWN_HOSTS",
      "DEPLOY_USER",
      "DEPLOY_WIREGUARD_CONFIG",
      "DEPLOY_WIREGUARD_HOST",
      "HFS_CONTROLLER_ADMIN_READ_TOKEN",
    ]);
    assert.doesNotMatch(workflow + guard + executor, /HFS_PRIVATE_SOURCE|HFS_GHCR|packages: write|upload-artifact|hfs-selger-app@sha256/);
    assert.doesNotMatch(guard, /method:\s*"(?:POST|PUT|PATCH|DELETE)"/);
  });

  it("keeps the fixed executor independent from deployment and emits only connectivity status", () => {
    assert.doesNotMatch(workflow, /release-deploy-only\.sh|release-image-only\.sh/);
    assert.doesNotMatch(executor, /\bdocker\s+(?:pull|run|exec|compose)|\bscp\b|\brsync\b|mkdir .*incoming|--install|--rollback|image_reference|release_sha/i);
    for (const command of [
      "id -un",
      "id -nG",
      "stat -Lc '%a %u %g' /usr/local/sbin/hfs-deploy-release",
      "sha256sum /usr/local/sbin/hfs-deploy-release",
      "sudo -n /usr/local/sbin/hfs-deploy-release --check",
    ]) assert.match(executor, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(executor, /deploy_authorization=false/);
    assert.doesNotMatch(executor, /DEPLOY_(COMPLETE|PASS)|RELEASE_READY/);
  });
});
