import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  POLICY,
  finalizeRequest,
  validateNativeApprovalEvidence,
  validatePublishedImage,
  validateRequest,
} from "../scripts/release-controller-contract.mjs";

const now = 2_000_000_000;
const sha = (character, length = 64) => character.repeat(length);
const APP_COMMIT = sha("1", 40);
const APP_TREE = sha("2", 40);

function fixture(purpose = "RELEASE_IMAGE_ONLY") {
  const purposePolicy = POLICY.purposes[purpose];
  return finalizeRequest({
    schema: POLICY.schema,
    purpose,
    approvalPurpose: purposePolicy.approvalPurpose,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 120,
    expiresAtEpoch: now + 600,
    app: {
      repository: POLICY.appRepository,
      ref: POLICY.appRef,
      commit: APP_COMMIT,
      tree: APP_TREE,
      workflow: POLICY.appWorkflow,
      workflowBlob: POLICY.appWorkflowBlob,
      composeBlob: POLICY.composeBlob,
      caddyBlob: POLICY.caddyBlob,
      helperBlob: POLICY.helperBlob,
      sudoersBlob: POLICY.sudoersBlob,
    },
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: sha("b", 40),
      workflow: purposePolicy.workflow,
      workflowBlob: sha("c", 40),
      executor: purposePolicy.executor,
      executorBlob: sha("d", 40),
    },
    run: {
      id: purpose === "RELEASE_IMAGE_ONLY" ? "555000111" : "555000222",
      attempt: 1,
      event: "workflow_dispatch",
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: sha("b", 40),
      actor: POLICY.reviewer,
      actorId: POLICY.reviewerId,
      triggeringActor: POLICY.reviewer,
      triggeringActorId: POLICY.reviewerId,
      pullRequestCount: 0,
    },
    secretNames: [...purposePolicy.secrets],
    image: purpose === "RELEASE_IMAGE_ONLY" ? null : {
      reference: `ghcr.io/ronmel71/hfs-selger-app@sha256:${sha("9")}`,
      digest: `sha256:${sha("9")}`,
      publicationRunId: "555000111",
      publicationControllerHead: sha("e", 40),
      publicationWorkflowBlob: sha("f", 40),
      publicationRequestId: sha("8"),
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

function resign(request) {
  return finalizeRequest(request);
}

function nativeEvidence(request, environmentId = 123456789) {
  const name = POLICY.purposes[request.purpose].environment;
  const runUrl = `https://api.github.com/repos/${POLICY.controllerRepository}/actions/runs/${request.run.id}`;
  return {
    expectedEnvironmentId: environmentId,
    nowEpoch: now,
    run: {
      id: Number(request.run.id),
      run_attempt: 1,
      event: "workflow_dispatch",
      head_branch: "main",
      head_sha: request.controller.head,
      repository: { full_name: POLICY.controllerRepository },
      status: "in_progress",
      conclusion: null,
      created_at: new Date((now - 100) * 1000).toISOString(),
      updated_at: new Date((now - 10) * 1000).toISOString(),
    },
    approvals: [{
      state: "approved",
      user: { login: POLICY.reviewer, id: POLICY.reviewerId },
      environments: [{ name, id: environmentId }],
    }],
    jobInventory: {
      total_count: 2,
      jobs: [
        {
          id: 700001,
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
          id: 700002,
          run_id: Number(request.run.id),
          run_attempt: 1,
          head_sha: request.controller.head,
          head_branch: "main",
          run_url: runUrl,
          name: `${POLICY.purposes[request.purpose].protectedJobName} · ${request.app.commit}`,
          status: "in_progress",
          conclusion: null,
          created_at: new Date((now - 89) * 1000).toISOString(),
          started_at: new Date((now - 60) * 1000).toISOString(),
          completed_at: null,
        },
      ],
    },
    environment: {
      id: environmentId,
      name,
      can_admins_bypass: false,
      protection_rules: [
        {
          type: "required_reviewers",
          prevent_self_review: false,
          reviewers: [{ type: "User", reviewer: { login: POLICY.reviewer, id: POLICY.reviewerId } }],
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

describe("release controller request contract", () => {
  it("pins the two real purpose-specific protected environment IDs", () => {
    assert.equal(POLICY.purposes.RELEASE_IMAGE_ONLY.environmentId, 27579543667);
    assert.equal(POLICY.purposes.RELEASE_DEPLOY_ONLY.environmentId, 27579657157);
    assert.notEqual(POLICY.purposes.RELEASE_IMAGE_ONLY.environmentId, POLICY.purposes.RELEASE_DEPLOY_ONLY.environmentId);
  });

  it("accepts separate image and deploy requests without pre-claiming native approval", () => {
    for (const purpose of ["RELEASE_IMAGE_ONLY", "RELEASE_DEPLOY_ONLY"]) {
      const request = fixture(purpose);
      assert.equal("nativeApproval" in request, false);
      assert.equal(validateRequest(request, options(request)).purpose, purpose);
    }
  });

  it("accepts two different approved app releases on one unchanged controller policy", () => {
    const first = fixture();
    const second = fixture();
    second.app.commit = sha("3", 40);
    second.app.tree = sha("4", 40);
    const rebound = resign(second);
    assert.equal(validateRequest(first, options(first)).appCommit, APP_COMMIT);
    assert.equal(validateRequest(rebound, options(rebound)).appCommit, sha("3", 40));
    assert.notEqual(first.requestId, rebound.requestId);
  });

  for (const [name, purpose, mutate, code] of [
    ["wrong repository", "RELEASE_IMAGE_ONLY", (r) => { r.app.repository = "attacker/fork"; }, "CONTRACT_APP_PIN"],
    ["malformed app commit", "RELEASE_IMAGE_ONLY", (r) => { r.app.commit = "refs/heads/staging"; }, "CONTRACT_APP_PIN"],
    ["malformed app tree", "RELEASE_IMAGE_ONLY", (r) => { r.app.tree = sha("A", 40); }, "CONTRACT_APP_PIN"],
    ["wrong app workflow blob", "RELEASE_IMAGE_ONLY", (r) => { r.app.workflowBlob = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["wrong deploy helper blob", "RELEASE_DEPLOY_ONLY", (r) => { r.app.helperBlob = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["mutable controller ref", "RELEASE_IMAGE_ONLY", (r) => { r.controller.ref = "refs/tags/latest"; }, "CONTRACT_CONTROLLER_PIN"],
    ["wrong controller workflow", "RELEASE_IMAGE_ONLY", (r) => { r.controller.workflow = ".github/workflows/other.yml"; }, "CONTRACT_CONTROLLER_PIN"],
    ["mismatched controller head", "RELEASE_IMAGE_ONLY", (r) => { r.run.head = sha("8", 40); }, "CONTRACT_RUN"],
    ["attempt two", "RELEASE_IMAGE_ONLY", (r) => { r.run.attempt = 2; }, "CONTRACT_RUN"],
    ["third-party actor", "RELEASE_IMAGE_ONLY", (r) => { r.run.actor = "attacker"; }, "CONTRACT_RUN"],
    ["fork pull request", "RELEASE_IMAGE_ONLY", (r) => { r.run.pullRequestCount = 1; }, "CONTRACT_RUN"],
    ["wrong image purpose", "RELEASE_IMAGE_ONLY", (r) => { r.approvalPurpose = "APPROVE_DEPLOY"; }, "CONTRACT_PURPOSE"],
    ["stale request", "RELEASE_IMAGE_ONLY", (r) => { r.createdAtEpoch = now - 1_801; r.expiresAtEpoch = now + 1; }, "CONTRACT_FRESHNESS"],
    ["expired request", "RELEASE_DEPLOY_ONLY", (r) => { r.expiresAtEpoch = now; }, "CONTRACT_FRESHNESS"],
    ["underprivileged image secrets", "RELEASE_IMAGE_ONLY", (r) => { r.secretNames.pop(); }, "CONTRACT_SECRET_SCOPE"],
    ["overprivileged image secrets", "RELEASE_IMAGE_ONLY", (r) => { r.secretNames.push("DEPLOY_SSH_KEY"); }, "CONTRACT_SECRET_SCOPE"],
    ["deploy publisher credential", "RELEASE_DEPLOY_ONLY", (r) => { r.secretNames.push("HFS_GHCR_PUBLISH_TOKEN"); }, "CONTRACT_SECRET_SCOPE"],
    ["unknown image digest", "RELEASE_DEPLOY_ONLY", (r) => { r.image.digest = "sha256:unknown"; }, "CONTRACT_IMAGE_BINDING"],
    ["mismatched digest", "RELEASE_DEPLOY_ONLY", (r) => { r.image.digest = `sha256:${sha("3")}`; }, "CONTRACT_IMAGE_BINDING"],
    ["wrong publication run", "RELEASE_DEPLOY_ONLY", (r) => { r.image.publicationRunId = "latest"; }, "CONTRACT_IMAGE_BINDING"],
    ["shell metacharacter in nonce", "RELEASE_DEPLOY_ONLY", (r) => { r.nonce = `${sha("a", 63)};`; }, "CONTRACT_IDENTIFIER"],
    ["unexpected native approval", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval = { state: "approved" }; }, "CONTRACT_FIELDS"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture(purpose);
      mutate(request);
      const signed = code === "CONTRACT_IDENTIFIER" || code === "CONTRACT_FIELDS" ? request : resign(request);
      assert.throws(() => validateRequest(signed, options(signed)), new RegExp(code));
    });
  }

  it("rejects duplicate, rerun, and missing consumers", () => {
    const request = fixture();
    const exact = options(request).inventory[0];
    assert.throws(() => validateRequest(request, { nowEpoch: now, inventory: [exact, { ...exact, runId: "555000999" }] }), /CONTRACT_REPLAY/);
    assert.throws(() => validateRequest(request, { nowEpoch: now, inventory: [{ ...exact, attempt: 2 }] }), /CONTRACT_REPLAY/);
    assert.throws(() => validateRequest(request, { nowEpoch: now, inventory: [] }), /CONTRACT_REPLAY/);
  });

  it("accepts only full read-back image digests", () => {
    const request = fixture();
    const reference = `ghcr.io/ronmel71/hfs-selger-app@sha256:${sha("9")}`;
    assert.equal(validatePublishedImage(request, reference), `sha256:${sha("9")}`);
    assert.throws(() => validatePublishedImage(request, "ghcr.io/ronmel71/hfs-selger-app:latest"), /CONTRACT_PUBLISHED_DIGEST/);
  });
});

describe("post-gate native approval evidence", () => {
  it("accepts timestamp-free approval as a bounded interval before the exact gated job", () => {
    const request = fixture();
    const result = validateNativeApprovalEvidence(request, nativeEvidence(request));
    assert.equal(result.reviewerId, POLICY.reviewerId);
    assert.equal(result.approvalNotBeforeEpoch, now - 100);
    assert.equal(result.approvalNotAfterEpoch, now - 60);
    assert.equal("approvedAtEpoch" in result, false);
  });

  for (const [name, mutate, code] of [
    ["unconfigured environment ID", (e) => { e.expectedEnvironmentId = null; }, "NATIVE_ENVIRONMENT_ID_UNCONFIGURED"],
    ["missing approval", (e) => { e.approvals = []; }, "NATIVE_APPROVAL_COUNT"],
    ["extra approval", (e) => { e.approvals.push(structuredClone(e.approvals[0])); }, "NATIVE_APPROVAL_COUNT"],
    ["extra required reviewer", (e) => { e.environment.protection_rules[0].reviewers.push({ type: "User", reviewer: { login: "attacker", id: 7 } }); }, "NATIVE_REVIEW_POLICY"],
    ["other reviewer", (e) => { e.approvals[0].user.login = "attacker"; }, "NATIVE_APPROVAL"],
    ["wrong environment", (e) => { e.approvals[0].environments[0].name = "production-host-deployment"; }, "NATIVE_APPROVAL"],
    ["wrong environment ID", (e) => { e.approvals[0].environments[0].id += 1; }, "NATIVE_APPROVAL"],
    ["admin bypass", (e) => { e.environment.can_admins_bypass = true; }, "NATIVE_ENVIRONMENT"],
    ["self-review deadlock", (e) => { e.environment.protection_rules[0].prevent_self_review = true; }, "NATIVE_REVIEW_POLICY"],
    ["missing gated job", (e) => { e.jobInventory.jobs.pop(); e.jobInventory.total_count = 1; }, "NATIVE_JOB_INVENTORY"],
    ["partial job inventory", (e) => { e.jobInventory.total_count = 3; }, "NATIVE_JOB_INVENTORY"],
    ["duplicate job record", (e) => { e.jobInventory.jobs[1].id = e.jobInventory.jobs[0].id; }, "NATIVE_JOB_INVENTORY"],
    ["similarly named ungated job", (e) => { e.jobInventory.jobs[1].name += " copy"; }, "NATIVE_JOB_IDENTITY"],
    ["wrong gated job SHA", (e) => { e.jobInventory.jobs[1].head_sha = "7".repeat(40); }, "NATIVE_JOB_PROVENANCE"],
    ["wrong gated job attempt", (e) => { e.jobInventory.jobs[1].run_attempt = 2; }, "NATIVE_JOB_PROVENANCE"],
    ["gate starts after request expiry", (e) => { e.jobInventory.jobs[1].started_at = new Date((now + 601) * 1000).toISOString(); }, "NATIVE_JOB_ORDER"],
    ["expired current execution", (e) => { e.nowEpoch = now + 601; }, "NATIVE_APPROVAL_FRESHNESS"],
    ["unprotected main", (e) => { e.branchProtection.enforce_admins.enabled = false; }, "NATIVE_MAIN_PROTECTION"],
    ["force pushes allowed on main", (e) => { e.branchProtection.allow_force_pushes.enabled = true; }, "NATIVE_MAIN_PROTECTION"],
    ["deletion allowed on main", (e) => { e.branchProtection.allow_deletions.enabled = true; }, "NATIVE_MAIN_PROTECTION"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture();
      const evidence = nativeEvidence(request);
      mutate(evidence);
      assert.throws(() => validateNativeApprovalEvidence(request, evidence), new RegExp(code));
    });
  }

  it("accepts completed historical execution only when the exact gated job finished inside its original lifetime", () => {
    const request = fixture();
    const evidence = nativeEvidence(request);
    evidence.allowHistorical = true;
    evidence.run.status = "completed";
    evidence.run.conclusion = "success";
    evidence.jobInventory.jobs[1].status = "completed";
    evidence.jobInventory.jobs[1].conclusion = "success";
    evidence.jobInventory.jobs[1].completed_at = new Date((now - 10) * 1000).toISOString();
    assert.equal(validateNativeApprovalEvidence(request, evidence).protectedJobId, 700002);
    evidence.jobInventory.jobs[1].completed_at = new Date((now + 601) * 1000).toISOString();
    assert.throws(() => validateNativeApprovalEvidence(request, evidence), /NATIVE_JOB_ORDER/);
  });
});
