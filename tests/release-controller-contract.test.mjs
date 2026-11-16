import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { POLICY, finalizeRequest, validatePublishedImage, validateRequest } from "../scripts/release-controller-contract.mjs";

const now = 1_800_000_000;
const sha = (character, length = 64) => character.repeat(length);

function fixture(purpose = "RELEASE_IMAGE_ONLY") {
  const purposePolicy = POLICY.purposes[purpose];
  const request = {
    schema: POLICY.schema,
    purpose,
    approvalPurpose: purposePolicy.approvalPurpose,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 60,
    expiresAtEpoch: now + 1_200,
    app: {
      repository: POLICY.appRepository,
      ref: POLICY.appRef,
      commit: POLICY.appCommit,
      tree: POLICY.appTree,
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
      id: "555000111",
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
    nativeApproval: {
      state: "approved",
      reviewer: POLICY.reviewer,
      reviewerId: POLICY.reviewerId,
      environment: purposePolicy.environment,
      approvalCount: 1,
      canAdminsBypass: false,
      preventSelfReview: false,
    },
    secretNames: [...purposePolicy.secrets],
    image: purpose === "RELEASE_IMAGE_ONLY" ? null : {
      reference: `ghcr.io/ronmel71/hfs-selger-app@sha256:${sha("e")}`,
      digest: `sha256:${sha("e")}`,
      publicationRunId: "555000000",
      publicationControllerHead: sha("f", 40),
      publicationWorkflowBlob: sha("1", 40),
      publicationRequestId: sha("2"),
    },
  };
  return finalizeRequest(request);
}

function options(request) {
  return {
    nowEpoch: now,
    inventory: [{ requestId: request.requestId, nonce: request.nonce, purpose: request.purpose, runId: request.run.id, attempt: 1 }],
  };
}

function resign(request) {
  request.requestId = sha("0");
  return finalizeRequest(request);
}

describe("public release controller contract", () => {
  it("accepts distinct exact image and deploy bindings", () => {
    for (const purpose of ["RELEASE_IMAGE_ONLY", "RELEASE_DEPLOY_ONLY"]) {
      const request = fixture(purpose);
      assert.deepEqual(validateRequest(request, options(request)), {
        purpose,
        requestId: request.requestId,
        appCommit: POLICY.appCommit,
      });
    }
  });

  for (const [name, purpose, mutate, code] of [
    ["wrong app repository", "RELEASE_IMAGE_ONLY", (r) => { r.app.repository = "attacker/fork"; }, "CONTRACT_APP_PIN"],
    ["wrong app ref", "RELEASE_IMAGE_ONLY", (r) => { r.app.ref = "refs/heads/main"; }, "CONTRACT_APP_PIN"],
    ["wrong app commit", "RELEASE_IMAGE_ONLY", (r) => { r.app.commit = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["wrong app tree", "RELEASE_IMAGE_ONLY", (r) => { r.app.tree = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["wrong app workflow blob", "RELEASE_IMAGE_ONLY", (r) => { r.app.workflowBlob = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["wrong deploy helper blob", "RELEASE_DEPLOY_ONLY", (r) => { r.app.helperBlob = sha("3", 40); }, "CONTRACT_APP_PIN"],
    ["mutable controller ref", "RELEASE_IMAGE_ONLY", (r) => { r.controller.ref = "refs/tags/latest"; }, "CONTRACT_CONTROLLER_PIN"],
    ["wrong controller workflow", "RELEASE_IMAGE_ONLY", (r) => { r.controller.workflow = ".github/workflows/other.yml"; }, "CONTRACT_CONTROLLER_PIN"],
    ["mismatched controller head", "RELEASE_IMAGE_ONLY", (r) => { r.run.head = sha("8", 40); }, "CONTRACT_RUN"],
    ["attempt two", "RELEASE_IMAGE_ONLY", (r) => { r.run.attempt = 2; }, "CONTRACT_RUN"],
    ["third-party actor", "RELEASE_IMAGE_ONLY", (r) => { r.run.actor = "attacker"; }, "CONTRACT_RUN"],
    ["fork pull request", "RELEASE_IMAGE_ONLY", (r) => { r.run.pullRequestCount = 1; }, "CONTRACT_RUN"],
    ["wrong reviewer", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval.reviewer = "attacker"; }, "CONTRACT_NATIVE_APPROVAL"],
    ["missing approval", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval.state = "pending"; }, "CONTRACT_NATIVE_APPROVAL"],
    ["duplicate approvals", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval.approvalCount = 2; }, "CONTRACT_NATIVE_APPROVAL"],
    ["admin bypass on", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval.canAdminsBypass = true; }, "CONTRACT_NATIVE_APPROVAL"],
    ["self-review prevention deadlock", "RELEASE_IMAGE_ONLY", (r) => { r.nativeApproval.preventSelfReview = true; }, "CONTRACT_NATIVE_APPROVAL"],
    ["wrong protected environment", "RELEASE_DEPLOY_ONLY", (r) => { r.nativeApproval.environment = "production-image-publication"; }, "CONTRACT_NATIVE_APPROVAL"],
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
    ["unexpected URL field", "RELEASE_IMAGE_ONLY", (r) => { r.callbackUrl = "http://169.254.169.254"; }, "CONTRACT_FIELDS"],
  ]) {
    it(`rejects ${name}`, () => {
      const request = fixture(purpose);
      mutate(request);
      const signed = code === "CONTRACT_IDENTIFIER" || code === "CONTRACT_FIELDS" ? request : resign(request);
      assert.throws(() => validateRequest(signed, options(signed)), new RegExp(code));
    });
  }

  it("rejects a changed request, duplicate consumer, rerun consumer, and missing consumer", () => {
    let request = fixture();
    request.app.commit = sha("4", 40);
    assert.throws(() => validateRequest(request, options(request)), /CONTRACT_APP_PIN|CONTRACT_REQUEST_ID/);

    request = fixture();
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
