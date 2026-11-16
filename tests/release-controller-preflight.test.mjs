import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { POLICY, finalizeRequest } from "../scripts/release-controller-contract.mjs";
import { preflight } from "../scripts/release-controller-preflight.mjs";

const originalFetch = globalThis.fetch;
const originalEnvironment = { ...process.env };
const now = Math.floor(Date.now() / 1000);
const sha = (character, length = 64) => character.repeat(length);

function makeResponse(value, status = 200) {
  return { status, headers: { get: () => "application/json" }, json: async () => structuredClone(value) };
}

function configure() {
  const run = {
    id: 555000111,
    repository: { full_name: POLICY.controllerRepository, private: false, fork: false },
    head_repository: { full_name: POLICY.controllerRepository, fork: false },
    path: ".github/workflows/release-image-only.yml@refs/heads/main",
    head_branch: "main",
    head_sha: sha("b", 40),
    event: "workflow_dispatch",
    run_attempt: 1,
    actor: { login: POLICY.reviewer, id: POLICY.reviewerId },
    triggering_actor: { login: POLICY.reviewer, id: POLICY.reviewerId },
    pull_requests: [],
  };
  const request = finalizeRequest({
    schema: POLICY.schema,
    purpose: "RELEASE_IMAGE_ONLY",
    approvalPurpose: "PREPARE_IMAGE",
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 60,
    expiresAtEpoch: now + 600,
    app: {
      repository: POLICY.appRepository, ref: POLICY.appRef, commit: POLICY.appCommit, tree: POLICY.appTree,
      workflow: POLICY.appWorkflow, workflowBlob: POLICY.appWorkflowBlob, composeBlob: POLICY.composeBlob,
      caddyBlob: POLICY.caddyBlob, helperBlob: POLICY.helperBlob, sudoersBlob: POLICY.sudoersBlob,
    },
    controller: {
      repository: POLICY.controllerRepository, ref: POLICY.controllerRef, head: run.head_sha,
      workflow: POLICY.purposes.RELEASE_IMAGE_ONLY.workflow, workflowBlob: sha("c", 40),
      executor: POLICY.purposes.RELEASE_IMAGE_ONLY.executor, executorBlob: sha("d", 40),
    },
    run: {
      id: String(run.id), attempt: 1, event: run.event, repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef, head: run.head_sha, actor: POLICY.reviewer, actorId: POLICY.reviewerId,
      triggeringActor: POLICY.reviewer, triggeringActorId: POLICY.reviewerId, pullRequestCount: 0,
    },
    nativeApproval: {
      state: "approved", reviewer: POLICY.reviewer, reviewerId: POLICY.reviewerId,
      environment: POLICY.purposes.RELEASE_IMAGE_ONLY.environment, approvalCount: 1,
      canAdminsBypass: false, preventSelfReview: false,
    },
    secretNames: [...POLICY.purposes.RELEASE_IMAGE_ONLY.secrets],
    image: null,
  });
  run.display_title = `Release image only · RELEASE_IMAGE_ONLY · ${request.requestId} · ${request.nonce}`;
  Object.assign(process.env, {
    GH_TOKEN: "synthetic-token",
    GITHUB_RUN_ID: String(run.id),
    HFS_RELEASE_PURPOSE: request.purpose,
    HFS_REQUEST_ID: request.requestId,
    HFS_NONCE: request.nonce,
    HFS_CREATED_AT_EPOCH: String(request.createdAtEpoch),
    HFS_EXPIRES_AT_EPOCH: String(request.expiresAtEpoch),
    HFS_CONTROLLER_HEAD: request.controller.head,
    HFS_CONTROLLER_WORKFLOW_BLOB: request.controller.workflowBlob,
    HFS_CONTROLLER_EXECUTOR_BLOB: request.controller.executorBlob,
  });
  return { run, request };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const key of Object.keys(process.env)) if (!(key in originalEnvironment)) delete process.env[key];
  Object.assign(process.env, originalEnvironment);
});
describe("release controller live preflight", () => {
  it("accepts one exact first-attempt controller consumer", async () => {
    const { run } = configure();
    globalThis.fetch = async (url, options) => {
      assert.equal(options.method, "GET");
      assert.equal(options.redirect, "error");
      if (url.endsWith(`/actions/runs/${run.id}`)) return makeResponse(run);
      return makeResponse({ total_count: 1, workflow_runs: [run] });
    };
    await assert.doesNotReject(preflight());
  });

  it("rejects duplicate consumers across repository workflows", async () => {
    const { run } = configure();
    const duplicate = { ...run, id: run.id + 1 };
    globalThis.fetch = async (url) => url.endsWith(`/actions/runs/${run.id}`)
      ? makeResponse(run)
      : makeResponse({ total_count: 2, workflow_runs: [run, duplicate] });
    await assert.rejects(preflight(), /CONTRACT_REPLAY/);
  });

  it("fails closed before validation on API denial", async () => {
    configure();
    globalThis.fetch = async () => makeResponse({}, 403);
    await assert.rejects(preflight(), /PREFLIGHT_API_HTTP_403/);
  });
});
