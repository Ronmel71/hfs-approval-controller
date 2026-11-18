import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { POLICY, finalizeRequest } from "../scripts/release-controller-contract.mjs";
import { attestPrivateAppSource, validateRequestPhase, verifyNativeApprovalPhase } from "../scripts/release-controller-preflight.mjs";

const originalFetch = globalThis.fetch;
const originalEnvironment = { ...process.env };
const now = Math.floor(Date.now() / 1000);
const sha = (character, length = 64) => character.repeat(length);
const iso = (epoch) => new Date(epoch * 1000).toISOString();
const APP_COMMIT = sha("1", 40);
const APP_TREE = sha("2", 40);
const STAGING_HEAD = sha("3", 40);
const SUPERSEDED_HELPER_BLOB = "30ee1ec77efe72d754a17ecc839f0cfa581542ce";
const PREVIOUS_HELPER_BLOB = "76e408175ac0ff8b207665475f9f5d1240766738";

function jsonResponse(value, status = 200) {
  return {
    status,
    url: "https://api.github.com/mock",
    headers: { get: () => "application/json" },
    json: async () => structuredClone(value),
  };
}

function bytesResponse(value, status = 200) {
  return {
    status,
    url: "https://pipelines.actions.githubusercontent.com/mock",
    headers: { get: () => "application/zip" },
    arrayBuffer: async () => value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
  };
}

function storedZip(name, text) {
  const file = Buffer.from(text);
  const fileName = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(file.length, 18);
  local.writeUInt32LE(file.length, 22);
  local.writeUInt16LE(fileName.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(file.length, 20);
  central.writeUInt32LE(file.length, 24);
  central.writeUInt16LE(fileName.length, 28);
  central.writeUInt32LE(0, 42);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length + fileName.length, 12);
  eocd.writeUInt32LE(local.length + fileName.length + file.length, 16);
  return Buffer.concat([local, fileName, file, central, fileName, eocd]);
}

function appPins() {
  return {
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
  };
}

function runFields(run) {
  return {
    id: String(run.id),
    attempt: run.run_attempt,
    event: run.event,
    repository: POLICY.controllerRepository,
    ref: POLICY.controllerRef,
    head: run.head_sha,
    actor: POLICY.reviewer,
    actorId: POLICY.reviewerId,
    triggeringActor: POLICY.reviewer,
    triggeringActorId: POLICY.reviewerId,
    pullRequestCount: 0,
  };
}

function githubRun(id, workflow, head) {
  return {
    id,
    repository: { full_name: POLICY.controllerRepository, private: false, fork: false },
    head_repository: { full_name: POLICY.controllerRepository, fork: false },
    path: `${workflow}@refs/heads/main`,
    head_branch: "main",
    head_sha: head,
    event: "workflow_dispatch",
    run_attempt: 1,
    actor: { login: POLICY.reviewer, id: POLICY.reviewerId },
    triggering_actor: { login: POLICY.reviewer, id: POLICY.reviewerId },
    pull_requests: [],
    status: "completed",
    conclusion: "success",
    created_at: iso(now - 100),
    updated_at: iso(now - 10),
  };
}

function jobInventory(run, purpose, { historical = false, requestCreated = now - 120, requestExpires = now + 600 } = {}) {
  const runUrl = `https://api.github.com/repos/${POLICY.controllerRepository}/actions/runs/${run.id}`;
  const runCreated = Math.floor(Date.parse(run.created_at) / 1000);
  const evidenceStart = Math.max(requestCreated, runCreated);
  const protectedStarted = Math.max(evidenceStart + 10, now - 60);
  return {
    total_count: 2,
    jobs: [
      {
        id: run.id * 10 + 1,
        run_id: run.id,
        run_attempt: 1,
        head_sha: run.head_sha,
        head_branch: "main",
        run_url: runUrl,
        name: "validate-request",
        status: "completed",
        conclusion: "success",
        created_at: run.created_at,
        started_at: iso(evidenceStart + 1),
        completed_at: iso(evidenceStart + 5),
      },
      {
        id: run.id * 10 + 2,
        run_id: run.id,
        run_attempt: 1,
        head_sha: run.head_sha,
        head_branch: "main",
        run_url: runUrl,
        name: `${POLICY.purposes[purpose].protectedJobName} · ${APP_COMMIT}`,
        status: historical ? "completed" : "in_progress",
        conclusion: historical ? "success" : null,
        created_at: iso(evidenceStart + 6),
        started_at: iso(protectedStarted),
        completed_at: historical ? iso(Math.min(protectedStarted + 10, requestExpires - 1)) : null,
      },
    ],
  };
}

function environment(name, id) {
  return {
    id,
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
  };
}

function privateSourceResponse(url, request, mutate = () => {}) {
  const path = new URL(url).pathname;
  const prefix = `/repos/${POLICY.appRepository}`;
  if (!path.startsWith(prefix)) return null;
  const state = {
    repository: { full_name: POLICY.appRepository, private: true, fork: false },
    ref: { ref: POLICY.appRef, object: { sha: STAGING_HEAD } },
    commit: { sha: request.app.commit, commit: { tree: { sha: request.app.tree } } },
    comparison: { status: "ahead", base_commit: { sha: request.app.commit }, merge_base_commit: { sha: request.app.commit } },
    blobs: new Map([
      [POLICY.appWorkflow, POLICY.appWorkflowBlob],
      ["deploy/production/docker-compose.yml", POLICY.composeBlob],
      ["deploy/production/Caddyfile", POLICY.caddyBlob],
      ["deploy/production/host/hfs-deploy-release", POLICY.helperBlob],
      ["deploy/production/host/hfsdeploy-sudoers", POLICY.sudoersBlob],
    ]),
  };
  mutate(state);
  if (path === prefix) return jsonResponse(state.repository);
  if (path === `${prefix}/git/ref/heads/staging`) return jsonResponse(state.ref);
  if (path === `${prefix}/commits/${request.app.commit}`) return jsonResponse(state.commit);
  if (path === `${prefix}/compare/${request.app.commit}...${STAGING_HEAD}`) return jsonResponse(state.comparison);
  for (const [file, blob] of state.blobs) if (path === `${prefix}/contents/${file}`) return jsonResponse({ sha: blob });
  return null;
}

const branchProtection = {
  enforce_admins: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
};

function configureImage() {
  const policy = POLICY.purposes.RELEASE_IMAGE_ONLY;
  const run = githubRun(555000111, policy.workflow, sha("b", 40));
  run.status = "in_progress";
  run.conclusion = null;
  const request = finalizeRequest({
    schema: POLICY.schema,
    purpose: "RELEASE_IMAGE_ONLY",
    approvalPurpose: policy.approvalPurpose,
    requestId: sha("0"),
    nonce: sha("a"),
    createdAtEpoch: now - 120,
    expiresAtEpoch: now + 600,
    app: appPins(),
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: run.head_sha,
      workflow: policy.workflow,
      workflowBlob: sha("c", 40),
      executor: policy.executor,
      executorBlob: sha("d", 40),
    },
    run: runFields(run),
    secretNames: [...policy.secrets],
    image: null,
  });
  run.display_title = `Release image only · RELEASE_IMAGE_ONLY · ${request.app.commit} · ${request.requestId} · ${request.nonce}`;
  setRequestEnvironment(request);
  return { request, run };
}

function setRequestEnvironment(request) {
  Object.assign(process.env, {
    GH_TOKEN: "synthetic-token",
    HFS_CONTROLLER_ADMIN_READ_TOKEN: "synthetic-admin-read-token",
    HFS_PRIVATE_SOURCE_READ_TOKEN: "synthetic-private-source-token",
    GITHUB_RUN_ID: String(request.run.id),
    HFS_RELEASE_PURPOSE: request.purpose,
    HFS_REQUEST_ID: request.requestId,
    HFS_NONCE: request.nonce,
    HFS_CREATED_AT_EPOCH: String(request.createdAtEpoch),
    HFS_EXPIRES_AT_EPOCH: String(request.expiresAtEpoch),
    HFS_APP_COMMIT: request.app.commit,
    HFS_APP_TREE: request.app.tree,
    HFS_CONTROLLER_HEAD: request.controller.head,
    HFS_CONTROLLER_WORKFLOW_BLOB: request.controller.workflowBlob,
    HFS_CONTROLLER_EXECUTOR_BLOB: request.controller.executorBlob,
  });
  if (request.image) {
    Object.assign(process.env, {
      HFS_IMAGE_REFERENCE: request.image.reference,
      HFS_PUBLICATION_RUN_ID: String(request.image.publicationRunId),
      HFS_PUBLICATION_REQUEST_ID: request.image.publicationRequestId,
      HFS_PUBLICATION_CONTROLLER_HEAD: request.image.publicationControllerHead,
      HFS_PUBLICATION_WORKFLOW_BLOB: request.image.publicationWorkflowBlob,
    });
  }
}

function configureDeploy(mutate = () => {}) {
  const imagePolicy = POLICY.purposes.RELEASE_IMAGE_ONLY;
  const deployPolicy = POLICY.purposes.RELEASE_DEPLOY_ONLY;
  const imageRun = githubRun(555000111, imagePolicy.workflow, sha("e", 40));
  const imageRequest = finalizeRequest({
    schema: POLICY.schema,
    purpose: "RELEASE_IMAGE_ONLY",
    approvalPurpose: imagePolicy.approvalPurpose,
    requestId: sha("0"),
    nonce: sha("1"),
    createdAtEpoch: now - 200,
    expiresAtEpoch: now + 500,
    app: appPins(),
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: imageRun.head_sha,
      workflow: imagePolicy.workflow,
      workflowBlob: sha("f", 40),
      executor: imagePolicy.executor,
      executorBlob: sha("a", 40),
    },
    run: runFields(imageRun),
    secretNames: [...imagePolicy.secrets],
    image: null,
  });
  imageRun.display_title = `Release image only · RELEASE_IMAGE_ONLY · ${imageRequest.app.commit} · ${imageRequest.requestId} · ${imageRequest.nonce}`;
  const reference = `ghcr.io/ronmel71/hfs-selger-app@sha256:${sha("9")}`;
  const deployRun = githubRun(555000222, deployPolicy.workflow, sha("b", 40));
  deployRun.status = "in_progress";
  deployRun.conclusion = null;
  deployRun.created_at = iso(now - 20);
  deployRun.updated_at = iso(now - 5);
  const state = {
    imageRun,
    imageRequest,
    reference,
    imageEnvironmentId: 101010,
    approvals: [{
      state: "approved",
      user: { login: POLICY.reviewer, id: POLICY.reviewerId },
      environments: [{ name: imagePolicy.environment, id: 101010 }],
    }],
    imageEnvironment: environment(imagePolicy.environment, 101010),
    deployEnvironmentId: 202020,
    workflowSha: imageRequest.controller.workflowBlob,
    executorSha: imageRequest.controller.executorBlob,
    artifactsMissing: false,
    artifactDigestWrong: false,
    apiDenied: false,
  };
  state.manifest = {
    schema: POLICY.provenanceSchema,
    purpose: "RELEASE_IMAGE_ONLY",
    approvalPurpose: imagePolicy.approvalPurpose,
    requestId: imageRequest.requestId,
    nonce: imageRequest.nonce,
    createdAtEpoch: imageRequest.createdAtEpoch,
    expiresAtEpoch: imageRequest.expiresAtEpoch,
    publicationRunId: String(imageRun.id),
    controllerRepository: POLICY.controllerRepository,
    controllerRef: POLICY.controllerRef,
    controllerHead: imageRun.head_sha,
    controllerWorkflow: imagePolicy.workflow,
    controllerWorkflowBlob: imageRequest.controller.workflowBlob,
    controllerExecutor: imagePolicy.executor,
    controllerExecutorBlob: imageRequest.controller.executorBlob,
    appRepository: POLICY.appRepository,
    appRef: POLICY.appRef,
    appCommit: APP_COMMIT,
    appTree: APP_TREE,
    imageReference: reference,
    imageDigest: reference.split("@")[1],
    publishedAtEpoch: now - 40,
  };
  state.imageJobs = jobInventory(imageRun, "RELEASE_IMAGE_ONLY", {
    historical: true,
    requestCreated: imageRequest.createdAtEpoch,
    requestExpires: imageRequest.expiresAtEpoch,
  });
  mutate(state);
  const deployRequest = finalizeRequest({
    schema: POLICY.schema,
    purpose: "RELEASE_DEPLOY_ONLY",
    approvalPurpose: deployPolicy.approvalPurpose,
    requestId: sha("0"),
    nonce: sha("2"),
    createdAtEpoch: now - 30,
    expiresAtEpoch: now + 500,
    app: appPins(),
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: deployRun.head_sha,
      workflow: deployPolicy.workflow,
      workflowBlob: sha("c", 40),
      executor: deployPolicy.executor,
      executorBlob: sha("d", 40),
    },
    run: runFields(deployRun),
    secretNames: [...deployPolicy.secrets],
    image: {
      reference: state.reference,
      digest: state.reference.split("@")[1],
      publicationRunId: String(state.imageRun.id),
      publicationControllerHead: state.imageRun.head_sha,
      publicationWorkflowBlob: state.imageRequest.controller.workflowBlob,
      publicationRequestId: state.imageRequest.requestId,
    },
  });
  deployRun.display_title = `Release deploy only · RELEASE_DEPLOY_ONLY · ${deployRequest.app.commit} · ${deployRequest.requestId} · ${deployRequest.nonce} · publication ${deployRequest.image.publicationRunId}`;
  setRequestEnvironment(deployRequest);
  state.deployRun = deployRun;
  state.deployRequest = deployRequest;
  state.deployJobs = jobInventory(deployRun, "RELEASE_DEPLOY_ONLY", {
    requestCreated: deployRequest.createdAtEpoch,
    requestExpires: deployRequest.expiresAtEpoch,
  });
  state.inventory = [deployRun, state.imageRun];
  state.zip = storedZip(POLICY.provenanceArtifactFile, `${JSON.stringify(state.manifest)}\n`);
  state.artifact = {
    id: 777000111,
    name: POLICY.provenanceArtifactName,
    expired: false,
    created_at: iso(now - 30),
    digest: state.artifactDigestWrong ? `sha256:${sha("0")}` : `sha256:${createHash("sha256").update(state.zip).digest("hex")}`,
    workflow_run: { id: state.imageRun.id, head_sha: state.imageRun.head_sha },
  };
  installDeployFetch(state);
  return state;
}

function installDeployFetch(state) {
  globalThis.fetch = async (url) => {
    if (state.apiDenied) return jsonResponse({}, 403);
    const source = privateSourceResponse(url, state.deployRequest);
    if (source) return source;
    const parsed = new URL(url);
    const path = `${parsed.pathname}${parsed.search}`;
    if (path.endsWith(`/actions/runs/${state.deployRun.id}`)) return jsonResponse(state.deployRun);
    if (path.endsWith(`/actions/runs/${state.imageRun.id}`)) return jsonResponse(state.imageRun);
    if (path.includes(`/actions/runs/${state.deployRun.id}/attempts/1/jobs`)) return jsonResponse(state.deployJobs);
    if (path.includes(`/actions/runs/${state.imageRun.id}/attempts/1/jobs`)) return jsonResponse(state.imageJobs);
    if (path.includes("/actions/runs?")) return jsonResponse({ total_count: state.inventory.length, workflow_runs: state.inventory });
    if (path.endsWith(`/actions/runs/${state.imageRun.id}/approvals`)) return jsonResponse(state.approvals);
    if (path.endsWith(`/actions/runs/${state.deployRun.id}/approvals`)) {
      return jsonResponse([{ state: "approved", user: { login: POLICY.reviewer, id: POLICY.reviewerId }, environments: [{ name: POLICY.purposes.RELEASE_DEPLOY_ONLY.environment, id: state.deployEnvironmentId }] }]);
    }
    if (path.includes(`/environments/${POLICY.purposes.RELEASE_IMAGE_ONLY.environment}`)) return jsonResponse(state.imageEnvironment);
    if (path.includes(`/environments/${POLICY.purposes.RELEASE_DEPLOY_ONLY.environment}`)) return jsonResponse(environment(POLICY.purposes.RELEASE_DEPLOY_ONLY.environment, state.deployEnvironmentId));
    if (path.endsWith("/branches/main/protection")) return jsonResponse(branchProtection);
    if (path.includes(`/contents/${POLICY.purposes.RELEASE_IMAGE_ONLY.workflow}`)) return jsonResponse({ sha: state.workflowSha });
    if (path.includes(`/contents/${POLICY.purposes.RELEASE_IMAGE_ONLY.executor}`)) return jsonResponse({ sha: state.executorSha });
    if (path.endsWith(`/actions/runs/${state.imageRun.id}/artifacts?per_page=100`)) {
      return jsonResponse({ total_count: state.artifactsMissing ? 0 : 1, artifacts: state.artifactsMissing ? [] : [state.artifact] });
    }
    if (path.endsWith(`/actions/artifacts/${state.artifact.id}/zip`)) return bytesResponse(state.zip);
    throw new Error(`unexpected URL ${url}`);
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const key of Object.keys(process.env)) if (!(key in originalEnvironment)) delete process.env[key];
  Object.assign(process.env, originalEnvironment);
});

describe("release controller phased preflight", () => {
  it("validates a pre-gate request without reading approvals", async () => {
    const { run } = configureImage();
    globalThis.fetch = async (url) => {
      if (url.endsWith(`/actions/runs/${run.id}`)) return jsonResponse(run);
      return jsonResponse({ total_count: 1, workflow_runs: [run] });
    };
    await assert.doesNotReject(validateRequestPhase());
  });

  it("keeps private source credentials and calls out of the pre-gate phase", async () => {
    const { run } = configureImage();
    delete process.env.HFS_PRIVATE_SOURCE_READ_TOKEN;
    const urls = [];
    globalThis.fetch = async (url) => {
      urls.push(url);
      if (url.endsWith(`/actions/runs/${run.id}`)) return jsonResponse(run);
      return jsonResponse({ total_count: 1, workflow_runs: [run] });
    };
    await assert.doesNotReject(validateRequestPhase());
    assert.equal(urls.some((url) => url.includes(POLICY.appRepository)), false);
  });

  it("rejects duplicate request consumers", async () => {
    const { run } = configureImage();
    const duplicate = { ...run, id: run.id + 1 };
    globalThis.fetch = async (url) => url.endsWith(`/actions/runs/${run.id}`)
      ? jsonResponse(run)
      : jsonResponse({ total_count: 2, workflow_runs: [run, duplicate] });
    await assert.rejects(validateRequestPhase(), /CONTRACT_REPLAY/);
  });

  it("post-gate phase reads real approval and environment evidence", async () => {
    const { request, run } = configureImage();
    const id = 202020;
    globalThis.fetch = async (url) => {
      const source = privateSourceResponse(url, request);
      if (source) return source;
      if (url.endsWith(`/actions/runs/${run.id}`)) return jsonResponse(run);
      if (url.endsWith(`/actions/runs/${run.id}/approvals`)) {
        return jsonResponse([{ state: "approved", user: { login: POLICY.reviewer, id: POLICY.reviewerId }, environments: [{ name: POLICY.purposes.RELEASE_IMAGE_ONLY.environment, id }] }]);
      }
      if (url.includes(`/actions/runs/${run.id}/attempts/1/jobs`)) return jsonResponse(jobInventory(run, "RELEASE_IMAGE_ONLY", { requestCreated: request.createdAtEpoch, requestExpires: request.expiresAtEpoch }));
      if (url.includes("/environments/")) return jsonResponse(environment(POLICY.purposes.RELEASE_IMAGE_ONLY.environment, id));
      if (url.endsWith("/branches/main/protection")) return jsonResponse(branchProtection);
      throw new Error(`unexpected URL ${url}`);
    };
    assert.equal((await verifyNativeApprovalPhase({ expectedEnvironmentId: id })).requestId, request.requestId);
  });

  it("fails closed on approval API denial", async () => {
    configureImage();
    globalThis.fetch = async () => jsonResponse({}, 403);
    await assert.rejects(verifyNativeApprovalPhase({ expectedEnvironmentId: 1 }), /PREFLIGHT_API_HTTP_403/);
  });

  it("fails closed when the dedicated Administration-read credential is absent", async () => {
    const { run } = configureImage();
    delete process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN;
    globalThis.fetch = async (url) => {
      if (url.endsWith(`/actions/runs/${run.id}`)) return jsonResponse(run);
      return jsonResponse({});
    };
    await assert.rejects(verifyNativeApprovalPhase({ expectedEnvironmentId: 1 }), /PREFLIGHT_ADMIN_READ_TOKEN_UNCONFIGURED/);
  });

  it("fails closed when the Administration-read provider denies branch-protection readback", async () => {
    const { run } = configureImage();
    globalThis.fetch = async (url) => {
      if (url.endsWith(`/actions/runs/${run.id}`)) return jsonResponse(run);
      if (url.endsWith("/branches/main/protection")) return jsonResponse({}, 403);
      return jsonResponse({});
    };
    await assert.rejects(verifyNativeApprovalPhase({ expectedEnvironmentId: 1 }), /PREFLIGHT_ADMIN_READ_HTTP_403/);
  });
});

describe("post-approval private source attestation", () => {
  it("accepts the corrected deploy helper blob", async () => {
    const { request } = configureImage();
    globalThis.fetch = async (url) => privateSourceResponse(url, request) ?? jsonResponse({}, 404);
    assert.equal((await attestPrivateAppSource(request)).appCommit, request.app.commit);
  });

  for (const [name, mutate, code] of [
    ["wrong repository", (s) => { s.repository.full_name = "attacker/fork"; }, "SOURCE_ATTESTATION_PIN"],
    ["wrong reviewed branch", (s) => { s.ref.ref = "refs/heads/main"; }, "SOURCE_ATTESTATION_PIN"],
    ["unmerged commit", (s) => { s.comparison.status = "diverged"; }, "SOURCE_ATTESTATION_ANCESTRY"],
    ["tree mismatch", (s) => { s.commit.commit.tree.sha = sha("7", 40); }, "SOURCE_ATTESTATION_PIN"],
    ["altered infrastructure blob", (s) => { s.blobs.set("deploy/production/Caddyfile", sha("7", 40)); }, "SOURCE_ATTESTATION_PIN"],
    ["superseded deploy helper blob", (s) => { s.blobs.set("deploy/production/host/hfs-deploy-release", SUPERSEDED_HELPER_BLOB); }, "SOURCE_ATTESTATION_PIN"],
    ["previous deploy helper blob", (s) => { s.blobs.set("deploy/production/host/hfs-deploy-release", PREVIOUS_HELPER_BLOB); }, "SOURCE_ATTESTATION_PIN"],
  ]) {
    it(`rejects ${name}`, async () => {
      const { request } = configureImage();
      globalThis.fetch = async (url) => privateSourceResponse(url, request, mutate) ?? jsonResponse({}, 404);
      await assert.rejects(attestPrivateAppSource(request), new RegExp(code));
    });
  }

  it("fails closed on private provider API failure", async () => {
    const { request } = configureImage();
    globalThis.fetch = async () => jsonResponse({}, 500);
    await assert.rejects(attestPrivateAppSource(request), /SOURCE_ATTESTATION_RESPONSE/);
  });
});

describe("authoritative image publication provenance", () => {
  it("keeps historical image evidence out of the credential-free deploy pre-gate phase", async () => {
    configureDeploy();
    delete process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN;
    await assert.doesNotReject(validateRequestPhase());
  });

  it("accepts correct mocked run, approval, blobs, immutable artifact bytes, and image linkage", async () => {
    configureDeploy();
    await assert.doesNotReject(verifyNativeApprovalPhase({ expectedEnvironmentId: 202020, publicationEnvironmentId: 101010 }));
  });

  for (const [name, mutate] of [
    ["forged run ID", (s) => { s.imageRun.id += 7; }],
    ["fabricated digest", (s) => { s.reference = `ghcr.io/ronmel71/hfs-selger-app@sha256:${sha("7")}`; }],
    ["mismatched app commit", (s) => { s.manifest.appCommit = sha("7", 40); }],
    ["other controller revision", (s) => { s.imageRun.head_sha = sha("7", 40); }],
    ["missing image gated job", (s) => { s.imageJobs.jobs.pop(); s.imageJobs.total_count = 1; }],
    ["partial image job inventory", (s) => { s.imageJobs.total_count = 3; }],
    ["duplicate image jobs", (s) => { s.imageJobs.jobs[1].id = s.imageJobs.jobs[0].id; }],
    ["wrong image gated job name", (s) => { s.imageJobs.jobs[1].name = "Native approval · RELEASE_IMAGE_ONLY · other"; }],
    ["wrong image gated job SHA", (s) => { s.imageJobs.jobs[1].head_sha = sha("7", 40); }],
    ["wrong image gated job attempt", (s) => { s.imageJobs.jobs[1].run_attempt = 2; }],
    ["late image execution", (s) => { s.imageJobs.jobs[1].completed_at = iso(s.imageRequest.expiresAtEpoch + 1); }],
    ["failed publisher", (s) => { s.imageRun.conclusion = "failure"; }],
    ["retried publisher", (s) => { s.imageRun.run_attempt = 2; }],
    ["mutated publisher workflow", (s) => { s.workflowSha = sha("7", 40); }],
    ["missing artifact", (s) => { s.artifactsMissing = true; }],
    ["wrong artifact digest", (s) => { s.artifactDigestWrong = true; }],
    ["API denial", (s) => { s.apiDenied = true; }],
  ]) {
    it(`rejects ${name} with the fail-closed provenance result`, async () => {
      configureDeploy(mutate);
      await assert.rejects(verifyNativeApprovalPhase({ expectedEnvironmentId: 202020, publicationEnvironmentId: 101010 }), /PROVENANCE_NOT_VERIFIED|PREFLIGHT_RUN_PROVENANCE|PREFLIGHT_API_HTTP_403/);
    });
  }
});
