import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildAuthorization, installRequestId, signAuthorization, validateRunInventory } from "../scripts/install-only-authorization.mjs";

const now = 1_800_000_000;
const sha = (character, length = 64) => character.repeat(length);
const expected = {
  repository: "owner/private-release",
  workflowPath: ".github/workflows/existing-transfer.yml",
  workflowRef: "refs/heads/staging",
  jobName: "independent-install-only-readback",
};
const readbackBytes = Buffer.from("{\"observedAt\":\"2027-01-15T08:00:00.000Z\"}\n");
const request = {
  purpose: "INSTALL_ONLY",
  releaseRepository: expected.repository,
  releaseCommit: sha("a", 40),
  releaseManifestSha256: sha("b"),
  bundleDigestSha256: sha("c"),
  stagedReadbackSha256: "5b8e5f3653bf9b779cf8f35b9fb192261817a729aa89feaefc84007995102d07",
  authorizationNonce: sha("e"),
  expiresAtEpoch: now + 3600,
  installOnly: true,
  startAuthorized: false,
  readbackRunId: 555000111,
  readbackJobId: 555000222,
};

function fixture() {
  const value = {
    run: {
      id: 555000333,
      repository: { full_name: "Ronmel71/hfs-approval-controller", private: false, fork: false },
      head_repository: { full_name: "Ronmel71/hfs-approval-controller", fork: false },
      path: ".github/workflows/install-only-authorization.yml",
      head_branch: "main",
      head_sha: sha("f", 40),
      display_title: "",
      event: "workflow_dispatch",
      run_attempt: 1,
      actor: { login: "Ronmel71", id: 321374159 },
      triggering_actor: { login: "Ronmel71", id: 321374159 },
      pull_requests: [],
    },
    approvals: [{
      state: "approved",
      user: { login: "Ronmel71", id: 321374159 },
      environments: [{ id: 26423058762, name: "production-first-start", can_admins_bypass: false }],
    }],
    privateRun: {
      id: request.readbackRunId,
      repository: { full_name: expected.repository, private: true, fork: false },
      path: expected.workflowPath,
      head_branch: "staging",
      head_sha: request.releaseCommit,
      event: "workflow_dispatch",
      run_attempt: 1,
      status: "completed",
      conclusion: "success",
      pull_requests: [],
    },
    privateJob: {
      id: request.readbackJobId,
      run_id: request.readbackRunId,
      name: expected.jobName,
      head_sha: request.releaseCommit,
      status: "completed",
      conclusion: "success",
    },
    artifact: {
      id: 555000444,
      name: `install-only-readback-${request.authorizationNonce}`,
      expired: false,
      digest: `sha256:${sha("d")}`,
      created_at: "2027-01-15T08:05:00.000Z",
      workflow_run: { id: request.readbackRunId, head_sha: request.releaseCommit },
    },
    request: structuredClone(request),
    readbackBytes,
    expected,
    controllerHeadSha: sha("f", 40),
    now,
  };
  const readbackProvenance = {
    repository: expected.repository,
    workflowPath: expected.workflowPath,
    workflowRef: expected.workflowRef,
    headSha: request.releaseCommit,
    runId: String(value.privateRun.id),
    runAttempt: 1,
    jobId: String(value.privateJob.id),
    jobName: expected.jobName,
    artifactId: String(value.artifact.id),
    artifactName: value.artifact.name,
    artifactDigestSha256: sha("d"),
    observedAt: "2027-01-15T08:00:00.000Z",
    artifactCreatedAt: value.artifact.created_at,
  };
  const requestId = installRequestId({ request: value.request, readbackProvenance, controllerHeadSha: value.controllerHeadSha });
  value.workflowInputs = {
    purpose: "INSTALL_ONLY",
    requestId,
    readbackArtifactId: String(value.artifact.id),
    authorizationNonce: value.request.authorizationNonce,
  };
  value.run.display_title = `Install-only authorization · INSTALL_ONLY · ${requestId} · artifact ${value.artifact.id} · nonce ${value.request.authorizationNonce}`;
  value.inventory = {
    schema: "hfs.production-first-start.install-only-run-inventory/v1",
    complete: true,
    query: { repository: "Ronmel71/hfs-approval-controller", event: "workflow_dispatch", perPage: 100 },
    pages: [{ total_count: 1, workflow_runs: [structuredClone(value.run)] }],
  };
  return value;
}

describe("install-only authorization", () => {
  it("binds native approval, exact controller head, authenticated readback provenance, and a fresh issue time", () => {
    const value = fixture();
    const payload = buildAuthorization(value);
    assert.equal(payload.controllerHeadSha, value.controllerHeadSha);
    assert.equal(payload.purpose, "INSTALL_ONLY");
    assert.equal(payload.requestId, value.workflowInputs.requestId);
    assert.equal(payload.issuedAtEpoch, now);
    assert.equal(payload.readbackProvenance.artifactId, "555000444");
    const { privateKey } = generateKeyPairSync("ed25519");
    assert.match(signAuthorization(payload, privateKey.export({ type: "pkcs8", format: "pem" })).signatureBase64Url, /^[A-Za-z0-9_-]{86}$/);
  });

  for (const [name, mutate, code] of [
    ["changed controller head", (f) => { f.run.head_sha = sha("1", 40); }, "AUTH_CONTROLLER_HEAD"],
    ["attempt two", (f) => { f.run.run_attempt = 2; }, "AUTH_CONTROLLER_RUN"],
    ["spoofed readback run", (f) => { f.privateRun.id += 1; }, "AUTH_READBACK_RUN"],
    ["failed readback job", (f) => { f.privateJob.conclusion = "failure"; }, "AUTH_READBACK_JOB"],
    ["changed release", (f) => { f.privateRun.head_sha = sha("2", 40); }, "AUTH_READBACK_RUN"],
    ["changed readback bytes", (f) => { f.readbackBytes = Buffer.from("changed"); }, "AUTH_READBACK_DIGEST"],
    ["artifact from another run", (f) => { f.artifact.workflow_run.id += 1; }, "AUTH_READBACK_ARTIFACT"],
    ["expired approval", (f) => { f.request.expiresAtEpoch = now; }, "AUTH_EXPIRY"],
    ["audit purpose", (f) => { f.request.purpose = "READ_ONLY_AUDIT_NO_GO"; }, "AUTH_PURPOSE"],
    ["wrong request id", (f) => { f.workflowInputs.requestId = sha("9"); }, "AUTH_REQUEST_ID"],
    ["changed nonce", (f) => { f.workflowInputs.authorizationNonce = sha("9"); }, "AUTH_WORKFLOW_INPUTS"],
    ["24-hour expiry", (f) => { f.request.expiresAtEpoch = now + 86400; }, "AUTH_EXPIRY"],
    ["rerun replay", (f) => { f.run.run_attempt = 2; }, "AUTH_CONTROLLER_RUN"],
  ]) {
    it(`rejects ${name}`, () => {
      const value = fixture();
      mutate(value);
      assert.throws(() => buildAuthorization(value), new RegExp(code));
    });
  }

  it("rejects a duplicate matching dispatch even when it uses another workflow or branch", () => {
    const value = fixture();
    const duplicate = structuredClone(value.run);
    duplicate.id += 1;
    duplicate.path = ".github/workflows/other.yml";
    duplicate.head_branch = "other";
    value.inventory.pages[0].total_count = 2;
    value.inventory.pages[0].workflow_runs.push(duplicate);
    assert.throws(() => buildAuthorization(value), /AUTH_DUPLICATE_RUN/);
  });

  it("rejects incomplete pagination and an inventory that omits the current run", () => {
    let value = fixture();
    value.inventory.pages[0].total_count = 2;
    assert.throws(() => buildAuthorization(value), /AUTH_RUN_INVENTORY_INCOMPLETE/);

    value = fixture();
    value.inventory.pages[0].workflow_runs[0].id += 1;
    assert.throws(() => buildAuthorization(value), /AUTH_RUN_INVENTORY_CURRENT/);
  });

  it("accepts complete multi-page inventory and rejects an incomplete full final page", () => {
    const runName = "target";
    const current = { id: 900000001, event: "workflow_dispatch", display_title: runName, path: ".github/workflows/install-only-authorization.yml", head_branch: "main", head_sha: sha("f", 40), run_attempt: 1 };
    const unrelated = Array.from({ length: 100 }, (_, index) => ({ id: 800000000 + index, event: "workflow_dispatch", display_title: `other-${index}` }));
    const inventory = {
      schema: "hfs.production-first-start.install-only-run-inventory/v1",
      complete: true,
      query: { repository: "Ronmel71/hfs-approval-controller", event: "workflow_dispatch", perPage: 100 },
      pages: [
        { total_count: 101, workflow_runs: unrelated },
        { total_count: 101, workflow_runs: [current] },
      ],
    };
    assert.doesNotThrow(() => validateRunInventory({ inventory, run: current, runName }));
    inventory.pages = [{ total_count: 100, workflow_runs: unrelated }];
    assert.throws(() => validateRunInventory({ inventory, run: current, runName }), /AUTH_RUN_INVENTORY_INCOMPLETE/);
  });
});
