import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildAuthorization, signAuthorization } from "../scripts/install-only-authorization.mjs";

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
  releaseRepository: expected.repository,
  releaseCommit: sha("a", 40),
  releaseManifestSha256: sha("b"),
  bundleDigestSha256: sha("c"),
  stagedReadbackSha256: "5b8e5f3653bf9b779cf8f35b9fb192261817a729aa89feaefc84007995102d07",
  authorizationNonce: sha("e"),
  expiresAtEpoch: now + 7200,
  installOnly: true,
  startAuthorized: false,
  readbackRunId: 555000111,
  readbackJobId: 555000222,
};

function fixture() {
  return {
    run: {
      id: 555000333,
      repository: { full_name: "Ronmel71/hfs-approval-controller", private: false, fork: false },
      head_repository: { full_name: "Ronmel71/hfs-approval-controller", fork: false },
      path: ".github/workflows/install-only-authorization.yml",
      head_branch: "main",
      head_sha: sha("f", 40),
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
}

describe("install-only authorization", () => {
  it("binds native approval, exact controller head, authenticated readback provenance, and a fresh issue time", () => {
    const value = fixture();
    const payload = buildAuthorization(value);
    assert.equal(payload.controllerHeadSha, value.controllerHeadSha);
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
  ]) {
    it(`rejects ${name}`, () => {
      const value = fixture();
      mutate(value);
      assert.throws(() => buildAuthorization(value), new RegExp(code));
    });
  }
});
