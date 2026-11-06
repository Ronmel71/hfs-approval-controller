import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildEnvelope,
  canonicalBytes,
  providerAttestationPayload,
  sha256,
  validateProbe,
} from "../scripts/production-first-start-continuity.mjs";

const now = Math.floor(Date.parse("2026-11-06T12:00:00.000Z") / 1000);
const expected = {
  schema: "hfs.production-first-start.continuity-expected/v1",
  mode: "ACTIVATION_REQUIRED_READ_ONLY",
  sourceKind: "DIRECT_PROVIDER_READ_ONLY",
  sourceAuthenticationMethod: "DIRECT_PROVIDER_ATTESTATION_V1",
  reviewer: "Ronmel71",
  repository: "owner/private-release",
  workflowRef: "owner/private-release/.github/workflows/production-first-start.yml@refs/heads/staging",
  workflowPath: ".github/workflows/production-first-start.yml",
  workflowBranch: "staging",
  environment: "production-first-start",
  runAttempt: 1,
  commit: "a".repeat(40),
  host: "production.example.invalid",
  peer: "192.0.2.10",
  dnsName: "production.example.invalid",
  dnsA: "192.0.2.20",
  databaseTableCount: 44,
  artifact: { path: "deploy/production/host/runner", sha256: "b".repeat(64), bytes: 30077 },
  jobName: "signer-continuity-handoff-hard-disabled",
};
const expectedDigest = sha256(canonicalBytes(expected));

function observation(phase) {
  const after = phase === "AFTER";
  const value = {
    schema: "hfs.production-first-start.observation/v1",
    mode: expected.mode,
    source: {
      kind: "DIRECT_PROVIDER_READ_ONLY", readOnly: true,
      independenceId: after ? "provider-after-0001" : "provider-before-0001",
      authentication: { method: "DIRECT_PROVIDER_ATTESTATION_V1", issuer: "https://provider.example.invalid/", subjectDigest: (after ? "2" : "1").repeat(64), attestationDigest: (after ? "4" : "3").repeat(64), verifiedAt: after ? "2026-11-06T12:07:59.000Z" : "2026-11-06T11:59:59.000Z" },
    },
    run: {
      repository: expected.repository, workflowRef: expected.workflowRef, environment: expected.environment, environmentProtected: true,
      runId: "555000111", runAttempt: 1, commit: expected.commit, productionRef: "refs/heads/staging",
      approval: after ? null : { decision: "APPROVED", id: "private-review-0001", reviewer: "Ronmel71", reviewedAt: "2026-11-06T11:59:00.000Z", runId: "555000111", environment: expected.environment, workflowRef: expected.workflowRef },
      workflowRuns: [{ runId: "555000111", runAttempt: 1, status: "in_progress", workflowRef: expected.workflowRef }],
    },
    artifact: { ...expected.artifact, immutable: true },
    transport: { host: expected.host, peer: expected.peer, wireguardPinned: true, sshHostKeyPinned: true, connected: true },
    database: { operation: "SELECT_COUNT_ONLY", tables: Object.fromEntries(Array.from({ length: 44 }, (_, index) => [`table_${String(index).padStart(2, "0")}`, String(index)])) },
    dns: { operation: "READ_ONLY_RESOLVE", name: expected.dnsName, a: [expected.dnsA], aaaa: [] },
    email: { allowRealEmail: false, sentCount: 0, sendAttempted: false, inboxReadAttempted: false },
    tls: after ? { checked: true, caValid: true, sniValid: true, ready: true, elapsedSeconds: 12 } : { checked: false, caValid: null, sniValid: null, ready: null, elapsedSeconds: null },
    nonce: (after ? "d" : "c").repeat(64),
    observedAt: after ? "2026-11-06T12:08:00.000Z" : "2026-11-06T12:00:00.000Z",
  };
  value.source.authentication.attestationDigest = sha256(canonicalBytes(providerAttestationPayload(value)));
  return value;
}

function evidence(source, phase, beforeProbe = null) {
  const entries = Object.entries(source.database.tables).sort(([a], [b]) => a.localeCompare(b));
  const issued = Date.parse(source.observedAt);
  return {
    schema: "hfs.production-first-start.evidence/v2", phase, runId: source.run.runId, runAttempt: 1,
    commit: source.run.commit, productionRef: source.run.productionRef,
    artifact: { path: source.artifact.path, sha256: source.artifact.sha256, bytes: source.artifact.bytes },
    github: { repository: source.run.repository, workflowRef: source.run.workflowRef, environment: source.run.environment },
    host: { name: source.transport.host, peer: source.transport.peer },
    database: { tableCount: 44, countDigest: sha256(Buffer.from(JSON.stringify(entries))) },
    dns: { name: source.dns.name, a: source.dns.a, aaaa: source.dns.aaaa }, workflow: { idle: true }, email: { allowRealEmail: false, sentCount: 0 },
    nonce: source.nonce, issuedAt: source.observedAt, expiresAt: new Date(issued + (phase === "BEFORE" ? 900_000 : 300_000)).toISOString(),
    result: phase === "BEFORE" ? "READY_FOR_ONE_APPROVED_START" : "AFTER_PASS",
    approval: phase === "BEFORE" ? { decision: "APPROVED", approvalId: source.run.approval.id } : null,
    before: phase === "BEFORE" ? null : { digest: sha256(canonicalBytes(beforeProbe.evidence)), nonce: beforeProbe.evidence.nonce },
  };
}

function probe(phase, beforeProbe = null) {
  const value = { schema: "hfs.production-first-start.probe/v1", phase, sourceIndependenceId: observation(phase).source.independenceId, observation: observation(phase), evidence: null };
  value.evidence = evidence(value.observation, phase, beforeProbe);
  return { ...value, probeDigest: sha256(Buffer.from(JSON.stringify(value))) };
}

function fixture(phase = "BEFORE", beforeProbe = null) {
  const current = probe(phase, beforeProbe);
  const { privateKey } = generateKeyPairSync("ed25519");
  const controllerRun = {
    id: 555000333, repository: { full_name: "Ronmel71/hfs-approval-controller", private: false, fork: false }, head_repository: { full_name: "Ronmel71/hfs-approval-controller", fork: false },
    path: ".github/workflows/production-first-start-continuity.yml", head_branch: "main", head_sha: "f".repeat(40), event: "workflow_dispatch", run_attempt: 1,
    actor: { login: "Ronmel71", id: 321374159 }, triggering_actor: { login: "Ronmel71", id: 321374159 }, pull_requests: [],
  };
  const approvals = [{ state: "approved", user: { login: "Ronmel71", id: 321374159 }, environments: [{ id: 26423058762, name: "production-first-start", can_admins_bypass: false }] }];
  const privateRun = { id: 555000111, repository: { full_name: expected.repository, private: true, fork: false }, path: expected.workflowPath, head_branch: "staging", head_sha: expected.commit, event: "workflow_dispatch", run_attempt: 1, pull_requests: [] };
  const privateJob = { id: 555000222, run_id: 555000111, name: expected.jobName, head_sha: expected.commit, status: "in_progress", conclusion: null };
  const artifactName = phase === "BEFORE" ? `production-first-start-before-${current.evidence.nonce}` : `production-first-start-after-${current.evidence.before.nonce}`;
  const artifact = { id: phase === "BEFORE" ? 555000444 : 555000445, name: artifactName, expired: false, digest: `sha256:${"e".repeat(64)}`, workflow_run: { id: 555000111, head_sha: expected.commit } };
  return { probe: current, expected, expectedDigest, phase, beforeProbe, controllerRun, approvals, privateRun, privateJob, artifact, controllerHeadSha: "f".repeat(40), privateJobId: "555000222", now: phase === "BEFORE" ? now : now + 480, privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

describe("production first-start signer continuity", () => {
  it("exercises the CODE_ONLY envelope schema with one exact controller run and private provenance", () => {
    const before = probe("BEFORE");
    const beforeEnvelope = buildEnvelope({ ...fixture("BEFORE"), codeOnlyTestMode: true });
    const afterEnvelope = buildEnvelope({ ...fixture("AFTER", before), codeOnlyTestMode: true });
    assert.equal(beforeEnvelope.attestation.phase, "BEFORE");
    assert.equal(afterEnvelope.attestation.beforeEvidenceSha256, sha256(canonicalBytes(before.evidence)));
    assert.match(beforeEnvelope.evidenceSignatureBase64Url, /^[A-Za-z0-9_-]{86}$/);
    assert.match(beforeEnvelope.attestationSignatureBase64Url, /^[A-Za-z0-9_-]{86}$/);
  });

  for (const [name, mutate, code] of [
    ["old smoke", (f) => { f.controllerRun.id = 42130962231; }, "CONTINUITY_SMOKE_FORBIDDEN"],
    ["no native reviewer", (f) => { f.approvals = []; }, "CONTINUITY_APPROVAL_COUNT"],
    ["wrong controller head", (f) => { f.controllerRun.head_sha = "1".repeat(40); }, "CONTINUITY_CONTROLLER_HEAD"],
    ["attempt two", (f) => { f.privateRun.run_attempt = 2; }, "CONTINUITY_PRIVATE_RUN"],
    ["unrelated job", (f) => { f.privateJob.name = "other"; }, "CONTINUITY_PRIVATE_JOB"],
    ["forged DB count", (f) => { f.probe.observation.database.tables.table_00 = "999"; }, "CONTINUITY_SOURCE_AUTH_DIGEST"],
    ["forged send count", (f) => { f.probe.observation.email.sentCount = 1; }, "CONTINUITY_EMAIL_SEND_COUNT"],
    ["stale BEFORE", (f) => { f.now += 301; }, "CONTINUITY_BEFORE_STALE"],
  ]) {
    it(`rejects ${name}`, () => {
      const value = { ...fixture(), codeOnlyTestMode: true };
      mutate(value);
      assert.throws(() => buildEnvelope(value), new RegExp(code));
    });
  }

  it("refuses a fully self-consistent forged probe despite authentic GitHub-shaped provenance", () => {
    const value = fixture();
    value.probe.observation.database.tables.table_00 = "999";
    value.probe.observation.source.authentication.issuer = "https://attacker.invalid/scoped-reader";
    value.probe.observation.source.authentication.attestationDigest = sha256(canonicalBytes(providerAttestationPayload(value.probe.observation)));
    value.probe.evidence = evidence(value.probe.observation, "BEFORE");
    const withoutDigest = {
      schema: value.probe.schema,
      phase: value.probe.phase,
      sourceIndependenceId: value.probe.sourceIndependenceId,
      observation: value.probe.observation,
      evidence: value.probe.evidence,
    };
    value.probe.probeDigest = sha256(Buffer.from(JSON.stringify(withoutDigest)));
    assert.equal(value.probe.observation.run.environmentProtected, true);
    assert.equal(value.probe.observation.run.approval.decision, "APPROVED");
    assert.throws(() => buildEnvelope(value), /PROVIDER_ATTESTATION_NOT_AUTHENTICATED/);
  });

  it("rejects replayed AFTER and a wrong protected expected digest", () => {
    const before = probe("BEFORE");
    const replay = probe("AFTER", before);
    replay.observation.nonce = before.evidence.nonce;
    replay.sourceIndependenceId = before.sourceIndependenceId;
    replay.observation.source.independenceId = before.sourceIndependenceId;
    assert.throws(() => validateProbe(replay, expected, expectedDigest, "AFTER", before), /CONTINUITY_AFTER_NOT_INDEPENDENT/);
    assert.throws(() => validateProbe(before, expected, "0".repeat(64), "BEFORE"), /CONTINUITY_EXPECTED_DIGEST/);
  });
});
