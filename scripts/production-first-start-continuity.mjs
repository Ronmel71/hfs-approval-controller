import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

export const PROBE_SCHEMA = "hfs.production-first-start.probe/v1";
export const EVIDENCE_SCHEMA = "hfs.production-first-start.evidence/v2";
export const EXPECTED_SCHEMA = "hfs.production-first-start.continuity-expected/v1";
export const ENVELOPE_SCHEMA = "hfs.production-first-start.continuity-envelope/v1";
export const ATTESTATION_SCHEMA = "hfs.production-first-start.continuity-attestation/v1";
export const CONTROLLER_REPOSITORY = "Ronmel71/hfs-approval-controller";
export const CONTROLLER_WORKFLOW_PATH = ".github/workflows/production-first-start-continuity.yml";
export const CONTROLLER_REF = "refs/heads/main";
export const ENVIRONMENT = "production-first-start";
export const REVIEWER_LOGIN = "Ronmel71";
export const REVIEWER_ID = 321374159;
export const FORBIDDEN_SMOKE_RUN_ID = "42130962231";

const HASH = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function fail(code) { throw new Error(code); }
function exactKeys(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
}
function exact(value, expected, code) { if (value !== expected) fail(code); }
function match(value, pattern, code) { if (typeof value !== "string" || !pattern.test(value)) fail(code); }
function time(value, code) {
  match(value, ISO, code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(code);
  return parsed;
}
export function canonicalBytes(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return Buffer.from(JSON.stringify(value));
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("CONTINUITY_CANONICAL_NUMBER");
    return Buffer.from(String(value));
  }
  if (Array.isArray(value)) return Buffer.concat([Buffer.from("["), ...value.flatMap((item, index) => [index ? Buffer.from(",") : Buffer.alloc(0), canonicalBytes(item)]), Buffer.from("]")]);
  if (!value || typeof value !== "object") fail("CONTINUITY_CANONICAL_TYPE");
  return Buffer.concat([Buffer.from("{"), ...Object.keys(value).sort().flatMap((key, index) => [index ? Buffer.from(",") : Buffer.alloc(0), Buffer.from(JSON.stringify(key)), Buffer.from(":"), canonicalBytes(value[key])]), Buffer.from("}")]);
}
export function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
export function providerAttestationPayload(observation) {
  return {
    database: observation.database,
    dns: observation.dns,
    email: observation.email,
    run: {
      repository: observation.run.repository,
      workflowRef: observation.run.workflowRef,
      environment: observation.run.environment,
      runId: observation.run.runId,
      runAttempt: observation.run.runAttempt,
      commit: observation.run.commit,
      productionRef: observation.run.productionRef,
      approval: observation.run.approval,
    },
    observedAt: observation.observedAt,
  };
}

function validateController(run, approvals, controllerHeadSha) {
  if (String(run.id) === FORBIDDEN_SMOKE_RUN_ID) fail("CONTINUITY_SMOKE_FORBIDDEN");
  if (run.repository?.full_name !== CONTROLLER_REPOSITORY || run.repository?.private !== false || run.repository?.fork !== false) fail("CONTINUITY_CONTROLLER_REPOSITORY");
  if (run.head_repository?.full_name !== CONTROLLER_REPOSITORY || run.head_repository?.fork !== false) fail("CONTINUITY_CONTROLLER_REPOSITORY");
  if (run.path !== CONTROLLER_WORKFLOW_PATH || run.head_branch !== "main" || run.head_sha !== controllerHeadSha || !COMMIT.test(controllerHeadSha)) fail("CONTINUITY_CONTROLLER_HEAD");
  if (run.event !== "workflow_dispatch" || run.run_attempt !== 1 || !Number.isSafeInteger(run.id)) fail("CONTINUITY_CONTROLLER_RUN");
  if (run.actor?.login !== REVIEWER_LOGIN || run.actor?.id !== REVIEWER_ID || run.triggering_actor?.login !== REVIEWER_LOGIN || run.triggering_actor?.id !== REVIEWER_ID) fail("CONTINUITY_CONTROLLER_ACTOR");
  if (!Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) fail("CONTINUITY_CONTROLLER_PR");
  if (!Array.isArray(approvals) || approvals.length !== 1) fail("CONTINUITY_APPROVAL_COUNT");
  const approval = approvals[0];
  if (approval.state !== "approved" || approval.user?.login !== REVIEWER_LOGIN || approval.user?.id !== REVIEWER_ID) fail("CONTINUITY_APPROVAL_REVIEWER");
  if (!Array.isArray(approval.environments) || approval.environments.length !== 1) fail("CONTINUITY_APPROVAL_ENVIRONMENT");
  const environment = approval.environments[0];
  if (environment.name !== ENVIRONMENT || !Number.isSafeInteger(environment.id) || environment.can_admins_bypass !== false) fail("CONTINUITY_APPROVAL_ENVIRONMENT");
  return environment;
}

function validateExpected(expected, expectedDigest) {
  exactKeys(expected, ["schema", "mode", "sourceKind", "sourceAuthenticationMethod", "reviewer", "repository", "workflowRef", "workflowPath", "workflowBranch", "environment", "runAttempt", "commit", "host", "peer", "dnsName", "dnsA", "databaseTableCount", "artifact", "jobName"], "CONTINUITY_EXPECTED_FIELDS");
  exact(expected.schema, EXPECTED_SCHEMA, "CONTINUITY_EXPECTED_SCHEMA");
  exact(expected.mode, "ACTIVATION_REQUIRED_READ_ONLY", "CONTINUITY_EXPECTED_MODE");
  exact(expected.sourceKind, "DIRECT_PROVIDER_READ_ONLY", "CONTINUITY_EXPECTED_SOURCE");
  exact(expected.sourceAuthenticationMethod, "DIRECT_PROVIDER_ATTESTATION_V1", "CONTINUITY_EXPECTED_SOURCE");
  match(expected.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "CONTINUITY_EXPECTED_REPOSITORY");
  match(expected.workflowPath, /^\.github\/workflows\/[a-z0-9][a-z0-9._-]*\.ya?ml$/, "CONTINUITY_EXPECTED_WORKFLOW");
  exact(expected.workflowRef, `${expected.repository}/${expected.workflowPath}@refs/heads/${expected.workflowBranch}`, "CONTINUITY_EXPECTED_WORKFLOW");
  match(expected.workflowBranch, /^[A-Za-z0-9._/-]+$/, "CONTINUITY_EXPECTED_WORKFLOW");
  match(expected.commit, COMMIT, "CONTINUITY_EXPECTED_COMMIT");
  if (expected.runAttempt !== 1 || expected.databaseTableCount !== 44) fail("CONTINUITY_EXPECTED_LIMITS");
  exactKeys(expected.artifact, ["path", "sha256", "bytes"], "CONTINUITY_EXPECTED_ARTIFACT");
  match(expected.artifact.sha256, HASH, "CONTINUITY_EXPECTED_ARTIFACT");
  if (!Number.isSafeInteger(expected.artifact.bytes) || expected.artifact.bytes < 1) fail("CONTINUITY_EXPECTED_ARTIFACT");
  match(expectedDigest, HASH, "CONTINUITY_EXPECTED_DIGEST");
  if (sha256(canonicalBytes(expected)) !== expectedDigest) fail("CONTINUITY_EXPECTED_DIGEST");
}

function validateSource(source, phase, beforeProbe) {
  exactKeys(source, ["kind", "readOnly", "independenceId", "authentication"], "CONTINUITY_SOURCE_FIELDS");
  exact(source.kind, "DIRECT_PROVIDER_READ_ONLY", "CONTINUITY_SOURCE_KIND");
  if (source.readOnly !== true) fail("CONTINUITY_SOURCE_READ_ONLY");
  match(source.independenceId, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/, "CONTINUITY_SOURCE_ID");
  exactKeys(source.authentication, ["method", "issuer", "subjectDigest", "attestationDigest", "verifiedAt"], "CONTINUITY_SOURCE_AUTH_FIELDS");
  exact(source.authentication.method, "DIRECT_PROVIDER_ATTESTATION_V1", "CONTINUITY_SOURCE_AUTH_METHOD");
  match(source.authentication.issuer, /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/, "CONTINUITY_SOURCE_AUTH_ISSUER");
  match(source.authentication.subjectDigest, HASH, "CONTINUITY_SOURCE_AUTH_SUBJECT");
  match(source.authentication.attestationDigest, HASH, "CONTINUITY_SOURCE_AUTH_DIGEST");
  time(source.authentication.verifiedAt, "CONTINUITY_SOURCE_AUTH_TIME");
  if (phase === "AFTER" && (!beforeProbe || source.independenceId === beforeProbe.sourceIndependenceId)) fail("CONTINUITY_AFTER_NOT_INDEPENDENT");
}

function validateObservation(observation, expected, phase, beforeProbe) {
  exactKeys(observation, ["schema", "mode", "source", "run", "artifact", "transport", "database", "dns", "email", "tls", "nonce", "observedAt"], "CONTINUITY_OBSERVATION_FIELDS");
  exact(observation.schema, "hfs.production-first-start.observation/v1", "CONTINUITY_OBSERVATION_SCHEMA");
  exact(observation.mode, expected.mode, "CONTINUITY_MODE");
  validateSource(observation.source, phase, beforeProbe);
  const run = observation.run;
  exactKeys(run, ["repository", "workflowRef", "environment", "environmentProtected", "runId", "runAttempt", "commit", "productionRef", "approval", "workflowRuns"], "CONTINUITY_RUN_FIELDS");
  exact(run.repository, expected.repository, "CONTINUITY_PRIVATE_REPOSITORY");
  exact(run.workflowRef, expected.workflowRef, "CONTINUITY_PRIVATE_WORKFLOW");
  exact(run.environment, expected.environment, "CONTINUITY_PRIVATE_ENVIRONMENT");
  if (run.environmentProtected !== true || run.runAttempt !== 1) fail("CONTINUITY_PRIVATE_RUN");
  match(run.runId, RUN_ID, "CONTINUITY_PRIVATE_RUN");
  exact(run.commit, expected.commit, "CONTINUITY_PRIVATE_HEAD");
  exact(run.productionRef, `refs/heads/${expected.workflowBranch}`, "CONTINUITY_PRIVATE_REF");
  if (!Array.isArray(run.workflowRuns)) fail("CONTINUITY_WORKFLOW_RUNS");
  for (const candidate of run.workflowRuns) {
    exactKeys(candidate, ["runId", "runAttempt", "status", "workflowRef"], "CONTINUITY_WORKFLOW_RUN_FIELDS");
    const own = candidate.runId === run.runId && candidate.runAttempt === 1 && candidate.workflowRef === run.workflowRef;
    if (!own && ["queued", "in_progress", "pending", "waiting"].includes(candidate.status)) fail("CONTINUITY_CONFLICTING_RUN");
  }
  if (phase === "BEFORE") {
    exactKeys(run.approval, ["decision", "id", "reviewer", "reviewedAt", "runId", "environment", "workflowRef"], "CONTINUITY_PRIVATE_APPROVAL_FIELDS");
    exact(run.approval.decision, "APPROVED", "CONTINUITY_PRIVATE_APPROVAL");
    exact(run.approval.reviewer, expected.reviewer, "CONTINUITY_PRIVATE_APPROVAL");
    exact(run.approval.runId, run.runId, "CONTINUITY_PRIVATE_APPROVAL");
    exact(run.approval.environment, expected.environment, "CONTINUITY_PRIVATE_APPROVAL");
    exact(run.approval.workflowRef, expected.workflowRef, "CONTINUITY_PRIVATE_APPROVAL");
    time(run.approval.reviewedAt, "CONTINUITY_PRIVATE_APPROVAL");
  } else if (run.approval !== null) fail("CONTINUITY_AFTER_APPROVAL");
  exactKeys(observation.artifact, ["path", "sha256", "bytes", "immutable"], "CONTINUITY_ARTIFACT_FIELDS");
  exact(observation.artifact.path, expected.artifact.path, "CONTINUITY_ARTIFACT");
  exact(observation.artifact.sha256, expected.artifact.sha256, "CONTINUITY_ARTIFACT");
  exact(observation.artifact.bytes, expected.artifact.bytes, "CONTINUITY_ARTIFACT");
  if (observation.artifact.immutable !== true) fail("CONTINUITY_ARTIFACT");
  exactKeys(observation.transport, ["host", "peer", "wireguardPinned", "sshHostKeyPinned", "connected"], "CONTINUITY_TRANSPORT_FIELDS");
  exact(observation.transport.host, expected.host, "CONTINUITY_HOST");
  exact(observation.transport.peer, expected.peer, "CONTINUITY_HOST");
  if (observation.transport.wireguardPinned !== true || observation.transport.sshHostKeyPinned !== true || observation.transport.connected !== true) fail("CONTINUITY_TRANSPORT");
  exactKeys(observation.database, ["operation", "tables"], "CONTINUITY_DATABASE_FIELDS");
  exact(observation.database.operation, "SELECT_COUNT_ONLY", "CONTINUITY_DATABASE_OPERATION");
  const entries = Object.entries(observation.database.tables ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length !== 44 || entries.some(([name, count]) => !/^[a-z][a-z0-9_]{1,62}$/.test(name) || !/^(?:0|[1-9]\d*)$/.test(count))) fail("CONTINUITY_DATABASE_COUNTS");
  exactKeys(observation.dns, ["operation", "name", "a", "aaaa"], "CONTINUITY_DNS_FIELDS");
  exact(observation.dns.operation, "READ_ONLY_RESOLVE", "CONTINUITY_DNS");
  exact(observation.dns.name, expected.dnsName, "CONTINUITY_DNS");
  if (!Array.isArray(observation.dns.a) || observation.dns.a.length !== 1 || observation.dns.a[0] !== expected.dnsA || !Array.isArray(observation.dns.aaaa) || observation.dns.aaaa.length !== 0) fail("CONTINUITY_DNS");
  exactKeys(observation.email, ["allowRealEmail", "sentCount", "sendAttempted", "inboxReadAttempted"], "CONTINUITY_EMAIL_FIELDS");
  if (observation.email.allowRealEmail !== false || observation.email.sentCount !== 0 || observation.email.sendAttempted !== false || observation.email.inboxReadAttempted !== false) fail("CONTINUITY_EMAIL_SEND_COUNT");
  exactKeys(observation.tls, ["checked", "caValid", "sniValid", "ready", "elapsedSeconds"], "CONTINUITY_TLS_FIELDS");
  if (phase === "BEFORE") {
    if (observation.tls.checked !== false || observation.tls.caValid !== null || observation.tls.sniValid !== null || observation.tls.ready !== null || observation.tls.elapsedSeconds !== null) fail("CONTINUITY_TLS_BEFORE");
  } else if (observation.tls.checked !== true || observation.tls.caValid !== true || observation.tls.sniValid !== true || observation.tls.ready !== true || !Number.isInteger(observation.tls.elapsedSeconds) || observation.tls.elapsedSeconds < 0 || observation.tls.elapsedSeconds > 180) fail("CONTINUITY_TLS_AFTER");
  if (observation.source.authentication.attestationDigest !== sha256(canonicalBytes(providerAttestationPayload(observation)))) fail("CONTINUITY_SOURCE_AUTH_DIGEST");
  match(observation.nonce, HASH, "CONTINUITY_NONCE");
  const observedAt = time(observation.observedAt, "CONTINUITY_OBSERVED_AT");
  if (phase === "AFTER") {
    const beforeAt = time(beforeProbe.evidence.issuedAt, "CONTINUITY_BEFORE_TIME");
    if (observedAt < beforeAt || observedAt - beforeAt > 900_000) fail("CONTINUITY_AFTER_DEADLINE");
    if (observation.nonce === beforeProbe.evidence.nonce) fail("CONTINUITY_NONCE_REPLAY");
  }
  return entries;
}

function derivedEvidence(observation, expected, phase, beforeProbe, entries) {
  const issuedAt = Date.parse(observation.observedAt);
  return {
    schema: EVIDENCE_SCHEMA,
    phase,
    runId: observation.run.runId,
    runAttempt: 1,
    commit: observation.run.commit,
    productionRef: observation.run.productionRef,
    artifact: { path: observation.artifact.path, sha256: observation.artifact.sha256, bytes: observation.artifact.bytes },
    github: { repository: observation.run.repository, workflowRef: observation.run.workflowRef, environment: observation.run.environment },
    host: { name: observation.transport.host, peer: observation.transport.peer },
    database: { tableCount: expected.databaseTableCount, countDigest: sha256(Buffer.from(JSON.stringify(entries))) },
    dns: { name: observation.dns.name, a: observation.dns.a, aaaa: observation.dns.aaaa },
    workflow: { idle: true },
    email: { allowRealEmail: false, sentCount: 0 },
    nonce: observation.nonce,
    issuedAt: observation.observedAt,
    expiresAt: new Date(issuedAt + (phase === "BEFORE" ? 900_000 : 300_000)).toISOString(),
    result: phase === "BEFORE" ? "READY_FOR_ONE_APPROVED_START" : "AFTER_PASS",
    approval: phase === "BEFORE" ? { decision: "APPROVED", approvalId: observation.run.approval.id } : null,
    before: phase === "BEFORE" ? null : { digest: sha256(canonicalBytes(beforeProbe.evidence)), nonce: beforeProbe.evidence.nonce },
  };
}

export function validateProbe(probe, expected, expectedDigest, phase, beforeProbe = null) {
  validateExpected(expected, expectedDigest);
  exactKeys(probe, ["schema", "phase", "sourceIndependenceId", "observation", "evidence", "probeDigest"], "CONTINUITY_PROBE_FIELDS");
  exact(probe.schema, PROBE_SCHEMA, "CONTINUITY_PROBE_SCHEMA");
  exact(probe.phase, phase, "CONTINUITY_PHASE");
  exact(probe.sourceIndependenceId, probe.observation?.source?.independenceId, "CONTINUITY_SOURCE_ID");
  const entries = validateObservation(probe.observation, expected, phase, beforeProbe);
  const evidence = derivedEvidence(probe.observation, expected, phase, beforeProbe, entries);
  if (!canonicalBytes(evidence).equals(canonicalBytes(probe.evidence))) fail("CONTINUITY_EVIDENCE_FORGED");
  const withoutDigest = { schema: probe.schema, phase: probe.phase, sourceIndependenceId: probe.sourceIndependenceId, observation: probe.observation, evidence: probe.evidence };
  if (probe.probeDigest !== sha256(Buffer.from(JSON.stringify(withoutDigest)))) fail("CONTINUITY_PROBE_DIGEST");
  return { ...probe, evidence };
}

function validatePrivateProvenance({ privateRun, privateJob, artifact, probe, expected, phase }) {
  if (privateRun.repository?.full_name !== expected.repository || privateRun.repository?.private !== true || privateRun.repository?.fork !== false) fail("CONTINUITY_PRIVATE_REPOSITORY");
  if (privateRun.path !== expected.workflowPath || privateRun.head_branch !== expected.workflowBranch || privateRun.head_sha !== expected.commit || privateRun.event !== "workflow_dispatch" || privateRun.run_attempt !== 1) fail("CONTINUITY_PRIVATE_RUN");
  if (!Array.isArray(privateRun.pull_requests) || privateRun.pull_requests.length !== 0) fail("CONTINUITY_PRIVATE_PR");
  if (String(privateRun.id) !== String(probe.evidence.runId)) fail("CONTINUITY_PRIVATE_RUN");
  if (String(privateJob.run_id) !== String(privateRun.id) || privateJob.name !== expected.jobName || privateJob.head_sha !== expected.commit || !["in_progress", "completed"].includes(privateJob.status)) fail("CONTINUITY_PRIVATE_JOB");
  if (privateJob.status === "completed" && privateJob.conclusion !== "success") fail("CONTINUITY_PRIVATE_JOB");
  const expectedName = phase === "BEFORE" ? `production-first-start-before-${probe.evidence.nonce}` : `production-first-start-after-${probe.evidence.before.nonce}`;
  if (!Number.isSafeInteger(artifact.id) || artifact.expired !== false || artifact.name !== expectedName || String(artifact.workflow_run?.id) !== String(privateRun.id) || artifact.workflow_run?.head_sha !== expected.commit) fail("CONTINUITY_PRIVATE_ARTIFACT");
  const digest = typeof artifact.digest === "string" && artifact.digest.startsWith("sha256:") ? artifact.digest.slice(7) : "";
  match(digest, HASH, "CONTINUITY_PRIVATE_ARTIFACT_DIGEST");
  return { digest, expectedName };
}

export function buildEnvelope({ probe, expected, expectedDigest, phase, beforeProbe = null, controllerRun, approvals, privateRun, privateJob, artifact, controllerHeadSha, privateJobId, now = Math.floor(Date.now() / 1000), privateKeyPem }) {
  const environment = validateController(controllerRun, approvals, controllerHeadSha);
  const verified = validateProbe(probe, expected, expectedDigest, phase, beforeProbe);
  if (String(privateJob.id) !== String(privateJobId) || !RUN_ID.test(String(privateJobId))) fail("CONTINUITY_PRIVATE_JOB");
  const provenance = validatePrivateProvenance({ privateRun, privateJob, artifact, probe: verified, expected, phase });
  const evidenceBytes = canonicalBytes(verified.evidence);
  const evidenceIssuedAt = Math.floor(Date.parse(verified.evidence.issuedAt) / 1000);
  if (phase === "BEFORE" && (now < evidenceIssuedAt - 30 || now - evidenceIssuedAt > 300)) fail("CONTINUITY_BEFORE_STALE");
  if (phase === "AFTER" && (now < evidenceIssuedAt - 30 || now - evidenceIssuedAt > 300)) fail("CONTINUITY_AFTER_STALE");
  if (Math.floor(Date.parse(verified.evidence.expiresAt) / 1000) <= now) fail("CONTINUITY_EVIDENCE_EXPIRED");
  if (phase === "AFTER" && beforeProbe && sha256(canonicalBytes(beforeProbe.evidence)) !== verified.evidence.before.digest) fail("CONTINUITY_AFTER_LINK");
  const attestation = {
    schema: ATTESTATION_SCHEMA,
    phase,
    controller: { repository: CONTROLLER_REPOSITORY, workflowPath: CONTROLLER_WORKFLOW_PATH, ref: CONTROLLER_REF, headSha: controllerHeadSha, runId: String(controllerRun.id), runAttempt: 1, event: "workflow_dispatch", actor: { login: REVIEWER_LOGIN, id: REVIEWER_ID }, approval: { state: "approved", reviewerLogin: REVIEWER_LOGIN, reviewerId: REVIEWER_ID, environment: ENVIRONMENT, environmentId: environment.id, canAdminsBypass: false } },
    source: { repository: expected.repository, workflowPath: expected.workflowPath, workflowRef: `refs/heads/${expected.workflowBranch}`, headSha: expected.commit, runId: String(privateRun.id), runAttempt: 1, jobId: String(privateJob.id), jobName: expected.jobName, artifactId: String(artifact.id), artifactName: provenance.expectedName, artifactDigestSha256: provenance.digest },
    evidenceSha256: sha256(evidenceBytes),
    evidenceNonce: verified.evidence.nonce,
    beforeEvidenceSha256: phase === "BEFORE" ? null : verified.evidence.before.digest,
    issuedAtEpoch: now,
    expiresAtEpoch: Math.min(Math.floor(Date.parse(verified.evidence.expiresAt) / 1000), now + (phase === "BEFORE" ? 900 : 180)),
  };
  let privateKey;
  try { privateKey = createPrivateKey(privateKeyPem); } catch { fail("CONTINUITY_PRIVATE_KEY"); }
  if (privateKey.asymmetricKeyType !== "ed25519") fail("CONTINUITY_PRIVATE_KEY");
  return {
    schema: ENVELOPE_SCHEMA,
    attestation,
    evidenceSignatureBase64Url: sign(null, evidenceBytes, privateKey).toString("base64url"),
    attestationSignatureBase64Url: sign(null, canonicalBytes(attestation), privateKey).toString("base64url"),
  };
}

function required(name) { const value = process.env[name]; if (!value) fail(`CONTINUITY_ENV_${name}`); return value; }
if (process.argv[1]?.endsWith("production-first-start-continuity.mjs")) {
  try {
    if (process.argv.length !== 14 || process.argv[2] !== "sign") fail("CONTINUITY_USAGE");
    const [phase, probePath, expectedPath, beforeProbePath, controllerRunPath, approvalsPath, privateRunPath, privateJobPath, artifactPath, privateJobIdPath, outputPath] = process.argv.slice(3);
    const json = (path) => JSON.parse(readFileSync(path, "utf8"));
    const envelope = buildEnvelope({
      phase, probe: json(probePath), expected: json(expectedPath), expectedDigest: required("HFS_FIRST_START_EXPECTED_SHA256"),
      beforeProbe: beforeProbePath === "-" ? null : json(beforeProbePath), controllerRun: json(controllerRunPath), approvals: json(approvalsPath),
      privateRun: json(privateRunPath), privateJob: json(privateJobPath), artifact: json(artifactPath), privateJobId: readFileSync(privateJobIdPath, "utf8").trim(),
      controllerHeadSha: required("GITHUB_SHA"), privateKeyPem: required("HFS_ED25519_SIGNING_KEY_PEM"),
    });
    writeFileSync(outputPath, `${JSON.stringify(envelope)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    process.stdout.write(`CONTINUITY_SIGNED phase=${phase}\n`);
  } catch (error) {
    process.stderr.write(`CONTINUITY_REFUSED code=${error instanceof Error ? error.message : "UNKNOWN"}\n`);
    process.exitCode = 78;
  }
}
