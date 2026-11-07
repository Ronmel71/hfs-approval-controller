import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

export const AUTHORIZATION_SCHEMA = "hfs.production-first-start.github-install-authorization/v1";
export const ENVELOPE_SCHEMA = "hfs.production-first-start.github-install-authorization-envelope/v1";
export const CONTROLLER_REPOSITORY = "Ronmel71/hfs-approval-controller";
export const CONTROLLER_WORKFLOW_PATH = ".github/workflows/install-only-authorization.yml";
export const CONTROLLER_REF = "refs/heads/main";
export const REVIEWER_LOGIN = "Ronmel71";
export const REVIEWER_ID = 321374159;
export const ENVIRONMENT = "production-first-start";
export const FORBIDDEN_RUN_ID = "42130962231";
export const AUTHORIZATION_PURPOSE = "INSTALL_ONLY";
export const REQUEST_ID_SCHEMA = "hfs.production-first-start.install-only-request-id/v1";
export const RUN_INVENTORY_SCHEMA = "hfs.production-first-start.install-only-run-inventory/v1";

const HASH = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const NONCE = /^[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const WORKFLOW_PATH = /^\.github\/workflows\/[a-z0-9][a-z0-9._-]*\.ya?ml$/;

function fail(code) {
  throw new Error(code);
}

function exactKeys(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
}

export function canonicalBytes(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return Buffer.from(JSON.stringify(value));
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("AUTH_CANONICAL_NUMBER");
    return Buffer.from(String(value));
  }
  if (Array.isArray(value)) return Buffer.concat([Buffer.from("["), ...value.flatMap((item, index) => [index ? Buffer.from(",") : Buffer.alloc(0), canonicalBytes(item)]), Buffer.from("]")]);
  if (!value || typeof value !== "object") fail("AUTH_CANONICAL_TYPE");
  const entries = Object.keys(value).sort().flatMap((key, index) => [index ? Buffer.from(",") : Buffer.alloc(0), Buffer.from(JSON.stringify(key)), Buffer.from(":"), canonicalBytes(value[key])]);
  return Buffer.concat([Buffer.from("{"), ...entries, Buffer.from("}")]);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateController(run, approvals, controllerHeadSha, expectedRunName) {
  if (String(run.id) === FORBIDDEN_RUN_ID) fail("AUTH_SMOKE_RUN_FORBIDDEN");
  if (run.repository?.full_name !== CONTROLLER_REPOSITORY || run.repository?.private !== false || run.repository?.fork !== false) fail("AUTH_CONTROLLER_REPOSITORY");
  if (run.head_repository?.full_name !== CONTROLLER_REPOSITORY || run.head_repository?.fork !== false) fail("AUTH_HEAD_REPOSITORY");
  if (run.path !== CONTROLLER_WORKFLOW_PATH || run.head_branch !== "main" || run.head_sha !== controllerHeadSha || !COMMIT.test(run.head_sha)) fail("AUTH_CONTROLLER_HEAD");
  if (run.display_title !== expectedRunName) fail("AUTH_CONTROLLER_REQUEST");
  if (run.event !== "workflow_dispatch" || run.run_attempt !== 1 || !Number.isSafeInteger(run.id)) fail("AUTH_CONTROLLER_RUN");
  if (run.actor?.login !== REVIEWER_LOGIN || run.actor?.id !== REVIEWER_ID || run.triggering_actor?.login !== REVIEWER_LOGIN || run.triggering_actor?.id !== REVIEWER_ID) fail("AUTH_CONTROLLER_ACTOR");
  if (!Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) fail("AUTH_CONTROLLER_PULL_REQUEST");
  if (!Array.isArray(approvals) || approvals.length !== 1) fail("AUTH_APPROVAL_COUNT");
  const approval = approvals[0];
  if (approval.state !== "approved" || approval.user?.login !== REVIEWER_LOGIN || approval.user?.id !== REVIEWER_ID) fail("AUTH_APPROVAL_REVIEWER");
  if (!Array.isArray(approval.environments) || approval.environments.length !== 1) fail("AUTH_APPROVAL_ENVIRONMENT");
  const environment = approval.environments[0];
  if (environment.name !== ENVIRONMENT || !Number.isSafeInteger(environment.id) || environment.can_admins_bypass !== false) fail("AUTH_APPROVAL_ENVIRONMENT");
  return environment;
}

function validateRequest(request, readbackBytes, expected, now) {
  exactKeys(request, [
    "purpose",
    "releaseRepository", "releaseCommit", "releaseManifestSha256", "bundleDigestSha256",
    "stagedReadbackSha256", "authorizationNonce", "expiresAtEpoch", "installOnly", "startAuthorized",
    "readbackRunId", "readbackJobId",
  ], "AUTH_REQUEST_FIELDS");
  if (request.purpose !== AUTHORIZATION_PURPOSE) fail("AUTH_PURPOSE");
  if (request.releaseRepository !== expected.repository || !COMMIT.test(request.releaseCommit)) fail("AUTH_RELEASE");
  for (const key of ["releaseManifestSha256", "bundleDigestSha256", "stagedReadbackSha256"]) {
    if (!HASH.test(request[key])) fail("AUTH_DIGEST");
  }
  if (request.stagedReadbackSha256 !== sha256(readbackBytes)) fail("AUTH_READBACK_DIGEST");
  if (!NONCE.test(request.authorizationNonce)) fail("AUTH_NONCE");
  if (!Number.isSafeInteger(request.expiresAtEpoch) || request.expiresAtEpoch <= now || request.expiresAtEpoch > now + 3600) fail("AUTH_EXPIRY");
  if (!RUN_ID.test(String(request.readbackRunId)) || !RUN_ID.test(String(request.readbackJobId))) fail("AUTH_READBACK_IDS");
  if (request.installOnly !== true || request.startAuthorized !== false) fail("AUTH_SCOPE");
}

export function installRequestId({ request, readbackProvenance, controllerHeadSha }) {
  return sha256(canonicalBytes({
    schema: REQUEST_ID_SCHEMA,
    purpose: request.purpose,
    controllerRepository: CONTROLLER_REPOSITORY,
    controllerWorkflowPath: CONTROLLER_WORKFLOW_PATH,
    controllerRef: CONTROLLER_REF,
    controllerHeadSha,
    releaseRepository: request.releaseRepository,
    releaseCommit: request.releaseCommit,
    releaseManifestSha256: request.releaseManifestSha256,
    bundleDigestSha256: request.bundleDigestSha256,
    stagedReadbackSha256: request.stagedReadbackSha256,
    readbackProvenance,
    authorizationNonce: request.authorizationNonce,
  }));
}

function expectedRunName({ purpose, requestId, readbackArtifactId, authorizationNonce }) {
  return `Install-only authorization · ${purpose} · ${requestId} · artifact ${readbackArtifactId} · nonce ${authorizationNonce}`;
}

export function validateRunInventory({ inventory, run, runName }) {
  exactKeys(inventory, ["schema", "complete", "query", "pages"], "AUTH_RUN_INVENTORY_FIELDS");
  if (inventory.schema !== RUN_INVENTORY_SCHEMA || inventory.complete !== true) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
  exactKeys(inventory.query, ["repository", "event", "perPage"], "AUTH_RUN_INVENTORY_FIELDS");
  if (inventory.query.repository !== CONTROLLER_REPOSITORY || inventory.query.event !== "workflow_dispatch" || inventory.query.perPage !== 100) fail("AUTH_RUN_INVENTORY_QUERY");
  if (!Array.isArray(inventory.pages) || inventory.pages.length === 0) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
  let totalCount;
  const allRuns = [];
  for (const [index, page] of inventory.pages.entries()) {
    if (!Number.isSafeInteger(page?.total_count) || page.total_count < 0 || !Array.isArray(page.workflow_runs)) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
    if (totalCount === undefined) totalCount = page.total_count;
    if (page.total_count !== totalCount || page.workflow_runs.length > 100) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
    if (index < inventory.pages.length - 1 && page.workflow_runs.length !== 100) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
    if (index === inventory.pages.length - 1 && page.workflow_runs.length === 100) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
    allRuns.push(...page.workflow_runs);
  }
  if (allRuns.length !== totalCount) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
  const ids = allRuns.map((candidate) => String(candidate?.id));
  if (ids.some((id) => !RUN_ID.test(id)) || new Set(ids).size !== ids.length) fail("AUTH_RUN_INVENTORY_INCOMPLETE");
  const matches = allRuns.filter((candidate) => candidate.event === "workflow_dispatch" && candidate.display_title === runName);
  if (matches.length !== 1) fail("AUTH_DUPLICATE_RUN");
  const match = matches[0];
  if (String(match.id) !== String(run.id) || match.path !== CONTROLLER_WORKFLOW_PATH || match.head_branch !== "main" || match.head_sha !== run.head_sha || match.run_attempt !== 1) fail("AUTH_RUN_INVENTORY_CURRENT");
}

function validateReadbackProvenance({ request, privateRun, privateJob, artifact, expected }) {
  if (privateRun.repository?.full_name !== expected.repository || privateRun.repository?.private !== true || privateRun.repository?.fork !== false) fail("AUTH_READBACK_REPOSITORY");
  if (String(privateRun.id) !== String(request.readbackRunId) || privateRun.path !== expected.workflowPath || privateRun.head_sha !== request.releaseCommit) fail("AUTH_READBACK_RUN");
  if (privateRun.head_branch !== expected.workflowRef.replace("refs/heads/", "") || privateRun.event !== "workflow_dispatch" || privateRun.run_attempt !== 1 || privateRun.status !== "completed" || privateRun.conclusion !== "success") fail("AUTH_READBACK_RUN");
  if (!Array.isArray(privateRun.pull_requests) || privateRun.pull_requests.length !== 0) fail("AUTH_READBACK_PULL_REQUEST");
  if (String(privateJob.id) !== String(request.readbackJobId) || String(privateJob.run_id) !== String(privateRun.id) || privateJob.name !== expected.jobName) fail("AUTH_READBACK_JOB");
  if (privateJob.head_sha !== request.releaseCommit || privateJob.status !== "completed" || privateJob.conclusion !== "success") fail("AUTH_READBACK_JOB");
  if (!Number.isSafeInteger(artifact.id) || artifact.expired !== false || artifact.name !== `install-only-readback-${request.authorizationNonce}`) fail("AUTH_READBACK_ARTIFACT");
  if (String(artifact.workflow_run?.id) !== String(privateRun.id) || artifact.workflow_run?.head_sha !== request.releaseCommit) fail("AUTH_READBACK_ARTIFACT");
  const digest = typeof artifact.digest === "string" && artifact.digest.startsWith("sha256:") ? artifact.digest.slice(7) : "";
  if (!HASH.test(digest)) fail("AUTH_READBACK_ARTIFACT_DIGEST");
  let readback;
  try {
    readback = JSON.parse(expected.readbackBytes.toString("utf8"));
  } catch {
    fail("AUTH_READBACK_JSON");
  }
  const observedAtMs = Date.parse(readback.observedAt);
  const artifactCreatedAtMs = Date.parse(artifact.created_at);
  if (!Number.isFinite(observedAtMs) || !Number.isFinite(artifactCreatedAtMs) || observedAtMs > artifactCreatedAtMs || artifactCreatedAtMs - observedAtMs > 900_000) fail("AUTH_READBACK_TIME");
  return {
    repository: expected.repository,
    workflowPath: expected.workflowPath,
    workflowRef: expected.workflowRef,
    headSha: request.releaseCommit,
    runId: String(privateRun.id),
    runAttempt: 1,
    jobId: String(privateJob.id),
    jobName: expected.jobName,
    artifactId: String(artifact.id),
    artifactName: artifact.name,
    artifactDigestSha256: digest,
    observedAt: readback.observedAt,
    artifactCreatedAt: artifact.created_at,
  };
}

export function buildAuthorization({ run, approvals, inventory, privateRun, privateJob, artifact, request, readbackBytes, expected, workflowInputs, controllerHeadSha, now = Math.floor(Date.now() / 1000) }) {
  if (!expected || typeof expected.repository !== "string" || !WORKFLOW_PATH.test(expected.workflowPath) || !/^refs\/heads\/[a-zA-Z0-9._/-]+$/.test(expected.workflowRef) || typeof expected.jobName !== "string" || expected.jobName.length < 3) fail("AUTH_EXPECTED_PROVENANCE");
  if (!COMMIT.test(controllerHeadSha)) fail("AUTH_CONTROLLER_HEAD");
  validateRequest(request, readbackBytes, expected, now);
  const readbackProvenance = validateReadbackProvenance({ request, privateRun, privateJob, artifact, expected: { ...expected, readbackBytes } });
  exactKeys(workflowInputs, ["purpose", "requestId", "readbackArtifactId", "authorizationNonce"], "AUTH_WORKFLOW_INPUTS");
  if (workflowInputs.purpose !== AUTHORIZATION_PURPOSE || workflowInputs.purpose !== request.purpose) fail("AUTH_PURPOSE");
  if (!HASH.test(workflowInputs.requestId) || !RUN_ID.test(workflowInputs.readbackArtifactId) || !NONCE.test(workflowInputs.authorizationNonce)) fail("AUTH_WORKFLOW_INPUTS");
  if (workflowInputs.readbackArtifactId !== String(artifact.id) || workflowInputs.authorizationNonce !== request.authorizationNonce) fail("AUTH_WORKFLOW_INPUTS");
  const requestId = installRequestId({ request, readbackProvenance, controllerHeadSha });
  if (workflowInputs.requestId !== requestId) fail("AUTH_REQUEST_ID");
  const runName = expectedRunName(workflowInputs);
  const environment = validateController(run, approvals, controllerHeadSha, runName);
  validateRunInventory({ inventory, run, runName });
  return {
    schema: AUTHORIZATION_SCHEMA,
    decision: "INSTALL_ONLY_GO",
    purpose: AUTHORIZATION_PURPOSE,
    requestId,
    issuer: `https://github.com/${CONTROLLER_REPOSITORY}`,
    controllerRepository: CONTROLLER_REPOSITORY,
    controllerWorkflowPath: CONTROLLER_WORKFLOW_PATH,
    controllerRef: CONTROLLER_REF,
    controllerHeadSha,
    runId: String(run.id),
    runAttempt: 1,
    event: "workflow_dispatch",
    actor: { login: REVIEWER_LOGIN, id: REVIEWER_ID },
    triggeringActor: { login: REVIEWER_LOGIN, id: REVIEWER_ID },
    approval: {
      state: "approved",
      reviewerLogin: REVIEWER_LOGIN,
      reviewerId: REVIEWER_ID,
      environment: ENVIRONMENT,
      environmentId: environment.id,
      canAdminsBypass: false,
    },
    releaseRepository: request.releaseRepository,
    releaseCommit: request.releaseCommit,
    releaseManifestSha256: request.releaseManifestSha256,
    bundleDigestSha256: request.bundleDigestSha256,
    stagedReadbackSha256: request.stagedReadbackSha256,
    readbackProvenance,
    authorizationNonce: request.authorizationNonce,
    issuedAtEpoch: now,
    expiresAtEpoch: request.expiresAtEpoch,
    installOnly: true,
    startAuthorized: false,
  };
}

export function signAuthorization(payload, privateKeyPem) {
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    fail("AUTH_PRIVATE_KEY");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") fail("AUTH_PRIVATE_KEY");
  return {
    schema: ENVELOPE_SCHEMA,
    payload,
    signatureBase64Url: sign(null, canonicalBytes(payload), privateKey).toString("base64url"),
  };
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) fail(`AUTH_ENV_${name}`);
  return value;
}

if (process.argv[1]?.endsWith("install-only-authorization.mjs")) {
  try {
    if (process.argv.length !== 11 || process.argv[2] !== "sign") fail("AUTH_USAGE");
    const [requestPath, readbackPath, controllerRunPath, approvalsPath, inventoryPath, privateRunPath, privateJobPath, artifactPath] = process.argv.slice(3);
    const json = (path) => JSON.parse(readFileSync(path, "utf8"));
    const payload = buildAuthorization({
      request: json(requestPath),
      readbackBytes: readFileSync(readbackPath),
      run: json(controllerRunPath),
      approvals: json(approvalsPath),
      inventory: json(inventoryPath),
      privateRun: json(privateRunPath),
      privateJob: json(privateJobPath),
      artifact: json(artifactPath),
      controllerHeadSha: requiredEnv("GITHUB_SHA"),
      workflowInputs: {
        purpose: requiredEnv("HFS_AUTHORIZATION_PURPOSE"),
        requestId: requiredEnv("HFS_AUTHORIZATION_REQUEST_ID"),
        readbackArtifactId: requiredEnv("HFS_READBACK_ARTIFACT_ID"),
        authorizationNonce: requiredEnv("HFS_AUTHORIZATION_NONCE"),
      },
      expected: {
        repository: requiredEnv("HFS_PRIVATE_REPOSITORY"),
        workflowPath: requiredEnv("HFS_READBACK_WORKFLOW_PATH"),
        workflowRef: requiredEnv("HFS_READBACK_WORKFLOW_REF"),
        jobName: requiredEnv("HFS_READBACK_JOB_NAME"),
      },
    });
    process.stdout.write(`${JSON.stringify(signAuthorization(payload, requiredEnv("HFS_ED25519_SIGNING_KEY_PEM")))}\n`);
  } catch (error) {
    process.stderr.write(`AUTHORIZATION_REFUSED code=${error.message}\n`);
    process.exitCode = 78;
  }
}
