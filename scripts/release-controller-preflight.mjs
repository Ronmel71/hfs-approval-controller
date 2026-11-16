import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { pathToFileURL } from "node:url";
import {
  POLICY,
  Refused,
  finalizeRequest,
  validateNativeApprovalEvidence,
  validateRequest,
} from "./release-controller-contract.mjs";

const refuse = (code) => { throw new Refused(code); };
const required = (name) => process.env[name] || refuse("PREFLIGHT_CONFIGURATION");
const asEpoch = (value, code) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) refuse(code);
  return Math.floor(parsed / 1000);
};

async function githubResponse(path, { binary = false, token, errorPrefix = "PREFLIGHT_API" } = {}) {
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${POLICY.controllerRepository}${path}`, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token ?? required("GH_TOKEN")}`,
        "User-Agent": "hfs-release-controller-preflight",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: binary ? "follow" : "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    refuse(`${errorPrefix}_NETWORK`);
  }
  if (response.status !== 200) {
    refuse([401, 403, 404, 429].includes(response.status) ? `${errorPrefix}_HTTP_${response.status}` : `${errorPrefix}_RESPONSE`);
  }
  return response;
}

async function getJson(path, options) {
  const response = await githubResponse(path, options);
  const errorPrefix = options?.errorPrefix ?? "PREFLIGHT_API";
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) refuse(`${errorPrefix}_CONTENT_TYPE`);
  try {
    return await response.json();
  } catch {
    refuse(`${errorPrefix}_JSON`);
  }
}

async function getBytes(path) {
  const response = await githubResponse(path, { binary: true });
  const finalUrl = new URL(response.url || `https://api.github.com/repos/${POLICY.controllerRepository}${path}`);
  if (finalUrl.protocol !== "https:") refuse("PREFLIGHT_ARTIFACT_REDIRECT");
  try {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > 256 * 1024) refuse("PREFLIGHT_ARTIFACT_SIZE");
    return bytes;
  } catch {
    refuse("PREFLIGHT_ARTIFACT_BYTES");
  }
}

async function completeInventory() {
  const runs = [];
  const ids = new Set();
  let total;
  let firstPageIds;
  for (let page = 1; page <= 10; page += 1) {
    const result = await getJson(`/actions/runs?event=workflow_dispatch&branch=main&per_page=100&page=${page}`);
    if (!Number.isSafeInteger(result.total_count) || !Array.isArray(result.workflow_runs)) refuse("PREFLIGHT_INVENTORY");
    if (total === undefined) total = result.total_count;
    if (result.total_count !== total) refuse("PREFLIGHT_INVENTORY_DRIFT");
    if (page === 1) firstPageIds = result.workflow_runs.map((run) => run.id);
    for (const run of result.workflow_runs) {
      if (!Number.isSafeInteger(run.id) || ids.has(run.id)) refuse("PREFLIGHT_INVENTORY");
      ids.add(run.id);
      runs.push(run);
    }
    if (result.workflow_runs.length < 100) {
      if (ids.size !== total) refuse("PREFLIGHT_INVENTORY_INCOMPLETE");
      const confirm = await getJson("/actions/runs?event=workflow_dispatch&branch=main&per_page=100&page=1");
      if (confirm.total_count !== total || !Array.isArray(confirm.workflow_runs) ||
          JSON.stringify(confirm.workflow_runs.map((run) => run.id)) !== JSON.stringify(firstPageIds)) refuse("PREFLIGHT_INVENTORY_DRIFT");
      return runs;
    }
  }
  refuse("PREFLIGHT_INVENTORY_INCOMPLETE");
}

function appPins() {
  return {
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
  };
}

function imageBinding(purpose) {
  if (purpose === "RELEASE_IMAGE_ONLY") return null;
  const reference = required("HFS_IMAGE_REFERENCE");
  return {
    reference,
    digest: reference.slice(reference.indexOf("@") + 1),
    publicationRunId: required("HFS_PUBLICATION_RUN_ID"),
    publicationControllerHead: required("HFS_PUBLICATION_CONTROLLER_HEAD"),
    publicationWorkflowBlob: required("HFS_PUBLICATION_WORKFLOW_BLOB"),
    publicationRequestId: required("HFS_PUBLICATION_REQUEST_ID"),
  };
}

function runFields(run) {
  return {
    id: String(run.id),
    attempt: run.run_attempt,
    event: run.event,
    repository: run.repository?.full_name,
    ref: `refs/heads/${run.head_branch}`,
    head: run.head_sha,
    actor: run.actor?.login,
    actorId: run.actor?.id,
    triggeringActor: run.triggering_actor?.login,
    triggeringActorId: run.triggering_actor?.id,
    pullRequestCount: run.pull_requests?.length,
  };
}

function buildRequest(run) {
  const purpose = required("HFS_RELEASE_PURPOSE");
  const purposePolicy = POLICY.purposes[purpose] || refuse("PREFLIGHT_PURPOSE");
  return finalizeRequest({
    schema: POLICY.schema,
    purpose,
    approvalPurpose: purposePolicy.approvalPurpose,
    requestId: "0".repeat(64),
    nonce: required("HFS_NONCE"),
    createdAtEpoch: Number(required("HFS_CREATED_AT_EPOCH")),
    expiresAtEpoch: Number(required("HFS_EXPIRES_AT_EPOCH")),
    app: appPins(),
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: required("HFS_CONTROLLER_HEAD"),
      workflow: purposePolicy.workflow,
      workflowBlob: required("HFS_CONTROLLER_WORKFLOW_BLOB"),
      executor: purposePolicy.executor,
      executorBlob: required("HFS_CONTROLLER_EXECUTOR_BLOB"),
    },
    run: runFields(run),
    secretNames: [...purposePolicy.secrets],
    image: imageBinding(purpose),
  });
}

function requestTitle(request) {
  const prefix = request.purpose === "RELEASE_IMAGE_ONLY" ? "Release image only" : "Release deploy only";
  const publication = request.purpose === "RELEASE_DEPLOY_ONLY" ? ` · publication ${request.image.publicationRunId}` : "";
  return `${prefix} · ${request.purpose} · ${request.requestId} · ${request.nonce}${publication}`;
}

function assertRunProvenance(run, purposePolicy) {
  if (!run || run.repository?.full_name !== POLICY.controllerRepository || run.repository?.private !== false ||
      run.repository?.fork !== false || run.head_repository?.full_name !== POLICY.controllerRepository ||
      run.head_repository?.fork !== false || run.path?.split("@")[0] !== purposePolicy.workflow ||
      run.head_branch !== "main" || run.event !== "workflow_dispatch" || run.run_attempt !== 1 ||
      !Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) refuse("PREFLIGHT_RUN_PROVENANCE");
}

function inventoryEntry(request, run) {
  return { requestId: request.requestId, nonce: request.nonce, purpose: request.purpose, runId: String(run.id), attempt: run.run_attempt };
}

function validateConsumerInventory(request, runs) {
  const exact = runs.filter((run) => run.display_title === requestTitle(request)).map((run) => inventoryEntry(request, run));
  validateRequest(request, { nowEpoch: Math.floor(Date.now() / 1000), inventory: exact });
  if (request.purpose === "RELEASE_DEPLOY_ONLY") {
    const consumers = runs.filter((run) =>
      run.path?.split("@")[0] === POLICY.purposes.RELEASE_DEPLOY_ONLY.workflow &&
      typeof run.display_title === "string" &&
      run.display_title.endsWith(` · publication ${request.image.publicationRunId}`));
    if (consumers.length !== 1 || String(consumers[0].id) !== String(request.run.id) || consumers[0].run_attempt !== 1) refuse("PREFLIGHT_PUBLICATION_REPLAY");
  }
}

async function readNativeEvidence(request, run, expectedEnvironmentId, { allowHistorical = false } = {}) {
  const purposePolicy = POLICY.purposes[request.purpose];
  const adminReadToken = process.env.HFS_CONTROLLER_ADMIN_READ_TOKEN || refuse("PREFLIGHT_ADMIN_READ_TOKEN_UNCONFIGURED");
  const [approvals, environment, branchProtection] = await Promise.all([
    getJson(`/actions/runs/${run.id}/approvals`),
    getJson(`/environments/${encodeURIComponent(purposePolicy.environment)}`),
    getJson("/branches/main/protection", { token: adminReadToken, errorPrefix: "PREFLIGHT_ADMIN_READ" }),
  ]);
  return validateNativeApprovalEvidence(request, {
    run,
    approvals,
    environment,
    branchProtection,
    expectedEnvironmentId,
    allowHistorical,
  });
}

function exactManifestKeys(manifest) {
  const expected = [
    "schema", "purpose", "approvalPurpose", "requestId", "nonce", "createdAtEpoch", "expiresAtEpoch",
    "publicationRunId", "controllerRepository", "controllerRef", "controllerHead", "controllerWorkflow",
    "controllerWorkflowBlob", "controllerExecutor", "controllerExecutorBlob", "appRepository", "appRef",
    "appCommit", "appTree", "imageReference", "imageDigest", "publishedAtEpoch",
  ];
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) ||
      JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expected.sort())) refuse("PROVENANCE_MANIFEST_FIELDS");
}

export function validatePublicationManifest(manifest, request, publicationRun, artifact) {
  exactManifestKeys(manifest);
  const publishedAt = manifest.publishedAtEpoch;
  const artifactAt = asEpoch(artifact.created_at, "PROVENANCE_ARTIFACT_TIMESTAMP");
  const runCreated = asEpoch(publicationRun.created_at, "PROVENANCE_RUN_TIMESTAMP");
  const runCompleted = asEpoch(publicationRun.updated_at, "PROVENANCE_RUN_TIMESTAMP");
  if (manifest.schema !== POLICY.provenanceSchema || manifest.purpose !== "RELEASE_IMAGE_ONLY" ||
      manifest.approvalPurpose !== POLICY.purposes.RELEASE_IMAGE_ONLY.approvalPurpose ||
      String(manifest.publicationRunId) !== String(publicationRun.id) ||
      manifest.requestId !== request.image.publicationRequestId ||
      manifest.controllerRepository !== POLICY.controllerRepository || manifest.controllerRef !== POLICY.controllerRef ||
      manifest.controllerHead !== request.image.publicationControllerHead ||
      manifest.controllerWorkflow !== POLICY.purposes.RELEASE_IMAGE_ONLY.workflow ||
      manifest.controllerWorkflowBlob !== request.image.publicationWorkflowBlob ||
      manifest.controllerExecutor !== POLICY.purposes.RELEASE_IMAGE_ONLY.executor ||
      !/^[0-9a-f]{40}$/.test(manifest.controllerExecutorBlob) ||
      manifest.appRepository !== POLICY.appRepository || manifest.appRef !== POLICY.appRef ||
      manifest.appCommit !== request.app.commit || manifest.appTree !== request.app.tree ||
      manifest.imageReference !== request.image.reference || manifest.imageDigest !== request.image.digest ||
      !/^[0-9a-f]{64}$/.test(manifest.nonce) || !Number.isSafeInteger(manifest.createdAtEpoch) ||
      !Number.isSafeInteger(manifest.expiresAtEpoch) || !Number.isSafeInteger(publishedAt) ||
      publishedAt < runCreated || publishedAt < manifest.createdAtEpoch || publishedAt >= manifest.expiresAtEpoch ||
      artifactAt < publishedAt || artifactAt > runCompleted + 60) refuse("PROVENANCE_MANIFEST");
  return manifest;
}

function zipSingleJson(bytes) {
  const eocd = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0 || eocd + 22 > bytes.length || bytes.readUInt16LE(eocd + 10) !== 1) refuse("PROVENANCE_ARTIFACT_ZIP");
  const central = bytes.readUInt32LE(eocd + 16);
  if (bytes.readUInt32LE(central) !== 0x02014b50) refuse("PROVENANCE_ARTIFACT_ZIP");
  const flags = bytes.readUInt16LE(central + 8);
  const method = bytes.readUInt16LE(central + 10);
  const compressedSize = bytes.readUInt32LE(central + 20);
  const uncompressedSize = bytes.readUInt32LE(central + 24);
  const nameLength = bytes.readUInt16LE(central + 28);
  const name = bytes.subarray(central + 46, central + 46 + nameLength).toString("utf8");
  const local = bytes.readUInt32LE(central + 42);
  if ((flags & 1) !== 0 || ![0, 8].includes(method) || name !== POLICY.provenanceArtifactFile ||
      bytes.readUInt32LE(local) !== 0x04034b50) refuse("PROVENANCE_ARTIFACT_ZIP");
  const localNameLength = bytes.readUInt16LE(local + 26);
  const localExtraLength = bytes.readUInt16LE(local + 28);
  const start = local + 30 + localNameLength + localExtraLength;
  const compressed = bytes.subarray(start, start + compressedSize);
  const content = method === 8 ? inflateRawSync(compressed, { maxOutputLength: 64 * 1024 }) : compressed;
  if (content.length !== uncompressedSize || content.length > 64 * 1024) refuse("PROVENANCE_ARTIFACT_ZIP");
  try {
    return JSON.parse(content.toString("utf8"));
  } catch {
    refuse("PROVENANCE_ARTIFACT_JSON");
  }
}

async function publicationEvidenceInner(request, runs, expectedEnvironmentId) {
  const publicationRun = await getJson(`/actions/runs/${request.image.publicationRunId}`);
  assertRunProvenance(publicationRun, POLICY.purposes.RELEASE_IMAGE_ONLY);
  if (publicationRun.status !== "completed" || publicationRun.conclusion !== "success" ||
      publicationRun.head_sha !== request.image.publicationControllerHead) refuse("PROVENANCE_RUN");
  const title = /^Release image only · RELEASE_IMAGE_ONLY · ([0-9a-f]{64}) · ([0-9a-f]{64})$/.exec(publicationRun.display_title);
  if (!title || title[1] !== request.image.publicationRequestId) refuse("PROVENANCE_REQUEST");
  const publicationMatches = runs.filter((run) => run.display_title === publicationRun.display_title &&
    run.path?.split("@")[0] === POLICY.purposes.RELEASE_IMAGE_ONLY.workflow);
  if (publicationMatches.length !== 1 || String(publicationMatches[0].id) !== String(publicationRun.id) ||
      publicationMatches[0].run_attempt !== 1) refuse("PROVENANCE_PUBLICATION_REPLAY");
  const [workflowContent, executorContent, artifacts] = await Promise.all([
    getJson(`/contents/${POLICY.purposes.RELEASE_IMAGE_ONLY.workflow}?ref=${publicationRun.head_sha}`),
    getJson(`/contents/${POLICY.purposes.RELEASE_IMAGE_ONLY.executor}?ref=${publicationRun.head_sha}`),
    getJson(`/actions/runs/${publicationRun.id}/artifacts?per_page=100`),
  ]);
  if (workflowContent.sha !== request.image.publicationWorkflowBlob || artifacts.total_count !== 1 ||
      !Array.isArray(artifacts.artifacts) || artifacts.artifacts.length !== 1) refuse("PROVENANCE_BLOB");
  const matches = artifacts.artifacts.filter((artifact) => artifact.name === POLICY.provenanceArtifactName);
  if (matches.length !== 1) refuse("PROVENANCE_ARTIFACT");
  const artifact = matches[0];
  if (!Number.isSafeInteger(artifact.id) || artifact.expired !== false ||
      artifact.workflow_run?.id !== publicationRun.id || artifact.workflow_run?.head_sha !== publicationRun.head_sha ||
      !/^sha256:[0-9a-f]{64}$/.test(artifact.digest)) refuse("PROVENANCE_ARTIFACT");
  const bytes = await getBytes(`/actions/artifacts/${artifact.id}/zip`);
  if (`sha256:${createHash("sha256").update(bytes).digest("hex")}` !== artifact.digest) refuse("PROVENANCE_ARTIFACT_DIGEST");
  const manifest = validatePublicationManifest(zipSingleJson(bytes), request, publicationRun, artifact);
  if (executorContent.sha !== manifest.controllerExecutorBlob) refuse("PROVENANCE_BLOB");
  const publicationRequest = finalizeRequest({
    schema: POLICY.schema,
    purpose: "RELEASE_IMAGE_ONLY",
    approvalPurpose: POLICY.purposes.RELEASE_IMAGE_ONLY.approvalPurpose,
    requestId: "0".repeat(64),
    nonce: manifest.nonce,
    createdAtEpoch: manifest.createdAtEpoch,
    expiresAtEpoch: manifest.expiresAtEpoch,
    app: appPins(),
    controller: {
      repository: POLICY.controllerRepository,
      ref: POLICY.controllerRef,
      head: manifest.controllerHead,
      workflow: manifest.controllerWorkflow,
      workflowBlob: manifest.controllerWorkflowBlob,
      executor: manifest.controllerExecutor,
      executorBlob: manifest.controllerExecutorBlob,
    },
    run: runFields(publicationRun),
    secretNames: [...POLICY.purposes.RELEASE_IMAGE_ONLY.secrets],
    image: null,
  });
  if (publicationRequest.requestId !== manifest.requestId) refuse("PROVENANCE_REQUEST_BINDING");
  validateRequest(publicationRequest, {
    nowEpoch: manifest.publishedAtEpoch,
    inventory: [inventoryEntry(publicationRequest, publicationRun)],
  });
  await readNativeEvidence(publicationRequest, publicationRun, expectedEnvironmentId, { allowHistorical: true });
  return Object.freeze({ publicationRunId: publicationRun.id, artifactId: artifact.id, digest: manifest.imageDigest });
}

export async function verifyPublicationProvenance(request, runs, {
  expectedEnvironmentId = POLICY.purposes.RELEASE_IMAGE_ONLY.environmentId,
} = {}) {
  try {
    return await publicationEvidenceInner(request, runs, expectedEnvironmentId);
  } catch {
    refuse("PROVENANCE_NOT_VERIFIED");
  }
}

export async function validateRequestPhase() {
  const runId = required("GITHUB_RUN_ID");
  const run = await getJson(`/actions/runs/${runId}`);
  const purpose = required("HFS_RELEASE_PURPOSE");
  const purposePolicy = POLICY.purposes[purpose] || refuse("PREFLIGHT_PURPOSE");
  assertRunProvenance(run, purposePolicy);
  const request = buildRequest(run);
  if (request.requestId !== required("HFS_REQUEST_ID")) refuse("PREFLIGHT_REQUEST_ID");
  if (run.display_title !== requestTitle(request)) refuse("PREFLIGHT_RUN_NAME");
  const runs = await completeInventory();
  validateConsumerInventory(request, runs);
  process.stdout.write(`RELEASE_CONTROLLER_REQUEST_VALID purpose=${purpose} request_id=${request.requestId}\n`);
  return request;
}

export async function verifyNativeApprovalPhase({
  expectedEnvironmentId,
  publicationEnvironmentId = POLICY.purposes.RELEASE_IMAGE_ONLY.environmentId,
} = {}) {
  const runId = required("GITHUB_RUN_ID");
  const run = await getJson(`/actions/runs/${runId}`);
  const purpose = required("HFS_RELEASE_PURPOSE");
  const purposePolicy = POLICY.purposes[purpose] || refuse("PREFLIGHT_PURPOSE");
  assertRunProvenance(run, purposePolicy);
  const request = buildRequest(run);
  if (request.requestId !== required("HFS_REQUEST_ID") || run.display_title !== requestTitle(request)) refuse("PREFLIGHT_REQUEST_ID");
  await readNativeEvidence(request, run, expectedEnvironmentId ?? purposePolicy.environmentId);
  if (purpose === "RELEASE_DEPLOY_ONLY") {
    const runs = await completeInventory();
    validateConsumerInventory(request, runs);
    await verifyPublicationProvenance(request, runs, { expectedEnvironmentId: publicationEnvironmentId });
  }
  process.stdout.write(`RELEASE_CONTROLLER_NATIVE_APPROVAL_VERIFIED purpose=${purpose} request_id=${request.requestId}\n`);
  return request;
}

// Backward-compatible export for tests and callers; it is strictly the pre-gate phase.
export const preflight = validateRequestPhase;

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3 || !["validate-request", "verify-native-approval"].includes(process.argv[2])) refuse("PREFLIGHT_USAGE");
    if (process.argv[2] === "validate-request") await validateRequestPhase();
    else await verifyNativeApprovalPhase();
  } catch (error) {
    process.stderr.write(`RELEASE_CONTROLLER_PREFLIGHT_REFUSED code=${error instanceof Refused ? error.code : "PREFLIGHT_INTERNAL"}\n`);
    process.exitCode = 78;
  }
}
