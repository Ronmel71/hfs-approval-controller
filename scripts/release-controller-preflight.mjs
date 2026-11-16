import { POLICY, finalizeRequest, validateRequest } from "./release-controller-contract.mjs";
import { pathToFileURL } from "node:url";

const refuse = (code) => { throw new Error(code); };
const required = (name) => process.env[name] || refuse("PREFLIGHT_CONFIGURATION");

async function getJson(path) {
  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${POLICY.controllerRepository}${path}`, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${required("GH_TOKEN")}`,
        "User-Agent": "hfs-release-controller-preflight",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    refuse("PREFLIGHT_API_NETWORK");
  }
  if (response.status !== 200) refuse([401, 403, 404, 429].includes(response.status) ? `PREFLIGHT_API_HTTP_${response.status}` : "PREFLIGHT_API_RESPONSE");
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) refuse("PREFLIGHT_API_CONTENT_TYPE");
  try {
    return await response.json();
  } catch {
    refuse("PREFLIGHT_API_JSON");
  }
}
async function completeInventory(expectedTitle, request) {
  const found = [];
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
      if (run.display_title === expectedTitle) {
        found.push({ requestId: request.requestId, nonce: request.nonce, purpose: request.purpose, runId: String(run.id), attempt: run.run_attempt });
      }
    }
    if (result.workflow_runs.length < 100) {
      if (ids.size !== total) refuse("PREFLIGHT_INVENTORY_INCOMPLETE");
      const confirm = await getJson("/actions/runs?event=workflow_dispatch&branch=main&per_page=100&page=1");
      if (confirm.total_count !== total || !Array.isArray(confirm.workflow_runs) ||
          JSON.stringify(confirm.workflow_runs.map((run) => run.id)) !== JSON.stringify(firstPageIds)) refuse("PREFLIGHT_INVENTORY_DRIFT");
      return found;
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

export async function preflight() {
  const purpose = required("HFS_RELEASE_PURPOSE");
  const purposePolicy = POLICY.purposes[purpose] || refuse("PREFLIGHT_PURPOSE");
  const runId = required("GITHUB_RUN_ID");
  const run = await getJson(`/actions/runs/${runId}`);
  if (String(run.id) !== runId || run.repository?.full_name !== POLICY.controllerRepository || run.repository?.private !== false ||
      run.repository?.fork !== false || run.head_repository?.full_name !== POLICY.controllerRepository || run.head_repository?.fork !== false ||
      run.path?.split("@")[0] !== purposePolicy.workflow || run.head_branch !== "main" || run.event !== "workflow_dispatch" ||
      !Array.isArray(run.pull_requests)) refuse("PREFLIGHT_RUN_PROVENANCE");

  const unsigned = {
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
    run: {
      id: runId,
      attempt: run.run_attempt,
      event: run.event,
      repository: run.repository.full_name,
      ref: `refs/heads/${run.head_branch}`,
      head: run.head_sha,
      actor: run.actor?.login,
      actorId: run.actor?.id,
      triggeringActor: run.triggering_actor?.login,
      triggeringActorId: run.triggering_actor?.id,
      pullRequestCount: run.pull_requests.length,
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
    image: imageBinding(purpose),
  };
  const request = finalizeRequest(unsigned);
  if (request.requestId !== required("HFS_REQUEST_ID")) refuse("PREFLIGHT_REQUEST_ID");
  const expectedTitle = `${purpose === "RELEASE_IMAGE_ONLY" ? "Release image only" : "Release deploy only"} · ${purpose} · ${request.requestId} · ${request.nonce}`;
  if (run.display_title !== expectedTitle) refuse("PREFLIGHT_RUN_NAME");
  const inventory = await completeInventory(expectedTitle, request);
  validateRequest(request, { nowEpoch: Math.floor(Date.now() / 1000), inventory });
  process.stdout.write(`RELEASE_CONTROLLER_PREFLIGHT_PASS purpose=${purpose} request_id=${request.requestId}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await preflight();
  } catch (error) {
    process.stderr.write(`RELEASE_CONTROLLER_PREFLIGHT_REFUSED code=${error instanceof Error ? error.message : "PREFLIGHT_INTERNAL"}\n`);
    process.exitCode = 78;
  }
}
