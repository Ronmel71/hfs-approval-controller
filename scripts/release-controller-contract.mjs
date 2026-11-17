import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const POLICY = Object.freeze({
  schema: "hfs.public-release-controller/v1",
  provenanceSchema: "hfs.public-release-image-provenance/v1",
  provenanceArtifactName: "hfs-release-image-provenance",
  provenanceArtifactFile: "hfs-release-image-provenance.json",
  appRepository: "Ronmel71/hfs-selger-app",
  appRef: "refs/heads/staging",
  appWorkflow: ".github/workflows/production-release-approved.yml",
  appWorkflowBlob: "2c15f1e1a47af65d309c08eca4b86cbb445734a0",
  composeBlob: "aee2e09c124c02b89dce653b9d1f628c1ea00eb6",
  caddyBlob: "3049dae5a81cc2396990ca986a97e5275f9a83dd",
  helperBlob: "30ee1ec77efe72d754a17ecc839f0cfa581542ce",
  sudoersBlob: "baa83f6efe64faab8f12cb5f5a9b6a5665b51de8",
  controllerRepository: "Ronmel71/hfs-approval-controller",
  controllerRef: "refs/heads/main",
  reviewer: "Ronmel71",
  reviewerId: 321374159,
  maxLifetimeSeconds: 30 * 60,
  purposes: Object.freeze({
    RELEASE_IMAGE_ONLY: Object.freeze({
      approvalPurpose: "PREPARE_IMAGE",
      workflow: ".github/workflows/release-image-only.yml",
      executor: "scripts/release-image-only.sh",
      environment: "production-image-publication",
      environmentId: 27579543667,
      protectedJobName: "Native approval · RELEASE_IMAGE_ONLY",
      secrets: Object.freeze(["HFS_GHCR_PUBLISH_TOKEN", "HFS_PRIVATE_SOURCE_READ_TOKEN"]),
    }),
    RELEASE_DEPLOY_ONLY: Object.freeze({
      approvalPurpose: "APPROVE_DEPLOY",
      workflow: ".github/workflows/release-deploy-only.yml",
      executor: "scripts/release-deploy-only.sh",
      environment: "production-host-deployment",
      environmentId: 27579657157,
      protectedJobName: "Native approval · RELEASE_DEPLOY_ONLY",
      secrets: Object.freeze([
        "DEPLOY_SSH_KEY",
        "DEPLOY_SSH_KNOWN_HOSTS",
        "DEPLOY_USER",
        "DEPLOY_WIREGUARD_CONFIG",
        "DEPLOY_WIREGUARD_HOST",
        "HFS_PRIVATE_SOURCE_READ_TOKEN",
      ]),
    }),
  }),
});

export class Refused extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const refuse = (code) => { throw new Refused(code); };
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]{5,19}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IMAGE = /^ghcr\.io\/ronmel71\/hfs-selger-app@sha256:[0-9a-f]{64}$/;

function exactKeys(value, expected, code) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) refuse(code);
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function epoch(value, code) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) refuse(code);
  return Math.floor(parsed / 1000);
}

function requestBinding(request) {
  // GitHub assigns the run ID after dispatch. Native approval is deliberately
  // absent: pre-gate validation must never claim that review already happened.
  const binding = {
    schema: request.schema,
    purpose: request.purpose,
    approvalPurpose: request.approvalPurpose,
    nonce: request.nonce,
    createdAtEpoch: request.createdAtEpoch,
    expiresAtEpoch: request.expiresAtEpoch,
    app: request.app,
    controller: request.controller,
    secretNames: request.secretNames,
    image: request.image,
  };
  return createHash("sha256").update(stable(binding)).digest("hex");
}

function validatePins(request, purposePolicy) {
  exactKeys(request.app, ["repository", "ref", "commit", "tree", "workflow", "workflowBlob", "composeBlob", "caddyBlob", "helperBlob", "sudoersBlob"], "CONTRACT_APP_FIELDS");
  if (request.app.repository !== POLICY.appRepository || request.app.ref !== POLICY.appRef ||
      !SHA40.test(request.app.commit) || !SHA40.test(request.app.tree) ||
      request.app.workflow !== POLICY.appWorkflow || request.app.workflowBlob !== POLICY.appWorkflowBlob ||
      request.app.composeBlob !== POLICY.composeBlob || request.app.caddyBlob !== POLICY.caddyBlob ||
      request.app.helperBlob !== POLICY.helperBlob || request.app.sudoersBlob !== POLICY.sudoersBlob) refuse("CONTRACT_APP_PIN");
  exactKeys(request.controller, ["repository", "ref", "head", "workflow", "workflowBlob", "executor", "executorBlob"], "CONTRACT_CONTROLLER_FIELDS");
  if (request.controller.repository !== POLICY.controllerRepository || request.controller.ref !== POLICY.controllerRef ||
      request.controller.workflow !== purposePolicy.workflow || request.controller.executor !== purposePolicy.executor ||
      !SHA40.test(request.controller.head) || !SHA40.test(request.controller.workflowBlob) ||
      !SHA40.test(request.controller.executorBlob)) refuse("CONTRACT_CONTROLLER_PIN");
}

function validateRun(request) {
  exactKeys(request.run, ["id", "attempt", "event", "repository", "ref", "head", "actor", "actorId", "triggeringActor", "triggeringActorId", "pullRequestCount"], "CONTRACT_RUN_FIELDS");
  if (!RUN_ID.test(String(request.run.id)) || request.run.attempt !== 1 || request.run.event !== "workflow_dispatch" ||
      request.run.repository !== POLICY.controllerRepository || request.run.ref !== POLICY.controllerRef ||
      request.run.head !== request.controller.head || request.run.actor !== POLICY.reviewer ||
      request.run.actorId !== POLICY.reviewerId || request.run.triggeringActor !== POLICY.reviewer ||
      request.run.triggeringActorId !== POLICY.reviewerId || request.run.pullRequestCount !== 0) refuse("CONTRACT_RUN");
}

function validateFreshness(request, nowEpoch) {
  if (!Number.isSafeInteger(request.createdAtEpoch) || !Number.isSafeInteger(request.expiresAtEpoch) ||
      request.createdAtEpoch > nowEpoch || request.expiresAtEpoch <= nowEpoch ||
      request.expiresAtEpoch - request.createdAtEpoch > POLICY.maxLifetimeSeconds) refuse("CONTRACT_FRESHNESS");
}

function validateSecrets(request, purposePolicy) {
  if (!Array.isArray(request.secretNames) || request.secretNames.some((name) => typeof name !== "string") ||
      JSON.stringify([...request.secretNames].sort()) !== JSON.stringify([...purposePolicy.secrets].sort())) refuse("CONTRACT_SECRET_SCOPE");
}

function validateImageBinding(request) {
  if (request.image !== null) refuse("CONTRACT_IMAGE_PREMATURE");
}

function validateDeployBinding(request) {
  exactKeys(request.image, ["reference", "digest", "publicationRunId", "publicationControllerHead", "publicationWorkflowBlob", "publicationRequestId"], "CONTRACT_IMAGE_FIELDS");
  if (!IMAGE.test(request.image.reference) || !DIGEST.test(request.image.digest) ||
      request.image.reference !== `ghcr.io/ronmel71/hfs-selger-app@${request.image.digest}` ||
      !RUN_ID.test(String(request.image.publicationRunId)) || !SHA40.test(request.image.publicationControllerHead) ||
      !SHA40.test(request.image.publicationWorkflowBlob) || !SHA64.test(request.image.publicationRequestId)) refuse("CONTRACT_IMAGE_BINDING");
}

export function validateRequest(request, { nowEpoch = Math.floor(Date.now() / 1000), inventory = [] } = {}) {
  exactKeys(request, ["schema", "purpose", "approvalPurpose", "requestId", "nonce", "createdAtEpoch", "expiresAtEpoch", "app", "controller", "run", "secretNames", "image"], "CONTRACT_FIELDS");
  const purposePolicy = POLICY.purposes[request.purpose];
  if (!purposePolicy || request.schema !== POLICY.schema || request.approvalPurpose !== purposePolicy.approvalPurpose) refuse("CONTRACT_PURPOSE");
  if (!SHA64.test(request.nonce) || !SHA64.test(request.requestId)) refuse("CONTRACT_IDENTIFIER");
  validatePins(request, purposePolicy);
  validateRun(request);
  validateFreshness(request, nowEpoch);
  validateSecrets(request, purposePolicy);
  if (request.purpose === "RELEASE_IMAGE_ONLY") validateImageBinding(request);
  else validateDeployBinding(request);
  if (request.requestId !== requestBinding(request)) refuse("CONTRACT_REQUEST_ID");
  if (!Array.isArray(inventory)) refuse("CONTRACT_INVENTORY");
  const matching = inventory.filter((entry) => isObject(entry) && entry.requestId === request.requestId &&
    entry.nonce === request.nonce && entry.purpose === request.purpose);
  if (matching.length !== 1 || String(matching[0].runId) !== String(request.run.id) || matching[0].attempt !== 1) refuse("CONTRACT_REPLAY");
  return Object.freeze({ purpose: request.purpose, requestId: request.requestId, appCommit: request.app.commit });
}

export function validateNativeApprovalEvidence(request, {
  run,
  approvals,
  jobInventory,
  environment,
  branchProtection,
  expectedEnvironmentId = POLICY.purposes[request.purpose]?.environmentId,
  nowEpoch = Math.floor(Date.now() / 1000),
  allowHistorical = false,
} = {}) {
  const purposePolicy = POLICY.purposes[request.purpose] || refuse("NATIVE_PURPOSE");
  if (!Number.isSafeInteger(expectedEnvironmentId)) refuse("NATIVE_ENVIRONMENT_ID_UNCONFIGURED");
  if (!isObject(run) || String(run.id) !== String(request.run.id) || run.run_attempt !== 1 ||
      run.event !== "workflow_dispatch" || run.head_branch !== "main" || run.head_sha !== request.controller.head ||
      run.repository?.full_name !== POLICY.controllerRepository ||
      (run.status !== "in_progress" && run.status !== "completed")) refuse("NATIVE_RUN");
  const runCreated = epoch(run.created_at, "NATIVE_RUN_TIMESTAMP");
  if (runCreated < request.createdAtEpoch || runCreated >= request.expiresAtEpoch || runCreated > nowEpoch) refuse("NATIVE_RUN_TIMESTAMP");
  if (!Array.isArray(approvals) || approvals.length !== 1) refuse("NATIVE_APPROVAL_COUNT");
  const approval = approvals[0];
  if (!isObject(approval) || approval.state !== "approved" || approval.user?.login !== POLICY.reviewer ||
      approval.user?.id !== POLICY.reviewerId || !Array.isArray(approval.environments) || approval.environments.length !== 1 ||
      approval.environments[0]?.name !== purposePolicy.environment || approval.environments[0]?.id !== expectedEnvironmentId) refuse("NATIVE_APPROVAL");
  if (!isObject(jobInventory) || !Number.isSafeInteger(jobInventory.total_count) ||
      !Array.isArray(jobInventory.jobs) || jobInventory.total_count !== jobInventory.jobs.length ||
      jobInventory.jobs.length !== 2) refuse("NATIVE_JOB_INVENTORY");
  const ids = new Set();
  for (const job of jobInventory.jobs) {
    if (!Number.isSafeInteger(job?.id) || ids.has(job.id)) refuse("NATIVE_JOB_INVENTORY");
    ids.add(job.id);
    if (String(job.run_id) !== String(run.id) || job.run_attempt !== 1 || job.head_sha !== request.controller.head ||
        job.head_branch !== "main" || job.run_url !== `https://api.github.com/repos/${POLICY.controllerRepository}/actions/runs/${run.id}`) {
      refuse("NATIVE_JOB_PROVENANCE");
    }
  }
  const validationJobs = jobInventory.jobs.filter((job) => job.name === "validate-request");
  const expectedProtectedJobName = `${purposePolicy.protectedJobName} · ${request.app.commit}`;
  const protectedJobs = jobInventory.jobs.filter((job) => job.name === expectedProtectedJobName);
  if (validationJobs.length !== 1 || protectedJobs.length !== 1) refuse("NATIVE_JOB_IDENTITY");
  const validationJob = validationJobs[0];
  const protectedJob = protectedJobs[0];
  const validationCreated = epoch(validationJob.created_at, "NATIVE_JOB_TIMESTAMP");
  const validationStarted = epoch(validationJob.started_at, "NATIVE_JOB_TIMESTAMP");
  const validationCompleted = epoch(validationJob.completed_at, "NATIVE_JOB_TIMESTAMP");
  const protectedCreated = epoch(protectedJob.created_at, "NATIVE_JOB_TIMESTAMP");
  const protectedStarted = epoch(protectedJob.started_at, "NATIVE_JOB_TIMESTAMP");
  if (validationJob.status !== "completed" || validationJob.conclusion !== "success" ||
      validationCreated < runCreated || validationStarted < validationCreated || validationCompleted < validationStarted ||
      validationCompleted > protectedStarted || protectedCreated < runCreated ||
      protectedStarted < protectedCreated || protectedStarted >= request.expiresAtEpoch || protectedStarted > nowEpoch) {
    refuse("NATIVE_JOB_ORDER");
  }
  if (allowHistorical) {
    const protectedCompleted = epoch(protectedJob.completed_at, "NATIVE_JOB_TIMESTAMP");
    if (run.status !== "completed" || run.conclusion !== "success" || protectedJob.status !== "completed" ||
        protectedJob.conclusion !== "success" || protectedCompleted < protectedStarted ||
        protectedCompleted >= request.expiresAtEpoch || protectedCompleted > nowEpoch) refuse("NATIVE_JOB_ORDER");
  } else if (run.status !== "in_progress" || protectedJob.status !== "in_progress" ||
      protectedJob.conclusion !== null || protectedJob.completed_at !== null || request.expiresAtEpoch <= nowEpoch) {
    refuse("NATIVE_APPROVAL_FRESHNESS");
  }
  if (!isObject(environment) || environment.name !== purposePolicy.environment || environment.id !== expectedEnvironmentId ||
      environment.can_admins_bypass !== false || !Array.isArray(environment.protection_rules)) refuse("NATIVE_ENVIRONMENT");
  const reviewerRules = environment.protection_rules.filter((rule) => rule?.type === "required_reviewers");
  const branchRules = environment.protection_rules.filter((rule) => rule?.type === "branch_policy");
  if (reviewerRules.length !== 1 || branchRules.length !== 1 || reviewerRules[0].prevent_self_review !== false ||
      !Array.isArray(reviewerRules[0].reviewers) || reviewerRules[0].reviewers.length !== 1 ||
      reviewerRules[0].reviewers[0]?.type !== "User" || reviewerRules[0].reviewers[0]?.reviewer?.login !== POLICY.reviewer ||
      reviewerRules[0].reviewers[0]?.reviewer?.id !== POLICY.reviewerId) refuse("NATIVE_REVIEW_POLICY");
  if (environment.deployment_branch_policy?.protected_branches !== true ||
      environment.deployment_branch_policy?.custom_branch_policies !== false) refuse("NATIVE_BRANCH_POLICY");
  if (!isObject(branchProtection) || branchProtection.enforce_admins?.enabled !== true ||
      branchProtection.allow_force_pushes?.enabled !== false || branchProtection.allow_deletions?.enabled !== false) refuse("NATIVE_MAIN_PROTECTION");
  return Object.freeze({
    environment: purposePolicy.environment,
    environmentId: expectedEnvironmentId,
    reviewerId: POLICY.reviewerId,
    approvalNotBeforeEpoch: runCreated,
    approvalNotAfterEpoch: protectedStarted,
    protectedJobId: protectedJob.id,
  });
}

export function finalizeRequest(request) {
  const copy = structuredClone(request);
  delete copy.nativeApproval;
  copy.requestId = requestBinding(copy);
  return copy;
}

export function validatePublishedImage(request, observedReference) {
  validateRequest(request, { nowEpoch: request.createdAtEpoch, inventory: [{ requestId: request.requestId, nonce: request.nonce, purpose: request.purpose, runId: request.run.id, attempt: 1 }] });
  if (request.purpose !== "RELEASE_IMAGE_ONLY" || !IMAGE.test(observedReference)) refuse("CONTRACT_PUBLISHED_DIGEST");
  return observedReference.slice(observedReference.indexOf("@") + 1);
}

export function fixtureFromFile(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function cli(argv) {
  try {
    if (argv.length !== 4 || argv[2] !== "validate") refuse("CONTRACT_USAGE");
    const request = fixtureFromFile(argv[3]);
    validateRequest(request, {
      nowEpoch: Number(process.env.HFS_NOW_EPOCH),
      inventory: JSON.parse(process.env.HFS_RUN_INVENTORY_JSON ?? "[]"),
    });
    process.stdout.write(`RELEASE_CONTROLLER_CONTRACT_PASS purpose=${request.purpose} request_id=${request.requestId}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`RELEASE_CONTROLLER_REFUSED code=${error instanceof Refused ? error.code : "CONTRACT_INTERNAL"}\n`);
    return 78;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await cli(process.argv);
