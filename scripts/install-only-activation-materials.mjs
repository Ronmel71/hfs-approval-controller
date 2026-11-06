#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
} from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PRIVATE_REPOSITORY = "Ronmel71/hfs-selger-app";
const CONTROLLER_REPOSITORY = "Ronmel71/hfs-approval-controller";
const WORKFLOW_PATH = ".github/workflows/install-only-activation-materials.yml";
const ENVIRONMENT = { id: 26423058762, name: "production-first-start" };
const REVIEWER = { id: 321374159, login: "Ronmel71" };
const COMMIT = /^[0-9a-f]{40}$/;
const HASH = /^[0-9a-f]{64}$/;
const MATERIAL_NAMES = [
  "activation-material-handoff.json",
  "hfs-production-first-start-sudoers",
  "production-first-start-evidence-v2.pub",
  "production-first-start-install-v2.approval",
  "production-first-start-v2.trust",
].sort();
const FILES = {
  bootstrap: { bytes: 10926, sha256: "aae51f17a7b8da3c68871eec6f1324b7816761cbe1ab5968947c1bf032983cdf" },
  installer: { bytes: 9316, sha256: "06dd35c084cebcbeb76c7846ece0ba05382b20e3988f526acbe86af28d365a7a" },
  helper: { bytes: 7564, sha256: "99f7faf97c9179f7ea8d54d7c003206395d00e3d2e4fff6bc744b3ed122bb4ff" },
  verifier: { bytes: 11953, sha256: "5dcd88ee351e73a27312586699349d6904086523d8431a7fbe167bf8ff5cb00f" },
  runner: { bytes: 30077, sha256: "20ce3d7bccffa7166f9607f15a97740e9e1b91681a620a56ec62e85f5516d9a7" },
};
const MATERIAL_FILES = {
  trust: "production-first-start-v2.trust",
  public_key: "production-first-start-evidence-v2.pub",
  sudoers: "hfs-production-first-start-sudoers",
  approval: "production-first-start-install-v2.approval",
};
const APPROVAL_KEYS = [
  "schema", "repository", "source_commit", "target_host", "install_only", "start_authorized",
  "bootstrap_contract", "bootstrap_sha256", "installer_sha256", "authorization_nonce",
  "expires_at_epoch", "helper_sha256", "verifier_sha256", "runner_sha256", "trust_sha256",
  "public_key_sha256", "sudoers_sha256",
];
const TRUST_KEYS = [
  "schema", "helper_sha256", "verifier_sha256", "runner_sha256", "runner_bytes",
  "public_key_sha256", "commit", "artifact_path", "repository", "workflow_ref",
  "environment", "run_attempt", "host", "peer", "dns_name", "dns_a", "database_table_count",
];
const SUDOERS = Buffer.from([
  "Defaults:hfsdeploy env_reset",
  "Defaults!/usr/local/sbin/hfs-production-first-start-v2 !setenv, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin",
  "hfsdeploy ALL=(root) NOPASSWD:NOSETENV: /usr/local/sbin/hfs-production-first-start-v2 start, /usr/local/sbin/hfs-production-first-start-v2 after",
  "",
].join("\n"));

function fail(code) {
  throw new Error(code);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
}

function parseJson(bytes, code) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(code);
  }
}

function parseLines(bytes, keys, code) {
  const text = bytes.toString("utf8");
  if (text.includes("\r") || !text.endsWith("\n")) fail(code);
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== keys.length) fail(code);
  const result = {};
  lines.forEach((line, index) => {
    const separator = line.indexOf("=");
    if (separator < 1 || line.slice(0, separator) !== keys[index] || !line.slice(separator + 1)) fail(code);
    result[keys[index]] = line.slice(separator + 1);
  });
  return result;
}

function regularFile(path, code) {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(code);
  return readFileSync(path);
}

export function validateAuthenticatedSource(requestedSourceCommit, authenticatedPrivateRef) {
  if (!COMMIT.test(requestedSourceCommit) || !COMMIT.test(authenticatedPrivateRef) || requestedSourceCommit !== authenticatedPrivateRef) {
    fail("MATERIAL_PRIVATE_SOURCE_MISMATCH");
  }
}

export function validateControllerEvidence({ run, approvals, runId, controllerHead, reviewedControllerHead }) {
  if (!COMMIT.test(controllerHead) || controllerHead !== reviewedControllerHead || run.id !== Number(runId) ||
      run.workflow_id <= 0 || run.path !== WORKFLOW_PATH || run.event !== "workflow_dispatch" ||
      run.head_branch !== "main" || run.head_sha !== controllerHead || run.run_attempt !== 1 ||
      run.repository?.full_name !== CONTROLLER_REPOSITORY || run.head_repository?.full_name !== CONTROLLER_REPOSITORY ||
      run.head_repository?.private !== false || run.head_repository?.fork !== false ||
      run.actor?.login !== REVIEWER.login || run.actor?.id !== REVIEWER.id ||
      run.triggering_actor?.login !== REVIEWER.login || run.triggering_actor?.id !== REVIEWER.id ||
      !Array.isArray(run.pull_requests) || run.pull_requests.length !== 0) {
    fail("MATERIAL_CONTROLLER_RUN");
  }
  if (!Array.isArray(approvals) || approvals.length !== 1) fail("MATERIAL_CONTROLLER_APPROVAL");
  const approval = approvals[0];
  if (approval.state !== "approved" || approval.user?.login !== REVIEWER.login ||
      approval.user?.id !== REVIEWER.id || !Array.isArray(approval.environments) ||
      approval.environments.length !== 1 || approval.environments[0]?.id !== ENVIRONMENT.id ||
      approval.environments[0]?.name !== ENVIRONMENT.name || approval.environments[0]?.can_admins_bypass !== false) {
    fail("MATERIAL_CONTROLLER_APPROVAL");
  }
}

function validatePolicy(policyBytes) {
  const policy = parseJson(policyBytes, "MATERIAL_POLICY_JSON");
  if (policy.schema !== "hfs.production-first-start.install-only-bundle/v1" ||
      policy.status !== "CODE_ONLY_BUNDLE_READY" || policy.consoleGo !== false ||
      policy.repository !== PRIVATE_REPOSITORY || policy.targetHost !== "hfs-selger-app-prod-hel1-01" ||
      policy.installOnly !== true || policy.startAuthorized !== false || policy.approvalFieldCount !== 17 ||
      Object.hasOwn(policy, "sourceCommit") || !Array.isArray(policy.files) || policy.files.length !== 9) {
    fail("MATERIAL_POLICY_CONTRACT");
  }
  const ids = ["bootstrap", "installer", "helper", "verifier", "runner", "trust", "public_key", "sudoers", "approval"];
  if (policy.files.map((file) => file.id).join(",") !== ids.join(",")) fail("MATERIAL_POLICY_FILES");
  for (const id of ids.slice(0, 5)) {
    const file = policy.files.find((entry) => entry.id === id);
    if (file.bytes !== FILES[id].bytes || file.sha256 !== FILES[id].sha256) fail("MATERIAL_POLICY_FIXED_FILE_DRIFT");
  }
  for (const id of ids.slice(5)) {
    const file = policy.files.find((entry) => entry.id === id);
    if (file.bytes !== "ACTIVATION_REQUIRED" || file.sha256 !== "ACTIVATION_REQUIRED") fail("MATERIAL_POLICY_PLACEHOLDER_DRIFT");
  }
  const controller = policy.controllerAuthorization;
  if (controller?.repository !== CONTROLLER_REPOSITORY || controller.ref !== "refs/heads/main" ||
      controller.environment !== ENVIRONMENT.name || controller.stageOnlyReviewEnvironmentId !== ENVIRONMENT.id ||
      controller.reviewerLogin !== REVIEWER.login || controller.reviewerId !== REVIEWER.id) {
    fail("MATERIAL_POLICY_CONTROLLER_DRIFT");
  }
  return policy;
}

function makeTrust({ sourceCommit, publicKeySha256, targetHost }) {
  return Buffer.from([
    "schema=hfs.production-first-start.trust/v2",
    `helper_sha256=${FILES.helper.sha256}`,
    `verifier_sha256=${FILES.verifier.sha256}`,
    `runner_sha256=${FILES.runner.sha256}`,
    `runner_bytes=${FILES.runner.bytes}`,
    `public_key_sha256=${publicKeySha256}`,
    `commit=${sourceCommit}`,
    "artifact_path=deploy/production/host/hfs-first-start-f468ff3-after900-tlsready180-headless-v2",
    `repository=${PRIVATE_REPOSITORY}`,
    "workflow_ref=Ronmel71/hfs-selger-app/.github/workflows/production-first-start.yml@refs/heads/staging",
    `environment=${ENVIRONMENT.name}`,
    "run_attempt=1",
    `host=${targetHost}`,
    "peer=10.77.0.1",
    "dns_name=tilbud.facilityservices.no",
    "dns_a=62.238.3.65",
    "database_table_count=44",
    "",
  ].join("\n"));
}

function makeApproval({ sourceCommit, targetHost, nonce, expiresAtEpoch, digests }) {
  const values = {
    schema: "hfs.production-first-start.install-approval/v1",
    repository: PRIVATE_REPOSITORY,
    source_commit: sourceCommit,
    target_host: targetHost,
    install_only: "true",
    start_authorized: "false",
    bootstrap_contract: "hfs.production-first-start.sealed-bootstrap/v2",
    bootstrap_sha256: FILES.bootstrap.sha256,
    installer_sha256: FILES.installer.sha256,
    authorization_nonce: nonce,
    expires_at_epoch: String(expiresAtEpoch),
    helper_sha256: FILES.helper.sha256,
    verifier_sha256: FILES.verifier.sha256,
    runner_sha256: FILES.runner.sha256,
    trust_sha256: digests.trust,
    public_key_sha256: digests.public_key,
    sudoers_sha256: digests.sudoers,
  };
  return Buffer.from(`${APPROVAL_KEYS.map((key) => `${key}=${values[key]}`).join("\n")}\n`);
}

function validatePrivateKey(signingKeyPem) {
  if (!signingKeyPem) fail("MATERIAL_SIGNING_KEY_MISSING");
  let privateKey;
  try {
    privateKey = createPrivateKey(signingKeyPem);
  } catch {
    fail("MATERIAL_SIGNING_KEY_INVALID");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") fail("MATERIAL_SIGNING_KEY_INVALID");
  return privateKey;
}

export function validateMaterialDirectory({ outputDirectory, sourceCommit, policyBytes, controllerHead, now }) {
  const names = readdirSync(outputDirectory).sort();
  if (names.join("\n") !== MATERIAL_NAMES.join("\n")) fail("MATERIAL_FILE_SET");
  const bytes = Object.fromEntries(MATERIAL_NAMES.map((name) => [name, regularFile(join(outputDirectory, name), "MATERIAL_FILE_TYPE")]));
  for (const value of Object.values(bytes)) {
    if (/-----BEGIN [^-\n]*PRIVATE KEY-----/.test(value.toString("utf8"))) fail("MATERIAL_PRIVATE_KEY_EXPOSURE");
  }
  if (bytes["hfs-production-first-start-sudoers"].length !== 316 ||
      sha256(bytes["hfs-production-first-start-sudoers"]) !== "052cea6b47b250ea970347bcde2bc4ab218545852088128958d12a345bdea1ad") {
    fail("MATERIAL_SUDOERS_DRIFT");
  }
  const publicKeyBytes = bytes["production-first-start-evidence-v2.pub"];
  let publicKey;
  try {
    publicKey = createPublicKey(publicKeyBytes);
  } catch {
    fail("MATERIAL_PUBLIC_KEY_INVALID");
  }
  if (publicKey.asymmetricKeyType !== "ed25519" || /PRIVATE KEY/.test(publicKeyBytes.toString("utf8"))) fail("MATERIAL_PUBLIC_KEY_INVALID");
  const policy = validatePolicy(policyBytes);
  const trust = parseLines(bytes["production-first-start-v2.trust"], TRUST_KEYS, "MATERIAL_TRUST_FIELDS");
  if (trust.schema !== "hfs.production-first-start.trust/v2" || trust.helper_sha256 !== FILES.helper.sha256 ||
      trust.verifier_sha256 !== FILES.verifier.sha256 || trust.runner_sha256 !== FILES.runner.sha256 ||
      trust.runner_bytes !== String(FILES.runner.bytes) || trust.public_key_sha256 !== sha256(publicKeyBytes) ||
      trust.commit !== sourceCommit || trust.repository !== PRIVATE_REPOSITORY || trust.host !== policy.targetHost) {
    fail("MATERIAL_TRUST_BINDING");
  }
  const approval = parseLines(bytes["production-first-start-install-v2.approval"], APPROVAL_KEYS, "MATERIAL_APPROVAL_FIELDS");
  if (approval.schema !== "hfs.production-first-start.install-approval/v1" || approval.repository !== PRIVATE_REPOSITORY ||
      approval.source_commit !== sourceCommit || approval.target_host !== policy.targetHost || approval.install_only !== "true" ||
      approval.start_authorized !== "false" || !HASH.test(approval.authorization_nonce) ||
      approval.trust_sha256 !== sha256(bytes["production-first-start-v2.trust"]) ||
      approval.public_key_sha256 !== sha256(publicKeyBytes) ||
      approval.sudoers_sha256 !== sha256(bytes["hfs-production-first-start-sudoers"])) {
    fail("MATERIAL_APPROVAL_BINDING");
  }
  const expiry = Number(approval.expires_at_epoch);
  if (!/^[1-9][0-9]{9}$/.test(approval.expires_at_epoch) || !Number.isSafeInteger(expiry) || expiry <= now || expiry > now + 86400) {
    fail("MATERIAL_APPROVAL_EXPIRY");
  }
  const handoffBytes = bytes["activation-material-handoff.json"];
  const handoff = parseJson(handoffBytes, "MATERIAL_HANDOFF_JSON");
  exactKeys(handoff, ["schema", "repository", "sourceCommit", "policyManifestSha256", "controllerHeadSha", "files"], "MATERIAL_HANDOFF_FIELDS");
  if (handoff.schema !== "hfs.production-first-start.activation-material-handoff/v1" ||
      handoff.repository !== PRIVATE_REPOSITORY || handoff.sourceCommit !== sourceCommit ||
      handoff.policyManifestSha256 !== sha256(policyBytes) || handoff.controllerHeadSha !== controllerHead) {
    fail("MATERIAL_HANDOFF_BINDING");
  }
  exactKeys(handoff.files, Object.keys(MATERIAL_FILES), "MATERIAL_HANDOFF_FILE_SET");
  for (const [id, name] of Object.entries(MATERIAL_FILES)) {
    const entry = handoff.files[id];
    exactKeys(entry, ["name", "bytes", "sha256"], "MATERIAL_HANDOFF_FILE_FIELDS");
    if (entry.name !== name || entry.bytes !== bytes[name].length || entry.sha256 !== sha256(bytes[name])) fail("MATERIAL_HANDOFF_FILE_BINDING");
  }
  return handoff;
}

export function generateMaterials({
  sourceCommit,
  authenticatedPrivateRef,
  policyBytes,
  controllerHead,
  reviewedControllerHead,
  signingKeyPem,
  outputDirectory,
  now = Math.floor(Date.now() / 1000),
  nonce = randomBytes(32).toString("hex"),
}) {
  validateAuthenticatedSource(sourceCommit, authenticatedPrivateRef);
  if (!COMMIT.test(controllerHead) || controllerHead !== reviewedControllerHead) fail("MATERIAL_CONTROLLER_HEAD_MISMATCH");
  if (!HASH.test(nonce)) fail("MATERIAL_NONCE_FORMAT");
  const policy = validatePolicy(policyBytes);
  const privateKey = validatePrivateKey(signingKeyPem);
  const publicKeyBytes = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
  const trustBytes = makeTrust({ sourceCommit, publicKeySha256: sha256(publicKeyBytes), targetHost: policy.targetHost });
  const digests = { trust: sha256(trustBytes), public_key: sha256(publicKeyBytes), sudoers: sha256(SUDOERS) };
  const approvalBytes = makeApproval({ sourceCommit, targetHost: policy.targetHost, nonce, expiresAtEpoch: now + 3600, digests });
  const materials = {
    trust: trustBytes,
    public_key: publicKeyBytes,
    sudoers: SUDOERS,
    approval: approvalBytes,
  };
  mkdirSync(outputDirectory, { mode: 0o700 });
  for (const [id, name] of Object.entries(MATERIAL_FILES)) writeFileSync(join(outputDirectory, name), materials[id], { mode: 0o600, flag: "wx" });
  const handoff = {
    schema: "hfs.production-first-start.activation-material-handoff/v1",
    repository: PRIVATE_REPOSITORY,
    sourceCommit,
    policyManifestSha256: sha256(policyBytes),
    controllerHeadSha: controllerHead,
    files: Object.fromEntries(Object.entries(MATERIAL_FILES).map(([id, name]) => [id, {
      name,
      bytes: materials[id].length,
      sha256: sha256(materials[id]),
    }])),
  };
  writeFileSync(join(outputDirectory, "activation-material-handoff.json"), `${JSON.stringify(handoff, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  validateMaterialDirectory({ outputDirectory, sourceCommit, policyBytes, controllerHead, now });
  return handoff;
}

function parseArguments(argv) {
  const allowed = new Map([
    ["--source-commit", "sourceCommit"], ["--authenticated-private-ref", "authenticatedPrivateRef"],
    ["--policy", "policyPath"], ["--controller-head", "controllerHead"],
    ["--reviewed-controller-head", "reviewedControllerHead"], ["--output", "outputDirectory"],
    ["--controller-run", "controllerRunPath"], ["--controller-approvals", "controllerApprovalsPath"],
    ["--controller-run-id", "controllerRunId"],
  ]);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = allowed.get(argv[index]);
    if (!key || !argv[index + 1] || Object.hasOwn(values, key)) fail("MATERIAL_ARGUMENTS");
    values[key] = argv[index + 1];
  }
  if (Object.keys(values).length !== allowed.size) fail("MATERIAL_ARGUMENTS");
  return values;
}

export function runCli(argv = process.argv.slice(2), environment = process.env) {
  const args = parseArguments(argv);
  validateControllerEvidence({
    run: parseJson(readFileSync(args.controllerRunPath), "MATERIAL_CONTROLLER_RUN_JSON"),
    approvals: parseJson(readFileSync(args.controllerApprovalsPath), "MATERIAL_CONTROLLER_APPROVAL_JSON"),
    runId: args.controllerRunId,
    controllerHead: args.controllerHead,
    reviewedControllerHead: args.reviewedControllerHead,
  });
  const handoff = generateMaterials({
    ...args,
    policyBytes: readFileSync(args.policyPath),
    signingKeyPem: environment.HFS_ED25519_SIGNING_KEY_PEM,
    outputDirectory: resolve(args.outputDirectory),
  });
  process.stdout.write(`MATERIAL_SOURCE_CODE_READY_NO_GO\nPOLICY_MANIFEST_SHA256=${handoff.policyManifestSha256}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    runCli();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "MATERIAL_UNKNOWN"}\n`);
    process.exitCode = 1;
  }
}
