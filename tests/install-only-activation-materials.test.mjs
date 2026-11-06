import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  generateMaterials,
  validateAuthenticatedSource,
  validateControllerEvidence,
  validateMaterialDirectory,
} from "../scripts/install-only-activation-materials.mjs";

const sourceCommit = "6".repeat(40);
const controllerHead = "5".repeat(40);
const now = 1793980000;
const policy = {
  schema: "hfs.production-first-start.install-only-bundle/v1",
  status: "CODE_ONLY_BUNDLE_READY",
  consoleGo: false,
  repository: "Ronmel71/hfs-selger-app",
  targetHost: "hfs-selger-app-prod-hel1-01",
  installOnly: true,
  startAuthorized: false,
  approvalFieldCount: 17,
  controllerAuthorization: {
    repository: "Ronmel71/hfs-approval-controller",
    ref: "refs/heads/main",
    environment: "production-first-start",
    stageOnlyReviewEnvironmentId: 26423058762,
    reviewerLogin: "Ronmel71",
    reviewerId: 321374159,
  },
  files: [
    ["bootstrap", 10926, "aae51f17a7b8da3c68871eec6f1324b7816761cbe1ab5968947c1bf032983cdf"],
    ["installer", 9316, "06dd35c084cebcbeb76c7846ece0ba05382b20e3988f526acbe86af28d365a7a"],
    ["helper", 7564, "99f7faf97c9179f7ea8d54d7c003206395d00e3d2e4fff6bc744b3ed122bb4ff"],
    ["verifier", 11953, "5dcd88ee351e73a27312586699349d6904086523d8431a7fbe167bf8ff5cb00f"],
    ["runner", 30077, "20ce3d7bccffa7166f9607f15a97740e9e1b91681a620a56ec62e85f5516d9a7"],
    ["trust", "ACTIVATION_REQUIRED", "ACTIVATION_REQUIRED"],
    ["public_key", "ACTIVATION_REQUIRED", "ACTIVATION_REQUIRED"],
    ["sudoers", "ACTIVATION_REQUIRED", "ACTIVATION_REQUIRED"],
    ["approval", "ACTIVATION_REQUIRED", "ACTIVATION_REQUIRED"],
  ].map(([id, bytes, sha256]) => ({ id, bytes, sha256 })),
};
const policyBytes = Buffer.from(`${JSON.stringify(policy, null, 2)}\n`);
const { privateKey } = generateKeyPairSync("ed25519");
const signingKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

function temporary() {
  return mkdtempSync(join(tmpdir(), "hfs-controller-materials-"));
}

function generate(overrides = {}) {
  const root = temporary();
  const outputDirectory = join(root, "output");
  generateMaterials({
    sourceCommit,
    authenticatedPrivateRef: sourceCommit,
    policyBytes,
    controllerHead,
    reviewedControllerHead: controllerHead,
    signingKeyPem,
    outputDirectory,
    now,
    nonce: "a".repeat(64),
    ...overrides,
  });
  return { root, outputDirectory };
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error instanceof Error && error.message === code);
}

test("generates only the exact five nonsecret consumer-compatible files", () => {
  const fixture = generate();
  try {
    const handoff = validateMaterialDirectory({ ...fixture, sourceCommit, policyBytes, controllerHead, now });
    assert.equal(handoff.sourceCommit, sourceCommit);
    assert.equal(handoff.controllerHeadSha, controllerHead);
    assert.equal(readFileSync(join(fixture.outputDirectory, "hfs-production-first-start-sudoers")).length, 316);
    assert.doesNotMatch(readFileSync(join(fixture.outputDirectory, "production-first-start-evidence-v2.pub"), "utf8"), /PRIVATE KEY/);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("fails closed without the protected Ed25519 key", () => {
  const root = temporary();
  try {
    expectCode(() => generateMaterials({
      sourceCommit, authenticatedPrivateRef: sourceCommit, policyBytes, controllerHead,
      reviewedControllerHead: controllerHead, signingKeyPem: "", outputDirectory: join(root, "output"), now,
    }), "MATERIAL_SIGNING_KEY_MISSING");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects wrong private SHA and changed controller head", () => {
  expectCode(() => validateAuthenticatedSource(sourceCommit, "7".repeat(40)), "MATERIAL_PRIVATE_SOURCE_MISMATCH");
  const root = temporary();
  try {
    expectCode(() => generateMaterials({
      sourceCommit, authenticatedPrivateRef: sourceCommit, policyBytes, controllerHead,
      reviewedControllerHead: "8".repeat(40), signingKeyPem, outputDirectory: join(root, "output"), now,
    }), "MATERIAL_CONTROLLER_HEAD_MISMATCH");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects wrong reviewer and retry attempt", () => {
  const run = {
    id: 123456, workflow_id: 987, path: ".github/workflows/install-only-activation-materials.yml",
    event: "workflow_dispatch", head_branch: "main", head_sha: controllerHead, run_attempt: 1,
    repository: { full_name: "Ronmel71/hfs-approval-controller" },
    head_repository: { full_name: "Ronmel71/hfs-approval-controller", private: false, fork: false },
    actor: { login: "Ronmel71", id: 321374159 }, triggering_actor: { login: "Ronmel71", id: 321374159 }, pull_requests: [],
  };
  const approvals = [{
    state: "approved", user: { login: "Ronmel71", id: 321374159 },
    environments: [{ id: 26423058762, name: "production-first-start", can_admins_bypass: false }],
  }];
  validateControllerEvidence({ run, approvals, runId: "123456", controllerHead, reviewedControllerHead: controllerHead });
  expectCode(() => validateControllerEvidence({ run: { ...run, run_attempt: 2 }, approvals, runId: "123456", controllerHead, reviewedControllerHead: controllerHead }), "MATERIAL_CONTROLLER_RUN");
  expectCode(() => validateControllerEvidence({ run, approvals: [{ ...approvals[0], user: { login: "other", id: 1 } }], runId: "123456", controllerHead, reviewedControllerHead: controllerHead }), "MATERIAL_CONTROLLER_APPROVAL");
});

test("rejects trust/public-key mismatch and exact sudoers byte drift", () => {
  for (const [name, replacement, code] of [
    ["production-first-start-v2.trust", "public_key_sha256=", "MATERIAL_TRUST_BINDING"],
    ["hfs-production-first-start-sudoers", "Defaults:hfsdeploy env_reset", "MATERIAL_SUDOERS_DRIFT"],
  ]) {
    const fixture = generate();
    try {
      const path = join(fixture.outputDirectory, name);
      const original = readFileSync(path, "utf8");
      const changed = name.endsWith(".trust") ? original.replace(/public_key_sha256=[0-9a-f]{64}/, `${replacement}${"0".repeat(64)}`) : `${replacement}\n`;
      writeFileSync(path, changed);
      expectCode(() => validateMaterialDirectory({ ...fixture, sourceCommit, policyBytes, controllerHead, now }), code);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("rejects stale, overlong, and malformed one-use approval values", () => {
  for (const [key, value, code] of [
    ["expires_at_epoch", String(now), "MATERIAL_APPROVAL_EXPIRY"],
    ["expires_at_epoch", String(now + 86401), "MATERIAL_APPROVAL_EXPIRY"],
    ["authorization_nonce", "not-a-nonce", "MATERIAL_APPROVAL_BINDING"],
  ]) {
    const fixture = generate();
    try {
      const path = join(fixture.outputDirectory, "production-first-start-install-v2.approval");
      const changed = readFileSync(path, "utf8").replace(new RegExp(`${key}=[^\\n]+`), `${key}=${value}`);
      writeFileSync(path, changed);
      expectCode(() => validateMaterialDirectory({ ...fixture, sourceCommit, policyBytes, controllerHead, now }), code);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("rejects missing, extra, and private-key material", () => {
  for (const mutate of [
    (directory) => rmSync(join(directory, "production-first-start-v2.trust")),
    (directory) => writeFileSync(join(directory, "extra"), "unexpected\n"),
    (directory) => writeFileSync(
      join(directory, "production-first-start-v2.trust"),
      `-----BEGIN ${"PRIVATE KEY"}-----\nsynthetic-rejected-value\n-----END ${"PRIVATE KEY"}-----\n`,
    ),
  ]) {
    const fixture = generate();
    try {
      mutate(fixture.outputDirectory);
      assert.throws(() => validateMaterialDirectory({ ...fixture, sourceCommit, policyBytes, controllerHead, now }));
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("workflow remains manual, protected, SHA-pinned, and literal-disabled", () => {
  const workflow = readFileSync(new URL("../.github/workflows/install-only-activation-materials.yml", import.meta.url), "utf8");
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /environment: production-first-start/);
  assert.match(workflow, /publish-materials:\n    if: \$\{\{ false \}\}/);
  assert.match(workflow, /GITHUB_RUN_ATTEMPT" == 1/);
  assert.match(workflow, /actions\/runs\/\$GITHUB_RUN_ID\/approvals/);
  assert.match(workflow, /publish-materials:\n    if: \$\{\{ false \}\}[^\n]*\n[\s\S]*?    permissions:\n      actions: read\n      contents: read/);
  assert.equal((workflow.match(/\n      actions: read\n/g) ?? []).length, 1);
  assert.doesNotMatch(workflow, /\n\s+actions: write/);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40}/);
  assert.doesNotMatch(workflow, /pull_request:|pull_request_target:|repository_dispatch:|schedule:/);
  assert.doesNotMatch(workflow, /permissions:\s*write-all|id-token:\s*write|contents:\s*write/);
});
