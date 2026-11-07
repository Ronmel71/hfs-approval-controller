import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const workflowPath = ".github/workflows/protected-credential-preflight.yml";
const workflow = readFileSync(workflowPath, "utf8");
const match = workflow.match(/node --input-type=module <<'NODE'\n([\s\S]*?)\n {10}NODE/);
assert.ok(match, "inline verifier must remain extractable for exact-code tests");
const source = match[1].replace(/^ {10}/gm, "");

for (const required of [
  "workflow_dispatch:",
  "actions: read",
  "environment: production-first-start",
  "timeout-minutes: 5",
  "github.ref == 'refs/heads/main'",
  "github.run_attempt == 1",
  "HFS_PRIVATE_READBACK_TOKEN: ${{ secrets.HFS_PRIVATE_READBACK_TOKEN }}",
  "HFS_PRIVATE_REPOSITORY: ${{ secrets.HFS_PRIVATE_REPOSITORY }}",
  "HFS_READBACK_WORKFLOW_PATH: ${{ secrets.HFS_READBACK_WORKFLOW_PATH }}",
  "HFS_READBACK_WORKFLOW_REF: ${{ secrets.HFS_READBACK_WORKFLOW_REF }}",
  "HFS_READBACK_JOB_NAME: ${{ secrets.HFS_READBACK_JOB_NAME }}",
  "HFS_PRIVATE_AUTHORIZATION_ISSUE: ${{ secrets.HFS_PRIVATE_AUTHORIZATION_ISSUE }}",
  "/actions/runs/${runId}/approvals",
  "redirect: \"error\"",
  "AbortSignal.timeout(10000)",
  "set +x",
]) assert.ok(workflow.includes(required), "missing workflow contract: " + required);

for (const forbidden of [
  "HFS_PRIVATE_SOURCE_READ_TOKEN",
  "HFS_ED25519_SIGNING_KEY_PEM",
  "createPrivateKey",
  "createPublicKey",
  "GITHUB_OUTPUT",
  "actions/cache",
  "actions/upload-artifact",
  "uses:",
  "id-token:",
  "contents:",
  "issues:",
  "deployments:",
  "packages:",
  "write-all",
  'method: "POST"',
  'method: "PUT"',
  'method: "PATCH"',
  'method: "DELETE"',
]) assert.equal(workflow.includes(forbidden), false, "forbidden workflow capability: " + forbidden);

const directory = mkdtempSync(join(tmpdir(), "hfs-readback-preflight-"));
const verifierPath = join(directory, "verifier.mjs");
const mockPath = join(dirname(fileURLToPath(import.meta.url)), "protected-credential-preflight.mock.mjs");
writeFileSync(verifierPath, source);

const baseEnvironment = {
  ...process.env,
  CONTROLLER_TOKEN: "controller-token-test",
  HFS_PRIVATE_READBACK_TOKEN: "private-token-test",
  HFS_PRIVATE_REPOSITORY: "Ronmel71/hfs-selger-app",
  HFS_READBACK_WORKFLOW_PATH: ".github/workflows/first-start-runner-transfer.yml",
  HFS_READBACK_WORKFLOW_REF: "refs/heads/staging",
  HFS_READBACK_JOB_NAME: "independent-install-only-readback",
  HFS_PRIVATE_AUTHORIZATION_ISSUE: "288",
  GITHUB_REPOSITORY: "Ronmel71/hfs-approval-controller",
  GITHUB_REF: "refs/heads/main",
  GITHUB_EVENT_NAME: "workflow_dispatch",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_RUN_ID: "123456789",
  GITHUB_SHA: "a".repeat(40),
};

function execute(testCase, overrides = {}) {
  const result = spawnSync(process.execPath, ["--import", mockPath, verifierPath], {
    encoding: "utf8",
    env: { ...baseEnvironment, PREFLIGHT_TEST_CASE: testCase, ...overrides },
  });
  for (const secret of ["controller-token-test", "private-token-test"]) {
    assert.equal(result.stdout.includes(secret), false, testCase + " leaked a token to stdout");
    assert.equal(result.stderr.includes(secret), false, testCase + " leaked a token to stderr");
  }
  return result;
}

const pass = execute("pass");
assert.equal(pass.status, 0, pass.stderr);
assert.equal(pass.stderr, "");
assert.equal(pass.stdout, "READBACK_PREFLIGHT_PASS PRIVATE_ACTIONS_READ PRIVATE_ISSUE_READ NATIVE_REVIEW_VERIFIED NO_WRITES NO_SIGNING\n");

for (const [testCase, expectedCode, overrides = {}] of [
  ["http401", "READBACK_PREFLIGHT_AUTH_FAILED"],
  ["http403", "READBACK_PREFLIGHT_SCOPE_DENIED"],
  ["http404", "READBACK_PREFLIGHT_TARGET_NOT_FOUND_OR_HIDDEN"],
  ["http500", "READBACK_PREFLIGHT_RESPONSE_INVALID"],
  ["transport", "READBACK_PREFLIGHT_RESPONSE_INVALID"],
  ["redirect", "READBACK_PREFLIGHT_RESPONSE_INVALID"],
  ["invalid-json", "READBACK_PREFLIGHT_RESPONSE_INVALID"],
  ["repo-mismatch", "READBACK_PREFLIGHT_REPOSITORY_MISMATCH"],
  ["workflow-mismatch", "READBACK_PREFLIGHT_WORKFLOW_MISMATCH"],
  ["issue-mismatch", "READBACK_PREFLIGHT_ISSUE_MISMATCH"],
  ["head-mismatch", "READBACK_PREFLIGHT_REQUIRED_REVIEW_MISSING"],
  ["reviewer-mismatch", "READBACK_PREFLIGHT_REQUIRED_REVIEW_MISSING"],
  ["environment-mismatch", "READBACK_PREFLIGHT_REQUIRED_REVIEW_MISSING"],
  ["admin-bypass", "READBACK_PREFLIGHT_REQUIRED_REVIEW_MISSING"],
  ["wrong-attempt", "READBACK_PREFLIGHT_REQUIRED_REVIEW_MISSING", { GITHUB_RUN_ATTEMPT: "2" }],
  ["missing-token", "READBACK_PREFLIGHT_AUTH_FAILED", { HFS_PRIVATE_READBACK_TOKEN: "" }],
  ["wrong-config-repo", "READBACK_PREFLIGHT_REPOSITORY_MISMATCH", { HFS_PRIVATE_REPOSITORY: "other/repo" }],
  ["wrong-config-workflow", "READBACK_PREFLIGHT_WORKFLOW_MISMATCH", { HFS_READBACK_JOB_NAME: "other-job" }],
  ["wrong-config-issue", "READBACK_PREFLIGHT_ISSUE_MISMATCH", { HFS_PRIVATE_AUTHORIZATION_ISSUE: "1" }],
]) {
  const result = execute(testCase, overrides);
  assert.notEqual(result.status, 0, testCase + " unexpectedly passed");
  assert.equal(result.stdout, "", testCase + " wrote unexpected stdout");
  assert.equal(result.stderr, expectedCode + "\n", testCase + " returned an unstable error");
}

rmSync(directory, { recursive: true, force: true });
process.stdout.write("protected-credential-preflight.test: PASS\n");
