const runId = 123456789;
const head = "a".repeat(40);
const privatePrefix = "/repos/Ronmel71/hfs-selger-app";
const controllerPrefix = "/repos/Ronmel71/hfs-approval-controller";
const fixtures = new Map([
  [privatePrefix, { full_name: "Ronmel71/hfs-selger-app", private: true, fork: false }],
  [privatePrefix + "/actions/workflows/379993056", { id: 379993056, path: ".github/workflows/first-start-runner-transfer.yml", state: "active" }],
  [privatePrefix + "/issues/288", { repository_url: "https://api.github.com" + privatePrefix, number: 288, state: "open" }],
  [controllerPrefix + "/actions/runs/" + runId, {
    id: runId,
    repository: { full_name: "Ronmel71/hfs-approval-controller", private: false, fork: false },
    path: ".github/workflows/protected-credential-preflight.yml",
    head_branch: "main",
    head_sha: head,
    event: "workflow_dispatch",
    run_attempt: 1,
    pull_requests: [],
  }],
  [controllerPrefix + "/actions/runs/" + runId + "/approvals", [{
    state: "approved",
    user: { login: "Ronmel71", id: 321374159 },
    environments: [{ id: 26423058762, name: "production-first-start", can_admins_bypass: false }],
    can_admins_bypass: false,
  }]],
]);

const testCase = process.env.PREFLIGHT_TEST_CASE;
if (testCase === "repo-mismatch") fixtures.get(privatePrefix).full_name = "other/repo";
if (testCase === "workflow-mismatch") fixtures.get(privatePrefix + "/actions/workflows/379993056").state = "disabled_manually";
if (testCase === "issue-mismatch") fixtures.get(privatePrefix + "/issues/288").state = "closed";
if (testCase === "head-mismatch") fixtures.get(controllerPrefix + "/actions/runs/" + runId).head_sha = "b".repeat(40);
if (testCase === "reviewer-mismatch") fixtures.get(controllerPrefix + "/actions/runs/" + runId + "/approvals")[0].user.id = 1;
if (testCase === "environment-mismatch") fixtures.get(controllerPrefix + "/actions/runs/" + runId + "/approvals")[0].environments[0].id = 1;
if (testCase === "admin-bypass") fixtures.get(controllerPrefix + "/actions/runs/" + runId + "/approvals")[0].can_admins_bypass = true;

globalThis.fetch = async (url, options) => {
  const parsed = new URL(url);
  if (parsed.origin !== "https://api.github.com" || !fixtures.has(parsed.pathname)) {
    throw new Error("unexpected endpoint");
  }
  if (options.method !== "GET" || options.redirect !== "error" || !(options.signal instanceof AbortSignal)) {
    throw new Error("unsafe request options");
  }
  const expectedToken = parsed.pathname.startsWith(controllerPrefix) ? "controller-token-test" : "private-token-test";
  if (options.headers.Authorization !== "Bearer " + expectedToken) throw new Error("wrong credential routing");
  if (testCase === "transport") throw new Error("transport failed");
  if (testCase === "redirect") throw new TypeError("redirect mode is error");
  if (testCase === "invalid-json") return { status: 200, json: async () => { throw new Error("invalid json"); } };
  const status = { http401: 401, http403: 403, http404: 404, http500: 500 }[testCase] ?? 200;
  return new Response(JSON.stringify(fixtures.get(parsed.pathname)), { status });
};
