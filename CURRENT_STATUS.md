# Current status

## 2026-11-16 — issue #430 branch-protection readback capability correction

- Existing controller PR #13 and branch `feat/issue-428-public-release-controller` were updated in place; no replacement branch or PR was created. The issue-pinned head/base matched before editing, and the verified `stage-only-review.yml` blob remains `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`.
- Capability readback confirmed that public `/branches/main` exposes only a weak `protected: true`; public `/rulesets` and `/rules/branches/main` are empty for the controller's classic protection. None can prove enforce-admins ON plus force-push/deletion OFF. Exact `/branches/main/protection` remains the necessary evidence and requires Administration read.
- Native approval/environment reads retain the ordinary job `GITHUB_TOKEN` with `actions: read`. Branch-protection readback now requires only a distinct environment-scoped `HFS_CONTROLLER_ADMIN_READ_TOKEN`; missing credentials and provider 403 responses have distinct fail-closed results. Workflow permissions were not expanded and no credential, environment, reviewer, secret, variable, or policy was created or changed.
- Deploy's historical image-run native approval, exact image source blobs, and retained ZIP/digest provenance are now verified inside the credentialed deploy job after its native environment pause and before private checkout, host credentials, or the executor. The pre-gate job remains credential-free and only validates immutable request/run bindings and complete anti-replay inventory.
- Offline coverage includes provider 200, missing admin-read credential, provider 403, unsupported `administration` workflow permission, changed enforce-admin/force-push/deletion policy, and rejection of weaker public alternatives. Both privileged controller jobs and both private-app jobs remain literal-disabled. No dispatch/rerun, GHCR, host/WireGuard/SSH, private-app change, merge, or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Activation remains blocked until a separately approved task provisions and live-proves one controller-repository-scoped GitHub App or fine-grained token with Administration read and no Administration write as the protected environment secret `HFS_CONTROLLER_ADMIN_READ_TOKEN`.

## 2026-11-16 — issue #429 native approval and image provenance correction

- Existing controller PR #13 and branch `feat/issue-428-public-release-controller` remain based on protected `main` `b379829c3fbcb87df9b70e1fb82f50296373cc6a`; no replacement branch or PR was created. The verified `stage-only-review.yml` blob remains byte-for-byte `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`.
- The request contract no longer contains or fabricates `nativeApproval`. `validate-request` now proves request/run/app/controller bindings, freshness, secret-name scope, and complete anti-replay inventory before the native gate. Each dormant protected job has a distinct after-gate `verify-native-approval` step before any private-source, publisher, host credential, or executor use.
- The after-gate verifier reads the real run approvals, environment configuration, and protected-main policy. It requires one Ronny approval (ID `321374159`), the exact purpose-specific environment name and numeric ID, admin bypass off, self-review prevention off, attempt 1, and an approval timestamp inside the request lifetime. The two new environment IDs are intentionally `null` until a separately authorized environment task creates and proves them; missing IDs, API denial, or missing approval timestamps fail closed.
- Deploy provenance no longer trusts syntactically valid `HFS_PUBLICATION_*` inputs. It verifies one completed/successful first-attempt image run, exact controller head/workflow/executor blobs, original request ID/nonce and native image approval, exhaustive publication/deploy anti-replay inventory, and one nonexpired run-bound artifact. It verifies the downloaded ZIP's GitHub SHA-256 digest, exact single JSON member, app SHA/tree, publication times, and full immutable GHCR reference/digest. The dormant publisher writes and uploads that minimal provenance artifact only after registry digest readback.
- Both privileged jobs remain literal `if: ${{ false }}`. Existing source pin `798ada90d2b6461a59d4b495ca3798b110b1a2e6`, split secret scopes, /32 WireGuard, pinned `hfsdeploy@10.77.0.1`, no-clobber staging, narrow root helper, sanitized logging, and rollback boundaries are preserved.
- Offline tests cover missing/other/duplicate approvals, wrong environment/name/ID, bypass, self-review deadlock, approval timestamp/expiry and API 403; forged run IDs, fabricated/wrong digests, app/controller drift, stale image approval, failed/retried/mutated publisher, missing/tampered artifact, duplicate consumers, and correct mocked authoritative linkage. No dispatch, rerun, environment/reviewer/secret/policy change, GHCR operation, host/WireGuard/SSH access, merge, deploy, or private-app change occurred. Work/Codex/delegation: 0.

### Next gate

Review updated controller PR #13. Environment creation, numeric-ID pinning, live approvals timestamp capability proof, literal stop-gate removal, publisher execution, app repin, secret migration, merge, image publication, and deploy remain separate exact-SHA-authorized tasks.

## 2026-11-09 — dedicated connectivity-only native approval (code review)

- Adds a separate manual, first-attempt `main` workflow for one opaque 64-hex request, using the existing protected `production-first-start` environment. It validates the request before native review and emits only a harmless connectivity approval marker afterward.
- The new workflow contains no checkout, secret, signing, artifact, API write, host access or install/start path. Existing stage-only and authorization workflows, credentials and environment settings remain unchanged. Public inputs disclose no private source or target details.
- Three local Node contract tests pass. The existing code-only PR check also includes these tests. The private consumer must independently bind exact source/purpose/nonce, pinned workflow/reviewer/environment, freshness and single use; this workflow alone grants no server authority.
- This change is code-only. No operational workflow dispatch, merge, environment/secret change, remote test, install, start or deploy is authorized by this PR.

### Next gate

Review this controller PR and the private consumer change together. Merge and any later diagnostic dispatch require separate approval; do not reuse any install/start approval for connectivity.

## 2026-11-08 — issue #321 signer basename and safe refusal diagnostics

- Branch `fix/issue-321-signer-basename` is based on verified controller `main` commit `adb53fdab348c52d545bc424857774cac1f0e002`. The authorization workflow now writes the pinned signer bytes to the required basename `install-only-authorization.mjs` and uses that exact file for both `git hash-object` verification and the Node CLI call.
- Signer stderr is captured only in a mode-0600 file under the existing mode-0700 work directory. An exact single-line `AUTHORIZATION_REFUSED code=AUTH_[A-Z0-9_]+` with signer exit 78 is reduced through an explicit stable-code allowlist; all other exit-78 text becomes `AUTH_UNKNOWN`. Raw stderr is never printed or consumed by command substitution or a trap. Non-CLI failures retain only the existing public phase and numeric exit marker.
- Offline regression coverage reproduces the historical wrong-basename behavior (empty stdout and jq schema exit 4), proves the corrected downloaded basename activates the CLI and returns exit 78 with `AUTH_USAGE`, and rejects empty, arbitrary, unallowlisted and multiline/malicious stderr without leakage. The source signer and signing protocol are unchanged.
- Local verification passes: 36/36 Node tests, five workflow/security contract commands, shell syntax and diff checks, plus YAML parsing for all seven workflows. The minimal local host has no jq binary, so the new test uses its strict empty-input fallback locally; GitHub's Ubuntu PR runner executes the same case with real jq. Controller PR #11 is open, and its exact-head `Controller code-only checks / validate` gate passes.
- No workflow was dispatched, rerun or retried; no signature, authorization, issue #288 write, secret, token, environment, artifact, host, install, start, merge, deploy or production data was changed. `installAuthorized=false`, `startAuthorized=false`. Work/Codex usage: 0 calls.

### Next gate

Review controller PR #11. Do not merge or dispatch from this task; any later authorization remains a separate exact-SHA approval.

## 2026-11-07 — issue #317 safe INSTALL_ONLY phase diagnostics

- Controller PR #10 on `fix/issue-317-phase-errors` adds one fail-closed `ERR` contract to `install-only-authorization.yml`. The only failure marker is `INSTALL_ONLY_AUTHORIZATION_ERROR phase=<PUBLIC_PHASE_ID> exit=<NUMERIC_STATUS>`; tool stderr is suppressed so URLs, paths, response bodies, request values, nonces, tokens and signed-envelope content are not logged.
- Fixed public phases cover preflight, source pin, artifact metadata, artifact ZIP, ZIP members, request/provenance, native approval, complete paginated inventory, signer and issue delivery. The original numeric status is preserved, including `jq` exit 4.
- Synthetic offline tests force failures from `curl`, `jq`, `unzip`, `node` and a shell guard. Each case emits exactly one expected marker, leaks none of the injected sensitive diagnostics, preserves the exit status, and proves that signing and issue-write sentinels cannot run afterward.
- Existing fail-closed authentication, anti-replay, SHA/signature verification, signed expiry, reviewer/environment policy, least privilege, cleanup and no-retry/no-fallback behavior remain intact. The full 36-test Node suite, both existing workflow contracts, protected credential preflight tests, YAML parsing, diff checks and controller PR CI are green.
- No workflow was dispatched, rerun or retried; no signature or private issue comment was created; no secret, token, environment, artifact, host, install, start, merge, deploy or production data was changed. `installAuthorized=false`, `startAuthorized=false`. Work/Codex usage: 0 calls.

### Next gate

Review controller PR #10. Do not merge or dispatch from this task; any later activation remains a separate exact-SHA approval.

## 2026-11-07 — issue #293 isolated readback credential preflight

- Branch `feat/issue-293-readback-preflight` updates the existing protected credential preflight, its code-only PR test path, offline tests, and documentation. It replaces the old source-reader/signing challenge with an isolated `HFS_PRIVATE_READBACK_TOKEN` read-only verifier.
- The private token can perform only three fixed GETs: exact private repository metadata, active workflow ID `379993056` at `.github/workflows/first-start-runner-transfer.yml`, and open private issue `288`. The controller token has only `actions: read` and performs only the current run and approval GETs.
- The verifier binds `main`, attempt 1, the current run head, exact reviewer `Ronmel71` / `321374159`, and environment `production-first-start` / `26423058762`. Redirects, timeout/transport errors, invalid JSON, HTTP failures, target drift, and approval drift fail closed with stable non-sensitive codes.
- The workflow does not expose or use `HFS_PRIVATE_SOURCE_READ_TOKEN` or `HFS_ED25519_SIGNING_KEY_PEM`; it has no signing, write, OIDC, deploy, checkout, cache, output, or artifact path. Synthetic exact-code tests cover PASS and negative HTTP, transport, JSON, repository, workflow, issue, head, reviewer, environment, admin-bypass, attempt, missing-token, and configuration cases.
- Controller PR #9 is open for review. The full local controller suite, workflow YAML parsing, diff checks, unchanged installation/deploy guard comparison, and exact-head code-only PR CI are green; local `actionlint` is unavailable and is not claimed.
- No workflow was dispatched or rerun; no protected review, secret value, token, environment, issue #288, artifact, host, install, start, merge, or deploy state was changed. `installAuthorized=false`, `startAuthorized=false`. Work/Codex usage: 0 calls.

### Next gate

Review the single controller code PR. A later preflight dispatch requires a separate explicit approval bound to the exact merged controller SHA; this code change grants no production authority.

## 2026-11-07 — issue #281 install-only authorization hardening

- Branch `fix/issue-281-install-authorization-hardening` keeps the controller code-only and fail-closed while adding explicit `purpose=INSTALL_ONLY`, a canonical SHA-256 request ID, and exact workflow inputs for request ID, readback artifact ID and nonce.
- The request ID binds the reviewed controller head, exact private source/manifest/bundle/readback digests, immutable readback run/job/artifact identity and digest, nonce and purpose. Both signer and private consumer independently recompute it.
- Before issuance the workflow fully paginates repository-wide `workflow_dispatch` inventory. The signer rejects incomplete pagination, omission of the current run, reruns and any duplicate canonical request/artifact/nonce run, including a matching run on another workflow or branch.
- Signer and consumer share one maximum lifetime: expiry must be later than issuance and no more than 3,600 seconds after it. Audit purpose, wrong request ID, changed artifact/nonce, expired or 24-hour approvals and bad signatures fail closed.
- No workflow was dispatched or rerun; no protected review, secret, environment, artifact, host, install, start, merge or deploy state was changed. Work/Codex usage: 0 calls.
- Controller PR #8 contains implementation commit `e2ff2445cb4b21dd2f4af0f0b5aa9f242ea0d3ec`. All 36 Node tests, both shell workflow contracts, YAML parsing, signer-blob pin readback and diff checks pass; implementation-head controller code-only CI is green.

### Next gate

Review the exact controller and private app PR heads together. A green CI result is code evidence only and grants no installation authority; any future dispatch remains a separate explicit decision.

## 2026-11-06 — issue #266 dormant install-only material source

- Branch `feat/issue-266-install-only-materials` adds one manual-only controller workflow whose sole publisher remains literal-disabled with `if: ${{ false }}`.
- The candidate can only generate the five declared nonsecret v3 material files. It requires exact protected controller review provenance, attempt 1, the current reviewed controller `main` head, an authenticated exact private `staging` head and policy manifest, and an environment-scoped Ed25519 key. Missing or drifting inputs fail closed.
- The Ed25519 private key remains in memory and is never written, logged, placed in an API argument, or included in output. No key, secret, variable, permission, environment, or reviewer was created or changed.
- Public-artifact exposure is explicitly bounded and documented in `README.md`. The nonce is short-lived and one-use but not treated as secret; if that classification changes, the public uploader must remain disabled and the existing private artifact handoff must be used.
- Static and synthetic tests cover missing key, private SHA mismatch, trust/public-key mismatch, exact sudoers drift, expiry bounds, nonce format, controller-head drift, missing/extra/private material, reviewer/attempt mismatch, SHA-pinned Actions, and the literal-disabled guard.
- No workflow was dispatched, no artifact was uploaded or downloaded, and no private repository, host, provider, install, start, merge, or deployment state was changed. Work/Codex usage: 0 calls.

### Next gate

Review and merge the single controller PR as a code-only change. Even after merge, publication remains disabled. Any later activation requires a separate SHA-specific review and provisioning decision; the private consumer must remain unpinned until the real controller workflow ID is known and separately reviewed.
