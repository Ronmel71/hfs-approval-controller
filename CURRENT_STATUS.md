# Current status

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
