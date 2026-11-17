# Current status

## 2026-11-17 — issue #436 image-only activation candidate

- Branch `feat/issue-436-image-activation` starts exactly at controller `main` `f1e152dcc0c6278a665f59b96ea0acd239ace90d`, after confirming no open controller PR. Private app `staging` remains read-only at commit `798ada90d2b6461a59d4b495ca3798b110b1a2e6`, tree `782771cf58956453d31313756252ba073a852c5c`; no app source, ref, credential, environment, policy, registry, host, or production state was changed.
- The `release-image-only` job replaces only its literal stop-gate with the exact strict condition already used by `validate-request`: manual `workflow_dispatch`, `refs/heads/main`, attempt 1, actor `Ronmel71`, and triggering actor `Ronmel71`. It still needs `validate-request`, uses fixed environment `production-image-publication`, and performs authentic after-native-gate approval, environment, protected-main, exact-source and anti-replay verification before private checkout or publisher execution. The image executor is unchanged.
- Controller Administration-read run `44087258322` (image job `134052977887`) and run `44087466609` (deploy job `134053685375`) were re-read as completed/successful manual attempt-1 runs at exact head `f1e152dcc0c6278a665f59b96ea0acd239ace90d`. Each has one native approval by `Ronmel71` ID `321374159` for its fixed environment, admin bypass off, self-review prevention off and protected-branch policy. Their logs report `ADMIN_READ_PREFLIGHT_PASS`, `credential_read=true release_ready=false authorization=false`; they prove read capability only and cannot authorize publication or deploy.
- Publisher setup manifest for `production-image-publication`: `HFS_CONTROLLER_ADMIN_READ_TOKEN` is present and is restricted to controller Administration read plus Metadata read; `HFS_PRIVATE_SOURCE_READ_TOKEN` is missing and is intended only for read-only contents/source attestation and exact checkout of `Ronmel71/hfs-selger-app`; `HFS_GHCR_PUBLISH_TOKEN` is missing and is intended only to publish/read back the immutable `ghcr.io/ronmel71/hfs-selger-app` image; `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` are missing environment variables intended only as the target project's public image-build inputs. Authorized metadata currently reports exactly the Administration-read secret and zero variables; no credential or configuration value was read. Prefer existing suitably scoped credentials in a later separately approved setup rather than creating or rotating them.
- Deploy remains dormant: `.github/workflows/release-deploy-only.yml` and `scripts/release-deploy-only.sh` retain blobs `b0acaad341f5394e2b4a83bea253208f6a092936` and `ebdbc3778b1cc430d9c682f43a2b1016c2da355f`, and its privileged job remains literal-disabled. `stage-only-review.yml`, `native-capability-probe.yml`, `controller-admin-read-preflight.yml`, `scripts/controller-admin-read-preflight.mjs`, and private-app legacy `production-release-approved.yml` retain required blobs `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`, `0162b90496b366c1370cb28546e6e46e1955d0dd`, `d2534b4a76204d5b576df54482894c0373004363`, `ca65319dc78556c2b4c67da97cdc688a2c0bce22`, and `2c15f1e1a47af65d309c08eca4b86cbb445734a0`; both private legacy release jobs remain literal-disabled.
- Local verification passes the exact CI-equivalent Node groups at 36/36, 3/3 and 138/138 tests (177 total), all five shell/security contract programs, Bash syntax for every controller script/test, YAML parsing for all 12 workflows, diff checks, protected-blob checks and a changed-diff credential-pattern scan. Local `actionlint`, `shellcheck` and `gitleaks` are unavailable and are not claimed.
- Controller PR #18 carries this single review surface and its exact-head code-only CI is green. The branch is code ready for review, not release ready. No merge, dispatch/rerun/cancel, native release approval, credential or configuration write, GHCR login/build/push/pull, publication, deploy, host/provider/business-data operation, or Work/Codex/delegation occurred.

### Next gate

After review and merge under separate authority, verify the exact source candidate, post-merge controller head and workflow/executor blobs, required secret/variable names and target-project public build values without logging values, plus registry inventory/conflict/duplicate-publication status. Then request one new exact-release approval; do not reuse either Administration-read PASS run.

## 2026-11-17 — issue #435 Administration-read raw-provider boundary correction

- Existing controller PR #17 and branch `feat/issue-434-admin-read-preflight` were updated in place from reviewed head `45154fa317feb21ee4b2d791250e503dc321a176`; no new branch or PR was created. The pinned controller `main` remains exactly `5e41500c97e3befff031478983fadb829c570a47`.
- `readMainProtection()` now returns the raw fixed-endpoint GitHub branch-protection response to the real `verify-admin-read` orchestration. The shared `validateMainProtectionEvidence()` remains the single raw-policy validation and normalization boundary inside `validateAdminReadEvidence()`; enforce-admins ON and force-push/deletion OFF still fail closed without accepting a normalized object as trusted input.
- A real CLI-path regression drives `verify-admin-read` through faithful synthetic GitHub run, inventory, job, approval, environment, exact-source and branch-protection responses. Restoring the reviewed double-validation line makes the valid case fail with `ADMIN_READ_PREFLIGHT_REFUSED code=NATIVE_MAIN_PROTECTION`; the corrected path emits `ADMIN_READ_PREFLIGHT_PASS`. Raw policy drift, malformed or denied protection responses, missing token, wrong native approval and wrong exact-source evidence remain refusals.
- Local verification passes all 178 Node tests, every controller shell/security contract, pinned private-app source checks, Node/Bash syntax, workflow YAML parsing for all 12 workflows, exact protected-workflow blob checks, diff checks and changed-diff secret/security scans. Local `actionlint` remains unavailable and is not claimed.
- Protected `release-image-only.yml`, `release-deploy-only.yml`, `stage-only-review.yml`, and `native-capability-probe.yml` remain byte-identical at blobs `228a2bcd48b315363af1a19e72497d96f1c60526`, `b0acaad341f5394e2b4a83bea253208f6a092936`, `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`, and `0162b90496b366c1370cb28546e6e46e1955d0dd`. All four real release jobs remain literal-disabled.
- No live capability PASS, credential creation/read/copy/storage, dispatch/rerun/cancel, native approval, environment/secret/variable/permission/policy mutation, app write, provider/registry/host/business/email action, merge, publication or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Review the updated controller PR #17 and its exact-final-head CI. Merge, credential provisioning, live dispatch/native approval, literal stop-gate removal, publication and deploy remain separately authorized future work.

## 2026-11-17 — issue #434 protected controller Administration-read preflight candidate

- Branch `feat/issue-434-admin-read-preflight` is based exactly on controller `main` `5e41500c97e3befff031478983fadb829c570a47` (tree `96594f2f4e33247fc4a826f3731a055fb7f115b0`) after confirming no open controller PR. Private app `staging` remains read-only at `798ada90d2b6461a59d4b495ca3798b110b1a2e6`; no app file or ref was changed.
- The candidate adds one separate manual-only preflight with a credential-free request-validation job and one selected native-environment-protected readback job. Its fixed `image`/`deploy` selector maps only to `production-image-publication` ID `27579543667` or `production-host-deployment` ID `27579657157`; exact reviewed controller SHA/workflow/script blobs, Ronny actor and triggering actor, attempt 1, a fresh one-use request, and a 30-minute maximum lifetime are fail-closed bindings.
- Only the protected step can receive the environment-scoped `HFS_CONTROLLER_ADMIN_READ_TOKEN`, and it can use it only for read-only `GET /repos/Ronmel71/hfs-approval-controller/branches/main/protection`. The ordinary job token separately reads authentic run, approval, job, environment, and controller-source evidence. The preflight and release paths share the same protected-main validator for enforce-admins ON plus force-push/deletion OFF.
- Positive and negative offline coverage proves credential isolation, fixed path/source/target/attempt, missing token, 401/403/404/429, redirect refusal, timeout handling, non-JSON/malformed/policy drift refusal, and that neither this preflight nor the harmless probe can satisfy a release contract. A pass is explicitly `credential_read=true release_ready=false authorization=false`; no live PASS is claimed.
- Local verification passes all 177 Node tests, all controller shell/security contracts, pinned private-app source checks, Node/Bash syntax, workflow YAML parsing for all 12 workflows, exact protected-workflow blob checks, diff checks, and changed-diff secret/security scans. Local `actionlint` is unavailable and is not claimed.
- Protected `release-image-only.yml`, `release-deploy-only.yml`, `stage-only-review.yml`, and the original credential-free `native-capability-probe.yml` remain byte-identical at blobs `228a2bcd48b315363af1a19e72497d96f1c60526`, `b0acaad341f5394e2b4a83bea253208f6a092936`, `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`, and `0162b90496b366c1370cb28546e6e46e1955d0dd`.
- Work in progress: none beyond review and exact-head CI. Known faults: none in offline checks. No workflow dispatch/rerun/cancel, native reviewer approval, token/credential creation or handling, environment/secret/variable/permission/policy mutation, app write, registry/host/provider/business/email action, merge, publication, or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Review the one controller PR and its exact-head CI. After a separately approved merge, credential creation/storage and one exact-post-merge-SHA target dispatch/native approval remain separate human-authorized steps; the required future credential is a new controller-only fine-grained PAT with Administration read, implicit Metadata read, no writes or unrelated access, bounded expiry, and Ronny-owned renewal. No access is blocked for code review; the credential is intentionally unprovisioned.

## 2026-11-17 — issue #433 harmless native capability probe candidate

- Branch `feat/issue-433-native-capability-probe` is based exactly on controller `main` `81aaba6c8d64d0eef6972fe759a6c13aae9651b9` (tree `1b05645a78a145b0eb6203b0d51869e476cf3f47`) after confirming no open controller PR. The private app repository remained read-only. Protected `stage-only-review.yml`, `release-image-only.yml`, and `release-deploy-only.yml` retain blobs `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`, `228a2bcd48b315363af1a19e72497d96f1c60526`, and `b0acaad341f5394e2b4a83bea253208f6a092936`.
- The candidate adds one manual-only, two-job read-only probe. Its enumerated `image`/`deploy` selector maps only to `production-image-publication` ID `27579543667` or `production-host-deployment` ID `27579657157`; request ID, nonce, 30-minute lifetime, exact controller head/workflow/script blobs, `main`, Ronny actor and triggering actor, attempt 1, and complete stable dispatch inventory are fail-closed bindings.
- After Ronny's real native approval, the selected gated job uses only ephemeral `GITHUB_TOKEN` with `actions: read` and `contents: read` to read the current run, timestamp-free approval history, complete exact attempt-1 job inventory, named environment policy, and exact public-controller source. It has no secret, private-source, registry, host, signing, email, business-data, artifact, output, envelope, or release path. `NATIVE_PROBE_PASS` always carries `release_ready=false authorization=false`, and release contracts reject probe requests.
- The probe reuses the existing pure native-gate evidence validator; full release verification still separately requires full protected-main readback. An ephemeral-token protection denial is reported as `ADMIN_READ_BLOCKED`, never replaced with public `protected: true` or synthetic input. If blocked, the unchanged release verifier still requires a separately approved controller-scoped GitHub App or fine-grained token with Administration read and no Administration write.
- Authenticated read-only provider inspection reconfirmed both environment names/IDs, admin bypass off, prevent-self-review off, Ronny (`321374159`) as sole reviewer, protected-branches-only policy, and zero environment secrets/variables. Existing operator auth can read full current `main` protection, but future runner-token capability is intentionally unproven until an authorized live run.
- Local verification passes all 151 Node tests, all controller shell/security contracts, Node/Bash syntax, workflow YAML parsing, exact pinned blobs, and changed-diff secret/security scans. Local `actionlint` is unavailable and is not claimed. No workflow dispatch/rerun/cancel, native approval, environment/reviewer/secret/variable/token/policy write, app write, registry/host/private-provider action, merge, publication, or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Review controller PR #16. Merge and each independent future exact-post-merge-SHA `image` or `deploy` dispatch/native approval remain separate explicit approvals; Ronny performs the native approval himself, and no combined live PASS is promised.

## 2026-11-17 — issue #432 real environment IDs and bounded native-approval freshness

- Branch `feat/issue-432-native-approval-bounds` is based exactly on protected controller `main` `5d5a34674227af58c377c2c22856f3ea28e56223` (tree `4f6cb393df0c870dbf069e6478e12d7fb3b9c666`). Private app `staging` was verified read-only at `798ada90d2b6461a59d4b495ca3798b110b1a2e6`; no app file or ref was changed. The protected `stage-only-review.yml` blob remains byte-identical `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`.
- Authenticated provider readback confirmed distinct empty protected environments `production-image-publication` ID `27579543667` and `production-host-deployment` ID `27579657157`, each with Ronny (`321374159`) as the sole required reviewer, prevent-self-review off, administrator bypass off, and protected-branches-only policy. Those exact IDs are now pinned in controller purpose policy; no environment or policy write occurred.
- Real approval history for run `43394899577` contains only `user`, `state`, `comment`, and `environments`; it has no approval timestamp. Real attempt-1 job `131783355524` supplies authenticated run/head/attempt identity and `started_at`/`completed_at`. The verifier now proves only the justified interval `run created <= approval <= exact protected job started`; it never substitutes `run.updated_at`, wall clock, or a caller-authored field and never claims an exact approval time.
- Current evidence requires a complete stable attempt-1 inventory with exactly the successful `validate-request` dependency and exact purpose/app-specific protected job. Every job is bound to run ID, first attempt, controller SHA, `main`, and API run URL. The gate must start inside the original 30-minute request lifetime; current execution must remain in progress with an unexpired request, while historical publication must complete successfully within its original lifetime before its immutable artifact/manifest can authorize a separate deploy.
- Focused timestamp-free provider-shape coverage includes current and historical success, missing/partial/duplicate inventory, similarly named job, wrong SHA/attempt/reviewer/environment, late gate/completion, expired current request, API denial, source/image mismatch, replay, and two app releases on unchanged controller policy. Administration-read failures remain fail-closed; `HFS_CONTROLLER_ADMIN_READ_TOKEN` is still unprovisioned and no live PASS is claimed.
- Both controller release jobs and both private-app legacy release jobs remain literal-disabled. No dispatch/rerun/cancel, credential, environment/reviewer/secret/variable/token/permission/policy write, GHCR operation, private-app write, host/WireGuard/SSH access, merge, publication, or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Review controller PR #15. Merge, Administration-read credential provisioning, harmless live approval probe, literal stop-gate removal, publication, and deploy remain separate exact-SHA-authorized tasks.

## 2026-11-16 — issue #431 self-service per-release source binding

- Branch `feat/issue-431-dynamic-release-bindings` is based exactly on protected controller `main` `65ae526ad74cce6b8fbf0c55f3caa44019037003`. Only the controller candidate is changed; private app `staging` was verified read-only at `798ada90d2b6461a59d4b495ca3798b110b1a2e6`. The protected `stage-only-review.yml` blob remains byte-identical `8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4`.
- `appCommit` and `appTree` are now strict full lowercase 40-hex per-request inputs for both independent release purposes and are covered by each canonical request hash. Full app commit appears in the run name, protected approval job, and summary. Repository/ref, app workflow/blob, Compose, Caddy, helper, and sudoers remain fixed controller policy; checkout can use only the approved full commit and has no branch/tag/latest fallback.
- After each native environment approval and before private checkout execution, the existing least-privilege private source token performs fixed read-only provider attestation of exact private repository identity, reviewed staging head, requested-commit ancestry, commit tree, and every locked blob. Both executors independently recheck fetched HEAD/tree/workflow/infra blobs before build/publish or SSH. The credential-free pre-gates contain no private source token or private source calls.
- Deploy still requires a fresh independent approval and authenticated historical image evidence. Its request app commit/tree must match the original publication manifest, canonical image request, immutable GHCR digest, artifact digest, controller head, workflow/executor blobs, native approval, and anti-replay inventory; a digest from another source is refused.
- Controller PR #14 contains the single review surface. Local verification passes 36/36 existing controller Node tests, 3/3 connectivity tests, 73/73 release-controller tests, all controller shell/security contracts, Bash syntax, workflow YAML parse, secret scan, exact private-source pin checks, preserved stage-only blob, and diff checks. Exact-head controller CI is required green; local `actionlint` is unavailable and is not claimed.
- Both controller privileged jobs and both legacy private app jobs remain literal-disabled. No workflow dispatch/rerun, environment/reviewer/secret/policy write, GHCR operation, app-repository write, host/WireGuard/SSH connection, provider mutation, merge, or deploy occurred. Work/Codex/delegation: 0.

### Next gate

Review the single controller PR. Merge, environment configuration, credential provisioning, literal stop-gate removal, dispatch, publication, and deploy remain outside this task.

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
