#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/install-only-authorization.yml
stage_workflow=.github/workflows/stage-only-review.yml
signer=scripts/install-only-authorization.mjs

fail() {
  printf 'install-only-workflow.test: %s\n' "$1" >&2
  exit 1
}

grep -Fq 'workflow_dispatch:' "$workflow" || fail 'manual event missing'
grep -Fq 'environment: production-first-start' "$workflow" || fail 'native environment gate missing'
grep -Fq "github.ref == 'refs/heads/main'" "$workflow" || fail 'main ref guard missing'
grep -Fq '[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]' "$workflow" || fail 'attempt-one guard missing'
grep -Fq '/actions/runs/$GITHUB_RUN_ID/approvals' "$workflow" || fail 'authenticated native approval read missing'
grep -Fq '/actions/jobs/$private_job_id' "$workflow" || fail 'private readback job provenance missing'
grep -Fq 'install-only-readback-${request.authorizationNonce}' "$signer" || fail 'nonce-named artifact binding missing'
grep -Fq 'artifactDigestSha256' "$signer" || fail 'artifact digest binding missing'
grep -Fq 'controllerHeadSha' "$signer" || fail 'controller head binding missing'
! grep -Fq 'uses:' "$workflow" || fail 'external action is forbidden'
! grep -Eq 'pull_request|pull_request_target|repository_dispatch' "$workflow" || fail 'non-manual trigger present'
! grep -Eq 'Ronmel71/hfs-selger-app|hfs-selger-app-prod|62\.238\.|/opt/|Supabase|Resend' "$workflow" "$signer" || fail 'private implementation detail in public control code'

expected_blob=$(sed -n 's/^[[:space:]]*readonly signer_blob=\([0-9a-f]\{40\}\)$/\1/p' "$workflow")
[[ -n "$expected_blob" && "$expected_blob" == "$(git hash-object "$signer")" ]] || fail 'signer blob pin drift'

grep -Fq 'workflow_dispatch:' "$stage_workflow" || fail 'stage-only manual event missing'
grep -Fq 'request_id:' "$stage_workflow" || fail 'stage-only request id missing'
grep -Fq 'required: true' "$stage_workflow" || fail 'stage-only request id is optional'
grep -Fq 'run-name: Stage-only review · ${{ inputs.request_id }}' "$stage_workflow" || fail 'stage-only public request binding missing'
grep -Fq 'environment: production-first-start' "$stage_workflow" || fail 'stage-only native environment gate missing'
grep -Fq "github.ref == 'refs/heads/main'" "$stage_workflow" || fail 'stage-only main ref guard missing'
grep -Fq 'permissions:' "$stage_workflow" || fail 'stage-only permissions missing'
grep -Fq '  contents: read' "$stage_workflow" || fail 'stage-only contents permission missing'
grep -Fq '[[ "$REQUEST_ID" =~ ^[0-9a-f]{64}$ ]]' "$stage_workflow" || fail 'stage-only opaque request validation missing'
grep -Fq "printf 'STAGE_ONLY_REVIEW_APPROVED\\n'" "$stage_workflow" || fail 'stage-only harmless marker missing'
! grep -Fq 'uses:' "$stage_workflow" || fail 'stage-only external action is forbidden'
! grep -Eq 'pull_request|pull_request_target|repository_dispatch|schedule:' "$stage_workflow" || fail 'stage-only non-manual trigger present'
! grep -Eq 'secrets\.|Authorization:|github\.token|GH_TOKEN|GITHUB_TOKEN' "$stage_workflow" || fail 'stage-only workflow must be credential-free'
! grep -Eq 'Ronmel71/hfs-selger-app|hfs-selger-app-prod|62\.238\.|/opt/|Supabase|Resend|[0-9a-f]{40}' "$stage_workflow" || fail 'private data or pinned private identity in public stage workflow'
[[ "$(grep -c '^      - name:' "$stage_workflow")" == 1 ]] || fail 'stage-only workflow must have one harmless step'

# The read-only credential preflight must remain a manual, environment-protected
# verifier. A PR cannot execute it or grant production capabilities.
preflight=.github/workflows/protected-credential-preflight.yml
grep -Fxq '  workflow_dispatch:' "$preflight" || fail 'credential preflight must be manual-only'
[[ "$(grep -Fc 'permissions: {}' "$preflight")" == 2 ]] || fail 'credential preflight must have zero GITHUB_TOKEN permissions'
grep -Fq "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.run_attempt == 1" "$preflight" || fail 'credential preflight exact main/attempt guard missing'
grep -Fxq '    environment: production-first-start' "$preflight" || fail 'credential preflight protected environment missing'
grep -Fq 'HFS_ED25519_SIGNING_KEY_PEM: ${{ secrets.HFS_ED25519_SIGNING_KEY_PEM }}' "$preflight" || fail 'credential preflight Ed25519 environment binding missing'
grep -Fq 'HFS_PRIVATE_SOURCE_READ_TOKEN: ${{ secrets.HFS_PRIVATE_SOURCE_READ_TOKEN }}' "$preflight" || fail 'credential preflight reader environment binding missing'
grep -Fq 'privateKey.asymmetricKeyType !== "ed25519"' "$preflight" || fail 'credential preflight Ed25519 verification missing'
grep -Fq 'method: "GET"' "$preflight" || fail 'credential preflight GET-only request missing'
grep -Fq 'redirect: "error"' "$preflight" || fail 'credential preflight redirect refusal missing'
grep -Fq '/repos/Ronmel71/hfs-selger-app' "$preflight" || fail 'credential preflight exact private repository missing'
grep -Fq '/git/ref/heads/staging' "$preflight" || fail 'credential preflight exact private ref missing'
grep -Fq 'manifest.json?ref=' "$preflight" || fail 'credential preflight immutable manifest read missing'
grep -Fq 'manifest.consoleGo !== false || manifest.startAuthorized !== false' "$preflight" || fail 'credential preflight must require no-go source'
grep -Fq 'CREDENTIAL_PREFLIGHT_PASS SIGNER_VALID PRIVATE_READ_VALID NO_WRITES NO_PUBLISH NO_DEPLOY' "$preflight" || fail 'credential preflight fixed PASS marker missing'
! grep -Eq 'pull_request:|pull_request_target:|repository_dispatch:|schedule:|^[[:space:]]*push:' "$preflight" || fail 'credential preflight non-manual event forbidden'
! grep -Eq 'uses:|actions/upload-artifact|docker |[^A-Z]POST[^A-Z]|[^A-Z]PUT[^A-Z]|[^A-Z]PATCH[^A-Z]|[^A-Z]DELETE[^A-Z]|set -x|curl ' "$preflight" || fail 'credential preflight write, external action or shell trace forbidden'

printf 'install-only-workflow.test: PASS\n'
