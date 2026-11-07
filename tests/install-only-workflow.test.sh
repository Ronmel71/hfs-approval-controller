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
grep -Fq 'run-name: Install-only authorization · ${{ inputs.purpose }} · ${{ inputs.request_id }} · artifact ${{ inputs.readback_artifact_id }} · nonce ${{ inputs.authorization_nonce }}' "$workflow" || fail 'canonical request run name missing'
grep -Fq 'inputs.purpose == '\''INSTALL_ONLY'\''' "$workflow" || fail 'INSTALL_ONLY purpose guard missing'
grep -Fq 'HFS_AUTHORIZATION_REQUEST_ID: ${{ inputs.request_id }}' "$workflow" || fail 'request id input missing'
grep -Fq 'HFS_AUTHORIZATION_NONCE: ${{ inputs.authorization_nonce }}' "$workflow" || fail 'nonce input missing'
grep -Fq 'environment: production-first-start' "$workflow" || fail 'native environment gate missing'
grep -Fq "github.ref == 'refs/heads/main'" "$workflow" || fail 'main ref guard missing'
grep -Fq '[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]' "$workflow" || fail 'attempt-one guard missing'
grep -Fq '/actions/runs/$GITHUB_RUN_ID/approvals' "$workflow" || fail 'authenticated native approval read missing'
grep -Fq 'actions/runs?event=workflow_dispatch&per_page=100&page=$page' "$workflow" || fail 'paginated repository dispatch inventory missing'
grep -Fq 'install-only-run-inventory/v1' "$workflow" || fail 'complete inventory contract missing'
grep -Fq '/actions/jobs/$private_job_id' "$workflow" || fail 'private readback job provenance missing'
grep -Fq 'install-only-readback-${request.authorizationNonce}' "$signer" || fail 'nonce-named artifact binding missing'
grep -Fq 'artifactDigestSha256' "$signer" || fail 'artifact digest binding missing'
grep -Fq 'controllerHeadSha' "$signer" || fail 'controller head binding missing'
grep -Fq 'REQUEST_ID_SCHEMA' "$signer" || fail 'canonical request id binding missing'
grep -Fq 'AUTH_DUPLICATE_RUN' "$signer" || fail 'duplicate dispatch refusal missing'
grep -Fq 'request.expiresAtEpoch > now + 3600' "$signer" || fail '60-minute signer maximum missing'
! grep -Fq 'request.expiresAtEpoch > now + 86400' "$signer" || fail 'legacy 24-hour signer maximum remains'
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
[[ "$(grep -Fc '  actions: read' "$preflight")" == 2 ]] || fail 'credential preflight must have only actions-read GITHUB_TOKEN permission'
grep -Fq "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.run_attempt == 1" "$preflight" || fail 'credential preflight exact main/attempt guard missing'
grep -Fxq '    environment: production-first-start' "$preflight" || fail 'credential preflight protected environment missing'
grep -Fq 'HFS_PRIVATE_READBACK_TOKEN: ${{ secrets.HFS_PRIVATE_READBACK_TOKEN }}' "$preflight" || fail 'credential preflight readback token binding missing'
for config in HFS_PRIVATE_REPOSITORY HFS_READBACK_WORKFLOW_PATH HFS_READBACK_WORKFLOW_REF HFS_READBACK_JOB_NAME HFS_PRIVATE_AUTHORIZATION_ISSUE; do
  grep -Fq "$config: "'${{ secrets.'"$config"' }}' "$preflight" || fail "credential preflight configuration binding missing: $config"
done
! grep -Eq 'HFS_ED25519_SIGNING_KEY_PEM|HFS_PRIVATE_SOURCE_READ_TOKEN|createPrivateKey|createPublicKey|[^A-Za-z]sign\(' "$preflight" || fail 'credential preflight signing/source credential forbidden'
grep -Fq 'method: "GET"' "$preflight" || fail 'credential preflight GET-only request missing'
grep -Fq 'redirect: "error"' "$preflight" || fail 'credential preflight redirect refusal missing'
grep -Fq 'privateWorkflowId: 379993056' "$preflight" || fail 'credential preflight exact private workflow missing'
grep -Fq 'privateIssue: 288' "$preflight" || fail 'credential preflight exact private issue missing'
grep -Fq '/actions/runs/${runId}/approvals' "$preflight" || fail 'credential preflight native approval read missing'
grep -Fq 'environmentId: 26423058762' "$preflight" || fail 'credential preflight exact protected environment missing'
grep -Fq 'reviewerId: 321374159' "$preflight" || fail 'credential preflight exact reviewer missing'
grep -Fq 'READBACK_PREFLIGHT_PASS PRIVATE_ACTIONS_READ PRIVATE_ISSUE_READ NATIVE_REVIEW_VERIFIED NO_WRITES NO_SIGNING' "$preflight" || fail 'credential preflight fixed PASS marker missing'
! grep -Eq 'pull_request:|pull_request_target:|repository_dispatch:|schedule:|^[[:space:]]*push:' "$preflight" || fail 'credential preflight non-manual event forbidden'
! grep -Eq 'uses:|actions/upload-artifact|actions/cache|GITHUB_OUTPUT|id-token:|contents:|issues:|deployments:|packages:|docker |[^A-Z]POST[^A-Z]|[^A-Z]PUT[^A-Z]|[^A-Z]PATCH[^A-Z]|[^A-Z]DELETE[^A-Z]|set -x|curl ' "$preflight" || fail 'credential preflight write, external action or shell trace forbidden'

printf 'install-only-workflow.test: PASS\n'
