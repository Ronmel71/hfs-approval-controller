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

printf 'install-only-workflow.test: PASS\n'
