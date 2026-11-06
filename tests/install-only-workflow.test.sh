#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/install-only-authorization.yml
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

printf 'install-only-workflow.test: PASS\n'
