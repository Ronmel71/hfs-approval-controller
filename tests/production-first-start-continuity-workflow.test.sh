#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/production-first-start-continuity.yml
signer=scripts/production-first-start-continuity.mjs
fail() { printf 'production-first-start-continuity-workflow.test: %s\n' "$1" >&2; exit 1; }

grep -Fq 'workflow_dispatch:' "$workflow" || fail 'manual trigger missing'
grep -Fq 'environment: production-first-start' "$workflow" || fail 'protected environment missing'
grep -Fq "github.ref == 'refs/heads/main'" "$workflow" || fail 'main guard missing'
grep -Fq '[[ "$GITHUB_RUN_ATTEMPT" == 1' "$workflow" || fail 'controller attempt-one guard missing'
grep -Fq '/actions/runs/$GITHUB_RUN_ID/approvals' "$workflow" || fail 'native approval read missing'
grep -Fq '/actions/runs/$private_run_id/artifacts?per_page=100' "$workflow" || fail 'bounded AFTER artifact polling missing'
grep -Fq 'production-first-start-after-$before_nonce' "$workflow" || fail 'AFTER is not bound to BEFORE nonce'
grep -Fq 'artifact_bytes" -le 262144' "$workflow" || fail 'artifact size is unbounded'
grep -Fq 'deadline=$((SECONDS + 780))' "$workflow" || fail 'AFTER wait is unbounded'
grep -Fq 'trap cleanup EXIT HUP INT TERM' "$workflow" || fail 'secret cleanup trap missing'
grep -Fq 'CONTINUITY_SIGNED phase=${phase}' "$signer" || fail 'bounded signer output missing'
grep -Fq 'writeFileSync(outputPath' "$signer" || fail 'envelope is not file-only'
! grep -Fq 'uses:' "$workflow" || fail 'external action is forbidden'
! grep -Eq 'pull_request|pull_request_target|repository_dispatch|schedule:' "$workflow" || fail 'non-manual trigger present'
! grep -Eq 'console\.log|process\.stdout\.write\(`\$\{JSON\.stringify\(envelope\)' "$signer" || fail 'envelope could be logged'
[[ "$(grep -c 'HFS_ED25519_SIGNING_KEY_PEM:' "$workflow")" == 1 ]] || fail 'key is not scoped to one protected step'

expected_blob=$(sed -n 's/^[[:space:]]*readonly signer_blob=\([0-9a-f]\{40\}\)$/\1/p' "$workflow")
[[ -n "$expected_blob" && "$expected_blob" == "$(git hash-object "$signer")" ]] || fail 'signer blob pin drift'

printf 'production-first-start-continuity-workflow.test: PASS\n'
