#!/usr/bin/env bash
set -euo pipefail

repo=${1:?usage: pinned-app-source.test.sh /path/to/hfs-selger-app}
commit=3e143784a0c83cdacf584267a57aa8476433ea89
workflow=.github/workflows/production-release-approved.yml

fail() {
  printf 'pinned-app-source.test: %s\n' "$1" >&2
  exit 1
}

[[ "$(git -C "$repo" rev-parse origin/staging)" == "$commit" ]] || fail 'staging pin drift'
[[ "$(git -C "$repo" show -s --format=%T "$commit")" == a5f3d7179014931ba9d9f5d4e85a6b131fe76e2c ]] || fail 'app tree drift'
[[ "$(git -C "$repo" rev-parse "$commit:$workflow")" == 2c15f1e1a47af65d309c08eca4b86cbb445734a0 ]] || fail 'app workflow blob drift'

source=$(git -C "$repo" show "$commit:$workflow")
publisher=${source#*"  release-image:"}
publisher=${publisher%%"  deploy:"*}
deploy=${source#*"  deploy:"}
[[ "$publisher" == *'if: ${{ false }}'* ]] || fail 'private publisher is not literal-disabled'
[[ "$deploy" == *'if: ${{ false }}'* ]] || fail 'private deploy is not literal-disabled'
[[ "$publisher" != *'DEPLOY_SSH_KEY'* ]] || fail 'private publisher contains host credential'

helper_path=deploy/production/host/hfs-deploy-release
[[ "$(git -C "$repo" rev-parse "$commit:$helper_path")" == 76e408175ac0ff8b207665475f9f5d1240766738 ]] || fail 'corrected helper blob drift'
helper=$(git -C "$repo" show "$commit:$helper_path")
for required in \
  'required immutable image is not locally available' \
  'running $service RepoDigest differs from protected state' \
  'test "$HFS_DEPLOYMENT_ENV" = production; test "$HFS_ALLOW_REAL_EMAIL" = false' \
  'public HTTPS health check failed' \
  'readonly transaction_rollback_image="$current_image"' \
  'readonly transaction_rollback_release="$current_release"' \
  'readonly transaction_rollback_release_sha="$current_release_sha"' \
  'atomic_write "$STATE_ROOT/previous-image" "$transaction_rollback_image"' \
  'compose "$transaction_rollback_release" "$transaction_rollback_image" "$caddy_image" up -d --remove-orphans' \
  'trap '\''rollback "$?"'\'' ERR' \
  'rollback=RESTORED_AND_HEALTHY'; do
  [[ "$helper" == *"$required"* ]] || fail "pinned helper safety contract missing: $required"
done
printf 'pinned-app-source.test: PASS\n'
