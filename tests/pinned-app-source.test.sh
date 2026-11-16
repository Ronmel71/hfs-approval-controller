#!/usr/bin/env bash
set -euo pipefail

repo=${1:?usage: pinned-app-source.test.sh /path/to/hfs-selger-app}
commit=798ada90d2b6461a59d4b495ca3798b110b1a2e6
workflow=.github/workflows/production-release-approved.yml

fail() {
  printf 'pinned-app-source.test: %s\n' "$1" >&2
  exit 1
}

[[ "$(git -C "$repo" rev-parse origin/staging)" == "$commit" ]] || fail 'staging pin drift'
[[ "$(git -C "$repo" show -s --format=%T "$commit")" == 782771cf58956453d31313756252ba073a852c5c ]] || fail 'app tree drift'
[[ "$(git -C "$repo" rev-parse "$commit:$workflow")" == 2c15f1e1a47af65d309c08eca4b86cbb445734a0 ]] || fail 'app workflow blob drift'

source=$(git -C "$repo" show "$commit:$workflow")
publisher=${source#*"  release-image:"}
publisher=${publisher%%"  deploy:"*}
deploy=${source#*"  deploy:"}
[[ "$publisher" == *'if: ${{ false }}'* ]] || fail 'private publisher is not literal-disabled'
[[ "$deploy" == *'if: ${{ false }}'* ]] || fail 'private deploy is not literal-disabled'
[[ "$publisher" != *'DEPLOY_SSH_KEY'* ]] || fail 'private publisher contains host credential'

helper=$(git -C "$repo" show "$commit:deploy/production/host/hfs-deploy-release")
for required in \
  'required immutable image is not locally available' \
  'running $service RepoDigest differs from protected state' \
  'test "$HFS_DEPLOYMENT_ENV" = production; test "$HFS_ALLOW_REAL_EMAIL" = false' \
  'public HTTPS health check failed' \
  'trap '\''rollback "$?"'\'' ERR' \
  'rollback=RESTORED_AND_HEALTHY'; do
  [[ "$helper" == *"$required"* ]] || fail "pinned helper safety contract missing: $required"
done
printf 'pinned-app-source.test: PASS\n'
