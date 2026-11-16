#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'RELEASE_IMAGE_REFUSED code=%s\n' "$1" >&2
  exit 78
}

[[ "${GITHUB_RUN_ATTEMPT:-}" == 1 ]] || die ATTEMPT
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || die EVENT
[[ "${GITHUB_REPOSITORY:-}" == Ronmel71/hfs-approval-controller ]] || die CONTROLLER_REPOSITORY
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || die CONTROLLER_REF
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die CONTROLLER_HEAD
[[ "${HFS_APP_COMMIT:-}" == 798ada90d2b6461a59d4b495ca3798b110b1a2e6 ]] || die APP_COMMIT
[[ "${HFS_APP_TREE:-}" == 782771cf58956453d31313756252ba073a852c5c ]] || die APP_TREE
[[ "${HFS_APP_WORKFLOW_BLOB:-}" == 2c15f1e1a47af65d309c08eca4b86cbb445734a0 ]] || die APP_WORKFLOW
[[ -n "${HFS_GHCR_PUBLISH_TOKEN:-}" ]] || die PUBLISH_CREDENTIAL
[[ -n "${NEXT_PUBLIC_SUPABASE_URL:-}" && -n "${NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:-}" ]] || die BUILD_INPUT

[[ "$(git rev-parse HEAD)" == "$HFS_APP_COMMIT" ]] || die SOURCE_HEAD
[[ "$(git rev-parse HEAD^{tree})" == "$HFS_APP_TREE" ]] || die SOURCE_TREE
[[ "$(git rev-parse HEAD:.github/workflows/production-release-approved.yml)" == "$HFS_APP_WORKFLOW_BLOB" ]] || die SOURCE_WORKFLOW

image="ghcr.io/ronmel71/hfs-selger-app:${HFS_APP_COMMIT}"
registry_host="ghcr.io"
printf '%s' "$HFS_GHCR_PUBLISH_TOKEN" | docker login "$registry_host" --username Ronmel71 --password-stdin >/dev/null
docker build \
  --build-arg "NEXT_PUBLIC_SUPABASE_URL=$NEXT_PUBLIC_SUPABASE_URL" \
  --build-arg "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=$NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY" \
  --tag "$image" .
docker push "$image" >/dev/null

reference="$(docker buildx imagetools inspect "$image" --format '{{json .Manifest.Digest}}' | tr -d '"')"
[[ "$reference" =~ ^sha256:[0-9a-f]{64}$ ]] || die DIGEST_READBACK
immutable="ghcr.io/ronmel71/hfs-selger-app@$reference"
printf 'PUBLISHED_IMAGE_REFERENCE=%s\n' "$immutable" >> "$GITHUB_OUTPUT"
printf 'RELEASE_IMAGE_ONLY_COMPLETE app_sha=%s image_digest=%s\n' "$HFS_APP_COMMIT" "$reference" >> "$GITHUB_STEP_SUMMARY"
