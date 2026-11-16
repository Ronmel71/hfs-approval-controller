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
[[ "${HFS_PUBLICATION_REQUEST_ID:-}" =~ ^[0-9a-f]{64}$ ]] || die REQUEST_ID
[[ "${HFS_PUBLICATION_NONCE:-}" =~ ^[0-9a-f]{64}$ ]] || die NONCE
[[ "${HFS_PUBLICATION_CREATED_AT_EPOCH:-}" =~ ^[0-9]{10}$ ]] || die CREATED_AT
[[ "${HFS_PUBLICATION_EXPIRES_AT_EPOCH:-}" =~ ^[0-9]{10}$ ]] || die EXPIRES_AT
(( HFS_PUBLICATION_EXPIRES_AT_EPOCH > HFS_PUBLICATION_CREATED_AT_EPOCH )) || die EXPIRY
(( HFS_PUBLICATION_EXPIRES_AT_EPOCH - HFS_PUBLICATION_CREATED_AT_EPOCH <= 1800 )) || die EXPIRY
[[ "${HFS_CONTROLLER_WORKFLOW_BLOB:-}" =~ ^[0-9a-f]{40}$ ]] || die CONTROLLER_WORKFLOW
[[ "${HFS_CONTROLLER_EXECUTOR_BLOB:-}" =~ ^[0-9a-f]{40}$ ]] || die CONTROLLER_EXECUTOR
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]{5,19}$ ]] || die RUN_ID
[[ -n "${RUNNER_TEMP:-}" ]] || die RUNNER_TEMP
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
export HFS_PUBLISHED_IMAGE_REFERENCE="$immutable"
export HFS_PUBLISHED_IMAGE_DIGEST="$reference"
export HFS_PUBLISHED_AT_EPOCH="$(date +%s)"
node --input-type=module <<'NODE'
import { writeFileSync } from "node:fs";
const value = (name) => process.env[name];
const manifest = {
  schema: "hfs.public-release-image-provenance/v1",
  purpose: "RELEASE_IMAGE_ONLY",
  approvalPurpose: "PREPARE_IMAGE",
  requestId: value("HFS_PUBLICATION_REQUEST_ID"),
  nonce: value("HFS_PUBLICATION_NONCE"),
  createdAtEpoch: Number(value("HFS_PUBLICATION_CREATED_AT_EPOCH")),
  expiresAtEpoch: Number(value("HFS_PUBLICATION_EXPIRES_AT_EPOCH")),
  publicationRunId: value("GITHUB_RUN_ID"),
  controllerRepository: value("GITHUB_REPOSITORY"),
  controllerRef: value("GITHUB_REF"),
  controllerHead: value("GITHUB_SHA"),
  controllerWorkflow: ".github/workflows/release-image-only.yml",
  controllerWorkflowBlob: value("HFS_CONTROLLER_WORKFLOW_BLOB"),
  controllerExecutor: "scripts/release-image-only.sh",
  controllerExecutorBlob: value("HFS_CONTROLLER_EXECUTOR_BLOB"),
  appRepository: "Ronmel71/hfs-selger-app",
  appRef: "refs/heads/staging",
  appCommit: value("HFS_APP_COMMIT"),
  appTree: value("HFS_APP_TREE"),
  imageReference: value("HFS_PUBLISHED_IMAGE_REFERENCE"),
  imageDigest: value("HFS_PUBLISHED_IMAGE_DIGEST"),
  publishedAtEpoch: Number(value("HFS_PUBLISHED_AT_EPOCH")),
};
writeFileSync(`${process.env.RUNNER_TEMP}/hfs-release-image-provenance.json`, `${JSON.stringify(manifest)}\n`, { mode: 0o600 });
NODE
printf 'RELEASE_IMAGE_ONLY_COMPLETE app_sha=%s image_digest=%s\n' "$HFS_APP_COMMIT" "$reference" >> "$GITHUB_STEP_SUMMARY"
