import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const image = readFileSync(new URL("../.github/workflows/release-image-only.yml", import.meta.url), "utf8");
const deploy = readFileSync(new URL("../.github/workflows/release-deploy-only.yml", import.meta.url), "utf8");
const imageScript = readFileSync(new URL("../scripts/release-image-only.sh", import.meta.url), "utf8");
const deployScript = readFileSync(new URL("../scripts/release-deploy-only.sh", import.meta.url), "utf8");
const preflightScript = readFileSync(new URL("../scripts/release-controller-preflight.mjs", import.meta.url), "utf8");
const existingGate = readFileSync(new URL("../.github/workflows/stage-only-review.yml", import.meta.url));
const gitBlob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");

describe("dormant controller workflows", () => {
  it("preserves the verified existing native-review workflow byte-for-byte", () => {
    assert.equal(gitBlob(existingGate), "8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4");
  });

  it("keeps every credential or artifact producing job literal-disabled", () => {
    assert.match(image, /  release-image-only:\n(?:.|\n)*?    if: \$\{\{ false \}\}/);
    assert.match(deploy, /  release-deploy-only:\n(?:.|\n)*?    if: \$\{\{ false \}\}/);
    assert.equal(image.match(/if: \$\{\{ false \}\}/g)?.length, 1);
    assert.equal(deploy.match(/if: \$\{\{ false \}\}/g)?.length, 1);
    assert.doesNotMatch(image + deploy, /^  (pull_request|pull_request_target|push|schedule|repository_dispatch):/m);
  });

  it("puts distinct native environments on the credential-bearing jobs before any secret use", () => {
    const imageJob = image.slice(image.indexOf("  release-image-only:"));
    const deployJob = deploy.slice(deploy.indexOf("  release-deploy-only:"));
    assert.match(imageJob, /environment: production-image-publication/);
    assert.match(deployJob, /environment: production-host-deployment/);
    assert.ok(imageJob.indexOf("environment:") < imageJob.indexOf("secrets."));
    assert.ok(deployJob.indexOf("environment:") < deployJob.indexOf("secrets."));
    assert.doesNotMatch(image.slice(0, image.indexOf("  release-image-only:")), /secrets\./);
    assert.doesNotMatch(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /secrets\./);
    assert.match(image.slice(0, image.indexOf("  release-image-only:")), /node scripts\/release-controller-preflight\.mjs/);
    assert.match(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /node scripts\/release-controller-preflight\.mjs/);
    assert.match(preflightScript, /redirect: "error"/);
    assert.match(preflightScript, /\/actions\/runs\?event=workflow_dispatch&branch=main&per_page=100&page=/);
    assert.doesNotMatch(preflightScript, /method:\s*"(?:POST|PUT|PATCH|DELETE)"/);
  });

  it("isolates image publication from host credentials and deploy from publisher credentials", () => {
    assert.doesNotMatch(image, /DEPLOY_(WIREGUARD|SSH|USER)/);
    assert.match(image, /HFS_PRIVATE_SOURCE_READ_TOKEN/);
    assert.match(image, /HFS_GHCR_PUBLISH_TOKEN/);
    assert.doesNotMatch(deploy, /HFS_GHCR_PUBLISH_TOKEN|packages: write/);
    for (const name of ["DEPLOY_WIREGUARD_CONFIG", "DEPLOY_WIREGUARD_HOST", "DEPLOY_SSH_KEY", "DEPLOY_SSH_KNOWN_HOSTS", "DEPLOY_USER"]) {
      assert.match(deploy, new RegExp(name));
    }
  });

  it("pins the app source and uses digest readback without mutable tags or fallback", () => {
    for (const source of [image, deploy, imageScript, deployScript]) {
      assert.match(source, /798ada90d2b6461a59d4b495ca3798b110b1a2e6/);
      assert.doesNotMatch(source, /:latest|refs\/heads\/staging[^'"\n]*checkout/);
    }
    assert.match(imageScript, /docker buildx imagetools inspect/);
    assert.match(imageScript, /ghcr\.io\/ronmel71\/hfs-selger-app@\$reference/);
    assert.match(deploy, /publication_run_id/);
    assert.match(deploy, /publication_controller_head/);
    assert.match(deploy, /publication_workflow_blob/);
  });

  it("uses hook-free WireGuard, strict no-agent SSH, no-clobber staging, and only the narrow helper", () => {
    assert.match(deployScript, /PreUp\|PostUp\|PreDown\|PostDown\|SaveConfig/);
    assert.match(deployScript, /10\\\.77\\\.0\\\.2\/32/);
    assert.match(deployScript, /AllowedIPs.*10\\\.77\\\.0\\\.1\/32/);
    for (const directive of ["BatchMode yes", "IdentitiesOnly yes", "IdentityAgent none", "StrictHostKeyChecking yes", "PasswordAuthentication no"]) {
      assert.match(deployScript, new RegExp(directive));
    }
    assert.match(deployScript, /set -euC; umask 077; mkdir/);
    assert.match(deployScript, /sudo -n \/usr\/local\/sbin\/hfs-deploy-release/);
    assert.doesNotMatch(deployScript, /ssh .*root@|sudo -i|docker (run|exec|pull)/);
    assert.doesNotMatch(imageScript + deployScript, /set -x|printenv|env\s*>|echo \$.*TOKEN/);
  });
});
