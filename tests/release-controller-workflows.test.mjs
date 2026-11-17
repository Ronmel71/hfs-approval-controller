import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const image = readFileSync(new URL("../.github/workflows/release-image-only.yml", import.meta.url), "utf8");
const deploy = readFileSync(new URL("../.github/workflows/release-deploy-only.yml", import.meta.url), "utf8");
const imageScript = readFileSync(new URL("../scripts/release-image-only.sh", import.meta.url), "utf8");
const deployScript = readFileSync(new URL("../scripts/release-deploy-only.sh", import.meta.url), "utf8");
const contractScript = readFileSync(new URL("../scripts/release-controller-contract.mjs", import.meta.url), "utf8");
const preflightScript = readFileSync(new URL("../scripts/release-controller-preflight.mjs", import.meta.url), "utf8");
const existingGate = readFileSync(new URL("../.github/workflows/stage-only-review.yml", import.meta.url));
const gitBlob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
const CORRECTED_HELPER_BLOB = "76e408175ac0ff8b207665475f9f5d1240766738";
const SUPERSEDED_HELPER_BLOB = "30ee1ec77efe72d754a17ecc839f0cfa581542ce";

describe("two-purpose controller workflows", () => {
  it("preserves the verified existing native-review workflow byte-for-byte", () => {
    assert.equal(gitBlob(existingGate), "8d9cffac492d41804ff2dd5a5f1d09d4b925bbf4");
  });

  it("activates both purpose-specific jobs only behind the exact strict pre-gate condition", () => {
    const strictReleaseCondition = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.run_attempt == 1 && github.actor == 'Ronmel71' && github.triggering_actor == 'Ronmel71'";
    const imageConditions = [...image.matchAll(/^\s+if: \$\{\{ (.+) \}\}$/gm)].map((match) => match[1]);
    const deployConditions = [...deploy.matchAll(/^\s+if: \$\{\{ (.+) \}\}$/gm)].map((match) => match[1]);

    assert.deepEqual(imageConditions, [strictReleaseCondition, strictReleaseCondition]);
    assert.deepEqual(deployConditions, [strictReleaseCondition, strictReleaseCondition]);
    assert.doesNotMatch(image, /if: \$\{\{ false \}\}/);
    assert.doesNotMatch(deploy, /if: \$\{\{ false \}\}/);
    assert.doesNotMatch(image + deploy, /^  (pull_request|pull_request_target|push|schedule|repository_dispatch):/m);
    assert.match(image, /  release-image-only:\n(?:.|\n)*?    needs: validate-request/);
    assert.match(deploy, /  release-deploy-only:\n(?:.|\n)*?    needs: validate-request/);
    assert.match(image, /environment: production-image-publication/);
    assert.match(deploy, /environment: production-host-deployment/);
    assert.doesNotMatch(image, /RELEASE_DEPLOY_ONLY|APPROVE_DEPLOY|production-host-deployment|release-deploy-only/);
  });

  it("rejects broadened, automatic, rerun, and non-Ronny deploy gates", () => {
    const strictReleaseCondition = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.run_attempt == 1 && github.actor == 'Ronmel71' && github.triggering_actor == 'Ronmel71'";
    const acceptsReleaseGate = (condition) => condition === strictReleaseCondition;

    assert.equal(acceptsReleaseGate(strictReleaseCondition), true);
    for (const unsafeCondition of [
      "github.ref == 'refs/heads/main' && github.run_attempt == 1 && github.actor == 'Ronmel71' && github.triggering_actor == 'Ronmel71'",
      strictReleaseCondition.replace("workflow_dispatch", "push"),
      strictReleaseCondition.replace("github.ref == 'refs/heads/main' && ", ""),
      strictReleaseCondition.replace("github.run_attempt == 1", "github.run_attempt >= 1"),
      strictReleaseCondition.replace("github.actor == 'Ronmel71'", "github.actor == 'another-user'"),
      strictReleaseCondition.replace("github.triggering_actor == 'Ronmel71'", "github.triggering_actor == 'another-user'"),
    ]) {
      assert.equal(acceptsReleaseGate(unsafeCondition), false, unsafeCondition);
    }
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
    assert.match(image.slice(0, image.indexOf("  release-image-only:")), /node scripts\/release-controller-preflight\.mjs validate-request/);
    assert.match(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /node scripts\/release-controller-preflight\.mjs validate-request/);
    assert.match(imageJob, /HFS_PRIVATE_SOURCE_READ_TOKEN: \$\{\{ secrets\.HFS_PRIVATE_SOURCE_READ_TOKEN \}\}(?:.|\n)*run: node scripts\/release-controller-preflight\.mjs verify-native-approval/);
    assert.match(deployJob, /HFS_PRIVATE_SOURCE_READ_TOKEN: \$\{\{ secrets\.HFS_PRIVATE_SOURCE_READ_TOKEN \}\}(?:.|\n)*run: node scripts\/release-controller-preflight\.mjs verify-native-approval/);
    assert.doesNotMatch(image.slice(0, image.indexOf("  release-image-only:")), /verify-native-approval|NATIVE_APPROVED/);
    assert.doesNotMatch(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /verify-native-approval|NATIVE_APPROVED/);
    assert.match(preflightScript, /redirect: binary \? "follow" : "error"/);
    assert.match(preflightScript, /\/actions\/runs\?event=workflow_dispatch&branch=main&per_page=100&page=/);
    assert.match(preflightScript, /\/actions\/runs\/\$\{run\.id\}\/approvals/);
    assert.match(preflightScript, /\/environments\/\$\{encodeURIComponent\(purposePolicy\.environment\)\}/);
    assert.match(preflightScript, /HFS_CONTROLLER_ADMIN_READ_TOKEN/);
    assert.match(imageJob, /HFS_CONTROLLER_ADMIN_READ_TOKEN: \$\{\{ secrets\.HFS_CONTROLLER_ADMIN_READ_TOKEN \}\}/);
    assert.match(deployJob, /HFS_CONTROLLER_ADMIN_READ_TOKEN: \$\{\{ secrets\.HFS_CONTROLLER_ADMIN_READ_TOKEN \}\}/);
    assert.doesNotMatch(image.slice(0, image.indexOf("  release-image-only:")), /HFS_CONTROLLER_ADMIN_READ_TOKEN/);
    assert.doesNotMatch(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /HFS_CONTROLLER_ADMIN_READ_TOKEN/);
    assert.doesNotMatch(image + deploy, /administration:\s*(?:read|write)/);
    assert.doesNotMatch(preflightScript, /\/rulesets|\/rules\/branches\/main|branches\/main["`]/);
    assert.match(preflightScript, /PROVENANCE_NOT_VERIFIED/);
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

  it("binds a strict per-request app source and uses digest readback without mutable tags or fallback", () => {
    for (const source of [image, deploy, imageScript, deployScript]) {
      assert.doesNotMatch(source, /:latest|refs\/heads\/staging[^'"\n]*checkout/);
    }
    for (const workflow of [image, deploy]) {
      assert.match(workflow, /app_commit:\n\s+description: Exact approved private app commit \(40 lowercase hex\)/);
      assert.match(workflow, /app_tree:\n\s+description: Exact approved private app tree \(40 lowercase hex\)/);
      assert.match(workflow, /ref: \$\{\{ inputs\.app_commit \}\}/);
      assert.match(workflow, /name: Native approval · RELEASE_(?:IMAGE|DEPLOY)_ONLY · \$\{\{ inputs\.app_commit \}\}/);
      assert.match(workflow, /run-name:.*\$\{\{ inputs\.app_commit \}\}/);
    }
    assert.doesNotMatch(image.slice(0, image.indexOf("  release-image-only:")), /HFS_PRIVATE_SOURCE_READ_TOKEN|secrets\./);
    assert.doesNotMatch(deploy.slice(0, deploy.indexOf("  release-deploy-only:")), /HFS_PRIVATE_SOURCE_READ_TOKEN|secrets\./);
    assert.match(preflightScript, /attestPrivateAppSource/);
    assert.match(preflightScript, /\/compare\/\$\{request\.app\.commit\}\.\.\.\$\{stagingHead\}/);
    assert.match(imageScript, /docker buildx imagetools inspect/);
    assert.match(imageScript, /ghcr\.io\/ronmel71\/hfs-selger-app@\$reference/);
    assert.match(image, /actions\/upload-artifact@[0-9a-f]{40}/);
    assert.match(image, /hfs-release-image-provenance/);
    assert.match(imageScript, /hfs\.public-release-image-provenance\/v1/);
    assert.match(deploy, /publication_run_id/);
    assert.match(deploy, /publication_controller_head/);
    assert.match(deploy, /publication_workflow_blob/);
    assert.match(deploy, /run-name:.*publication \$\{\{ inputs\.publication_run_id \}\}/);
    assert.doesNotMatch(image + deploy, /798ada90d2b6461a59d4b495ca3798b110b1a2e6|782771cf58956453d31313756252ba073a852c5c/);
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

  it("accepts only the corrected helper at contract and executor boundaries", () => {
    for (const source of [contractScript, imageScript, deployScript]) {
      assert.match(source, new RegExp(CORRECTED_HELPER_BLOB));
      assert.doesNotMatch(source, new RegExp(SUPERSEDED_HELPER_BLOB));
    }
  });
});
