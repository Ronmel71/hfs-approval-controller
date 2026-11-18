#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'RELEASE_DEPLOY_REFUSED code=%s\n' "$1" >&2
  exit 78
}

wg_path=""
ssh_root=""
remote_dir=""

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$remote_dir" && -n "$ssh_root" && -f "$ssh_root/config" ]]; then
    ssh -F "$ssh_root/config" hfs-production \
      "rm -f -- '$remote_dir/docker-compose.yml' '$remote_dir/Caddyfile'; rmdir -- '$remote_dir'" >/dev/null 2>&1 || true
  fi
  if [[ -n "$wg_path" && -f "$wg_path" ]]; then
    sudo wg-quick down "$wg_path" >/dev/null 2>&1 || true
    shred -u "$wg_path" 2>/dev/null || rm -f -- "$wg_path"
  fi
  if [[ -n "$ssh_root" && -d "$ssh_root" ]]; then
    find "$ssh_root" -type f -exec shred -u {} + 2>/dev/null || true
    rmdir "$ssh_root" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT

[[ "${GITHUB_RUN_ATTEMPT:-}" == 1 ]] || die ATTEMPT
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || die EVENT
[[ "${GITHUB_REPOSITORY:-}" == Ronmel71/hfs-approval-controller ]] || die CONTROLLER_REPOSITORY
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || die CONTROLLER_REF
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die CONTROLLER_HEAD
[[ "${HFS_APP_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || die APP_COMMIT
[[ "${HFS_APP_TREE:-}" =~ ^[0-9a-f]{40}$ ]] || die APP_TREE
[[ "${HFS_APP_WORKFLOW_BLOB:-}" == 2c15f1e1a47af65d309c08eca4b86cbb445734a0 ]] || die APP_WORKFLOW
[[ "${HFS_IMAGE_REFERENCE:-}" =~ ^ghcr\.io/ronmel71/hfs-selger-app@sha256:[0-9a-f]{64}$ ]] || die IMAGE_DIGEST
[[ "${HFS_PUBLICATION_RUN_ID:-}" =~ ^[1-9][0-9]{5,19}$ ]] || die PUBLICATION_RUN
[[ "${DEPLOY_WIREGUARD_HOST:-}" == 10.77.0.1 ]] || die WG_HOST
[[ "${DEPLOY_USER:-}" == hfsdeploy ]] || die SSH_USER
[[ -n "${DEPLOY_WIREGUARD_CONFIG:-}" && -n "${DEPLOY_SSH_KEY:-}" && -n "${DEPLOY_SSH_KNOWN_HOSTS:-}" ]] || die HOST_CREDENTIAL

[[ "$(git rev-parse HEAD)" == "$HFS_APP_COMMIT" ]] || die SOURCE_HEAD
[[ "$(git rev-parse HEAD^{tree})" == "$HFS_APP_TREE" ]] || die SOURCE_TREE
[[ "$(git rev-parse HEAD:.github/workflows/production-release-approved.yml)" == "$HFS_APP_WORKFLOW_BLOB" ]] || die SOURCE_WORKFLOW
[[ "$(git rev-parse HEAD:deploy/production/docker-compose.yml)" == aee2e09c124c02b89dce653b9d1f628c1ea00eb6 ]] || die COMPOSE_BLOB
[[ "$(git rev-parse HEAD:deploy/production/Caddyfile)" == 3049dae5a81cc2396990ca986a97e5275f9a83dd ]] || die CADDY_BLOB
[[ "$(git rev-parse HEAD:deploy/production/host/hfs-deploy-release)" == 76e408175ac0ff8b207665475f9f5d1240766738 ]] || die HELPER_BLOB
[[ "$(git rev-parse HEAD:deploy/production/host/hfsdeploy-sudoers)" == baa83f6efe64faab8f12cb5f5a9b6a5665b51de8 ]] || die SUDOERS_BLOB

wg_path="$RUNNER_TEMP/hfs-wg.conf"
umask 077
printf '%s\n' "$DEPLOY_WIREGUARD_CONFIG" > "$wg_path"
if grep -Eiq '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=' "$wg_path"; then die WG_HOOK; fi
[[ "$(grep -Ec '^\[Interface\][[:space:]]*$' "$wg_path")" == 1 ]] || die WG_INTERFACE
[[ "$(grep -Ec '^\[Peer\][[:space:]]*$' "$wg_path")" == 1 ]] || die WG_PEER
grep -Eq '^[[:space:]]*Address[[:space:]]*=[[:space:]]*10\.77\.0\.2/32[[:space:]]*$' "$wg_path" || die WG_ADDRESS
grep -Eq '^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*10\.77\.0\.1/32[[:space:]]*$' "$wg_path" || die WG_ALLOWED_IP

ssh_root="$RUNNER_TEMP/hfs-controller-ssh"
install -d -m 0700 "$ssh_root"
printf '%s\n' "$DEPLOY_SSH_KEY" > "$ssh_root/id_ed25519"
printf '%s\n' "$DEPLOY_SSH_KNOWN_HOSTS" > "$ssh_root/known_hosts"
chmod 0600 "$ssh_root/id_ed25519" "$ssh_root/known_hosts"
[[ "$(grep -cve '^[[:space:]]*$' "$ssh_root/known_hosts")" == 1 ]] || die KNOWN_HOSTS_COUNT
grep -Eq '^10\.77\.0\.1 (ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,3}$' "$ssh_root/known_hosts" || die KNOWN_HOSTS_PIN
sed \
  -e "s|@KEY@|$ssh_root/id_ed25519|g" \
  -e "s|@KNOWN_HOSTS@|$ssh_root/known_hosts|g" \
  > "$ssh_root/config" <<'EOF'
Host hfs-production
  HostName 10.77.0.1
  User hfsdeploy
  Port 22
  BatchMode yes
  IdentitiesOnly yes
  IdentityAgent none
  IdentityFile @KEY@
  StrictHostKeyChecking yes
  UserKnownHostsFile @KNOWN_HOSTS@
  GlobalKnownHostsFile /dev/null
  PasswordAuthentication no
  KbdInteractiveAuthentication no
EOF
chmod 0600 "$ssh_root/config"

sudo wg-quick up "$wg_path" >/dev/null
remote_dir="/opt/hfs-selger-app/incoming/$HFS_APP_COMMIT"
ssh -F "$ssh_root/config" hfs-production \
  "set -euC; umask 077; mkdir '$remote_dir'; cat > '$remote_dir/docker-compose.yml'" \
  < deploy/production/docker-compose.yml
ssh -F "$ssh_root/config" hfs-production \
  "set -euC; umask 077; test -d '$remote_dir'; cat > '$remote_dir/Caddyfile'" \
  < deploy/production/Caddyfile
ssh -F "$ssh_root/config" hfs-production \
  "sudo -n /usr/local/sbin/hfs-deploy-release '$HFS_IMAGE_REFERENCE' '$HFS_APP_COMMIT'"

printf 'RELEASE_DEPLOY_ONLY_COMPLETE app_sha=%s image_digest=%s\n' \
  "$HFS_APP_COMMIT" "${HFS_IMAGE_REFERENCE##*@}" >> "$GITHUB_STEP_SUMMARY"
