#!/usr/bin/env bash
set -Eeuo pipefail

readonly EXPECTED_HELPER_SHA256=d9b8296d9cc32757e611b547f222c94976dea5dd8de38986dbb84401fd8565ad
readonly INTERFACE_NAME=hfs-check
readonly REMOTE_HOST=10.77.0.1
readonly REMOTE_USER=hfsdeploy
readonly HELPER_PATH=/usr/local/sbin/hfs-deploy-release

die() {
  printf 'HOST_CONNECTIVITY_ONLY_REFUSED code=%s\n' "$1" >&2
  exit 78
}

job_root=""
wg_path=""
ssh_root=""
wg_attempted=0
wg_owned=0
wg_state_ambiguous=0
completed=0

interface_state() {
  local links
  links="$(ip -o link show 2>/dev/null)" || return 2
  if awk -F ': ' -v wanted="$INTERFACE_NAME" '
    {
      name=$2
      sub(/@.*/, "", name)
      if (name == wanted) found=1
    }
    END { exit(found ? 0 : 1) }
  ' <<< "$links"; then
    return 0
  fi
  return 1
}

interface_owned_by_job() {
  local observed_public_key
  observed_public_key="$(sudo wg show "$INTERFACE_NAME" public-key 2>/dev/null)" || return 1
  [[ "$observed_public_key" == "$expected_client_public_key" ]]
}

require_fresh() {
  local now_epoch
  now_epoch="$(date +%s)" || die EXPIRY
  [[ "$now_epoch" =~ ^[0-9]{10}$ ]] || die EXPIRY
  (( now_epoch < HFS_CONNECTIVITY_EXPIRES_AT_EPOCH )) || die EXPIRED
}

cleanup() {
  local status=$? cleanup_failed=0 state_status
  trap - EXIT
  if [[ "$wg_owned" == 1 ]]; then
    if ! sudo wg-quick down "$wg_path" >/dev/null 2>&1; then
      cleanup_failed=1
    fi
    if interface_state; then
      cleanup_failed=1
    else
      state_status=$?
      if [[ "$state_status" != 1 ]]; then
        cleanup_failed=1
      fi
    fi
  elif [[ "$wg_state_ambiguous" == 1 ]]; then
    cleanup_failed=1
  fi
  if [[ -n "$job_root" && -d "$job_root" ]]; then
    if ! find "$job_root" -type f -exec shred -u -- {} + >/dev/null 2>&1; then
      cleanup_failed=1
      find "$job_root" -type f -exec rm -f -- {} + >/dev/null 2>&1 || true
    fi
    if ! rmdir "$ssh_root" "$job_root" >/dev/null 2>&1; then
      cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    printf 'HOST_CONNECTIVITY_ONLY_INCOMPLETE code=CLEANUP\n' >&2
    exit 79
  fi
  if [[ "$status" == 0 && "$completed" == 1 ]]; then
    local line='HOST_CONNECTIVITY_ONLY_PASS identity=true docker_group=false helper_pin=true helper_check=true cleanup=true deploy_authorization=false'
    printf '%s\n' "$line"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      printf -- '- %s\n- Read-only transport/check evidence only; no deploy, install, rollback, release, or overall application readiness was authorized.\n' "$line" >> "$GITHUB_STEP_SUMMARY"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || die EVENT
[[ "${GITHUB_REPOSITORY:-}" == Ronmel71/hfs-approval-controller ]] || die REPOSITORY
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || die REF
[[ "${GITHUB_RUN_ATTEMPT:-}" == 1 ]] || die ATTEMPT
[[ "${GITHUB_ACTOR:-}" == Ronmel71 ]] || die ACTOR
[[ "${GITHUB_TRIGGERING_ACTOR:-}" == Ronmel71 ]] || die TRIGGERING_ACTOR
[[ "${HFS_CONNECTIVITY_PURPOSE:-}" == HOST_CONNECTIVITY_ONLY ]] || die PURPOSE
[[ "${HFS_CONNECTIVITY_CONTROLLER_HEAD:-}" =~ ^[0-9a-f]{40}$ && "${GITHUB_SHA:-}" == "$HFS_CONNECTIVITY_CONTROLLER_HEAD" ]] || die CONTROLLER_HEAD
[[ "${HFS_CONNECTIVITY_REMOTE_HELPER_SHA256:-}" == "$EXPECTED_HELPER_SHA256" ]] || die HELPER_PIN
[[ "${HFS_CONNECTIVITY_EXPIRES_AT_EPOCH:-}" =~ ^[0-9]{10}$ ]] || die EXPIRY
require_fresh
[[ "${DEPLOY_WIREGUARD_HOST:-}" == "$REMOTE_HOST" ]] || die WG_HOST
[[ "${DEPLOY_USER:-}" == "$REMOTE_USER" ]] || die SSH_USER
[[ -n "${DEPLOY_WIREGUARD_CONFIG:-}" && -n "${DEPLOY_SSH_KEY:-}" && -n "${DEPLOY_SSH_KNOWN_HOSTS:-}" ]] || die HOST_CREDENTIAL
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die RUNNER_TEMP

umask 077
job_root="$(mktemp -d "$RUNNER_TEMP/hfs-connectivity.XXXXXX")"
chmod 0700 "$job_root"
wg_path="$job_root/$INTERFACE_NAME.conf"
ssh_root="$job_root/ssh"
install -d -m 0700 "$ssh_root"
printf '%s\n' "$DEPLOY_WIREGUARD_CONFIG" > "$wg_path"
printf '%s\n' "$DEPLOY_SSH_KEY" > "$ssh_root/id_ed25519"
printf '%s\n' "$DEPLOY_SSH_KNOWN_HOSTS" > "$ssh_root/known_hosts"
chmod 0600 "$wg_path" "$ssh_root/id_ed25519" "$ssh_root/known_hosts"
unset DEPLOY_WIREGUARD_CONFIG DEPLOY_SSH_KEY DEPLOY_SSH_KNOWN_HOSTS DEPLOY_WIREGUARD_HOST DEPLOY_USER

[[ "${wg_path##*/}" == hfs-check.conf && ${#INTERFACE_NAME} -le 15 ]] || die WG_BASENAME

if ! awk '
  function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
  BEGIN { section=""; interfaces=0; peers=0 }
  /^[[:space:]]*($|#|;)/ { next }
  /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
    name=$0; gsub(/[[:space:]\[\]]/, "", name)
    if (name == "Interface") { interfaces++; section="Interface" }
    else if (name == "Peer") { peers++; section="Peer" }
    else exit 10
    next
  }
  {
    split_at=index($0, "="); if (split_at == 0 || section == "") exit 11
    key=trim(substr($0, 1, split_at - 1))
    if (section == "Interface" && key !~ /^(Address|PrivateKey)$/) exit 12
    if (section == "Peer" && key !~ /^(PublicKey|PresharedKey|Endpoint|AllowedIPs|PersistentKeepalive)$/) exit 13
    seen[section "." key]++
  }
  END {
    if (interfaces != 1 || peers != 1) exit 14
    required[1]="Interface.Address"; required[2]="Interface.PrivateKey"; required[3]="Peer.PublicKey"
    required[4]="Peer.PresharedKey"; required[5]="Peer.Endpoint"; required[6]="Peer.AllowedIPs"
    for (i=1; i<=6; i++) if (seen[required[i]] != 1) exit 15
    for (key in seen) if (seen[key] != 1) exit 16
  }
' "$wg_path"; then
  die WG_SCHEMA
fi

config_value() {
  local wanted_section=$1 wanted_key=$2
  awk -v wanted_section="$wanted_section" -v wanted_key="$wanted_key" '
    function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { section=$0; gsub(/[[:space:]\[\]]/, "", section); next }
    {
      split_at=index($0, "="); if (split_at == 0) next
      key=trim(substr($0, 1, split_at - 1))
      if (section == wanted_section && key == wanted_key) print trim(substr($0, split_at + 1))
    }
  ' "$wg_path"
}

address="$(config_value Interface Address)"
private_key="$(config_value Interface PrivateKey)"
server_public_key="$(config_value Peer PublicKey)"
preshared_key="$(config_value Peer PresharedKey)"
endpoint="$(config_value Peer Endpoint)"
allowed_ips="$(config_value Peer AllowedIPs)"
keepalive="$(config_value Peer PersistentKeepalive)"

[[ "$address" == 10.77.0.2/32 ]] || die WG_ADDRESS
[[ "$allowed_ips" == 10.77.0.1/32 ]] || die WG_ROUTE
[[ "$private_key" =~ ^[A-Za-z0-9+/]{43}=$ && "$server_public_key" =~ ^[A-Za-z0-9+/]{43}=$ && "$preshared_key" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die WG_KEY_FORMAT
[[ "$preshared_key" != AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ]] || die WG_PSK
client_public_key="$(printf '%s\n' "$private_key" | wg pubkey 2>/dev/null)" || die WG_PRIVATE_KEY
[[ "$client_public_key" =~ ^[A-Za-z0-9+/]{43}=$ && "$client_public_key" != "$server_public_key" ]] || die WG_BINDING
expected_client_public_key="$client_public_key"
[[ "$endpoint" =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[1-9][0-9]{0,4}$ ]] || die WG_ENDPOINT
endpoint_port="${endpoint##*:}"
(( endpoint_port <= 65535 )) || die WG_ENDPOINT
[[ -z "$keepalive" || "$keepalive" =~ ^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$ ]] || die WG_KEEPALIVE
unset address private_key server_public_key preshared_key endpoint allowed_ips keepalive endpoint_port client_public_key

strip_path="$job_root/wg-strip"
wg-quick strip "$wg_path" > "$strip_path" 2>/dev/null || die WG_STRIP
chmod 0600 "$strip_path"

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
  PreferredAuthentications publickey
  ClearAllForwardings yes
  RequestTTY no
  PermitLocalCommand no
  ProxyCommand none
  ConnectTimeout 10
  ConnectionAttempts 2
  ServerAliveInterval 5
  ServerAliveCountMax 2
  LogLevel ERROR
EOF
chmod 0600 "$ssh_root/config"

if interface_state; then
  die WG_PREEXISTING
else
  state_status=$?
  if [[ "$state_status" != 1 ]]; then
    wg_state_ambiguous=1
    die WG_STATE
  fi
fi

require_fresh
start_epoch="$(date +%s)"
wg_attempted=1
set +e
sudo wg-quick up "$wg_path" >/dev/null 2>&1
up_status=$?
set -e

if interface_state; then
  if [[ "$wg_attempted" == 1 ]] && interface_owned_by_job; then
    wg_owned=1
  else
    wg_state_ambiguous=1
    die WG_OWNERSHIP
  fi
else
  state_status=$?
  if [[ "$state_status" != 1 ]]; then
    wg_state_ambiguous=1
    die WG_STATE
  fi
fi
if [[ "$up_status" != 0 ]]; then
  die WG_UP
fi
[[ "$wg_owned" == 1 ]] || die WG_STATE

ssh_read() {
  local remote_command=$1 output_path=$2
  require_fresh
  ssh -F "$ssh_root/config" hfs-production "$remote_command" > "$output_path" 2>/dev/null
}

identity_path="$job_root/identity"
ssh_read 'id -un' "$identity_path" || die SSH_IDENTITY
[[ "$(<"$identity_path")" == hfsdeploy ]] || die REMOTE_IDENTITY

handshake_path="$job_root/handshake"
require_fresh
sudo wg show "$INTERFACE_NAME" latest-handshakes > "$handshake_path" 2>/dev/null || die WG_HANDSHAKE
[[ "$(awk 'NF == 2 { count++; timestamp=$2 } END { if (count == 1) print timestamp }' "$handshake_path")" =~ ^[1-9][0-9]{9}$ ]] || die WG_HANDSHAKE
handshake_epoch="$(awk 'NF == 2 { timestamp=$2 } END { print timestamp }' "$handshake_path")"
now_epoch="$(date +%s)"
(( handshake_epoch >= start_epoch - 5 && handshake_epoch <= now_epoch && now_epoch - handshake_epoch <= 30 )) || die WG_HANDSHAKE

groups_path="$job_root/groups"
ssh_read 'id -nG' "$groups_path" || die SSH_GROUPS
grep -Eq '(^|[[:space:]])hfsdeploy($|[[:space:]])' "$groups_path" || die REMOTE_GROUPS
if grep -Eq '(^|[[:space:]])docker($|[[:space:]])' "$groups_path"; then die REMOTE_DOCKER_GROUP; fi

metadata_path="$job_root/helper-metadata"
ssh_read "stat -Lc '%a %u %g' /usr/local/sbin/hfs-deploy-release" "$metadata_path" || die HELPER_METADATA
[[ "$(<"$metadata_path")" == '755 0 0' ]] || die HELPER_METADATA

hash_path="$job_root/helper-sha256"
ssh_read 'sha256sum /usr/local/sbin/hfs-deploy-release' "$hash_path" || die HELPER_HASH
read -r observed_hash observed_path < "$hash_path" || die HELPER_HASH
[[ "$observed_hash" == "$EXPECTED_HELPER_SHA256" && "$observed_path" == "$HELPER_PATH" ]] || die HELPER_HASH

check_path="$job_root/helper-check"
ssh_read 'sudo -n /usr/local/sbin/hfs-deploy-release --check' "$check_path" || die HELPER_CHECK
[[ "$(<"$check_path")" == 'hfs-deploy-release: installation validation passed; no release state changed' ]] || die HELPER_CHECK_OUTPUT

completed=1
