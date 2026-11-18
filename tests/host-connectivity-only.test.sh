#!/usr/bin/env bash
set -euo pipefail

executor="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/host-connectivity-only.sh"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
mkdir "$test_root/bin" "$test_root/proof-bin"

real_wg="${WG_BIN:-$(command -v wg || true)}"
real_wg_quick="${WG_QUICK_BIN:-$(command -v wg-quick || true)}"
if [[ ! -x "$real_wg" || ! -x "$real_wg_quick" ]]; then
  package_download="$test_root/package-download"
  package_root="$test_root/wireguard-tools"
  mkdir "$package_download" "$package_root"
  (
    cd "$package_download"
    apt-get download wireguard-tools >/dev/null 2>&1
  ) || {
    printf 'official distro wireguard-tools package is required for the isolated proof\n' >&2
    exit 69
  }
  package_file="$(find "$package_download" -maxdepth 1 -type f -name 'wireguard-tools_*.deb' -print -quit)"
  [[ -n "$package_file" ]] || exit 69
  dpkg-deb -x "$package_file" "$package_root"
  real_wg="$package_root/usr/bin/wg"
  real_wg_quick="$package_root/usr/bin/wg-quick"
fi
[[ -x "$real_wg" && -x "$real_wg_quick" ]]

client_private="$($real_wg genkey)"
client_public="$(printf '%s\n' "$client_private" | "$real_wg" pubkey)"
server_private="$($real_wg genkey)"
server_public="$(printf '%s\n' "$server_private" | "$real_wg" pubkey)"
preshared_key="$($real_wg genpsk)"
unset server_private client_public

write_config() {
  local path=$1
  cat > "$path" <<EOF
[Interface]
Address = 10.77.0.2/32
PrivateKey = $client_private

[Peer]
PublicKey = $server_public
PresharedKey = $preshared_key
Endpoint = vpn.example.test:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
EOF
  chmod 0600 "$path"
}

cat > "$test_root/bin/wg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == pubkey && "$#" == 1 ]]; then
  exec "$REAL_WG" pubkey
fi
printf 'unexpected wg invocation\n' >&2
exit 91
EOF

cat > "$test_root/bin/wg-quick" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == strip && "$#" == 2 ]]; then
  printf '[Interface]\n[Peer]\n'
  exit 0
fi
printf 'unexpected direct wg-quick invocation\n' >&2
exit 91
EOF

cat > "$test_root/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$STUB_SUDO_LOG"
if [[ "${1:-}" == wg-quick && "${2:-}" == up && "$#" == 3 ]]; then
  exit 0
fi
if [[ "${1:-}" == wg-quick && "${2:-}" == down && "$#" == 3 ]]; then
  [[ "${CLEANUP_FAIL:-0}" == 0 ]]
  exit
fi
if [[ "${1:-}" == wg && "${2:-}" == show && "${3:-}" == hfs-check && "${4:-}" == latest-handshakes && "$#" == 4 ]]; then
  printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t%s\n' "$(date +%s)"
  exit 0
fi
printf 'unexpected sudo invocation\n' >&2
exit 92
EOF

cat > "$test_root/bin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 4 && "$1" == -F && -f "$2" && "$3" == hfs-production ]] || exit 93
command=$4
printf '%s\n' "$command" >> "$STUB_SSH_LOG"
case "$command" in
  'id -un')
    [[ "${SSH_MODE:-success}" == wrong_identity ]] && printf 'root\n' || printf 'hfsdeploy\n'
    ;;
  'id -nG')
    [[ "${SSH_MODE:-success}" == docker_group ]] && printf 'hfsdeploy docker\n' || printf 'hfsdeploy\n'
    ;;
  "stat -Lc '%a %u %g' /usr/local/sbin/hfs-deploy-release")
    printf '755 0 0\n'
    ;;
  'sha256sum /usr/local/sbin/hfs-deploy-release')
    if [[ "${SSH_MODE:-success}" == wrong_helper_hash ]]; then
      printf '%064d  /usr/local/sbin/hfs-deploy-release\n' 0
    else
      printf '1889dea8df10f9dfd11f51fe845703758577b0f1af4ac6960fd5f846db4b0351  /usr/local/sbin/hfs-deploy-release\n'
    fi
    ;;
  'sudo -n /usr/local/sbin/hfs-deploy-release --check')
    [[ "${SSH_MODE:-success}" != check_fail ]] || exit 94
    printf 'hfs-deploy-release: installation validation passed; no release state changed\n'
    ;;
  *)
    exit 95
    ;;
esac
EOF
chmod 0700 "$test_root/bin/wg" "$test_root/bin/wg-quick" "$test_root/bin/sudo" "$test_root/bin/ssh"

for blocked_command in wg ip ssh curl nc ping; do
  cat > "$test_root/proof-bin/$blocked_command" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$0" >> "$WG_PROOF_CALLED"
exit 97
EOF
  chmod 0700 "$test_root/proof-bin/$blocked_command"
done

proof_config="$test_root/hfs-check.conf"
write_config "$proof_config"
export WG_PROOF_CALLED="$test_root/proof-called"
if command -v unshare >/dev/null && unshare -Ur -- true >/dev/null 2>&1; then
  PATH="$test_root/proof-bin:$PATH" unshare -Ur -- "$real_wg_quick" strip "$proof_config" > "$test_root/proof.out" 2> "$test_root/proof.err"
else
  sudo -n env PATH="$test_root/proof-bin:$PATH" "$real_wg_quick" strip "$proof_config" > "$test_root/proof.out" 2> "$test_root/proof.err"
fi
grep -Fxq '[Interface]' "$test_root/proof.out"
grep -Fxq '[Peer]' "$test_root/proof.out"
[[ ! -e "$WG_PROOF_CALLED" ]]

WG_QUICK_BIN="$real_wg_quick" bash "$(dirname "$executor")/../tests/release-deploy-wg-quick.test.sh" > "$test_root/release-wg-quick.out"
grep -Fxq 'release deploy wg-quick basename test: PASS' "$test_root/release-wg-quick.out"

run_case() {
  local name=$1 config=$2 ssh_mode=$3 cleanup_fail=$4 expected_status=$5 expected_error=${6:-}
  local case_root="$test_root/$name"
  mkdir -p "$case_root/temp"
  : > "$case_root/ssh.log"
  : > "$case_root/sudo.log"
  set +e
  env \
    PATH="$test_root/bin:$PATH" \
    REAL_WG="$real_wg" \
    STUB_SSH_LOG="$case_root/ssh.log" \
    STUB_SUDO_LOG="$case_root/sudo.log" \
    SSH_MODE="$ssh_mode" \
    CLEANUP_FAIL="$cleanup_fail" \
    RUNNER_TEMP="$case_root/temp" \
    GITHUB_EVENT_NAME=workflow_dispatch \
    GITHUB_REPOSITORY=Ronmel71/hfs-approval-controller \
    GITHUB_REF=refs/heads/main \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_ACTOR=Ronmel71 \
    GITHUB_TRIGGERING_ACTOR=Ronmel71 \
    GITHUB_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    HFS_CONNECTIVITY_PURPOSE=HOST_CONNECTIVITY_ONLY \
    HFS_CONNECTIVITY_CONTROLLER_HEAD=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    HFS_CONNECTIVITY_REMOTE_HELPER_SHA256=1889dea8df10f9dfd11f51fe845703758577b0f1af4ac6960fd5f846db4b0351 \
    DEPLOY_WIREGUARD_HOST=10.77.0.1 \
    DEPLOY_USER=hfsdeploy \
    DEPLOY_WIREGUARD_CONFIG="$(<"$config")" \
    DEPLOY_SSH_KEY='synthetic-private-key' \
    DEPLOY_SSH_KNOWN_HOSTS='10.77.0.1 ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
    bash "$executor" > "$case_root/out" 2> "$case_root/err"
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] || {
    printf 'case %s: expected status %s, got %s\n' "$name" "$expected_status" "$status" >&2
    sed -n '1,20p' "$case_root/err" >&2
    exit 1
  }
  if [[ -n "$expected_error" ]]; then grep -Fq "$expected_error" "$case_root/err"; fi
  if [[ "$expected_status" != 0 ]]; then ! grep -Fq HOST_CONNECTIVITY_ONLY_PASS "$case_root/out"; fi
}

base_config="$test_root/base.conf"
write_config "$base_config"
run_case success "$base_config" success 0 0
grep -Fq 'HOST_CONNECTIVITY_ONLY_PASS identity=true docker_group=false helper_pin=true helper_check=true cleanup=true deploy_authorization=false' "$test_root/success/out"
cat > "$test_root/expected-ssh.log" <<'EOF'
id -un
id -nG
stat -Lc '%a %u %g' /usr/local/sbin/hfs-deploy-release
sha256sum /usr/local/sbin/hfs-deploy-release
sudo -n /usr/local/sbin/hfs-deploy-release --check
EOF
cmp "$test_root/expected-ssh.log" "$test_root/success/ssh.log"
grep -Eq '^wg-quick up .*/hfs-check\.conf$' "$test_root/success/sudo.log"
grep -Eq '^wg show hfs-check latest-handshakes$' "$test_root/success/sudo.log"
grep -Eq '^wg-quick down .*/hfs-check\.conf$' "$test_root/success/sudo.log"

for mode in wrong_identity docker_group wrong_helper_hash check_fail; do
  run_case "$mode" "$base_config" "$mode" 0 78 HOST_CONNECTIVITY_ONLY_REFUSED
  grep -Eq '^wg-quick down .*/hfs-check\.conf$' "$test_root/$mode/sudo.log"
done

run_case cleanup_failure "$base_config" success 1 79 'HOST_CONNECTIVITY_ONLY_INCOMPLETE code=CLEANUP'
! grep -Fq HOST_CONNECTIVITY_ONLY_PASS "$test_root/cleanup_failure/out"

make_invalid() {
  local name=$1
  cp "$base_config" "$test_root/$name.conf"
}

make_invalid broad_route
sed -i 's/AllowedIPs = 10\.77\.0\.1\/32/AllowedIPs = 0.0.0.0\/0/' "$test_root/broad_route.conf"
make_invalid hook
sed -i '/PrivateKey/a PreUp = echo forbidden' "$test_root/hook.conf"
make_invalid extra_peer
printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = other.example.test:51820\nAllowedIPs = 10.77.0.1/32\n' "$server_public" "$preshared_key" >> "$test_root/extra_peer.conf"
make_invalid no_psk
sed -i '/^PresharedKey =/d' "$test_root/no_psk.conf"
make_invalid unknown
sed -i '/^Address =/a DNS = 1.1.1.1' "$test_root/unknown.conf"
make_invalid malformed
sed -i 's/^PublicKey = .*/PublicKey = invalid/' "$test_root/malformed.conf"

for invalid in broad_route hook extra_peer no_psk unknown malformed; do
  run_case "invalid_$invalid" "$test_root/$invalid.conf" success 0 78 HOST_CONNECTIVITY_ONLY_REFUSED
  [[ ! -s "$test_root/invalid_$invalid/ssh.log" ]]
  ! grep -Fq 'wg-quick up' "$test_root/invalid_$invalid/sudo.log"
done

grep -Fq 'BatchMode yes' "$executor"
grep -Fq 'IdentitiesOnly yes' "$executor"
grep -Fq 'IdentityAgent none' "$executor"
grep -Fq 'StrictHostKeyChecking yes' "$executor"
grep -Fq 'GlobalKnownHostsFile /dev/null' "$executor"
grep -Fq 'ClearAllForwardings yes' "$executor"
! grep -Eiq '\b(scp|rsync|docker|--install|--rollback)\b' "$executor"

printf 'host connectivity only executor tests: PASS\n'
