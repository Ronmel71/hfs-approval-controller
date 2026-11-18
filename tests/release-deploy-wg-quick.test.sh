#!/usr/bin/env bash
set -euo pipefail

wg_quick_bin="${WG_QUICK_BIN:-}"
if [[ -z "$wg_quick_bin" ]]; then
  wg_quick_bin="$(command -v wg-quick || true)"
fi
[[ -x "$wg_quick_bin" ]] || {
  printf 'wg-quick is required (set WG_QUICK_BIN to its executable path)\n' >&2
  exit 69
}
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
mkdir "$test_root/bin"

for blocked_command in wg ip ssh curl nc ping; do
  cat > "$test_root/bin/$blocked_command" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$0" >> "$WG_QUICK_TEST_CALLED"
exit 97
EOF
  chmod 0700 "$test_root/bin/$blocked_command"
done

write_config() {
  local path="$1"
  cat > "$path" <<'EOF'
[Interface]
Address = 10.77.0.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
EOF
  chmod 0600 "$path"
}

old_config="$test_root/hfs-controller-wg.conf"
new_config="$test_root/hfs-wg.conf"
write_config "$old_config"
write_config "$new_config"

export WG_QUICK_TEST_CALLED="$test_root/called"
export PATH="$test_root/bin:$PATH"

run_strip() {
  if command -v unshare >/dev/null && unshare -Ur -- true >/dev/null 2>&1; then
    unshare -Ur -- "$@"
  else
    sudo -n env PATH="$PATH" "$@"
  fi
}

if run_strip "$wg_quick_bin" strip "$old_config" > "$test_root/old.out" 2> "$test_root/old.err"; then
  printf 'expected wg-quick to reject the overlength interface basename\n' >&2
  exit 1
fi
grep -Fq 'must be a valid interface name' "$test_root/old.err"

run_strip "$wg_quick_bin" strip "$new_config" > "$test_root/new.out" 2> "$test_root/new.err"
grep -Fxq '[Interface]' "$test_root/new.out"
grep -Fxq '[Peer]' "$test_root/new.out"
[[ ! -e "$WG_QUICK_TEST_CALLED" ]]

printf 'release deploy wg-quick basename test: PASS\n'
