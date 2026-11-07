#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/install-only-authorization.yml
source_signer=scripts/install-only-authorization.mjs

fail() {
  printf 'install-only-signer-callsite.test: %s\n' "$1" >&2
  exit 1
}

test_root=$(mktemp -d)
cleanup() {
  find "$test_root" -type f -exec shred -u -- {} + >/dev/null 2>&1 || true
  rmdir -- "$test_root" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$test_root"

# Reproduce the workflow download without network access, preserving the exact
# basename contract that activates the signer's CLI guard.
work="$test_root/download"
mkdir -m 0700 -- "$work"
signer="$work/install-only-authorization.mjs"
base64 < "$source_signer" | base64 --decode > "$signer"
[[ "$(git hash-object "$signer")" == "$(git hash-object "$source_signer")" ]] || fail 'offline downloaded signer hash drift'

set +e
node "$signer" invalid > "$work/active.stdout" 2> "$work/active.stderr"
active_status=$?
set -e
[[ "$active_status" == 78 ]] || fail "exact-basename CLI returned $active_status, expected 78"
[[ ! -s "$work/active.stdout" ]] || fail 'invalid CLI emitted stdout'
[[ "$(cat "$work/active.stderr")" == 'AUTHORIZATION_REFUSED code=AUTH_USAGE' ]] || fail 'invalid CLI did not emit stable AUTH_USAGE refusal'

# Prove the historical wrong basename skips the CLI, leaves stdout empty, and
# reaches jq's empty-envelope exit 4 instead of the intended signer exit 78.
wrong_signer="$work/signer.mjs"
cp -- "$source_signer" "$wrong_signer"
node "$wrong_signer" invalid > "$work/inactive.stdout" 2> "$work/inactive.stderr"
[[ ! -s "$work/inactive.stdout" && ! -s "$work/inactive.stderr" ]] || fail 'wrong-basename reproduction unexpectedly ran the CLI'
set +e
if command -v jq >/dev/null 2>&1; then
  jq -e '.schema == "hfs.production-first-start.github-install-authorization-envelope/v1"' "$work/inactive.stdout" >/dev/null 2>&1
else
  # The GitHub runner exercises real jq. This strict fallback keeps the offline
  # test runnable on minimal hosts while modelling only jq's empty-input result.
  [[ ! -s "$work/inactive.stdout" ]]
  (exit 4)
fi
jq_status=$?
set -e
[[ "$jq_status" == 4 ]] || fail "empty signer stdout returned jq status $jq_status, expected 4"

# Execute the parser copied directly from the workflow so arbitrary stderr can
# never become a public diagnostic. Only one exact allowlisted line is exposed.
parser_file="$test_root/parser.sh"
sed -n '/^          parse_signer_refusal() {$/,/^          }$/p' "$workflow" | sed 's/^          //' > "$parser_file"
# shellcheck source=/dev/null
source "$parser_file"
reporter_file="$test_root/reporter.sh"
sed -n '/^          report_error() {$/,/^          }$/p' "$workflow" | sed 's/^          //' > "$reporter_file"
# shellcheck source=/dev/null
source "$reporter_file"

assert_code() {
  name=$1
  stderr_value=$2
  expected=$3
  printf '%s' "$stderr_value" > "$work/signer.stderr"
  chmod 0600 "$work/signer.stderr"
  actual=
  parser_output="$test_root/parser-output"
  parse_signer_refusal actual > "$parser_output" 2>&1
  [[ ! -s "$parser_output" ]] || fail "$name parser leaked output"
  [[ "$actual" == "$expected" ]] || fail "$name produced $actual, expected $expected"
}

assert_code allowlisted $'AUTHORIZATION_REFUSED code=AUTH_USAGE\n' AUTH_USAGE
assert_code unknown-code $'AUTHORIZATION_REFUSED code=AUTH_NOT_ALLOWLISTED\n' AUTH_UNKNOWN
assert_code extra-line $'AUTHORIZATION_REFUSED code=AUTH_USAGE\nmalicious-token nonce=/private/path\n' AUTH_UNKNOWN
assert_code arbitrary $'malicious-token nonce=/private/path AUTH_USAGE\n' AUTH_UNKNOWN

set +e
report_output=$(
  exec 3>&1
  phase=SIGNER
  authorization_code=AUTH_UNKNOWN
  (exit 78)
  report_error
)
report_status=$?
set -e
[[ "$report_status" == 78 ]] || fail "safe refusal reporter returned $report_status, expected 78"
[[ "$report_output" == 'INSTALL_ONLY_AUTHORIZATION_ERROR phase=SIGNER exit=78 code=AUTH_UNKNOWN' ]] || fail 'safe refusal reporter emitted unexpected output'
! grep -Eq 'malicious|token|nonce|/private/' <<< "$report_output" || fail 'safe refusal reporter leaked raw signer stderr'

printf 'install-only-signer-callsite.test: PASS\n'
