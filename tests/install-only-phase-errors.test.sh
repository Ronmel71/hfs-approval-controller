#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/install-only-authorization.yml

fail() {
  printf 'install-only-phase-errors.test: %s\n' "$1" >&2
  exit 1
}

grep -Fq 'trap report_error ERR' "$workflow" || fail 'ERR trap missing'
grep -Fq "printf 'INSTALL_ONLY_AUTHORIZATION_ERROR phase=%s exit=%d\\n'" "$workflow" || fail 'stable error marker missing'
grep -Fq "printf 'INSTALL_ONLY_AUTHORIZATION_ERROR phase=%s exit=%d code=%s\\n'" "$workflow" || fail 'stable signer refusal marker missing'
grep -Fq 'exec 3>&2' "$workflow" || fail 'protected diagnostic descriptor missing'
grep -Fq 'quiet_capture private_run_id jq' "$workflow" || fail 'single-report capture wrapper missing'
! grep -Fq 'set -x' "$workflow" || fail 'shell tracing is forbidden'

expected_phases='ARTIFACT_META ARTIFACT_ZIP INVENTORY ISSUE_DELIVERY NATIVE_APPROVAL PREFLIGHT REQUEST_PROVENANCE SIGNER SOURCE_PIN ZIP_MEMBERS'
actual_phases=$(sed -n 's/^[[:space:]]*phase=\([A-Z_]*\)$/\1/p' "$workflow" | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//')
[[ "$actual_phases" == "$expected_phases" ]] || fail "phase allowlist drift: $actual_phases"

run_failure() {
  name=$1
  expected_phase=$2
  expected_exit=$3
  failure=$4
  output_file=$(mktemp)
  marker_file=$(mktemp)
  mock_dir=$(mktemp -d)

  if [[ "$failure" != shellguard ]]; then
    cat > "$mock_dir/$failure" <<EOF
#!/usr/bin/env bash
printf 'leaked-$failure-secret' >&2
exit $expected_exit
EOF
    chmod 0700 "$mock_dir/$failure"
  fi

  set +e
  PATH="$mock_dir:$PATH" TEST_PHASE="$expected_phase" TEST_FAILURE="$failure" TEST_MARKER_FILE="$marker_file" \
    bash -Eeuo pipefail -c '
      set +x
      exec 3>&2
      phase=PREFLIGHT
      report_error() {
        local status=$?
        trap - ERR
        printf "INSTALL_ONLY_AUTHORIZATION_ERROR phase=%s exit=%d\\n" "$phase" "$status" >&3
        exit "$status"
      }
      trap report_error ERR
      phase=$TEST_PHASE
      case "$TEST_FAILURE" in
        curl) curl --fail --silent --show-error https://invalid.example ;;
        jq) jq -e . /private/request.json ;;
        unzip) unzip -Z1 /private/readback.zip ;;
        node) node /private/signer.mjs sign ;;
        shellguard) [[ forbidden == allowed ]] ;;
        *) exit 99 ;;
      esac 2>/dev/null
      printf SIGNER_CALLED >> "$TEST_MARKER_FILE"
      printf ISSUE_WRITE_CALLED >> "$TEST_MARKER_FILE"
    ' >"$output_file" 2>&1
  status=$?
  set -e

  [[ "$status" == "$expected_exit" ]] || fail "$name returned $status, expected $expected_exit"
  [[ "$(cat "$output_file")" == "INSTALL_ONLY_AUTHORIZATION_ERROR phase=$expected_phase exit=$expected_exit" ]] || fail "$name emitted unexpected diagnostics"
  [[ ! -s "$marker_file" ]] || fail "$name passed signing or issue write after failure"
  ! grep -Eq 'leaked-|secret|token|nonce|https?://|/[^ ]+' "$output_file" || fail "$name leaked sensitive diagnostics"
  rm -f -- "$output_file" "$marker_file" "$mock_dir/$failure" 2>/dev/null || true
  rmdir -- "$mock_dir"
}

run_failure curl SOURCE_PIN 22 curl
run_failure jq-exit-4 ARTIFACT_META 4 jq
run_failure unzip ZIP_MEMBERS 9 unzip
run_failure node SIGNER 7 node
run_failure shellguard PREFLIGHT 1 shellguard

printf 'install-only-phase-errors.test: PASS\n'
