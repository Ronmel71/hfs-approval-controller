# Current status

## 2026-11-06 — issue #266 dormant install-only material source

- Branch `feat/issue-266-install-only-materials` adds one manual-only controller workflow whose sole publisher remains literal-disabled with `if: ${{ false }}`.
- The candidate can only generate the five declared nonsecret v3 material files. It requires exact protected controller review provenance, attempt 1, the current reviewed controller `main` head, an authenticated exact private `staging` head and policy manifest, and an environment-scoped Ed25519 key. Missing or drifting inputs fail closed.
- The Ed25519 private key remains in memory and is never written, logged, placed in an API argument, or included in output. No key, secret, variable, permission, environment, or reviewer was created or changed.
- Public-artifact exposure is explicitly bounded and documented in `README.md`. The nonce is short-lived and one-use but not treated as secret; if that classification changes, the public uploader must remain disabled and the existing private artifact handoff must be used.
- Static and synthetic tests cover missing key, private SHA mismatch, trust/public-key mismatch, exact sudoers drift, expiry bounds, nonce format, controller-head drift, missing/extra/private material, reviewer/attempt mismatch, SHA-pinned Actions, and the literal-disabled guard.
- No workflow was dispatched, no artifact was uploaded or downloaded, and no private repository, host, provider, install, start, merge, or deployment state was changed. Work/Codex usage: 0 calls.

### Next gate

Review and merge the single controller PR as a code-only change. Even after merge, publication remains disabled. Any later activation requires a separate SHA-specific review and provisioning decision; the private consumer must remain unpinned until the real controller workflow ID is known and separately reviewed.
