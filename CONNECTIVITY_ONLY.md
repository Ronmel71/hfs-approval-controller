# Connectivity-only native approval

The dedicated manual `connectivity-only-review.yml` workflow records a native
approval for one opaque SHA-256 request. Its only input is a lowercase 64-hex
`request_id`. It runs on `main`, attempt 1, and uses the existing protected
`production-first-start` environment. Environment settings are unchanged.

The workflow has no checkout, secret reference, signing, artifact, API write,
remote command or installation/start path. It validates the input before asking
for native review and emits only `CONNECTIVITY_ONLY_APPROVAL_RECORDED` afterward.
The public request must contain only an opaque binding, never private source,
target information, credentials or raw request payloads.

The private consumer must independently verify the current reviewed source,
exact controller workflow blob and native reviewer/environment identities;
recompute the opaque purpose/source/target/nonce binding; enforce a short expiry;
and serialize consumers while rejecting any prior, failed or cancelled use of
the same approval. A marker or successful controller run alone is not authority.

This approval is separate from existing stage-only, signing, install and start
flows and grants none of those permissions. Opening/merging this code PR does
not dispatch this workflow. Any live dispatch needs separate explicit approval.

Local contract check: `node --test tests/connectivity-only-review.test.mjs`.
