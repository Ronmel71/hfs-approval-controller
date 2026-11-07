# HFS approval controller

This public repository contains only the minimal native-review control plane. It does not contain application source, provider records, private release contents, or signing keys. The dormant install-only material candidate contains only the operational identifiers that its five-file public contract already classifies as nonsecret.

## Dormant install-only activation materials candidate

`install-only-activation-materials.yml` is manual-only and its sole `publish-materials` job is literal-disabled with `if: ${{ false }}`. It cannot publish from this repository state. A future, separately reviewed activation would have to pin the merged controller head, retain the native `production-first-start` review, provision one environment-scoped Ed25519 private key, and provision one fine-grained private-repository token restricted to read-only contents. The token is used only to prove that the requested full 40-hex source is the current private `staging` head and to read the exact policy manifest at that immutable commit. Neither credential is provisioned here.

The candidate derives only the public SPKI PEM in memory and writes exactly five files. It never writes, prints, uploads, or passes private PEM bytes as an argument. The one-hour random nonce is an artifact identifier and single-use approval binding, not an authentication secret: the private consumer additionally requires exact protected controller run/approval provenance, immutable source and controller heads, artifact digest, expiry, and an unconsumed root-owned host state. The host label, WireGuard peer address, public DNS name, and public A record reveal limited topology but no credential, customer record, or access path. Before any later activation, review that classification again. If the nonce or topology is then classified as sensitive, do not enable this public upload; use the already connected private GitHub artifact retrieval path with the same provenance checks instead.

The fixed `database_table_count=44` trust field is schema compatibility only. This install-only candidate performs no production database, DNS, email, host, or provider readback and grants no start authority.

`install-only-authorization.yml` is a code-only candidate. A future, separately approved activation must:

1. merge a reviewed controller commit and pin that exact full commit SHA in the private release manifest;
2. keep `production-first-start` protected by required reviewer `Ronmel71`, self-review allowed, and administrator bypass disabled;
3. provision an environment-scoped Ed25519 signing key and a least-privilege private token limited to Actions read plus delivery to one private issue;
4. provide the private repository, existing readback workflow/ref, expected job name, and delivery issue only as protected environment secrets;
5. dispatch once with the opaque artifact ID produced by the authenticated independent readback job.

The dispatch must declare `purpose=INSTALL_ONLY`, the exact readback artifact ID and nonce, and the canonical request ID. That SHA-256 request ID binds the purpose, reviewed controller head, exact release commit and manifest/bundle/readback digests, immutable readback run/job/artifact identity and digest, and nonce. The signer re-derives it before signing; the private consumer independently re-derives it before accepting.

The job has no checkout and uses no external action. After native approval it fetches its own run and approval records, exhaustively paginates repository-wide `workflow_dispatch` runs, and refuses unless exactly one run has the canonical request/artifact/nonce run name. Incomplete inventory, duplicate runs, reruns, another workflow or branch, a different reviewer, and an old or audit-only request all fail closed. It then fetches the private readback artifact and exact run/job provenance, signs an authorization whose expiry is at most 3,600 seconds after issuance, and delivers that envelope only to the private repository. It never logs the private request or signed envelope.

No key, secret, environment value, dispatch, signature, or authorization is created by this repository state.

## Production first-start signer continuity candidate

`production-first-start-continuity.yml` is a separate code-only candidate. Its production
signing entry point is intentionally fail-closed with
`PROVIDER_ATTESTATION_NOT_AUTHENTICATED`. GitHub run/job/artifact provenance does not
authenticate provider identity, independently observed Supabase/DNS/Resend facts or the
caller-authored private approval fields inside `probe.json`. Synthetic envelope tests can
exercise the schema only through an explicit code-only test flag that the CLI and workflow
cannot set. Consequently this repository state cannot sign BEFORE or AFTER.

The retained candidate structure still binds one native-review-protected attempt-1
controller job, exact private workflow head/job/artifact, one in-memory Ed25519 key,
nonce-linked phases and the 780/900-second timing bounds. Those controls are necessary but
not sufficient for source authentication.

Activation remains separate. It requires an exact merged controller head, independently
pinned public-key SPKI digest, the environment-scoped signing key, one least-privilege
private token limited to Actions read and one issue write, and the protected expected
contract digest. The private BEFORE and AFTER jobs, real provider identities, dispatch,
start, transfer, install, promotion, merge and deploy are not enabled by this candidate.
Before production signing can be reconsidered, a separately reviewed protected reader must
authenticate scoped provider identities and raw Supabase counts, HFS/run-scoped zero-send
Resend evidence, DNS readback and GitHub-native private approval provenance independently
of the uploaded probe. No new proof platform is implied.
