# HFS approval controller

This public repository contains only the minimal native-review control plane. It does not contain application source, host details, provider data, private release contents, or signing keys.

`install-only-authorization.yml` is a code-only candidate. A future, separately approved activation must:

1. merge a reviewed controller commit and pin that exact full commit SHA in the private release manifest;
2. keep `production-first-start` protected by required reviewer `Ronmel71`, self-review allowed, and administrator bypass disabled;
3. provision an environment-scoped Ed25519 signing key and a least-privilege private token limited to Actions read plus delivery to one private issue;
4. provide the private repository, existing readback workflow/ref, expected job name, and delivery issue only as protected environment secrets;
5. dispatch once with the opaque artifact ID produced by the authenticated independent readback job.

The job has no checkout and uses no external action. After native approval it fetches its own run and approval records, fetches the private readback artifact and exact run/job provenance, signs a 60-minute authorization envelope, and delivers that envelope only to the private repository. It never logs the private request or signed envelope.

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
