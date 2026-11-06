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

`production-first-start-continuity.yml` is a separate code-only candidate. It keeps one
native-review-protected attempt-1 job alive for both phases. The job authenticates an
exact private workflow head, job and immutable artifact, revalidates the complete
direct-provider probe against a protected expected-contract digest, signs BEFORE, then
waits at most 13 minutes for the nonce-linked AFTER artifact and signs it with the same
in-memory Ed25519 key. It delivers only detached signatures and hashed provenance to the
private issue; evidence and expected values are never written to this public repository,
an artifact, or logs.

Activation remains separate. It requires an exact merged controller head, independently
pinned public-key SPKI digest, the environment-scoped signing key, one least-privilege
private token limited to Actions read and one issue write, and the protected expected
contract digest. The private BEFORE and AFTER jobs, real provider identities, dispatch,
start, transfer, install, promotion, merge and deploy are not enabled by this candidate.
