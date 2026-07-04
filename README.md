# mia-verifier

Reference verifier for **draft-anders-merchant-identity-assertions-01**
(Merchant Identity Assertions for Autonomous Commerce).

- Draft: https://datatracker.ietf.org/doc/draft-anders-merchant-identity-assertions/
- Status: tracks revision -01 (2026-07-04). Field names and procedure steps
  follow the draft text; where the draft changes, this code will follow.

## What this is

A Python implementation of the MIA verification procedure — proof envelope
checks (MerchantIdentityProof-v1 / Ed25519), RFC 8785 (JCS) canonical signing
input, key-directory (JWKS) resolution with verificationMethod authority
matching, strict exclusive temporal validity, subject/domain binding, and
third-party issuance authorization (delegation document + DNS TXT) — plus a
synthetic adversarial test campaign that exercises it.

## Run it

    pip install -r requirements.txt
    python verifier.py

The campaign issues MIAs for a synthetic merchant population (self-issued and
third-party-issued), then runs 12,000 mixed transactions across twelve attack
classes: post-signing tampering, signature corruption, attacker-hosted key
directories, cross-domain replay, expired / not-yet-valid / exact-boundary
timestamps, unauthorized third-party issuance, redirect responses, wrong
content types, and structural fuzzing. Expected result: zero false accepts,
zero false rejects. The run is seeded and reproducible.

## Evidence

- `evidence/validation_report.json` — campaign results (12,000 cases, clean)
- `evidence/cross_language_interop.json` — an MIA issued by an independent
  TypeScript implementation whose signature this verifier validates:
  two languages, one wire format.

## Scope and caveats

This is a reference/testing implementation, not a production library. It
simulates transport (retrieval, redirects, DNS) in-process; a production
verifier must perform real HTTPS retrieval per the draft (no redirects,
size limits, Content-Type enforcement). Independent implementations and
interop reports are welcome — open an issue.

## License

MIT.
