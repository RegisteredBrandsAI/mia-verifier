#!/usr/bin/env python3
"""
MIA Synthetic Validation Harness
draft-anders-merchant-identity-assertions-01

Exercises the enumerated MIDD verification procedure end-to-end with
synthetic data. Scenario: AI procurement agent verifies the legal entity
behind supplier.example.com before releasing payment.

NOTE: Field names are synthetic placeholders. Align to the exact -01
field names before publishing any of this as reference material.
"""

import json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
import rfc8785  # RFC 8785 JSON Canonicalization Scheme

CLOCK_SKEW_TOLERANCE_S = 300  # per -01 clock-skew tolerance

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# ISSUER SIDE — synthetic merchant creates and signs a MIDD
# ---------------------------------------------------------------------------

def issue_midd(domain: str, entity: dict, sk: Ed25519PrivateKey,
               issued_at=None, expires_at=None):
    issued_at = issued_at or now_utc()
    expires_at = expires_at or issued_at + timedelta(days=90)
    pk_raw = sk.public_key().public_bytes_raw()
    midd = {
        "midd_version": "0.1",
        "domain": domain,
        "legal_entity": entity,
        "issued_at": iso(issued_at),
        "expires_at": iso(expires_at),
        "public_key": {"kty": "OKP", "crv": "Ed25519", "x": b64u(pk_raw)},
        "proof": {"type": "Ed25519Signature", "alg": "EdDSA"},
    }
    # Sign RFC 8785 canonical form of the document minus the signature value
    canonical = rfc8785.dumps(midd)
    sig = sk.sign(canonical)
    midd["proof"]["signature"] = b64u(sig)
    return midd

# ---------------------------------------------------------------------------
# VERIFIER SIDE — enumerated MIDD verification procedure
# ---------------------------------------------------------------------------

def verify_midd(midd: dict, *, origin_domain: str, final_url_host: str,
                media_type: str, dns_txt_records: list,
                authorized_entity: dict, at_time=None):
    """Returns (outcome, checks) where checks is the ordered scoring record."""
    t = at_time or now_utc()
    checks = []

    def check(step, name, ok, detail):
        checks.append({"step": step, "check": name,
                       "result": "PASS" if ok else "FAIL", "detail": detail})
        return ok

    # Step 1 — Transport / redirect discipline (CDN cross-origin redirect prohibited)
    ok1 = check(1, "transport_origin_integrity",
                final_url_host.lower() == origin_domain.lower(),
                f"final URL host '{final_url_host}' vs asserted origin '{origin_domain}'")

    # Step 2 — Media type
    ok2 = check(2, "media_type",
                media_type == "application/midd+json",
                f"received '{media_type}'")

    # Step 3 — Well-formed document
    required = {"midd_version", "domain", "legal_entity", "issued_at",
                "expires_at", "public_key", "proof"}
    missing = required - set(midd)
    ok3 = check(3, "document_structure", not missing,
                "all required members present" if not missing else f"missing: {missing}")

    # Step 4 — Domain binding (RFC 5890 / IDNA2008 A-label comparison)
    ok4 = check(4, "domain_binding",
                midd.get("domain", "").lower() == origin_domain.lower(),
                f"MIDD domain '{midd.get('domain')}' vs origin '{origin_domain}'")

    # Step 5 — Temporal validity with clock-skew tolerance
    ia = datetime.strptime(midd["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    ex = datetime.strptime(midd["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    skew = timedelta(seconds=CLOCK_SKEW_TOLERANCE_S)
    ok5 = check(5, "temporal_validity",
                (ia - skew) <= t <= (ex + skew),
                f"eval time {iso(t)} within [{midd['issued_at']}, {midd['expires_at']}] ±{CLOCK_SKEW_TOLERANCE_S}s")

    # Step 6 — DNS TXT key pinning (multi-record handling: any matching record suffices)
    pk_raw = b64u_dec(midd["public_key"]["x"])
    thumbprint = "sha256:" + hashlib.sha256(pk_raw).hexdigest()
    matches = [r for r in dns_txt_records if r.startswith("midd-key=")
               and r.split("=", 1)[1] == thumbprint]
    ok6 = check(6, "dns_txt_key_pinning",
                bool(matches),
                f"{len(dns_txt_records)} TXT record(s) scanned, {len(matches)} match thumbprint {thumbprint[:23]}…")

    # Step 7 — Signature verification over RFC 8785 canonical form
    unsigned = json.loads(json.dumps(midd))
    sig = b64u_dec(unsigned["proof"].pop("signature"))
    canonical = rfc8785.dumps(unsigned)
    try:
        sk_pub = __import__("cryptography.hazmat.primitives.asymmetric.ed25519",
                            fromlist=["Ed25519PublicKey"]).Ed25519PublicKey.from_public_bytes(pk_raw)
        sk_pub.verify(sig, canonical)
        sig_ok = True
    except InvalidSignature:
        sig_ok = False
    ok7 = check(7, "ed25519_signature", sig_ok,
                "signature valid over JCS canonical form" if sig_ok else "signature INVALID — document altered or key mismatch")

    # Step 8 — Legal entity match vs procurement authorization
    le = midd.get("legal_entity", {})
    ok8 = check(8, "entity_authorization_match",
                le.get("name") == authorized_entity.get("name")
                and le.get("registration_id") == authorized_entity.get("registration_id"),
                f"asserted '{le.get('name')}' ({le.get('registration_id')}) vs authorized '{authorized_entity.get('name')}' ({authorized_entity.get('registration_id')})")

    outcome = "VERIFIED" if all(c["result"] == "PASS" for c in checks) else "REJECTED"
    return outcome, checks, canonical, thumbprint

# ---------------------------------------------------------------------------
# ERT — Evidence Receipt Token (audit evidence, signed by the verifying agent)
# ---------------------------------------------------------------------------

def build_ert(outcome, checks, canonical, thumbprint, agent_sk, scenario):
    ert = {
        "ert_version": "0.1",
        "verification_id": str(uuid.uuid4()),
        "timestamp": iso(now_utc()),
        "verifier": "procurement-agent.buyer.example.net",
        "scenario": scenario,
        "target_domain": "supplier.example.com",
        "midd_canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "midd_key_thumbprint": thumbprint,
        "clock_skew_tolerance_s": CLOCK_SKEW_TOLERANCE_S,
        "checks": checks,
        "outcome": outcome,
        "disposition": ("proceed_to_payment_authorization" if outcome == "VERIFIED"
                        else "halt_and_escalate_to_principal"),
    }
    canonical_ert = rfc8785.dumps(ert)
    ert["verifier_signature"] = {
        "alg": "EdDSA",
        "key": b64u(agent_sk.public_key().public_bytes_raw()),
        "signature": b64u(agent_sk.sign(canonical_ert)),
    }
    return ert

# ---------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    merchant_sk = Ed25519PrivateKey.generate()
    agent_sk = Ed25519PrivateKey.generate()

    entity = {"name": "Supplier Manufacturing GmbH",
              "jurisdiction": "AT", "registration_id": "FN 512345a"}
    midd = issue_midd("supplier.example.com", entity, merchant_sk)

    pk_raw = merchant_sk.public_key().public_bytes_raw()
    good_txt = ["v=spf1 include:_spf.example.com ~all",   # unrelated record — multi-record handling
                "midd-key=sha256:" + hashlib.sha256(pk_raw).hexdigest()]
    authorized = dict(entity)

    print("=" * 72)
    print("TEST 1 — HAPPY PATH (valid MIDD, correct origin, authorized entity)")
    outcome, checks, canonical, thumb = verify_midd(
        midd, origin_domain="supplier.example.com",
        final_url_host="supplier.example.com",
        media_type="application/midd+json",
        dns_txt_records=good_txt, authorized_entity=authorized)
    ert = build_ert(outcome, checks, canonical, thumb, agent_sk,
                    "AI procurement agent verifying invoice counterparty prior to payment release")
    for c in checks:
        print(f"  [{c['result']}] step {c['step']} {c['check']}: {c['detail']}")
    print(f"  OUTCOME: {outcome}")

    with open("/home/claude/midd_supplier_example_com.json", "w") as f:
        json.dump(midd, f, indent=2)
    with open("/home/claude/ert_scoring_record.json", "w") as f:
        json.dump(ert, f, indent=2)

    # Negative tests — each must be caught by exactly the intended check
    print("\n" + "=" * 72)
    print("TEST 2 — TAMPERED PAYLOAD (attacker edits legal entity after signing)")
    tampered = json.loads(json.dumps(midd))
    tampered["legal_entity"]["name"] = "Fraudulent Shell LLC"
    tampered["legal_entity"]["registration_id"] = "XX 000000x"
    o, cs, _, _ = verify_midd(tampered, origin_domain="supplier.example.com",
                              final_url_host="supplier.example.com",
                              media_type="application/midd+json",
                              dns_txt_records=good_txt, authorized_entity=authorized)
    fails = [c for c in cs if c["result"] == "FAIL"]
    print(f"  OUTCOME: {o} | failed checks: {[c['check'] for c in fails]}")

    print("\nTEST 3 — DOMAIN SUBSTITUTION (MIDD lifted from lookalike host)")
    o, cs, _, _ = verify_midd(midd, origin_domain="suppl1er.example.com",
                              final_url_host="suppl1er.example.com",
                              media_type="application/midd+json",
                              dns_txt_records=good_txt, authorized_entity=authorized)
    fails = [c for c in cs if c["result"] == "FAIL"]
    print(f"  OUTCOME: {o} | failed checks: {[c['check'] for c in fails]}")

    print("\nTEST 4 — EXPIRED ASSERTION (evaluated 91 days after issuance)")
    o, cs, _, _ = verify_midd(midd, origin_domain="supplier.example.com",
                              final_url_host="supplier.example.com",
                              media_type="application/midd+json",
                              dns_txt_records=good_txt, authorized_entity=authorized,
                              at_time=now_utc() + timedelta(days=91))
    fails = [c for c in cs if c["result"] == "FAIL"]
    print(f"  OUTCOME: {o} | failed checks: {[c['check'] for c in fails]}")

    print("\nTEST 5 — CLOCK SKEW WITHIN TOLERANCE (verifier clock 4 min slow)")
    o, cs, _, _ = verify_midd(midd, origin_domain="supplier.example.com",
                              final_url_host="supplier.example.com",
                              media_type="application/midd+json",
                              dns_txt_records=good_txt, authorized_entity=authorized,
                              at_time=now_utc() - timedelta(seconds=240))
    print(f"  OUTCOME: {o} (temporal check: {[c['result'] for c in cs if c['check']=='temporal_validity'][0]})")

    print("\nTEST 6 — CDN CROSS-ORIGIN REDIRECT (final host is CDN, prohibited)")
    o, cs, _, _ = verify_midd(midd, origin_domain="supplier.example.com",
                              final_url_host="cdn-edge.fastcache.example",
                              media_type="application/midd+json",
                              dns_txt_records=good_txt, authorized_entity=authorized)
    fails = [c for c in cs if c["result"] == "FAIL"]
    print(f"  OUTCOME: {o} | failed checks: {[c['check'] for c in fails]}")

    print("\nTEST 7 — DNS TXT KEY MISMATCH (rotated key not pinned)")
    stale_txt = ["midd-key=sha256:" + "0" * 64]
    o, cs, _, _ = verify_midd(midd, origin_domain="supplier.example.com",
                              final_url_host="supplier.example.com",
                              media_type="application/midd+json",
                              dns_txt_records=stale_txt, authorized_entity=authorized)
    fails = [c for c in cs if c["result"] == "FAIL"]
    print(f"  OUTCOME: {o} | failed checks: {[c['check'] for c in fails]}")

    print("\n" + "=" * 72)
    print("Artifacts written: midd_supplier_example_com.json, ert_scoring_record.json")
