#!/usr/bin/env python3
"""
MIA Reference Verifier v2 — aligned to draft-anders-merchant-identity-assertions-01
Implements the actual Section "Verification Procedure" steps with the real
field names (camelCase), proof envelope (MerchantIdentityProof-v1),
verificationMethod authority matching, JWKS key directory lookup, strict
exclusive temporal bounds, and third-party issuer authorization via
_mia-auth DNS TXT + mia-delegation.json.
"""

import json, hashlib, random, string, copy, time
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import rfc8785

random.seed(126)  # Vienna

def b64u(b): 
    import base64; return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64u_dec(s):
    import base64; return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def now(): return datetime.now(timezone.utc)
def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
def parse(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

RECOGNIZED_ALGS = {"Ed25519"}
PROOF_TYPE = "MerchantIdentityProof-v1"
MEDIA_TYPE = "application/merchant-identity+json"

# --------------------------------------------------------------------------
# Simulated network: domain -> resources
# --------------------------------------------------------------------------
class Net:
    def __init__(self):
        self.wellknown = {}      # domain -> (media_type, mia_doc, redirect_to_or_None)
        self.jwks = {}           # url -> jwks dict
        self.dns_txt = {}        # name -> [txt strings]
        self.delegation = {}     # domain -> midd delegation doc

    def fetch_mia(self, domain):
        mt, doc, redirect = self.wellknown[domain]
        return mt, doc, redirect

NET = Net()

# --------------------------------------------------------------------------
# Issuance (self-issued and third-party) per draft
# --------------------------------------------------------------------------
def issue_mia(subject, legal, issuer_domain, issuer_sk, kid, issued=None, expires=None):
    issued = issued or now() - timedelta(days=1)
    expires = expires or issued + timedelta(days=365)
    key_dir = f"https://{issuer_domain}/.well-known/jwks.json"
    claims = {
        "version": 1,
        "subject": subject,
        "legalName": legal["legalName"],
        "entityType": legal["entityType"],
        "jurisdiction": legal["jurisdiction"],
        "registrationId": legal["registrationId"],
        "issuedAt": iso(issued),
        "expiresAt": iso(expires),
        "issuer": {"name": f"Issuer for {issuer_domain}", "domain": issuer_domain,
                   "keyDirectory": key_dir},
    }
    canonical = rfc8785.dumps(claims)  # JCS per RFC 8785 (draft signing step 2)
    sig = issuer_sk.sign(canonical)
    mia = dict(claims)
    mia["proof"] = {
        "type": PROOF_TYPE, "alg": "Ed25519", "created": iso(issued),
        "verificationMethod": f"{key_dir}#{kid}",
        "proofValue": b64u(sig),
    }
    return mia

def publish_jwk(issuer_domain, kid, sk):
    url = f"https://{issuer_domain}/.well-known/jwks.json"
    jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid,
           "x": b64u(sk.public_key().public_bytes_raw())}
    NET.jwks.setdefault(url, {"keys": []})["keys"].append(jwk)

def authorize_third_party(subject, issuer_domain, subject_sk, subject_kid):
    """Draft: _mia-auth TXT + signed delegation doc at subject's mia-delegation.json"""
    NET.dns_txt[f"_mia-auth.{subject}"] = [f"v=mia1; issuer={issuer_domain}"]
    claims = {"version": 1, "subject": subject, "authorizedIssuer": issuer_domain,
              "issuedAt": iso(now() - timedelta(days=1)),
              "expiresAt": iso(now() + timedelta(days=365))}
    sig = subject_sk.sign(rfc8785.dumps(claims))
    doc = dict(claims)
    doc["proof"] = {"type": PROOF_TYPE, "alg": "Ed25519", "created": claims["issuedAt"],
                    "verificationMethod": f"https://{subject}/.well-known/jwks.json#{subject_kid}",
                    "proofValue": b64u(sig)}
    NET.delegation[subject] = doc

# --------------------------------------------------------------------------
# Verifier — the draft's enumerated procedure
# --------------------------------------------------------------------------
def domains_equal(a, b):
    return a.lower().rstrip(".") == b.lower().rstrip(".") and not a.endswith(".") and not b.endswith(".")
    # NOTE: draft Domain Comparison (RFC 5890) — strict A-label compare;
    # trailing-dot handling per draft text (reject non-identical forms).

def domains_equal_strict(a, b):
    return a.lower() == b.lower()

def verify_sig_with_jwks(doc, jwks_url_expected_authority=None):
    proof = doc.get("proof")
    vm = proof["verificationMethod"]
    key_dir, _, kid = vm.rpartition("#")
    authority = key_dir.split("://", 1)[1].split("/", 1)[0]
    if jwks_url_expected_authority is not None and not domains_equal_strict(authority, jwks_url_expected_authority):
        return False, "verificationMethod authority mismatch"
    jwks = NET.jwks.get(key_dir)
    if not jwks:
        return False, "key directory unavailable"
    jwk = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
    if jwk is None:
        return False, "kid not found"
    unsigned = copy.deepcopy(doc); unsigned.pop("proof")
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
        pk.verify(b64u_dec(proof["proofValue"]), rfc8785.dumps(unsigned))
        return True, "ok"
    except (InvalidSignature, Exception) as e:
        return False, f"signature invalid ({type(e).__name__})"

def verify_mia(target_domain, at_time=None):
    """Full procedure. Returns (valid, step_record)."""
    t = at_time or now()
    steps = []
    def step(n, name, ok, detail=""):
        steps.append({"step": n, "name": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        return ok
    try:
        # 1. Retrieve via HTTPS; MUST NOT follow redirects
        if target_domain not in NET.wellknown:
            step(1, "retrieve", False, "no MIA available"); return False, steps
        mt, doc, redirect = NET.fetch_mia(target_domain)
        if redirect:
            step(1, "retrieve", False, "redirected response = retrieval failure"); return False, steps
        step(1, "retrieve", True)
        # 2. Content-Type
        if not step(2, "content_type", mt == MEDIA_TYPE, mt): return False, steps
        # 3. Parse; proof present
        doc = json.loads(json.dumps(doc))
        if not step(3, "proof_present", isinstance(doc, dict) and "proof" in doc): return False, steps
        proof = doc["proof"]
        # 4. proof.type and alg recognized
        if not step(4, "proof_type_alg",
                    proof.get("type") == PROOF_TYPE and proof.get("alg") in RECOGNIZED_ALGS,
                    f"type={proof.get('type')} alg={proof.get('alg')}"): return False, steps
        # 5-8. verificationMethod split, authority==issuer.domain, JWKS fetch, kid, canonical, sig
        ok, why = verify_sig_with_jwks(doc, jwks_url_expected_authority=doc.get("issuer", {}).get("domain", ""))
        if not step(5, "key_resolution_and_signature", ok, why): return False, steps
        # 10. strictly between issuedAt and expiresAt (exclusive)
        ia, ex = parse(doc["issuedAt"]), parse(doc["expiresAt"])
        if not step(6, "temporal_strict_exclusive", ia < t < ex,
                    f"{iso(t)} in ({doc['issuedAt']}, {doc['expiresAt']})"): return False, steps
        # 11. subject matches target domain
        if not step(7, "subject_binding", domains_equal_strict(doc["subject"], target_domain),
                    f"subject={doc['subject']} target={target_domain}"): return False, steps
        # 12. third-party authorization if issuer.domain != subject
        if not domains_equal_strict(doc["issuer"]["domain"], doc["subject"]):
            txt = NET.dns_txt.get(f"_mia-auth.{doc['subject']}", [])
            txt_ok = any(f"issuer={doc['issuer']['domain']}" in r and r.startswith("v=mia1") for r in txt)
            deleg = NET.delegation.get(doc["subject"])
            deleg_ok = False
            if deleg and deleg.get("authorizedIssuer") == doc["issuer"]["domain"]:
                dok, _ = verify_sig_with_jwks(deleg, jwks_url_expected_authority=doc["subject"])
                deleg_ok = dok and parse(deleg["issuedAt"]) < t < parse(deleg["expiresAt"])
            if not step(8, "third_party_authorization", txt_ok and deleg_ok,
                        f"txt={txt_ok} delegation={deleg_ok}"): return False, steps
        else:
            step(8, "third_party_authorization", True, "self-issued, not required")
        return True, steps
    except Exception as e:
        steps.append({"step": "?", "name": "exception", "result": "FAIL", "detail": type(e).__name__})
        return False, steps

# --------------------------------------------------------------------------
# Campaign
# --------------------------------------------------------------------------
POP = 1000
merchants = []
issuer3p_sk = Ed25519PrivateKey.generate()
ISSUER3P = "trust.example.org"
publish_jwk(ISSUER3P, "key-01", issuer3p_sk)

for i in range(POP):
    sk = Ed25519PrivateKey.generate()
    d = "".join(random.choices(string.ascii_lowercase, k=8)) + ".example.com"
    legal = {"legalName": f"Vendor {i:04d} Corp", "entityType": "corporation",
             "jurisdiction": "US", "registrationId": f"{i:02d}-{random.randint(1000000,9999999)}"}
    kid = f"key-{i:04d}"
    publish_jwk(d, kid, sk)
    third = random.random() < 0.4
    if third:
        authorize_third_party(d, ISSUER3P, sk, kid)
        mia = issue_mia(d, legal, ISSUER3P, issuer3p_sk, "key-01")
    else:
        mia = issue_mia(d, legal, d, sk, kid)
    NET.wellknown[d] = (MEDIA_TYPE, mia, None)
    merchants.append({"domain": d, "sk": sk, "kid": kid, "mia": mia, "third": third})

TX = 12000
counts = {}
fa = fr = 0
t0 = time.time()
for _ in range(TX):
    m = random.choice(merchants)
    r = random.random()
    if r < 0.60:
        kind, expect = "legit", True
        valid, _ = verify_mia(m["domain"])
    else:
        kind = random.choice(["attacker_jwks_key_substitution", "unknown_proof_type",
                              "unrecognized_alg", "tampered_claims", "not_yet_valid",
                              "expired", "subject_mismatch", "redirect", "wrong_content_type",
                              "unauthorized_third_party", "kid_missing", "issuedAt_boundary_exact"])
        expect = False
        save = NET.wellknown[m["domain"]]
        doc = copy.deepcopy(m["mia"])
        at = None
        if kind == "attacker_jwks_key_substitution":
            # attacker hosts own JWKS and points verificationMethod there
            ask = Ed25519PrivateKey.generate()
            publish_jwk("evil.example.net", "key-ev", ask)
            unsigned = copy.deepcopy(doc); unsigned.pop("proof")
            unsigned["legalName"] = "Evil Corp"
            sig = ask.sign(rfc8785.dumps(unsigned))
            doc = unsigned
            doc["proof"] = {"type": PROOF_TYPE, "alg": "Ed25519", "created": iso(now()),
                            "verificationMethod": "https://evil.example.net/.well-known/jwks.json#key-ev",
                            "proofValue": b64u(sig)}
        elif kind == "unknown_proof_type":
            doc["proof"]["type"] = "DataIntegrityProof"
        elif kind == "unrecognized_alg":
            doc["proof"]["alg"] = "secp256k1"
        elif kind == "tampered_claims":
            doc["legalName"] = "Hijacked LLC"
        elif kind == "not_yet_valid":
            at = parse(doc["issuedAt"]) - timedelta(hours=1)
        elif kind == "expired":
            at = parse(doc["expiresAt"]) + timedelta(seconds=1)
        elif kind == "issuedAt_boundary_exact":
            at = parse(doc["issuedAt"])  # exclusive bound: exactly issuedAt is invalid
        elif kind == "subject_mismatch":
            other_m = random.choice([x for x in merchants if x["domain"] != m["domain"]])
            other = other_m["domain"]
            other_save = NET.wellknown[other]
            NET.wellknown[other] = (MEDIA_TYPE, doc, None)
            valid, _ = verify_mia(other)
            NET.wellknown[other] = other_save
            counts.setdefault(kind, [0, 0])
            counts[kind][0] += 1; counts[kind][1] += int(valid != expect)
            fa += int(valid)
            continue
        elif kind == "redirect":
            NET.wellknown[m["domain"]] = (MEDIA_TYPE, doc, "https://cdn.example/cached")
        elif kind == "wrong_content_type":
            NET.wellknown[m["domain"]] = ("application/json", doc, None)
        elif kind == "unauthorized_third_party":
            # third-party MIA for a subject that never delegated
            victim = random.choice([x for x in merchants if not x["third"]])
            doc = issue_mia(victim["domain"], {"legalName": "Fake", "entityType": "corporation",
                            "jurisdiction": "US", "registrationId": "00-0000000"},
                            ISSUER3P, issuer3p_sk, "key-01")
            NET.wellknown[victim["domain"]] = (MEDIA_TYPE, doc, None)
            valid, _ = verify_mia(victim["domain"])
            NET.wellknown[victim["domain"]] = (MEDIA_TYPE, victim["mia"], None)
            counts.setdefault(kind, [0, 0])
            counts[kind][0] += 1; counts[kind][1] += int(valid != expect)
            fa += int(valid)
            continue
        elif kind == "kid_missing":
            doc["proof"]["verificationMethod"] = doc["proof"]["verificationMethod"].rsplit("#", 1)[0] + "#ghost"
        if kind in ("redirect", "wrong_content_type"):
            valid, _ = verify_mia(m["domain"], at_time=at)
            NET.wellknown[m["domain"]] = save
        else:
            NET.wellknown[m["domain"]] = (MEDIA_TYPE, doc, None)
            valid, _ = verify_mia(m["domain"], at_time=at)
            NET.wellknown[m["domain"]] = save
    counts.setdefault(kind, [0, 0])
    counts[kind][0] += 1
    wrong = valid != expect
    counts[kind][1] += int(wrong)
    if wrong and valid: fa += 1
    if wrong and not valid: fr += 1
elapsed = time.time() - t0

report = {
    "suite": "MIA v2 draft-aligned validation (field names + procedure per -01)",
    "population": POP, "third_party_issued_fraction": 0.4,
    "transactions": TX, "throughput_per_sec": round(TX / elapsed),
    "false_accepts": fa, "false_rejects": fr,
    "per_kind": {k: {"n": v[0], "deviations": v[1]} for k, v in sorted(counts.items())},
    "verdict": "CLEAN" if fa == 0 and fr == 0 else "DEVIATIONS",
}
print(json.dumps(report, indent=2))
with open("/home/claude/mia_v2_report.json", "w") as f:
    json.dump(report, f, indent=2)
