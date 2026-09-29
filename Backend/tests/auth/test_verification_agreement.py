"""
Phase 10.2a — the verification rules, moved into
``ccure_platform.identity.verification`` with keys and configuration injected.

Three things are pinned here:

1. **The golden table.** For every case in a 156-token corpus (all five kinds ×
   valid, expired, future ``nbf``/``iat``, wrong issuer/audience, unknown and
   foreign ``kid``, wrong principal type, every missing claim, legacy HS256 in
   four shapes, plus ``alg:none``, ES384/RS256/HS256 under an ES256 ``kid``,
   refused headers and eight malformed shapes) and 21 service assertions, the
   outcome ``tokens`` gives — accepted, or the reason code it logs — with legacy
   HS256 off and on. The table was recorded from the Phase 9 implementation
   *before* the move (5,362 evaluations, zero differences afterwards), so it is
   the pre-move behaviour, quirks included: an ``iat`` in the future is accepted
   (python-jose does not check it; ``nbf`` is the claim that is), and an
   any-kind decode of a service token fails on the user audience.

2. **Agreement with a public-only key source.** The gateway's token check
   (Phase 10) will hold no private key, no JWT secret and no ``.env``: it will
   verify against keys built from the published JWKS. Every case is verified
   both through ``tokens`` and through ``verification`` with a key source built
   only from ``KeySet.jwks()``; the decisions must be identical.

3. **The boundary.** ``verification`` imports only the standard library and
   python-jose, reads no configuration or environment, and importing it loads
   no application module; only ``tokens`` imports it.
"""

from __future__ import annotations

import ast
import base64
import json
import logging
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import jwt

from ccure_platform.identity import keys as keymod
from ccure_platform.identity import tokens, verification
from config import JWTConfig
from scripts.architecture.import_graph import discover_modules
from testpaths import BACKEND_ROOT

KINDS = ["access", "refresh", "ticket", "mfa_challenge", "service_access"]
_REASON = re.compile(r"reason=(\w+)")


# ── the corpus ────────────────────────────────────────────────────────────────


def _pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _raw(header, payload, sig=b"sig") -> str:
    return f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}.{_b64(sig)}"


_DROP = object()


class Corpus:
    """Throwaway keys, a throwaway legacy secret, and the tokens built on them."""

    def __init__(self):
        self.ka, self.kr, self.kn = (
            ec.generate_private_key(ec.SECP256R1()) for _ in range(3)
        )
        self.foreign = ec.generate_private_key(ec.SECP256R1())
        self.p384 = ec.generate_private_key(ec.SECP384R1())
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.svc = ec.generate_private_key(ec.SECP256R1())
        self.legacy = secrets.token_hex(32)
        self.legacy_other = secrets.token_hex(32)
        self.keyset = keymod.KeySet(
            keys=(
                keymod.SigningKey(
                    kid="kid-A", state="active", alg="ES256", private_key=self.ka
                ),
                keymod.SigningKey(
                    kid="kid-R", state="retired", alg="ES256", private_key=self.kr
                ),
                keymod.SigningKey(
                    kid="kid-N", state="next", alg="ES256", private_key=self.kn
                ),
            )
        )
        self.now = datetime.now(timezone.utc)
        self.tokens = self._tokens()
        self.assertions = self._assertions()

    def t(self, seconds: int) -> int:
        return int((self.now + timedelta(seconds=seconds)).timestamp())

    def _es(self, claims, kid="kid-A", key=None, alg="ES256", headers=None):
        header = {"kid": kid} if kid is not None else {}
        header.update(headers or {})
        return jwt.encode(claims, _pem(key or self.ka), algorithm=alg, headers=header)

    def _base(self, kind, **over):
        svc = kind == "service_access"
        claims = {
            "iss": tokens.ISSUER,
            "aud": tokens.CORE_SERVICE_AUDIENCE if svc else tokens.USER_AUDIENCE,
            "sub": "svc:alpha" if svc else "usr_t1",
            "type": kind,
            "ptype": "service" if svc else "user",
            "jti": f"jti-{kind}",
            "iat": self.t(-10),
            "nbf": self.t(-10),
            "exp": self.t(3600),
        }
        if svc:
            claims.update(scope="a b", tenant="org_t1")
        for key, value in over.items():
            if value is _DROP:
                claims.pop(key, None)
            else:
                claims[key] = value
        return claims

    def _tokens(self) -> dict[str, str]:
        c, t, base, es = {}, self.t, self._base, self._es
        for k in KINDS:
            c[f"{k}/valid"] = es(base(k))
            c[f"{k}/valid_retired_key"] = es(base(k), kid="kid-R", key=self.kr)
            c[f"{k}/valid_next_key"] = es(base(k), kid="kid-N", key=self.kn)
            c[f"{k}/aud_list"] = es(base(k, aud=[base(k)["aud"], "urn:other"]))
            c[f"{k}/expired"] = es(base(k, iat=t(-7200), nbf=t(-7200), exp=t(-3600)))
            c[f"{k}/future_nbf"] = es(base(k, nbf=t(3000)))
            c[f"{k}/future_iat"] = es(base(k, iat=t(3000)))
            c[f"{k}/wrong_issuer"] = es(base(k, iss="https://evil.example"))
            c[f"{k}/wrong_audience"] = es(base(k, aud="urn:evil"))
            c[f"{k}/unknown_kid"] = es(base(k), kid="kid-UNKNOWN")
            c[f"{k}/wrong_key_same_kid"] = es(base(k), key=self.foreign)
            c[f"{k}/wrong_ptype"] = es(
                base(k, ptype="user" if k == "service_access" else "service")
            )
            c[f"{k}/bad_ptype_value"] = es(base(k, ptype="robot"))
            for claim in (
                "jti",
                "nbf",
                "iat",
                "sub",
                "ptype",
                "type",
                "iss",
                "aud",
                "exp",
            ):
                c[f"{k}/missing_{claim}"] = es(base(k, **{claim: _DROP}))
            c[f"{k}/legacy_hs256"] = jwt.encode(
                {"sub": "usr_t1", "type": k, "iat": t(-10), "exp": t(3600)},
                self.legacy,
                algorithm="HS256",
            )
            c[f"{k}/legacy_hs256_expired"] = jwt.encode(
                {"sub": "usr_t1", "type": k, "iat": t(-7200), "exp": t(-3600)},
                self.legacy,
                algorithm="HS256",
            )
            c[f"{k}/legacy_hs256_other_secret"] = jwt.encode(
                {"sub": "usr_t1", "type": k, "exp": t(3600)},
                self.legacy_other,
                algorithm="HS256",
            )
            c[f"{k}/legacy_hs256_with_iss_aud"] = jwt.encode(
                base(k), self.legacy, algorithm="HS256"
            )
        g = "global/"
        c[g + "legacy_no_type"] = jwt.encode(
            {"sub": "usr_t1", "exp": t(3600)}, self.legacy, algorithm="HS256"
        )
        c[g + "hs256_with_kid"] = jwt.encode(
            base("access"), self.legacy, algorithm="HS256", headers={"kid": "kid-A"}
        )
        c[g + "hs256_lowercase_alg"] = _raw(
            {"alg": "hs256", "typ": "JWT"}, base("access")
        )
        c[g + "es384_kid_A"] = jwt.encode(
            base("access"), _pem(self.p384), algorithm="ES384", headers={"kid": "kid-A"}
        )
        c[g + "rs256_kid_A"] = jwt.encode(
            base("access"), _pem(self.rsa), algorithm="RS256", headers={"kid": "kid-A"}
        )
        c[g + "alg_none_kid"] = _raw(
            {"alg": "none", "kid": "kid-A"}, base("access"), b""
        )
        c[g + "alg_none_no_kid"] = _raw({"alg": "none"}, base("access"), b"")
        c[g + "es256_no_kid"] = es(base("access"), kid=None)
        c[g + "kid_int"] = _raw({"alg": "ES256", "kid": 123}, base("access"))
        c[g + "kid_empty"] = es(base("access"), kid="")
        for h in ("jku", "x5u", "jwk", "x5c", "crit"):
            c[g + f"refused_header_{h}"] = es(
                base("access"), headers={h: "x" if h != "crit" else ["exp"]}
            )
        c[g + "empty"] = ""
        c[g + "garbage"] = "not-a-token"
        c[g + "two_segments"] = "a.b"
        c[g + "three_garbage_segments"] = "a.b.c"
        valid = c["access/valid"]
        head, body, sig = valid.split(".")
        c[g + "truncated_signature"] = valid[:-20]
        c[g + "truncated_payload"] = valid[: len(valid) // 2]
        c[g + "header_not_json"] = f"{_b64(b'{not json')}.{body}.{sig}"
        c[g + "header_json_list"] = f"{_b64(b'[]')}.{body}.{sig}"
        c[g + "payload_list"] = f"{head}.{_b64(b'[1,2]')}.{sig}"
        tampered = json.loads(base64.urlsafe_b64decode(body + "=="))
        tampered["sub"] = "usr_other"
        c[g + "tampered_payload"] = (
            f"{head}.{_b64(json.dumps(tampered).encode())}.{sig}"
        )
        c[g + "signature_swapped"] = f"{head}.{body}.{c['refresh/valid'].split('.')[2]}"
        return c

    # service assertions (RFC 7523)
    def key_for(self, service_id, kid):
        return (
            _PublicKey("ES256", self.svc.public_key())
            if (service_id, kid) == ("alpha", "svc-k1")
            else None
        )

    def _assertion(self, **over):
        claims = {
            "iss": "alpha",
            "sub": "alpha",
            "aud": tokens.SERVICE_ASSERTION_AUDIENCE,
            "jti": "as-1",
            "iat": self.t(-5),
            "exp": self.t(40),
        }
        header, alg, key = {"kid": "svc-k1"}, "ES256", self.svc
        for k, v in over.items():
            if k == "_hdr":
                header.update(v)
            elif k == "_alg":
                alg = v
            elif k == "_key":
                key = v
            elif v is _DROP:
                claims.pop(k, None)
            else:
                claims[k] = v
        if header.get("kid") is _DROP:
            header.pop("kid")
        secret = self.legacy if alg == "HS256" else _pem(key)
        return jwt.encode(claims, secret, algorithm=alg, headers=header)

    def _assertions(self) -> dict[str, str]:
        a, t = self._assertion, self.t
        kid_header = _b64(json.dumps({"alg": "ES256", "kid": "svc-k1"}).encode())
        return {
            "valid": a(),
            "alg_hs256": a(_alg="HS256"),
            "alg_es384": a(_alg="ES384", _key=self.p384),
            "missing_kid": a(_hdr={"kid": _DROP}),
            "missing_iss": a(iss=_DROP),
            "iss_not_string": a(iss=7),
            "unknown_kid": a(_hdr={"kid": "svc-kX"}),
            "other_service": a(iss="beta", sub="beta"),
            "wrong_aud": a(aud="urn:evil"),
            "sub_mismatch": a(sub="beta"),
            "iat_future": a(iat=t(30), exp=t(60)),
            "lifetime_too_long": a(iat=t(-5), exp=t(120)),
            "expired": a(iat=t(-100), exp=t(-50)),
            "missing_jti": a(jti=_DROP),
            "empty_jti": a(jti=""),
            "jti_not_string": a(jti=5),
            "iat_string": _raw(
                {"alg": "ES256", "kid": "svc-k1"},
                {
                    "iss": "alpha",
                    "sub": "alpha",
                    "aud": tokens.SERVICE_ASSERTION_AUDIENCE,
                    "jti": "j",
                    "iat": "x",
                    "exp": t(40),
                },
            ),
            "refused_header_jku": a(_hdr={"jku": "https://x"}),
            "wrong_key": a(_key=self.foreign),
            "garbage": "garbage",
            "claims_list": f"{kid_header}.{_b64(b'[1]')}.x",
        }


class _PublicKey:
    """A verification key holding a public key only."""

    def __init__(self, alg, public_key):
        self.alg = alg
        self.public_pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


class _JwksSource:
    """What the gateway's check will hold: keys rebuilt from the published JWKS."""

    def __init__(self, jwks: dict):
        self._keys = {}
        for jwk in jwks["keys"]:
            assert not keymod.PRIVATE_JWK_MEMBERS & set(
                jwk
            ), "a private member was published"
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
                int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"),
                ec.SECP256R1(),
            )
            self._keys[jwk["kid"]] = _PublicKey(jwk["alg"], numbers.public_key())

    def verification_key(self, kid):
        return self._keys.get(kid)


@pytest.fixture(scope="module")
def corpus():
    return Corpus()


@pytest.fixture
def platform(corpus, monkeypatch):
    """``tokens`` configured with the corpus keyset and legacy secret."""
    monkeypatch.setattr(tokens, "_keyset", corpus.keyset)
    monkeypatch.setattr(tokens, "SECRET_KEY", corpus.legacy)
    return corpus


def _natural(case: str) -> tuple[str, str]:
    kind = case.split("/")[0]
    kind = kind if kind in KINDS else "access"
    audience = (
        tokens.CORE_SERVICE_AUDIENCE
        if kind == "service_access"
        else tokens.USER_AUDIENCE
    )
    return kind, audience


def _through_tokens(fn, caplog, *args, **kwargs) -> str:
    caplog.clear()
    result = fn(*args, **kwargs)
    if result is not None:
        return "OK"
    reasons = [
        _REASON.search(r.getMessage())
        for r in caplog.records
        if r.name == "ccure.tokens"
    ]
    reasons = [m.group(1) for m in reasons if m]
    assert len(reasons) <= 1, reasons
    return reasons[0] if reasons else "NONE"


def _through_verification(outcome) -> str:
    if isinstance(outcome, verification.Refusal):
        return outcome.reason
    return "OK" if outcome is not None else "NONE"


# ── 1. the golden table (recorded from the Phase 9 implementation) ────────────

# case: (verify legacy-off, verify legacy-on, any-kind legacy-off, any-kind legacy-on)
GOLDEN = {
    "access/aud_list": ("OK", "OK", "OK", "OK"),
    "access/bad_ptype_value": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
    ),
    "access/expired": ("expired", "expired", "expired", "expired"),
    "access/future_iat": ("OK", "OK", "OK", "OK"),
    "access/future_nbf": (
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
    ),
    "access/legacy_hs256": ("legacy_disabled", "OK", "legacy_disabled", "OK"),
    "access/legacy_hs256_expired": (
        "legacy_disabled",
        "expired",
        "legacy_disabled",
        "expired",
    ),
    "access/legacy_hs256_other_secret": (
        "legacy_disabled",
        "bad_signature",
        "legacy_disabled",
        "bad_signature",
    ),
    "access/legacy_hs256_with_iss_aud": (
        "legacy_disabled",
        "wrong_audience",
        "legacy_disabled",
        "wrong_audience",
    ),
    "access/missing_aud": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_exp": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_iat": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_iss": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_jti": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_nbf": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_ptype": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_sub": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/missing_type": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "access/unknown_kid": ("unknown_kid", "unknown_kid", "unknown_kid", "unknown_kid"),
    "access/valid": ("OK", "OK", "OK", "OK"),
    "access/valid_next_key": ("OK", "OK", "OK", "OK"),
    "access/valid_retired_key": ("OK", "OK", "OK", "OK"),
    "access/wrong_audience": (
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
    ),
    "access/wrong_issuer": (
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
    ),
    "access/wrong_key_same_kid": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "access/wrong_ptype": ("wrong_ptype", "wrong_ptype", "wrong_ptype", "wrong_ptype"),
    "global/alg_none_kid": (
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
    ),
    "global/alg_none_no_kid": (
        "missing_kid",
        "missing_kid",
        "missing_kid",
        "missing_kid",
    ),
    "global/empty": ("malformed", "malformed", "malformed", "malformed"),
    "global/es256_no_kid": ("missing_kid", "missing_kid", "missing_kid", "missing_kid"),
    "global/es384_kid_A": (
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
    ),
    "global/garbage": ("malformed", "malformed", "malformed", "malformed"),
    "global/header_json_list": ("malformed", "malformed", "malformed", "malformed"),
    "global/header_not_json": ("malformed", "malformed", "malformed", "malformed"),
    "global/hs256_lowercase_alg": (
        "missing_kid",
        "missing_kid",
        "missing_kid",
        "missing_kid",
    ),
    "global/hs256_with_kid": (
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
    ),
    "global/kid_empty": ("missing_kid", "missing_kid", "missing_kid", "missing_kid"),
    "global/kid_int": ("missing_kid", "missing_kid", "missing_kid", "missing_kid"),
    "global/legacy_no_type": ("legacy_disabled", "wrong_kind", "legacy_disabled", "OK"),
    "global/payload_list": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "global/refused_header_crit": (
        "refused_header",
        "refused_header",
        "refused_header",
        "refused_header",
    ),
    "global/refused_header_jku": (
        "refused_header",
        "refused_header",
        "refused_header",
        "refused_header",
    ),
    "global/refused_header_jwk": (
        "refused_header",
        "refused_header",
        "refused_header",
        "refused_header",
    ),
    "global/refused_header_x5c": (
        "refused_header",
        "refused_header",
        "refused_header",
        "refused_header",
    ),
    "global/refused_header_x5u": (
        "refused_header",
        "refused_header",
        "refused_header",
        "refused_header",
    ),
    "global/rs256_kid_A": (
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
        "alg_mismatch",
    ),
    "global/signature_swapped": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "global/tampered_payload": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "global/three_garbage_segments": (
        "malformed",
        "malformed",
        "malformed",
        "malformed",
    ),
    "global/truncated_payload": ("malformed", "malformed", "malformed", "malformed"),
    "global/truncated_signature": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "global/two_segments": ("malformed", "malformed", "malformed", "malformed"),
    "mfa_challenge/aud_list": ("OK", "OK", "OK", "OK"),
    "mfa_challenge/bad_ptype_value": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
    ),
    "mfa_challenge/expired": ("expired", "expired", "expired", "expired"),
    "mfa_challenge/future_iat": ("OK", "OK", "OK", "OK"),
    "mfa_challenge/future_nbf": (
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
    ),
    "mfa_challenge/legacy_hs256": ("legacy_disabled", "OK", "legacy_disabled", "OK"),
    "mfa_challenge/legacy_hs256_expired": (
        "legacy_disabled",
        "expired",
        "legacy_disabled",
        "expired",
    ),
    "mfa_challenge/legacy_hs256_other_secret": (
        "legacy_disabled",
        "bad_signature",
        "legacy_disabled",
        "bad_signature",
    ),
    "mfa_challenge/legacy_hs256_with_iss_aud": (
        "legacy_disabled",
        "wrong_audience",
        "legacy_disabled",
        "wrong_audience",
    ),
    "mfa_challenge/missing_aud": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_exp": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_iat": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_iss": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_jti": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_nbf": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_ptype": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_sub": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/missing_type": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "mfa_challenge/unknown_kid": (
        "unknown_kid",
        "unknown_kid",
        "unknown_kid",
        "unknown_kid",
    ),
    "mfa_challenge/valid": ("OK", "OK", "OK", "OK"),
    "mfa_challenge/valid_next_key": ("OK", "OK", "OK", "OK"),
    "mfa_challenge/valid_retired_key": ("OK", "OK", "OK", "OK"),
    "mfa_challenge/wrong_audience": (
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
    ),
    "mfa_challenge/wrong_issuer": (
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
    ),
    "mfa_challenge/wrong_key_same_kid": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "mfa_challenge/wrong_ptype": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
    ),
    "refresh/aud_list": ("OK", "OK", "OK", "OK"),
    "refresh/bad_ptype_value": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
    ),
    "refresh/expired": ("expired", "expired", "expired", "expired"),
    "refresh/future_iat": ("OK", "OK", "OK", "OK"),
    "refresh/future_nbf": (
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
    ),
    "refresh/legacy_hs256": ("legacy_disabled", "OK", "legacy_disabled", "OK"),
    "refresh/legacy_hs256_expired": (
        "legacy_disabled",
        "expired",
        "legacy_disabled",
        "expired",
    ),
    "refresh/legacy_hs256_other_secret": (
        "legacy_disabled",
        "bad_signature",
        "legacy_disabled",
        "bad_signature",
    ),
    "refresh/legacy_hs256_with_iss_aud": (
        "legacy_disabled",
        "wrong_audience",
        "legacy_disabled",
        "wrong_audience",
    ),
    "refresh/missing_aud": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_exp": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_iat": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_iss": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_jti": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_nbf": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_ptype": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_sub": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/missing_type": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "refresh/unknown_kid": ("unknown_kid", "unknown_kid", "unknown_kid", "unknown_kid"),
    "refresh/valid": ("OK", "OK", "OK", "OK"),
    "refresh/valid_next_key": ("OK", "OK", "OK", "OK"),
    "refresh/valid_retired_key": ("OK", "OK", "OK", "OK"),
    "refresh/wrong_audience": (
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
    ),
    "refresh/wrong_issuer": (
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
    ),
    "refresh/wrong_key_same_kid": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "refresh/wrong_ptype": ("wrong_ptype", "wrong_ptype", "wrong_ptype", "wrong_ptype"),
    "service_access/aud_list": ("OK", "OK", "wrong_audience", "wrong_audience"),
    "service_access/bad_ptype_value": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/expired": ("expired", "expired", "expired", "expired"),
    "service_access/future_iat": ("OK", "OK", "wrong_audience", "wrong_audience"),
    "service_access/future_nbf": (
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
    ),
    "service_access/legacy_hs256": (
        "legacy_disabled",
        "legacy_service",
        "legacy_disabled",
        "OK",
    ),
    "service_access/legacy_hs256_expired": (
        "legacy_disabled",
        "expired",
        "legacy_disabled",
        "expired",
    ),
    "service_access/legacy_hs256_other_secret": (
        "legacy_disabled",
        "bad_signature",
        "legacy_disabled",
        "bad_signature",
    ),
    "service_access/legacy_hs256_with_iss_aud": (
        "legacy_disabled",
        "wrong_audience",
        "legacy_disabled",
        "wrong_audience",
    ),
    "service_access/missing_aud": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_exp": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_iat": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_iss": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_jti": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_nbf": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_ptype": (
        "missing_claim",
        "missing_claim",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/missing_sub": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "service_access/missing_type": (
        "missing_claim",
        "missing_claim",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/unknown_kid": (
        "unknown_kid",
        "unknown_kid",
        "unknown_kid",
        "unknown_kid",
    ),
    "service_access/valid": ("OK", "OK", "wrong_audience", "wrong_audience"),
    "service_access/valid_next_key": ("OK", "OK", "wrong_audience", "wrong_audience"),
    "service_access/valid_retired_key": (
        "OK",
        "OK",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/wrong_audience": (
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/wrong_issuer": (
        "wrong_issuer",
        "wrong_issuer",
        "wrong_audience",
        "wrong_audience",
    ),
    "service_access/wrong_key_same_kid": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "service_access/wrong_ptype": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_audience",
        "wrong_audience",
    ),
    "ticket/aud_list": ("OK", "OK", "OK", "OK"),
    "ticket/bad_ptype_value": (
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
        "wrong_ptype",
    ),
    "ticket/expired": ("expired", "expired", "expired", "expired"),
    "ticket/future_iat": ("OK", "OK", "OK", "OK"),
    "ticket/future_nbf": (
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
        "not_yet_valid",
    ),
    "ticket/legacy_hs256": ("legacy_disabled", "OK", "legacy_disabled", "OK"),
    "ticket/legacy_hs256_expired": (
        "legacy_disabled",
        "expired",
        "legacy_disabled",
        "expired",
    ),
    "ticket/legacy_hs256_other_secret": (
        "legacy_disabled",
        "bad_signature",
        "legacy_disabled",
        "bad_signature",
    ),
    "ticket/legacy_hs256_with_iss_aud": (
        "legacy_disabled",
        "wrong_audience",
        "legacy_disabled",
        "wrong_audience",
    ),
    "ticket/missing_aud": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_exp": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_iat": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_iss": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_jti": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_nbf": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_ptype": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_sub": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/missing_type": (
        "missing_claim",
        "missing_claim",
        "missing_claim",
        "missing_claim",
    ),
    "ticket/unknown_kid": ("unknown_kid", "unknown_kid", "unknown_kid", "unknown_kid"),
    "ticket/valid": ("OK", "OK", "OK", "OK"),
    "ticket/valid_next_key": ("OK", "OK", "OK", "OK"),
    "ticket/valid_retired_key": ("OK", "OK", "OK", "OK"),
    "ticket/wrong_audience": (
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
        "wrong_audience",
    ),
    "ticket/wrong_issuer": (
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
        "wrong_issuer",
    ),
    "ticket/wrong_key_same_kid": (
        "bad_signature",
        "bad_signature",
        "bad_signature",
        "bad_signature",
    ),
    "ticket/wrong_ptype": ("wrong_ptype", "wrong_ptype", "wrong_ptype", "wrong_ptype"),
}
GOLDEN_ASSERTIONS = {
    "alg_es384": "alg_mismatch",
    "alg_hs256": "alg_mismatch",
    "claims_list": "malformed",
    "empty_jti": "missing_claim",
    "expired": "expired",
    "garbage": "malformed",
    "iat_future": "not_yet_valid",
    "iat_string": "bad_signature",
    "iss_not_string": "missing_claim",
    "jti_not_string": "invalid_claims",
    "lifetime_too_long": "lifetime_too_long",
    "missing_iss": "missing_claim",
    "missing_jti": "missing_claim",
    "missing_kid": "missing_kid",
    "other_service": "unknown_service_key",
    "refused_header_jku": "refused_header",
    "sub_mismatch": "subject_mismatch",
    "unknown_kid": "unknown_service_key",
    "valid": "OK",
    "wrong_aud": "wrong_audience",
    "wrong_key": "bad_signature",
}


@pytest.mark.parametrize("legacy_on", [False, True], ids=["legacy-off", "legacy-on"])
def test_tokens_matches_the_recorded_phase9_outcomes(
    platform, caplog, monkeypatch, legacy_on
):
    monkeypatch.setattr(JWTConfig, "ACCEPT_LEGACY_HS256", legacy_on)
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert set(platform.tokens) == set(
        GOLDEN
    ), "the corpus and the golden table disagree"
    wrong = []
    for case, token in platform.tokens.items():
        kind, audience = _natural(case)
        got_verify = _through_tokens(
            tokens.verify,
            caplog,
            token,
            expected_kind=kind,
            issuer=tokens.ISSUER,
            audience=audience,
        )
        got_any = _through_tokens(tokens.decode_any_kind, caplog, token)
        want = GOLDEN[case]
        expected = (want[1], want[3]) if legacy_on else (want[0], want[2])
        if (got_verify, got_any) != expected:
            wrong.append(f"{case}: got {(got_verify, got_any)}, recorded {expected}")
    assert not wrong, "\n".join(wrong)


def test_service_assertions_match_the_recorded_phase9_outcomes(platform, caplog):
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert set(platform.assertions) == set(GOLDEN_ASSERTIONS)
    wrong = []
    for case, assertion in platform.assertions.items():
        got = _through_tokens(
            tokens.verify_service_assertion, caplog, assertion, key_for=platform.key_for
        )
        if got != GOLDEN_ASSERTIONS[case]:
            wrong.append(f"{case}: got {got}, recorded {GOLDEN_ASSERTIONS[case]}")
    assert not wrong, "\n".join(wrong)


def test_an_unknown_kind_still_raises(platform):
    with pytest.raises(ValueError, match="unknown token kind 'bogus'"):
        tokens.verify(
            "x",
            expected_kind="bogus",
            issuer=tokens.ISSUER,
            audience=tokens.USER_AUDIENCE,
        )
    with pytest.raises(ValueError, match="unknown token kind 'bogus'"):
        verification.verify(
            "x",
            expected_kind="bogus",
            issuer=tokens.ISSUER,
            audience=tokens.USER_AUDIENCE,
            keyset=lambda: None,
            legacy=None,
        )


def test_no_keyset_is_refused_as_before(platform, caplog, monkeypatch):
    monkeypatch.setattr(tokens, "_keyset", None)
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    got = _through_tokens(
        tokens.verify,
        caplog,
        platform.tokens["access/valid"],
        expected_kind="access",
        issuer=tokens.ISSUER,
        audience=tokens.USER_AUDIENCE,
    )
    assert got == "no_keyset"


# ── 2. agreement with a public-only (JWKS) key source ────────────────────────


@pytest.mark.parametrize("legacy_on", [False, True], ids=["legacy-off", "legacy-on"])
def test_a_jwks_only_verifier_decides_exactly_as_the_platform(
    platform, caplog, monkeypatch, legacy_on
):
    """Every token × every expected kind × every audience, both paths."""
    monkeypatch.setattr(JWTConfig, "ACCEPT_LEGACY_HS256", legacy_on)
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    source = _JwksSource(platform.keyset.jwks())
    legacy = verification.LegacyHS256(platform.legacy) if legacy_on else None
    audiences = (
        tokens.USER_AUDIENCE,
        tokens.CORE_SERVICE_AUDIENCE,
        tokens.IR_SERVICE_AUDIENCE,
    )
    wrong, compared = [], 0
    for case, token in platform.tokens.items():
        for kind in KINDS:
            for audience in audiences:
                app = _through_tokens(
                    tokens.verify,
                    caplog,
                    token,
                    expected_kind=kind,
                    issuer=tokens.ISSUER,
                    audience=audience,
                )
                gw = _through_verification(
                    verification.verify(
                        token,
                        expected_kind=kind,
                        issuer=tokens.ISSUER,
                        audience=audience,
                        keyset=lambda: source,
                        legacy=legacy,
                    )
                )
                compared += 1
                if app != gw:
                    wrong.append(
                        f"{case} as {kind} for {audience}: platform {app}, jwks-only {gw}"
                    )
    assert compared == len(platform.tokens) * len(KINDS) * len(audiences)
    assert not wrong, "\n".join(wrong[:20])


def test_the_jwks_only_verifier_never_accepts_legacy_hs256(platform):
    source = _JwksSource(platform.keyset.jwks())
    for case, token in platform.tokens.items():
        if "legacy_hs256" in case or case == "global/legacy_no_type":
            kind, audience = _natural(case)
            outcome = verification.verify(
                token,
                expected_kind=kind,
                issuer=tokens.ISSUER,
                audience=audience,
                keyset=lambda: source,
                legacy=None,
            )
            assert isinstance(outcome, verification.Refusal), case
            assert outcome.reason == "legacy_disabled", (case, outcome.reason)


def test_tokens_reexports_the_rules_rather_than_redefining_them():
    for name in (
        "ACCESS",
        "REFRESH",
        "TICKET",
        "MFA_CHALLENGE",
        "SERVICE_ACCESS",
        "USER_KINDS",
        "KINDS",
        "KIND_PTYPE",
        "PTYPE_USER",
        "PTYPE_SERVICE",
        "REQUIRED_ASYMMETRIC_CLAIMS",
        "SERVICE_ASSERTION_MAX_LIFETIME",
    ):
        assert getattr(tokens, name) is getattr(verification, name), name
    assert tokens._REFUSED_HEADERS is verification.REFUSED_HEADERS
    assert tokens.ALGORITHM == verification.LEGACY_ALGORITHM == "HS256"
    assert (
        tokens._SERVICE_ASSERTION_ALGORITHM
        == verification.SERVICE_ASSERTION_ALGORITHM
        == "ES256"
    )


# ── 3. the boundary ──────────────────────────────────────────────────────────

VERIFICATION_PATH = BACKEND_ROOT / "ccure_platform" / "identity" / "verification.py"
#: Everything verification.py may import. The standard library and python-jose.
_ALLOWED_IMPORTS = {"__future__", "dataclasses", "datetime", "typing", "jose"}
#: Names whose use would mean reading configuration, secrets or state. Modules
#: (config, keys, db, …) are excluded by the import test above instead.
_FORBIDDEN_NAMES = {
    "os",
    "environ",
    "getenv",
    "load_dotenv",
    "open",
    "JWTConfig",
    "SessionLocal",
    "SECRET_KEY",
    "TOKEN_KEYS_DIR",
    "MFA_ENCRYPTION_KEY",
}


def _top_level_imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module.split(".")[0]


def test_verification_imports_only_the_stdlib_and_jose():
    tree = ast.parse(VERIFICATION_PATH.read_text(encoding="utf-8"))
    imported = set(_top_level_imports(tree))
    assert imported <= _ALLOWED_IMPORTS, sorted(imported - _ALLOWED_IMPORTS)
    assert "jose" in imported


def test_verification_reads_no_configuration_environment_or_files():
    tree = ast.parse(VERIFICATION_PATH.read_text(encoding="utf-8"))
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not used & _FORBIDDEN_NAMES, sorted(used & _FORBIDDEN_NAMES)


def test_importing_verification_loads_no_application_module():
    """What the gateway's check will do: import the rules and nothing else."""
    probe = (
        "import sys; import ccure_platform.identity.verification\n"
        "roots = {'config','dotenv','db','sqlalchemy','redis','celery','fastapi','main',"
        "'core','routers','auth','scans','engines'}\n"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in roots or m in ("
        "'ccure_platform.identity.keys','ccure_platform.identity.tokens',"
        "'ccure_platform.identity.jwt_handler'))\n"
        "print(','.join(bad))\n"
    )
    env = {**os.environ, "PYTHONPATH": str(BACKEND_ROOT)}
    out = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert (
        out.stdout.strip() == ""
    ), f"importing verification loaded: {out.stdout.strip()}"


def test_only_the_token_module_imports_verification():
    importers = set()
    for module, path in discover_modules().items():
        if module == "ccure_platform.identity.verification":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "ccure_platform.identity.verification" or (
                    node.module == "ccure_platform.identity"
                    and any(a.name == "verification" for a in node.names)
                ):
                    importers.add(module)
            elif isinstance(node, ast.Import):
                if any(
                    a.name == "ccure_platform.identity.verification" for a in node.names
                ):
                    importers.add(module)
    assert importers == {"ccure_platform.identity.tokens"}, sorted(importers)


def test_no_second_verifier_decodes_tokens():
    """jwt.decode is called in verification only; tokens signs and delegates."""
    callers = []
    for module, path in discover_modules().items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "decode"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "jwt"
            ):
                callers.append(module)
    assert set(callers) == {"ccure_platform.identity.verification"}, sorted(
        set(callers)
    )
