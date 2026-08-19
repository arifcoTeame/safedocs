# Author: Arif Alsuhaimi
"""
Proof-of-redaction: a signed, tamper-evident record of exactly what was
removed and when. This is the "trust" half of the product — it lets a
recipient verify a redacted document was not altered after clearance.

Local fallback signs with an RSA key generated on first run. In production
Nutrient DWS performs the digital signature (see dws_client.sign_document),
which is what the demo should show in production; keep this as the
offline path and for local verification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .models import PiiSpan

_KEY_DIR = Path("keys")
_KEY_PATH = _KEY_DIR / "safedocs_private.pem"


def _load_or_create_key() -> rsa.RSAPrivateKey:
    if _KEY_PATH.exists():
        return serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
    _KEY_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return key


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_proof(document_id: str, original: str, redacted: str,
                spans: list[PiiSpan]) -> dict:
    """Assemble the certificate body (what was removed, hashes, timestamp)."""
    removed = [
        {"kind": s.kind, "lang": s.lang, "confidence": round(s.confidence, 2),
         "length": len(s.text)}
        for s in spans if s.approved
    ]
    return {
        "product": "SafeDocs",
        "document_id": document_id,
        "issued_at": int(time.time()),
        "issued_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "original_sha256": _sha256(original),
        "redacted_sha256": _sha256(redacted),
        "redactions": removed,
        "redaction_count": len(removed),
        # Note: the raw redacted text is never stored in the proof, only hashes.
    }


def sign_proof(proof: dict) -> dict:
    """Return {proof, signature, public_key} — verifiable by any third party."""
    key = _load_or_create_key()
    body = json.dumps(proof, sort_keys=True, ensure_ascii=False).encode("utf-8")
    signature = key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return {
        "proof": proof,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": pub_pem,
    }


def verify(signed: dict) -> bool:
    """Recompute the signature to confirm the proof was not tampered with."""
    try:
        pub = serialization.load_pem_public_key(signed["public_key"].encode("utf-8"))
        body = json.dumps(signed["proof"], sort_keys=True, ensure_ascii=False).encode("utf-8")
        pub.verify(base64.b64decode(signed["signature"]),
                   body, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
