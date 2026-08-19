# Author: Arif Alsuhaimi
"""
Nutrient DWS integration — WIRED AGAINST THE REAL `nutrient-dws` CLIENT (v3.1.0).

DWS does the heavy lifting on three fronts, all via official client methods:
  • parse()                 -> read the document + per-field confidence (review)
  • create_redactions_ai()  -> AI detection & removal of PII (Arabic + English)
  • create_redactions_preset() -> structured identifiers (email, card, phone)
  • apply_redactions()      -> burn the redactions permanently into the PDF
  • sign()                  -> CAdES/PAdES tamper-evident, dated signature

SafeDocs adds the bilingual Arabic layer (pii.py) and the human-review step.

The whole DWS path is guarded: any error falls back to the local engine so a
live demo never breaks. Runs fully offline when USE_DWS=false.

To go live: set USE_DWS=true and DWS_API_KEY (+ optional DWS_EXTRACT_API_KEY).
"""
from __future__ import annotations

import re

from . import pii, signing
from .config import settings
from .models import ExtractResult, PiiSpan

# Natural-language criteria for the AI redactor — explicitly bilingual.
_AI_CRITERIA = (
    "All personally identifiable information in Arabic or English: full names, "
    "national ID or civil-registry numbers, phone and mobile numbers, email "
    "addresses, physical/postal addresses, IBANs and bank account numbers, and "
    "credit/debit card numbers."
)
_PRESETS = ["email-address", "credit-card-number", "international-phone-number"]


def _client():
    """Build the async NutrientClient. Imported lazily so offline users don't
    need the dependency installed."""
    from nutrient_dws import NutrientClient
    kwargs = {"api_key": settings.dws_api_key}
    if settings.dws_extract_api_key:
        kwargs["extract_api_key"] = settings.dws_extract_api_key
    return NutrientClient(**kwargs)


# --- 1) Extraction -----------------------------------------------------------

async def extract(document_id: str, filename: str, text: str,
                  raw_bytes: bytes | None = None, is_pdf: bool = False) -> ExtractResult:
    lang = pii.detect_language(text)

    # Local path: txt uploads, DWS off, or no PDF bytes to send.
    if not settings.use_dws or not is_pdf or not raw_bytes:
        spans = pii.detect(text)
        return ExtractResult(document_id=document_id, filename=filename, lang=lang,
                             char_count=len(text), spans=spans, engine="local-fallback")

    # DWS path: read the PDF with the Data Extraction API for review + confidence.
    try:
        client = _client()
        resp = await client.parse(raw_bytes, mode="understand")
        doc_text, dws_spans = _spans_from_parse(resp)
        # Base the review/redaction spans on the local bilingual detector run
        # over the PDF's own text layer — it has the correct character offsets
        # (needed by the local redactor) and handles reversed / label-after-value
        # Arabic that DWS's extracted text may present differently. Then fold in
        # any extra values DWS surfaced, and the detector's view of DWS text.
        spans = pii.detect(text)
        if doc_text and doc_text != text:
            spans = _merge(spans, pii.detect(doc_text))
        spans = _merge(spans, dws_spans)
        return ExtractResult(document_id=document_id, filename=filename, lang=lang,
                             char_count=len(text), spans=spans, engine="dws")
    except Exception:
        spans = pii.detect(text)
        return ExtractResult(document_id=document_id, filename=filename, lang=lang,
                             char_count=len(text), spans=spans, engine="local-fallback")


def _spans_from_parse(resp: dict):
    """Turn a DWS ParseResponse into (text, spans). Handles both output shapes."""
    output = resp.get("output", {}) if isinstance(resp, dict) else {}
    spans: list[PiiSpan] = []
    text = ""

    # Markdown output -> whole-document string.
    if "markdown" in output:
        text = output.get("markdown", "") or ""

    # Spatial output -> typed elements; pull key/value regions as candidate PII.
    for el in output.get("elements", []) or []:
        if el.get("type") == "keyValueRegion":
            for pair in el.get("pairs", []):
                key = (pair.get("key") or {}).get("value", "")
                val = (pair.get("value") or {}).get("value", "")
                conf = float(pair.get("confidence", 0.6) or 0.6)
                if not val:
                    continue
                text += f"{key}: {val}\n"
                spans.append(PiiSpan(
                    id="dws_" + str(len(spans)),
                    kind=_guess_kind(key), text=str(val),
                    start=0, end=0, confidence=conf, lang=pii._span_lang(str(val)),
                ))
        elif el.get("type") in ("paragraph", "text") and el.get("text"):
            text += el["text"] + "\n"

    return text, spans


def _guess_kind(label: str) -> str:
    l = (label or "").lower()
    if any(k in l for k in ("email", "بريد")): return "email"
    if any(k in l for k in ("phone", "mobile", "هاتف", "جوال")): return "phone"
    if any(k in l for k in ("id", "هوية", "سجل")): return "national_id"
    if any(k in l for k in ("iban", "account", "حساب")): return "iban"
    if any(k in l for k in ("address", "عنوان")): return "address"
    if any(k in l for k in ("name", "اسم", "عميل", "مريض")): return "name"
    return "field"


def _merge(a: list[PiiSpan], b: list[PiiSpan]) -> list[PiiSpan]:
    out = list(a)
    seen = {(s.kind, s.text) for s in a}
    for s in b:
        if (s.kind, s.text) not in seen:
            out.append(s)
            seen.add((s.kind, s.text))
    return out


# --- 2 & 3) Redaction + signature on the real PDF ----------------------------

async def redact_and_sign_pdf(raw_bytes: bytes,
                              approved_spans: list[PiiSpan] | None = None) -> tuple[bytes, list[str]]:
    """DWS-native redaction + signature on the real PDF.

    The redaction honours the HUMAN REVIEW step: every value the reviewer
    approved is staged as an exact-text redaction (`create_redactions_text`) —
    this is what ties the bilingual Arabic layer and the approve/keep decisions
    to what DWS actually burns out of the PDF. AI + preset detection run on top
    as a safety net for anything the reviewer's list missed.

    Pipeline (all on Nutrient DWS):
      create_redactions_text  (per approved value — Arabic + English, human-gated)
      create_redactions_ai    (bilingual criteria — safety net)
      create_redactions_preset(email / card / phone — structured identifiers)
      apply_redactions        (burn them in permanently)
      sign                    (CAdES / PAdES b-lt, visible + dated)

    Returns (signed_pdf_bytes, ops) where `ops` is the ordered list of DWS
    operations performed — surfaced in the UI to show the DWS pipeline.
    Raises on failure so the caller can fall back to the local engine.
    """
    client = _client()
    ops: list[str] = []
    buf = raw_bytes

    # 1) Human-approved exact values → precise, review-gated redactions.
    #    De-duplicate by text so we don't stage the same value twice.
    approved_values: list[str] = []
    seen: set[str] = set()
    for s in (approved_spans or []):
        v = (s.text or "").strip()
        if s.approved and len(v) >= 3 and v not in seen:
            seen.add(v)
            approved_values.append(v)

    for value in approved_values:
        staged = False
        # Stage the whole value plus each comma/dash-separated segment. A phrase
        # like the address «حي النرجس، الرياض» often won't match as one text run
        # (the comma breaks it), but its parts «حي النرجس» and «الرياض» do — so
        # the full value still gets covered.
        for fragment in _redaction_fragments(value):
            try:
                buf = (await client.create_redactions_text(
                    buf, text=fragment, redaction_state="stage"))["buffer"]
                staged = True
            except Exception:
                pass  # one un-matched fragment must not sink the run
        if staged:
            ops.append(f"create_redactions_text «{_preview(value)}»")

    # 2) AI-detected PII (explicitly bilingual criteria) as a safety net.
    try:
        buf = (await client.create_redactions_ai(
            buf, criteria=_AI_CRITERIA, redaction_state="stage"))["buffer"]
        ops.append("create_redactions_ai (Arabic + English)")
    except Exception:
        pass

    # 3) Structured identifiers, belt-and-suspenders.
    for preset in _PRESETS:
        try:
            buf = (await client.create_redactions_preset(
                buf, preset=preset, redaction_state="stage"))["buffer"]
            ops.append(f"create_redactions_preset:{preset}")
        except Exception:
            pass  # a missing preset must not sink the whole run

    # 4) Burn everything in permanently.
    buf = (await client.apply_redactions(buf))["buffer"]
    ops.append("apply_redactions")

    # 5) Apply a dated, tamper-evident, *visible* CAdES signature.
    sign_data = {
        "signatureType": "cades",
        "cadesLevel": "b-lt",
        "flatten": True,
        "appearance": {"mode": "signatureAndDescription"},
    }
    try:
        signed = (await client.sign(buf, data=sign_data))["buffer"]
    except Exception:
        # Some tenants reject the appearance block — retry with a plain signature.
        sign_data.pop("appearance", None)
        signed = (await client.sign(buf, data=sign_data))["buffer"]
    ops.append("sign (CAdES b-lt)")
    return signed, ops


def _preview(value: str, n: int = 14) -> str:
    value = value.replace("\n", " ").strip()
    return value if len(value) <= n else value[:n] + "…"


def _redaction_fragments(value: str) -> list[str]:
    """The full value first, then each comma/semicolon/dash-separated part —
    so a multi-part phrase whose whole form doesn't match a single PDF text run
    (e.g. an address split by a comma) still gets each part redacted."""
    fragments = [value]
    for part in re.split(r"[،؛;,\-–—]", value):
        part = part.strip()
        if len(part) >= 3 and part not in fragments:
            fragments.append(part)
    return fragments


# --- Local text fallbacks (unchanged behaviour) ------------------------------

def redact_text(text: str, spans: list[PiiSpan]) -> str:
    return pii.redact(text, spans)


def sign_proof(document_id: str, original: str, redacted: str,
               spans: list[PiiSpan]) -> dict:
    return signing.sign_proof(signing.build_proof(document_id, original, redacted, spans))


async def account_info() -> dict | None:
    """Live credit/usage readout for the health endpoint (DWS on)."""
    if not settings.use_dws:
        return None
    try:
        info = await _client().get_account_info()
        return info if isinstance(info, dict) else dict(info)
    except Exception:
        return None
