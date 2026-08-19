# Author: Arif Alsuhaimi
"""SafeDocs pipeline tests.  Run:  python -m pytest -q"""
import io

import nutrient_dws
from fastapi.testclient import TestClient
from pypdf import PdfWriter

from app import signing
from app.config import settings
from app.main import app


def _pdf_bytes():
    w = PdfWriter(); w.add_blank_page(width=300, height=300)
    b = io.BytesIO(); w.write(b); return b.getvalue()


def test_local_end_to_end():
    settings.use_dws = False
    c = TestClient(app)
    sample = open("sample_docs/sample_contract.txt", "rb").read()
    d = c.post("/api/upload", files={"file": ("s.txt", sample, "text/plain")}).json()
    assert d["engine"] == "local-fallback"
    assert len(d["spans"]) >= 5                      # bilingual detection worked
    kinds = {s["kind"] for s in d["spans"]}
    assert {"name", "email", "iban"} <= kinds
    res = c.post("/api/redact", json={"document_id": d["document_id"],
          "decisions": [{"span_id": s["id"], "approved": True} for s in d["spans"]]}).json()
    assert res["redacted_count"] == len(d["spans"])
    proof = c.get(res["proof_url"]).json()
    assert signing.verify(proof) is True             # signature valid
    proof["proof"]["redaction_count"] = 999
    assert signing.verify(proof) is False            # tamper-evident


def test_verify_and_tamper_endpoints():
    settings.use_dws = False
    c = TestClient(app)
    sample = open("sample_docs/sample_contract.txt", "rb").read()
    d = c.post("/api/upload", files={"file": ("s.txt", sample, "text/plain")}).json()
    doc_id = d["document_id"]
    c.post("/api/redact", json={"document_id": doc_id,
          "decisions": [{"span_id": s["id"], "approved": True} for s in d["spans"]]})
    assert c.get(f"/api/verify/{doc_id}").json()["valid"] is True
    c.post(f"/api/verify/{doc_id}/tamper")           # corrupt the stored proof
    assert c.get(f"/api/verify/{doc_id}").json()["valid"] is False


def test_upload_guards():
    settings.use_dws = False
    c = TestClient(app)
    # Unsupported type
    assert c.post("/api/upload", files={"file": ("a.exe", b"x", "application/octet-stream")}).status_code == 415
    # Empty file
    assert c.post("/api/upload", files={"file": ("a.txt", b"", "text/plain")}).status_code == 400


def test_path_traversal_blocked():
    c = TestClient(app)
    # A crafted id must never escape the storage dir.
    assert c.get("/api/download/..%2f..%2fetc%2fpasswd").status_code in (400, 404)
    assert c.get("/api/proof/not_a_valid_id").status_code == 400


def test_bilingual_detection_iban_and_address():
    """Arabic IBAN must be captured in full (not misread as a phone), and the
    Arabic address must be cleaned so DWS can redact it exactly."""
    from app import pii
    text = ("اسم العميل: خالد بن سعيد العتيبي\n"
            "رقم الهوية: 1098234567\n"
            "البريد الإلكتروني: khalid.otaibi@example.com\n"
            "رقم الآيبان: SA0380000000608010167519\n"
            "العنوان: حي النرجس، الرياض  \n")
    by_kind = {}
    for s in pii.detect(text):
        by_kind.setdefault(s.kind, []).append(s.text)
    assert "SA0380000000608010167519" in by_kind.get("iban", [])       # full IBAN
    assert "حي النرجس، الرياض" in by_kind.get("address", [])            # trimmed
    assert "خالد بن سعيد العتيبي" in by_kind.get("name", [])            # name intact
    assert "1098234567" in by_kind.get("national_id", [])              # id intact
    assert "khalid.otaibi@example.com" in by_kind.get("email", [])     # email intact


def test_detect_glued_arabic_labels():
    """PDF text layers often glue an Arabic label to its value with no colon
    (e.g. 'العنوانحي النرجس، الرياض'). Detection must still catch the value —
    the address especially, which has no structural regex fallback."""
    from app import pii
    # Mimics real pypdf extraction: colon before the label, value glued after.
    text = (":اسم العميلخالد بن سعيد العتيبي\n"
            ":رقم الهوية1098234567\n"
            ":رقم الآيبانSA0380000000608010167519\n"
            ":العنوانحي النرجس، الرياض\n")
    by = {}
    for s in pii.detect(text):
        by.setdefault(s.kind, []).append(s.text)
    assert "حي النرجس، الرياض" in by.get("address", [])          # the address is caught
    assert "خالد بن سعيد العتيبي" in by.get("name", [])
    assert "1098234567" in by.get("national_id", [])            # correct badge, not phone
    assert "SA0380000000608010167519" in by.get("iban", [])     # full IBAN incl. SA
    # And it actually redacts out of the document
    assert "حي النرجس، الرياض" not in pii.redact(text, pii.detect(text))


def test_detect_reversed_arabic_labels():
    """Some PDFs (e.g. macOS TextEdit) export Arabic in visual order with the
    label AFTER the value ('القيمة :التسمية'). The address must still be caught
    and redacted — and the label must not swallow the next line's text."""
    from app import pii
    text = ("العتيبي سعيد بن خالد :العميل اسم\n"
            "الرياض النرجس، حي :العنوان\n"
            "Tenant: Sarah Miller\n")
    by = {}
    for s in pii.detect(text):
        by.setdefault(s.kind, []).append(s.text)
    assert "الرياض النرجس، حي" in by.get("address", [])       # reversed address caught
    assert "Tenant: Sarah Miller" not in by.get("address", [])  # no newline bleed
    assert "Sarah Miller" in by.get("name", [])                # English name still fine
    out = pii.redact(text, pii.detect(text))
    assert "الرياض النرجس، حي" not in out                      # address redacted
    assert "العتيبي سعيد بن خالد" not in out                   # arabic name redacted


def test_dws_pipeline_wiring(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, **kw): pass
        async def parse(self, data, mode="structure", output_format="spatial"):
            calls.append("parse")
            return {"output": {"elements": [{"type": "keyValueRegion", "pairs": [
                {"key": {"value": "الاسم"}, "value": {"value": "خالد العتيبي"}, "confidence": 0.91},
                {"key": {"value": "Email"}, "value": {"value": "k@example.com"}, "confidence": 0.99},
            ]}]}}
        async def create_redactions_text(self, pdf, text, redaction_state="stage", **kw):
            calls.append("text:" + text); return {"buffer": b"%PDF-text"}
        async def create_redactions_ai(self, pdf, criteria, redaction_state="stage", **kw):
            calls.append("ai"); return {"buffer": b"%PDF-ai"}
        async def create_redactions_preset(self, pdf, preset, redaction_state="stage", **kw):
            calls.append("preset:" + preset); return {"buffer": b"%PDF-preset"}
        async def apply_redactions(self, pdf):
            calls.append("apply"); return {"buffer": b"%PDF-applied"}
        async def sign(self, pdf, data=None, options=None):
            calls.append("sign:" + data["signatureType"]); return {"buffer": b"%PDF-SIGNED"}
        async def get_account_info(self): return {"credits": 1}

    monkeypatch.setattr(nutrient_dws, "NutrientClient", FakeClient)
    settings.use_dws = True
    settings.dws_api_key = "test"

    c = TestClient(app)
    d = c.post("/api/upload", files={"file": ("c.pdf", _pdf_bytes(), "application/pdf")}).json()
    assert d["engine"] == "dws"
    assert any(s["lang"] == "ar" for s in d["spans"])   # Arabic came through DWS
    res = c.post("/api/redact", json={"document_id": d["document_id"],
          "decisions": [{"span_id": s["id"], "approved": True} for s in d["spans"]]}).json()
    assert res["engine"] == "dws"
    dl = c.get(res["download_url"])
    assert dl.content == b"%PDF-SIGNED"                  # signed PDF returned
    # The full DWS pipeline ran, and human-approved values drove text redactions.
    assert any(x.startswith("text:") for x in calls)    # review-gated redaction
    assert "ai" in calls and "apply" in calls and "sign:cades" in calls
    assert res["dws_operations"]                        # surfaced to the UI

    settings.use_dws = False                             # reset for other tests


def test_dws_honours_human_review(monkeypatch):
    """Deselected items must NOT be staged as text redactions."""
    staged = []

    class FakeClient:
        def __init__(self, **kw): pass
        async def parse(self, data, mode="structure", output_format="spatial"):
            return {"output": {"elements": [{"type": "keyValueRegion", "pairs": [
                {"key": {"value": "الاسم"}, "value": {"value": "خالد العتيبي"}, "confidence": 0.91},
                {"key": {"value": "Email"}, "value": {"value": "keep@example.com"}, "confidence": 0.99},
            ]}]}}
        async def create_redactions_text(self, pdf, text, redaction_state="stage", **kw):
            staged.append(text); return {"buffer": b"x"}
        async def create_redactions_ai(self, pdf, criteria, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def create_redactions_preset(self, pdf, preset, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def apply_redactions(self, pdf): return {"buffer": b"x"}
        async def sign(self, pdf, data=None, options=None): return {"buffer": b"%PDF-S"}
        async def get_account_info(self): return {"credits": 1}

    monkeypatch.setattr(nutrient_dws, "NutrientClient", FakeClient)
    settings.use_dws = True
    settings.dws_api_key = "test"

    c = TestClient(app)
    d = c.post("/api/upload", files={"file": ("c.pdf", _pdf_bytes(), "application/pdf")}).json()
    # Keep the email span, redact everything else.
    decisions = [{"span_id": s["id"], "approved": (s["text"] != "keep@example.com")}
                 for s in d["spans"]]
    c.post("/api/redact", json={"document_id": d["document_id"], "decisions": decisions})
    assert "خالد العتيبي" in staged                     # approved value redacted
    assert "keep@example.com" not in staged             # kept value never staged

    settings.use_dws = False


def test_dws_extract_includes_address_from_pdf_text(monkeypatch):
    """On the DWS path, detection must also run over the PDF's own text layer,
    so the Arabic address/name appear in review even if DWS's extracted text
    presents them differently (or omits them)."""
    class FakeClient:
        def __init__(self, **kw): pass
        async def parse(self, data, mode="structure", output_format="spatial"):
            # DWS text WITHOUT the Arabic address (only English)
            return {"output": {"markdown": "Tenant: Sarah Miller\n"}}
        async def create_redactions_text(self, pdf, text, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def create_redactions_ai(self, pdf, criteria, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def create_redactions_preset(self, pdf, preset, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def apply_redactions(self, pdf): return {"buffer": b"x"}
        async def sign(self, pdf, data=None, options=None): return {"buffer": b"%PDF-S"}
        async def get_account_info(self): return {"credits": 1}

    import asyncio
    from app import dws_client
    monkeypatch.setattr(nutrient_dws, "NutrientClient", FakeClient)
    settings.use_dws = True; settings.dws_api_key = "test"
    # PDF text layer (reversed Arabic, label after value) — what pypdf extracts.
    pdf_text = ("الرياض النرجس، حي :العنوان\n"
                "العتيبي سعيد بن خالد :العميل اسم\nTenant: Sarah Miller\n")
    res = asyncio.get_event_loop().run_until_complete(
        dws_client.extract("doc_x", "f.pdf", pdf_text, raw_bytes=b"%PDF", is_pdf=True))
    kinds = {s.kind: s.text for s in res.spans}
    assert res.engine == "dws"
    assert any(s.kind == "address" for s in res.spans)          # address surfaced
    assert any(s.kind == "name" and s.lang == "ar" for s in res.spans)
    settings.use_dws = False


def test_dws_redacts_multipart_arabic_address(monkeypatch):
    """A comma-separated Arabic address must have each part staged for redaction,
    so it is fully covered even when the whole phrase isn't a single text run."""
    staged = []

    class FakeClient:
        def __init__(self, **kw): pass
        async def parse(self, data, mode="structure", output_format="spatial"):
            return {"output": {"elements": [{"type": "keyValueRegion", "pairs": [
                {"key": {"value": "العنوان"}, "value": {"value": "حي النرجس، الرياض"}, "confidence": 0.8},
            ]}]}}
        async def create_redactions_text(self, pdf, text, redaction_state="stage", **kw):
            staged.append(text); return {"buffer": b"x"}
        async def create_redactions_ai(self, pdf, criteria, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def create_redactions_preset(self, pdf, preset, redaction_state="stage", **kw):
            return {"buffer": b"x"}
        async def apply_redactions(self, pdf): return {"buffer": b"x"}
        async def sign(self, pdf, data=None, options=None): return {"buffer": b"%PDF-S"}
        async def get_account_info(self): return {"credits": 1}

    monkeypatch.setattr(nutrient_dws, "NutrientClient", FakeClient)
    settings.use_dws = True
    settings.dws_api_key = "test"

    c = TestClient(app)
    d = c.post("/api/upload", files={"file": ("c.pdf", _pdf_bytes(), "application/pdf")}).json()
    c.post("/api/redact", json={"document_id": d["document_id"],
          "decisions": [{"span_id": s["id"], "approved": True} for s in d["spans"]]})
    assert "حي النرجس، الرياض" in staged     # full phrase attempted
    assert "حي النرجس" in staged             # and each part, so it's fully covered
    assert "الرياض" in staged

    settings.use_dws = False
