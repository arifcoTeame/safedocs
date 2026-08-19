# Author: Arif Alsuhaimi
"""SafeDocs API — upload -> extract -> human review -> redact -> sign."""
from __future__ import annotations

import io
import json
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import dws_client, signing
from .config import settings
from .models import ExtractResult, RedactRequest, RedactResult, VerifyResult

app = FastAPI(title="SafeDocs", version="1.0.0")

STORAGE = Path(settings.storage_dir)
STORAGE.mkdir(exist_ok=True)
STATIC = Path(__file__).resolve().parent.parent / "static"

# Upload guards.
MAX_UPLOAD_BYTES = 15 * 1024 * 1024          # 15 MB — plenty for a demo document
ALLOWED_EXT = (".pdf", ".txt")
# Server-generated ids look like "doc_<10 hex>"; reject anything else so a
# crafted id can never escape the storage directory (path-traversal guard).
_DOC_ID_RE = re.compile(r"^doc_[0-9a-f]{10}$")

# In-memory session store — fine for this demo. Swap for Redis/DB later.
_DOCS: dict[str, dict] = {}
# Last DWS error (if any) — surfaced by /api/health for quick debugging.
_LAST_DWS_ERROR: dict[str, str] = {}


def _safe_doc_id(document_id: str) -> str:
    """Validate a document id before using it to build a filesystem path."""
    if not _DOC_ID_RE.match(document_id):
        raise HTTPException(400, "Invalid document id.")
    return document_id


def _read_text(filename: str, data: bytes) -> str:
    if filename.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            return "\n".join((page.extract_text() or "") for page in reader.pages)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"Could not read PDF: {exc}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


@app.middleware("http")
async def _no_cache_frontend(request, call_next):
    """Tell the browser to always revalidate the SPA + its assets, so an edited
    app.js/style.css is never served stale from cache during the demo."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.post("/api/upload", response_model=ExtractResult)
async def upload(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (max {MAX_UPLOAD_BYTES // (1024*1024)} MB).")
    filename = file.filename or "document.txt"
    if not filename.lower().endswith(ALLOWED_EXT):
        raise HTTPException(415, "Unsupported file type. Upload a PDF or TXT.")
    is_pdf = filename.lower().endswith(".pdf")
    text = _read_text(filename, data)
    document_id = "doc_" + uuid.uuid4().hex[:10]

    result = await dws_client.extract(document_id, filename, text,
                                      raw_bytes=data, is_pdf=is_pdf)
    _DOCS[document_id] = {
        "text": text, "raw": data, "is_pdf": is_pdf,
        "spans": {s.id: s for s in result.spans},
    }
    return result


@app.post("/api/redact", response_model=RedactResult)
async def redact(req: RedactRequest):
    doc = _DOCS.get(req.document_id)
    if not doc:
        raise HTTPException(404, "Unknown document_id (session expired?).")

    decisions = {d.span_id: d.approved for d in req.decisions}
    spans = list(doc["spans"].values())
    for s in spans:
        if s.id in decisions:
            s.approved = decisions[s.id]
    approved = [s for s in spans if s.approved]
    original = doc["text"]

    # --- DWS-native path: redact + sign the real PDF ------------------------
    if settings.use_dws and doc["is_pdf"]:
        try:
            signed_pdf, dws_ops = await dws_client.redact_and_sign_pdf(
                doc["raw"], approved_spans=approved)
            (STORAGE / f"{req.document_id}.signed.pdf").write_bytes(signed_pdf)
            # A companion proof (hashes + what-was-removed) for the certificate view.
            proof = dws_client.sign_proof(req.document_id, original,
                                          "[redacted by Nutrient DWS]", spans)
            proof["proof"]["dws_operations"] = dws_ops
            (STORAGE / f"{req.document_id}.proof.json").write_text(
                json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
            preview = ("✔ Redacted and CAdES-signed by Nutrient DWS.\n\n"
                       "DWS pipeline:\n" + "\n".join(f"  • {op}" for op in dws_ops) +
                       "\n\nDownload the signed PDF below.")
            return RedactResult(
                document_id=req.document_id, redacted_count=len(approved),
                redacted_preview=preview,
                proof_id=req.document_id, signature_valid=True,
                download_url=f"/api/download/{req.document_id}",
                proof_url=f"/api/proof/{req.document_id}", engine="dws",
                dws_operations=dws_ops)
        except Exception as exc:  # noqa: BLE001
            # Never break the demo — fall back, but record why for the health view.
            _LAST_DWS_ERROR["msg"] = f"{type(exc).__name__}: {exc}"
            print(f"[SafeDocs] DWS path failed, using local fallback: {exc}")

    # --- Local text path ----------------------------------------------------
    redacted = dws_client.redact_text(original, spans)
    signed = dws_client.sign_proof(req.document_id, original, redacted, spans)
    (STORAGE / f"{req.document_id}.redacted.txt").write_text(redacted, encoding="utf-8")
    (STORAGE / f"{req.document_id}.proof.json").write_text(
        json.dumps(signed, ensure_ascii=False, indent=2), encoding="utf-8")

    return RedactResult(
        document_id=req.document_id, redacted_count=len(approved),
        redacted_preview=redacted[:1200], proof_id=signed["proof"]["document_id"],
        signature_valid=True, download_url=f"/api/download/{req.document_id}",
        proof_url=f"/api/proof/{req.document_id}", engine="local-fallback")


@app.get("/api/download/{document_id}")
async def download(document_id: str):
    document_id = _safe_doc_id(document_id)
    pdf = STORAGE / f"{document_id}.signed.pdf"
    if pdf.exists():
        return FileResponse(pdf, media_type="application/pdf",
                            filename=f"{document_id}.signed.pdf")
    txt = STORAGE / f"{document_id}.redacted.txt"
    if txt.exists():
        return FileResponse(txt, media_type="text/plain",
                            filename=f"{document_id}.redacted.txt")
    raise HTTPException(404, "Not found.")


@app.get("/api/proof/{document_id}")
async def proof(document_id: str):
    document_id = _safe_doc_id(document_id)
    path = STORAGE / f"{document_id}.proof.json"
    if not path.exists():
        raise HTTPException(404, "Not found.")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.get("/api/verify/{document_id}", response_model=VerifyResult)
async def verify(document_id: str):
    """Re-verify the stored proof's signature — the tamper-evidence story.
    Any change to the proof body since signing makes this return valid=False."""
    document_id = _safe_doc_id(document_id)
    path = STORAGE / f"{document_id}.proof.json"
    if not path.exists():
        raise HTTPException(404, "Not found.")
    signed = json.loads(path.read_text(encoding="utf-8"))
    ok = signing.verify(signed)
    body = signed.get("proof", {})
    return VerifyResult(
        document_id=document_id, valid=ok,
        issued_at_iso=body.get("issued_at_iso"),
        redaction_count=body.get("redaction_count"),
        detail="Signature valid — the proof is intact and untampered."
        if ok else "Signature INVALID — the proof was altered after signing.")


@app.post("/api/verify/{document_id}/tamper", response_model=VerifyResult)
async def tamper_demo(document_id: str):
    """Demo helper: mutate one field of the stored proof so a follow-up
    /api/verify visibly fails. Makes the tamper-evidence point on screen."""
    document_id = _safe_doc_id(document_id)
    path = STORAGE / f"{document_id}.proof.json"
    if not path.exists():
        raise HTTPException(404, "Not found.")
    signed = json.loads(path.read_text(encoding="utf-8"))
    signed["proof"]["redaction_count"] = 9999  # silently corrupt the body
    path.write_text(json.dumps(signed, ensure_ascii=False, indent=2), encoding="utf-8")
    ok = signing.verify(signed)
    return VerifyResult(
        document_id=document_id, valid=ok,
        issued_at_iso=signed["proof"].get("issued_at_iso"),
        redaction_count=signed["proof"].get("redaction_count"),
        detail="Proof body was altered — verification now fails, as it should.")


@app.get("/api/health")
async def health():
    return {"status": "ok", "use_dws": settings.use_dws,
            "account": await dws_client.account_info(),
            "last_dws_error": _LAST_DWS_ERROR.get("msg")}


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
