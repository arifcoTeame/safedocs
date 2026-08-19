# Author: Arif Alsuhaimi
"""Request/response schemas shared across the API."""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel


class PiiSpan(BaseModel):
    """One detected piece of sensitive information."""
    id: str
    kind: str                 # e.g. "email", "national_id", "person_name"
    text: str                 # the raw matched text (shown to the reviewer only)
    start: int                # char offset in the extracted text
    end: int
    confidence: float         # 0.0 - 1.0
    lang: Literal["ar", "en", "mixed"] = "en"
    # The human reviewer decides. Low-confidence spans default to needing review.
    approved: bool = True


class ExtractResult(BaseModel):
    document_id: str
    filename: str
    lang: Literal["ar", "en", "mixed"]
    char_count: int
    spans: list[PiiSpan]
    engine: str               # "dws" or "local-fallback"


class RedactDecision(BaseModel):
    span_id: str
    approved: bool


class RedactRequest(BaseModel):
    document_id: str
    decisions: list[RedactDecision]


class RedactResult(BaseModel):
    document_id: str
    redacted_count: int
    redacted_preview: str
    proof_id: str
    signature_valid: bool
    download_url: str
    proof_url: str
    engine: str
    # Ordered list of Nutrient DWS operations performed (DWS path only).
    dws_operations: list[str] = []


class VerifyResult(BaseModel):
    document_id: str
    valid: bool
    issued_at_iso: Optional[str] = None
    redaction_count: Optional[int] = None
    detail: str
