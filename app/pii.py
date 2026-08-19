# Author: Arif Alsuhaimi
"""
Bilingual (Arabic / English) PII detection — the local fallback engine.

This is what makes SafeDocs run on day 1 without any external service, and it
is also the differentiator: most redaction tools are English-only. When
USE_DWS=true, dws_client delegates extraction to Nutrient DWS instead, but this
module stays useful for the Arabic layer and for offline demos.

Detection is pattern + label based and returns a confidence score per hit.
Low-confidence hits are the ones a human should review before release.
"""
from __future__ import annotations

import re
import uuid

from .models import PiiSpan


# --- Regex patterns (language-agnostic structured identifiers) ---------------

_PATTERNS: list[tuple[str, str, float]] = [
    # kind, pattern, base confidence
    ("email", r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", 0.98),
    # IBAN: 2-letter country + 2 check digits + up to 30 alnum (spaces allowed
    # between groups, as IBANs are often printed in blocks of four).
    ("iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", 0.97),
    ("credit_card", r"\b(?:\d[ -]?){13,16}\b", 0.80),
    # Gulf / Saudi national ID: 10 digits starting with 1 or 2. Lookarounds
    # (not \b) so it still matches when glued to an Arabic label like
    # "رقم الهوية1098234567" in a PDF text layer.
    ("national_id", r"(?<![\dA-Za-z])[12]\d{9}(?!\d)", 0.85),
    # Phone numbers (intl + local, incl. Arabic-Indic digits handled after norm).
    # The negative lookbehind stops the digit run of an IBAN (e.g. the "038…"
    # right after "SA") from being mistaken for a phone number.
    ("phone", r"(?<![A-Za-z])(?:\+?\d[\d\s\-()]{7,}\d)", 0.70),
    ("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.80),
]

# Label cues that strongly indicate the *next* token(s) are personal data.
# English labels
_LABELS_EN = {
    "name": r"(?:name|full name|client|applicant|patient|tenant)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "address": r"(?:address|residence)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "dob": r"(?:date of birth|dob|born)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    # IBAN / bank account: capture just the alnum token so DWS gets the whole
    # identifier even when the structured regex misses a word boundary.
    "iban": r"(?:iban|account\s*(?:no\.?|number)|acct)[^\S\n]*[:\-]?[^\S\n]*([A-Z0-9][A-Z0-9 ]{10,40})",
}
# Arabic labels (اسم، العنوان، تاريخ الميلاد، رقم الهوية، الهاتف)
_LABELS_AR = {
    "name": r"(?:الاسم|الإسم|اسم العميل|اسم المريض|المتقدم)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "address": r"(?:العنوان|السكن|محل الإقامة)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "dob": r"(?:تاريخ الميلاد|المولد)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "national_id": r"(?:رقم الهوية|الهوية الوطنية|السجل المدني)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "phone": r"(?:الهاتف|الجوال|رقم الجوال|رقم الهاتف)[^\S\n]*[:\-]?[^\S\n]*(.+)",
    "iban": r"(?:رقم الآيبان|الآيبان|الايبان|رقم الحساب|الحساب البنكي)[^\S\n]*[:\-]?[^\S\n]*([A-Z0-9][A-Z0-9 ]{10,40})",
}

_ARABIC_RE = re.compile(r"[\u0600-\u06FF]")
# Arabic-Indic digits -> ASCII, so numeric patterns catch them too.
_AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")

# Bidi / zero-width control marks a PDF text layer may sprinkle around RTL runs.
_BIDI_CTRL = dict.fromkeys(
    [0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF], None)


def _clean_value(value: str) -> str:
    """Normalise a captured value so it matches the document text exactly:
    drop bidi/zero-width marks, collapse inner whitespace, and trim edges plus
    any trailing separators. Critical for `create_redactions_text` (an exact
    match) to land on Arabic values like the address «حي النرجس، الرياض»."""
    value = value.translate(_BIDI_CTRL)
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"^[\s.,;:،؛]+", "", value)  # strip leading separators
    value = re.sub(r"[\s.,;:،؛]+$", "", value)  # strip trailing separators
    return value


# --- Order-agnostic, per-line label detection --------------------------------
# PDF text layers vary wildly for Arabic: a label can come before its value
# ("العنوان: X") OR after it in visual order ("X :العنوان"), and multi-word
# labels can be word-reversed ("اسم العميل" -> "العميل اسم"). The strict regex
# labels above miss those forms. This pass looks for a label *anywhere on a
# line*, in either word order, and treats the rest of the line as the value —
# so the address (which has no structural regex fallback) is always caught.

def _either_order(phrase: str) -> str:
    words = [re.escape(w) for w in phrase.split()]
    if len(words) == 1:
        return words[0]
    fwd = r"\s+".join(words)
    rev = r"\s+".join(reversed(words))
    return f"(?:{fwd}|{rev})"


_LINE_LABEL_SPECS = [
    ("national_id", ["رقم الهوية", "الهوية الوطنية", "السجل المدني"]),
    ("iban", ["رقم الآيبان", "الآيبان", "الايبان", "رقم الحساب"]),
    ("phone", ["رقم الجوال", "رقم الهاتف", "الجوال", "الهاتف"]),
    ("dob", ["تاريخ الميلاد", "المولد"]),
    ("name", ["اسم العميل", "اسم المستأجر", "اسم المريض"]),
    ("address", ["العنوان", "محل الإقامة", "السكن"]),
]
_LINE_LABEL_RX = [
    (kind, re.compile("|".join(_either_order(p) for p in phrases)))
    for kind, phrases in _LINE_LABEL_SPECS
]


def _detect_label_lines(text: str) -> list[PiiSpan]:
    """Detect label→value pairs line by line, label before OR after the value."""
    out: list[PiiSpan] = []
    pos = 0
    for line in text.split("\n"):
        start = pos
        pos += len(line) + 1  # + newline
        for kind, rx in _LINE_LABEL_RX:
            m = rx.search(line)
            if not m:
                continue
            before, after = line[:m.start()], line[m.end():]
            # The value is whichever side is left once the label is removed.
            side = after if len(after.strip(" \t:،؛-")) >= len(before.strip(" \t:،؛-")) else before
            value = _clean_value(side)
            if len(value) < 3:
                continue
            i = line.find(value)
            if i < 0:
                continue
            out.append(PiiSpan(
                id=_new_id(), kind=kind, text=value,
                start=start + i, end=start + i + len(value),
                confidence=0.72, lang=_span_lang(value),
            ))
            break  # one label per line
    return out


def detect_language(text: str) -> str:
    ar = len(_ARABIC_RE.findall(text))
    en = len(re.findall(r"[A-Za-z]", text))
    if ar and en:
        return "mixed"
    if ar:
        return "ar"
    return "en"


def _span_lang(fragment: str) -> str:
    return "ar" if _ARABIC_RE.search(fragment) else "en"


def _new_id() -> str:
    return "pii_" + uuid.uuid4().hex[:10]


def detect(text: str) -> list[PiiSpan]:
    """Return all detected PII spans in `text`, de-duplicated by offset."""
    normalized = text.translate(_AR_DIGITS)
    spans: list[PiiSpan] = []
    seen: set[tuple[int, int]] = set()

    # 1) Structured identifiers via regex
    for kind, pattern, conf in _PATTERNS:
        for m in re.finditer(pattern, normalized):
            key = (m.start(), m.end())
            if key in seen:
                continue
            raw = text[m.start():m.end()].strip()
            if len(raw) < 3:
                continue
            seen.add(key)
            spans.append(PiiSpan(
                id=_new_id(), kind=kind, text=raw,
                start=m.start(), end=m.end(),
                confidence=conf, lang=_span_lang(raw),
            ))

    # 2) Label-driven values (names, addresses, DOB) in both languages
    for label_map, base_conf in ((_LABELS_EN, 0.75), (_LABELS_AR, 0.75)):
        for kind, pattern in label_map.items():
            for m in re.finditer(pattern, text, flags=re.IGNORECASE):
                value = _clean_value(m.group(1))
                if not value:
                    continue
                # Position the span on the captured value, not the label.
                v_start = m.start(1)
                v_end = m.end(1)
                key = (v_start, v_end)
                if key in seen:
                    continue
                seen.add(key)
                spans.append(PiiSpan(
                    id=_new_id(), kind=kind, text=value,
                    start=v_start, end=v_end,
                    confidence=base_conf, lang=_span_lang(value),
                ))

    # 3) Order-agnostic per-line labels (handles reversed / label-after-value
    #    Arabic PDF extractions). Overlaps with the above are resolved next.
    spans.extend(_detect_label_lines(text))

    return _resolve_overlaps(spans)


def _resolve_overlaps(spans: list[PiiSpan]) -> list[PiiSpan]:
    """When two matches overlap (e.g. a phone pattern catching part of an IBAN),
    keep the higher-confidence / longer one and drop the other."""
    ranked = sorted(spans, key=lambda s: (s.confidence, s.end - s.start), reverse=True)
    kept: list[PiiSpan] = []
    for s in ranked:
        if any(not (s.end <= k.start or s.start >= k.end) for k in kept):
            continue
        kept.append(s)
    kept.sort(key=lambda s: s.start)
    return kept


def redact(text: str, spans: list[PiiSpan]) -> str:
    """
    Produce the clean copy: replace every APPROVED span with a redaction bar.
    Works right-to-left over offsets so earlier indices stay valid.
    """
    out = text
    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        if not span.approved or span.end <= span.start:
            continue  # skip zero-length placeholders (e.g. DWS value-only spans)
        bar = "█" * max(4, min(len(span.text), 12))
        out = out[:span.start] + f"[{span.kind.upper()} {bar}]" + out[span.end:]
    return out
