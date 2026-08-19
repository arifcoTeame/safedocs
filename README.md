<p align="center">
  <img src="static/logo.png" alt="SafeDocs logo" height="130">
</p>

# SafeDocs — Redact. Prove. Release.

**One-line pitch:** Upload a document, auto-detect and redact personal data in **Arabic and English**, and download a clean copy plus a **signed, verifiable proof** of exactly what was removed and when.

Most redaction tools are English-only. SafeDocs handles Arabic labels, names, and Arabic-Indic digits — and ships a verifiable proof certificate that lets a recipient confirm the file was not altered after clearance.

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Then open [http://localhost:8000](http://localhost:8000).

## Environment Variables

Copy `.env.example` to `.env`. For local testing, no API keys are required.

```ini
USE_DWS=false          # Set to true to use Document Web Services
DWS_API_KEY=           # Your DWS API key
```

## How it works

```
upload ──> extract (Engine)  ──> HUMAN REVIEW ──> redact ──> sign proof
             fields + confidence        approve/keep      clean copy   verifiable
```

**Where Nutrient DWS does the core work:** with `USE_DWS=true`, Nutrient DWS carries the core document pipeline end-to-end — `parse` reads the PDF for review, `create_redactions_text` / `create_redactions_ai` / `create_redactions_preset` detect and stage the personal data (Arabic **and** English), `apply_redactions` burns it permanently into the PDF, and `sign` applies a CAdES/PAdES tamper-evident digital signature. SafeDocs adds the bilingual Arabic detection layer and the human-review gate on top. Verify the live pipeline against your key with `python check_dws.py`.

- **`app/pii.py`** — bilingual detector (regex + AR/EN label cues), confidence scores, and overlap resolution.
- **`app/dws_client.py`** — the Nutrient DWS integration: `parse` (review), `create_redactions_text` / `create_redactions_ai` / `create_redactions_preset` + `apply_redactions` (redact), and `sign` (CAdES).
- **`app/signing.py`** — builds the proof (hashes of original + redacted, timestamp, list of what was removed) and signs it (RSA). `verify()` proves tamper-evidence: any change to the proof fails verification.
- **`app/main.py`** — FastAPI routes handling the core endpoints.
- **`static/`** — single-page bilingual UI (RTL-aware): live progress spinners and a one-click **Verify / Tamper** trust demo.

### API endpoints

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/upload` | Upload PDF/TXT → extract + detect PII |
| POST | `/api/redact` | Apply human-approved redactions + sign |
| GET | `/api/download/{id}` | Download the clean, signed document |
| GET | `/api/proof/{id}` | The proof certificate (hashes + what was removed) |
| GET | `/api/verify/{id}` | Re-verify the proof signature (tamper check) |

### Security & robustness

- Path-traversal guard: document ids are validated before ever touching the filesystem.
- Upload guards: 15 MB size cap and PDF/TXT-only enforcement.
- The proof stores only **hashes** of the original and redacted text — never the sensitive content itself.

## Project structure

```
safedocs/
├── app/
│   ├── main.py         # API routes
│   ├── dws_client.py   # document processing integration
│   ├── pii.py          # bilingual detection + redaction
│   ├── signing.py      # proof + tamper-evident signature
│   ├── models.py       # schemas
│   └── config.py       # env settings
├── static/             # index.html, style.css, app.js
├── sample_docs/        # bilingual demo doc
├── storage/            # runtime output (kept via .gitkeep)
├── tests/             # pytest suite
├── requirements.txt
├── .env.example
└── run.py
```

## Deployment

SafeDocs is ready for production deployment:
- **Render:** Push to GitHub, choose "New → Blueprint" and select the repo. `render.yaml` handles the setup.
- **Docker:** `docker build -t safedocs . && docker run -p 8000:8000 safedocs`
- **Heroku / Railway:** The `Procfile` is pre-configured.

## Author

Designed and developed by **Arif Alsuhaimi**.
