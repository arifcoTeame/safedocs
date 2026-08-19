# Author: Arif Alsuhaimi
"""
check_dws.py — confirm the REAL Nutrient DWS pipeline works with your keys.

Run this on a machine with internet access (e.g. your Mac):

    pip install -r requirements.txt
    python check_dws.py

It reads DWS_API_KEY from .env (never prints it), builds a tiny in-memory PDF
containing an email address, and runs the exact DWS steps SafeDocs uses:

    create_redactions_ai  ->  apply_redactions  ->  sign (CAdES b-lt)

On success it prints the byte size of each stage and a final ✓. Any failure is
printed with its type so you can tell a key problem from a network problem.

This is a standalone diagnostic — it does not touch the app or your .env.
"""
from __future__ import annotations

import asyncio
import io
import sys

from dotenv import dotenv_values
from reportlab.pdfgen import canvas

from nutrient_dws import NutrientClient

CRITERIA = ("All personally identifiable information in Arabic or English: "
            "names, national IDs, phone numbers, emails, addresses, IBANs and "
            "credit/debit card numbers.")


def _tiny_pdf() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(72, 720, "Applicant: Sarah Miller")
    c.drawString(72, 700, "Email: sarah.miller@example.com")
    c.drawString(72, 680, "Card: 4111 1111 1111 1111")
    c.save()
    return buf.getvalue()


async def main() -> int:
    env = dotenv_values(".env")
    api_key = env.get("DWS_API_KEY", "")
    if not api_key:
        print("✗ No DWS_API_KEY found in .env")
        return 1
    print(f"Loaded DWS_API_KEY from .env (length {len(api_key)}, prefix "
          f"{api_key[:4]}…) — value not shown.")

    client = NutrientClient(api_key=api_key)
    pdf = _tiny_pdf()
    print(f"Built test PDF: {len(pdf)} bytes")

    try:
        staged = (await client.create_redactions_ai(
            pdf, criteria=CRITERIA, redaction_state="stage"))["buffer"]
        print(f"✓ create_redactions_ai  -> {len(staged)} bytes")

        applied = (await client.apply_redactions(staged))["buffer"]
        print(f"✓ apply_redactions      -> {len(applied)} bytes")

        signed = (await client.sign(applied, data={
            "signatureType": "cades", "cadesLevel": "b-lt", "flatten": True,
        }))["buffer"]
        print(f"✓ sign (CAdES b-lt)     -> {len(signed)} bytes")
    except Exception as exc:  # noqa: BLE001
        print(f"✗ DWS call failed: {type(exc).__name__}: {exc}")
        print("  If this is a NetworkError, check your internet/firewall.")
        print("  If this is an AuthenticationError, re-check the key in .env.")
        return 2

    with open("dws_signed_check.pdf", "wb") as f:
        f.write(signed)
    print("\n✓ SUCCESS — DWS redaction + CAdES signing work.")
    print("  Wrote dws_signed_check.pdf (open it to see the signed, redacted PDF).")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
