# Author: Arif Alsuhaimi
"""
Generate a bilingual (Arabic + English) sample PDF for the Nutrient DWS demo.

IMPORTANT — why this uses WeasyPrint and not reportlab:
A redaction-ready Arabic PDF must store a *logical* Unicode text layer (base
letters, logical order). The older reportlab + arabic-reshaper approach bakes
Arabic into *presentation forms* in *visual* order — it looks right on screen
but the text layer is not real Arabic, so detectors miss it AND DWS cannot align
its redaction boxes (the Arabic values come out un-redacted). WeasyPrint renders
through a real text engine, producing correctly shaped Arabic with a proper
logical text layer that both SafeDocs and Nutrient DWS can detect and redact.

The document carries matching personal fields in BOTH languages — a name,
national ID, email and IBAN in Arabic (اسم، رقم الهوية، البريد الإلكتروني،
رقم الآيبان) and again in English. All data is synthetic.

Install (macOS):
    pip install weasyprint
    brew install pango            # WeasyPrint needs the system pango library

Run:
    python sample_docs/make_sample_pdf.py            # -> sample_docs/sample_contract.pdf
    python sample_docs/make_sample_pdf.py --out X.pdf

No Homebrew / WeasyPrint won't install? See the zero-tooling route in the README:
type the same text into TextEdit or Pages and File → Export as PDF — macOS
produces a correct Arabic text layer natively.
"""
from __future__ import annotations

import argparse
import os
import sys

HTML_DOC = """<!DOCTYPE html>
<html lang="ar"><head><meta charset="utf-8"><style>
  @page { size: A4; margin: 2cm; }
  body { font-family: "Helvetica Neue", Arial, sans-serif; color: #10233b; font-size: 13px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #5b6572; margin: 0 0 18px; }
  hr { border: none; border-top: 1px solid #d2d8e0; margin: 14px 0 20px; }
  h2 { font-size: 15px; margin: 18px 0 8px; color: #1b3556; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 12px; }
  td { padding: 5px 8px; vertical-align: top; }
  .arblock { direction: rtl; }
  .lbl { font-weight: bold; white-space: nowrap; width: 38%; }
  .val { font-family: "SFMono-Regular", Menlo, monospace; }
  .ltr { direction: ltr; unicode-bidi: isolate; text-align: left; }
  .foot { color: #7a828c; font-size: 10px; font-style: italic; margin-top: 30px; }
</style></head><body>
  <h1>عقد إيجار &nbsp;·&nbsp; Lease Agreement</h1>
  <p class="sub">SafeDocs — bilingual sample</p>
  <hr>

  <h2 style="direction:rtl;text-align:right">البيانات (عربي)</h2>
  <table class="arblock">
    <tr><td class="lbl">اسم العميل:</td><td class="val">خالد بن سعيد العتيبي</td></tr>
    <tr><td class="lbl">رقم الهوية:</td><td class="val ltr">1098234567</td></tr>
    <tr><td class="lbl">البريد الإلكتروني:</td><td class="val ltr">khalid.otaibi@example.com</td></tr>
    <tr><td class="lbl">رقم الآيبان:</td><td class="val ltr">SA0380000000608010167519</td></tr>
    <tr><td class="lbl">الجوال:</td><td class="val ltr">+966 55 123 4567</td></tr>
    <tr><td class="lbl">العنوان:</td><td class="val">حي النرجس، الرياض</td></tr>
  </table>

  <h2>Details (English)</h2>
  <table>
    <tr><td class="lbl">Tenant:</td><td class="val">Sarah Miller</td></tr>
    <tr><td class="lbl">National ID:</td><td class="val">2087654321</td></tr>
    <tr><td class="lbl">Email:</td><td class="val">sarah.miller@example.com</td></tr>
    <tr><td class="lbl">IBAN:</td><td class="val">GB29NWBK60161331926819</td></tr>
    <tr><td class="lbl">Phone:</td><td class="val">+1 415 555 0123</td></tr>
    <tr><td class="lbl">Address:</td><td class="val">14 Rose Street, London</td></tr>
  </table>

  <p class="foot">SafeDocs sample — synthetic data for demo purposes only.</p>
</body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Make the bilingual sample PDF (WeasyPrint).")
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                        "sample_contract.pdf"))
    args = parser.parse_args()

    try:
        from weasyprint import HTML
    except Exception as exc:  # noqa: BLE001
        sys.exit(
            f"WeasyPrint is not available ({type(exc).__name__}: {exc}).\n"
            "Install it:  pip install weasyprint   and on macOS:  brew install pango\n"
            "Or use the zero-tooling route (see README): paste the sample text into\n"
            "TextEdit or Pages and File -> Export as PDF.")

    HTML(string=HTML_DOC).write_pdf(args.out)
    print(f"Wrote {args.out}")
    print("Tip: upload it with USE_DWS=true to see DWS redact the Arabic *and* "
          "English fields, then CAdES-sign the result.")


if __name__ == "__main__":
    main()
