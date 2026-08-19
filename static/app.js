// Author: Arif Alsuhaimi
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let currentDoc = null; // { document_id, spans: [...] }
let LANG = "ar";       // current UI language (Arabic is the default)

// Readable, localized names for each detected PII type — shown as a badge so a
// the system clearly distinguishes name vs ID vs IBAN vs address, etc.
const KIND_LABELS = {
  ar: { name: "اسم", national_id: "هوية", email: "بريد", iban: "آيبان",
        phone: "جوال", address: "عنوان", credit_card: "بطاقة", dob: "ميلاد",
        ip_address: "IP", field: "حقل" },
  en: { name: "Name", national_id: "National ID", email: "Email", iban: "IBAN",
        phone: "Phone", address: "Address", credit_card: "Card", dob: "DOB",
        ip_address: "IP", field: "Field" },
};
const kindLabel = (kind) =>
  (KIND_LABELS[LANG] || KIND_LABELS.ar)[kind] || kind.replace(/_/g, " ");

// --- i18n ------------------------------------------------------------------
const I18N = {
  ar: {
    toggle: "English",
    tagline: "حماية المستندات وتوثيقها",
    num1: "١", num2: "٢", num3: "٣",
    step1_title: "ارفع مستنداً",
    drop_main: "اسحب ملفاً هنا أو اضغط للاختيار",
    drop_sub: "PDF أو TXT",
    sample_btn: "جرّب مستنداً نموذجياً",
    step2_title: "راجع قبل الحجب",
    hint: "البنود منخفضة الثقة تحتاج نظرك. أزل العلامة عن أي بند لا تريد حجبه.",
    sel_all: "تحديد الكل", sel_none: "إلغاء الكل",
    redact_btn: "احجب ووقّع", back_btn: "رجوع",
    step3_title: "نسخة نظيفة موثّقة",
    seal_signed: "موقّع رقمياً",
    dws_ran: "خطوات نُفّذت على DWS",
    verify_btn: "تحقّق من الشهادة", tamper_btn: "حاكِ عبثاً",
    verify_hint: 'التوقيع يكشف أي تعديل بعد الاعتماد — جرّب "حاكِ عبثاً" ثم "تحقّق".',
    dl_doc: "نزّل النسخة النظيفة", dl_proof: "شهادة الإثبات", again_btn: "مستند آخر",
    foot_local: "النموذج الأولي يعمل محلياً؛ فعّل Nutrient DWS من ملف .env.",
    foot_dws: "متصل بـ Nutrient DWS — الاستخراج والحجب والتوقيع تُنفَّذ على DWS.",
    lang_label: "اللغة:", items_word: "بند حسّاس", engine_local: "محلي",
    lang_ar: "عربي", lang_en: "إنجليزي", lang_mixed: "مختلط",
    no_pii: "لم يُكتشف أي بيانات شخصية.", redactions_word: "حجب",
    verify_not: "لم يُتحقق بعد", verify_ok: "الشهادة صحيحة وغير معدّلة.",
    verify_bad: "فشل التحقق — الشهادة عُدّلت بعد التوقيع.",
    t_upload_fail: "تعذّر رفع الملف. حاول مرة أخرى.",
    t_server_fail: "تعذّر الاتصال بالخادم.",
    t_redact_fail: "تعذّرت المعالجة.",
    t_tamper_done: 'تم تعديل الشهادة — اضغط "تحقّق" لترى الفشل.',
    t_no_proof: "لا توجد شهادة للتحقق.", t_verify_fail: "تعذّر التحقق.",
  },
  en: {
    toggle: "عربي",
    tagline: "Redact. Prove. Release.",
    num1: "1", num2: "2", num3: "3",
    step1_title: "Upload a document",
    drop_main: "Drag a file here or click to choose",
    drop_sub: "PDF or TXT",
    sample_btn: "Load a sample document",
    step2_title: "Review before redaction",
    hint: "Low-confidence items need your eyes. Uncheck anything you want to keep.",
    sel_all: "Select all", sel_none: "Select none",
    redact_btn: "Redact & sign", back_btn: "Back",
    step3_title: "Cleared & sealed",
    seal_signed: "Digitally signed",
    dws_ran: "Ran on Nutrient DWS",
    verify_btn: "Verify", tamper_btn: "Tamper",
    verify_hint: 'The signature detects any change after clearance — try "Tamper" then "Verify".',
    dl_doc: "Download clean copy", dl_proof: "Proof certificate", again_btn: "Another document",
    foot_local: "Prototype runs locally; enable Nutrient DWS in the .env file.",
    foot_dws: "Connected to Nutrient DWS — extraction, redaction and signing run on DWS.",
    lang_label: "Language:", items_word: "sensitive items", engine_local: "Local",
    lang_ar: "Arabic", lang_en: "English", lang_mixed: "Mixed",
    no_pii: "No personal data detected.", redactions_word: "redactions",
    verify_not: "Not verified yet", verify_ok: "The proof is intact and untampered.",
    verify_bad: "Verification failed — the proof was altered after signing.",
    t_upload_fail: "Could not upload the file. Please try again.",
    t_server_fail: "Could not reach the server.",
    t_redact_fail: "Processing failed.",
    t_tamper_done: 'Proof altered — press "Verify" to see it fail.',
    t_no_proof: "No proof to verify.", t_verify_fail: "Verification failed.",
  },
};
const t = (key) => (I18N[LANG] || I18N.ar)[key] ?? key;

let useDws = false;       // last known engine mode (for the footer)
let healthKnown = false;  // has /api/health answered yet? (avoids badge flash)
let lastResult = null;    // last redact response (to re-render on language switch)
let lastVerify = null;    // last verify result (null = not verified)

function applyLang(lang) {
  LANG = I18N[lang] ? lang : "ar";
  const rtl = LANG === "ar";
  document.documentElement.lang = LANG;
  document.documentElement.dir = rtl ? "rtl" : "ltr";
  $("#lang-toggle").textContent = t("toggle");
  // Static text nodes
  $$("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key === "foot_local") return;            // footer handled below
    el.textContent = t(key);
  });
  // Footer text only once we know the engine — otherwise stays blank (no flash).
  $("#foot-note").textContent = healthKnown ? t(useDws ? "foot_dws" : "foot_local") : "";
  try { localStorage.setItem("safedocs_lang", LANG); } catch {}
  // Re-render dynamic content that's currently on screen
  if (currentDoc && !$("#step-review").classList.contains("is-hidden")) renderReview(currentDoc);
  if (lastResult && !$("#step-result").classList.contains("is-hidden")) renderResult(lastResult);
  if (lastResult) setVerifyState(lastVerify);
}

const SAMPLE = `عقد إيجار
اسم العميل: خالد بن سعيد العتيبي
رقم الهوية: 1098234567
الجوال: +966 55 123 4567
البريد الإلكتروني: khalid.otaibi@example.com
العنوان: حي النرجس، الرياض

Lease Agreement
Applicant: Sarah Miller
Email: sarah.miller@example.com
IBAN: SA0380000000608010167519
Card: 4111 1111 1111 1111
`;

function show(step) {
  ["upload", "review", "result"].forEach((s) =>
    $("#step-" + s).classList.toggle("is-hidden", s !== step));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setEngine(engine) {
  const b = $("#engine-badge");
  const isDws = engine === "dws";
  b.textContent = isDws ? "engine: Nutrient DWS" : "engine: local-fallback";
  b.classList.toggle("is-dws", isDws);
}

function toast(msg, kind = "err") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast toast-${kind}`;
  setTimeout(() => t.classList.add("is-hidden"), 4200);
}

function busy(btn, on) {
  btn.classList.toggle("is-busy", on);
  btn.disabled = on;
}

async function uploadFile(file) {
  const drop = $("#drop");
  drop.classList.add("is-busy");
  try {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      toast(e.detail || "تعذّر رفع الملف. حاول مرة أخرى.");
      return;
    }
    const data = await res.json();
    currentDoc = data;
    renderReview(data);
    show("review");
  } catch {
    toast("تعذّر الاتصال بالخادم.");
  } finally {
    drop.classList.remove("is-busy");
  }
}

function renderReview(data) {
  setEngine(data.engine);
  const engineLabel = data.engine === "dws" ? "Nutrient DWS" : t("engine_local");
  const langName = t("lang_" + data.lang) || data.lang;
  $("#review-meta").innerHTML =
    `<span class="chip">${escapeHtml(data.filename)}</span>` +
    `<span class="chip">${t("lang_label")} ${langName}</span>` +
    `<span class="chip">${data.spans.length} ${t("items_word")}</span>` +
    `<span class="chip chip-engine">${engineLabel}</span>`;

  const list = $("#spanlist");
  list.innerHTML = "";
  if (!data.spans.length) {
    list.innerHTML = `<li class="hint">${t("no_pii")}</li>`;
  }
  for (const s of data.spans) {
    const lo = s.confidence < 0.6;
    const li = document.createElement("li");
    li.className = "spanitem" + (lo ? " is-lo" : "");
    li.innerHTML =
      `<input type="checkbox" data-id="${s.id}" ${s.approved ? "checked" : ""}>
       <span class="badge badge-${s.kind}">${escapeHtml(kindLabel(s.kind))}</span>
       <span class="val">${escapeHtml(s.text)}</span>
       <span class="spacer"></span>
       <span class="tag lang">${s.lang}</span>
       <span class="tag ${lo ? "conf-lo" : "conf-hi"}">${Math.round(s.confidence * 100)}%</span>`;
    list.appendChild(li);
  }
}

async function redact() {
  const btn = $("#redact-btn");
  const decisions = $$(".spanitem input").map((i) => ({
    span_id: i.dataset.id,
    approved: i.checked,
  }));
  busy(btn, true);
  try {
    const res = await fetch("/api/redact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ document_id: currentDoc.document_id, decisions }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      toast(e.detail || t("t_redact_fail"));
      return;
    }
    const data = await res.json();
    renderResult(data);
    show("result");
  } catch {
    toast(t("t_server_fail"));
  } finally {
    busy(btn, false);
  }
}

function renderResult(data) {
  lastResult = data;
  setEngine(data.engine);
  $("#preview").textContent = data.redacted_preview;
  $("#seal-detail").textContent = `${data.proof_id} · ${data.redacted_count} ${t("redactions_word")}`;
  $("#dl-doc").href = data.download_url;
  $("#dl-proof").href = data.proof_url;

  // What DWS did
  const ops = data.dws_operations || [];
  const box = $("#dws-ops");
  if (ops.length) {
    $("#dws-ops-list").innerHTML = ops.map((o) => `<li>${escapeHtml(o)}</li>`).join("");
    box.classList.remove("is-hidden");
  } else {
    box.classList.add("is-hidden");
  }

  // Reset verify state
  setVerifyState(null);
}

function setVerifyState(result) {
  lastVerify = result;
  const el = $("#verify-state");
  if (result == null) {
    el.textContent = t("verify_not");
    el.className = "verify-state";
  } else if (result.valid) {
    el.textContent = `✓ ${t("verify_ok")}`;
    el.className = "verify-state ok";
  } else {
    el.textContent = `✕ ${t("verify_bad")}`;
    el.className = "verify-state bad";
  }
}

async function verifyProof() {
  if (!currentDoc) return;
  try {
    const res = await fetch(`/api/verify/${currentDoc.document_id}`);
    if (!res.ok) { toast(t("t_no_proof")); return; }
    setVerifyState(await res.json());
  } catch { toast(t("t_verify_fail")); }
}

async function tamperProof() {
  if (!currentDoc) return;
  try {
    const res = await fetch(`/api/verify/${currentDoc.document_id}/tamper`, { method: "POST" });
    if (!res.ok) { toast(t("t_no_proof")); return; }
    await res.json();
    lastVerify = null;
    toast(t("t_tamper_done"), "warn");
  } catch { toast(t("t_verify_fail")); }
}

function escapeHtml(t) {
  return String(t).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// --- wiring ----------------------------------------------------------------
const drop = $("#drop"), fileInput = $("#file");
fileInput.addEventListener("change", (e) => e.target.files[0] && uploadFile(e.target.files[0]));
["dragover", "dragenter"].forEach((ev) =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("drag"); }));
drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && uploadFile(e.dataTransfer.files[0]));

$("#sample-btn").addEventListener("click", () =>
  uploadFile(new File([SAMPLE], "sample_contract.txt", { type: "text/plain" })));
$("#redact-btn").addEventListener("click", redact);
$("#back-btn").addEventListener("click", () => show("upload"));
$("#again-btn").addEventListener("click", () => { currentDoc = null; show("upload"); });
$("#sel-all").addEventListener("click", () => $$(".spanitem input").forEach((i) => (i.checked = true)));
$("#sel-none").addEventListener("click", () => $$(".spanitem input").forEach((i) => (i.checked = false)));
$("#verify-btn").addEventListener("click", verifyProof);
$("#tamper-btn").addEventListener("click", tamperProof);
$("#lang-toggle").addEventListener("click", () => applyLang(LANG === "ar" ? "en" : "ar"));

// Apply the saved / default language (English by default) before anything shows.
let savedLang = "en";
try { savedLang = localStorage.getItem("safedocs_lang") || "en"; } catch {}
applyLang(savedLang);

// Engine badge stays hidden until /api/health answers, so it never flashes
// "local" before turning green.
fetch("/api/health").then((r) => r.json()).then((d) => {
  useDws = !!d.use_dws;
  healthKnown = true;
  setEngine(useDws ? "dws" : "local");
  $("#engine-badge").classList.remove("is-hidden");
  $("#foot-note").textContent = t(useDws ? "foot_dws" : "foot_local");
}).catch(() => {
  healthKnown = true;
  $("#foot-note").textContent = t("foot_local");
});
