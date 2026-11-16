import { api, fmtDate, h, logout, toast } from "./api.js";

let records = [];
let filter = "all";
const list = document.getElementById("list");

document.getElementById("logout").addEventListener("click", logout);

async function boot() {
  try {
    const { user } = await api("/api/auth/me");
    document.getElementById("who").textContent = user.username;
    document.getElementById("fullname").textContent = user.fullName;
  } catch {
    location.replace("/");
    return;
  }
  await load();
}

async function load() {
  try {
    ({ records } = await api("/api/records"));
    render();
  } catch (err) {
    if (err.status === 401) return location.replace("/");
    list.replaceChildren(h("div", { class: "alert" }, err.message));
  }
}

function stats() {
  const set = (id, v) => (document.getElementById(id).textContent = v);
  set("stat-total", records.length);
  set("stat-med", records.filter((r) => r.category === "medical").length);
  set("stat-fin", records.filter((r) => r.category === "financial").length);
  set("stat-ok", `${records.filter((r) => r.integrity === "verified").length}/${records.length}`);
}

function card(r) {
  const failed = r.integrity === "failed";
  const el = h(
    "article",
    { class: "rec", "data-cat": r.category, "data-integrity": r.integrity },
    h("div", { class: "rec-bar" }),
    h(
      "div",
      { class: "rec-main" },
      h(
        "div",
        { class: "rec-top" },
        h("span", { class: `tag tag-${r.category}` }, r.category),
        failed
          ? h("span", { class: "tag tag-cipher" }, "GCM tag failed — refused")
          : h("span", { class: "tag tag-ok" }, "Tag verified · decrypted"),
        h("span", { class: "tag" }, `row #${r.id}`),
        h("span", { class: "when" }, fmtDate(r.createdAt)),
      ),
      h(
        "div",
        { class: "flip" },
        h(
          "div",
          { class: "face-plain" },
          failed
            ? h("p", { class: "body" }, "This row failed authentication and was not decrypted. It may have been modified on disk.")
            : [
                h("h3", {}, r.title),
                r.subject ? h("div", { class: "subject" }, r.subject) : null,
                h("p", { class: "body" }, r.body),
              ],
        ),
        h(
          "dl",
          { class: "face-cipher kv", "aria-label": "Stored ciphertext" },
          h("dt", {}, "algorithm"), h("dd", {}, r.stored.cipherAlgorithm),
          h("dt", {}, "iv"), h("dd", { class: "cipher-text" }, r.stored.iv),
          h("dt", {}, "auth_tag"), h("dd", { class: "cipher-text" }, r.stored.authTag),
          h("dt", {}, "ciphertext"), h("dd", { class: "cipher-text" }, r.stored.ciphertext),
        ),
      ),
      h(
        "div",
        { class: "rec-actions" },
        h("button", {
          class: "btn btn-sm",
          type: "button",
          onclick: (e) => {
            const on = el.classList.toggle("show-cipher");
            e.currentTarget.textContent = on ? "Show decrypted" : "Show stored ciphertext";
          },
        }, "Show stored ciphertext"),
        h("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => tamper(r.id) }, "Run tamper test"),
        h("button", { class: "btn btn-sm btn-ghost btn-danger", type: "button", onclick: () => remove(r.id) }, "Delete"),
      ),
    ),
  );
  return el;
}

function render() {
  stats();
  const shown = records.filter((r) => filter === "all" || r.category === filter);
  if (!shown.length) {
    list.replaceChildren(
      h(
        "div",
        { class: "empty" },
        h("p", { class: "eyebrow" }, records.length ? "Nothing in this category" : "The vault is empty"),
        h("h3", {}, records.length ? "No matching records." : "Seal your first record."),
        h("p", {}, "Use the form on the left — or press “Fill sample” — and watch the plaintext become AES-256-GCM ciphertext before it is stored."),
      ),
    );
    return;
  }
  list.replaceChildren(...shown.map(card));
}

for (const chip of document.querySelectorAll(".chip")) {
  chip.addEventListener("click", () => {
    filter = chip.dataset.filter;
    for (const c of document.querySelectorAll(".chip")) c.setAttribute("aria-pressed", String(c === chip));
    render();
  });
}

// --- create ----------------------------------------------------------------
const form = document.getElementById("new-record");
const recErr = document.getElementById("rec-error");
const submit = document.getElementById("rec-submit");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  recErr.classList.add("hidden");
  submit.disabled = true;
  submit.textContent = "Encrypting…";
  const body = {
    category: form.category.value,
    title: form.title.value,
    subject: form.subject.value,
    body: form.body.value,
  };
  try {
    const { record } = await api("/api/records", { method: "POST", body });
    records.unshift(record);
    render();
    showReceipt(body, record.stored);
    form.reset();
    toast("Record encrypted and stored.");
  } catch (err) {
    recErr.textContent = err.message;
    recErr.classList.remove("hidden");
  } finally {
    submit.disabled = false;
    submit.textContent = "Encrypt & store";
  }
});

function showReceipt(plain, stored) {
  const box = document.getElementById("receipt");
  box.replaceChildren(
    h("p", { class: "eyebrow" }, "Step 3 · What was just written to disk"),
    h(
      "div",
      { class: "receipt-grid" },
      h("div", {}, h("p", { class: "eyebrow muted" }, "You typed"), h("div", { class: "plain" }, `${plain.title} — ${plain.body.slice(0, 140)}${plain.body.length > 140 ? "…" : ""}`)),
      h("div", { class: "arrow", "aria-hidden": "true" }, "→"),
      h("div", {}, h("p", { class: "eyebrow muted" }, "records.ciphertext"), h("div", { class: "cipher-text" }, stored.ciphertext.slice(0, 260) + (stored.ciphertext.length > 260 ? "…" : ""))),
    ),
  );
  box.classList.remove("hidden");
  box.style.animation = "none";
  void box.offsetWidth;
  box.style.animation = "";
}

const samples = [
  {
    category: "medical",
    title: "Cardiology consult — March 2026",
    subject: "Jordan Reyes · MRN 448-120",
    body: "Echocardiogram: mild mitral regurgitation, EF 58%.\nBP 142/91. Started lisinopril 10 mg daily.\nFollow-up in 6 weeks; repeat lipid panel.",
  },
  {
    category: "financial",
    title: "Q1 brokerage statement",
    subject: "Priya Natarajan · Acct ****7731",
    body: "Portfolio value: $412,880.14\nRealised gains YTD: $18,204.55\nRouting 021000021 · Account 4410 2297 7731\nBeneficiary: R. Natarajan (spouse).",
  },
  {
    category: "medical",
    title: "Psychiatry intake note",
    subject: "Sam Oduya · MRN 902-551",
    body: "Presenting with generalised anxiety, GAD-7 score 14.\nPrescribed sertraline 50 mg. CBT referral placed.\nNo history of self-harm reported.",
  },
  {
    category: "financial",
    title: "Mortgage application — income proof",
    subject: "Elena Kovač · SSN ***-**-4419",
    body: "Gross annual salary: €96,500 (employer: Halden Systems GmbH).\nCredit score: 781. Outstanding debts: car loan €11,300.",
  },
];
let sampleIdx = 0;
document.getElementById("fill-sample").addEventListener("click", () => {
  const s = samples[sampleIdx++ % samples.length];
  form.querySelector(`input[name=category][value=${s.category}]`).checked = true;
  form.title.value = s.title;
  form.subject.value = s.subject;
  form.body.value = s.body;
});

// --- delete / tamper -------------------------------------------------------
async function remove(id) {
  if (!confirm("Permanently delete this encrypted record?")) return;
  try {
    await api(`/api/records/${id}`, { method: "DELETE" });
    records = records.filter((r) => r.id !== id);
    render();
    toast("Record deleted.");
  } catch (err) {
    toast(err.message);
  }
}

const dialog = document.getElementById("tamper");
async function tamper(id) {
  const body = document.getElementById("tamper-body");
  body.replaceChildren(h("div", { class: "skeleton sk-row" }));
  dialog.showModal();
  try {
    const res = await api(`/api/records/${id}/tamper-test`);
    const row = (t) =>
      h(
        "div",
        { class: "trow" },
        h("span", { class: `tag ${t.accepted ? "tag-ok" : "tag-cipher"}` }, t.accepted ? "accepted" : "rejected"),
        h("div", {}, t.label, t.error ? h("span", { class: "err" }, t.error) : null),
      );
    body.replaceChildren(
      row(res.original),
      ...res.tests.map(row),
      h("p", { class: "muted small" }, "AES-GCM verifies its 128-bit tag before releasing any plaintext. A single flipped bit, or moving a row to another user (AAD mismatch), is detected and refused."),
    );
  } catch (err) {
    body.replaceChildren(h("div", { class: "alert" }, err.message));
  }
}

boot();
