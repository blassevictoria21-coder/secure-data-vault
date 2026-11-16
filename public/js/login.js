import { api } from "./api.js";

// Already signed in? Go straight to the dashboard.
api("/api/auth/me").then(() => location.replace("/dashboard.html")).catch(() => {});

const form = document.getElementById("auth-form");
const errorBox = document.getElementById("auth-error");
const submit = document.getElementById("auth-submit");
const pw = document.getElementById("password");
let mode = "login";

function setMode(next) {
  mode = next;
  for (const t of document.querySelectorAll(".tab")) t.setAttribute("aria-selected", String(t.dataset.mode === mode));
  for (const el of document.querySelectorAll(".register-only")) el.classList.toggle("hidden", mode !== "register");
  submit.textContent = mode === "login" ? "Unlock vault" : "Create account & hash password";
  pw.autocomplete = mode === "login" ? "current-password" : "new-password";
  errorBox.classList.add("hidden");
  if (mode === "register") refreshPreview();
}
for (const t of document.querySelectorAll(".tab")) t.addEventListener("click", () => setMode(t.dataset.mode));

// --- illustrative hash preview (the server generates the real salt) -------
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
let previewSalt = crypto.getRandomValues(new Uint8Array(16));
document.getElementById("hp-salt").textContent = hex(previewSalt);
async function refreshPreview() {
  const out = document.getElementById("hp-hash");
  if (!pw.value) { out.textContent = "type a password…"; return; }
  const bytes = new Uint8Array([...previewSalt, ...new TextEncoder().encode(pw.value.normalize("NFKC"))]);
  out.textContent = hex(await crypto.subtle.digest("SHA-256", bytes));
}
pw.addEventListener("input", () => mode === "register" && refreshPreview());

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.classList.add("hidden");
  submit.disabled = true;
  const original = submit.textContent;
  submit.textContent = mode === "login" ? "Verifying hash…" : "Hashing & storing…";
  try {
    const body = {
      username: form.username.value,
      password: form.password.value,
      ...(mode === "register" ? { fullName: form.fullName.value } : {}),
    };
    await api(mode === "login" ? "/api/auth/login" : "/api/auth/register", { method: "POST", body });
    location.href = "/dashboard.html";
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
    submit.disabled = false;
    submit.textContent = original;
  }
});

// --- hero animation: a sample record visibly turning into ciphertext -------
const samples = [
  "Diagnosis: Type 2 diabetes — HbA1c 7.9%",
  "IBAN GB29 NWBK 6016 1331 9268 19 · balance £48,210",
  "Prescription: Sertraline 50 mg, once daily",
  "Salary slip: gross $112,400 · tax ID 914-22-0871",
];
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const randB64 = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => B64[b & 63]).join("");
const plainEl = document.getElementById("spec-plain");
const cipherEl = document.getElementById("spec-cipher");
let i = 0;
function cycle() {
  const text = samples[i++ % samples.length];
  plainEl.textContent = text;
  let frame = 0;
  const target = randB64(Math.ceil((text.length * 4) / 3)) + "==";
  const tick = () => {
    frame++;
    const settled = Math.floor((frame / 24) * target.length);
    cipherEl.textContent = target.slice(0, settled) + randB64(Math.max(0, target.length - settled));
    if (settled < target.length) requestAnimationFrame(tick);
  };
  tick();
}
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
cycle();
if (!reduced) setInterval(cycle, 4200);

const rain = document.getElementById("rain");
rain.textContent = Array.from({ length: 48 }, () => randB64(90)).join("\n");
