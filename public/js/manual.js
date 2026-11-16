import { api, h } from "./api.js";

document.getElementById("print").addEventListener("click", () => window.print());
document.getElementById("cover-date").textContent = new Date().toLocaleDateString(undefined, { dateStyle: "long" });
document.getElementById("cover-url").textContent = location.host;

// --- screenshot slots: images stay local (object URLs), never uploaded ----
for (const shot of document.querySelectorAll(".shot")) {
  const input = shot.querySelector("input[type=file]");
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (!file) return;
    const img = h("img", { src: URL.createObjectURL(file), alt: shot.nextElementSibling?.textContent || "Screenshot" });
    img.addEventListener("click", () => input.click());
    shot.replaceChildren(img, input);
    shot.classList.add("has-img");
  });
}

// --- live evidence (only when signed in) -----------------------------------
const iso = (v) => (v ? new Date(v).toISOString().replace("T", " ").slice(0, 19) : "NULL");
function fill(table, cols, rows) {
  table.replaceChildren(
    h("thead", {}, h("tr", {}, cols.map(([k]) => h("th", {}, k)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, cols.map(([, p, cls, fmt]) => h("td", { class: cls }, fmt ? fmt(r[p]) : String(r[p] ?? "NULL")))))),
  );
}
api("/api/evidence")
  .then((data) => {
    const when = new Date().toISOString();
    for (const el of document.querySelectorAll(".cap-time")) el.textContent = when;
    fill(document.getElementById("lu"), [
      ["id", "id"], ["username", "username"], ["password_salt", "passwordSalt", "c"],
      ["password_hash", "passwordHash", "c"], ["hash_algorithm", "hashAlgorithm"], ["created_at", "createdAt", "", iso],
    ], data.users);
    fill(document.getElementById("lr"), [
      ["id", "id"], ["owner_id", "ownerId"], ["category", "category"], ["ciphertext", "ciphertext", "c", (v) => (v.length > 180 ? v.slice(0, 180) + "…" : v)],
      ["iv", "iv", "c"], ["auth_tag", "authTag", "c"], ["key_version", "keyVersion"],
    ], data.records.slice(0, 8));
    document.getElementById("live-users").classList.remove("hidden");
    if (data.records.length) document.getElementById("live-records").classList.remove("hidden");
    document.getElementById("live-status").textContent = `Live evidence embedded · ${data.records.length} record rows`;
  })
  .catch(() => {});

// --- Appendix A: raw source ------------------------------------------------
fetch("/source/manifest.json")
  .then((r) => (r.ok ? r.json() : Promise.reject()))
  .then(async ({ groups }) => {
    const out = [];
    let n = 1;
    for (const g of groups) {
      out.push(h("h3", {}, `A.${n++} ${g.title}`));
      for (const f of g.files) {
        const text = await fetch(f.url).then((r) => r.text());
        out.push(h("div", { class: "src-file" }, h("h4", {}, f.path, h("span", {}, `${f.lines} lines`)), h("pre", {}, h("code", {}, text))));
      }
    }
    document.getElementById("source").replaceChildren(...out);
  })
  .catch(() => {
    document.getElementById("source").replaceChildren(h("p", { class: "muted" }, "Source export not found — it is generated during the deploy build (npm run build)."));
  });
