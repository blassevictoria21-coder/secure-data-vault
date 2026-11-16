import { api, h, logout } from "./api.js";

document.getElementById("logout").addEventListener("click", logout);

const iso = (v) => (v ? new Date(v).toISOString().replace("T", " ").slice(0, 19) : "NULL");

function table(el, columns, rows, rowClass) {
  el.replaceChildren(
    h("thead", {}, h("tr", {}, columns.map((c) => h("th", {}, c.key)))),
    h(
      "tbody",
      {},
      rows.length
        ? rows.map((r) =>
            h("tr", { class: rowClass?.(r) }, columns.map((c) => h("td", { class: c.cls }, c.fmt ? c.fmt(r[c.prop]) : String(r[c.prop] ?? "NULL")))),
          )
        : h("tr", {}, h("td", { colspan: columns.length }, "No rows yet — add a record from the Records screen.")),
    ),
  );
}

async function boot() {
  let data;
  try {
    const { user } = await api("/api/auth/me");
    document.getElementById("who").textContent = user.username;
    data = await api("/api/evidence");
  } catch {
    location.replace("/");
    return;
  }

  document.getElementById("q-users").textContent = data.queries.users;
  document.getElementById("q-records").textContent = data.queries.records;
  document.getElementById("ev-meta").replaceChildren(
    h("span", {}, "captured ", h("b", {}, new Date().toISOString())),
    h("span", {}, "engine ", h("b", {}, "Netlify Database · PostgreSQL")),
    h("span", {}, "master key source ", h("b", {}, data.keySource === "environment" ? "VAULT_MASTER_KEY env var" : "isolated key store (Netlify Blobs)")),
    h("span", {}, "key stored in database ", h("b", {}, "never")),
  );

  table(
    document.getElementById("t-users"),
    [
      { key: "id", prop: "id" },
      { key: "username", prop: "username" },
      { key: "full_name", prop: "fullName" },
      { key: "password_salt", prop: "passwordSalt", cls: "h" },
      { key: "password_hash", prop: "passwordHash", cls: "h" },
      { key: "hash_algorithm", prop: "hashAlgorithm" },
      { key: "created_at", prop: "createdAt", fmt: iso, cls: "nowrap" },
      { key: "last_login_at", prop: "lastLoginAt", fmt: iso, cls: "nowrap" },
    ],
    data.users,
  );
  const u = data.users[0];
  document.getElementById("c-users").replaceChildren(
    h("li", {}, "No password column exists"),
    h("li", {}, `Salt is ${u ? u.passwordSalt.length / 2 : 16} random bytes`),
    h("li", {}, `Hash is ${u ? u.passwordHash.length * 4 : 256}-bit SHA-256 digest`),
  );

  table(
    document.getElementById("t-records"),
    [
      { key: "id", prop: "id" },
      { key: "owner_id", prop: "ownerId" },
      { key: "category", prop: "category" },
      { key: "ciphertext", prop: "ciphertext", cls: "c" },
      { key: "iv", prop: "iv", cls: "h" },
      { key: "auth_tag", prop: "authTag", cls: "h" },
      { key: "cipher_algorithm", prop: "cipherAlgorithm", cls: "nowrap" },
      { key: "key_version", prop: "keyVersion" },
      { key: "created_at", prop: "createdAt", fmt: iso, cls: "nowrap" },
    ],
    data.records,
    (r) => (r.ownedByYou ? "mine" : null),
  );
  const ivs = new Set(data.records.map((r) => r.iv));
  document.getElementById("c-records").replaceChildren(
    h("li", {}, "No title, subject or body column in plaintext"),
    h("li", {}, `${ivs.size} unique IVs across ${data.records.length} rows`),
    h("li", {}, "Every row carries a 128-bit GCM tag"),
    h("li", {}, "Brass edge = rows you own"),
  );
}

boot();
