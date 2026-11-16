/**
 * Secure Data Vault — API server (Netlify Server, Hono).
 *
 * Routes
 *   POST   /api/auth/register   create account  (salt + SHA-256 hash stored)
 *   POST   /api/auth/login      verify password, issue signed session cookie
 *   POST   /api/auth/logout     clear session
 *   GET    /api/auth/me         current user
 *   GET    /api/records         query + AES-GCM decrypt the caller's rows
 *   POST   /api/records         AES-GCM encrypt + insert a record
 *   DELETE /api/records/:id     delete one of the caller's records
 *   GET    /api/records/:id/tamper-test   prove GCM rejects modified ciphertext
 *   GET    /api/evidence        raw, undecrypted rows exactly as stored on disk
 */
import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import { records, users } from "../../db/schema.js";
import {
  VaultConfigError,
  decryptRecord,
  encryptRecord,
  ensureKeys,
  keySource,
  generateSalt,
  hashPassword,
  verifyPassword,
} from "./lib/crypto.js";
import { clearSession, issueSession, readSession } from "./lib/session.js";

type Env = { Variables: { userId: number } };
const app = new Hono<Env>();

const CATEGORIES = ["medical", "financial"] as const;
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
// Used to keep login timing identical whether or not the username exists.
const DUMMY_SALT = "00000000000000000000000000000000";
const DUMMY_HASH = "0".repeat(64);

// --- hardening headers on every API response -------------------------------
app.use("/api/*", async (c, next) => {
  await next();
  c.header("Cache-Control", "no-store");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
});

// --- load / derive the encryption + session keys once per process -------
app.use("/api/*", async (_c, next) => {
  await ensureKeys();
  await next();
});

// --- CSRF defence: state-changing requests must be same-origin JSON ---------
app.use("/api/*", async (c, next) => {
  if (c.req.method !== "GET") {
    const origin = c.req.header("origin");
    const allowed = new Set(
      [c.req.header("x-forwarded-host"), c.req.header("host"), new URL(c.req.url).host].filter(Boolean),
    );
    let originHost = "";
    try {
      originHost = origin ? new URL(origin).host : "";
    } catch {
      originHost = "invalid";
    }
    if (origin && !allowed.has(originHost)) {
      return c.json({ error: "Cross-origin request rejected." }, 403);
    }
  }
  await next();
});

app.onError((err, c) => {
  if (err instanceof VaultConfigError) {
    console.error(err.message);
    return c.json({ error: "The vault encryption key could not be loaded on the server." }, 503);
  }
  console.error(err);
  return c.json({ error: "Internal server error." }, 500);
});

async function readJson(c: { req: { json: () => Promise<unknown> } }): Promise<Record<string, unknown>> {
  try {
    const body = await c.req.json();
    return body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
const str = (v: unknown) => (typeof v === "string" ? v : "");

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

app.post("/api/auth/register", async (c) => {
  const body = await readJson(c);
  const username = str(body.username).trim().toLowerCase();
  const fullName = str(body.fullName).trim();
  const password = str(body.password);

  if (!USERNAME_RE.test(username))
    return c.json({ error: "Username must be 3–32 characters: a–z, 0–9, dot, dash or underscore." }, 400);
  if (fullName.length < 2 || fullName.length > 80)
    return c.json({ error: "Please enter your full name (2–80 characters)." }, 400);
  if (password.length < 10 || password.length > 128)
    return c.json({ error: "Password must be between 10 and 128 characters." }, 400);

  const existing = await db.select({ id: users.id }).from(users).where(eq(users.username, username));
  if (existing.length) return c.json({ error: "That username is already taken." }, 409);

  // STEP 2 — salt + SHA-256. The plaintext password never leaves this function.
  const passwordSalt = generateSalt();
  const passwordHash = hashPassword(password, passwordSalt);

  const [user] = await db
    .insert(users)
    .values({ username, fullName, passwordSalt, passwordHash, lastLoginAt: new Date() })
    .returning({ id: users.id, username: users.username, fullName: users.fullName });

  issueSession(c, user.id);
  return c.json({ user }, 201);
});

app.post("/api/auth/login", async (c) => {
  const body = await readJson(c);
  const username = str(body.username).trim().toLowerCase();
  const password = str(body.password);

  const [user] = await db.select().from(users).where(eq(users.username, username));
  const ok = user
    ? verifyPassword(password, user.passwordSalt, user.passwordHash)
    : (verifyPassword(password, DUMMY_SALT, DUMMY_HASH), false);

  if (!user || !ok) return c.json({ error: "Invalid username or password." }, 401);

  await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
  issueSession(c, user.id);
  return c.json({ user: { id: user.id, username: user.username, fullName: user.fullName } });
});

app.post("/api/auth/logout", (c) => {
  clearSession(c);
  return c.json({ ok: true });
});

// --- everything below requires a valid session ----------------------------
const requireAuth = async (c: any, next: () => Promise<void>) => {
  const userId = readSession(c);
  if (!userId) return c.json({ error: "Not signed in." }, 401);
  c.set("userId", userId);
  await next();
};
app.use("/api/auth/me", requireAuth);
app.use("/api/records", requireAuth);
app.use("/api/records/*", requireAuth);
app.use("/api/evidence", requireAuth);

app.get("/api/auth/me", async (c) => {
  const [user] = await db
    .select({
      id: users.id,
      username: users.username,
      fullName: users.fullName,
      createdAt: users.createdAt,
      lastLoginAt: users.lastLoginAt,
    })
    .from(users)
    .where(eq(users.id, c.get("userId")));
  if (!user) {
    clearSession(c);
    return c.json({ error: "Not signed in." }, 401);
  }
  return c.json({ user });
});

// ---------------------------------------------------------------------------
// Records — encrypt on write, decrypt on authorised read
// ---------------------------------------------------------------------------

app.get("/api/records", async (c) => {
  const userId = c.get("userId");
  // STEP 4 — query only the caller's rows, then decrypt each one.
  const rows = await db
    .select()
    .from(records)
    .where(eq(records.ownerId, userId))
    .orderBy(desc(records.createdAt));

  const decrypted = rows.map((row) => {
    const meta = {
      id: row.id,
      category: row.category,
      createdAt: row.createdAt,
      stored: { ciphertext: row.ciphertext, iv: row.iv, authTag: row.authTag, cipherAlgorithm: row.cipherAlgorithm },
    };
    try {
      const data = JSON.parse(decryptRecord(row, userId));
      return { ...meta, integrity: "verified", title: data.title, subject: data.subject, body: data.body };
    } catch {
      // GCM tag mismatch: the row was modified on disk or the key is wrong.
      return { ...meta, integrity: "failed" };
    }
  });
  return c.json({ records: decrypted });
});

app.post("/api/records", async (c) => {
  const userId = c.get("userId");
  const body = await readJson(c);
  const category = str(body.category);
  const title = str(body.title).trim();
  const subject = str(body.subject).trim();
  const content = str(body.body).trim();

  if (!CATEGORIES.includes(category as (typeof CATEGORIES)[number]))
    return c.json({ error: "Category must be medical or financial." }, 400);
  if (!title || title.length > 120) return c.json({ error: "Title is required (max 120 characters)." }, 400);
  if (subject.length > 120) return c.json({ error: "Subject must be 120 characters or fewer." }, 400);
  if (!content || content.length > 10_000)
    return c.json({ error: "Record body is required (max 10,000 characters)." }, 400);

  // STEP 3 — serialise every sensitive field and encrypt BEFORE the INSERT.
  const sealed = encryptRecord(JSON.stringify({ title, subject, body: content }), userId);

  const [row] = await db
    .insert(records)
    .values({ ownerId: userId, category, ...sealed })
    .returning();

  return c.json(
    {
      record: {
        id: row.id,
        category,
        createdAt: row.createdAt,
        title,
        subject,
        body: content,
        integrity: "verified",
        stored: { ciphertext: row.ciphertext, iv: row.iv, authTag: row.authTag, cipherAlgorithm: row.cipherAlgorithm },
      },
    },
    201,
  );
});

app.delete("/api/records/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id)) return c.json({ error: "Invalid id." }, 400);
  const deleted = await db
    .delete(records)
    .where(and(eq(records.id, id), eq(records.ownerId, c.get("userId"))))
    .returning({ id: records.id });
  if (!deleted.length) return c.json({ error: "Record not found." }, 404);
  return c.json({ ok: true });
});

/** Flips one bit of a stored ciphertext in memory and shows GCM refusing it. */
app.get("/api/records/:id/tamper-test", async (c) => {
  const userId = c.get("userId");
  const id = Number(c.req.param("id"));
  const [row] = await db
    .select()
    .from(records)
    .where(and(eq(records.id, id), eq(records.ownerId, userId)));
  if (!row) return c.json({ error: "Record not found." }, 404);

  const bytes = Buffer.from(row.ciphertext, "base64");
  bytes[0] ^= 0x01;
  const tampered = { ...row, ciphertext: bytes.toString("base64") };

  const attempt = (label: string, fn: () => string) => {
    try {
      fn();
      return { label, accepted: true };
    } catch (e) {
      return { label, accepted: false, error: (e as Error).message };
    }
  };
  return c.json({
    original: attempt("Original row, correct owner", () => decryptRecord(row, userId)),
    tests: [
      attempt("1 bit flipped in ciphertext", () => decryptRecord(tampered, userId)),
      attempt("Row re-assigned to another owner (AAD mismatch)", () => decryptRecord(row, userId + 1)),
    ],
  });
});

// ---------------------------------------------------------------------------
// Evidence — raw database view (what an attacker with disk access would see)
// ---------------------------------------------------------------------------

app.get("/api/evidence", async (c) => {
  const userId = c.get("userId");
  const userRows = await db.select().from(users).where(eq(users.id, userId));
  const recordRows = await db.select().from(records).orderBy(desc(records.id)).limit(50);
  return c.json({
    keySource: keySource(),
    queries: {
      users: `SELECT * FROM users WHERE id = ${userId};`,
      records: "SELECT * FROM records ORDER BY id DESC LIMIT 50;",
    },
    users: userRows,
    records: recordRows.map((r) => ({ ...r, ownedByYou: r.ownerId === userId })),
  });
});

app.all("/api/*", (c) => c.json({ error: "Not found." }, 404));

export default app;

export const config = { path: "/api/*" };
