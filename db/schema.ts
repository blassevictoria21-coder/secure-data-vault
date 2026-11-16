/**
 * Secure Data Vault — database schema (Netlify Database / Postgres).
 *
 * Two tables, exactly as the specification requires:
 *   users   — dashboard accounts. Passwords are NEVER stored; only a random
 *             per-user salt and SHA-256(salt || password).
 *   records — highly sensitive medical / financial files. The sensitive text
 *             (title, subject, body) is serialised and encrypted with
 *             AES-256-GCM before it is written. Only ciphertext, the IV and the
 *             GCM authentication tag reach the disk.
 */
import { pgTable, serial, text, timestamp, integer, smallint, index } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial().primaryKey(),
  username: text().notNull().unique(),
  fullName: text("full_name").notNull(),
  /** 16 random bytes from a CSPRNG, hex-encoded (32 chars). Unique per user. */
  passwordSalt: text("password_salt").notNull(),
  /** hex(SHA-256(salt_bytes || utf8(password))) — 64 hex chars. */
  passwordHash: text("password_hash").notNull(),
  hashAlgorithm: text("hash_algorithm").notNull().default("SHA-256"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
});

export const records = pgTable(
  "records",
  {
    id: serial().primaryKey(),
    ownerId: integer("owner_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** Non-sensitive classification used for filtering: "medical" | "financial". */
    category: text().notNull(),
    /** base64(AES-256-GCM ciphertext of the JSON payload {title, subject, body}). */
    ciphertext: text().notNull(),
    /** base64 of the 96-bit random nonce. A fresh IV is generated for every write. */
    iv: text().notNull(),
    /** base64 of the 128-bit GCM authentication tag (integrity + authenticity). */
    authTag: text("auth_tag").notNull(),
    cipherAlgorithm: text("cipher_algorithm").notNull().default("AES-256-GCM"),
    keyVersion: smallint("key_version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("records_owner_idx").on(t.ownerId)],
);

export type User = typeof users.$inferSelect;
export type VaultRecord = typeof records.$inferSelect;
