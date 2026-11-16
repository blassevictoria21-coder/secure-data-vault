/**
 * Secure Data Vault — cryptography module.
 *
 * Everything security-critical lives in this one file so it can be audited in
 * isolation. Only Node's built-in `node:crypto` (OpenSSL) is used — no
 * hand-rolled primitives.
 *
 *  1. Password hashing   SHA-256 over (16-byte random salt || UTF-8 password)
 *  2. Record encryption  AES-256-GCM, fresh 96-bit IV per write, 128-bit tag,
 *                        owner id bound in as Additional Authenticated Data
 *  3. Key management     one 256-bit master secret (VAULT_MASTER_KEY env var,
 *                        or a separate Netlify Blobs key store)
 *                        → HKDF-SHA-256 → independent sub-keys per purpose
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

const KEY_VERSION = 1;
let cachedKeys: { aes: Buffer; session: Buffer; source: KeySource } | null = null;
export type KeySource = "environment" | "key-store";

function decodeKey(raw: string): Buffer {
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new VaultConfigError("The vault master key must decode to exactly 32 bytes (256 bits).");
  }
  return key;
}

/**
 * Resolves the 256-bit master secret. It is NEVER stored in the database, so a
 * stolen database dump alone cannot be decrypted.
 *
 *  1. Preferred: the VAULT_MASTER_KEY environment variable (base64 or hex).
 *  2. Fallback: a key generated once from the CSPRNG and kept in a dedicated
 *     Netlify Blobs store ("vault-keys"), physically separate from Postgres.
 *     `onlyIfNew` guarantees concurrent cold starts agree on a single key.
 */
async function loadMasterKey(): Promise<{ key: Buffer; source: KeySource }> {
  const env = process.env.VAULT_MASTER_KEY;
  if (env) return { key: decodeKey(env), source: "environment" };

  const { getStore } = await import("@netlify/blobs");
  const store = getStore({ name: "vault-keys", consistency: "strong" });
  let stored = await store.get("master-key-v1");
  if (!stored) {
    await store.set("master-key-v1", randomBytes(32).toString("base64"), { onlyIfNew: true });
    stored = await store.get("master-key-v1");
  }
  if (!stored) throw new VaultConfigError("Unable to load or create the vault master key.");
  return { key: decodeKey(stored), source: "key-store" };
}

/**
 * Derives purpose-specific keys with HKDF so that the AES key and the session
 * signing key are cryptographically independent, even though only one secret
 * has to be provisioned. Called once per server process (see index.ts).
 */
let loading: Promise<void> | null = null;
export function ensureKeys(): Promise<void> {
  if (cachedKeys) return Promise.resolve();
  loading ??= loadMasterKey()
    .then(({ key, source }) => {
      const salt = Buffer.from("secure-data-vault/v1");
      cachedKeys = {
        aes: Buffer.from(hkdfSync("sha256", key, salt, "records-aes-256-gcm", 32)),
        session: Buffer.from(hkdfSync("sha256", key, salt, "session-hmac-sha256", 32)),
        source,
      };
    })
    .finally(() => {
      loading = null;
    });
  return loading;
}

function keys() {
  if (!cachedKeys) throw new VaultConfigError("Vault keys requested before ensureKeys() resolved.");
  return cachedKeys;
}

export function keySource(): KeySource {
  return keys().source;
}

export function sessionKey(): Buffer {
  return keys().session;
}

export class VaultConfigError extends Error {}

// ---------------------------------------------------------------------------
// 1. Password hashing — SHA-256 + cryptographic salt
// ---------------------------------------------------------------------------

export const SALT_BYTES = 16;

/** Generates a fresh 128-bit salt from the OS CSPRNG. */
export function generateSalt(): string {
  return randomBytes(SALT_BYTES).toString("hex");
}

/** hex( SHA-256( salt_bytes || utf8(password) ) ) */
export function hashPassword(password: string, saltHex: string): string {
  return createHash("sha256")
    .update(Buffer.from(saltHex, "hex"))
    .update(Buffer.from(password.normalize("NFKC"), "utf8"))
    .digest("hex");
}

/** Recomputes the hash and compares in constant time (no timing side channel). */
export function verifyPassword(password: string, saltHex: string, expectedHashHex: string): boolean {
  const actual = Buffer.from(hashPassword(password, saltHex), "hex");
  const expected = Buffer.from(expectedHashHex, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// ---------------------------------------------------------------------------
// 2. Record encryption — AES-256-GCM
// ---------------------------------------------------------------------------

export const CIPHER = "aes-256-gcm";
const IV_BYTES = 12; // 96-bit nonce, the size recommended by NIST SP 800-38D
const TAG_BYTES = 16; // 128-bit authentication tag

export interface EncryptedPayload {
  ciphertext: string; // base64
  iv: string; // base64
  authTag: string; // base64
  keyVersion: number;
}

/** Binds a ciphertext to its owner so rows cannot be swapped between users. */
function aadFor(ownerId: number): Buffer {
  return Buffer.from(`secure-data-vault:record:owner=${ownerId}`, "utf8");
}

export function encryptRecord(plaintext: string, ownerId: number): EncryptedPayload {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(CIPHER, keys().aes, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aadFor(ownerId));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    keyVersion: KEY_VERSION,
  };
}

/** Throws if the ciphertext, IV, tag, owner or key has been tampered with. */
export function decryptRecord(payload: Omit<EncryptedPayload, "keyVersion">, ownerId: number): string {
  const decipher = createDecipheriv(CIPHER, keys().aes, Buffer.from(payload.iv, "base64"), {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(aadFor(ownerId));
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}
