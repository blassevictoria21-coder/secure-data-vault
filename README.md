# Secure Data Vault

A web dashboard and database that protect highly sensitive **medical and financial records at rest**:

- **Users table**: passwords are salted (16-byte CSPRNG salt) and hashed with **SHA-256**. There is no password column.
- **Records table**: title, subject and body are encrypted with **AES-256-GCM** (random 96-bit IV per row, 128-bit auth tag, owner id bound as AAD) *before* the `INSERT`.
- **Secure retrieval**: after login (HMAC-signed, HttpOnly, SameSite=Strict session), the server queries only the owner's rows, verifies each GCM tag, decrypts, and shows the plaintext.

It also ships the project deliverables as pages in the site:

| Page | Purpose |
| --- | --- |
| `/` | Landing page + login / create account (with live salted-hash preview) |
| `/dashboard.html` | Seal new records, view decrypted records, toggle stored ciphertext, run tamper tests |
| `/evidence.html` | Raw database viewer showing hashes and ciphertext exactly as stored (for screenshots) |
| `/manual.html` | Security Manual, print-ready as a PDF, with live DB evidence, screenshot slots and the full source code appended |
| `/deck.html` | 10-slide Project Defense Deck (arrow keys, `N` for speaker notes, `F` for fullscreen, export to PDF) |

## Tech stack

- **Netlify Server** running a [Hono](https://hono.dev) API (`netlify/server/index.ts`)
- **Netlify Database** (managed PostgreSQL) with **Drizzle ORM**; migrations in `netlify/database/migrations/`
- **node:crypto** (OpenSSL): SHA-256, AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, CSPRNG
- Static HTML/CSS/ES-module dashboard in `public/` with a strict Content-Security-Policy

## Encryption key

All keys are derived with HKDF from one 256-bit master key:

1. **`VAULT_MASTER_KEY`** environment variable (recommended), 32 bytes as base64 or hex, e.g. `openssl rand -base64 32`.
2. If that is not set, the server generates a key once and keeps it in a dedicated Netlify Blobs store (`vault-keys`), which is separate from the database.

Never change the key once records exist, or they can no longer be decrypted.

## Running locally

```bash
npm install
netlify dev            # emulates the server, database and blobs locally
```

Then open the URL printed by the CLI, create an account, and click **Fill sample** to add records.

## Producing the deliverables

1. Create an account and add a few records.
2. Screenshot `/` (Create account tab), `/dashboard.html` and `/evidence.html`. Also screenshot the same queries in a PostgreSQL client or with `netlify db connect --query "SELECT * FROM users"`.
3. Open `/manual.html`, fill in the cover fields, attach the screenshots to the figure slots, and press **Download PDF**.
4. Open `/deck.html`, edit the byline on slide 1, and present it, or **Export PDF**.

## Schema changes

Edit `db/schema.ts`, then run `npx drizzle-kit generate --name <change>`. Migrations are applied automatically on deploy.
