CREATE TABLE "records" (
	"id" serial PRIMARY KEY,
	"owner_id" integer NOT NULL,
	"category" text NOT NULL,
	"ciphertext" text NOT NULL,
	"iv" text NOT NULL,
	"auth_tag" text NOT NULL,
	"cipher_algorithm" text DEFAULT 'AES-256-GCM' NOT NULL,
	"key_version" smallint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"username" text NOT NULL UNIQUE,
	"full_name" text NOT NULL,
	"password_salt" text NOT NULL,
	"password_hash" text NOT NULL,
	"hash_algorithm" text DEFAULT 'SHA-256' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX "records_owner_idx" ON "records" ("owner_id");--> statement-breakpoint
ALTER TABLE "records" ADD CONSTRAINT "records_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE CASCADE;