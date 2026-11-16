/**
 * Stateless, tamper-proof session tokens.
 *
 * token = base64url(JSON{uid, exp}) + "." + base64url(HMAC-SHA-256(sessionKey, body))
 *
 * Delivered as an HttpOnly, Secure, SameSite=Strict cookie so page scripts can
 * never read it and other sites can never send it.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { sessionKey } from "./crypto.js";

export const COOKIE = "vault_session";
const TTL_SECONDS = 60 * 30; // 30-minute sessions

function sign(body: string): string {
  return createHmac("sha256", sessionKey()).update(body).digest("base64url");
}

export function issueSession(c: Context, userId: number) {
  const body = Buffer.from(
    JSON.stringify({ uid: userId, exp: Math.floor(Date.now() / 1000) + TTL_SECONDS }),
  ).toString("base64url");
  setCookie(c, COOKIE, `${body}.${sign(body)}`, {
    httpOnly: true,
    secure: true, // browsers also honour Secure cookies on http://localhost
    sameSite: "Strict",
    path: "/",
    maxAge: TTL_SECONDS,
  });
}

export function clearSession(c: Context) {
  deleteCookie(c, COOKIE, { path: "/" });
}

/** Returns the authenticated user id, or null if the token is missing, forged or expired. */
export function readSession(c: Context): number | null {
  const token = getCookie(c, COOKIE);
  if (!token) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expected = Buffer.from(sign(body));
  const given = Buffer.from(mac);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const { uid, exp } = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof uid !== "number" || typeof exp !== "number" || exp < Date.now() / 1000) return null;
    return uid;
  } catch {
    return null;
  }
}
