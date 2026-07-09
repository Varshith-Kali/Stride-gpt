/**
 * Next.js Edge Proxy — per-request security hardening.
 *
 * Runs before every request on the Edge runtime (fastest possible path).
 * In Next.js 16+, this file is named "proxy.ts" (replaces "middleware.ts").
 *
 * Responsibilities:
 *   1. Generate a cryptographic nonce for every HTML page response.
 *   2. Thread the nonce into the Content-Security-Policy header so that
 *      Next.js inline scripts are explicitly allowlisted by nonce, rather
 *      than by the blanket 'unsafe-inline' keyword.
 *   3. Expose the nonce via a request header (x-nonce) so layout.tsx can
 *      read it and apply it during SSR.
 *
 * Security note:
 *   A nonce-based CSP is strictly stronger than 'unsafe-inline' because:
 *     - Each nonce is a random, single-use 16-byte value (base64-encoded).
 *     - An attacker injecting a <script> tag cannot know the nonce ahead
 *       of time — their script is blocked even if 'unsafe-inline' is absent.
 *   We keep 'unsafe-inline' as a FALLBACK only for browsers that don't
 *   support nonces (very old Safari / IE11). Modern browsers honour the
 *   nonce and ignore 'unsafe-inline' when a nonce is present.
 *
 * References:
 *   https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
 *   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
 */

import { NextResponse, type NextRequest } from "next/server";

export const config = {
  /**
   * Run middleware on every route EXCEPT:
   *   - Static files served from /_next/static/
   *   - Public assets (/_next/image, /favicon.ico, /icon.*)
   * API routes (/api/*) also receive the nonce for response tracing,
   * but the CSP header only matters for HTML pages.
   */
  matcher: [
    "/((?!_next/static|_next/image|favicon\\.ico|icon\\.|robots\\.txt|sitemap\\.xml).*)",
  ],
};

export function middleware(req: NextRequest): NextResponse {
  // --- 1. Generate a cryptographic nonce --------------------------------
  // 16 random bytes → 22-char base64url string. Unpredictable per request.
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");

  // --- 2. Build the nonce-hardened CSP ----------------------------------
  const csp = [
    "default-src 'self'",
    // Nonce allowlists Next.js inline scripts explicitly.
    // 'unsafe-inline' is kept as a fallback for browsers without nonce support —
    // modern browsers ignore it when a valid nonce is present.
    `script-src 'self' 'nonce-${nonce}' 'unsafe-inline'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    // connect-src: 'self' only — the browser NEVER calls OpenAI directly.
    // All LLM calls are made server-side via /api/* routes.
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");

  // --- 3. Clone request headers with nonce for SSR ----------------------
  // Next.js layout.tsx can read x-nonce to set the nonce attribute on
  // <script> tags rendered server-side.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);

  const res = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // --- 4. Set security headers on the response --------------------------
  res.headers.set("Content-Security-Policy", csp);

  // x-nonce is exposed to the SSR layer only — never sent to the browser.
  // (It's set on the request headers, not the response headers.)

  return res;
}
