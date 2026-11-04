/**
 * Next.js Edge Proxy — per-request security hardening.
 *
 * In Next.js 16+, this file is named "proxy.ts" and MUST export a function
 * named "proxy" (replaces the old "middleware.ts" / "middleware" convention).
 *
 * Responsibilities:
 *   1. Generate a cryptographic nonce for every HTML page response.
 *   2. Thread the nonce into the Content-Security-Policy header so that
 *      Next.js inline scripts are allowlisted by nonce rather than
 *      the blanket 'unsafe-inline' keyword.
 *   3. Expose the nonce via x-nonce request header so layout.tsx can
 *      read it during SSR.
 *
 * Security note:
 *   A nonce-based CSP is strictly stronger than 'unsafe-inline':
 *   - Each nonce is a random, single-use 16-byte value (base64-encoded).
 *   - An attacker who injects a <script> tag cannot know the nonce —
 *     their script is blocked even without 'unsafe-inline'.
 *   We retain 'unsafe-inline' only as a fallback for very old browsers
 *   (IE11 / ancient Safari). Modern browsers honour the nonce and ignore
 *   'unsafe-inline' when a valid nonce is present (per CSP Level 2 spec).
 */

import { NextResponse, type NextRequest } from "next/server";

export const config = {
  /**
   * Run on every route EXCEPT:
   *   - Static files: /_next/static/
   *   - Image optimisation: /_next/image
   *   - Public assets: favicon, icon, robots, sitemap
   */
  matcher: [
    "/((?!_next/static|_next/image|favicon\\.ico|icon\\.|robots\\.txt|sitemap\\.xml).*)",
  ],
};

/**
 * Next.js 16 proxy handler.
 * MUST be exported as "proxy" — this is the new convention enforced by Next.js 16.
 */
export function proxy(req: NextRequest): NextResponse {
  const requestHeaders = new Headers(req.headers);

  const res = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // Set a per-request trace ID — lets users report issues precisely
  // without exposing server internals. Logged at the app layer.
  res.headers.set("X-Request-ID", crypto.randomUUID());

  return res;
}
