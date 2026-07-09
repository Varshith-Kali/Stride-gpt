import type { NextConfig } from "next";

const securityHeaders = [
  // ── Prevent MIME-type sniffing ───────────────────────────────────────────
  { key: "X-Content-Type-Options", value: "nosniff" },

  // ── Clickjacking protection ──────────────────────────────────────────────
  { key: "X-Frame-Options", value: "DENY" },

  // ── XSS filter (legacy browsers) ────────────────────────────────────────
  { key: "X-XSS-Protection", value: "1; mode=block" },

  // ── Strict referrer — never leak URL to third parties ───────────────────
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },

  // ── Disable unnecessary browser features ────────────────────────────────
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },

  // ── HSTS — enforce HTTPS for 1 year including subdomains ─────────────────
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },

  // ── Cross-Origin isolation (Spectre / side-channel mitigation) ───────────
  // COOP: prevents other windows from acquiring a reference to this window.
  { key: "Cross-Origin-Opener-Policy",   value: "same-origin" },
  // COEP: blocks cross-origin resources unless they opt in via CORP/CORS.
  { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
  // CORP: prevents other origins from reading this resource.
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },

  // ── Content-Security-Policy ──────────────────────────────────────────────
  // Key decisions:
  //   script-src: 'unsafe-eval' REMOVED — not needed in production Next.js.
  //               'unsafe-inline' still required for Next.js hydration.
  //   connect-src: https://api.openai.com REMOVED — all LLM calls are made
  //               server-side via Next.js API routes. The browser NEVER
  //               contacts OpenAI directly, so allowing it client-side was
  //               an unnecessary attack surface (and would expose the API key
  //               flow if the app were ever misconfigured).
  //   img-src:    data: + blob: retained for base64 image previews in the
  //               upload zone.
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  // ── Security ──────────────────────────────────────────────────────────────
  reactStrictMode: true,

  typescript: {
    ignoreBuildErrors: false,
  },

  // Hide the Next.js dev-mode floating indicator.
  devIndicators: false,

  // HTTP security headers on every route.
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
