import type { NextConfig } from "next";

const securityHeaders = [
  // ── Prevent MIME-type sniffing ───────────────────────────────────────────
  { key: "X-Content-Type-Options", value: "nosniff" },


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
];

const nextConfig: NextConfig = {
  output: "standalone",

  allowedDevOrigins: [
    "*.run.app",
    "**.run.app",
    "**.google.com",
    "**.googlers.com",
    "**.googleusercontent.com",
    "localhost",
    "127.0.0.1",
  ],

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
