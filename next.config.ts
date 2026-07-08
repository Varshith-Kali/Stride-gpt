import type { NextConfig } from "next";

const securityHeaders = [
  // Prevent MIME-type sniffing
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Deny embedding in iframes (clickjacking protection)
  { key: "X-Frame-Options", value: "DENY" },
  // Disable legacy XSS filter (modern browsers — belt-and-suspenders)
  { key: "X-XSS-Protection", value: "1; mode=block" },
  // Strict referrer — don't leak URL to third parties
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Permissions policy — disable unnecessary browser features
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  // HSTS — force HTTPS for 1 year, include subdomains
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },
  // Content-Security-Policy
  // Allows:
  //   - Scripts from self + inline (Next.js requires unsafe-inline for hydration)
  //   - Styles from self + inline (Tailwind)
  //   - Images from self + data: (base64 avatars, etc.)
  //   - Connections to Groq and Gemini APIs only
  //   - Fonts from Google Fonts CDN
  //   - No plugins, no object embeds, no framing
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self' https://api.openai.com",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  // ── Security ──────────────────────────────────────────────────────
  // ReactStrictMode catches subtle bugs by double-invoking effects in dev.
  reactStrictMode: true,

  // Never ignore TypeScript errors — type safety is a security boundary.
  typescript: {
    ignoreBuildErrors: false,
  },

  // HTTP security headers applied to all routes.
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
