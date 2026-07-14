<div align="center">

<br />

<img src="public/placeholder.svg" alt="STRIDE GPT Shield" width="64" height="64" style="border-radius:14px" />

<br /><br />

# STRIDE GPT

### AI-Powered Threat Modeling Studio

**STRIDE · OWASP LLM Top 10 · MITRE ATT&CK · DREAD · Safety Metrics**

<br />

[![Next.js](https://img.shields.io/badge/Next.js_16-black?logo=next.js&logoColor=white)](https://nextjs.org)
[![React](https://img.shields.io/badge/React_19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript_5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS_v4-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![OpenAI](https://img.shields.io/badge/OpenAI_GPT--5.5-412991?logo=openai&logoColor=white)](https://openai.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)

<br />

> **Enterprise-grade threat modeling at the speed of AI.**  
> Bring your OpenAI API key. Describe your application. Upload your architecture diagram.  
> Get a complete, analyst-quality threat model in seconds — nothing stored on the server.

<br />

</div>

---

## Table of Contents

- [Overview](#overview)
- [Feature Set](#feature-set)
- [Architecture](#architecture)
- [Security Design](#security-design)
- [Getting Started](#getting-started)
- [Tech Stack](#tech-stack)
- [API Reference](#api-reference)
- [Export Formats](#export-formats)
- [Supported Model](#supported-model)
- [License](#license)

---

## Overview

STRIDE GPT is an open-source, browser-based security analysis studio built for security architects, AppSec engineers, and development teams. It converts application descriptions and architecture diagrams into complete, structured threat models using OpenAI's reasoning models.

**Key design principles:**

- **Zero server-side persistence** — API keys never touch a database or log file
- **Session-only API key** — cleared on browser close or page refresh; never written to `localStorage`
- **Server-side LLM calls only** — the browser never contacts OpenAI directly
- **Input-to-output sanitization** — every field validated, clamped, and stripped before reaching the LLM or the browser
- **Production-hardened** — HSTS, CSP with nonce, COOP/COEP/CORP headers, no `unsafe-eval`

---

## Feature Set

### 🛡️ STRIDE Threat Model *(Core)*

Generates a structured, analyst-quality threat model covering all six STRIDE categories:

| Category | Description |
|----------|-------------|
| **S**poofing | Identity impersonation across components and auth boundaries |
| **T**ampering | Data integrity violations in transit and at rest |
| **R**epudiation | Absence of audit trails and non-repudiation controls |
| **I**nformation Disclosure | Unauthorized data exposure and information leakage |
| **D**enial of Service | Availability attacks on services, queues, and APIs |
| **E**levation of Privilege | Unauthorized permission escalation |

Each threat entry includes:
- Unique threat ID (`T001`–`T020`), affected component, and risk rating (`Low / Medium / High / Critical`)
- Specific attack vector and realistic business impact (not generic descriptions)
- Real MITRE ATT&CK technique IDs (e.g. `T1078 Valid Accounts`)
- OWASP LLM Top 10 and ASI Top 10 mappings for AI/Agentic applications
- Executive summary, architecture notes, and detected patterns

**Architecture diagram support:** Upload PNG / JPEG / WebP diagrams. The model performs a full visual analysis — extracting components, trust boundaries, data flows, authentication touchpoints, and visible misconfigurations — before generating threats. The diagram is treated as ground truth; the text description supplements it.

---

### 🌲 Attack Tree

Decomposes the attacker's primary goal into a nested attack tree with:
- Minimum 3 levels of depth, 6–10 distinct leaf techniques
- Leaf nodes reference specific components (e.g. "Exploit JWT misconfiguration in Auth Service")
- Rendered as an interactive Mermaid diagram
- 2–3 paragraph narrative of the most plausible attack paths and critical chokepoints

---

### 🔧 Mitigations

Architecture-aware, component-specific countermeasures for every identified threat:
- References the specific component, library, framework, or configuration to change
- OWASP (`A01:2021`) and NIST SP 800-53 control references
- Priority calibrated to threat risk level **and** exploitability
- Hardening checklist of 8–10 testable verification steps

---

### 📊 DREAD Risk Scoring

Quantitative risk scoring across five dimensions, calibrated to the deployment context:

| Dimension | Scale | Calibration |
|-----------|-------|-------------|
| Damage | 1–10 | Business/data impact if fully exploited |
| Reproducibility | 1–10 | How reliably the attack can be repeated |
| Exploitability | 1–10 | Skill/resources required (10 = unauthenticated, trivial) |
| Affected Users | 1–10 | Breadth of impact (10 = all users / all tenants) |
| Discoverability | 1–10 | Ease of finding the vulnerability |

**Total / 50** → Severity band: `<10 Low` · `10–19 Medium` · `20–29 High` · `30–50 Critical`

Architecture diagrams are used to calibrate internet-exposure and component-criticality scores.

---

### 🗺️ Data Flow Diagram (DFD)

Auto-generated Level-0 DFD derived from the application description and architecture diagram:
- Components typed as: External Entity · Process · Data Store · Trust Boundary
- Trust zones: `High` (internal) · `Medium` (processing) · `Low` (internet-facing / third-party)
- Rendered as a Mermaid `flowchart LR` with colour-coded trust zones (Trusted / Internal / Untrusted subgraphs)
- Every internet-facing entry point is captured as a component

---

### 🧪 Gherkin / BDD Security Test Cases

Converts each STRIDE threat into a concrete, testable BDD scenario:
- `Given` — real application state naming component/role
- `When` — attacker's specific action against a named component or endpoint
- `Then` — observable system defence response + audit log assertion
- One scenario per threat; scoped to the actual application name and stack

---

### 🔒 Safety Metrics *(Security Posture Evaluation)*

The most analytically rigorous section — evaluates whether your **current security controls** actually mitigate each identified threat:

**Verdict scale:**

| Verdict | Meaning |
|---------|---------|
| 🟢 **SAFE** | Controls fully and demonstrably mitigate this threat. Defence-in-depth exists. Coverage is unambiguous. |
| 🟡 **PARTIALLY SAFE** | Controls exist but leave meaningful gaps, attack surface remains, or only one layer covers a multi-layer threat. |
| 🔴 **UNSAFE** | No controls listed, controls are irrelevant to this specific threat, or controls are clearly insufficient. |

**Evaluation criteria (strictly enforced):**
1. Judged against the specific STRIDE category, attack vector, and MITRE ATT&CK technique
2. A network-layer control does **not** automatically cover application-layer or identity-layer threats
3. Control **quality** over presence — "we use HTTPS" is not a control for SQL injection
4. Errs toward `PARTIALLY_SAFE` over `SAFE` — real security requires defence-in-depth
5. No controls provided → verdict is **always** `UNSAFE`

Each threat card shows: verdict badge, 3–5 sentence reasoning citing the specific control and gap, and up to 7 specific gap items.

**Safety Metrics are included as the last column in the Excel export.**

---

### 🔐 Recommendations *(Prioritized Action Plan)*

Consolidates threats and analyst context into a prioritized remediation roadmap:
- Groups related threats where logical
- Effort rating (`Low / Medium / High`) with risk-reduction statement
- Weighted by analyst justification notes (inline context from the threat review)
- Executive summary paragraph of the overall recommendation posture

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (Client)                         │
│                                                                 │
│  React 19 + Next.js 16 App Router                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Threat Model Studio                                       │  │
│  │  6 tabs: Threats · Attack Tree · Mitigations · DREAD ·   │  │
│  │          DFD · Safety Metrics                             │  │
│  │                                                           │  │
│  │  API key: in-memory only (React state)                    │  │
│  │  Cleared on: browser close / page refresh / New Analysis │  │
│  └──────────────┬───────────────────────────────────────────┘  │
│                 │  POST /api/* (JSON + optional base64 images)  │
└─────────────────┼───────────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────────┐
│                   Next.js Edge Proxy (proxy.ts)                 │
│   Per-request CSP nonce · Security headers on every response    │
└─────────────────┬───────────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────────┐
│               Next.js API Routes (Node.js runtime)              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  readJsonRequest()                                        │   │
│  │  • Content-Type guard (415 if not application/json)      │   │
│  │  • Body size limit: 20 MB (images included)              │   │
│  │  • JSON parse with error boundary                        │   │
│  └──────────────┬──────────────────────────────────────────┘   │
│                 │                                               │
│  ┌──────────────▼──────────────────────────────────────────┐   │
│  │  Input Validation (validation.ts)                         │   │
│  │  • validateThreatModelInput() — appType/auth allowlists  │   │
│  │  • validateImages() — MIME type, size, count guards      │   │
│  │  • validateCurrentControls() — sanitize posture input    │   │
│  │  • sanitizeThreats() — strip injection, clamp lengths    │   │
│  └──────────────┬──────────────────────────────────────────┘   │
│                 │                                               │
│  ┌──────────────▼──────────────────────────────────────────┐   │
│  │  stride-engine.ts                                         │   │
│  │  • callLLM() → POST /v1/responses (OpenAI Responses API) │   │
│  │  • 120s timeout + AbortController                        │   │
│  │  • text.format: json_object enforced                     │   │
│  │  • Typed LlmError (geo-block/invalid-key/rate-limit/…)   │   │
│  └──────────────┬──────────────────────────────────────────┘   │
│                 │  Error boundary: handleError()               │
│                 │  • LlmError → 502 + requestId (UUID)         │
│                 │  • All others → 500 "Internal server error"  │
│                 │  • No stack traces, no file paths to client  │
└─────────────────┼───────────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────────┐
│          OpenAI Responses API (POST /v1/responses)              │
│          Model: gpt-5.5  ·  Endpoint: api.openai.com           │
│          API key: Authorization header only — never logged      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Design

| Control | Implementation |
|---------|---------------|
| **API key handling** | In-memory React state only. Never written to `localStorage`, `sessionStorage`, cookies, or any server. Cleared on browser close, page refresh, or "New Analysis". |
| **Server-side LLM calls** | The browser never contacts `api.openai.com` directly. All calls are server-side API routes. `api.openai.com` is removed from CSP `connect-src`. |
| **Content-Security-Policy** | Per-request cryptographic nonce (16-byte random, base64). `unsafe-eval` removed. `unsafe-inline` present as legacy fallback only — modern browsers use the nonce. |
| **Cross-Origin isolation** | `Cross-Origin-Opener-Policy: same-origin` · `Cross-Origin-Embedder-Policy: require-corp` · `Cross-Origin-Resource-Policy: same-origin` (Spectre / side-channel mitigation) |
| **HTTP security headers** | HSTS (1 year + preload) · `X-Frame-Options: DENY` · `X-Content-Type-Options: nosniff` · `Referrer-Policy: strict-origin-when-cross-origin` · `Permissions-Policy` (camera/mic/geo disabled) |
| **Input validation** | Content-Type guard (415) · 20 MB body limit · JSON parse boundary · appType/auth method allowlists · image MIME/size/count guards · control-character stripping |
| **Output sanitization** | Field-length clamping on every LLM output field · XSS pattern stripping · STRIDE/risk value allowlisting · threat title normalization for cross-tab correlation |
| **Error handling** | `requestId = crypto.randomUUID()` on every error response. `LlmError` messages are user-facing guidance only. All other exceptions return `"Internal server error"` — no stack traces, file paths, or internal state reach the client. |
| **JSON enforcement** | `text: { format: { type: "json_object" } }` sent with every LLM call (Responses API). Model cannot return markdown fences or prose. |
| **XSS in diagrams** | Mermaid `securityLevel: "strict"` · `htmlLabels: false` · pre-render source sanitizer strips dangerous patterns before rendering |
| **Dependency hygiene** | SheetJS removed (high-severity CVEs). Excel export uses a custom zero-dependency OOXML/ZIP writer. All dependencies audited for trust and maintenance status. |
| **TypeScript strict mode** | `ignoreBuildErrors: false` · Build fails on any type error. Type safety treated as a security boundary. |

---

## Getting Started

### Prerequisites

- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **OpenAI API key** — [platform.openai.com](https://platform.openai.com)  
  *(GPT-5.5 access required — available on Pay-as-you-go and higher tiers)*

### Installation

```bash
# Clone the repository
git clone https://github.com/Varshith-Kali/Stride-gpt.git
cd Stride-gpt/stride-gpt

# Install dependencies
npm install

# Start the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Configuration

1. Click **Configure API** in the top navigation bar
2. Paste your **OpenAI API key** (`sk-...`)
3. The key is stored in React component state only — it is never persisted anywhere
4. Your key is cleared automatically when you close the browser or refresh the page

No `.env` files, no environment variables, no server-side configuration required.

### Workflow

```
1. Fill in application details
   └── App name, type, authentication methods, deployment flags

2. Write or paste the application description
   └── Architecture, components, data flows, integrations, trust boundaries

3. (Optional) Upload architecture diagram(s)
   └── PNG / JPEG / WebP — the model analyses the diagram as ground truth

4. Generate Threat Model
   └── Review STRIDE threats, attack vectors, MITRE mappings

5. Generate additional analyses from the results tabs
   └── Attack Tree · Mitigations · DREAD · DFD · Safety Metrics

6. Input Current Controls (for Safety Metrics)
   └── Describe your existing security posture per threat

7. Generate Safety Metrics
   └── SAFE / PARTIALLY SAFE / UNSAFE verdict per threat

8. Export
   └── Excel (.xlsx) — full report with Safety Metrics column
       JSON (.json) — raw structured output for pipelines
```

---

## Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Framework | [Next.js](https://nextjs.org) — App Router, server-side API routes, Edge proxy | 16.x |
| Language | TypeScript — strict mode, `ignoreBuildErrors: false` | 5.x |
| Runtime | React with `useMemo`, `useCallback`, `useDeferredValue` optimizations | 19.x |
| Styling | Tailwind CSS v4 + custom design system | 4.x |
| UI Components | [shadcn/ui](https://ui.shadcn.com) (Radix UI primitives) | latest |
| Animations | [Framer Motion](https://www.framer.com/motion) | 12.x |
| Diagrams | [Mermaid.js](https://mermaid.js.org) — strict security mode | 11.x |
| Icons | [Lucide React](https://lucide.dev) | 0.525+ |
| Notifications | [Sonner](https://sonner.emilkowal.ski) | 2.x |
| Fonts | Inter · JetBrains Mono (Google Fonts, self-hosted via next/font) | — |
| LLM | OpenAI Responses API (`POST /v1/responses`) | GPT-5.5 |
| Export | Custom zero-dependency OOXML/ZIP writer (no SheetJS) | — |

---

## API Reference

All API routes run on Node.js (`runtime = "nodejs"`, `maxDuration = 120`).  
Every route is POST-only. Authentication is via the `config.apiKey` field in the request body.

| Endpoint | Description | Input |
|----------|-------------|-------|
| `POST /api/threat-model` | Generate STRIDE threat model | `input`, `images?` |
| `POST /api/attack-tree` | Generate attack tree + Mermaid | `input`, `images?` |
| `POST /api/mitigations` | Generate mitigations + checklist | `input`, `threats`, `images?` |
| `POST /api/dread` | Generate DREAD scores | `threats`, `input?`, `images?` |
| `POST /api/dfd` | Generate DFD components + flows | `input`, `images?` |
| `POST /api/gherkin` | Generate BDD test scenarios | `threats`, `input?` |
| `POST /api/safety-metrics` | Generate safety posture evaluation | `input`, `threats`, `currentControls`, `images?` |
| `POST /api/recommendations` | Generate prioritized recommendations | `threats`, `justifications`, `appInput`, `images?` |
| `POST /api/test-connection` | Validate API key and model access | `config` |

All responses follow the shape: `{ ...result }` on success, `{ error: string, requestId: string }` on failure.

---

## Export Formats

| Format | Contents |
|--------|----------|
| **Excel (.xlsx)** | One row per threat · ID · Category · Threat Title · Component · Description · STRIDE Category · MITRE ATT&CK · Risk · Mitigation · Priority · OWASP Reference · DREAD (D/R/E/A/D/Total/Severity) · **Safety Metrics** (verdict + reasoning) |
| **JSON (.json)** | Full structured output: threat model, mitigations, DREAD scores, DFD, safety metrics |

The Excel workbook is generated entirely in-browser using a custom OOXML/ZIP writer — no external spreadsheet libraries and no SheetJS (removed due to high-severity CVEs).

---

## Supported Model

STRIDE GPT uses a single, best-in-class reasoning model:

| Model | Provider | Notes |
|-------|----------|-------|
| `gpt-5.5` | OpenAI | Reasoning model · Responses API · JSON output enforced via `text.format` |

GPT-5.5 is a reasoning model — it performs internal chain-of-thought before generating the structured JSON response. This produces significantly more accurate threat identification, realistic MITRE technique mapping, and calibrated risk scoring compared to standard models.

**Timeout:** 120 seconds (matches Next.js `maxDuration = 120`) — aligned to the reasoning model's typical response time for complex applications.

---

## Project Structure

```
stride-gpt/
├── src/
│   ├── app/
│   │   ├── api/                    # Next.js API routes (server-side)
│   │   │   ├── threat-model/       # STRIDE generation
│   │   │   ├── attack-tree/        # Attack tree + Mermaid
│   │   │   ├── mitigations/        # Countermeasures + checklist
│   │   │   ├── dread/              # DREAD risk scoring
│   │   │   ├── dfd/                # Data Flow Diagram
│   │   │   ├── gherkin/            # BDD test cases
│   │   │   ├── safety-metrics/     # Posture evaluation
│   │   │   ├── recommendations/    # Prioritized actions
│   │   │   └── test-connection/    # API key validation
│   │   ├── layout.tsx              # Root layout + CSP nonce wiring
│   │   ├── page.tsx                # Landing page
│   │   ├── icon.tsx                # Favicon (shield monogram)
│   │   └── globals.css             # Design system tokens
│   ├── components/
│   │   ├── threat-model-studio.tsx # Main application UI (6 tabs)
│   │   ├── api-config-dialog.tsx   # API key configuration
│   │   ├── mermaid-renderer.tsx    # Secure Mermaid rendering
│   │   └── brand-mark.tsx          # Logo component
│   ├── lib/
│   │   ├── stride-engine.ts        # LLM calls, prompts, types
│   │   ├── api-utils.ts            # Shared route utilities
│   │   ├── export-utils.ts         # Excel/JSON export engine
│   │   ├── validation.ts           # Input sanitization
│   │   ├── llm-config.ts           # LLM config types + validation
│   │   └── utils.ts                # Shared utilities
│   ├── hooks/
│   │   ├── use-llm-config.ts       # API key state (in-memory only)
│   │   ├── use-toast.ts            # Toast notification hook
│   │   └── use-mobile.ts           # Responsive layout hook
│   └── proxy.ts                    # Edge proxy — CSP nonce + security headers
├── next.config.ts                  # Security headers (HSTS, COOP, COEP, CORP, CSP)
├── package.json
└── README.md
```

---

## License

MIT © 2025–2026 STRIDE GPT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files, to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the following conditions: the above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** The authors are not responsible for the accuracy of AI-generated threat models. Security analysis output should be reviewed by qualified security professionals before being used to make security decisions.
