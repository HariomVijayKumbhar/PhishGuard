# PhishGuard 🛡️

**AI-powered phishing & social engineering detector for small teams.**

> 🔬 Safe Email Threat Sandbox · 📱 Quishing (QR Phishing) Detector · 🎮 Spot-the-Phish Training Lab · 🚨 SOC Action Kit · 🌐 Live Threat Intelligence

## ✨ Features

| Feature                                     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 🔬 **Safe Email Threat Sandbox**            | Full-screen visual inspector that renders sanitized email HTML with color-coded, interactive threat overlays — red glow for spoofed/lookalike domains, orange for href-text mismatch, yellow for raw-IP links, purple for urgency/manipulation phrases, blue for clean external links. All `<a>` tags are converted to inert `<span data-href>` elements — **zero clickable links, zero image loads, zero script execution**. Clicking any flagged element slides in a Threat Detail Panel with full impersonation analysis and a direct hand-off to the Threat Intel Inspector. |
| 📱 **Quishing (QR Code Phishing) Detector** | Automatically scans attached/inline email images for QR codes, or accepts direct image/screenshot uploads. Decodes entirely **in memory** (with decompression-bomb & size guards), unmasks the destination URL, and runs it through the lookalike/heuristic engine — the extracted URL is **never visited**.                                                                                                                                                                                                                                                                     |
| 🎮 **Spot-the-Phish Training Lab**          | Gamified security training with real-world sanitized case studies (CEO Fraud, Fake Invoice, Ransomware Delivery, Cloud Account Takeover). Users inspect emails, click what looks suspicious, and earn a Cyber Defender score with a full breakdown. Built from static, isolated JSON templates — zero external execution.                                                                                                                                                                                                                                                        |
| 🚨 **SOC Incident Response Kit**            | Enterprise-ready defensive actions: IOC extraction, blocklist recommendations, and escalation workflows proving security-operations readiness.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 🌐 **Live Threat Intelligence Inspector**   | Inspect any flagged URL/domain with live intel lookups, pre-loaded directly from the Sandbox or scan results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 🧠 **AI + Heuristic Engine**                | Multi-provider LLM analysis (Groq/Claude/Gemini/OpenAI/OpenRouter) combined with Levenshtein-based lookalike domain detection (incl. hyphen-label typosquats like `paypa1-verify.com`), urgency-phrase detection across 6 manipulation categories, raw-IP flagging, URL-shortener & href-mismatch analysis.                                                                                                                                                                                                                                                                      |
| 📜 **Scan History**                         | All scans persisted to Supabase with Row-Level Security — only you can see your own history.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 🔐 **Login Gating**                         | Email scanning is open to everyone; premium features (Sandbox, Threat Intel, SOC Kit, QR Scanner, History) require sign-in.                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

## Problem Statement & Proposed Solution

Small teams and growing organizations are disproportionately targeted by sophisticated social engineering, spear-phishing, and credential harvesting attacks, yet lack dedicated 24/7 Security Operations Centers (SOC) or expensive enterprise threat intelligence platforms to evaluate suspicious inbound communications. **PhishGuard** bridges this defense gap by providing an intuitive, security-hardened web platform where team members can scan raw email text or `.eml` files to receive an immediate risk score (0–100), clear verdict, tactical indicator breakdown, and an AI-generated, sanitized summary that explains the psychological manipulation mechanisms without triggering embedded threats or instructions.

---

## Monorepo Architecture

```
phishguard/
├── frontend/             # React + Vite + Tailwind CSS dashboard (Vercel)
├── backend/              # Node.js + Express API + Mail parser (Render)
├── .github/workflows/    # CI/CD pipelines (Lint, Test, Audit, Build)
├── docs/                 # Architecture, Threat Model, and Documentation
│   ├── architecture.md
│   ├── THREAT_MODEL.md
│   └── README.md
├── docker-compose.yml    # Local containerized orchestration
└── README.md             # Project overview & quickstart
```

---

## Technology Stack

- **Frontend:** React 18, Vite, Tailwind CSS, Lucide React, Recharts
- **Backend:** Node.js, Express, `mailparser`, `parse-domain`, `fastest-levenshtein`, `cheerio`, `jimp`, `jsqr`, `helmet`, `express-rate-limit`
- **AI Core:** Multi-provider LLM engine supporting Anthropic Claude, Groq (Llama 3.3), OpenRouter, Google Gemini, and OpenAI (Structured JSON output with strict prompt injection containment)
- **Database & Auth:** Supabase (PostgreSQL with Row Level Security + Supabase Auth)
- **Containerization:** Docker multi-stage build, non-root user
- **Testing:** Jest (Backend unit/integration), Vitest + React Testing Library (Frontend)

---

## Quickstart (Local Development)

### 1. Prerequisites

- Node.js 20+ (Node v24 recommended)
- npm 10+
- Git

### 2. Backend Setup

```bash
cd backend
cp .env.example .env
npm install
npm run dev
```

Backend runs by default at `http://localhost:8080`. Check health at `http://localhost:8080/health`.

### 3. Frontend Setup

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Frontend runs by default at `http://localhost:5173`.

---

## Security & Defense-in-Depth

PhishGuard is treated as a security product from day one:

- **Sandboxed Preview:** The Threat Sandbox renders only server-sanitized + client-re-annotated HTML. All `<a>` tags become inert `<span data-href>` elements — there are zero real clickable links, images are stripped (tracking-pixel prevention), and a second client-side pass strips any residual `<script>`/`on*` attributes. Clicks are captured and routed to the Threat Intel Inspector instead of navigating.
- **QR Decoding In Memory:** QR/Quishing images are decoded strictly in memory with size and decompression-bomb guards; the extracted URL is analyzed but never auto-visited.
- **Zero Raw Rendering:** Outside the sandbox, email HTML is never rendered via `dangerouslySetInnerHTML`.
- **Prompt Injection Containment:** Untrusted email payloads are strictly isolated in `<email_content>` tags with deterministic output schema validation.
- **Row Level Security (RLS):** Supabase ensures no user can ever access another user's scan history.
- **Strict Network Policies:** Strict CORS origin lock, Helmet security headers, and payload limits (5MB max upload).
