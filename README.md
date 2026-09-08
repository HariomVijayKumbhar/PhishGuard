# PhishGuard 🛡️

**AI-powered phishing & social engineering detector for small teams.**

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
- **Backend:** Node.js, Express, `mailparser`, `parse-domain`, `fastest-levenshtein`, `helmet`, `express-rate-limit`
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
- **Zero Raw Rendering:** Email HTML is never rendered via `dangerouslySetInnerHTML`.
- **Prompt Injection Containment:** Untrusted email payloads are strictly isolated in `<email_content>` tags with deterministic output schema validation.
- **Row Level Security (RLS):** Supabase ensures no user can ever access another user's scan history.
- **Strict Network Policies:** Strict CORS origin lock, Helmet security headers, and payload limits (5MB max upload).
