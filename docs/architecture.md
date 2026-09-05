# PhishGuard — Architecture & Data Flow

PhishGuard employs a layered, defense-in-depth architecture designed to safely parse, analyze, score, and present phishing investigations without exposing users or systems to exploitation.

---

## 1. System Overview

```mermaid
flowchart TD
    User([End User / Security Analyst]) -->|HTTPS| Frontend[React + Vite Frontend (Vercel)]
    Frontend -->|Supabase Auth & Session JWT| SupabaseAuth[(Supabase Auth)]
    Frontend -->|Read Scans with RLS (auth.uid)| SupabaseDB[(PostgreSQL / Supabase)]
    
    Frontend -->|POST /api/scan (Multipart or JSON + Bearer JWT)| Backend[Express Backend (Render / Docker)]
    
    subgraph Backend Pipeline [Backend Pipeline (Zero-Trust on Untrusted Email)]
        StreamLimiter[Multer Stream Limiter (5MB Cap)] --> Parser[mailparser / Raw Parser]
        Parser --> HeuristicEngine[Local Heuristics Engine]
        HeuristicEngine -->|Lookalike Domains (Levenshtein)| Domains[Domain & Anchor Verifier]
        HeuristicEngine -->|Sanitize HTML Server-side| Sanitizer[HTML Sanitizer]
        HeuristicEngine --> AIService[Anthropic Claude AI Layer]
        AIService -->|Strict JSON Prompt Defense| ClaudeAPI[(Anthropic Claude 3.5 Sonnet)]
        ClaudeAPI -->|JSON Response Validation| JSONValidator[Schema & Output Guard]
        JSONValidator --> ResultPacker[Result Synthesizer]
    end

    Backend -->|Write Scan Record (Service Role Key)| SupabaseDB
    Backend -->|Return Analysis JSON| Frontend
```

---

## 2. Ingestion & Analysis Pipeline

1. **Upload & Size Enforcement:**
   - Multi-part `.eml` or JSON payload is streamed through Multer. Uploads exceeding 5MB are terminated at the HTTP stream layer before full in-memory buffering.
2. **Deterministic Heuristics:**
   - `mailparser` unpacks email headers (From, To, Subject, Date, SPF/DKIM/DMARC headers).
   - Domain parser extracts URLs and detects typosquatting / lookalike domains against known high-value targets (PayPal, Google, Microsoft, Apple, Bank of America, etc.) with Levenshtein distance $\le 2$.
   - Mismatches between link anchor text (e.g., `https://mybank.com`) and target `href` (e.g., `https://evil-spoof.ru`) are flagged as critical indicators.
3. **AI Reasoning (Isolated Context):**
   - Untrusted body text is placed inside `<email_content>` boundaries.
   - Claude evaluates psychological attack tactics (urgency, fear, authority impersonation, financial bait) and calculates a holistic risk score.
4. **Data Isolation & Storage:**
   - Scan records and indicator rows are persisted with the requesting user's verified `user_id`.
   - Supabase Row Level Security (RLS) guarantees complete tenant isolation.
