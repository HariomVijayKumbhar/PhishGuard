# Graph Report - Phishguard  (2026-09-08)

## Corpus Check
- Corpus is ~11,688 words - fits in a single context window. You may not need a graph.

## Summary
- 158 nodes · 231 edges · 14 communities (12 shown, 2 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 8 edges (avg confidence: 0.91)
- Token cost: 1,200 input · 600 output

## Community Hubs (Navigation)
- Backend Dependencies & SDKs
- AI Analysis & LLM Providers
- Scan Routes & Auth Middleware
- Express Server & API Lifecycle
- Frontend UI Components & Icons
- Frontend Tooling & PostCSS
- Backend Package Metadata
- Email Parsing & Domain Heuristics
- Frontend App Layout & Routing
- Threat Model & Rate Limiting

## God Nodes (most connected - your core abstractions)
1. `classifyEmailWithAI()` - 12 edges
2. `buildUserAnalysisPrompt()` - 8 edges
3. `parseEmailInput()` - 7 edges
4. `getSupabaseAdmin()` - 7 edges
5. `analyzeLinks()` - 7 edges
6. `SYSTEM_PROMPT` - 6 edges
7. `keywords` - 5 edges
8. `requireAuth()` - 5 edges
9. `processParsedEmail()` - 5 edges
10. `verifyUserToken()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `Supabase RLS Tenant Isolation` --references--> `requireAuth()`  [INFERRED]
  docs/architecture.md → backend/src/middleware/auth.js
- `Isolated AI Reasoning Layer` --implements--> `classifyEmailWithAI()`  [INFERRED]
  docs/architecture.md → backend/src/services/ai/aiService.js
- `Threat: Prompt Injection in Email Content` --rationale_for--> `SYSTEM_PROMPT`  [INFERRED]
  docs/THREAT_MODEL.md → backend/src/services/ai/promptTemplates.js
- `Ingestion & Analysis Pipeline` --implements--> `upload`  [INFERRED]
  docs/architecture.md → backend/src/routes/scan.js
- `Deterministic Heuristics Engine` --implements--> `extractIndicators()`  [INFERRED]
  docs/architecture.md → backend/src/routes/scan.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Pipeline Security Guardrails Flow** — docs_architecture_ingestion_pipeline, docs_threat_model_email_body_injection, docs_architecture_ai_reasoning_layer, backend_src_services_ai_aiservice_classifyemailwithai [INFERRED 0.85]

## Communities (14 total, 2 thin omitted)

### Community 0 - "Backend Dependencies & SDKs"
Cohesion: 0.07
Nodes (29): @anthropic-ai/sdk, dependencies, @anthropic-ai/sdk, cheerio, cors, dotenv, express, express-rate-limit (+21 more)

### Community 1 - "AI Analysis & LLM Providers"
Cohesion: 0.21
Nodes (14): AIClassificationError, classifyEmailWithAI(), cleanJsonOutput(), validateSchema(), buildUserAnalysisPrompt(), SYSTEM_PROMPT, callAnthropicClaude(), callGoogleGemini() (+6 more)

### Community 2 - "Scan Routes & Auth Middleware"
Cohesion: 0.20
Nodes (17): extractBearerToken(), optionalAuth(), requireAuth(), extractIndicators(), processParsedEmail(), scanRateLimiter, upload, getScanById() (+9 more)

### Community 3 - "Express Server & API Lifecycle"
Cohesion: 0.14
Nodes (12): keywords, app, router, setSupabaseAdmin(), mockIndicators, mockScans, System Architecture Overview, Defense in Depth Security Principles (+4 more)

### Community 4 - "Frontend UI Components & Icons"
Cohesion: 0.12
Nodes (15): dependencies, lucide-react, react, react-dom, name, private, scripts, build (+7 more)

### Community 5 - "Frontend Tooling & PostCSS"
Cohesion: 0.13
Nodes (15): autoprefixer, devDependencies, autoprefixer, postcss, tailwindcss, @types/react, @types/react-dom, vite (+7 more)

### Community 6 - "Backend Package Metadata"
Cohesion: 0.13
Nodes (14): author, description, devDependencies, nodemon, license, main, name, scripts (+6 more)

### Community 7 - "Email Parsing & Domain Heuristics"
Cohesion: 0.30
Nodes (10): EmailParseError, extractLinksFromContent(), extractSecurityHeaders(), parseEmailInput(), sanitizeEmailHtml(), analyzeLinks(), checkAnchorHrefMismatch(), checkLookalikeDomain() (+2 more)

## Knowledge Gaps
- **54 isolated node(s):** `name`, `version`, `description`, `main`, `type` (+49 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `keywords` connect `Express Server & API Lifecycle` to `Backend Package Metadata`?**
  _High betweenness centrality (0.284) - this node is a cross-community bridge._
- **Why does `express` connect `Express Server & API Lifecycle` to `Scan Routes & Auth Middleware`?**
  _High betweenness centrality (0.274) - this node is a cross-community bridge._
- **Why does `dependencies` connect `Backend Dependencies & SDKs` to `Backend Package Metadata`?**
  _High betweenness centrality (0.236) - this node is a cross-community bridge._
- **What connects `name`, `version`, `description` to the rest of the system?**
  _54 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Backend Dependencies & SDKs` be split into smaller, more focused modules?**
  _Cohesion score 0.06896551724137931 - nodes in this community are weakly interconnected._
- **Should `Express Server & API Lifecycle` be split into smaller, more focused modules?**
  _Cohesion score 0.14166666666666666 - nodes in this community are weakly interconnected._
- **Should `Frontend UI Components & Icons` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._