import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Activity, Lock, Terminal, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [backendStatus, setBackendStatus] = useState('checking');
  const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8080';

  useEffect(() => {
    fetch(`${backendUrl}/health`)
      .then((res) => res.json())
      .then((data) => {
        if (data?.status === 'ok') {
          setBackendStatus('online');
        } else {
          setBackendStatus('error');
        }
      })
      .catch(() => setBackendStatus('offline'));
  }, [backendUrl]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                PhishGuard
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  v1.0-scaffold
                </span>
              </h1>
              <p className="text-xs text-slate-400">AI-powered phishing detector for small teams</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700">
              <Activity className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Backend:</span>
              {backendStatus === 'online' && (
                <span className="text-emerald-400 font-medium flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  Connected
                </span>
              )}
              {backendStatus === 'checking' && (
                <span className="text-amber-400">Pinging...</span>
              )}
              {backendStatus === 'offline' && (
                <span className="text-rose-400 flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                  Offline
                </span>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Hero Banner / Welcome */}
          <div className="lg:col-span-2 space-y-6">
            <div className="p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-900/50 border border-slate-800 relative overflow-hidden">
              <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none"></div>
              
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold mb-4">
                <Lock className="w-3.5 h-3.5" /> Security Hardened Scaffolding Active
              </div>

              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white mb-3">
                Defend your organization against advanced social engineering.
              </h2>
              <p className="text-slate-400 text-sm leading-relaxed mb-6">
                PhishGuard isolates untrusted email payloads, analyzes deceptive domains via Levenshtein distance heuristics, and evaluates cognitive exploitation tactics using Claude AI.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                  <div className="font-semibold text-white mb-1 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Zero Raw HTML Rendering
                  </div>
                  <p className="text-slate-400">Strict client-side XSS prevention; raw HTML never rendered directly.</p>
                </div>
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                  <div className="font-semibold text-white mb-1 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Prompt Injection Defense
                  </div>
                  <p className="text-slate-400">Structured XML containment and deterministic JSON output validation.</p>
                </div>
              </div>
            </div>

            {/* Architecture Card */}
            <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Pipeline Execution Status
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-300">1. Repo & Scaffolding</span>
                  <span className="text-emerald-400 font-bold">READY (Phase 1)</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/40 text-slate-500">
                  <span>2. Backend Email Parser</span>
                  <span>PENDING (Phase 2)</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/40 text-slate-500">
                  <span>3. Claude AI Classifier</span>
                  <span>PENDING (Phase 3)</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/40 text-slate-500">
                  <span>4. Supabase DB & RLS</span>
                  <span>PENDING (Phase 4)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Info Sidebar */}
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800">
              <h3 className="text-sm font-semibold text-white mb-4">Environment Diagnostics</h3>
              <ul className="space-y-3 text-xs text-slate-400">
                <li className="flex justify-between border-b border-slate-800/60 pb-2">
                  <span>Frontend:</span>
                  <span className="text-slate-200 font-mono">Vite + React 18</span>
                </li>
                <li className="flex justify-between border-b border-slate-800/60 pb-2">
                  <span>Styling:</span>
                  <span className="text-slate-200 font-mono">Tailwind CSS</span>
                </li>
                <li className="flex justify-between border-b border-slate-800/60 pb-2">
                  <span>Backend Target:</span>
                  <span className="text-emerald-400 font-mono">{backendUrl}</span>
                </li>
                <li className="flex justify-between border-b border-slate-800/60 pb-2">
                  <span>Health Probe:</span>
                  <span className="text-slate-200 font-mono">GET /health</span>
                </li>
              </ul>
            </div>

            <div className="p-5 rounded-2xl bg-amber-500/5 border border-amber-500/20 text-xs text-amber-200/90 leading-relaxed">
              <div className="font-semibold text-amber-300 mb-1 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                Security Rule
              </div>
              All secret keys (`ANTHROPIC_API_KEY`, `SUPABASE_SERVICE_ROLE_KEY`) are strictly confined to the backend. The frontend bundle only consumes public anon tokens.
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        PhishGuard Security Suite • Built for Cyber Resilience
      </footer>
    </div>
  );
}
