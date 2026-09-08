import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Activity,
  Lock,
  User,
  LogIn,
  UserPlus,
  LogOut,
  History,
  Send,
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Sparkles,
  RefreshCw,
  Cpu,
  Layers,
  ChevronDown
} from 'lucide-react';
import AuthModal from './components/AuthModal.jsx';
import ScanHistoryModal from './components/ScanHistoryModal.jsx';

export default function App() {
  const [backendStatus, setBackendStatus] = useState('checking');
  const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8080';

  // Auth state
  const [token, setToken] = useState(() => localStorage.getItem('phishguard_auth_token') || null);
  const [user, setUser] = useState(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState('login');
  const [historyModalOpen, setHistoryModalOpen] = useState(false);

  // Scanner state
  const [inputMode, setInputMode] = useState('text'); // 'text' | 'file'
  const [emailText, setEmailText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedProvider, setSelectedProvider] = useState('auto');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);

  // Check backend health & restore user session
  useEffect(() => {
    fetch(`${backendUrl}/health`)
      .then((res) => res.json())
      .then((data) => {
        setBackendStatus(data?.status === 'ok' ? 'online' : 'error');
      })
      .catch(() => setBackendStatus('offline'));

    if (token) {
      fetch(`${backendUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then((res) => {
          if (!res.ok) throw new Error('Session expired');
          return res.json();
        })
        .then((data) => {
          if (data?.user) setUser(data.user);
        })
        .catch(() => {
          localStorage.removeItem('phishguard_auth_token');
          setToken(null);
          setUser(null);
        });
    }
  }, [backendUrl, token]);

  const handleAuthSuccess = ({ user, token }) => {
    setUser(user);
    if (token) setToken(token);
  };

  const handleLogout = () => {
    localStorage.removeItem('phishguard_auth_token');
    setToken(null);
    setUser(null);
  };

  const loadSampleEmail = (type) => {
    if (type === 'phishing') {
      setEmailText(`From: Security Team <support@paypa1-security.com>
To: target.employee@company.com
Subject: CRITICAL: Immediate Unauthorized Login Detected - Action Required

Dear Customer,

We detected an unauthorized sign-in attempt to your account from an unrecognized IP address (Moscow, Russia).
For your protection, your access will be suspended within 2 hours unless you confirm your identity.

Please review and verify your account credentials immediately:
http://paypa1-security.com/account-verification?token=8923482394

Failure to verify will result in permanent account termination.

Sincerely,
Security Operations Desk`);
    } else {
      setEmailText(`From: GitHub <notifications@github.com>
To: developer@company.com
Subject: [PhishGuard] Pull request #42 merged into main

Hey Hariom,

Your pull request #42 "Add OpenRouter and Groq providers" has been successfully merged into main by the automated CI pipeline.

All 8 integration tests passed with 100% code coverage.
View changes: https://github.com/phishguard/phishguard/pull/42

Thanks,
The GitHub Team`);
    }
    setScanResult(null);
    setScanError(null);
  };

  const handleScanSubmit = async (e) => {
    e.preventDefault();
    setScanError(null);
    setScanResult(null);

    if (inputMode === 'text' && (!emailText || emailText.trim().length === 0)) {
      setScanError('Please enter raw email content or header text to scan.');
      return;
    }

    if (inputMode === 'file' && !selectedFile) {
      setScanError('Please select a .eml or text file to upload.');
      return;
    }

    setIsScanning(true);

    try {
      let res;
      const headers = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      if (inputMode === 'file') {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('provider', selectedProvider);
        res = await fetch(`${backendUrl}/api/scan`, {
          method: 'POST',
          headers,
          body: formData
        });
      } else {
        headers['Content-Type'] = 'application/json';
        res = await fetch(`${backendUrl}/api/scan`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            email_text: emailText,
            provider: selectedProvider
          })
        });
      }

      const responseData = await res.json();

      if (!res.ok) {
        throw new Error(responseData.error || 'Failed to complete email scan');
      }

      setScanResult(responseData.data);
    } catch (err) {
      setScanError(err.message || 'An error occurred during scanning');
    } finally {
      setIsScanning(false);
    }
  };

  const getVerdictStyle = (verdict, score) => {
    if (verdict === 'phishing' || score >= 70) {
      return {
        bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
        badge: 'bg-rose-500 text-slate-950 font-bold',
        icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
        title: 'CRITICAL PHISHING THREAT'
      };
    }
    if (verdict === 'suspicious' || score >= 40) {
      return {
        bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
        badge: 'bg-amber-500 text-slate-950 font-bold',
        icon: <Shield className="w-6 h-6 text-amber-400" />,
        title: 'SUSPICIOUS COMMUNICATION'
      };
    }
    return {
      bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      badge: 'bg-emerald-500 text-slate-950 font-bold',
      icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
      title: 'BENIGN / SAFE EMAIL'
    };
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-emerald-500 selection:text-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/20 shadow-sm shadow-emerald-500/10">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white">PhishGuard</h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono">
                  v1.2-live
                </span>
              </div>
              <p className="text-xs text-slate-400">AI-powered phishing detector for teams</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Backend status pill */}
            <div className="hidden sm:flex items-center gap-2 text-xs px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 font-mono">
              <Activity className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">API:</span>
              {backendStatus === 'online' && (
                <span className="text-emerald-400 font-medium flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                  Online
                </span>
              )}
              {backendStatus === 'checking' && (
                <span className="text-amber-400">Checking...</span>
              )}
              {backendStatus === 'offline' && (
                <span className="text-rose-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                  Offline
                </span>
              )}
            </div>

            {/* Auth Buttons / User Profile */}
            {user ? (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setHistoryModalOpen(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-xl text-xs font-medium transition-colors"
                >
                  <History className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Scan History</span>
                </button>

                <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
                  <div className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-xs flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5" />
                    <span className="max-w-[120px] truncate">{user.email}</span>
                  </div>
                  <button
                    onClick={handleLogout}
                    title="Sign Out"
                    className="p-1.5 rounded-xl text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setAuthModalMode('login');
                    setAuthModalOpen(true);
                  }}
                  className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </button>
                <button
                  onClick={() => {
                    setAuthModalMode('register');
                    setAuthModalOpen(true);
                  }}
                  className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-xl text-xs font-bold transition-all shadow-md shadow-emerald-500/20 flex items-center gap-1.5"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Register</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">
        {/* Hero Notice when not logged in */}
        {!user && (
          <div className="p-4 rounded-2xl bg-gradient-to-r from-emerald-500/10 via-slate-900 to-slate-900 border border-emerald-500/20 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 shrink-0">
                <Sparkles className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Create an account or sign in to save your scans</h3>
                <p className="text-xs text-slate-400">Authenticated scans are automatically persisted with Supabase Row Level Security.</p>
              </div>
            </div>
            <button
              onClick={() => {
                setAuthModalMode('register');
                setAuthModalOpen(true);
              }}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-xl text-xs shrink-0 transition-colors shadow-lg shadow-emerald-500/20"
            >
              Get Started Free
            </button>
          </div>
        )}

        {/* Scan Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Column: Email Input & Controls (7 cols) */}
          <div className="lg:col-span-7 space-y-6">
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Layers className="w-4 h-4 text-emerald-400" />
                    Inbound Email Inspector
                  </h2>
                  <p className="text-xs text-slate-400">Isolate untrusted communications and evaluate threat vectors</p>
                </div>

                {/* Sample quick-loaders */}
                <div className="flex items-center gap-1.5 text-xs">
                  <span className="text-[11px] text-slate-500 mr-1 hidden sm:inline">Load Sample:</span>
                  <button
                    type="button"
                    onClick={() => loadSampleEmail('phishing')}
                    className="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors text-[11px] font-medium"
                  >
                    Phishing
                  </button>
                  <button
                    type="button"
                    onClick={() => loadSampleEmail('benign')}
                    className="px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors text-[11px] font-medium"
                  >
                    Benign
                  </button>
                </div>
              </div>

              {/* Mode Toggle & AI Provider Selector */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                <div className="inline-flex p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-medium">
                  <button
                    type="button"
                    onClick={() => setInputMode('text')}
                    className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
                      inputMode === 'text'
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Raw Text / Headers</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setInputMode('file')}
                    className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
                      inputMode === 'file'
                        ? 'bg-slate-800 text-white font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>.EML File Upload</span>
                  </button>
                </div>

                {/* AI Provider selector */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 flex items-center gap-1 font-mono">
                    <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                    AI:
                  </span>
                  <select
                    value={selectedProvider}
                    onChange={(e) => setSelectedProvider(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500/60 font-mono"
                  >
                    <option value="auto">Auto (Best Available)</option>
                    <option value="groq">Groq (Llama 3.3 70B)</option>
                    <option value="openrouter">OpenRouter Gateway</option>
                    <option value="anthropic">Claude 3.5 Sonnet</option>
                    <option value="gemini">Gemini 2.0 Flash</option>
                    <option value="openai">OpenAI GPT-4o</option>
                  </select>
                </div>
              </div>

              {/* Form content */}
              <form onSubmit={handleScanSubmit} className="space-y-4">
                {inputMode === 'text' ? (
                  <div className="space-y-2">
                    <textarea
                      rows={10}
                      value={emailText}
                      onChange={(e) => setEmailText(e.target.value)}
                      placeholder="Paste complete raw email headers and body text here...
Example:
From: Support <support@paypa1.com>
Subject: Urgent: Verify your credentials
Click here: http://paypa1.com/login"
                      className="w-full p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/40 transition-colors resize-y leading-relaxed"
                    />
                  </div>
                ) : (
                  <div className="p-8 border-2 border-dashed border-slate-800 hover:border-emerald-500/50 rounded-2xl bg-slate-950/60 text-center transition-colors">
                    <UploadCloud className="w-10 h-10 mx-auto text-slate-500 mb-3" />
                    <p className="text-xs font-semibold text-white mb-1">
                      {selectedFile ? selectedFile.name : 'Choose a .eml or raw email file'}
                    </p>
                    <p className="text-[11px] text-slate-500 mb-4">Maximum upload limit: 5MB</p>
                    <label className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium cursor-pointer transition-colors">
                      <span>Browse Files</span>
                      <input
                        type="file"
                        accept=".eml,.txt,message/rfc822"
                        className="hidden"
                        onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                      />
                    </label>
                  </div>
                )}

                {scanError && (
                  <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>{scanError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isScanning}
                  className="w-full py-3 px-6 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-xl text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed uppercase tracking-wider"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Analyzing Threat Vectors with AI...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      <span>Execute PhishGuard Inspection</span>
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>

          {/* Right Column: Scan Results or Diagnostics (5 cols) */}
          <div className="lg:col-span-5 space-y-6">
            {scanResult ? (
              <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-2xl space-y-6 animate-in fade-in duration-300">
                {/* Score & Verdict Header */}
                {(() => {
                  const style = getVerdictStyle(scanResult.verdict, scanResult.risk_score);
                  return (
                    <div className={`p-5 rounded-2xl border ${style.bg} space-y-3`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          {style.icon}
                          <span className="font-bold text-xs tracking-wider uppercase">{style.title}</span>
                        </div>
                        <span className={`px-2.5 py-1 rounded-full text-xs uppercase tracking-wider ${style.badge}`}>
                          {scanResult.verdict}
                        </span>
                      </div>

                      {/* Risk score gauge */}
                      <div className="space-y-1.5 pt-2">
                        <div className="flex justify-between items-baseline">
                          <span className="text-xs font-semibold text-white">Risk Score</span>
                          <span className="text-2xl font-black font-mono">{scanResult.risk_score}/100</span>
                        </div>
                        <div className="w-full bg-slate-950/80 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              scanResult.risk_score >= 70
                                ? 'bg-rose-500'
                                : scanResult.risk_score >= 40
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${scanResult.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {/* AI Explanation & Safe Summary */}
                <div className="space-y-3">
                  <h3 className="text-xs font-bold text-white tracking-wide uppercase flex items-center gap-2">
                    <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                    AI Threat Evaluation
                  </h3>
                  <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2 text-xs leading-relaxed text-slate-300">
                    <p>{scanResult.explanation}</p>
                    {scanResult.safe_summary && (
                      <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400">
                        <strong className="text-emerald-400">Safe Summary: </strong>
                        {scanResult.safe_summary}
                      </div>
                    )}
                  </div>
                </div>

                {/* Exploitation Tactics detected */}
                {scanResult.tactics_detected && scanResult.tactics_detected.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-300">Tactics & Psychological Triggers</h4>
                    <div className="flex flex-wrap gap-1.5">
                      {scanResult.tactics_detected.map((tactic, idx) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-mono"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Heuristic Flagged Indicators */}
                {scanResult.heuristics && (
                  <div className="space-y-2 pt-2 border-t border-slate-800/80 text-xs">
                    <h4 className="font-semibold text-slate-300">Heuristic Signals</h4>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 block">Lookalikes</span>
                        <span className="text-white font-bold">{scanResult.heuristics.lookalikeCount || 0}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-slate-500 block">Anchor Mismatch</span>
                        <span className="text-white font-bold">{scanResult.heuristics.anchorMismatchCount || 0}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Metadata details */}
                {scanResult.ai_metadata && (
                  <div className="text-[10px] text-slate-500 font-mono flex justify-between border-t border-slate-800/60 pt-3">
                    <span>Engine: {scanResult.ai_metadata.provider}</span>
                    <span>Model: {scanResult.ai_metadata.model}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-6">
                {/* Security Architecture Details */}
                <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    Security Guardrails Active
                  </h3>
                  <div className="space-y-3 text-xs text-slate-400">
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-white block font-medium">Prompt Injection Isolation</strong>
                        <p className="text-[11px] text-slate-400">Email payload strictly sandboxed within XML containment boundary.</p>
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-white block font-medium">Levenshtein Typosquatting</strong>
                        <p className="text-[11px] text-slate-400">Detects lookalike domains within edit distance ≤ 2 against trusted brands.</p>
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-white block font-medium">Row Level Security</strong>
                        <p className="text-[11px] text-slate-400">Database rows isolated by user ID at the PostgreSQL kernel layer.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Auth Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        initialMode={authModalMode}
        onAuthSuccess={handleAuthSuccess}
        backendUrl={backendUrl}
      />

      {/* Scan History Modal */}
      <ScanHistoryModal
        isOpen={historyModalOpen}
        onClose={() => setHistoryModalOpen(false)}
        backendUrl={backendUrl}
        token={token}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-5 text-center text-xs text-slate-500">
        PhishGuard Security Suite • Multi-Provider Threat Intelligence • AI Powered
      </footer>
    </div>
  );
}
