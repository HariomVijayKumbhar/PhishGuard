import React, { useState, useEffect } from 'react';
import {
  X,
  Search,
  Globe,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Shield,
  ArrowRight,
  Cpu,
  Mail
} from 'lucide-react';

export default function ThreatIntelModal({ isOpen, onClose, initialUrl, backendUrl, token }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [intelData, setIntelData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (initialUrl) {
      setTargetUrl(initialUrl);
      executeInspection(initialUrl);
    } else {
      setIntelData(null);
      setError(null);
    }
  }, [initialUrl, isOpen]);

  const executeInspection = async (urlToInspect) => {
    const query = urlToInspect || targetUrl;
    if (!query || !query.trim()) {
      setError('Please provide a valid URL or domain to inspect.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch(`${backendUrl}/api/intel/inspect-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ url: query.trim() })
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Threat intelligence query failed');
      }

      setIntelData(data.data);
    } catch (err) {
      setError(err.message || 'Failed to communicate with Threat Intel engine');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                Live URL & Domain Threat Intelligence
              </h3>
              <p className="text-xs text-slate-400">
                Real-time redirect unmasking, Shannon entropy DGA detection, and DNS/MX verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search Input Bar */}
        <div className="p-6 border-b border-slate-800 bg-slate-950/60">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              executeInspection();
            }}
            className="flex gap-2"
          >
            <div className="relative flex-1">
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example-phish-domain.com/login"
                className="w-full pl-4 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs flex items-center gap-2 transition-colors disabled:opacity-50"
            >
              {isLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              <span>Inspect Threat Intel</span>
            </button>
          </form>

          {error && (
            <div className="mt-3 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          {isLoading && (
            <div className="py-12 text-center space-y-3">
              <RefreshCw className="w-8 h-8 mx-auto text-cyan-400 animate-spin" />
              <p className="text-xs text-slate-400">Tracing network hops, analyzing entropy, and auditing DNS/MX records...</p>
            </div>
          )}

          {!isLoading && intelData && (
            <div className="space-y-6 animate-in fade-in duration-200">
              {/* Score & Verdict Card */}
              <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="space-y-1 text-center sm:text-left">
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">Threat Intelligence Verdict</span>
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`text-xl font-bold uppercase tracking-wider ${
                        intelData.verdict === 'MALICIOUS'
                          ? 'text-rose-400'
                          : intelData.verdict === 'SUSPICIOUS'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {intelData.verdict}
                    </span>
                    {intelData.ssrfBlocked && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono">
                        SSRF ATTEMPT BLOCKED
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-baseline gap-2 bg-slate-900 px-4 py-2 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 font-mono">Risk Rating:</span>
                  <span className="text-2xl font-black font-mono text-white">{intelData.threatScore}/100</span>
                </div>
              </div>

              {/* Redirect Trace Box */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                  Redirect Path & Destination Unmasker
                </h4>

                {intelData.redirectInfo?.isRedirected ? (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 break-all">
                      <span className="text-slate-500 block text-[10px] uppercase">Original Link</span>
                      {intelData.redirectInfo.initialUrl}
                    </div>
                    <div className="flex justify-center">
                      <ArrowRight className="w-4 h-4 text-cyan-400 rotate-90 sm:rotate-0" />
                    </div>
                    <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 break-all">
                      <span className="text-rose-400 block text-[10px] uppercase font-bold">Unmasked Destination</span>
                      {intelData.redirectInfo.finalUrl}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 font-mono">
                    Direct destination reached (0 redirects). Final URL: <span className="text-white break-all">{intelData.url}</span>
                  </p>
                )}
              </div>

              {/* Deep Telemetry Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Shannon Entropy */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="text-[10px] uppercase font-mono text-slate-500 flex items-center gap-1.5">
                    <Cpu className="w-3 h-3 text-emerald-400" />
                    Shannon Entropy
                  </span>
                  <div className="text-lg font-bold font-mono text-white">
                    {intelData.entropy?.score || 0}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {intelData.entropy?.isHighEntropy ? (
                      <span className="text-rose-400 font-medium">⚠️ High entropy: likely DGA malware domain</span>
                    ) : (
                      'Normal lexical randomness'
                    )}
                  </p>
                </div>

                {/* TLD Rating */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="text-[10px] uppercase font-mono text-slate-500 flex items-center gap-1.5">
                    <Globe className="w-3 h-3 text-cyan-400" />
                    TLD Threat Level
                  </span>
                  <div className="text-lg font-bold font-mono uppercase text-white">
                    {intelData.tldRisk?.level || 'STANDARD'}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    .{intelData.tldRisk?.tld || 'com'} extension
                  </p>
                </div>

                {/* DNS / MX Status */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="text-[10px] uppercase font-mono text-slate-500 flex items-center gap-1.5">
                    <Mail className="w-3 h-3 text-amber-400" />
                    Mail Infrastructure (MX)
                  </span>
                  <div className="text-lg font-bold font-mono text-white">
                    {intelData.dnsReport?.hasValidMx ? 'CONFIGURED' : 'MISSING'}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {intelData.dnsReport?.hasValidMx ? (
                      <span className="text-emerald-400">Valid mail exchanger</span>
                    ) : (
                      <span className="text-amber-400">No MX records (spoof risk)</span>
                    )}
                  </p>
                </div>
              </div>

              {/* Indicators Detected */}
              {intelData.indicators && intelData.indicators.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <h4 className="text-xs font-semibold text-slate-200">Threat Signals Identified</h4>
                  <div className="space-y-1.5">
                    {intelData.indicators.map((ind, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 flex items-start gap-2"
                      >
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <span>{ind.detail}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {!isLoading && !intelData && !error && (
            <div className="py-12 text-center text-slate-500 text-xs font-mono">
              Enter any suspicious link or domain above to inspect real-time threat intelligence.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
