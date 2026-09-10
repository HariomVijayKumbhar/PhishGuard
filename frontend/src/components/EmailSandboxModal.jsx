import React, { useState, useRef, useCallback } from 'react';
import {
  X,
  AlertTriangle,
  ShieldAlert,
  Globe,
  ExternalLink,
  Eye,
  FileText,
  ChevronRight,
  Lock
} from 'lucide-react';

// ─── Threat colour tokens ───────────────────────────────────────────────────
const THREAT_STYLES = {
  lookalike: {
    label: 'Spoofed Domain',
    color: 'text-rose-300',
    bg: 'bg-rose-500/20',
    border: 'border-rose-500/50',
    glow: 'shadow-rose-500/40',
    dot: 'bg-rose-500',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
    icon: <ShieldAlert className="w-4 h-4 text-rose-400" />
  },
  mismatch: {
    label: 'Anchor Mismatch',
    color: 'text-amber-300',
    bg: 'bg-amber-500/20',
    border: 'border-amber-500/50',
    glow: 'shadow-amber-500/40',
    dot: 'bg-amber-500',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    icon: <AlertTriangle className="w-4 h-4 text-amber-400" />
  },
  ip: {
    label: 'Raw IP Link',
    color: 'text-yellow-300',
    bg: 'bg-yellow-500/20',
    border: 'border-yellow-500/50',
    glow: 'shadow-yellow-500/40',
    dot: 'bg-yellow-500',
    badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    icon: <Globe className="w-4 h-4 text-yellow-400" />
  },
  flagged: {
    label: 'Flagged Link',
    color: 'text-orange-300',
    bg: 'bg-orange-500/20',
    border: 'border-orange-500/50',
    glow: 'shadow-orange-500/40',
    dot: 'bg-orange-500',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    icon: <AlertTriangle className="w-4 h-4 text-orange-400" />
  },
  external: {
    label: 'External Link',
    color: 'text-blue-300',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    glow: 'shadow-blue-500/20',
    dot: 'bg-blue-500',
    badge: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
    icon: <ExternalLink className="w-4 h-4 text-blue-400" />
  },
  clean: {
    label: 'External Link',
    color: 'text-blue-300',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    glow: 'shadow-blue-500/20',
    dot: 'bg-blue-500',
    badge: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
    icon: <ExternalLink className="w-4 h-4 text-blue-400" />
  }
};

const URGENCY_SEVERITY_STYLES = {
  high: { bg: 'bg-purple-500/25', border: 'border-purple-500/50', text: 'text-purple-200', dot: 'bg-purple-500' },
  medium: { bg: 'bg-purple-400/20', border: 'border-purple-400/40', text: 'text-purple-300', dot: 'bg-purple-400' },
  low: { bg: 'bg-purple-300/15', border: 'border-purple-300/30', text: 'text-purple-400', dot: 'bg-purple-300' }
};

// ─── Sandbox CSS injected into the page ────────────────────────────────────
const SANDBOX_STYLES = `
  .pg-sandbox-body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    line-height: 1.6;
    color: #cbd5e1;
    word-break: break-word;
  }
  .pg-sandbox-body p { margin: 0.5em 0; }
  .pg-sandbox-body h1, .pg-sandbox-body h2, .pg-sandbox-body h3 {
    color: #f1f5f9; margin: 0.8em 0 0.4em;
  }
  .pg-sandbox-body table { border-collapse: collapse; width: 100%; }
  .pg-sandbox-body td, .pg-sandbox-body th {
    padding: 6px 8px; border: 1px solid #334155;
  }
  /* Link threat classes */
  .pg-link {
    display: inline;
    padding: 1px 4px;
    border-radius: 4px;
    border: 1px solid;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.15s ease;
  }
  .pg-link:hover { filter: brightness(1.15); }
  .pg-threat-lookalike {
    background: rgba(239,68,68,0.18);
    border-color: rgba(239,68,68,0.55);
    color: #fca5a5;
    box-shadow: 0 0 8px rgba(239,68,68,0.35), inset 0 0 6px rgba(239,68,68,0.1);
  }
  .pg-threat-lookalike:hover {
    box-shadow: 0 0 16px rgba(239,68,68,0.55), inset 0 0 10px rgba(239,68,68,0.2);
  }
  .pg-threat-mismatch {
    background: rgba(245,158,11,0.18);
    border-color: rgba(245,158,11,0.55);
    color: #fcd34d;
    box-shadow: 0 0 8px rgba(245,158,11,0.35);
  }
  .pg-threat-mismatch:hover {
    box-shadow: 0 0 16px rgba(245,158,11,0.5);
  }
  .pg-threat-ip {
    background: rgba(234,179,8,0.18);
    border-color: rgba(234,179,8,0.55);
    color: #fef08a;
    box-shadow: 0 0 8px rgba(234,179,8,0.35);
  }
  .pg-threat-external, .pg-threat-clean {
    background: rgba(59,130,246,0.12);
    border-color: rgba(59,130,246,0.35);
    color: #93c5fd;
  }
  .pg-threat-external:hover, .pg-threat-clean:hover {
    background: rgba(59,130,246,0.2);
  }
  /* Urgency phrase classes */
  .pg-urgency {
    display: inline;
    padding: 1px 3px;
    border-radius: 3px;
    border-bottom: 2px solid;
    cursor: help;
  }
  .pg-sev-high {
    background: rgba(168,85,247,0.22);
    border-bottom-color: rgba(168,85,247,0.7);
    color: #e9d5ff;
  }
  .pg-sev-medium {
    background: rgba(167,84,247,0.15);
    border-bottom-color: rgba(167,84,247,0.5);
    color: #ddd6fe;
  }
  .pg-sev-low {
    background: rgba(167,84,247,0.08);
    border-bottom-color: rgba(167,84,247,0.35);
    color: #ede9fe;
  }
`;

// ─── Text Segment Renderer (plain-text emails) ──────────────────────────────
function TextSegmentRenderer({ segments, onElementClick }) {
  return (
    <div className="font-mono text-xs leading-relaxed text-slate-300 whitespace-pre-wrap">
      {segments.map((seg, i) => {
        if (seg.type === 'text') {
          return <span key={i}>{seg.content}</span>;
        }
        if (seg.type === 'urgency') {
          const sev = URGENCY_SEVERITY_STYLES[seg.severity] || URGENCY_SEVERITY_STYLES.medium;
          return (
            <span
              key={i}
              className={`${sev.bg} ${sev.text} border-b-2 ${sev.border} cursor-help px-0.5 rounded-sm`}
              title={`${seg.category} — Psychological manipulation phrase`}
              onClick={() => onElementClick({ type: 'urgency', ...seg })}
            >
              {seg.content}
            </span>
          );
        }
        if (seg.type === 'link') {
          const style = THREAT_STYLES[seg.threatClass] || THREAT_STYLES.external;
          return (
            <span
              key={i}
              className={`${style.bg} ${style.color} border ${style.border} cursor-pointer px-1 py-0.5 rounded font-semibold`}
              onClick={() => onElementClick({ type: 'link', ...seg })}
              title={`${style.label} — Click to inspect`}
            >
              {seg.content}
            </span>
          );
        }
        return null;
      })}
    </div>
  );
}

// ─── Threat Detail Panel (right sidebar) ───────────────────────────────────
function ThreatDetailPanel({ selection, onInspectUrl, onClose }) {
  if (!selection) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center px-6 text-slate-500">
        <Eye className="w-8 h-8 mb-3 opacity-40" />
        <p className="text-xs leading-relaxed">
          Click any <span className="text-rose-400">highlighted link</span> or{' '}
          <span className="text-purple-400">underlined phrase</span> in the preview to inspect its threat details here.
        </p>
      </div>
    );
  }

  const isUrgency = selection.type === 'urgency';
  const isLink = selection.type === 'link';
  const threat = selection.threatClass || 'clean';
  const style = THREAT_STYLES[threat] || THREAT_STYLES.external;

  return (
    <div className="p-4 space-y-4 overflow-y-auto h-full text-xs">
      {/* Threat type badge */}
      <div className="space-y-2">
        <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-xl border ${style.badge}`}>
          {style.icon}
          <span className="font-bold uppercase tracking-wider">
            {isUrgency ? 'Psychological Trigger' : style.label}
          </span>
        </div>

        {isUrgency && (
          <>
            <div className="p-3 rounded-xl bg-slate-950 border border-purple-500/20 space-y-1.5">
              <div className="text-[10px] uppercase text-slate-500">Category</div>
              <div className="text-purple-300 font-semibold">{selection.category}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] uppercase text-slate-500 mb-1">Detected Phrase</div>
              <div className="text-purple-200 font-mono bg-purple-500/10 px-2 py-1 rounded border border-purple-500/20 italic">
                "{selection.phrase || selection.content}"
              </div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] uppercase text-slate-500 mb-1">Severity</div>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                selection.severity === 'high' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
                selection.severity === 'medium' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                'bg-slate-700 text-slate-300 border-slate-600'
              }`}>
                {selection.severity || 'low'}
              </span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed p-2">
              This phrase is a common social engineering tactic used to create a sense of <strong className="text-purple-300">urgency, fear, or authority</strong> to pressure victims into immediate action without rational consideration.
            </p>
          </>
        )}

        {isLink && (
          <>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="text-[10px] uppercase text-slate-500">Destination (Defanged)</div>
              <div className={`font-mono ${style.color} break-all bg-slate-900 px-2 py-1.5 rounded border border-slate-800`}>
                {(selection.href || '').replace(/^https?:\/\//i, 'hxxps[://]').replace(/\./g, '[.]')}
              </div>
            </div>

            {threat === 'lookalike' && selection.linkData?.lookalike && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 space-y-2">
                <div className="text-[10px] uppercase text-rose-400">Brand Impersonation</div>
                <div className="text-rose-300 font-semibold">{selection.linkData.lookalike.brand}</div>
                <div className="text-rose-200/70 text-[11px] leading-relaxed">
                  {selection.linkData.lookalike.reason}
                </div>
                {selection.linkData.lookalike.distance !== undefined && (
                  <div className="text-[10px] text-slate-400">
                    Levenshtein distance: <span className="text-rose-300 font-mono font-bold">{selection.linkData.lookalike.distance}</span> (≤ 2 = lookalike)
                  </div>
                )}
              </div>
            )}

            {threat === 'mismatch' && selection.linkData?.mismatch && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-2">
                <div className="text-[10px] uppercase text-amber-400">Link Mismatch Deception</div>
                <div className="text-[11px] text-slate-300 leading-relaxed">
                  {selection.linkData.mismatch.reason}
                </div>
              </div>
            )}

            {threat === 'ip' && (
              <div className="p-3 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
                <div className="text-[10px] uppercase text-yellow-400 mb-1">Raw IP Address</div>
                <p className="text-yellow-200/80 text-[11px] leading-relaxed">
                  Legitimate services never link to raw IP addresses. This is a strong indicator of a phishing or malware distribution endpoint.
                </p>
              </div>
            )}

            {/* Inspect button */}
            {selection.href && (
              <button
                onClick={() => onInspectUrl(selection.href)}
                className="w-full py-2.5 px-3 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition-all"
              >
                <Globe className="w-4 h-4 text-cyan-400" />
                <span>Inspect Live Threat Intel</span>
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400 ml-auto" />
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function EmailSandboxModal({ isOpen, onClose, scanResult, onOpenThreatIntel, token }) {
  const [activeTab, setActiveTab] = useState('preview'); // 'preview' | 'text'
  const [selection, setSelection] = useState(null);
  const previewRef = useRef(null);

  // Auth guard — sandbox is a members-only feature
  const isAuthenticated = Boolean(token);

  const sandbox = scanResult?.sandbox_preview || {};
  const heuristics = scanResult?.heuristics || {};
  const metadata = scanResult?.metadata || {};

  // Count threats from heuristics
  const lookalikeCount = heuristics.lookalikeCount || 0;
  const mismatchCount = heuristics.anchorMismatchCount || 0;
  const ipCount = heuristics.ipLinksCount || 0;
  const urgencyCount = (sandbox.annotatedHtml?.match(/pg-urgency/g) || []).length;
  const totalThreats = lookalikeCount + mismatchCount + ipCount;

  const handleSandboxClick = useCallback((e) => {
    const target = e.target.closest('[data-threat], [data-category]');
    if (!target) { setSelection(null); return; }

    const threat = target.getAttribute('data-threat');
    const category = target.getAttribute('data-category');

    if (category) {
      // Urgency phrase clicked
      setSelection({
        type: 'urgency',
        category,
        phrase: target.getAttribute('data-phrase'),
        content: target.textContent,
        severity: target.className.includes('pg-sev-high') ? 'high'
          : target.className.includes('pg-sev-medium') ? 'medium' : 'low'
      });
    } else if (threat) {
      // Link span clicked
      const href = target.getAttribute('data-href') || '';
      const detail = target.getAttribute('data-detail') || '';
      const brand = target.getAttribute('data-brand') || '';
      const actual = target.getAttribute('data-actual') || '';

      const linkData = {
        lookalike: threat === 'lookalike' ? { brand, reason: detail } : null,
        mismatch: threat === 'mismatch' ? { reason: detail, actualHref: actual } : null
      };

      setSelection({ type: 'link', href, threatClass: threat, detail, linkData });
    }
  }, []);

  const handleInspectUrl = (url) => {
    onClose();
    if (onOpenThreatIntel) onOpenThreatIntel(url);
  };

  if (!isOpen || !scanResult) return null;

  // Hard auth gate — render a locked screen instead of the sandbox if not logged in
  if (!isAuthenticated) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
        <div className="relative w-full max-w-md p-8 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl text-center space-y-4">
          <div className="mx-auto p-3 w-fit rounded-2xl bg-rose-500/10 border border-rose-500/20">
            <Lock className="w-8 h-8 text-rose-400" />
          </div>
          <h3 className="text-base font-bold text-white">Sandbox Access Restricted</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            The Safe Email Threat Sandbox is available to authenticated users only. Sign in or create a free account to unlock interactive threat overlays and live threat intel inspection.
          </p>
          <button
            onClick={onClose}
            className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  const hasContent = sandbox.hasHtml
    ? Boolean(sandbox.annotatedHtml)
    : (sandbox.textSegments?.length > 0 || Boolean(sandbox.textBody));

  return (
    <>
      {/* Inject sandbox styles */}
      <style dangerouslySetInnerHTML={{ __html: SANDBOX_STYLES }} />

      <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
        <div className="relative w-full max-w-6xl max-h-[95vh] flex flex-col bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">

          {/* ── HEADER ── */}
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950/50 shrink-0">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Eye className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2.5">
                  Safe Email Threat Sandbox
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono border bg-rose-500/10 text-rose-300 border-rose-500/20">
                    🔒 SANDBOXED PREVIEW
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  All links neutralized · Images stripped · Scripts blocked · Interactive threat overlays active
                </p>
              </div>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* ── STATS BAR ── */}
          <div className="flex items-center gap-3 px-5 py-2 border-b border-slate-800 bg-slate-950/30 text-[11px] font-mono shrink-0 overflow-x-auto">
            <span className="text-slate-500">Signals:</span>
            <span className={`flex items-center gap-1.5 ${lookalikeCount > 0 ? 'text-rose-400' : 'text-slate-600'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${lookalikeCount > 0 ? 'bg-rose-500' : 'bg-slate-700'}`}></span>
              {lookalikeCount} Spoofed Domain{lookalikeCount !== 1 ? 's' : ''}
            </span>
            <span className={`flex items-center gap-1.5 ${mismatchCount > 0 ? 'text-amber-400' : 'text-slate-600'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${mismatchCount > 0 ? 'bg-amber-500' : 'bg-slate-700'}`}></span>
              {mismatchCount} Link Mismatch{mismatchCount !== 1 ? 'es' : ''}
            </span>
            <span className={`flex items-center gap-1.5 ${ipCount > 0 ? 'text-yellow-400' : 'text-slate-600'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${ipCount > 0 ? 'bg-yellow-500' : 'bg-slate-700'}`}></span>
              {ipCount} Raw IP Link{ipCount !== 1 ? 's' : ''}
            </span>
            <span className={`flex items-center gap-1.5 ${urgencyCount > 0 ? 'text-purple-400' : 'text-slate-600'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${urgencyCount > 0 ? 'bg-purple-500' : 'bg-slate-700'}`}></span>
              {urgencyCount} Urgency Trigger{urgencyCount !== 1 ? 's' : ''}
            </span>

            {/* Email metadata */}
            <span className="ml-auto text-slate-600 hidden lg:block truncate max-w-xs">
              From: {metadata.from || 'Unknown'} · {metadata.subject || '(No Subject)'}
            </span>
          </div>

          {/* ── TAB BAR ── */}
          {(sandbox.hasHtml && sandbox.textBody) && (
            <div className="flex border-b border-slate-800 bg-slate-950/40 px-5 text-xs font-medium shrink-0">
              <button
                onClick={() => setActiveTab('preview')}
                className={`py-2.5 px-3 border-b-2 transition-all flex items-center gap-1.5 ${
                  activeTab === 'preview'
                    ? 'border-emerald-400 text-white font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                HTML Preview
              </button>
              <button
                onClick={() => setActiveTab('text')}
                className={`py-2.5 px-3 border-b-2 transition-all flex items-center gap-1.5 ${
                  activeTab === 'text'
                    ? 'border-emerald-400 text-white font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                Plain Text
              </button>
            </div>
          )}

          {/* ── MAIN BODY: Preview + Threat Detail Panel ── */}
          <div className="flex flex-1 overflow-hidden min-h-0">

            {/* Left: Email Preview */}
            <div className="flex-1 overflow-y-auto border-r border-slate-800 min-w-0">
              {!hasContent ? (
                <div className="flex items-center justify-center h-full text-center text-slate-500 text-xs px-8">
                  <div className="space-y-2">
                    <Lock className="w-8 h-8 mx-auto opacity-40" />
                    <p>No preview content available for this email.<br />The email may be text-only without extractable body content.</p>
                  </div>
                </div>
              ) : (activeTab === 'text' || !sandbox.hasHtml) ? (
                <div className="p-5">
                  {sandbox.textSegments && sandbox.textSegments.length > 0 ? (
                    <TextSegmentRenderer
                      segments={sandbox.textSegments}
                      onElementClick={setSelection}
                    />
                  ) : (
                    <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                      {sandbox.textBody}
                    </pre>
                  )}
                </div>
              ) : (
                /* HTML annotated preview */
                <div
                  ref={previewRef}
                  className="p-5 pg-sandbox-body"
                  onClick={handleSandboxClick}
                  dangerouslySetInnerHTML={{ __html: sandbox.annotatedHtml }}
                />
              )}
            </div>

            {/* Right: Threat Detail Panel */}
            <div className="w-72 shrink-0 flex flex-col bg-slate-950/30 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 text-[10px] uppercase font-bold text-slate-500 tracking-widest flex items-center gap-2 shrink-0">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                Threat Detail Panel
              </div>
              <div className="flex-1 overflow-y-auto">
                <ThreatDetailPanel
                  selection={selection}
                  onInspectUrl={handleInspectUrl}
                  onClose={() => setSelection(null)}
                />
              </div>
            </div>
          </div>

          {/* ── LEGEND BAR ── */}
          <div className="flex items-center gap-4 px-5 py-2.5 border-t border-slate-800 bg-slate-950/60 text-[10px] font-mono text-slate-500 shrink-0 flex-wrap">
            <span className="font-bold text-slate-400 mr-1">Legend:</span>
            {[
              { dot: 'bg-rose-500', label: 'Spoofed Domain' },
              { dot: 'bg-amber-500', label: 'Anchor Mismatch' },
              { dot: 'bg-yellow-400', label: 'Raw IP Link' },
              { dot: 'bg-purple-500', label: 'Urgency Phrase' },
              { dot: 'bg-blue-500', label: 'External Link' }
            ].map(({ dot, label }) => (
              <span key={label} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${dot} shrink-0`}></span>
                {label}
              </span>
            ))}
          </div>

        </div>
      </div>
    </>
  );
}
