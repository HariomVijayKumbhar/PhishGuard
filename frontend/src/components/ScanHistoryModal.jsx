import React, { useState, useEffect } from 'react';
import { X, History, Loader2, AlertCircle, ShieldAlert, ShieldCheck, Shield, ChevronRight, Calendar } from 'lucide-react';

export default function ScanHistoryModal({ isOpen, onClose, backendUrl, token }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isOpen || !token) return;

    setLoading(true);
    setError(null);

    fetch(`${backendUrl}/api/scans`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load scan history');
        return res.json();
      })
      .then((data) => {
        setScans(data.scans || []);
      })
      .catch((err) => {
        setError(err.message || 'Error fetching scans');
      })
      .finally(() => {
        setLoading(false);
      });
  }, [isOpen, token, backendUrl]);

  if (!isOpen) return null;

  const getVerdictBadge = (verdict, score) => {
    if (verdict === 'phishing' || score >= 70) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <ShieldAlert className="w-3.5 h-3.5" /> Phishing ({score})
        </span>
      );
    }
    if (verdict === 'suspicious' || score >= 40) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <Shield className="w-3.5 h-3.5" /> Suspicious ({score})
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        <ShieldCheck className="w-3.5 h-3.5" /> Safe ({score})
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Your Scan History</h3>
              <p className="text-xs text-slate-400">Past email threat assessments stored under Row Level Security</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-3">
          {loading && (
            <div className="py-12 flex flex-col items-center justify-center text-slate-400 gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-emerald-400" />
              <p className="text-xs">Loading past scans from database...</p>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!loading && !error && scans.length === 0 && (
            <div className="py-12 text-center text-slate-400 space-y-2">
              <History className="w-8 h-8 mx-auto text-slate-600" />
              <p className="text-sm font-medium text-slate-300">No scans found yet</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Any emails you scan while signed in will automatically appear here with their risk scores and verdicts.
              </p>
            </div>
          )}

          {!loading && !error && scans.map((scan) => (
            <div
              key={scan.id}
              className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors space-y-2"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <h4 className="text-xs font-semibold text-white truncate">
                    {scan.subject || '(No Subject)'}
                  </h4>
                  <p className="text-[11px] text-slate-400 truncate">
                    From: <span className="font-mono text-slate-300">{scan.sender || 'Unknown Sender'}</span>
                  </p>
                </div>
                <div>{getVerdictBadge(scan.verdict, scan.risk_score)}</div>
              </div>

              {scan.explanation && (
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed bg-slate-900/60 p-2 rounded-lg border border-slate-800/40">
                  {scan.explanation}
                </p>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                <span className="flex items-center gap-1 font-mono">
                  <Calendar className="w-3 h-3" />
                  {new Date(scan.created_at).toLocaleString()}
                </span>
                <span className="text-slate-400">
                  Provider: <span className="text-emerald-400 capitalize">{scan.ai_provider || 'AI'}</span>
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-950/80 border-t border-slate-800/80 flex justify-between items-center text-xs text-slate-500">
          <span>Total Recorded: {scans.length}</span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
