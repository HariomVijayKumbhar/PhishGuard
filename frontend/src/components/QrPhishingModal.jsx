import React, { useState, useRef } from 'react';
import {
  X, QrCode, RefreshCw, AlertTriangle, ShieldCheck, Globe, Lock
} from 'lucide-react';

const VERDICT_STYLES = {
  MALICIOUS: { color: 'text-rose-300', bg: 'bg-rose-500/10', border: 'border-rose-500/30', icon: <AlertTriangle className="w-6 h-6 text-rose-400" /> },
  SUSPICIOUS: { color: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-500/30', icon: <AlertTriangle className="w-6 h-6 text-amber-400" /> },
  BENIGN: { color: 'text-emerald-300', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', icon: <ShieldCheck className="w-6 h-6 text-emerald-400" /> }
};

const SEV_COLORS = {
  HIGH: 'text-rose-300 bg-rose-500/10 border-rose-500/30',
  MEDIUM: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  LOW: 'text-slate-300 bg-slate-700/40 border-slate-600'
};

export default function QrPhishingModal({ isOpen, onClose, backendUrl, token, onInspectUrl }) {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);

  if (!isOpen) return null;

  const handleFile = (f) => {
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) { setError('Image exceeds the 5MB limit.'); return; }
    if (!['image/png', 'image/jpeg', 'image/jpg', 'image/webp'].includes(f.type)) {
      setError('Only PNG, JPEG, or WebP screenshots are supported.'); return;
    }
    setFile(f);
    setResult(null);
    setError(null);
    setPreviewUrl(URL.createObjectURL(f));
  };

  const handleScan = async () => {
    if (!file) return;
    setIsScanning(true);
    setError(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append('image', file);
      const res = await fetch(`${backendUrl}/api/scan/qr`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'QR decoding failed');
      setResult(data.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const analysis = result?.analysis;
  const vStyle = analysis ? (VERDICT_STYLES[analysis.verdict] || VERDICT_STYLES.BENIGN) : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl max-h-[90vh] flex flex-col bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/40 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20">
              <QrCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Quishing Detector — QR Code Phishing Scanner</h3>
              <p className="text-xs text-slate-400">Decodes QR payloads fully in-memory. The extracted URL is never visited.</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5">
          {!previewUrl ? (
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files?.[0]); }}
              onClick={() => inputRef.current?.click()}
              className={`p-10 border-2 border-dashed rounded-2xl text-center cursor-pointer transition-colors ${dragOver ? 'border-fuchsia-500/60 bg-fuchsia-500/5' : 'border-slate-800 hover:border-fuchsia-500/40 bg-slate-950/60'
                }`}
            >
              <QrCode className="w-10 h-10 mx-auto text-slate-500 mb-3" />
              <p className="text-xs font-semibold text-white mb-1">Drop a QR screenshot here, or click to browse</p>
              <p className="text-[11px] text-slate-500">Fake MFA resets, Authenticator enrolment pages, HR benefit links… · PNG / JPEG / WebP · max 5MB</p>
              <input
                ref={inputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={(e) => handleFile(e.target.files?.[0])}
              />
            </div>
          ) : (
            <div className="flex gap-4 items-start">
              <img src={previewUrl} alt="QR upload preview" className="w-40 h-40 object-contain rounded-xl border border-slate-800 bg-slate-950" />
              <div className="flex-1 space-y-3 pt-1">
                <p className="text-xs text-slate-300 font-mono truncate">{file?.name}</p>
                <div className="flex gap-2">
                  <button
                    onClick={handleScan}
                    disabled={isScanning}
                    className="px-4 py-2.5 bg-fuchsia-500 hover:bg-fuchsia-400 text-slate-950 font-bold rounded-xl text-xs flex items-center gap-2 transition-colors disabled:opacity-50"
                  >
                    {isScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <QrCode className="w-3.5 h-3.5" />}
                    <span>{isScanning ? 'Decoding in-memory…' : 'Decode & Analyze QR'}</span>
                  </button>
                  <button
                    onClick={() => { setFile(null); setPreviewUrl(null); setResult(null); }}
                    className="px-3 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs transition-colors"
                  >
                    Replace
                  </button>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {analysis && (
            <div className="space-y-4 animate-in fade-in duration-200">
              <div className={`p-5 rounded-2xl border ${vStyle.bg} ${vStyle.border} flex items-center justify-between gap-4`}>
                <div className="flex items-center gap-3">
                  {vStyle.icon}
                  <div>
                    <span className="text-[10px] uppercase tracking-wider font-mono text-slate-400 block">QR Verdict</span>
                    <span className={`text-xl font-bold uppercase tracking-wider ${vStyle.color}`}>{analysis.verdict}</span>
                  </div>
                </div>
                <div className="flex items-baseline gap-2 bg-slate-950/70 px-4 py-2 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 font-mono">Score:</span>
                  <span className="text-2xl font-black font-mono text-white">{analysis.threatScore}/100</span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-[10px] uppercase font-mono text-slate-500">Decoded Payload (defanged for safe display)</div>
                <div className="font-mono text-xs text-fuchsia-200 break-all bg-slate-900 px-3 py-2.5 rounded-lg border border-slate-800">
                  {(result.rawText || '(non-URL data)').replace(/^https?:\/\//i, 'hxxp[://]').replace(/\./g, '[.]')}
                </div>
              </div>

              {analysis.lookalike && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20">
                  <div className="text-[10px] uppercase text-rose-400 mb-1">Brand Impersonation via QR</div>
                  <div className="text-rose-300 font-semibold">{analysis.lookalike.brand}</div>
                  <div className="text-rose-200/70 text-[11px] mt-1">{analysis.lookalike.reason}</div>
                </div>
              )}

              {analysis.indicators?.length > 0 ? (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <h4 className="text-xs font-semibold text-slate-200">Threat Signals</h4>
                  {analysis.indicators.map((ind, i) => (
                    <div key={i} className={`p-2.5 rounded-lg border text-xs flex items-start gap-2 ${SEV_COLORS[ind.severity] || SEV_COLORS.LOW}`}>
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 opacity-70" />
                      <div>
                        <span className="font-mono text-[10px] uppercase opacity-60 block">{ind.type}</span>
                        {ind.detail}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  No static threat indicators found in this QR payload.
                </div>
              )}

              {analysis.isUrl && (
                <button
                  onClick={() => { onClose(); onInspectUrl && onInspectUrl(analysis.payload); }}
                  className="w-full py-2.5 px-3 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition-all"
                >
                  <Globe className="w-4 h-4 text-cyan-400" />
                  <span>Inspect Live Threat Intel for this destination</span>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between shrink-0">
          <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1.5">
            <Lock className="w-3 h-3" /> In-memory decoding · pixel-bomb protection · zero auto-visits
          </span>
          <button onClick={onClose} className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
