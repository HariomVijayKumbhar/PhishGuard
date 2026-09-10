import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  Download,
  ShieldAlert,
  FileText,
  Radio,
  Share2,
  Lock,
  Terminal
} from 'lucide-react';

export default function DefensiveActionModal({ isOpen, onClose, scanResult }) {
  const [activeTab, setActiveTab] = useState('ticket');
  const [copiedKey, setCopiedKey] = useState(null);

  if (!isOpen || !scanResult) return null;

  const incidentKit = scanResult.incident_kit || {};
  const iocs = incidentKit.iocs || {};
  const socTicket = incidentKit.socTicketMarkdown || '';
  const blocklistRules = incidentKit.blocklistRules || {
    hostsFormat: '',
    cloudflareCsv: '',
    rawList: ''
  };
  const teamAlert = incidentKit.teamAlert || '';

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2500);
    });
  };

  const downloadMarkdownFile = () => {
    const blob = new Blob([socTicket], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `phishguard-incident-${Date.now()}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                SOC Incident Response & Action Kit
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  {scanResult.verdict || 'TRIAGED'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Enterprise containment tools, defanged IOC telemetry, and automated security tickets
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

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 px-6 gap-2 text-xs font-medium overflow-x-auto">
          <button
            onClick={() => setActiveTab('ticket')}
            className={`py-3 px-3 border-b-2 transition-all flex items-center gap-2 shrink-0 ${
              activeTab === 'ticket'
                ? 'border-emerald-400 text-white font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>SOC Incident Ticket</span>
          </button>

          <button
            onClick={() => setActiveTab('blocklist')}
            className={`py-3 px-3 border-b-2 transition-all flex items-center gap-2 shrink-0 ${
              activeTab === 'blocklist'
                ? 'border-emerald-400 text-white font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>DNS & Firewall Rules</span>
          </button>

          <button
            onClick={() => setActiveTab('alert')}
            className={`py-3 px-3 border-b-2 transition-all flex items-center gap-2 shrink-0 ${
              activeTab === 'alert'
                ? 'border-emerald-400 text-white font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Share2 className="w-4 h-4" />
            <span>Internal Team Warning</span>
          </button>

          <button
            onClick={() => setActiveTab('iocs')}
            className={`py-3 px-3 border-b-2 transition-all flex items-center gap-2 shrink-0 ${
              activeTab === 'iocs'
                ? 'border-emerald-400 text-white font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Defanged IOC Vault</span>
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-4">
          {/* TAB 1: SOC TICKET */}
          {activeTab === 'ticket' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-400">
                  Standardized Incident Ticket formatted for Jira, ServiceNow, or SOC triage archives.
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={downloadMarkdownFile}
                    className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors border border-slate-700"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .md</span>
                  </button>
                  <button
                    onClick={() => copyToClipboard(socTicket, 'ticket')}
                    className="px-3 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-emerald-500/20"
                  >
                    {copiedKey === 'ticket' ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Markdown</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto select-all">
                {socTicket}
              </div>
            </div>
          )}

          {/* TAB 2: BLOCKLIST RULES */}
          {activeTab === 'blocklist' && (
            <div className="space-y-6">
              <p className="text-xs text-slate-400">
                Immediately block observed malicious domains across internal firewalls, DNS filters, and endpoint hosts files.
              </p>

              {/* Pi-hole & Hosts format */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    Hosts File & Pi-hole / AdGuard DNS Format
                  </span>
                  <button
                    onClick={() => copyToClipboard(blocklistRules.hostsFormat, 'hosts')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium flex items-center gap-1 transition-colors"
                  >
                    {copiedKey === 'hosts' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'hosts' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-900 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto">
                  {blocklistRules.hostsFormat}
                </pre>
              </div>

              {/* Cloudflare CSV format */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white flex items-center gap-2">
                    <Radio className="w-3.5 h-3.5 text-blue-400" />
                    Cloudflare Zero Trust / Gateway CSV
                  </span>
                  <button
                    onClick={() => copyToClipboard(blocklistRules.cloudflareCsv, 'cf')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium flex items-center gap-1 transition-colors"
                  >
                    {copiedKey === 'cf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'cf' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-900 rounded-lg text-xs font-mono text-blue-300 overflow-x-auto">
                  {blocklistRules.cloudflareCsv}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 3: TEAM WARNING ALERT */}
          {activeTab === 'alert' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-400">
                  Pre-composed warning notification for Slack, Microsoft Teams, or broadcast email.
                </p>
                <button
                  onClick={() => copyToClipboard(teamAlert, 'alert')}
                  className="px-3 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-emerald-500/20"
                >
                  {copiedKey === 'alert' ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Team Alert</span>
                    </>
                  )}
                </button>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-sans text-slate-200 whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
                {teamAlert}
              </div>
            </div>
          )}

          {/* TAB 4: DEFANGED IOC VAULT */}
          {activeTab === 'iocs' && (
            <div className="space-y-4">
              <p className="text-xs text-slate-400">
                All URLs and IP indicators are defanged according to CERT security standards to avoid triggering mail filters or accidental clicks.
              </p>

              <div className="space-y-3 text-xs font-mono">
                {/* Email Hash */}
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Payload SHA-256</span>
                    <span className="text-emerald-400 break-all">{iocs.emailSha256 || 'N/A'}</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(iocs.emailSha256, 'sha')}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 self-start sm:self-auto"
                  >
                    {copiedKey === 'sha' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {/* Sender Telemetry */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Defanged Sender Domain</span>
                    <span className="text-white">{iocs.defangedSenderDomain || 'N/A'}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Observed Sender IP</span>
                    <span className="text-white">{iocs.senderIp || 'N/A'}</span>
                  </div>
                </div>

                {/* Defanged URLs list */}
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-slate-500 block text-[10px] uppercase">Defanged Destinations ({iocs.defangedUrls?.length || 0})</span>
                  {iocs.defangedUrls && iocs.defangedUrls.length > 0 ? (
                    <ul className="space-y-1">
                      {iocs.defangedUrls.map((u, i) => (
                        <li key={i} className="text-rose-400 break-all bg-slate-900/60 p-2 rounded-lg border border-slate-800">
                          {u}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-slate-500 italic">No external links found.</span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close Action Kit
          </button>
        </div>
      </div>
    </div>
  );
}
