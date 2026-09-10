import React, { useState } from 'react';
import {
  X, Gamepad2, Trophy, CheckCircle2, XCircle, RotateCcw, ChevronRight,
  Target, AlertTriangle, Lightbulb, Award
} from 'lucide-react';
import SCENARIOS from '../data/phishScenarios.json';

const DIFFICULTY_STYLES = {
  easy: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  medium: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  hard: 'bg-rose-500/10 text-rose-300 border-rose-500/30'
};

export default function SpotThePhishLab({ isOpen, onClose }) {
  const [screen, setScreen] = useState('menu'); // menu | play | result
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [picks, setPicks] = useState({}); // segmentIdx -> true
  const [submitted, setSubmitted] = useState(false);
  const [score, setScore] = useState({ points: 0, total: 0, streak: 0 });

  if (!isOpen) return null;

  const scenario = SCENARIOS.scenarios[scenarioIdx];
  const suspiciousIdx = scenario.segments
    .map((s, i) => (s.t === 'susp' ? i : -1))
    .filter(i => i >= 0);

  const togglePick = (i) => {
    if (submitted) return;
    setPicks(p => ({ ...p, [i]: !p[i] }));
  };

  const handleSubmit = () => {
    let correct = 0, falsePositives = 0;
    for (const i of Object.keys(picks)) {
      if (!picks[i]) continue;
      if (suspiciousIdx.includes(Number(i))) correct++;
      else falsePositives++;
    }
    const missed = suspiciousIdx.filter(i => !picks[i]).length;
    const points = Math.max(0, correct * 100 - falsePositives * 50 - missed * 25);
    const perfect = missed === 0 && falsePositives === 0;
    setScore(s => ({
      points: s.points + points,
      total: s.total + suspiciousIdx.length * 100,
      streak: perfect ? s.streak + 1 : 0
    }));
    setSubmitted(true);
  };

  const nextScenario = () => {
    if (scenarioIdx + 1 < SCENARIOS.scenarios.length) {
      setScenarioIdx(scenarioIdx + 1);
      setPicks({});
      setSubmitted(false);
    } else {
      setScreen('result');
    }
  };

  const restart = () => {
    setScenarioIdx(0); setPicks({}); setSubmitted(false); setScore({ points: 0, total: 0, streak: 0 }); setScreen('menu');
  };

  const accuracy = score.total > 0 ? Math.round((score.points / score.total) * 100) : 0;
  const rank = accuracy >= 90 ? { title: '🥇 Cyber Defender Elite', color: 'text-amber-300' }
    : accuracy >= 70 ? { title: '🛡️ Threat Analyst', color: 'text-cyan-300' }
      : accuracy >= 40 ? { title: '🎯 Trainee Analyst', color: 'text-emerald-300' }
        : { title: '📚 Cadet — Keep Training', color: 'text-slate-300' };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/40 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-violet-500/10 text-violet-400 border border-violet-500/20">
              <Gamepad2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Spot the Phish — Security Training Lab</h3>
              <p className="text-xs text-slate-400">Click every suspicious element. Static sanitized case studies — zero external execution.</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs">
              <Trophy className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-white font-bold">{score.points}</span>
              {score.streak > 0 && <span className="text-emerald-400">🔥{score.streak}</span>}
            </div>
            <button onClick={onClose} className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5">

          {screen === 'menu' && (
            <div className="space-y-4">
              <div className="p-5 rounded-2xl bg-gradient-to-r from-violet-600/20 via-slate-900 to-slate-900 border border-violet-500/30 space-y-2">
                <h4 className="text-sm font-bold text-white flex items-center gap-2"><Target className="w-4 h-4 text-violet-400" /> Test your instincts</h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {SCENARIOS.scenarios.length} real-world sanitized attack scenarios: CEO Fraud, Fake Invoice, Ransomware Delivery, and Cloud Account Takeover.
                  Click every element you believe is suspicious — false clicks cost points, missed threats cost more.
                </p>
                <div className="flex gap-2 pt-2 text-[10px] font-mono">
                  <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">+100 correct</span>
                  <span className="px-2 py-1 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">−50 false alarm</span>
                  <span className="px-2 py-1 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">−25 missed threat</span>
                </div>
              </div>

              <div className="space-y-2">
                {SCENARIOS.scenarios.map((s, i) => (
                  <button
                    key={s.id}
                    onClick={() => { setScenarioIdx(i); setPicks({}); setSubmitted(false); setScreen('play'); }}
                    className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-violet-500/40 text-left flex items-center justify-between gap-3 transition-all group"
                  >
                    <div>
                      <div className="text-xs font-bold text-white group-hover:text-violet-200">{s.title}</div>
                      <div className="text-[11px] text-slate-500 font-mono mt-0.5 truncate max-w-md">From: {s.from}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${DIFFICULTY_STYLES[s.difficulty]}`}>{s.difficulty}</span>
                      <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-violet-400" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {screen === 'play' && (
            <div className="space-y-4">
              {/* Email mock */}
              <div className="rounded-2xl bg-slate-950 border border-slate-800 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800 space-y-1">
                  <div className="text-[11px] font-mono"><span className="text-slate-500">From: </span><span className="text-slate-300">{scenario.from}</span></div>
                  <div className="text-[11px] font-mono"><span className="text-slate-500">Subject: </span><span className="text-white font-semibold">{scenario.subject}</span></div>
                </div>
                <div className="p-4 space-y-1.5">
                  {scenario.segments.map((seg, i) => (
                    <span
                      key={i}
                      onClick={() => togglePick(i)}
                      className={`inline text-[13px] leading-relaxed cursor-pointer rounded px-0.5 transition-all ${submitted
                        ? seg.t === 'susp'
                          ? 'bg-rose-500/20 text-rose-200 border-b-2 border-rose-500 cursor-default'
                          : picks[i]
                            ? 'bg-amber-500/15 text-amber-200 border-b-2 border-amber-500 cursor-default'
                            : 'text-slate-300 cursor-default'
                        : picks[i]
                          ? 'bg-violet-500/25 text-violet-100 ring-1 ring-violet-500/50'
                          : 'text-slate-300 hover:bg-slate-800/60'
                        }`}
                    >
                      {seg.v}
                    </span>
                  ))}
                </div>
              </div>

              {!submitted ? (
                <button
                  onClick={handleSubmit}
                  disabled={Object.values(picks).filter(Boolean).length === 0}
                  className="w-full py-3 bg-violet-500 hover:bg-violet-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 font-bold rounded-xl text-xs uppercase tracking-wider transition-colors"
                >
                  Submit Analysis ({Object.values(picks).filter(Boolean).length} selected)
                </button>
              ) : (
                <div className="space-y-3 animate-in fade-in duration-200">
                  {/* Verdict banner */}
                  {(() => {
                    const missed = suspiciousIdx.filter(i => !picks[i]).length;
                    const fps = Object.keys(picks).filter(i => picks[i] && !suspiciousIdx.includes(Number(i))).length;
                    const perfect = missed === 0 && fps === 0;
                    return (
                      <div className={`p-4 rounded-xl border flex items-center gap-3 ${perfect ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-amber-500/10 border-amber-500/30'}`}>
                        {perfect ? <Trophy className="w-6 h-6 text-emerald-400" /> : <AlertTriangle className="w-6 h-6 text-amber-400" />}
                        <div>
                          <div className={`text-sm font-bold ${perfect ? 'text-emerald-300' : 'text-amber-300'}`}>
                            {perfect ? 'Flawless detection!' : `${missed} missed · ${fps} false alarm${fps !== 1 ? 's' : ''}`}
                          </div>
                          <div className="text-[11px] text-slate-400">Click each highlight below to learn the tell-tale sign.</div>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Explanations */}
                  <div className="space-y-2">
                    {suspiciousIdx.map(i => (
                      <div key={i} className="p-3 rounded-xl bg-slate-950 border border-rose-500/20 space-y-1.5">
                        <div className="flex items-center gap-2">
                          {picks[i] ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-rose-500/10 text-rose-300 border border-rose-500/20">{scenario.segments[i].category}</span>
                        </div>
                        <div className="text-[11px] text-slate-300 italic font-mono bg-slate-900 px-2 py-1.5 rounded border border-slate-800">
                          "{scenario.segments[i].v.length > 90 ? scenario.segments[i].v.slice(0, 90) + '…' : scenario.segments[i].v}"
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed flex gap-1.5">
                          <Lightbulb className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                          {scenario.segments[i].reason}
                        </p>
                      </div>
                    ))}
                    {Object.keys(picks).filter(i => picks[i] && !suspiciousIdx.includes(Number(i))).map(i => (
                      <div key={`fp-${i}`} className="p-3 rounded-xl bg-slate-950 border border-amber-500/20">
                        <div className="flex items-center gap-2">
                          <XCircle className="w-4 h-4 text-amber-400" />
                          <span className="text-[11px] text-amber-300 font-semibold">False alarm — this text is actually benign.</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={nextScenario}
                    className="w-full py-3 bg-violet-500 hover:bg-violet-400 text-slate-950 font-bold rounded-xl text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-colors"
                  >
                    <RotateCcw className="w-4 h-4" />
                    {scenarioIdx + 1 < SCENARIOS.scenarios.length ? 'Next Scenario' : 'See Final Results'}
                  </button>
                </div>
              )}
            </div>
          )}

          {screen === 'result' && (
            <div className="space-y-5 text-center py-6 animate-in fade-in duration-200">
              <div className="mx-auto p-4 w-fit rounded-2xl bg-amber-500/10 border border-amber-500/20">
                <Award className="w-10 h-10 text-amber-400" />
              </div>
              <div>
                <div className="text-4xl font-black font-mono text-white">{score.points}</div>
                <div className="text-xs text-slate-400 font-mono mt-1">Cyber Defender Score · max {score.total}</div>
              </div>
              <div className={`text-sm font-bold ${rank.color}`}>{rank.title}</div>
              <div className="w-full max-w-xs mx-auto bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-800">
                <div className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-full transition-all duration-700" style={{ width: `${Math.min(100, accuracy)}%` }} />
              </div>
              <div className="text-xs text-slate-500">{accuracy}% detection accuracy</div>
              <button
                onClick={restart}
                className="px-6 py-3 bg-violet-500 hover:bg-violet-400 text-slate-950 font-bold rounded-xl text-xs uppercase tracking-wider transition-colors"
              >
                Play Again
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between shrink-0">
          <span className="text-[10px] text-slate-500 font-mono">Scenario {Math.min(scenarioIdx + 1, SCENARIOS.scenarios.length)}/{SCENARIOS.scenarios.length} · Static curated JSON · safe by design</span>
          <button onClick={onClose} className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors">
            Close Lab
          </button>
        </div>
      </div>
    </div>
  );
}
