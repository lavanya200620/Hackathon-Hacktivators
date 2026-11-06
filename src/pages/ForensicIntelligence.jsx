import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  ArrowRight,
  Sparkles,
  Sliders,
  RefreshCw,
  Search
} from 'lucide-react';
import { computeForensicScore } from '../services/forensicScore';
import { ledgerStorage } from '../services/ledgerStorage';
import { checkpointService } from '../services/checkpointService';
import { keySecurityService } from '../services/keySecurity';
import StatusBadge from '../components/common/StatusBadge';

export default function ForensicIntelligence() {
  const [sources, setSources] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState('SRC-98214');
  const [customParams, setCustomParams] = useState({
    hashMatched: true,
    signatureValid: true,
    registryFound: true,
    keyStatus: 'ACTIVE',
    checkpointIntegrity: 'VALID',
    metadataConsistency: 'CONSISTENT',
    provenanceHistoryDepth: 5,
    isAuthorizedDerivative: false,
  });

  const [scoreResult, setScoreResult] = useState(null);

  useEffect(() => {
    const list = ledgerStorage.getSources();
    setSources(list);
    evaluateSource(list[0]);
  }, []);

  const evaluateSource = (source) => {
    if (!source) return;
    const key = keySecurityService.getKeyById(source.keyId || 'ED25519-2A71A707');
    const checkpointStatus = checkpointService.evaluateIntegrity().status;

    const params = {
      hashMatched: true,
      signatureValid: true,
      registryFound: true,
      keyStatus: key ? key.status : 'ACTIVE',
      checkpointIntegrity: checkpointStatus,
      metadataConsistency: 'CONSISTENT',
      provenanceHistoryDepth: source.verificationCount || 4,
      isAuthorizedDerivative: false,
    };

    setCustomParams(params);
    const result = computeForensicScore(params);
    setScoreResult(result);
  };

  const handleSourceChange = (id) => {
    setSelectedSourceId(id);
    const found = sources.find((s) => s.id === id);
    if (found) evaluateSource(found);
  };

  const handleParamToggle = (key, value) => {
    const updated = { ...customParams, [key]: value };
    setCustomParams(updated);
    setScoreResult(computeForensicScore(updated));
  };

  const selectedSource = sources.find((s) => s.id === selectedSourceId);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Forensic Intelligence Engine v2.4</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Forensic Intelligence Score
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Explainable rule-based triage scoring evaluating 8 distinct cryptographic, temporal, and metadata verification vectors.
          </p>
        </div>

        {/* Source Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Target Asset:</span>
          <select
            value={selectedSourceId}
            onChange={(e) => handleSourceChange(e.target.value)}
            className="bg-navy-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-400"
          >
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} – {s.fileName}
              </option>
            ))}
          </select>
        </div>
      </div>

      {scoreResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Score Gauge Card */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col justify-between space-y-6">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Triage Evaluation</span>
                <span className="text-[10px] text-slate-500 font-mono">Normalized Metric</span>
              </div>

              {/* Gauge Display */}
              <div className="my-8 flex flex-col items-center justify-center">
                <div className="relative w-40 h-40 rounded-full flex items-center justify-center border-4 border-slate-800 bg-navy-950 shadow-2xl">
                  {/* Outer Score Glow */}
                  <div
                    className={`absolute inset-0 rounded-full blur-xl opacity-30 ${
                      scoreResult.score >= 85
                        ? 'bg-emerald-500'
                        : scoreResult.score >= 65
                        ? 'bg-cyan-500'
                        : scoreResult.score >= 40
                        ? 'bg-amber-500'
                        : 'bg-rose-500'
                    }`}
                  />
                  <div className="text-center z-10">
                    <span
                      className={`text-4xl font-extrabold font-mono tracking-tight ${
                        scoreResult.score >= 85
                          ? 'text-emerald-400'
                          : scoreResult.score >= 65
                          ? 'text-cyan-400'
                          : scoreResult.score >= 40
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }`}
                    >
                      {scoreResult.score}
                    </span>
                    <span className="block text-[11px] text-slate-400 font-mono">/ 100 PTS</span>
                  </div>
                </div>

                <div className="mt-4 text-center">
                  <span
                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold font-mono border ${
                      scoreResult.score >= 85
                        ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300'
                        : scoreResult.score >= 65
                        ? 'bg-cyan-950/80 border-cyan-500/40 text-cyan-300'
                        : scoreResult.score >= 40
                        ? 'bg-amber-950/80 border-amber-500/40 text-amber-300'
                        : 'bg-rose-950/80 border-rose-500/40 text-rose-300'
                    }`}
                  >
                    {scoreResult.score >= 85 ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5" />
                    )}
                    {scoreResult.riskLevel}
                  </span>
                  <p className="text-[11px] text-slate-400 mt-2 font-mono">
                    Target: {selectedSource?.id || 'Active Asset'}
                  </p>
                </div>
              </div>
            </div>

            {/* Actionable Recommendations */}
            <div className="p-3.5 rounded-xl bg-navy-950 border border-slate-800 space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block font-mono">
                Recommended Forensic Action:
              </span>
              <ul className="space-y-1 text-xs text-slate-300">
                {scoreResult.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    <ArrowRight className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Right Column: Breakdown & Interactive Vector Toggles */}
          <div className="lg:col-span-2 space-y-6">
            {/* Vector Breakdown Table */}
            <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  Individual Check Vectors & Deductions
                </h3>
                <span className="text-[10px] text-slate-500 font-mono">Rule Evaluation Matrix</span>
              </div>

              <div className="space-y-2.5">
                {scoreResult.checks.map((chk, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-navy-900/60 border border-slate-800 flex items-center justify-between gap-4 text-xs"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0 text-xs font-bold ${
                          chk.status === 'PASS'
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : chk.status === 'WARNING' || chk.status === 'NEUTRAL'
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'bg-rose-500/20 text-rose-400'
                        }`}
                      >
                        {chk.status === 'PASS' ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          <XCircle className="w-4 h-4" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="font-semibold text-slate-200">{chk.vector}</div>
                        <div className="text-[11px] text-slate-400 truncate">{chk.description}</div>
                      </div>
                    </div>

                    <div className="text-right flex-shrink-0 font-mono">
                      <span
                        className={`font-bold ${
                          chk.points === chk.maxPoints
                            ? 'text-emerald-400'
                            : chk.points > 0
                            ? 'text-amber-400'
                            : 'text-rose-400'
                        }`}
                      >
                        +{chk.points}
                      </span>
                      <span className="text-slate-500 text-[10px]"> / {chk.maxPoints} pts</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Deductions Alert */}
              {scoreResult.deductions.length > 0 && (
                <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-500/30 text-xs space-y-1">
                  <span className="font-bold text-rose-300 uppercase text-[10px] block font-mono">
                    Point Deductions Applied:
                  </span>
                  {scoreResult.deductions.map((ded, i) => (
                    <div key={i} className="text-rose-200/90 flex items-center gap-1.5 text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                      <span>{ded}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Interactive Vector Simulation Controls */}
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                  Interactive Vector Simulation Tool
                </span>
                <span className="text-[10px] text-cyan-400 font-mono">Test Triage Scenarios</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                <button
                  onClick={() => handleParamToggle('hashMatched', !customParams.hashMatched)}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    customParams.hashMatched
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Hash Match:</span>
                  <span className="font-bold">{customParams.hashMatched ? 'MATCHED (PASS)' : 'MISMATCH (FAIL)'}</span>
                </button>

                <button
                  onClick={() => handleParamToggle('signatureValid', !customParams.signatureValid)}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    customParams.signatureValid
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Ed25519 Signature:</span>
                  <span className="font-bold">{customParams.signatureValid ? 'VALID (PASS)' : 'INVALID (FAIL)'}</span>
                </button>

                <button
                  onClick={() => {
                    const next =
                      customParams.keyStatus === 'ACTIVE'
                        ? 'COMPROMISED'
                        : customParams.keyStatus === 'COMPROMISED'
                        ? 'REPLACED'
                        : 'ACTIVE';
                    handleParamToggle('keyStatus', next);
                  }}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    customParams.keyStatus === 'ACTIVE'
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : customParams.keyStatus === 'REPLACED'
                      ? 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Key Status:</span>
                  <span className="font-bold">{customParams.keyStatus}</span>
                </button>

                <button
                  onClick={() => {
                    const next = customParams.checkpointIntegrity === 'VALID' ? 'ROLLBACK_DETECTED' : 'VALID';
                    handleParamToggle('checkpointIntegrity', next);
                  }}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    customParams.checkpointIntegrity === 'VALID'
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Checkpoint State:</span>
                  <span className="font-bold">{customParams.checkpointIntegrity}</span>
                </button>

                <button
                  onClick={() => {
                    const next =
                      customParams.metadataConsistency === 'CONSISTENT'
                        ? 'STRIPPED'
                        : customParams.metadataConsistency === 'STRIPPED'
                        ? 'INCONSISTENT'
                        : 'CONSISTENT';
                    handleParamToggle('metadataConsistency', next);
                  }}
                  className="p-2.5 rounded-lg border border-slate-700 bg-navy-900 text-left hover:border-cyan-400"
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Metadata State:</span>
                  <span className="font-bold text-slate-200">{customParams.metadataConsistency}</span>
                </button>

                <button
                  onClick={() =>
                    handleParamToggle('isAuthorizedDerivative', !customParams.isAuthorizedDerivative)
                  }
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    customParams.isAuthorizedDerivative
                      ? 'bg-cyan-950/40 border-cyan-500/40 text-cyan-300'
                      : 'bg-navy-900 border-slate-700 text-slate-300'
                  }`}
                >
                  <span className="text-[10px] text-slate-400 block font-mono">Authorized Derivative:</span>
                  <span className="font-bold">{customParams.isAuthorizedDerivative ? 'YES' : 'NO'}</span>
                </button>
              </div>
            </div>

            {/* Crucial Ethical & Forensic Disclaimer */}
            <div className="p-4 rounded-xl bg-navy-950 border border-slate-800 text-xs text-slate-400 flex items-start gap-2.5">
              <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
              <p>
                <strong>Forensic Triage Protocol Notice:</strong> {scoreResult.disclaimer}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

