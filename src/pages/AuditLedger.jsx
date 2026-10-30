import React, { useState, useEffect } from 'react';
import {
  Boxes,
  ShieldCheck,
  ShieldAlert,
  Link2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Hash,
  Clock,
  Layers,
  Sparkles,
  Zap,
  RotateCcw,
  ExternalLink,
  Cpu
} from 'lucide-react';
import StatusBadge from '../components/common/StatusBadge';
import EventModal from '../components/common/EventModal';
import { apiService } from '../services/api';
import { ledgerStorage } from '../services/ledgerStorage';

export default function AuditLedger() {
  const [blocks, setBlocks] = useState([]);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState({
    isValid: true,
    lastValidated: new Date().toISOString(),
    brokenAtBlock: null,
  });
  const [selectedBlock, setSelectedBlock] = useState(null);
  const [tamperSimulated, setTamperSimulated] = useState(false);

  useEffect(() => {
    loadLedger();
  }, []);

  const loadLedger = async () => {
    const res = await apiService.getLedger();
    setBlocks(res.blocks || ledgerStorage.getLedgerBlocks());
  };

  const handleValidateLedger = async () => {
    setIsValidating(true);
    setTimeout(async () => {
      const res = await apiService.validateLedger();
      setValidationResult({
        isValid: res.isValid,
        lastValidated: new Date().toISOString(),
        brokenAtBlock: res.brokenAtBlock,
        details: res.details,
      });
      setIsValidating(false);
    }, 500);
  };

  const handleSimulateTamper = () => {
    ledgerStorage.simulateTamper();
    setTamperSimulated(true);
    loadLedger();
  };

  const handleResetLedger = () => {
    ledgerStorage.resetLedger();
    setTamperSimulated(false);
    setValidationResult({
      isValid: true,
      lastValidated: new Date().toISOString(),
      brokenAtBlock: null,
    });
    loadLedger();
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Tamper-Evident Audit Ledger
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Inspect the mathematical integrity of the cryptographic hash-chained provenance events. Every action is sealed with previous block digest links.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {tamperSimulated ? (
            <button
              onClick={handleResetLedger}
              className="px-3 py-2 rounded-xl bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Pristine Ledger
            </button>
          ) : (
            <button
              onClick={handleSimulateTamper}
              className="px-3 py-2 rounded-xl bg-rose-950/70 hover:bg-rose-900/80 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              title="Corrupts block #3 payload to demonstrate tamper detection"
            >
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              Simulate Tamper Test
            </button>
          )}

          <button
            onClick={handleValidateLedger}
            disabled={isValidating}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-2 shadow-glow-cyan transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isValidating ? 'animate-spin' : ''}`} />
            <span>{isValidating ? 'Verifying Chain...' : 'Validate Ledger'}</span>
          </button>
        </div>
      </div>

      {/* Integrity Summary Banner */}
      <div
        className={`glass-panel p-6 rounded-2xl border transition-all ${
          validationResult.isValid
            ? 'border-emerald-500/40 shadow-glow-green'
            : 'border-rose-500/50 shadow-glow-red'
        }`}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div
              className={`w-12 h-12 rounded-2xl flex items-center justify-center ${
                validationResult.isValid
                  ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                  : 'bg-rose-500/10 border border-rose-500/30 text-rose-400'
              }`}
            >
              {validationResult.isValid ? (
                <ShieldCheck className="w-7 h-7" />
              ) : (
                <ShieldAlert className="w-7 h-7" />
              )}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white">
                  {validationResult.isValid
                    ? 'Cryptographic Ledger Status: VALID'
                    : 'Cryptographic Ledger Status: INVALID – TAMPER DETECTED'}
                </h2>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                    validationResult.isValid
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                      : 'bg-rose-950 text-rose-400 border border-rose-500/30'
                  }`}
                >
                  {validationResult.isValid ? 'Chain Intact' : 'Broken Merkle Link'}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                {validationResult.isValid
                  ? `All ${blocks.length} events mathematically verified against Ed25519 root authority and SHA-256 parents.`
                  : `Discrepancy detected at ${validationResult.brokenAtBlock || 'Block #3'}. Hash link mismatch proves retroactive alteration.`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 text-xs font-mono text-slate-400">
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Total Blocks</span>
              <span className="text-slate-200 font-bold text-sm">{blocks.length} Events</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Last Validation</span>
              <span className="text-cyan-400 text-xs">
                {new Date(validationResult.lastValidated).toLocaleTimeString()} UTC
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Visual Hash Chain Connecting Events */}
      <div className="space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" />
            Hash-Chained Block Timeline (Chronological Sequence)
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">Merkle Hash Linkage</span>
        </div>

        <div className="relative space-y-4">
          {blocks.map((block, index) => {
            const isBroken = validationResult.brokenAtBlock === block.id;

            return (
              <div key={block.id} className="relative">
                {/* Visual Connecting Hash Line to next block */}
                {index < blocks.length - 1 && (
                  <div
                    className={`absolute left-8 top-full w-0.5 h-4 z-10 ${
                      isBroken ? 'bg-rose-500 shadow-glow-red' : 'bg-cyan-500/30'
                    }`}
                  />
                )}

                <div
                  className={`glass-panel p-5 rounded-2xl border transition-all hover:border-cyan-500/40 cursor-pointer ${
                    isBroken
                      ? 'border-rose-500/80 bg-rose-950/30 shadow-glow-red'
                      : 'border-slate-800/90 hover:bg-navy-850/60'
                  }`}
                  onClick={() => setSelectedBlock(block)}
                >
                  <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                      {/* Block Number Pill */}
                      <div className="w-12 h-12 rounded-xl bg-navy-950 border border-slate-700 flex flex-col items-center justify-center font-mono flex-shrink-0">
                        <span className="text-[10px] text-slate-500 uppercase">BLK</span>
                        <span className="text-sm font-bold text-cyan-400">#{block.blockNumber || index + 1}</span>
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-sm font-bold text-white">{block.title}</h4>
                          <StatusBadge status={block.status} size="sm" />
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-400 font-mono">
                          <span className="text-cyan-400 font-bold">{block.id}</span>
                          <span>•</span>
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            {block.timestamp}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Cryptographic Link Hashes */}
                    <div className="w-full lg:w-auto flex flex-col sm:flex-row items-start sm:items-center gap-3 text-[11px] font-mono">
                      <div className="p-2 rounded-lg bg-navy-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] block uppercase">Prev Hash</span>
                        <span className="text-slate-400 truncate max-w-[150px] inline-block">
                          {block.prevHash ? `${block.prevHash.substring(0, 10)}...` : '0000000000...'}
                        </span>
                      </div>

                      <div className="p-2 rounded-lg bg-navy-950 border border-slate-800">
                        <span className="text-slate-500 text-[10px] block uppercase">Current Digest</span>
                        <span className="text-cyan-400 truncate max-w-[150px] inline-block">
                          {block.currentHash ? `${block.currentHash.substring(0, 10)}...` : 'e3b0c44298...'}
                        </span>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedBlock(block);
                        }}
                        className="px-3 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-200 border border-slate-700 text-xs font-semibold whitespace-nowrap"
                      >
                        Inspect Payload
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Block Inspector Modal */}
      <EventModal
        isOpen={Boolean(selectedBlock)}
        onClose={() => setSelectedBlock(null)}
        block={selectedBlock}
      />
    </div>
  );
}

