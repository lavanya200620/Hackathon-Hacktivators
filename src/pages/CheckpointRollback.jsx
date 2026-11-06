import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  History,
  RotateCcw,
  Lock,
  PlusCircle,
  RefreshCw,
  FileText,
  Boxes,
  Database,
  Info
} from 'lucide-react';
import { checkpointService } from '../services/checkpointService';
import { ledgerStorage } from '../services/ledgerStorage';

export default function CheckpointRollback() {
  const [checkpoints, setCheckpoints] = useState([]);
  const [integrityStatus, setIntegrityStatus] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [incidentReport, setIncidentReport] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = () => {
    const list = checkpointService.getCheckpoints();
    setCheckpoints(list);
    // Automatic integrity check on load
    runIntegrityCheck(list);
  };

  const runIntegrityCheck = (currentCheckpoints = checkpoints) => {
    setIsVerifying(true);
    setIncidentReport(null);
    setActionSuccess(null);

    setTimeout(() => {
      const evaluation = checkpointService.verifyLedgerIntegrity();
      setIntegrityStatus(evaluation);

      if (evaluation.status === 'ROLLBACK_DETECTED') {
        setIncidentReport({
          detectedAt: new Date().toISOString(),
          expectedBlocks: evaluation.checkpointRecordCount,
          actualBlocks: evaluation.currentRecordCount,
          expectedHash: evaluation.expectedHash,
          currentHash: evaluation.currentHash,
          missingCount: evaluation.checkpointRecordCount - evaluation.currentRecordCount,
        });
      }
      setIsVerifying(false);
    }, 400);
  };

  const handleSimulateAttack = () => {
    const result = checkpointService.simulateRollbackAttack();
    setActionSuccess('Simulated Rollback Attack executed: Live ledger truncated by 2 blocks. Re-evaluating integrity watchdog...');
    runIntegrityCheck();
  };

  const handleSimulateTamper = () => {
    const result = checkpointService.simulateTamperRecord();
    if (result.success) {
      setActionSuccess('Simulated Chain Tamper executed: Modified historical Block #3 hash pointer. Watchdog will catch broken link.');
      runIntegrityCheck();
    } else {
      alert(result.reason);
    }
  };

  const handleSimulateMissingCheckpoint = () => {
    checkpointService.simulateMissingCheckpoint();
    setActionSuccess('Simulated Missing Checkpoint: Removed preserved checkpoint store. Watchdog will report CHECKPOINT_MISSING.');
    runIntegrityCheck();
  };

  const handleResetCheckpoints = () => {
    checkpointService.initDefaultCheckpoints();
    setActionSuccess('Checkpoints & Ledger chain reset to authentic default state.');
    loadData();
  };

  const handleRestoreCheckpoint = () => {
    const result = checkpointService.restoreFromTrustedCheckpoint();
    if (result.success) {
      setActionSuccess('Ledger successfully restored from independent WORM Cold Storage checkpoint.');
      runIntegrityCheck();
    } else {
      alert('Restore failed: ' + result.error);
    }
  };

  const handleCreateCheckpoint = () => {
    const result = checkpointService.createCheckpoint({
      operator: 'Dr. Evelyn Vance (Chief Geoint Analyst)',
      notes: 'Periodic manual WORM state snapshot',
    });
    if (result.success) {
      setActionSuccess(`New sealed checkpoint created: ${result.checkpoint.id}`);
      loadData();
    } else {
      alert('Failed to create checkpoint: ' + result.error);
    }
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <Lock className="w-4 h-4" />
            <span>State Preservation & Anti-Rollback Engine</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Rollback Protection & Checkpoints
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Detect and prevent ledger truncation, rewind attacks, and historical rewrites using independently anchored WORM (Write-Once-Read-Many) state snapshots.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => runIntegrityCheck()}
            disabled={isVerifying}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-300 border border-background-border text-xs font-medium transition-all"
            title="Trigger real-time integrity verification"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
            Re-verify Watchdog
          </button>
          <button
            onClick={handleCreateCheckpoint}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-medium transition-all"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            Seal Checkpoint
          </button>
          <button
            onClick={handleSimulateAttack}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 text-xs font-medium transition-all"
            title="Simulate ledger truncation attack"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Truncate Ledger
          </button>
          <button
            onClick={handleSimulateTamper}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-amber-950/40 hover:bg-amber-900/50 text-amber-300 border border-amber-800/50 text-xs font-medium transition-all"
            title="Modify historical block hash in-place"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            Tamper Block
          </button>
          <button
            onClick={handleSimulateMissingCheckpoint}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-purple-950/40 hover:bg-purple-900/50 text-purple-300 border border-purple-800/50 text-xs font-medium transition-all"
            title="Simulate checkpoint unavailable state"
          >
            <Boxes className="w-3.5 h-3.5" />
            Drop Checkpoint
          </button>
          <button
            onClick={handleResetCheckpoints}
            className="flex items-center gap-1.5 px-2.5 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-400 hover:text-white border border-background-border text-xs transition-all"
            title="Reset to factory demo fixtures"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset
          </button>
        </div>
      </div>

      {/* Simulated Demo Notice Banner */}
      <div className="p-3.5 bg-cyan-950/30 rounded-xl border border-cyan-500/30 text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-4 h-4 text-cyan-accent flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-cyan-300 font-mono uppercase tracking-wider text-[11px]">Architectural Notice (Simulated Demo): </strong>
          In production enterprise deployments, state checkpoints are anchored into an external <strong>RFC 3161 Timestamp Authority (TSA)</strong> and an immutable <strong>AWS S3 Object Lock (WORM compliance mode)</strong> bucket. In this browser demo, the cryptographic hash tree and anti-rollback verification logic are executed client-side with full fidelity.
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionSuccess && (
        <div className="p-3.5 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-xs text-cyan-300 flex items-center justify-between animate-fade-in">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Live Watchdog Status Banner */}
      <div className={`p-6 rounded-2xl border transition-all ${
        integrityStatus?.status === 'ROLLBACK_DETECTED'
          ? 'bg-rose-950/40 border-rose-500 shadow-glow-rose/30'
          : 'bg-navy-900/90 border-emerald-500/40 shadow-xl'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
              integrityStatus?.status === 'ROLLBACK_DETECTED'
                ? 'bg-rose-500/20 text-rose-400 border border-rose-500 animate-pulse'
                : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
            }`}>
              {integrityStatus?.status === 'ROLLBACK_DETECTED' ? (
                <ShieldAlert className="w-6 h-6" />
              ) : (
                <ShieldCheck className="w-6 h-6" />
              )}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-wide">
                  {integrityStatus?.status === 'ROLLBACK_DETECTED'
                    ? 'CRITICAL ALERT: LEDGER ROLLBACK DETECTED'
                    : 'INTEGRITY WATCHDOG: ALL CHECKPOINTS VALIDATED'}
                </h2>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                  integrityStatus?.status === 'ROLLBACK_DETECTED'
                    ? 'bg-rose-500 text-white animate-bounce'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}>
                  {integrityStatus?.status || 'VALIDATING'}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                {integrityStatus?.status === 'ROLLBACK_DETECTED'
                  ? 'A divergence has been identified between the active ledger height and the tamper-evident WORM snapshot. Historical records have been suppressed or truncated!'
                  : 'The current ledger height and cryptographic cumulative root strictly equal or exceed the sealed state snapshot. Zero history rewrites detected.'}
              </p>
            </div>
          </div>

          {integrityStatus?.status === 'ROLLBACK_DETECTED' && (
            <button
              onClick={handleRestoreCheckpoint}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-navy-950 font-bold text-xs shadow-lg transition-all"
            >
              <RotateCcw className="w-4 h-4" />
              Restore from Trusted Checkpoint
            </button>
          )}
        </div>

        {/* Incident Report Details if Rollback Detected */}
        {incidentReport && (
          <div className="mt-6 pt-6 border-t border-rose-500/30">
            <h3 className="text-xs font-mono uppercase tracking-wider text-rose-300 font-bold mb-3 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5" />
              Automated Forensic Incident Report
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-navy-950/80 rounded-lg border border-rose-900/60">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Expected Height</span>
                <span className="text-white font-mono font-bold">{incidentReport.expectedBlocks} Blocks</span>
              </div>
              <div className="p-3 bg-navy-950/80 rounded-lg border border-rose-900/60">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Truncated Height</span>
                <span className="text-rose-400 font-mono font-bold">{incidentReport.actualBlocks} Blocks</span>
              </div>
              <div className="p-3 bg-navy-950/80 rounded-lg border border-rose-900/60">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Missing History</span>
                <span className="text-rose-300 font-mono font-bold">{incidentReport.missingCount} Block(s) Erased</span>
              </div>
              <div className="p-3 bg-navy-950/80 rounded-lg border border-rose-900/60">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Incident Detection Time</span>
                <span className="text-slate-300 font-mono text-[11px]">{new Date(incidentReport.detectedAt).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Checkpoint Architecture Information Card */}
      <div className="p-4 bg-navy-900/80 rounded-xl border border-background-border text-xs text-slate-300 flex items-start gap-3">
        <Info className="w-5 h-5 text-cyan-accent flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">Why Rollback Protection Matters:</strong> In digital content verification, an attacker who gains root database access cannot change cryptographic hashes without breaking the chain, but they <em>can</em> attempt to truncate recent audit blocks to make a forged document appear legitimate. Independent WORM checkpoints prevent this by sealing immutable height counters outside the operational cluster.
        </div>
      </div>

      {/* Checkpoints Timeline / Table */}
      <div className="bg-navy-900/90 border border-background-border rounded-xl shadow-xl overflow-hidden">
        <div className="p-4 border-b border-background-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Boxes className="w-4 h-4 text-cyan-accent" />
            Sealed WORM Checkpoint Vault
          </h2>
          <span className="text-xs text-slate-400 font-mono">{checkpoints.length} Sealed Snapshot{checkpoints.length === 1 ? '' : 's'}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-950/80 border-b border-background-border text-[11px] font-mono uppercase text-slate-400">
                <th className="py-3 px-4">Checkpoint ID</th>
                <th className="py-3 px-4">Ledger Height</th>
                <th className="py-3 px-4">Sealed Root Hash</th>
                <th className="py-3 px-4">Anchor Type</th>
                <th className="py-3 px-4">Sealed By</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-background-border/60">
              {checkpoints.map((chk) => (
                <tr key={chk.id} className="hover:bg-navy-850/50 transition-colors">
                  <td className="py-3 px-4 font-mono font-bold text-cyan-300">
                    {chk.id}
                  </td>
                  <td className="py-3 px-4 font-mono text-white">
                    Block #{chk.recordNumber}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-300">
                    {chk.latestHash ? `${chk.latestHash.substring(0, 12)}...${chk.latestHash.substring(56)}` : 'Merkle Root Sealed'}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {chk.anchorType}
                  </td>
                  <td className="py-3 px-4 text-slate-400 truncate max-w-xs">
                    {chk.operator}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                    {new Date(chk.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      {chk.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

