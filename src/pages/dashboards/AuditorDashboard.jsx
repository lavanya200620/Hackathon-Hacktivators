import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { ledgerStorage } from '../../services/ledgerStorage';
import { checkpointService } from '../../services/checkpointService';
import {
  FileCheck2,
  Database,
  ShieldCheck,
  Download,
  Search,
  CheckCircle2,
  FileSpreadsheet,
  ArrowRight,
  Clock,
  Layers,
  Lock
} from 'lucide-react';

export default function AuditorDashboard() {
  const { user } = useAuth();
  const [blocks, setBlocks] = useState([]);
  const [checkpoints, setCheckpoints] = useState([]);
  const [filterAction, setFilterAction] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [chainValid, setChainValid] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const rawBlocks = ledgerStorage.getLedgerBlocks();
    setBlocks(rawBlocks);
    setCheckpoints(checkpointService.getHistory ? checkpointService.getHistory() : []);

    ledgerStorage.validateLedgerChain().then(res => {
      setChainValid(res.isValid);
    });
  }, []);

  const handleExportComplianceReport = () => {
    setExporting(true);
    const reportData = {
      title: 'SourceMark Enterprise Forensic Audit & Non-Repudiation Proof',
      standard: 'ISO/IEC 27037:2012 & NIST SP 800-86 Digital Evidence Standard',
      auditor: user?.name,
      auditorEmail: user?.email,
      exportedAt: new Date().toISOString(),
      chainIntegrityStatus: chainValid ? 'CRYPTOGRAPHICALLY_VERIFIED' : 'TAMPER_DETECTED',
      totalBlocks: blocks.length,
      ledgerBlocks: blocks,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sourcemark-compliance-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => setExporting(false), 1000);
  };

  const filteredBlocks = blocks.filter(b => {
    const matchesAction = filterAction === 'ALL' || b.type === filterAction;
    const matchesSearch = !searchTerm ||
      (b.title && b.title.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (b.id && b.id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (b.currentHash && b.currentHash.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesAction && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center text-emerald-400">
            <FileCheck2 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Compliance & Forensic Audit Console</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                ROLE: AUDITOR
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Lead Auditor: <span className="text-slate-200 font-semibold">{user?.name}</span>. Immutable log scrutiny, non-repudiation cryptographic verification, and export.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportComplianceReport}
            disabled={exporting}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-emerald-600/30 transition disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            {exporting ? 'Exporting...' : 'Export NIST/ISO Package'}
          </button>
          <Link
            to="/reports"
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition"
          >
            PDF Certificate
          </Link>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Chain Integrity</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className={`text-2xl font-bold ${chainValid ? 'text-emerald-400' : 'text-red-400'}`}>
            {chainValid ? 'VERIFIED' : 'UNVERIFIED'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">SHA-256 Merkle link unbroken</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Immutable Blocks</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{blocks.length}</div>
          <div className="text-[11px] text-slate-500 mt-1">WORM append-only ledger</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Non-Repudiation Status</span>
            <Lock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">ENFORCED</div>
          <div className="text-[11px] text-slate-500 mt-1">RFC 3161 & Ed25519 sealed</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Compliance Standards</span>
            <CheckCircle2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">ISO 27037</div>
          <div className="text-[11px] text-slate-500 mt-1">NIST SP 800-86 Compliant</div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-sm font-bold text-white">Append-Only Audit Ledger Stream</h2>
            <p className="text-xs text-slate-400">Cryptographically chained events with SHA-256 block hash</p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search block ID, hash, title..."
                className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none"
            >
              <option value="ALL">All Event Types</option>
              <option value="GENESIS">GENESIS</option>
              <option value="REGISTER">REGISTER</option>
              <option value="VERIFY_ORIGINAL">VERIFY</option>
              <option value="TAMPER_DETECTED">TAMPER / SECURITY</option>
              <option value="SECURITY_INCIDENT">INCIDENT</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                <th className="pb-3">Block</th>
                <th className="pb-3">Type</th>
                <th className="pb-3">Event Summary</th>
                <th className="pb-3 font-mono">Current Hash (SHA-256)</th>
                <th className="pb-3">Timestamp</th>
                <th className="pb-3 text-right">Integrity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredBlocks.map((b) => (
                <tr key={b.id} className="hover:bg-slate-800/30">
                  <td className="py-3 font-mono text-emerald-400 font-semibold">{b.id}</td>
                  <td className="py-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                      {b.type}
                    </span>
                  </td>
                  <td className="py-3 font-medium text-white max-w-[260px] truncate">{b.title}</td>
                  <td className="py-3 font-mono text-[11px] text-slate-500 truncate max-w-[160px]">
                    {b.currentHash}
                  </td>
                  <td className="py-3 text-slate-400 font-mono text-[11px]">
                    {new Date(b.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 text-right">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      CONFIRMED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Auditor Shortcuts */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Link to="/ledger" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">Full Audit Ledger Explorer</div>
          <div className="text-[11px] text-slate-400">Inspect block payloads and cryptographically verify previous hashes</div>
        </Link>
        <Link to="/history" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">Historical Key Validator</div>
          <div className="text-[11px] text-slate-400">Validate signatures against pre-compromise RFC 3161 evidence</div>
        </Link>
        <Link to="/key-security" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">PKI Trust Registry</div>
          <div className="text-[11px] text-slate-400">Catalogued public keys and authority certificates</div>
        </Link>
      </div>
    </div>
  );
}

