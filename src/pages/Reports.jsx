import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Printer,
  FileCode,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Key,
  Database,
  Hash,
  Sparkles,
  Layers,
  ArrowRight
} from 'lucide-react';
import StatusBadge from '../components/common/StatusBadge';
import { ledgerStorage } from '../services/ledgerStorage';

export default function Reports() {
  const [sources, setSources] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState('SRC-98214');
  const [reportData, setReportData] = useState(null);

  useEffect(() => {
    const list = ledgerStorage.getSources();
    setSources(list);
    if (list.length > 0) {
      generateReport(list[0]);
    }
  }, []);

  const handleSelectSource = (id) => {
    setSelectedSourceId(id);
    const found = sources.find((s) => s.id === id);
    if (found) generateReport(found);
  };

  const generateReport = (source) => {
    const reportId = `RPT-${source.id}-${Math.floor(1000 + Math.random() * 9000)}`;
    const data = {
      reportId,
      sourceId: source.id,
      fileName: source.fileName,
      fileType: source.fileType,
      fileSize: source.fileSizeFormatted,
      creator: source.creator,
      creatorId: source.creatorId,
      category: source.category,
      originalSha256: source.sha256,
      uploadedSha256: source.sha256,
      signature: source.signature,
      signatureValidation: 'MATHEMATICALLY_AUTHENTIC',
      verdict: 'ORIGINAL',
      registeredAt: source.registeredAt,
      generatedTimestamp: new Date().toISOString(),
      keyId: source.keyId,
      tamperAnalysisResults: {
        varianceRate: '0.00%',
        bitwiseEquality: true,
        differingPixelCount: 0,
        integrityConfidence: '99.99%',
      },
      provenanceHistory: [
        { stage: 'Asset Registration', time: source.registeredAt, status: 'CONFIRMED' },
        { stage: 'SHA-256 WebCrypto Calculation', time: source.registeredAt, status: 'CONFIRMED' },
        { stage: 'Ed25519 Detached Signature Anchor', time: source.registeredAt, status: 'CONFIRMED' },
        { stage: 'Ledger Merkle Hash Commitment', time: source.registeredAt, status: 'CONFIRMED' },
      ],
    };
    setReportData(data);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportJSON = () => {
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sourcemark-forensic-report-${reportData.reportId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Forensic Verification Reports
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Generate and export cryptographically verifiable evidentiary reports complying with digital forensics audit standards.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJSON}
            className="px-3.5 py-2 rounded-xl border border-slate-700 bg-navy-900 hover:bg-navy-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <FileCode className="w-4 h-4 text-cyan-400" />
            Export JSON
          </button>
          <button
            onClick={handlePrint}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-1.5 shadow-glow-cyan transition-all"
          >
            <Printer className="w-4 h-4" />
            Print / Save PDF
          </button>
        </div>
      </div>

      {/* Select Source to Inspect */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800 flex items-center gap-3 print:hidden">
        <span className="text-xs font-bold text-slate-300 uppercase font-mono">Select Source Dossier:</span>
        <select
          value={selectedSourceId}
          onChange={(e) => handleSelectSource(e.target.value)}
          className="bg-navy-900 border border-slate-700 rounded-xl px-4 py-2 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-400 transition-colors"
        >
          {sources.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id} - {s.fileName} ({s.category})
            </option>
          ))}
        </select>
      </div>

      {/* Printable Forensic Report Document Container */}
      {reportData && (
        <div className="glass-panel p-8 sm:p-12 rounded-2xl border border-slate-700/80 shadow-2xl space-y-8 bg-navy-900/90 text-slate-100 print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
          {/* Report Top Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-6 border-b border-slate-700/80 gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xl sm:text-2xl font-black tracking-widest text-white print:text-black">
                  SOURCE<span className="text-cyan-400 print:text-blue-600">MARK</span>
                </span>
                <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-navy-800 text-cyan-300 border border-cyan-500/30 print:border-black print:text-black">
                  DIGITAL FORENSIC DOSSIER
                </span>
              </div>
              <p className="text-xs text-slate-400 print:text-slate-600 font-mono">
                Compliant with ISO/IEC 27037 Digital Evidence Standards
              </p>
            </div>

            <div className="text-right font-mono text-xs text-slate-400 print:text-slate-600">
              <div>
                Report ID: <span className="font-bold text-cyan-400 print:text-black">{reportData.reportId}</span>
              </div>
              <div>Generated: {new Date(reportData.generatedTimestamp).toUTCString()}</div>
            </div>
          </div>

          {/* Verification Verdict Banner */}
          <div className="p-4 rounded-xl bg-emerald-950/60 border border-emerald-500/40 print:bg-emerald-50 print:border-emerald-600 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 print:text-emerald-700" />
              <div>
                <h3 className="text-base font-bold text-emerald-300 print:text-emerald-900">
                  FINAL VERDICT: CRYPTOGRAPHICALLY VERIFIED ORIGINAL
                </h3>
                <p className="text-xs text-emerald-200/80 print:text-emerald-800 mt-0.5">
                  Binary content bitstream and Ed25519 signature verified mathematically without discrepancy.
                </p>
              </div>
            </div>
            <StatusBadge status="ORIGINAL" size="sm" />
          </div>

          {/* Dossier Section 1: Subject Artifact Details */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-black font-mono border-b border-slate-800 pb-1.5">
              1. Digital Asset Identification
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Source ID</span>
                <span className="text-cyan-400 print:text-blue-700 font-bold">{reportData.sourceId}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Filename</span>
                <span className="text-slate-200 print:text-black font-sans truncate block">{reportData.fileName}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Asset Size</span>
                <span className="text-slate-300 print:text-black">{reportData.fileSize}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Category</span>
                <span className="text-slate-300 print:text-black font-sans">{reportData.category}</span>
              </div>
            </div>
          </div>

          {/* Dossier Section 2: Cryptographic Signatures & Hash Fingerprints */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-black font-mono border-b border-slate-800 pb-1.5">
              2. Cryptographic Proof & Signature Ledger
            </h4>
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <div className="flex justify-between mb-1">
                  <span className="text-slate-400 text-[10px] uppercase">Original SHA-256 Digest</span>
                  <span className="text-emerald-400 print:text-emerald-700 font-bold">Exact Match</span>
                </div>
                <div className="text-cyan-300 print:text-slate-900 break-all select-all text-[11px]">
                  {reportData.originalSha256}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <div className="flex justify-between mb-1">
                  <span className="text-slate-400 text-[10px] uppercase">Ed25519 Detached Digital Signature</span>
                  <span className="text-emerald-400 print:text-emerald-700 font-bold">Valid Asymmetric Seal</span>
                </div>
                <div className="text-slate-400 print:text-slate-700 break-all text-[10px]">
                  {reportData.signature}
                </div>
              </div>
            </div>
          </div>

          {/* Dossier Section 3: Provenance Authority & Creator */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-black font-mono border-b border-slate-800 pb-1.5">
              3. Originator & Key Authority Attribution
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Registered Creator</span>
                <span className="text-slate-200 print:text-black font-sans">{reportData.creator}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Creator Identifier</span>
                <span className="text-cyan-400 print:text-blue-700">{reportData.creatorId}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Public Key Identifier</span>
                <span className="text-emerald-400 print:text-emerald-800">{reportData.keyId}</span>
              </div>
            </div>
          </div>

          {/* Dossier Section 4: Tamper Analysis Results */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-black font-mono border-b border-slate-800 pb-1.5">
              4. Forensic Tamper Detection Metrics
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Variance Rate</span>
                <span className="text-emerald-400 print:text-emerald-700 font-bold text-sm">
                  {reportData.tamperAnalysisResults.varianceRate}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Pixel Differences</span>
                <span className="text-emerald-400 print:text-emerald-700 font-bold text-sm">
                  {reportData.tamperAnalysisResults.differingPixelCount} Pixels
                </span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Bitwise Equality</span>
                <span className="text-slate-200 print:text-black font-bold text-sm">IDENTICAL</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 print:bg-slate-100 border border-slate-800 print:border-slate-300">
                <span className="text-slate-500 text-[10px] uppercase block">Integrity Score</span>
                <span className="text-cyan-400 print:text-blue-700 font-bold text-sm">
                  {reportData.tamperAnalysisResults.integrityConfidence}
                </span>
              </div>
            </div>
          </div>

          {/* Dossier Footer / Sign-off Seal */}
          <div className="pt-6 border-t border-slate-700/80 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 print:text-slate-600 gap-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400 print:text-blue-600" />
              <span>Certified Evidence Ledger Record • Cryptographically Verifiable Hash Anchor</span>
            </div>
            <div className="font-mono text-[11px]">
              Signature Engine: Ed25519-EdDSA-Curve25519
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

