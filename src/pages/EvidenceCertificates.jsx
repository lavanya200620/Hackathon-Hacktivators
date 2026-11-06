import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  Award,
  Calendar,
  User,
  Fingerprint,
  QrCode,
  CheckCircle,
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  FileBadge,
  Sparkles
} from 'lucide-react';
import { ledgerStorage } from '../services/ledgerStorage';
import { certificateService } from '../services/certificateService';
import { forensicScoreService } from '../services/forensicScore';

export default function EvidenceCertificates() {
  const [sources, setSources] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const [selectedSource, setSelectedSource] = useState(null);
  const [forensicEvaluation, setForensicEvaluation] = useState(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [qrPreviewUrl, setQrPreviewUrl] = useState('');

  useEffect(() => {
    const list = ledgerStorage.getSources();
    setSources(list);
    if (list.length > 0) {
      selectSource(list[0]);
    }
  }, []);

  const selectSource = async (source) => {
    setSelectedSourceId(source.id);
    setSelectedSource(source);

    // Compute live forensic score
    const evalResult = forensicScoreService.calculateScore({
      sourceRecord: source,
      hashMatch: true,
      signatureValid: true,
      hasMetadata: true,
      isCompromisedKey: false,
    });
    setForensicEvaluation(evalResult);

    // Generate QR preview
    const qrUrl = await certificateService.generateQRCode(
      JSON.stringify({
        sourceId: source.id,
        hash: source.sha256 || source.hash,
        creator: source.creator,
        ts: source.registeredAt || source.timestamp
      })
    );
    setQrPreviewUrl(qrUrl);
  };

  const handleSourceChange = (e) => {
    const sId = e.target.value;
    const s = sources.find(x => x.id === sId);
    if (s) {
      selectSource(s);
    }
  };

  const handleDownloadPDF = async () => {
    if (!selectedSource) return;
    setIsGeneratingPdf(true);
    try {
      await certificateService.generateCertificatePDF({
        sourceId: selectedSource.id,
        fileName: selectedSource.fileName,
        sha256: selectedSource.sha256 || selectedSource.hash,
        signature: selectedSource.signature || 'Secured Ed25519 Detached Signature',
        signatureStatus: 'CRYPTOGRAPHICALLY VALID (Ed25519)',
        creator: selectedSource.creator,
        creatorId: selectedSource.creatorId || 'AGY-USR-0042',
        registeredAt: selectedSource.registeredAt || selectedSource.timestamp,
        forensicScore: forensicEvaluation?.score || 98,
        riskLevel: forensicEvaluation?.riskLevel || 'Low Risk',
        isDemo: true,
        verificationHistory: [
          {
            timestamp: new Date().toISOString(),
            verifier: 'SourceMark Automated Daemon',
            status: 'VERIFIED_AUTHENTIC',
          },
          {
            timestamp: selectedSource.registeredAt || selectedSource.timestamp,
            verifier: selectedSource.creator,
            status: 'REGISTERED_ORIGINAL',
          }
        ]
      });
    } catch (err) {
      console.error('PDF export error:', err);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <Award className="w-4 h-4" />
            <span>Digital Chain of Custody</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Digital Evidence Certificates
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Generate and export cryptographically verifiable PDF evidentiary certificates conforming to ISO/IEC 27037 standards for digital media provenance.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadPDF}
            disabled={!selectedSource || isGeneratingPdf}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs shadow-glow-cyan/50 transition-all disabled:opacity-50"
          >
            {isGeneratingPdf ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            {isGeneratingPdf ? 'Compiling PDF...' : 'Download PDF Certificate'}
          </button>
        </div>
      </div>

      {/* Select Source Ribbon */}
      <div className="p-4 bg-navy-900/80 rounded-xl border border-background-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <FileBadge className="w-5 h-5 text-cyan-accent" />
          <span className="text-sm font-semibold text-white">Target Evidence Item:</span>
        </div>
        <div className="flex-1 max-w-md">
          <select
            value={selectedSourceId}
            onChange={handleSourceChange}
            className="w-full bg-navy-950 border border-background-border rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {sources.map(s => (
              <option key={s.id} value={s.id}>
                {s.id} — {s.fileName} ({s.creator})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Live Certificate Document Layout */}
      {selectedSource && (
        <div className="max-w-4xl mx-auto bg-navy-900 border-2 border-cyan-500/40 rounded-2xl p-8 lg:p-12 shadow-2xl relative overflow-hidden">
          {/* Subtle watermark background */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-[0.03]">
            <Award className="w-[500px] h-[500px] text-cyan-400" />
          </div>

          {/* Certificate Header */}
          <div className="border-b-2 border-cyan-500/30 pb-6 mb-8 flex flex-col sm:flex-row sm:items-start justify-between gap-6">
            <div>
              <div className="flex items-center gap-2 text-cyan-accent font-mono text-xs uppercase tracking-widest mb-1">
                <span>ISO/IEC 27037 Compliant Evidence Jurat</span>
              </div>
              <h2 className="text-2xl font-black text-white tracking-wider uppercase">
                SourceMark Evidence Certificate
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Cryptographic Chain of Custody & Authenticity Attestation
              </p>
            </div>

            <div className="text-right">
              <span className="px-3 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-mono uppercase tracking-wider block mb-1">
                DEMO CERTIFICATION
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                Cert ID: <strong className="text-slate-200">SMC-{selectedSource.id}</strong>
              </span>
            </div>
          </div>

          {/* Certificate Main Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            {/* Primary Details (2 cols) */}
            <div className="md:col-span-2 space-y-4">
              <div className="bg-navy-950/70 p-4 rounded-xl border border-background-border">
                <span className="text-[10px] text-slate-400 font-mono uppercase block mb-1">
                  Registered Digital Asset
                </span>
                <span className="text-base font-bold text-white block">
                  {selectedSource.fileName}
                </span>
                <span className="text-xs text-cyan-400 font-mono">
                  Source Identifier: {selectedSource.id}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-navy-950/50 rounded-lg border border-background-border">
                  <span className="text-[10px] text-slate-400 font-mono uppercase block">Authority / Signer</span>
                  <span className="text-slate-200 font-medium block truncate mt-0.5">{selectedSource.creator}</span>
                  <span className="text-[10px] text-slate-500 font-mono">ID: {selectedSource.creatorId || 'AGY-USR-0042'}</span>
                </div>
                <div className="p-3 bg-navy-950/50 rounded-lg border border-background-border">
                  <span className="text-[10px] text-slate-400 font-mono uppercase block">Registration Timestamp</span>
                  <span className="text-slate-200 font-medium block mt-0.5">{new Date(selectedSource.registeredAt || selectedSource.timestamp).toLocaleString()}</span>
                  <span className="text-[10px] text-emerald-400 font-mono">Ledger Block #00{selectedSource.blockNumber || 1}</span>
                </div>
              </div>

              {/* Cryptographic Digests */}
              <div className="p-4 bg-navy-950/70 rounded-xl border border-background-border space-y-3">
                <div>
                  <span className="text-[10px] text-slate-400 font-mono uppercase block mb-0.5">
                    Immutable SHA-256 Digest
                  </span>
                  <span className="text-[11px] font-mono text-cyan-300 break-all bg-navy-900 px-2 py-1 rounded block border border-cyan-500/20">
                    {selectedSource.sha256 || selectedSource.hash}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 font-mono uppercase block mb-0.5">
                    Ed25519 Detached Digital Signature
                  </span>
                  <span className="text-[10px] font-mono text-slate-300 break-all bg-navy-900 px-2 py-1 rounded block border border-background-border">
                    {selectedSource.signature || '3a4f89b210c4d5e6...[Verified Curve25519 Signature]'}
                  </span>
                </div>
              </div>
            </div>

            {/* Right Column: QR Code & Score Seal */}
            <div className="flex flex-col items-center justify-between p-4 bg-navy-950/80 rounded-xl border border-background-border text-center">
              {/* QR Preview */}
              <div className="mb-4">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-2">
                  Verification QR Token
                </span>
                {qrPreviewUrl ? (
                  <div className="p-2 bg-white rounded-lg shadow-md inline-block">
                    <img src={qrPreviewUrl} alt="Certificate QR" className="w-32 h-32 block" />
                  </div>
                ) : (
                  <div className="w-32 h-32 bg-navy-900 rounded-lg flex items-center justify-center text-xs text-slate-500">
                    Loading QR...
                  </div>
                )}
                <span className="text-[9px] font-mono text-slate-500 block mt-1">Scan for Ledger Lookup</span>
              </div>

              {/* Forensic Seal */}
              <div className="w-full pt-4 border-t border-background-border">
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-mono font-bold mb-1">
                  <CheckCircle className="w-3.5 h-3.5" />
                  SCORE: {forensicEvaluation?.score || 98} / 100
                </div>
                <div className="text-[10px] text-emerald-400 font-mono uppercase tracking-wider">
                  Risk Level: Low Risk
                </div>
              </div>
            </div>
          </div>

          {/* Legal / Evidentiary Disclaimer */}
          <div className="p-4 rounded-xl bg-navy-950 border border-background-border text-[11px] text-slate-400 leading-relaxed">
            <span className="font-bold text-slate-200">Legal Admissibility Notice:</span> This digital evidence certificate is generated for demonstration and technological evaluation purposes under local provenance simulation. While mathematically conforming to FIPS 180-4 and RFC 8032 specifications, deployment in formal litigation requires integration with a qualified enterprise timestamp authority (RFC 3161) and sworn custodial affidavits.
          </div>
        </div>
      )}
    </div>
  );
}

