import React, { useState } from 'react';
import { CheckCircle2, Copy, Check, Download, X, Shield, Key, FileText, Calendar } from 'lucide-react';

export default function ReceiptModal({ isOpen, onClose, data }) {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !data) return null;

  const handleCopyHash = () => {
    navigator.clipboard.writeText(data.sha256 || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadReceipt = () => {
    const receiptContent = JSON.stringify({
      title: 'SourceMark Digital Content Registration Receipt',
      standard: 'ISO/IEC 27037 Digital Forensics Evidence Schema',
      sourceId: data.id,
      fileName: data.fileName,
      sha256Fingerprint: data.sha256,
      ed25519Signature: data.signature,
      signerPublicKey: data.publicKey,
      keyIdentifier: data.keyId,
      creator: data.creator,
      creatorId: data.creatorId,
      category: data.category,
      registeredTimestamp: data.registeredAt,
      verificationEngine: 'Ed25519-EdDSA-Curve25519',
      ledgerAnchor: 'ACTIVE_CHAIN_VERIFIED',
    }, null, 2);

    const blob = new Blob([receiptContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sourcemark-receipt-${data.id || 'source'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-2xl bg-navy-900 border border-cyan-500/30 p-6 sm:p-8 shadow-2xl shadow-cyan-950/80 max-h-[90vh] overflow-y-auto">
        {/* Glow accent */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-48 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent" />

        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-white rounded-lg hover:bg-navy-850 transition-colors"
          aria-label="Close"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shadow-glow-green">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              Registration Cryptographic Receipt
            </h2>
            <p className="text-xs text-slate-400">
              Verifiable proof of digital creation and tamper-evident provenance registration
            </p>
          </div>
        </div>

        {/* Certificate Card Content */}
        <div className="p-4 rounded-xl bg-navy-950 border border-slate-800 space-y-4 text-xs font-mono">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 pb-3 border-b border-slate-800">
            <div>
              <span className="text-slate-400 block text-[10px] uppercase">Source Identification</span>
              <span className="text-cyan-400 font-bold text-base">{data.id}</span>
            </div>
            <div className="text-right">
              <span className="text-slate-400 block text-[10px] uppercase">Timestamp (UTC)</span>
              <span className="text-slate-300">{data.registeredAt || new Date().toISOString()}</span>
            </div>
          </div>

          <div>
            <span className="text-slate-400 block text-[10px] uppercase mb-1">File Artifact Name</span>
            <div className="p-2 rounded bg-navy-900 border border-slate-800 text-slate-200 font-sans flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span className="font-medium truncate">{data.fileName}</span>
              {data.fileSizeFormatted && (
                <span className="text-slate-500 text-xs ml-auto">({data.fileSizeFormatted})</span>
              )}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-400 text-[10px] uppercase">SHA-256 Content Fingerprint</span>
              <button
                onClick={handleCopyHash}
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] font-sans"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy Hash'}
              </button>
            </div>
            <div className="p-2.5 rounded bg-navy-900 border border-slate-800 text-cyan-300 break-all select-all text-[11px] leading-relaxed">
              {data.sha256}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <span className="text-slate-400 block text-[10px] uppercase mb-1">Creator / Author</span>
              <div className="p-2 rounded bg-navy-900 border border-slate-800 text-slate-300 font-sans truncate">
                {data.creator || 'Authenticated User'}
              </div>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px] uppercase mb-1">Public Key Identifier</span>
              <div className="p-2 rounded bg-navy-900 border border-slate-800 text-emerald-400 font-mono flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-emerald-400" />
                <span className="truncate">{data.keyId || 'ED25519-ROOT'}</span>
              </div>
            </div>
          </div>

          <div>
            <span className="text-slate-400 block text-[10px] uppercase mb-1">Ed25519 Digital Signature</span>
            <div className="p-2 rounded bg-navy-900 border border-slate-800 text-slate-400 break-all text-[10px] max-h-16 overflow-y-auto">
              {data.signature}
            </div>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="mt-6 flex flex-col sm:flex-row items-center justify-end gap-3 font-sans">
          <button
            onClick={handleCopyHash}
            className="w-full sm:w-auto px-4 py-2.5 rounded-xl border border-slate-700 bg-navy-800 hover:bg-navy-750 text-slate-200 font-medium text-xs flex items-center justify-center gap-2 transition-colors"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Fingerprint Copied' : 'Copy SHA-256'}
          </button>
          <button
            onClick={handleDownloadReceipt}
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center justify-center gap-2 shadow-glow-cyan transition-all"
          >
            <Download className="w-4 h-4" />
            Download Registration Receipt (.JSON)
          </button>
        </div>
      </div>
    </div>
  );
}

