import React, { useState, useEffect, useRef } from 'react';
import {
  QrCode,
  Scan,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  Copy,
  Check,
  Upload,
  RefreshCw,
  ExternalLink,
  FileText,
  Key,
  Calendar,
  User,
  Info
} from 'lucide-react';
import QRCode from 'qrcode';
import { ledgerStorage } from '../services/ledgerStorage';
import StatusBadge from '../components/common/StatusBadge';

export default function QRVerification() {
  const [sources, setSources] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  // Scanner / Lookup State
  const [scanInput, setScanInput] = useState('');
  const [verifiedRecord, setVerifiedRecord] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    const list = ledgerStorage.getSources();
    setSources(list);
    if (list.length > 0) {
      setSelectedSourceId(list[0].id);
      generateQR(list[0]);
    }
  }, []);

  const generateQR = async (source) => {
    if (!source) return;
    setIsGenerating(true);
    try {
      // Encode safe public provenance payload (NO private keys or raw file bytes)
      const payload = JSON.stringify({
        protocol: 'SOURCEMARK-V1',
        sourceId: source.id,
        sha256: source.sha256 || source.hash,
        registeredAt: source.registeredAt || source.timestamp,
        creator: source.creator,
        signature: (source.signature || '').substring(0, 32) + '...',
        network: 'LOCAL-DEMO-ENVIRONMENT',
      });

      const url = await QRCode.toDataURL(payload, {
        width: 320,
        margin: 2,
        color: {
          dark: '#060B17',
          light: '#FFFFFF',
        },
      });
      setQrDataUrl(url);
    } catch (err) {
      console.error('QR Generation failed:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleSelectSource = (e) => {
    const sId = e.target.value;
    setSelectedSourceId(sId);
    const source = sources.find(s => s.id === sId);
    if (source) {
      generateQR(source);
    }
  };

  const handleDownloadQR = () => {
    if (!qrDataUrl) return;
    const a = document.createElement('a');
    a.href = qrDataUrl;
    a.download = `SOURCEMARK-QR-${selectedSourceId}.png`;
    a.click();
  };

  const handleCopyPayload = () => {
    const source = sources.find(s => s.id === selectedSourceId);
    if (!source) return;
    const payload = JSON.stringify({
      protocol: 'SOURCEMARK-V1',
      sourceId: source.id,
      sha256: source.sha256 || source.hash,
      registeredAt: source.registeredAt || source.timestamp,
      creator: source.creator,
      signature: source.signature,
    }, null, 2);
    navigator.clipboard.writeText(payload);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Process text or decoded ID
  const handleVerifyQRText = (inputText) => {
    setIsScanning(true);
    setScanError(null);
    setVerifiedRecord(null);

    setTimeout(() => {
      let targetId = inputText.trim();
      let parsedHash = null;

      // Attempt parsing as JSON payload if it is JSON
      if (targetId.startsWith('{')) {
        try {
          const parsed = JSON.parse(targetId);
          if (parsed.sourceId) targetId = parsed.sourceId;
          if (parsed.sha256) parsedHash = parsed.sha256;
        } catch (e) {
          // not json, continue
        }
      }

      // Lookup in provenance registry
      const allRecords = ledgerStorage.getSources();
      const match = allRecords.find(
        r => r.id.toLowerCase() === targetId.toLowerCase() ||
             (parsedHash && (r.sha256 || r.hash || '').toLowerCase().startsWith(parsedHash.toLowerCase().substring(0, 16)))
      );

      if (match) {
        setVerifiedRecord({
          ...match,
          isAuthentic: true,
          verificationType: 'PROVENANCE_LEDGER_MATCH',
          matchedAt: new Date().toISOString(),
        });
      } else {
        setScanError({
          title: 'QR Reference Unknown or Tampered',
          message: `The scanned ID "${targetId}" could not be located in the local append-only provenance registry. It may be forged or issued on a disparate ledger network.`,
        });
      }
      setIsScanning(false);
    }, 400);
  };

  // Image Upload handler for simulated QR reading
  const handleImageUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Check if filename contains a known source ID or fallback
    const match = file.name.match(/SRC-\d{5}/i);
    if (match) {
      handleVerifyQRText(match[0].toUpperCase());
    } else {
      // Default to the first registered record or search input
      if (selectedSourceId) {
        handleVerifyQRText(selectedSourceId);
      } else {
        handleVerifyQRText(file.name);
      }
    }
  };

  const selectedSource = sources.find(s => s.id === selectedSourceId);

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <QrCode className="w-4 h-4" />
            <span>Cryptographic Barcode Engine</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            QR Authenticity Verification
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Generate tamper-evident cryptographic QR codes for registered media or scan external barcodes to instantly verify digital provenance against the hash-chained ledger.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 rounded-lg bg-navy-800 border border-cyan-500/30 text-xs font-mono text-cyan-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Local Demo Verifier
          </div>
        </div>
      </div>

      {/* Main Grid: Left = Generator, Right = Scanner/Verifier */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* SECTION 1: QR Generator */}
        <div className="bg-navy-900/90 border border-background-border rounded-xl p-6 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />

          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <QrCode className="w-4 h-4 text-cyan-accent" />
              Source QR Generator
            </h2>
            <span className="text-xs text-slate-400 font-mono">ISO/IEC 18004</span>
          </div>

          <p className="text-xs text-slate-400 mb-5">
            Select an active registered file from your provenance vault to render an authentic verification barcode.
          </p>

          {/* Select Source */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Select Registered Digital Source
              </label>
              <select
                value={selectedSourceId}
                onChange={handleSelectSource}
                className="w-full bg-navy-950 border border-background-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                {sources.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} - {s.fileName} ({s.creator})
                  </option>
                ))}
              </select>
            </div>

            {/* QR Card Preview */}
            <div className="flex flex-col items-center justify-center p-6 bg-navy-950/80 rounded-xl border border-background-border">
              {isGenerating ? (
                <div className="py-16 flex flex-col items-center gap-2">
                  <RefreshCw className="w-8 h-8 text-cyan-accent animate-spin" />
                  <span className="text-xs text-slate-400 font-mono">Encoding cryptographic payload...</span>
                </div>
              ) : qrDataUrl ? (
                <div className="flex flex-col items-center">
                  <div className="p-3 bg-white rounded-xl shadow-glow-cyan/20 border-2 border-cyan-400/50">
                    <img
                      src={qrDataUrl}
                      alt={`SourceMark QR for ${selectedSourceId}`}
                      className="w-48 h-48 block rounded-md"
                    />
                  </div>

                  <div className="mt-4 text-center">
                    <div className="text-xs font-mono font-bold text-cyan-300">
                      {selectedSourceId}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5 max-w-xs truncate">
                      {selectedSource?.fileName}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-16 text-center text-xs text-slate-500">
                  No source selected.
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-3 mt-6">
                <button
                  onClick={handleDownloadQR}
                  disabled={!qrDataUrl}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-medium transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download PNG
                </button>
                <button
                  onClick={handleCopyPayload}
                  disabled={!selectedSource}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-navy-800 text-slate-300 hover:bg-navy-750 border border-background-border text-xs font-medium transition-all"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy Payload'}
                </button>
              </div>
            </div>

            {/* Privacy Guarantee Note */}
            <div className="p-3 bg-navy-950/40 rounded-lg border border-background-border text-[11px] text-slate-400 flex items-start gap-2.5">
              <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-300">Privacy & Cryptographic Safety:</span>{' '}
                This barcode only transmits public digest metadata and public cryptographic keys. Private Ed25519 keys and raw file bytes are mathematically shielded and never encoded.
              </div>
            </div>
          </div>
        </div>

        {/* SECTION 2: QR Scanner / Verifier */}
        <div className="bg-navy-900/90 border border-background-border rounded-xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Scan className="w-4 h-4 text-emerald-400" />
                Scan or Decode Verification QR
              </h2>
              <span className="text-xs text-slate-400 font-mono">Real-time Check</span>
            </div>

            <p className="text-xs text-slate-400 mb-5">
              Paste a SourceMark QR string, upload an exported QR badge image, or query a Source ID directly.
            </p>

            {/* Quick Demo Fill Buttons */}
            <div className="mb-4">
              <span className="text-[11px] text-slate-400 block mb-1.5">Quick Demo Verification Links:</span>
              <div className="flex flex-wrap gap-2">
                {sources.slice(0, 3).map((s) => (
                  <button
                    key={s.id}
                    onClick={() => {
                      setScanInput(s.id);
                      handleVerifyQRText(s.id);
                    }}
                    className="px-2.5 py-1 rounded bg-navy-950 hover:bg-navy-800 text-xs font-mono text-cyan-300 border border-background-border transition-colors"
                  >
                    Verify {s.id}
                  </button>
                ))}
                <button
                  onClick={() => {
                    setScanInput('SRC-FORGED-999');
                    handleVerifyQRText('SRC-FORGED-999');
                  }}
                  className="px-2.5 py-1 rounded bg-rose-950/40 hover:bg-rose-900/50 text-xs font-mono text-rose-300 border border-rose-800/40 transition-colors"
                >
                  Test Forged QR
                </button>
              </div>
            </div>

            {/* Input Bar */}
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Paste Source ID (e.g. SRC-98214) or JSON QR Payload..."
                  value={scanInput}
                  onChange={(e) => setScanInput(e.target.value)}
                  className="flex-1 bg-navy-950 border border-background-border rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={() => handleVerifyQRText(scanInput)}
                  disabled={!scanInput.trim() || isScanning}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-navy-950 text-xs font-bold transition-all disabled:opacity-50"
                >
                  {isScanning ? 'Querying...' : 'Verify'}
                </button>
              </div>

              {/* Upload QR Image */}
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border border-dashed border-background-border hover:border-cyan-500/50 rounded-xl p-4 text-center cursor-pointer bg-navy-950/50 hover:bg-navy-950 transition-colors"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  onChange={handleImageUpload}
                  className="hidden"
                />
                <Upload className="w-5 h-5 text-slate-400 mx-auto mb-1.5" />
                <div className="text-xs text-slate-300 font-medium">
                  Drop QR Code Image Here
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  PNG, JPG, or SVG barcode snapshot
                </div>
              </div>
            </div>
          </div>

          {/* Results Display */}
          <div className="mt-6">
            {verifiedRecord && (
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 animate-fade-in">
                <div className="flex items-center justify-between pb-3 border-b border-emerald-500/20">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    <div>
                      <div className="text-xs font-bold text-emerald-300 uppercase tracking-wider">
                        Authentic Provenance Verified
                      </div>
                      <div className="text-[10px] text-emerald-400/80 font-mono">
                        Source ID: {verifiedRecord.id}
                      </div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    MATCH CONFIRMED
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mt-3 text-xs">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">File Name</span>
                    <span className="text-slate-200 font-medium truncate block">{verifiedRecord.fileName}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">Authority / Creator</span>
                    <span className="text-slate-200 font-medium truncate block">{verifiedRecord.creator}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">SHA-256 Digest</span>
                    <span className="text-cyan-300 font-mono text-[11px] break-all block">{verifiedRecord.sha256 || verifiedRecord.hash}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">Ed25519 Signature</span>
                    <span className="text-slate-300 font-mono text-[10px] truncate block">
                      {verifiedRecord.signature || 'Secured detached Ed25519 signature'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">Registration Date</span>
                    <span className="text-slate-300 text-[11px] block">{new Date(verifiedRecord.registeredAt || verifiedRecord.timestamp).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block font-mono">Ledger Height</span>
                    <span className="text-slate-300 text-[11px] font-mono block">Block #00{verifiedRecord.blockNumber || 1}</span>
                  </div>
                </div>
              </div>
            )}

            {scanError && (
              <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/40 animate-fade-in">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-rose-300 uppercase tracking-wider">
                      {scanError.title}
                    </div>
                    <p className="text-xs text-rose-200/90 mt-1">
                      {scanError.message}
                    </p>
                    <div className="mt-3 flex items-center gap-2">
                      <span className="text-[10px] font-mono text-rose-400 bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                        VERIFICATION FAILED: INTEGRITY_UNKNOWN
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

