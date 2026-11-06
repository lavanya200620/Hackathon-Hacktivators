import React, { useState, useRef } from 'react';
import {
  Layers,
  Upload,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Download,
  Copy,
  Check,
  FileText,
  Search,
  Filter,
  RefreshCw,
  Trash2,
  ExternalLink
} from 'lucide-react';
import { calculateSHA256 } from '../services/crypto';
import { ledgerStorage } from '../services/ledgerStorage';
import { keySecurityService } from '../services/keySecurity';
import { versionControlService } from '../services/versionControl';
import StatusBadge from '../components/common/StatusBadge';

export default function BatchVerification() {
  const [fileList, setFileList] = useState([]);
  const [results, setResults] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedHash, setCopiedHash] = useState(null);
  const fileInputRef = useRef(null);

  // Handle files selected via input or drop
  const handleFilesAdded = async (files) => {
    if (!files || files.length === 0) return;
    const incoming = Array.from(files);

    setIsProcessing(true);
    setProgress(0);

    const registeredSources = ledgerStorage.getSources();
    const batchResults = [];

    for (let i = 0; i < incoming.length; i++) {
      const file = incoming[i];
      try {
        // Real SHA-256 calculation
        const hash = await calculateSHA256(file);

        // Check if hash matches an existing registered source
        const exactMatch = registeredSources.find(
          s => (s.sha256 || s.hash || '').toLowerCase() === hash.toLowerCase()
        );

        // Check if name matches but hash differs (edited file indicator)
        const nameMatch = registeredSources.find(
          s => s.fileName.toLowerCase() === file.name.toLowerCase()
        );

        // Check if hash matches a registered authorized derivative
        const derivativeMatch = versionControlService.findVersionByHash(hash);

        let status = 'UNKNOWN';
        let matchedSource = null;
        let notes = 'File has no recorded cryptographic provenance on this ledger.';

        if (exactMatch) {
          // Check if key is compromised
          const isCompromised = keySecurityService.isKeyCompromised(exactMatch.publicKey || exactMatch.publicKeyHex || exactMatch.keyId || '');
          if (isCompromised) {
            status = 'COMPROMISED_KEY';
            matchedSource = exactMatch;
            notes = 'Hash matches registered source, but the signing key has been reported COMPROMISED.';
          } else {
            status = 'ORIGINAL';
            matchedSource = exactMatch;
            notes = `Bitwise match confirmed against ${exactMatch.id} (${exactMatch.creator}). Ed25519 signature valid.`;
          }
        } else if (derivativeMatch) {
          status = 'AUTHORIZED_DERIVATIVE';
          matchedSource = registeredSources.find(s => s.id === derivativeMatch.sourceId) || { id: derivativeMatch.sourceId };
          notes = `Approved derivative: ${derivativeMatch.transformationReason} (Version: ${derivativeMatch.versionId})`;
        } else if (nameMatch) {
          status = 'EDITED';
          matchedSource = nameMatch;
          notes = `File name matches ${nameMatch.id}, but SHA-256 bitstream differs. Possible unauthorized modification.`;
        }

        batchResults.push({
          id: `BATCH-${Date.now()}-${i}`,
          file,
          fileName: file.name,
          fileSize: file.size,
          fileSizeFormatted: formatBytes(file.size),
          hash,
          status,
          matchedSource,
          notes,
          processedAt: new Date().toISOString(),
        });
      } catch (err) {
        console.error('Error hashing file:', file.name, err);
        batchResults.push({
          id: `BATCH-ERR-${i}`,
          fileName: file.name,
          fileSize: file.size,
          fileSizeFormatted: formatBytes(file.size),
          hash: 'HASHING_ERROR',
          status: 'ERROR',
          notes: 'Failed to read bitstream.',
          processedAt: new Date().toISOString(),
        });
      }

      setProgress(Math.round(((i + 1) / incoming.length) * 100));
    }

    setResults(prev => [...batchResults, ...prev]);
    setIsProcessing(false);
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleCopy = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportReport = () => {
    if (results.length === 0) return;
    const reportData = {
      exportTimestamp: new Date().toISOString(),
      totalFiles: results.length,
      summary: {
        original: results.filter(r => r.status === 'ORIGINAL').length,
        edited: results.filter(r => r.status === 'EDITED').length,
        unknown: results.filter(r => r.status === 'UNKNOWN').length,
        compromised: results.filter(r => r.status === 'COMPROMISED_KEY').length,
      },
      records: results.map(r => ({
        fileName: r.fileName,
        size: r.fileSizeFormatted,
        sha256: r.hash,
        verdict: r.status,
        matchedSourceId: r.matchedSource?.id || null,
        notes: r.notes,
      })),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOURCEMARK-BATCH-AUDIT-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filter & Search
  const filteredResults = results.filter(r => {
    const matchesFilter = filterStatus === 'ALL' || r.status === filterStatus;
    const matchesQuery = searchQuery === '' ||
      r.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.hash.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.matchedSource && r.matchedSource.id.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesFilter && matchesQuery;
  });

  const countOriginal = results.filter(r => r.status === 'ORIGINAL').length;
  const countEdited = results.filter(r => r.status === 'EDITED').length;
  const countUnknown = results.filter(r => r.status === 'UNKNOWN').length;
  const countCompromised = results.filter(r => r.status === 'COMPROMISED_KEY').length;

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <Layers className="w-4 h-4" />
            <span>High-Throughput Digital Forensics</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Batch File Verification
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Drag and drop multiple digital assets to perform concurrent WebCrypto SHA-256 calculations, check provenance signatures, and triage compromised keys.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportReport}
            disabled={results.length === 0}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 border border-background-border text-xs font-medium text-slate-300 transition-all disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit JSON
          </button>
          <button
            onClick={() => setResults([])}
            disabled={results.length === 0}
            className="p-2 rounded-lg bg-navy-850 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 border border-background-border transition-all disabled:opacity-50"
            title="Clear list"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          if (e.dataTransfer.files) {
            handleFilesAdded(e.dataTransfer.files);
          }
        }}
        className="border-2 border-dashed border-cyan-500/30 hover:border-cyan-500/70 bg-navy-900/60 hover:bg-navy-900/90 rounded-2xl p-8 text-center cursor-pointer transition-all relative overflow-hidden group shadow-lg"
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={(e) => handleFilesAdded(e.target.files)}
          className="hidden"
        />

        <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
          <Upload className="w-7 h-7 text-cyan-accent" />
        </div>

        <h3 className="text-base font-semibold text-white">
          Drop Multiple Files for High-Volume Batch Triage
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
          JPG, PNG, WEBP, PDF, TXT, DOCX. Multi-threaded client-side SHA-256 byte hashing.
        </p>

        {isProcessing && (
          <div className="mt-6 max-w-md mx-auto">
            <div className="flex justify-between text-xs font-mono text-cyan-300 mb-1">
              <span>Calculating SHA-256 Bitstreams...</span>
              <span>{progress}%</span>
            </div>
            <div className="w-full h-2 bg-navy-950 rounded-full overflow-hidden border border-cyan-500/20">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 bg-navy-900/80 rounded-xl border border-background-border">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Total Evaluated</span>
            <Layers className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{results.length}</div>
        </div>

        <div className="p-4 bg-navy-900/80 rounded-xl border border-emerald-500/30">
          <div className="flex items-center justify-between text-emerald-400 text-xs mb-1">
            <span>Original (Verified)</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{countOriginal}</div>
        </div>

        <div className="p-4 bg-navy-900/80 rounded-xl border border-rose-500/30">
          <div className="flex items-center justify-between text-rose-400 text-xs mb-1">
            <span>Edited / Altered</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{countEdited}</div>
        </div>

        <div className="p-4 bg-navy-900/80 rounded-xl border border-amber-500/30">
          <div className="flex items-center justify-between text-amber-400 text-xs mb-1">
            <span>Unknown / Unregistered</span>
            <HelpCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">{countUnknown}</div>
        </div>
      </div>

      {/* Filter & Results Table */}
      <div className="bg-navy-900/90 border border-background-border rounded-xl shadow-xl overflow-hidden">
        {/* Controls */}
        <div className="p-4 border-b border-background-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <div className="flex flex-wrap gap-1.5">
              {['ALL', 'ORIGINAL', 'EDITED', 'UNKNOWN', 'COMPROMISED_KEY'].map((st) => (
                <button
                  key={st}
                  onClick={() => setFilterStatus(st)}
                  className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors ${
                    filterStatus === st
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-navy-950 text-slate-400 hover:text-slate-200 border border-background-border'
                  }`}
                >
                  {st.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search filename or hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-navy-950 border border-background-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-950/80 border-b border-background-border text-[11px] font-mono uppercase text-slate-400">
                <th className="py-3 px-4">File Name</th>
                <th className="py-3 px-4">SHA-256 Digest</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4">Ledger Match</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Forensic Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-background-border/60">
              {filteredResults.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-mono">
                    {results.length === 0
                      ? 'No files evaluated yet. Drag and drop assets above.'
                      : 'No records match active filters.'}
                  </td>
                </tr>
              ) : (
                filteredResults.map((item) => (
                  <tr key={item.id} className="hover:bg-navy-850/50 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-medium text-white truncate max-w-xs">
                        {item.fileName}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 font-mono text-[11px] text-cyan-300">
                        <span>{item.hash.substring(0, 12)}...{item.hash.substring(56)}</span>
                        <button
                          onClick={() => handleCopy(item.hash)}
                          className="text-slate-500 hover:text-cyan-300 transition-colors"
                          title="Copy hash"
                        >
                          {copiedHash === item.hash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {item.fileSizeFormatted}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      {item.matchedSource ? (
                        <span className="text-cyan-400 font-semibold">{item.matchedSource.id}</span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-xs truncate" title={item.notes}>
                      {item.notes}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

