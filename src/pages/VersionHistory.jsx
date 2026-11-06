import React, { useState, useEffect } from 'react';
import {
  GitBranch,
  GitCommit,
  PlusCircle,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  FileText,
  User,
  Calendar,
  Layers,
  ArrowRight,
  Info,
  RefreshCw,
  Copy,
  Check
} from 'lucide-react';
import { versionControlService } from '../services/versionControl';
import { ledgerStorage } from '../services/ledgerStorage';
import { calculateSHA256 } from '../services/crypto';

export default function VersionHistory() {
  const [versions, setVersions] = useState([]);
  const [sources, setSources] = useState([]);
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [copiedHash, setCopiedHash] = useState(null);

  // New Version Form State
  const [formSourceId, setFormSourceId] = useState('');
  const [formCategory, setFormCategory] = useState('Web Compression');
  const [formReason, setFormReason] = useState('');
  const [formActor, setFormActor] = useState('Dr. Evelyn Vance (Chief Geoint Analyst)');
  const [formFile, setFormFile] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = () => {
    const vers = versionControlService.getVersions();
    const srcs = ledgerStorage.getSources();
    setVersions(vers);
    setSources(srcs);
    if (srcs.length > 0 && !selectedSourceId) {
      setSelectedSourceId(srcs[0].id);
      setFormSourceId(srcs[0].id);
    }
  };

  const handleCopy = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleRegisterDerivative = async (e) => {
    e.preventDefault();
    if (!formSourceId || !formReason) return;
    setIsSubmitting(true);

    try {
      let hash = '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e';
      let fileName = `${formCategory.toLowerCase().replace(/\s+/g, '_')}_derivative.webp`;
      let fileSizeFormatted = '1.24 MB';

      if (formFile) {
        hash = await calculateSHA256(formFile);
        fileName = formFile.name;
        fileSizeFormatted = `${(formFile.size / (1024 * 1024)).toFixed(2)} MB`;
      }

      const parentSource = sources.find(s => s.id === formSourceId);

      versionControlService.registerDerivative({
        sourceId: formSourceId,
        fileName,
        originalHash: parentSource ? parentSource.hash : 'ORIGINAL_ROOT_HASH',
        newHash: hash,
        transformationReason: `${formCategory}: ${formReason}`,
        actor: formActor,
        actorId: 'AGY-USR-0042',
        fileSizeFormatted,
        approvedBy: 'Source Custodian Audit Committee',
        notes: `Derivative registered with authorized cryptographic lineage.`,
      });

      setShowRegisterModal(false);
      setFormReason('');
      setFormFile(null);
      loadData();
    } catch (err) {
      console.error('Error registering derivative:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const activeSource = sources.find(s => s.id === selectedSourceId);
  const sourceVersions = versions.filter(v => v.sourceId === selectedSourceId);

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <GitBranch className="w-4 h-4" />
            <span>Authorized Derivative Lineage</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Legitimate Re-saves & Version Control
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Distinguish benign editorial workflows (lossless compression, redaction, web format conversion) from malicious tampering with author-signed cryptographic derivative lineages.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowRegisterModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs shadow-glow-cyan/50 transition-all"
          >
            <PlusCircle className="w-4 h-4" />
            Register Authorized Derivative
          </button>
        </div>
      </div>

      {/* Forensic Distinction Explanation Banner */}
      <div className="p-4 bg-navy-900/90 rounded-xl border border-cyan-500/20 text-xs text-slate-300 flex items-start gap-3">
        <Info className="w-5 h-5 text-cyan-accent flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">The Derivative Distinction:</strong> Not all modified files are counterfeit. When a creative agency resizes an image for Instagram, or a legal firm redacts bank routing numbers from a PDF, the bitstream hash fundamentally changes. SourceMark allows authorized creators to seal child versions with provenance continuity, differentiating <span className="text-emerald-400 font-semibold">AUTHORIZED DERIVATIVES</span> from <span className="text-rose-400 font-semibold">MALICIOUS FORGERIES</span>.
        </div>
      </div>

      {/* Select Source Ribbon */}
      <div className="p-4 bg-navy-900/80 rounded-xl border border-background-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Layers className="w-5 h-5 text-cyan-accent" />
          <span className="text-sm font-semibold text-white">Select Master Asset:</span>
        </div>
        <div className="flex-1 max-w-md">
          <select
            value={selectedSourceId}
            onChange={(e) => setSelectedSourceId(e.target.value)}
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

      {/* Lineage Tree & Comparison */}
      {activeSource && (
        <div className="space-y-6">
          {/* Master Root Block */}
          <div className="p-6 bg-navy-900/90 rounded-2xl border-2 border-emerald-500/40 shadow-xl relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-background-border">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-emerald-300">ROOT MASTER ASSET (v1.0)</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      MASTER ORIGINAL
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-0.5">{activeSource.fileName}</h3>
                </div>
              </div>

              <div className="text-right text-xs">
                <span className="text-slate-400 block font-mono">Source ID</span>
                <span className="text-cyan-300 font-mono font-bold">{activeSource.id}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-xs">
              <div className="md:col-span-2">
                <span className="text-[10px] text-slate-400 font-mono uppercase block mb-1">Master SHA-256 Digest</span>
                <div className="flex items-center gap-2 bg-navy-950 p-2 rounded-lg border border-background-border">
                  <span className="text-cyan-300 font-mono text-[11px] break-all">{activeSource.sha256 || activeSource.hash}</span>
                  <button onClick={() => handleCopy(activeSource.sha256 || activeSource.hash)} className="text-slate-500 hover:text-cyan-300">
                    {copiedHash === (activeSource.sha256 || activeSource.hash) ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 font-mono uppercase block mb-1">Registered Authority</span>
                <div className="bg-navy-950 p-2 rounded-lg border border-background-border font-medium text-slate-200">
                  {activeSource.creator}
                </div>
              </div>
            </div>
          </div>

          {/* Derivatives Lineage Branch */}
          <div className="pl-6 border-l-2 border-cyan-500/40 space-y-4 ml-6">
            <div className="text-xs font-mono uppercase tracking-wider text-cyan-300 flex items-center gap-2">
              <GitCommit className="w-4 h-4 text-cyan-accent" />
              <span>Authorized Child Versions ({sourceVersions.length})</span>
            </div>

            {sourceVersions.length === 0 ? (
              <div className="p-6 bg-navy-900/60 rounded-xl border border-dashed border-background-border text-center text-xs text-slate-500">
                No authorized derivatives registered for this asset yet. Click "Register Authorized Derivative" above.
              </div>
            ) : (
              sourceVersions.map((ver, idx) => (
                <div
                  key={ver.versionId}
                  className="p-5 bg-navy-900/90 rounded-xl border border-background-border hover:border-cyan-500/40 transition-all shadow-md"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-background-border">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                      <span className="font-mono text-xs font-bold text-white">{ver.versionId}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                        {ver.authorizationStatus}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400 font-mono">
                      Created: {new Date(ver.createdAt).toLocaleDateString()}
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="text-[10px] text-slate-400 font-mono uppercase block">Derivative Asset Name</span>
                      <span className="text-slate-200 font-medium">{ver.fileName} ({ver.fileSizeFormatted})</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 font-mono uppercase block">Signer & Custodian</span>
                      <span className="text-slate-200 font-medium">{ver.actor}</span>
                    </div>
                    <div className="md:col-span-2">
                      <span className="text-[10px] text-slate-400 font-mono uppercase block">Transformation Justification</span>
                      <p className="text-slate-300 bg-navy-950 p-2.5 rounded-lg border border-background-border mt-1">
                        {ver.transformationReason}
                      </p>
                    </div>
                    <div className="md:col-span-2">
                      <span className="text-[10px] text-slate-400 font-mono uppercase block">New Derivative SHA-256 Digest</span>
                      <div className="flex items-center gap-2 bg-navy-950 p-2 rounded-lg border border-background-border font-mono text-[11px] text-slate-300 break-all mt-1">
                        <span>{ver.newHash}</span>
                        <button onClick={() => handleCopy(ver.newHash)} className="text-slate-500 hover:text-cyan-300">
                          {copiedHash === ver.newHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Modal: Register Derivative */}
      {showRegisterModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-lg bg-navy-900 border border-cyan-500/40 rounded-2xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between pb-4 border-b border-background-border mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-cyan-accent" />
                Register Authorized Derivative
              </h3>
              <button
                onClick={() => setShowRegisterModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRegisterDerivative} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Parent Master Source</label>
                <select
                  value={formSourceId}
                  onChange={(e) => setFormSourceId(e.target.value)}
                  className="w-full bg-navy-950 border border-background-border rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  {sources.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.id} — {s.fileName}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Derivative Transformation Type</label>
                <select
                  value={formCategory}
                  onChange={(e) => setFormCategory(e.target.value)}
                  className="w-full bg-navy-950 border border-background-border rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="Web Compression">Web Compression / Optimization (WebP / AVIF)</option>
                  <option value="Redaction">Confidential Redaction (PII / Financial Data scrub)</option>
                  <option value="Format Conversion">Format Transcoding (TIFF to JPEG / PDF)</option>
                  <option value="Watermarking">Distribution Watermarking (Embargo / Press Copy)</option>
                  <option value="Editorial Cropping">Approved Aspect Cropping</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Transformation Reason & Context</label>
                <textarea
                  rows={2}
                  required
                  placeholder="e.g. Scaled for responsive mobile delivery with multispectral sensor preserved..."
                  value={formReason}
                  onChange={(e) => setFormReason(e.target.value)}
                  className="w-full bg-navy-950 border border-background-border rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Authorizing Custodian</label>
                <input
                  type="text"
                  value={formActor}
                  onChange={(e) => setFormActor(e.target.value)}
                  className="w-full bg-navy-950 border border-background-border rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Upload Derivative File (Optional)</label>
                <input
                  type="file"
                  onChange={(e) => setFormFile(e.target.files?.[0] || null)}
                  className="w-full bg-navy-950 border border-background-border rounded-lg p-2 text-slate-400 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-cyan-500/20 file:text-cyan-300"
                />
              </div>

              <div className="pt-4 border-t border-background-border flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-4 py-2 rounded-lg bg-navy-800 text-slate-300 hover:bg-navy-750"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-bold transition-all"
                >
                  {isSubmitting ? 'Registering...' : 'Register Lineage'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

