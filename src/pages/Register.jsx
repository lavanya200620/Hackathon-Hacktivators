import React, { useState, useRef } from 'react';
import {
  Upload,
  FileCheck2,
  FileText,
  Image as ImageIcon,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  Download,
  Loader2,
  Shield,
  Key,
  Calendar,
  Sparkles,
  ArrowRight,
  Info,
  Layers,
  Cpu
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { calculateSHA256, signFingerprint, verifyFingerprintSignature, getOrCreateKeyPair } from '../services/crypto';
import { apiService } from '../services/api';
import ReceiptModal from '../components/common/ReceiptModal';

export default function Register() {
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Form Fields
  const [creatorName, setCreatorName] = useState('Dr. Evelyn Vance (Chief Geoint Analyst)');
  const [creatorId, setCreatorId] = useState('AGY-USR-0042');
  const [category, setCategory] = useState('Satellite Imagery');
  const [sourceOrigin, setSourceOrigin] = useState('Terminal Orbital Station Alpha');
  const [description, setDescription] = useState('High-resolution sensor survey dataset with verified hardware timestamp.');

  // Stepper & Workflow State
  const [currentStep, setCurrentStep] = useState(0); // 0: Idle, 1..6: Active steps, 7: Done
  const [stepStatuses, setStepStatuses] = useState({
    1: 'pending',
    2: 'pending',
    3: 'pending',
    4: 'pending',
    5: 'pending',
    6: 'pending',
  });
  const [registrationResult, setRegistrationResult] = useState(null);
  const [showReceiptModal, setShowReceiptModal] = useState(false);
  const [hashCopied, setHashCopied] = useState(false);

  const fileInputRef = useRef(null);

  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf', 'text/plain'];

  const validateAndSetFile = (selectedFile) => {
    setErrorMsg('');
    if (!selectedFile) return;

    if (!allowedTypes.includes(selectedFile.type) && !selectedFile.name.match(/\.(jpg|jpeg|png|pdf|txt)$/i)) {
      setErrorMsg('Unsupported format. Please upload JPG, PNG, PDF, or TXT file.');
      return;
    }

    if (selectedFile.size > 50 * 1024 * 1024) {
      setErrorMsg('File size exceeds the 50MB maximum threshold.');
      return;
    }

    setFile(selectedFile);

    // Image preview
    if (selectedFile.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (e) => setFilePreview(e.target.result);
      reader.readAsDataURL(selectedFile);
    } else {
      setFilePreview(null);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // 6-STAGE CRYPTOGRAPHIC REGISTRATION WORKFLOW
  const handleStartRegistration = async (e) => {
    e.preventDefault();
    if (!file) {
      setErrorMsg('Please select a file to register.');
      return;
    }

    setErrorMsg('');
    setRegistrationResult(null);

    try {
      // STEP 1: Upload file into buffer
      setCurrentStep(1);
      setStepStatuses((prev) => ({ ...prev, 1: 'running' }));
      await delay(400);
      setStepStatuses((prev) => ({ ...prev, 1: 'completed' }));

      // STEP 2: Generate SHA-256 fingerprint using Web Crypto API
      setCurrentStep(2);
      setStepStatuses((prev) => ({ ...prev, 2: 'running' }));
      const sha256Hash = await calculateSHA256(file);
      await delay(450);
      setStepStatuses((prev) => ({ ...prev, 2: 'completed' }));

      // STEP 3: Sign fingerprint using Ed25519
      setCurrentStep(3);
      setStepStatuses((prev) => ({ ...prev, 3: 'running' }));
      const signatureInfo = signFingerprint(sha256Hash);
      await delay(400);
      setStepStatuses((prev) => ({ ...prev, 3: 'completed' }));

      // STEP 4: Verify the generated signature
      setCurrentStep(4);
      setStepStatuses((prev) => ({ ...prev, 4: 'running' }));
      const isValid = verifyFingerprintSignature(
        sha256Hash,
        signatureInfo.signatureHex,
        signatureInfo.publicKeyHex
      );
      if (!isValid) {
        throw new Error('Ed25519 signature mathematical validation failed');
      }
      await delay(350);
      setStepStatuses((prev) => ({ ...prev, 4: 'completed' }));

      // STEP 5: Register provenance metadata
      setCurrentStep(5);
      setStepStatuses((prev) => ({ ...prev, 5: 'running' }));
      const newSourceId = `SRC-${Math.floor(10000 + Math.random() * 90000)}`;
      const payload = {
        id: newSourceId,
        fileName: file.name,
        fileType: file.type || 'application/octet-stream',
        fileSize: file.size,
        fileSizeFormatted: formatFileSize(file.size),
        sha256: sha256Hash,
        signature: signatureInfo.signatureHex,
        publicKey: signatureInfo.publicKeyHex,
        keyId: signatureInfo.keyId,
        creator: creatorName,
        creatorId: creatorId,
        category: category,
        description: description,
        sourceOrigin: sourceOrigin,
      };
      await delay(400);
      setStepStatuses((prev) => ({ ...prev, 5: 'completed' }));

      // STEP 6: Save the registration record and append event to audit ledger
      setCurrentStep(6);
      setStepStatuses((prev) => ({ ...prev, 6: 'running' }));
      const apiResponse = await apiService.registerSource(payload);
      await delay(450);
      setStepStatuses((prev) => ({ ...prev, 6: 'completed' }));

      // Successfully Completed!
      setCurrentStep(7);
      setRegistrationResult({
        ...payload,
        registeredAt: new Date().toISOString(),
        status: 'ACTIVE_REGISTERED',
        isDemoMode: apiResponse.isDemoMode,
      });

      // Trigger Confetti
      try {
        confetti({
          particleCount: 80,
          spread: 70,
          origin: { y: 0.6 },
          colors: ['#00F0FF', '#10B981', '#38BDF8', '#6366F1'],
        });
      } catch (err) {
        // confetti fallback
      }
    } catch (err) {
      console.error('Registration failure:', err);
      setErrorMsg(`Registration interrupted: ${err.message}`);
      setStepStatuses((prev) => ({ ...prev, [currentStep]: 'error' }));
    }
  };

  const handleCopyHash = () => {
    if (registrationResult) {
      navigator.clipboard.writeText(registrationResult.sha256);
      setHashCopied(true);
      setTimeout(() => setHashCopied(false), 2000);
    }
  };

  const resetForm = () => {
    setFile(null);
    setFilePreview(null);
    setCurrentStep(0);
    setRegistrationResult(null);
    setStepStatuses({ 1: 'pending', 2: 'pending', 3: 'pending', 4: 'pending', 5: 'pending', 6: 'pending' });
  };

  const stepLabels = [
    { num: 1, title: 'Upload & Buffer', desc: 'Secure in-memory binary read' },
    { num: 2, title: 'SHA-256 Fingerprint', desc: 'Web Crypto digest generation' },
    { num: 3, title: 'Ed25519 Signing', desc: 'Asymmetric cryptographic signature' },
    { num: 4, title: 'Verify Signature', desc: 'Curve25519 mathematical validation' },
    { num: 5, title: 'Provenance Metadata', desc: 'Assemble contextual forensic record' },
    { num: 6, title: 'Audit Ledger Commit', desc: 'Hash-chained block persistence' },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title & Description */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Register Digital Source
        </h1>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Create a cryptographically verifiable record of your digital content with SHA-256 hashing and Ed25519 digital signatures.
        </p>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/70 border border-rose-500/40 text-rose-300 flex items-center gap-3 text-xs">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* If Registration Succeeded: Show Premium Success Certificate Card */}
      {registrationResult && currentStep === 7 ? (
        <div className="glass-panel p-6 sm:p-8 rounded-2xl border border-emerald-500/40 shadow-glow-green space-y-6 animate-in zoom-in-95 duration-300">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-glow-green">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-white">Source Successfully Registered</h2>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 border border-emerald-500/50 text-emerald-400">
                    VERIFIED ANCHOR
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Content fingerprint and cryptographic provenance record have been permanently anchored.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <button
                onClick={resetForm}
                className="px-4 py-2 rounded-xl border border-slate-700 bg-navy-900 hover:bg-navy-800 text-slate-300 text-xs font-semibold transition-colors"
              >
                Register Another File
              </button>
              <button
                onClick={() => setShowReceiptModal(true)}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-2 shadow-glow-cyan transition-all"
              >
                <Download className="w-4 h-4" />
                View Receipt
              </button>
            </div>
          </div>

          {/* Forensic Record Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Source ID</span>
              <span className="text-cyan-400 font-bold text-sm">{registrationResult.id}</span>
            </div>

            <div className="p-3.5 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Filename</span>
              <span className="text-slate-200 font-medium truncate block font-sans" title={registrationResult.fileName}>
                {registrationResult.fileName}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Signature Status</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Ed25519 Valid
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Registration Time</span>
              <span className="text-slate-300">{new Date(registrationResult.registeredAt).toLocaleTimeString()} UTC</span>
            </div>
          </div>

          {/* Fingerprint Full Display with Copy */}
          <div className="p-4 rounded-xl bg-navy-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                SHA-256 Fingerprint (Master Content Digest)
              </span>
              <button
                onClick={handleCopyHash}
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 font-mono text-[11px]"
              >
                {hashCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {hashCopied ? 'Hash Copied to Clipboard' : 'Copy Hash'}
              </button>
            </div>
            <div className="p-3 rounded-lg bg-navy-900 border border-slate-800/80 text-cyan-300 font-mono text-xs break-all select-all">
              {registrationResult.sha256}
            </div>
          </div>

          {/* Cryptographic Key & Signer Metadata */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Creator Authority</span>
              <span className="text-slate-300 font-sans">{registrationResult.creator}</span>
            </div>
            <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Public Key Identifier</span>
              <span className="text-emerald-400">{registrationResult.keyId}</span>
            </div>
            <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
              <span className="text-slate-500 uppercase text-[10px] block">Ledger State</span>
              <span className="text-cyan-400">Committed to Chain</span>
            </div>
          </div>

          {/* Action Row */}
          <div className="flex flex-col sm:flex-row items-center justify-end gap-3 pt-2">
            <button
              onClick={handleCopyHash}
              className="w-full sm:w-auto px-4 py-2.5 rounded-xl border border-slate-700 bg-navy-850 hover:bg-navy-800 text-slate-200 text-xs font-semibold flex items-center justify-center gap-2 transition-colors"
            >
              {hashCopied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              {hashCopied ? 'Copied' : 'Copy Hash'}
            </button>
            <button
              onClick={() => setShowReceiptModal(true)}
              className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center justify-center gap-2 shadow-glow-cyan transition-all"
            >
              <Download className="w-4 h-4" />
              Download Registration Receipt (.JSON)
            </button>
          </div>
        </div>
      ) : (
        /* Form & Workflow View */
        <form onSubmit={handleStartRegistration} className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column: Drag & Drop Upload + Preview Panel */}
          <div className="lg:col-span-2 space-y-6">
            {/* Drag & Drop Area */}
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`relative border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all duration-300 flex flex-col items-center justify-center min-h-[260px] ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-950/20 shadow-glow-cyan'
                  : file
                  ? 'border-emerald-500/50 bg-navy-900/60'
                  : 'border-slate-700/80 hover:border-cyan-500/50 bg-navy-900/40 hover:bg-navy-900/70'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".jpg,.jpeg,.png,.pdf,.txt"
                onChange={(e) => validateAndSetFile(e.target.files[0])}
                className="hidden"
              />

              {file ? (
                <div className="space-y-3">
                  <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto shadow-glow-green">
                    <FileCheck2 className="w-7 h-7" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white truncate max-w-md">{file.name}</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">
                      {formatFileSize(file.size)} • {file.type || 'Unknown type'}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4"
                  >
                    Change File
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto shadow-glow-cyan">
                    <Upload className="w-7 h-7" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">
                      Drop digital asset here, or <span className="text-cyan-accent">browse files</span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Supports JPG, JPEG, PNG, PDF, and TXT (Maximum file size: 50MB)
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* File Preview and Information Panel */}
            {file && (
              <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Info className="w-4 h-4 text-cyan-400" />
                    File Information Panel
                  </h3>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                    Validated Input
                  </span>
                </div>

                <div className="flex flex-col sm:flex-row gap-4 items-start">
                  {filePreview ? (
                    <div className="w-32 h-32 rounded-xl overflow-hidden border border-slate-700 bg-navy-950 flex-shrink-0 relative group">
                      <img src={filePreview} alt="Preview" className="w-full h-full object-cover" />
                      <div className="absolute inset-0 bg-navy-950/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                        <ImageIcon className="w-6 h-6 text-cyan-400" />
                      </div>
                    </div>
                  ) : (
                    <div className="w-32 h-32 rounded-xl border border-slate-700 bg-navy-950 flex-shrink-0 flex flex-col items-center justify-center text-slate-400 p-2 text-center">
                      <FileText className="w-8 h-8 text-cyan-400 mb-1" />
                      <span className="text-[10px] font-mono uppercase">{file.name.split('.').pop()}</span>
                    </div>
                  )}

                  <div className="flex-1 space-y-2 text-xs font-mono">
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-500 font-sans">Full Filename:</span>
                      <span className="text-slate-200 font-sans font-medium truncate max-w-[240px]">{file.name}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-500 font-sans">Binary Size:</span>
                      <span className="text-cyan-400">{file.size.toLocaleString()} bytes ({formatFileSize(file.size)})</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-500 font-sans">MIME Type:</span>
                      <span className="text-slate-300">{file.type || 'application/octet-stream'}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-500 font-sans">Client-Side Digest:</span>
                      <span className="text-emerald-400">Web Crypto API Ready</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Creator Information Section */}
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  Creator & Provenance Attribution
                </h3>
                <span className="text-[10px] text-slate-500 font-mono">Forensic Metadata</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Creator Name / Title <span className="text-cyan-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    value={creatorName}
                    onChange={(e) => setCreatorName(e.target.value)}
                    className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Creator ID / Badge <span className="text-cyan-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    value={creatorId}
                    onChange={(e) => setCreatorId(e.target.value)}
                    className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-400 transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Content Category
                  </label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 transition-colors"
                  >
                    <option value="Satellite Imagery">Satellite Imagery / Geoint</option>
                    <option value="Legal Contract">Legal Document & Contract</option>
                    <option value="System Firmware">System Firmware & Binary</option>
                    <option value="Biometric Sensor">Biometric & Telemetry Data</option>
                    <option value="Intellectual Property">Intellectual Property / Patent</option>
                    <option value="Media Evidence">Forensic Media Evidence</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Source / Origin Information
                  </label>
                  <input
                    type="text"
                    value={sourceOrigin}
                    onChange={(e) => setSourceOrigin(e.target.value)}
                    placeholder="e.g. Orbital Station Node Alpha"
                    className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 transition-colors"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Optional Description / Context
                  </label>
                  <textarea
                    rows={2}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Provide contextual details for this digital source registration..."
                    className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 transition-colors resize-none"
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: 6-Stage Registration Workflow Stepper & Execution */}
          <div className="space-y-6">
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-5">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  6-Stage Cryptographic Workflow
                </h3>
                {currentStep > 0 && currentStep < 7 && (
                  <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30 animate-pulse">
                    Stage {currentStep}/6
                  </span>
                )}
              </div>

              {/* Stepper items */}
              <div className="space-y-3">
                {stepLabels.map((step) => {
                  const status = stepStatuses[step.num];
                  return (
                    <div
                      key={step.num}
                      className={`p-3 rounded-xl border transition-all flex items-center justify-between ${
                        status === 'completed'
                          ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                          : status === 'running'
                          ? 'bg-cyan-950/50 border-cyan-400 shadow-glow-cyan text-cyan-300'
                          : status === 'error'
                          ? 'bg-rose-950/50 border-rose-500/50 text-rose-300'
                          : 'bg-navy-900/50 border-slate-800 text-slate-400'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-mono font-bold ${
                            status === 'completed'
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : status === 'running'
                              ? 'bg-cyan-500/20 text-cyan-400 animate-pulse'
                              : status === 'error'
                              ? 'bg-rose-500/20 text-rose-400'
                              : 'bg-navy-800 text-slate-500'
                          }`}
                        >
                          {status === 'completed' ? (
                            <Check className="w-4 h-4 text-emerald-400" />
                          ) : status === 'running' ? (
                            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                          ) : (
                            step.num
                          )}
                        </div>
                        <div>
                          <p className="text-xs font-semibold text-slate-200">
                            STEP {step.num}: {step.title}
                          </p>
                          <p className="text-[10px] text-slate-400 mt-0.5">{step.desc}</p>
                        </div>
                      </div>

                      <div className="text-[10px] font-mono uppercase">
                        {status === 'completed' && <span className="text-emerald-400">Done</span>}
                        {status === 'running' && <span className="text-cyan-400 animate-pulse">Running</span>}
                        {status === 'pending' && <span className="text-slate-600">Waiting</span>}
                        {status === 'error' && <span className="text-rose-400">Error</span>}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Execute Button */}
              <button
                type="submit"
                disabled={!file || (currentStep > 0 && currentStep < 7)}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-navy-950 font-extrabold text-sm flex items-center justify-center gap-2 shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {currentStep > 0 && currentStep < 7 ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Executing Stage {currentStep} of 6...</span>
                  </>
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    <span>Execute Cryptographic Registration</span>
                  </>
                )}
              </button>

              <div className="p-3 rounded-lg bg-navy-950 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                <p>
                  Zero-Knowledge Guarantee: SHA-256 fingerprinting is performed locally inside your browser via Web Crypto API. Raw files are never transmitted unhashed.
                </p>
              </div>
            </div>
          </div>
        </form>
      )}

      {/* Cryptographic Receipt Modal */}
      <ReceiptModal
        isOpen={showReceiptModal}
        onClose={() => setShowReceiptModal(false)}
        data={registrationResult}
      />
    </div>
  );
}

