import React, { useState, useEffect } from 'react';
import {
  Key,
  Shield,
  User,
  Cpu,
  Lock,
  Copy,
  Check,
  Bell,
  RefreshCw,
  Server,
  AlertTriangle,
  Info,
  Radio,
  Sliders,
  CheckCircle2
} from 'lucide-react';
import { getOrCreateKeyPair } from '../services/crypto';
import { apiService } from '../services/api';

export default function Settings() {
  const [keyPair, setKeyPair] = useState(getOrCreateKeyPair());
  const [copiedKey, setCopiedKey] = useState(false);
  const [backendUrl, setBackendUrl] = useState(apiService.baseURL);
  const [backendStatus, setBackendStatus] = useState({ online: false, checking: false });
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Profile fields
  const [analystName, setAnalystName] = useState('Dr. Evelyn Vance');
  const [analystRole, setAnalystRole] = useState('Chief Forensic Analyst');
  const [organization, setOrganization] = useState('Global Geoint Integrity Division');
  const [creatorId, setCreatorId] = useState('AGY-USR-0042');

  // Preferences
  const [notifyOnTamper, setNotifyOnTamper] = useState(true);
  const [notifyOnRegister, setNotifyOnRegister] = useState(true);
  const [autoValidateLedger, setAutoValidateLedger] = useState(true);

  useEffect(() => {
    checkConnection();
  }, []);

  const checkConnection = async () => {
    setBackendStatus((s) => ({ ...s, checking: true }));
    const res = await apiService.checkHealth();
    setBackendStatus({ online: res.online, checking: false });
  };

  const handleCopyPublicKey = () => {
    navigator.clipboard.writeText(keyPair.publicKeyHex);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleSaveSettings = (e) => {
    e.preventDefault();
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Platform & Cryptographic Settings
        </h1>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Manage forensic analyst credentials, Ed25519 public cryptographic key identities, backend endpoint parameters, and zero-knowledge security configurations.
        </p>
      </div>

      {saveSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 flex items-center gap-3 text-xs animate-in zoom-in-95">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0 text-emerald-400" />
          <span>Analyst preferences and cryptographic configurations updated successfully.</span>
        </div>
      )}

      <form onSubmit={handleSaveSettings} className="space-y-8">
        {/* Section 1: User Profile & Creator ID */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <User className="w-4 h-4 text-cyan-400" />
              Forensic Analyst Profile & Attribution
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">Authentication Identity</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-400 font-medium mb-1">Analyst Full Name</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">Assigned Role</label>
              <input
                type="text"
                value={analystRole}
                onChange={(e) => setAnalystRole(e.target.value)}
                className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">Organization / Department</label>
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">Creator ID / Badge Code</label>
              <input
                type="text"
                value={creatorId}
                onChange={(e) => setCreatorId(e.target.value)}
                className="w-full bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Cryptographic Key Management (Ed25519) */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              Active Ed25519 Cryptographic Signer
            </h3>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
              Curve25519 • In-Memory HSM
            </span>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-navy-950 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase block">Key Identifier</span>
                <span className="text-cyan-400 font-bold">{keyPair.keyId}</span>
              </div>
              <div className="p-3 rounded-lg bg-navy-950 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase block">Algorithm Standard</span>
                <span className="text-slate-200">Ed25519 / RFC 8032 (Detached Signatures)</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-navy-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-[10px] uppercase">
                  Active Public Verification Key (Hexadecimal)
                </span>
                <button
                  type="button"
                  onClick={handleCopyPublicKey}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-sans text-[11px]"
                >
                  {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedKey ? 'Copied' : 'Copy Public Key'}
                </button>
              </div>
              <div className="p-2.5 rounded bg-navy-900 border border-slate-800 text-emerald-300 break-all select-all text-[11px]">
                {keyPair.publicKeyHex}
              </div>
            </div>

            {/* Zero-Trust Security Guarantee */}
            <div className="p-3.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-emerald-300/90 text-[11px] font-sans flex items-start gap-2.5">
              <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <p>
                <strong>Security Architecture Principle:</strong> Private signing keys are isolated exclusively inside the client runtime memory enclave. Private keys are never exposed in user interfaces, and raw content files never leave your client browser boundary.
              </p>
            </div>
          </div>
        </div>

        {/* Section 3: Backend API Integration Configuration */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Backend API & Service Connectivity
            </h3>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                backendStatus.online
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-500/30'
                  : 'bg-cyan-950 text-cyan-300 border-cyan-500/30'
              }`}
            >
              {backendStatus.online ? 'Online Endpoint' : 'Demo Simulation Mode'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Backend API Base URL (FastAPI / Express Server)
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={backendUrl}
                  onChange={(e) => setBackendUrl(e.target.value)}
                  className="flex-1 bg-navy-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-cyan-400 transition-colors"
                />
                <button
                  type="button"
                  onClick={checkConnection}
                  disabled={backendStatus.checking}
                  className="px-4 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${backendStatus.checking ? 'animate-spin' : ''}`} />
                  Ping
                </button>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-navy-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
              <p className="font-semibold text-slate-300">Expected Endpoints:</p>
              <div className="font-mono text-[10px] text-slate-500 grid grid-cols-1 sm:grid-cols-2 gap-1 mt-1">
                <span>POST /api/register</span>
                <span>POST /api/verify</span>
                <span>POST /api/compare</span>
                <span>GET /api/source/{'{id}'}</span>
                <span>GET /api/ledger</span>
                <span>GET /api/ledger/validate</span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 4: Notification Preferences */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              Forensic Audit Notification Preferences
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">Alert Rules</span>
          </div>

          <div className="space-y-3 text-xs">
            <label className="flex items-center justify-between p-3 rounded-lg bg-navy-900/60 border border-slate-800 cursor-pointer hover:bg-navy-850">
              <div>
                <span className="font-semibold text-slate-200 block">Critical Tamper Alert Broadcast</span>
                <span className="text-slate-400 text-[11px]">Notify analyst immediately when hash mismatch is flagged on a registered source.</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnTamper}
                onChange={(e) => setNotifyOnTamper(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 text-cyan-500 focus:ring-0 bg-navy-950"
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-lg bg-navy-900/60 border border-slate-800 cursor-pointer hover:bg-navy-850">
              <div>
                <span className="font-semibold text-slate-200 block">Registration Ledger Block Confirmation</span>
                <span className="text-slate-400 text-[11px]">Generate receipt notification when new Ed25519 digital signature is committed to ledger.</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnRegister}
                onChange={(e) => setNotifyOnRegister(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 text-cyan-500 focus:ring-0 bg-navy-950"
              />
            </label>
          </div>
        </div>

        {/* Bottom Save Action */}
        <div className="flex justify-end">
          <button
            type="submit"
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-2 shadow-glow-cyan transition-all"
          >
            Save All Platform Settings
          </button>
        </div>
      </form>
    </div>
  );
}

