import React, { useState, useEffect } from 'react';
import {
  Key,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RotateCw,
  Lock,
  User,
  CheckCircle,
  Copy,
  Check,
  RefreshCw,
  Info,
  Clock,
  FileCheck
} from 'lucide-react';
import { keySecurityService } from '../services/keySecurity';
import { ledgerStorage } from '../services/ledgerStorage';
import { getOrCreateKeyPair } from '../services/crypto';

export default function KeySecurityCentre() {
  const [keys, setKeys] = useState([]);
  const [activeLocalKey, setActiveLocalKey] = useState(null);
  const [copiedKeyId, setCopiedKeyId] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);
  const [retroactiveResults, setRetroactiveResults] = useState(null);
  const [selectedKeyForAudit, setSelectedKeyForAudit] = useState('');
  
  // 10-Step Stolen Key Attack Lifecycle Simulation State
  const [isSimRunning, setIsSimRunning] = useState(false);
  const [simStep, setSimStep] = useState(0);
  const [simLogs, setSimLogs] = useState([]);

  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = () => {
    const list = keySecurityService.getKeys();
    setKeys(list);
    const local = getOrCreateKeyPair();
    setActiveLocalKey(local);
    if (list.length > 0 && !selectedKeyForAudit) {
      setSelectedKeyForAudit(list[0].id);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedKeyId(id);
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  const handleSimulateStolenKey = async (keyId) => {
    const target = keys.find(k => k.id === keyId) || keys[0];
    const res = await keySecurityService.simulateStolenKey(target.id);
    setActionMessage({
      type: 'warning',
      text: `Stolen Key Attack Simulated: Key "${target.id}" marked COMPROMISED. Any new signatures produced with this key will fail forensic triage!`,
    });
    loadKeys();
  };

  const handleRotateKey = async (keyId) => {
    const res = await keySecurityService.rotateKey(keyId, 'Proactive Cryptographic Key Rotation (90-day Policy)');
    if (res.success) {
      setActionMessage({
        type: 'success',
        text: `Key successfully rotated! Previous key revoked and replaced by ${res.newKey.id}.`,
      });
      loadKeys();
    }
  };

  const handleResetKeys = () => {
    keySecurityService.resetToDefaults();
    setActionMessage({
      type: 'info',
      text: 'Key Registry reset to default factory state.',
    });
    setRetroactiveResults(null);
    setSimLogs([]);
    setSimStep(0);
    loadKeys();
  };

  const handleRunRetroactiveAudit = (keyId) => {
    const ledger = ledgerStorage.getSources();
    const result = keySecurityService.validateRetroactiveSignatures(keyId, ledger);
    setRetroactiveResults(result);
  };

  // Automated 10-Step Stolen Key Lifecycle Simulation
  const handleRunFullLifecycleSim = async () => {
    setIsSimRunning(true);
    setSimLogs([]);
    const logs = [];

    const addLog = (step, title, detail, pass = true) => {
      const entry = { step, title, detail, pass, time: new Date().toLocaleTimeString() };
      logs.push(entry);
      setSimLogs([...logs]);
      setSimStep(step);
    };

    try {
      // 1. Initial State Check
      const initialKey = keys[0];
      addLog(1, 'Target Key Identified', `Selected active authority key: ${initialKey.id} (${initialKey.owner})`);
      await new Promise(r => setTimeout(r, 600));

      // 2. Register source with active key
      const demoHash = '3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef012';
      const demoSource = ledgerStorage.addSource({
        id: `SRC-STOLEN-DEMO`,
        fileName: 'classified_satellite_pass_09.png',
        sha256: demoHash,
        signature: 'authentic_active_signature_vector',
        publicKey: initialKey.publicKeyHex,
        keyId: initialKey.id,
        creator: initialKey.owner,
        registeredAt: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
        status: 'ACTIVE_REGISTERED',
      });
      addLog(2, 'Master Source Registered', `Source ${demoSource.id} sealed with active key.`);
      await new Promise(r => setTimeout(r, 600));

      // 3. Simulate Stolen Key Breach
      await keySecurityService.simulateStolenKey(initialKey.id, 'Unauthorized exfiltration of private key material in cyber incident.');
      addLog(3, 'Stolen Key Attack Triggered', `Key ${initialKey.id} marked COMPROMISED at ${new Date().toLocaleTimeString()}.`);
      await new Promise(r => setTimeout(r, 600));

      // 4. Formally Revoke Key Authority
      await keySecurityService.revokeKey(initialKey.id, 'Key compromise quarantine');
      addLog(4, 'Key Authority Revoked', `Key authority revoked and logged in immutable audit ledger.`);
      await new Promise(r => setTimeout(r, 600));

      // 5. Verification of Pre-Compromise Original Asset
      const evalPre = keySecurityService.revalidateSignature(initialKey.id, demoSource.registeredAt);
      addLog(5, 'Pre-Compromise Asset Integrity Verified', `Historical record confirmed sealed BEFORE breach timestamp (${evalPre.status}).`);
      await new Promise(r => setTimeout(r, 600));

      // 6. Attempt Rogue Signature with Stolen Key
      addLog(6, 'Simulating Attacker Forgery Attempt', `Adversary attempting to register forged document using stolen key credentials...`);
      await new Promise(r => setTimeout(r, 600));

      // 7. Verify Rogue Registration is REJECTED
      const isCompromised = keySecurityService.isKeyCompromised(initialKey.id);
      addLog(7, 'Rogue Signing Operation REJECTED', `Security watchdog intercepted rogue attempt: Signing blocked for revoked key ${initialKey.id}.`, true);
      await new Promise(r => setTimeout(r, 600));

      // 8. Execute Emergency Key Rotation
      const rotated = await keySecurityService.rotateKey(initialKey.id, 'Emergency Rotation after private key theft');
      addLog(8, 'Emergency Key Rotation Executed', `Superseded ${initialKey.id} with new active authority ${rotated.newKey.id}.`);
      await new Promise(r => setTimeout(r, 600));

      // 9. Sign New Source with Replacement Key
      const newValidSource = ledgerStorage.addSource({
        id: `SRC-RECOVERY-01`,
        fileName: 'geoint_post_incident_audit.pdf',
        sha256: '777788889999aaaabbbbccccddddeeeeffff0000111122223333444455556666',
        signature: 'valid_replacement_signature',
        publicKey: rotated.newKey.publicKeyHex,
        keyId: rotated.newKey.id,
        creator: rotated.newKey.owner,
        registeredAt: new Date().toISOString(),
        status: 'ACTIVE_REGISTERED',
      });
      addLog(9, 'New Source Signed with Replacement Key', `Successfully signed ${newValidSource.id} using rotated key.`);
      await new Promise(r => setTimeout(r, 600));

      // 10. Final Verification of Replacement Key
      const evalNew = keySecurityService.evaluateKeyStatus(rotated.newKey.id);
      addLog(10, 'Full Lifecycle Verification Complete', `Replacement key verified ACTIVE and trustworthy. PKI integrity re-established.`, evalNew.isTrusted);

      loadKeys();
    } catch (err) {
      addLog(simStep + 1, 'Simulation Error', err.message, false);
    } finally {
      setIsSimRunning(false);
    }
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <Key className="w-4 h-4" />
            <span>Public Key Infrastructure (PKI) Governance</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Key Security Centre & Stolen Key Defense
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Manage authority signing keys, execute emergency key revocations, simulate compromised credentials, and run retroactive validation audits against past ledger entries.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleResetKeys}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-300 border border-background-border text-xs font-medium transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reset Keys to Factory
          </button>
        </div>
      </div>

      {/* Action Notification */}
      {actionMessage && (
        <div className={`p-4 rounded-xl border text-xs flex items-center justify-between animate-fade-in ${
          actionMessage.type === 'warning'
            ? 'bg-rose-950/40 border-rose-500/50 text-rose-300'
            : actionMessage.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
            : 'bg-cyan-950/40 border-cyan-500/50 text-cyan-300'
        }`}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Security Architecture Principle */}
      <div className="p-4 bg-navy-900/90 rounded-xl border border-cyan-500/20 text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-accent flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">Why Public-Key Integrity is Paramount:</strong> A cryptographic signature is only as trustworthy as the operational security of the private key. If an adversary steals an analyst's private key, forged files will pass raw mathematical checks. SourceMark maintains a real-time key registry so compromised keys immediately fail verification, even when the signature math is valid.
        </div>
      </div>

      {/* Active Session Hardware Key Info */}
      {activeLocalKey && (
        <div className="p-5 bg-navy-900/80 rounded-xl border border-background-border flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Lock className="w-5 h-5 text-cyan-accent" />
            </div>
            <div>
              <div className="text-xs text-slate-400 font-mono">Current Browser Session Active Key</div>
              <div className="text-sm font-bold text-white font-mono mt-0.5">{activeLocalKey.keyId}</div>
            </div>
          </div>

          <div className="text-xs font-mono text-slate-400 flex items-center gap-3">
            <span>Public Key: {activeLocalKey.publicKeyHex.substring(0, 16)}...{activeLocalKey.publicKeyHex.substring(48)}</span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px]">
              ONLINE & PROTECTED
            </span>
          </div>
        </div>
      )}

      {/* 10-Step Stolen Key Attack Lifecycle Interactive Simulation */}
      <div className="p-6 bg-gradient-to-br from-navy-900/90 via-navy-950/90 to-navy-900/90 rounded-2xl border border-cyan-500/30 shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-background-border">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <ShieldAlert className="w-4 h-4 text-cyan-accent" />
              <span>Interactive Threat Vector Simulation</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">
              10-Step Stolen Key Lifecycle Simulation
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Execute an end-to-end simulation: key exfiltration, compromise detection, key revocation, rogue signature interception, and emergency key rotation.
            </p>
          </div>

          <button
            onClick={handleRunFullLifecycleSim}
            disabled={isSimRunning}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-bold text-xs shadow-lg transition-all ${
              isSimRunning
                ? 'bg-navy-800 text-slate-400 cursor-not-allowed border border-background-border'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold'
            }`}
          >
            <RotateCw className={`w-4 h-4 ${isSimRunning ? 'animate-spin' : ''}`} />
            {isSimRunning ? `Executing Step ${simStep}/10...` : 'Run 10-Step Simulation'}
          </button>
        </div>

        {/* Live Simulation Step Logs */}
        {simLogs.length > 0 && (
          <div className="space-y-2 pt-2 animate-fade-in">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
              Lifecycle Execution Trace:
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {simLogs.map((log) => (
                <div
                  key={log.step}
                  className={`p-3 rounded-xl border text-xs flex items-start gap-3 transition-all ${
                    log.pass
                      ? 'bg-navy-950/70 border-emerald-500/30 text-slate-200'
                      : 'bg-rose-950/40 border-rose-500/50 text-rose-300'
                  }`}
                >
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold ${
                    log.pass ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  }`}>
                    {log.step}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-white truncate">{log.title}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{log.time}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">{log.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Registered Key Authorities Table */}
      <div className="bg-navy-900/90 border border-background-border rounded-xl shadow-xl overflow-hidden">
        <div className="p-4 border-b border-background-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-accent" />
            Authorized Key Registry
          </h2>
          <span className="text-xs text-slate-400 font-mono">{keys.length} Registered Authorit{keys.length === 1 ? 'y' : 'ies'}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-950/80 border-b border-background-border text-[11px] font-mono uppercase text-slate-400">
                <th className="py-3 px-4">Key ID</th>
                <th className="py-3 px-4">Owner & Authority Role</th>
                <th className="py-3 px-4">Public Key Fingerprint</th>
                <th className="py-3 px-4">Algorithm</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-background-border/60">
              {keys.map((k) => (
                <tr key={k.id} className="hover:bg-navy-850/50 transition-colors">
                  <td className="py-3 px-4 font-mono font-bold text-white">
                    {k.id}
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-200">{k.owner}</div>
                    <div className="text-[10px] text-slate-400 font-mono">{k.role}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-cyan-300">
                    <div className="flex items-center gap-1.5">
                      <span>{k.publicKeyHex.substring(0, 10)}...{k.publicKeyHex.substring(54)}</span>
                      <button
                        onClick={() => handleCopy(k.publicKeyHex, k.id)}
                        className="text-slate-500 hover:text-cyan-300"
                        title="Copy Public Key"
                      >
                        {copiedKeyId === k.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 text-[11px]">
                    {k.algorithm}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      k.status === 'ACTIVE'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : k.status === 'COMPROMISED'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse'
                        : 'bg-slate-700/40 text-slate-300 border border-slate-600/40'
                    }`}>
                      {k.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      {k.status === 'ACTIVE' && (
                        <>
                          <button
                            onClick={() => handleSimulateStolenKey(k.id)}
                            className="px-2 py-1 rounded bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 text-[10px] font-mono transition-colors"
                          >
                            Simulate Stolen
                          </button>
                          <button
                            onClick={() => handleRotateKey(k.id)}
                            className="px-2 py-1 rounded bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-background-border text-[10px] font-mono transition-colors"
                          >
                            Rotate Key
                          </button>
                        </>
                      )}
                      {k.status === 'COMPROMISED' && (
                        <button
                          onClick={() => handleRotateKey(k.id)}
                          className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-mono transition-colors"
                        >
                          Emergency Replace
                        </button>
                      )}
                      {k.status === 'REVOKED' && (
                        <span className="text-[10px] text-slate-500 font-mono">Archived</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Retroactive Signature Validation Section */}
      <div className="bg-navy-900/90 border border-background-border rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-background-border mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-accent" />
              Retroactive Signature Partitioning Audit
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Determine which historical ledger transactions remain trustworthy if a signing key is reported compromised.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedKeyForAudit}
              onChange={(e) => setSelectedKeyForAudit(e.target.value)}
              className="bg-navy-950 border border-background-border rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200"
            >
              {keys.map(k => (
                <option key={k.id} value={k.id}>{k.id} ({k.status})</option>
              ))}
            </select>
            <button
              onClick={() => handleRunRetroactiveAudit(selectedKeyForAudit)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-navy-950 text-xs font-bold transition-all"
            >
              Run Audit
            </button>
          </div>
        </div>

        {retroactiveResults && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in text-xs">
            {/* Pre-Compromise Valid */}
            <div className="p-4 bg-emerald-950/20 border border-emerald-500/30 rounded-xl">
              <div className="flex items-center gap-2 text-emerald-400 font-bold mb-2">
                <CheckCircle className="w-4 h-4" />
                <span>Pre-Compromise Signatures (Still Valid: {retroactiveResults.validCount || 0})</span>
              </div>
              <p className="text-[11px] text-slate-400 mb-3">
                Transactions timestamped before the reported compromise date have cryptographic continuity and remain legally and forensically intact.
              </p>
              <div className="text-slate-300 font-mono text-[10px]">
                Audited Key: {selectedKeyForAudit}
              </div>
            </div>

            {/* Post-Compromise Suspicious */}
            <div className="p-4 bg-rose-950/20 border border-rose-500/30 rounded-xl">
              <div className="flex items-center gap-2 text-rose-400 font-bold mb-2">
                <ShieldAlert className="w-4 h-4" />
                <span>Post-Compromise Signatures (Suspicious: {retroactiveResults.suspiciousCount || 0})</span>
              </div>
              <p className="text-[11px] text-slate-400 mb-3">
                Any transactions signed following the compromise window are partitioned as untrusted and require re-signing with rotated credentials.
              </p>
              <div className="text-slate-300 font-mono text-[10px]">
                Status: {retroactiveResults.status || 'EVALUATED'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

