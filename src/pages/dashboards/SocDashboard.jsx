import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { workflowService } from '../../services/workflowService';
import { keySecurityService } from '../../services/keySecurity';
import { ledgerStorage } from '../../services/ledgerStorage';
import {
  Activity,
  ShieldAlert,
  Radio,
  AlertTriangle,
  Lock,
  CheckCircle2,
  KeyRound,
  RefreshCw,
  ArrowRight,
  Zap,
  Slash
} from 'lucide-react';

export default function SocDashboard() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState('ALL');
  const [containmentNotice, setContainmentNotice] = useState('');

  useEffect(() => {
    loadAlerts();
  }, []);

  const loadAlerts = async () => {
    const list = await workflowService.getAlerts();
    setAlerts(list);
  };

  const handleContain = async (alertId, actionType = 'QUARANTINE_KEY') => {
    const contained = await workflowService.containAlert(alertId, actionType);
    
    // Log security incident to ledger
    await ledgerStorage.addLedgerBlock('SECURITY_INCIDENT', `SOC Threat Containment: ${contained.id}`, {
      alertId,
      action: actionType,
      analyst: user?.email || 'SOC_ANALYST',
    });

    setContainmentNotice(`Threat containment executed on alert ${alertId}. Incident logged to audit ledger.`);
    loadAlerts();
    setTimeout(() => setContainmentNotice(''), 4500);
  };

  const filteredAlerts = alerts.filter(a => {
    if (activeTab === 'ACTIVE') return !a.contained;
    if (activeTab === 'CONTAINED') return a.contained;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-center text-amber-400">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Security Operations Center (SOC)</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                ROLE: SOC ANALYST
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Active Watch Operator: <span className="text-slate-200 font-semibold">{user?.name}</span>. Real-time threat feeds, anomalous verification spikes, and active containment.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/forensic-intelligence"
            className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-amber-600/30 transition"
          >
            <Radio className="w-4 h-4 animate-pulse" />
            Live Integrity Stream
          </Link>
          <button
            onClick={loadAlerts}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {containmentNotice && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          <span>{containmentNotice}</span>
        </div>
      )}

      {/* Threat Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Active Threat Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {alerts.filter(a => !a.contained).length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Requiring containment or review</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Critical Alerts</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400">
            {alerts.filter(a => a.severity === 'CRITICAL').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Rollback & Revoked Key breaches</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Contained Incidents</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {alerts.filter(a => a.contained).length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Credentials quarantined & isolated</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Attack Surface Status</span>
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">DEFENDED</div>
          <div className="text-[11px] text-slate-500 mt-1">Cryptographic barriers active</div>
        </div>
      </div>

      {/* Main SOC Feed */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-sm font-bold text-white">Real-Time Threat & Anomaly Feed</h2>
            <p className="text-xs text-slate-400">Monitor unauthorized signing, rollbacks, and integrity divergences</p>
          </div>

          <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
            {['ALL', 'ACTIVE', 'CONTAINED'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                  activeTab === tab
                    ? 'bg-amber-600/30 text-amber-300 border border-amber-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-3">
          {filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`p-4 rounded-xl border transition ${
                alert.contained
                  ? 'bg-slate-950/40 border-slate-800/60 opacity-80'
                  : alert.severity === 'CRITICAL'
                  ? 'bg-red-950/20 border-red-500/30'
                  : 'bg-slate-950/80 border-slate-800'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-white">{alert.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      alert.severity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {alert.severity}
                    </span>
                    <span className="text-xs font-semibold text-slate-200">{alert.title}</span>
                  </div>

                  <p className="text-xs text-slate-400">{alert.description}</p>

                  <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono">
                    <span>Target: <strong className="text-slate-300">{alert.sourceId}</strong></span>
                    <span>Logged: {new Date(alert.timestamp).toLocaleString()}</span>
                    {alert.contained && (
                      <span className="text-emerald-400 font-semibold">
                        Contained at {new Date(alert.containedAt).toLocaleTimeString()} by {alert.containedBy}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {!alert.contained ? (
                    <>
                      <button
                        onClick={() => handleContain(alert.id, 'QUARANTINE_CREDENTIAL')}
                        className="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <Slash className="w-3.5 h-3.5" />
                        Quarantine Key
                      </button>
                      <button
                        onClick={() => handleContain(alert.id, 'ENFORCE_CONTAINMENT')}
                        className="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/30 text-amber-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        Contain
                      </button>
                    </>
                  ) : (
                    <span className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      THREAT ISOLATED
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Related SOC Navigation */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Link to="/key-security" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">Revocation Audit Ledger</div>
          <div className="text-[11px] text-slate-400">Inspect historical revocation blocks and compromised timelines</div>
        </Link>
        <Link to="/checkpoints" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">Checkpoint WORM Vault</div>
          <div className="text-[11px] text-slate-400">Detect ledger rollbacks and authority anchor divergences</div>
        </Link>
        <Link to="/key-security" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition">
          <div className="font-bold text-white text-xs mb-1">Key Security Center</div>
          <div className="text-[11px] text-slate-400">Emergency rotation and hardware protection controls</div>
        </Link>
      </div>
    </div>
  );
}

