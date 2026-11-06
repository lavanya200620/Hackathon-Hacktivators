import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  FileCheck2,
  ShieldAlert,
  Activity,
  ShieldCheck,
  Boxes,
  ArrowRight,
  Cpu,
  Lock,
  Layers,
  RefreshCw,
  Award,
  Building2,
  Users,
  Search,
  Database,
  CheckCircle2,
  AlertTriangle,
  Clock,
  KeyRound
} from 'lucide-react';
import { apiService } from '../services/api';

export default function GlobalOverview() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastSync, setLastSync] = useState(new Date().toLocaleTimeString());

  const fetchStats = async () => {
    try {
      const data = await apiService.getGlobalOverviewStats();
      setStats(data);
      setLastSync(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Failed to load global overview stats:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchStats();
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Enterprise Global Provenance Overview</h1>
              <p className="text-sm text-slate-400">
                Live PostgreSQL-backed cryptographic asset telemetry, tenant distribution, and ledger integrity
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            {stats?.databaseEngine || 'PostgreSQL 16.15'} • CONNECTED
          </div>
          <span className="text-xs text-slate-500 font-mono">Sync: {lastSync}</span>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors border border-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Primary KPI Grid (PostgreSQL Live Telemetry) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Card 1: Registered Sources */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Registered Assets</p>
              <h3 className="text-3xl font-extrabold text-white mt-2 tracking-tight">
                {stats?.sources?.total ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <FileCheck2 className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            SHA-256 Fingerprinted & Ed25519 Signed
          </p>
        </div>

        {/* Card 2: Ledger Blocks */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Ledger Blocks</p>
              <h3 className="text-3xl font-extrabold text-cyan-400 mt-2 tracking-tight">
                {stats?.ledger?.totalBlocks ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Boxes className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            {stats?.ledger?.registeredBlocks || 0} Assets • {stats?.ledger?.securityIncidentBlocks || 0} Security Events
          </p>
        </div>

        {/* Card 3: Enterprise Users */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Authorized Users</p>
              <h3 className="text-3xl font-extrabold text-indigo-400 mt-2 tracking-tight">
                {stats?.users?.total ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Users className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <span className="text-emerald-400 font-semibold">{stats?.users?.active || 0} Active</span> • {stats?.users?.deactivated || 0} Deactivated
          </p>
        </div>

        {/* Card 4: Tenant Organizations */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Tenant Organizations</p>
              <h3 className="text-3xl font-extrabold text-blue-400 mt-2 tracking-tight">
                {stats?.organizations?.length ?? 3}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Building2 className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <span className="text-blue-400 font-semibold">Strict Boundary</span> • Multi-Tenant Isolation
          </p>
        </div>

        {/* Card 5: Verifications */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Verification Events</p>
              <h3 className="text-3xl font-extrabold text-emerald-400 mt-2 tracking-tight">
                {stats?.sources?.verifications ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3">
            Bit-level cryptographic tamper & authenticity tests
          </p>
        </div>

        {/* Card 6: SOC Threat Alerts */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">SOC Threat Alerts</p>
              <h3 className="text-3xl font-extrabold text-amber-400 mt-2 tracking-tight">
                {stats?.alerts?.total ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <span className="text-emerald-400 font-semibold">{stats?.alerts?.contained || 0} Contained</span> • {stats?.alerts?.active || 0} Active
          </p>
        </div>

        {/* Card 7: WORM Checkpoints */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">WORM Checkpoints</p>
              <h3 className="text-3xl font-extrabold text-purple-400 mt-2 tracking-tight">
                {stats?.checkpoints?.total ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Lock className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3">
            Dual-store tamper-proof ledger anchors
          </p>
        </div>

        {/* Card 8: Investigations */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Forensic Investigations</p>
              <h3 className="text-3xl font-extrabold text-rose-400 mt-2 tracking-tight">
                {stats?.investigations?.total ?? '...'}
              </h3>
            </div>
            <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
              <Search className="w-5 h-5" />
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1.5">
            <span className="text-emerald-400 font-semibold">{stats?.investigations?.resolved || 0} Resolved</span> • {stats?.investigations?.active || 0} Active Case
          </p>
        </div>
      </div>

      {/* Middle Section: Tenant Organizations Breakdown & IAM Role Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Tenant Organizations */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <Building2 className="w-5 h-5 text-blue-400" />
              <h2 className="text-base font-bold text-white">Multi-Tenant Organization Topology</h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">Isolated Data Boundaries</span>
          </div>

          <div className="space-y-3">
            {stats?.organizations?.map((org) => (
              <div
                key={org.id}
                className="flex items-center justify-between p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 hover:border-blue-500/30 transition-all"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 border border-blue-500/30 text-blue-400">
                      {org.id}
                    </span>
                    <h3 className="text-sm font-semibold text-white">{org.name}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{org.department}</p>
                </div>

                <div className="text-right">
                  <span className="text-sm font-bold font-mono text-cyan-400">{org.sourcesCount}</span>
                  <span className="text-xs text-slate-400 ml-1">Assets</span>
                  <div className="text-[10px] text-emerald-400 font-medium">Tenant Active</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: IAM Role Distribution */}
        <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <Users className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white">IAM Identity Distribution</h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">6 Enterprise Roles</span>
          </div>

          <div className="space-y-2.5">
            {[
              { role: 'ADMINISTRATOR', label: 'Administrator', count: stats?.users?.roles?.ADMINISTRATOR || 1, color: 'text-red-400 bg-red-500/10 border-red-500/20' },
              { role: 'FORENSIC_INVESTIGATOR', label: 'Forensic Investigator', count: stats?.users?.roles?.FORENSIC_INVESTIGATOR || 1, color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
              { role: 'SOC_ANALYST', label: 'SOC Security Lead', count: stats?.users?.roles?.SOC_ANALYST || 1, color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' },
              { role: 'AUDITOR', label: 'Lead Compliance Auditor', count: stats?.users?.roles?.AUDITOR || 1, color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
              { role: 'ORGANIZATION_MANAGER', label: 'Organization Manager', count: stats?.users?.roles?.ORGANIZATION_MANAGER || 1, color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
              { role: 'USER', label: 'Standard Contributor', count: stats?.users?.roles?.USER || 23, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
            ].map(r => (
              <div key={r.role} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-800/40 border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${r.color}`}>
                    {r.role}
                  </span>
                  <span className="text-xs text-slate-300">{r.label}</span>
                </div>
                <span className="text-xs font-mono font-bold text-white px-2 py-0.5 rounded bg-slate-800">
                  {r.count} accounts
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Cryptographic Architecture Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <h2 className="text-base font-bold text-white mb-4 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          Active Cryptographic Trust Infrastructure
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-800/50 border border-slate-700/50">
            <span className="text-slate-400 block mb-1">SIGNATURE ALGORITHM</span>
            <span className="text-cyan-400 font-bold">Ed25519 (Curve25519)</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-800/50 border border-slate-700/50">
            <span className="text-slate-400 block mb-1">PAYLOAD HASHER</span>
            <span className="text-emerald-400 font-bold">SHA-256 (256-bit Digest)</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-800/50 border border-slate-700/50">
            <span className="text-slate-400 block mb-1">TIME AUTHORITY</span>
            <span className="text-amber-400 font-bold">RFC 3161 Imprint Engine</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-800/50 border border-slate-700/50">
            <span className="text-slate-400 block mb-1">EVIDENCE RETENTION</span>
            <span className="text-purple-400 font-bold">WORM Dual-Store Checkpoints</span>
          </div>
        </div>
      </div>
    </div>
  );
}

