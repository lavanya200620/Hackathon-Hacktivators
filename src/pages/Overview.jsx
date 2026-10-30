import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  FileCheck2,
  ShieldAlert,
  HelpCircle,
  Activity,
  FilePlus2,
  ShieldCheck,
  GitCompare,
  Boxes,
  ArrowRight,
  Cpu,
  Lock,
  Layers,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts';
import StatCard from '../components/common/StatCard';
import StatusBadge from '../components/common/StatusBadge';
import { apiService } from '../services/api';
import { ledgerStorage } from '../services/ledgerStorage';

export default function Overview() {
  const [stats, setStats] = useState(ledgerStorage.getStats());
  const [ledgerBlocks, setLedgerBlocks] = useState(ledgerStorage.getLedgerBlocks());
  const [sources, setSources] = useState(ledgerStorage.getSources());
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setIsRefreshing(true);
    const data = await apiService.getDashboardStats();
    setStats(data);
    const blocks = await apiService.getLedger();
    setLedgerBlocks(blocks.blocks || ledgerStorage.getLedgerBlocks());
    setSources(ledgerStorage.getSources());
    setTimeout(() => setIsRefreshing(false), 300);
  };

  // Pie chart distribution data
  const distributionData = [
    { name: 'Original (Verified)', value: 42, color: '#10B981' },
    { name: 'Edited (Tampered)', value: stats.editedDetected || 4, color: '#EF4444' },
    { name: 'Unknown (Unregistered)', value: stats.unknownDetected || 9, color: '#F59E0B' },
  ];

  // Timeline verification activity
  const timelineData = [
    { time: '10/24', registrations: 4, verifications: 12 },
    { time: '10/25', registrations: 6, verifications: 18 },
    { time: '10/26', registrations: 5, verifications: 15 },
    { time: '10/27', registrations: 9, verifications: 28 },
    { time: '10/28', registrations: 7, verifications: 22 },
    { time: '10/29', registrations: 11, verifications: 35 },
    { time: '10/30', registrations: 8, verifications: 29 },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Forensic Intelligence Active</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Digital Trust & Provenance Intelligence
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Monitor content authenticity, track cryptographic provenance and detect unauthorized modifications in real-time.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadDashboardData}
            disabled={isRefreshing}
            className="px-3.5 py-2 rounded-xl border border-slate-700 bg-navy-900 hover:bg-navy-800 text-slate-300 text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isRefreshing ? 'Syncing...' : 'Sync Data'}</span>
          </button>
          <Link
            to="/register"
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-2 shadow-glow-cyan transition-all"
          >
            <FilePlus2 className="w-4 h-4" />
            <span>Register Content</span>
          </Link>
        </div>
      </div>

      {/* 4 Primary Statistics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
        <StatCard
          title="Total Registered Files"
          value={stats.totalRegistered || sources.length}
          icon={FileCheck2}
          color="cyan"
          trend="+14% this week"
          description="Master files secured with SHA-256 and Ed25519 digital signatures."
        />
        <StatCard
          title="Total Verification Checks"
          value={stats.totalVerifications || 41}
          icon={Activity}
          color="blue"
          trend="+28% inspection volume"
          description="Cryptographic integrity queries processed across all nodes."
        />
        <StatCard
          title="Edited Files Detected"
          value={stats.editedDetected || 4}
          icon={ShieldAlert}
          color="red"
          trend="4 critical anomalies"
          trendType="down"
          description="Unauthorized alterations and pixel bitstream modifications caught."
        />
        <StatCard
          title="Unknown Files"
          value={stats.unknownDetected || 9}
          icon={HelpCircle}
          color="amber"
          trend="Unregistered inputs"
          description="Scanned files without any recognized provenance lineage."
        />
      </div>

      {/* Quick Actions Panel */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            Forensic Quick Actions
          </h2>
          <span className="text-xs text-slate-500 font-mono">Workflow Shortcuts</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <Link
            to="/register"
            className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 hover:border-cyan-500/40 hover:bg-navy-850 transition-all group flex items-start gap-3.5"
          >
            <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 group-hover:bg-cyan-500/20 transition-colors">
              <FilePlus2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200 group-hover:text-cyan-accent flex items-center gap-1">
                Register New File
                <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Hash and digitally sign master asset</p>
            </div>
          </Link>

          <Link
            to="/verify"
            className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 hover:border-emerald-500/40 hover:bg-navy-850 transition-all group flex items-start gap-3.5"
          >
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 group-hover:bg-emerald-500/20 transition-colors">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200 group-hover:text-emerald-400 flex items-center gap-1">
                Verify a File
                <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Validate signature and authenticity</p>
            </div>
          </Link>

          <Link
            to="/compare"
            className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 hover:border-blue-500/40 hover:bg-navy-850 transition-all group flex items-start gap-3.5"
          >
            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 group-hover:bg-blue-500/20 transition-colors">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200 group-hover:text-blue-400 flex items-center gap-1">
                Compare Files
                <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Side-by-side pixel & tamper diff</p>
            </div>
          </Link>

          <Link
            to="/ledger"
            className="p-4 rounded-xl bg-navy-900/80 border border-slate-800 hover:border-indigo-500/40 hover:bg-navy-850 transition-all group flex items-start gap-3.5"
          >
            <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 group-hover:bg-indigo-500/20 transition-colors">
              <Boxes className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200 group-hover:text-indigo-400 flex items-center gap-1">
                View Audit Ledger
                <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Inspect hash-chained block records</p>
            </div>
          </Link>
        </div>
      </div>

      {/* Analytics Grid: Verification Distribution (Doughnut) & Activity Timeline (Area) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Verification Distribution Doughnut */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-800/80">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
                Verification Distribution
              </h3>
              <span className="text-[11px] text-cyan-400 font-mono">Live Proportions</span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Breakdown of forensic outcomes evaluated across all registered digital sources.
            </p>
          </div>

          <div className="h-56 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distributionData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {distributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0B132B" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D152B',
                    borderColor: 'rgba(56, 189, 248, 0.3)',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '12px',
                    boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            {/* Center metric */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-extrabold text-white font-mono">55</span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">Checked</span>
            </div>
          </div>

          {/* Legend */}
          <div className="space-y-2 mt-4 pt-4 border-t border-slate-800">
            {distributionData.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-300">{item.name}</span>
                </div>
                <span className="font-mono font-bold text-slate-200">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Verification Activity Timeline */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-800/80">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
                Provenance & Verification Activity Timeline
              </h3>
              <div className="flex items-center gap-3 text-[11px] font-mono">
                <span className="flex items-center gap-1 text-cyan-400">
                  <span className="w-2 h-2 rounded bg-cyan-400" /> Verifications
                </span>
                <span className="flex items-center gap-1 text-indigo-400">
                  <span className="w-2 h-2 rounded bg-indigo-400" /> Registrations
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Chronological log of registration cryptographic events versus incoming authenticity requests.
            </p>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorVerif" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#00F0FF" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorReg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366F1" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#6366F1" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D152B',
                    borderColor: 'rgba(56, 189, 248, 0.3)',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="verifications" stroke="#00F0FF" strokeWidth={2} fillOpacity={1} fill="url(#colorVerif)" />
                <Area type="monotone" dataKey="registrations" stroke="#6366F1" strokeWidth={2} fillOpacity={1} fill="url(#colorReg)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800">
            <span>Peak Verification Rate: <strong>35 events/hr</strong></span>
            <span className="text-emerald-400 font-mono">0.02ms Average Cryptographic Latency</span>
          </div>
        </div>
      </div>

      {/* Section: Recent Activity & System Cryptographic Integrity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity List */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Recent Forensic Activity
            </h3>
            <Link to="/history" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              View All History <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-3">
            {ledgerBlocks.slice(-5).reverse().map((block) => (
              <div
                key={block.id}
                className="p-3.5 rounded-xl bg-navy-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-2 rounded-lg bg-navy-850 border border-slate-700/60 text-slate-300 flex-shrink-0">
                    <Boxes className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-slate-200 truncate">{block.title}</p>
                    <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-400 font-mono">
                      <span>{block.id}</span>
                      <span>•</span>
                      <span>{new Date(block.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                  </div>
                </div>

                <div className="flex-shrink-0">
                  <StatusBadge status={block.status} size="sm" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* System Integrity Card */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                System Integrity
              </h3>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                OPTIMAL
              </span>
            </div>

            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-navy-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-400">Ledger Hash Chaining</span>
                  <span className="text-emerald-400 font-mono font-semibold">100% Intact</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-navy-800 overflow-hidden">
                  <div className="h-full bg-emerald-400 rounded-full w-full" />
                </div>
                <p className="text-[10px] text-slate-500 mt-1 font-mono">
                  All blocks cryptographically linked via SHA-256 Merkle root.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-navy-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-400">Ed25519 Cryptographic Service</span>
                  <span className="text-cyan-400 font-mono font-semibold">Operational</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-navy-800 overflow-hidden">
                  <div className="h-full bg-cyan-400 rounded-full w-full" />
                </div>
                <p className="text-[10px] text-slate-500 mt-1 font-mono">
                  Curve25519 high-speed asymmetric signing engine active.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-navy-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-400">Zero-Knowledge Fingerprinting</span>
                  <span className="text-blue-400 font-mono font-semibold">Enforced</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-1 font-mono">
                  Raw file payloads never leave client boundary; hashes only.
                </p>
              </div>
            </div>
          </div>

          <Link
            to="/ledger"
            className="mt-4 w-full py-2.5 rounded-xl border border-cyan-500/30 bg-navy-850 hover:bg-navy-800 text-cyan-300 font-semibold text-xs flex items-center justify-center gap-2 transition-all shadow-glow-cyan/20"
          >
            <Boxes className="w-4 h-4 text-cyan-400" />
            Inspect Chain & Run Ledger Audit
          </Link>
        </div>
      </div>
    </div>
  );
}

