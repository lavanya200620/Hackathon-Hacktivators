import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import {
  Search,
  Bell,
  Radio,
  Clock,
  Shield,
  CheckCircle,
  AlertTriangle,
  ExternalLink,
  ChevronRight,
  Database
} from 'lucide-react';
import { apiService } from '../../services/api';

export default function TopNav({ collapsed }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [backendOnline, setBackendOnline] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  // Update clock every second
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Check backend health
  useEffect(() => {
    async function check() {
      const res = await apiService.checkHealth();
      setBackendOnline(res.online);
    }
    check();
  }, [location.pathname]);

  // Derive breadcrumb from pathname
  const pathnames = location.pathname.split('/').filter(x => x);
  const pageTitleMap = {
    '': 'Dashboard',
    'register': 'Register Digital Source',
    'verify': 'Verify Authenticity',
    'compare': 'Digital Tamper Analysis',
    'history': 'Provenance Trail',
    'ledger': 'Audit Ledger',
    'reports': 'Forensic Reports',
    'settings': 'Platform Settings',
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      // If it looks like a Source ID or hash, navigate to verify or history
      navigate(`/history?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <header
      className={`sticky top-0 z-30 h-16 border-b border-background-border bg-navy-950/80 backdrop-blur-xl transition-all duration-300 flex items-center justify-between px-6 ${
        collapsed ? 'ml-20' : 'ml-64'
      }`}
    >
      {/* Left: Breadcrumbs & Current Page Title */}
      <div className="flex items-center gap-2 text-sm">
        <Link to="/" className="text-slate-400 hover:text-cyan-accent transition-colors flex items-center gap-1.5">
          <Shield className="w-4 h-4 text-cyan-accent" />
          <span className="hidden sm:inline">SourceMark</span>
        </Link>
        <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
        <span className="font-semibold text-slate-100">
          {pageTitleMap[pathnames[0] || ''] || 'Overview'}
        </span>
      </div>

      {/* Center: Quick Search Bar */}
      <form onSubmit={handleSearchSubmit} className="hidden md:flex items-center max-w-md w-72 lg:w-96 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search by Source ID, filename, or SHA-256..."
          className="w-full bg-navy-900/90 border border-slate-700/60 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/80 focus:ring-1 focus:ring-cyan-400/40 transition-all font-mono"
        />
        {searchQuery && (
          <button
            type="submit"
            className="absolute right-2 px-1.5 py-0.5 text-[10px] bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/30 font-sans"
          >
            Enter
          </button>
        )}
      </form>

      {/* Right: Forensic Timestamp, Demo/Live Status, and Notification Bell */}
      <div className="flex items-center gap-4">
        {/* Real-time Forensic Clock */}
        <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-400 font-mono bg-navy-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime.toISOString().replace('T', ' ').substring(0, 19)} UTC</span>
        </div>

        {/* Backend Connectivity Status Pill */}
        <div
          title={backendOnline ? "Connected to backend API at 127.0.0.1:8000" : "Running in client-side cryptographic simulation mode (Backend Offline)"}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border cursor-help ${
            backendOnline
              ? 'bg-emerald-950/70 border-emerald-500/30 text-emerald-300'
              : 'bg-cyan-950/60 border-cyan-500/30 text-cyan-300'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
          <span>{backendOnline ? 'API Connected' : 'Demo Mode (Offline)'}</span>
        </div>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg text-slate-400 hover:text-white hover:bg-navy-800 transition-colors focus:outline-none"
            aria-label="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-cyan-400 ring-2 ring-navy-950" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-navy-900 border border-slate-700/80 shadow-2xl p-4 text-xs z-50 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <span className="font-semibold text-slate-200">Forensic Alerts</span>
                <span className="text-[10px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                  2 New
                </span>
              </div>
              <div className="space-y-2.5">
                <div className="p-2.5 rounded-lg bg-navy-800/80 border border-emerald-500/20">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-semibold mb-0.5">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Ledger Hash Chain Validated</span>
                  </div>
                  <p className="text-slate-300 text-[11px]">All 6 blocks verified against Ed25519 root authority.</p>
                  <span className="text-[10px] text-slate-500 font-mono mt-1 block">12 mins ago</span>
                </div>
                <div className="p-2.5 rounded-lg bg-navy-800/80 border border-rose-500/20">
                  <div className="flex items-center gap-1.5 text-rose-400 font-semibold mb-0.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Tamper Anomaly Detected</span>
                  </div>
                  <p className="text-slate-300 text-[11px]">Source SRC-98214 hash mismatch in inspection gate #2.</p>
                  <span className="text-[10px] text-slate-500 font-mono mt-1 block">1 hr ago</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

