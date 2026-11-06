import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import {
  Search,
  Bell,
  Clock,
  Shield,
  CheckCircle,
  AlertTriangle,
  ChevronRight,
  KeyRound,
  LogOut,
  User,
  ShieldAlert,
  ChevronDown
} from 'lucide-react';
import { apiService } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

export default function TopNav({ collapsed }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, role, switchRole, logout, ROLE_LABELS, ROLE_BADGE_COLORS, ENTERPRISE_ROLES } = useAuth();

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

  const pathnames = location.pathname.split('/').filter(x => x);
  const pageTitleMap = {
    '': 'Dashboard',
    'dashboard': 'Enterprise Dashboard',
    'register': 'Register Digital Source',
    'verify': 'Verify Authenticity',
    'compare': 'Digital Tamper Analysis',
    'history': 'Provenance Trail',
    'ledger': 'Audit Ledger',
    'reports': 'Forensic Reports',
    'forensic-intelligence': 'Forensic Intelligence Score',
    'qr-verification': 'QR Authenticity Verification',
    'evidence-certificates': 'Digital Evidence Certificates',
    'batch-verification': 'Batch File Verification',
    'metadata-intelligence': 'Metadata Intelligence',
    'checkpoints': 'Rollback Protection & Checkpoints',
    'version-history': 'Legitimate Re-saves & Versions',
    'key-security': 'Key Security Centre',
    'learn': 'Learn & Explore Centre',
    'security-risks': 'Security & Risk Awareness',
    'settings': 'Platform Settings',
    'login': 'Enterprise Authentication',
    'unauthorized': 'Access Restricted',
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/history?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
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
          {pageTitleMap[pathnames[0] || ''] || 'Dashboard'}
          {pathnames[1] ? ` • ${pathnames[1].toUpperCase()}` : ''}
        </span>
      </div>

      {/* Center: Search Bar */}
      <form onSubmit={handleSearchSubmit} className="hidden md:flex items-center max-w-md w-64 lg:w-80 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search Source ID, hash, file..."
          className="w-full bg-navy-900/90 border border-slate-700/60 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/80 transition-all font-mono"
        />
      </form>

      {/* Right Controls: Authenticated Identity, Clock, Status, Profile */}
      <div className="flex items-center gap-3">
        {/* Authenticated Role Clearance Badge (Read-Only) */}
        {user && (
          <div className="flex items-center gap-2">
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-semibold select-none ${
                ROLE_BADGE_COLORS[role] || 'bg-slate-800 border-slate-700 text-slate-200'
              }`}
              title={`Authenticated Identity: ${user.name || user.email} (${role})`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span className="hidden sm:inline font-mono uppercase text-[11px]">
                {role ? role.replace('_', ' ') : 'USER'}
              </span>
            </div>
            <div className="hidden md:block text-right">
              <div className="text-xs font-semibold text-white leading-tight">{user.name || user.email}</div>
              <div className="text-[10px] text-slate-400 font-mono leading-tight">{user.organizationId || 'ORG-01'}</div>
            </div>
          </div>
        )}

        {/* Real-time Forensic Clock */}
        <div className="hidden xl:flex items-center gap-1.5 text-xs text-slate-400 font-mono bg-navy-900/60 px-2.5 py-1 rounded-lg border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime.toISOString().replace('T', ' ').substring(0, 19)} UTC</span>
        </div>

        {/* Backend Status Pill */}
        <div
          title={backendOnline ? "Enterprise Backend Online (Port 8000)" : "Client-side cryptographic engine engaged (Backend Offline)"}
          className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
            backendOnline
              ? 'bg-emerald-950/70 border-emerald-500/30 text-emerald-300'
              : 'bg-cyan-950/60 border-cyan-500/30 text-cyan-300'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
          <span>{backendOnline ? 'Node/FastAPI Online' : 'Cryptographic Engine'}</span>
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
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-navy-900 border border-slate-700/80 shadow-2xl p-4 text-xs z-50">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <span className="font-semibold text-slate-200">Security & Provenance Alerts</span>
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
                  <p className="text-slate-300 text-[11px]">All blocks verified against root authority.</p>
                </div>
                <div className="p-2.5 rounded-lg bg-navy-800/80 border border-rose-500/20">
                  <div className="flex items-center gap-1.5 text-rose-400 font-semibold mb-0.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Key Compromise Protection Active</span>
                  </div>
                  <p className="text-slate-300 text-[11px]">Revoked key blacklist enforced on signing pipeline.</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Logout Button */}
        {user && (
          <button
            onClick={handleLogout}
            title="Sign Out"
            className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        )}
      </div>
    </header>
  );
}
