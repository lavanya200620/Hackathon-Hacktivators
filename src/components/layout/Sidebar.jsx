import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FilePlus2,
  ShieldCheck,
  GitCompare,
  History,
  Boxes,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Fingerprint,
  Cpu,
  Key
} from 'lucide-react';
import { getOrCreateKeyPair } from '../../services/crypto';

export default function Sidebar({ collapsed, setCollapsed }) {
  const keyInfo = getOrCreateKeyPair();

  const navItems = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/register', label: 'Register File', icon: FilePlus2 },
    { to: '/verify', label: 'Verify File', icon: ShieldCheck },
    { to: '/compare', label: 'Compare Files', icon: GitCompare },
    { to: '/history', label: 'Provenance History', icon: History },
    { to: '/ledger', label: 'Audit Ledger', icon: Boxes },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside
      className={`fixed top-0 left-0 z-40 h-screen transition-all duration-300 ease-in-out border-r border-background-border bg-navy-900/95 backdrop-blur-xl flex flex-col justify-between ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Branding Section */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-background-border/80">
          <NavLink to="/" className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex-shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/40 flex items-center justify-center shadow-glow-cyan">
              <ShieldCheck className="w-5 h-5 text-cyan-accent" />
              <div className="absolute inset-0 rounded-xl bg-cyan-400/10 animate-pulse-slow" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-lg tracking-wider text-white flex items-center gap-1">
                  SOURCE<span className="text-cyan-accent">MARK</span>
                </span>
                <span className="text-[10px] tracking-widest text-slate-400 font-mono uppercase">
                  Digital Forensics
                </span>
              </div>
            )}
          </NavLink>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-navy-800 transition-colors focus:outline-none"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label="Toggle navigation"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* System Trust Indicator */}
        {!collapsed && (
          <div className="mx-3 mt-3 p-2.5 rounded-lg bg-navy-850/80 border border-cyan-500/20 flex items-center gap-2 text-xs">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <div className="flex-1 min-w-0">
              <div className="text-[11px] font-semibold text-slate-300 truncate">Ed25519 Engine Active</div>
              <div className="text-[10px] text-cyan-400/80 font-mono truncate">{keyInfo.keyId}</div>
            </div>
          </div>
        )}

        {/* Navigation Menu Links */}
        <nav className="mt-4 px-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/15 to-blue-600/10 text-cyan-accent border border-cyan-500/30 shadow-glow-cyan/50 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      className={`w-5 h-5 flex-shrink-0 transition-colors ${
                        isActive ? 'text-cyan-accent' : 'text-slate-400 group-hover:text-slate-200'
                      }`}
                    />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                    {isActive && (
                      <span className="absolute right-0 top-1.5 bottom-1.5 w-1 rounded-l bg-cyan-accent" />
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* User Profile Section at Bottom */}
      <div className="p-3 border-t border-background-border/80 bg-navy-950/70">
        <NavLink
          to="/settings"
          className="flex items-center gap-3 p-2 rounded-lg hover:bg-navy-800/80 transition-colors group"
        >
          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1.5px] flex-shrink-0">
            <div className="w-full h-full rounded-full bg-navy-900 flex items-center justify-center text-xs font-bold text-white">
              EV
            </div>
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-200 truncate group-hover:text-cyan-accent">
                Dr. Evelyn Vance
              </p>
              <p className="text-[10px] text-slate-400 font-mono truncate">
                Analyst • AGY-0042
              </p>
            </div>
          )}
        </NavLink>
      </div>
    </aside>
  );
}

