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
  Key,
  QrCode,
  Award,
  Layers,
  FileSearch,
  Lock,
  GitBranch,
  BookOpen,
  Activity,
  Building2,
  Search,
  FileCheck2,
  Users
} from 'lucide-react';
import { getOrCreateKeyPair } from '../../services/crypto';
import { useAuth } from '../../context/AuthContext';

export default function Sidebar({ collapsed, setCollapsed }) {
  const keyInfo = getOrCreateKeyPair();
  const { user, role, ROLE_LABELS } = useAuth();

  // Role dashboard descriptor
  const getRoleDashboardInfo = () => {
    switch (role) {
      case 'ADMINISTRATOR':
        return { to: '/dashboard/admin', label: 'Admin Command', icon: Users, badge: 'ADMIN' };
      case 'FORENSIC_INVESTIGATOR':
        return { to: '/dashboard/investigator', label: 'Forensic Case Hub', icon: Search, badge: 'INVESTIGATOR' };
      case 'SOC_ANALYST':
        return { to: '/dashboard/soc', label: 'SOC Security Feed', icon: Activity, badge: 'SOC' };
      case 'AUDITOR':
        return { to: '/dashboard/auditor', label: 'Audit & Compliance', icon: FileCheck2, badge: 'AUDIT' };
      case 'ORGANIZATION_MANAGER':
        return { to: '/dashboard/manager', label: 'Department Lead', icon: Building2, badge: 'MANAGER' };
      default:
        return { to: '/dashboard/user', label: 'Contributor Hub', icon: LayoutDashboard, badge: 'USER' };
    }
  };

  const roleDash = getRoleDashboardInfo();
  const RoleDashIcon = roleDash.icon;

  const navSections = [
    {
      title: 'Enterprise Workspaces',
      items: [
        { to: roleDash.to, label: roleDash.label, icon: RoleDashIcon, isSpecialRoleDash: true },
        { to: '/overview', label: 'Global Overview', icon: LayoutDashboard },
      ]
    },
    {
      title: 'Core Provenance',
      items: [
        { to: '/register', label: 'Register File', icon: FilePlus2 },
        { to: '/verify', label: 'Verify File', icon: ShieldCheck },
        { to: '/compare', label: 'Compare Files', icon: GitCompare },
        { to: '/history', label: 'Provenance History', icon: History },
        { to: '/ledger', label: 'Audit Ledger', icon: Boxes },
      ]
    },
    {
      title: 'Forensic Intelligence',
      items: [
        { to: '/forensic-intelligence', label: 'Forensic Score', icon: Cpu },
        { to: '/qr-verification', label: 'QR Verification', icon: QrCode },
        { to: '/evidence-certificates', label: 'Evidence Certs', icon: Award },
        { to: '/batch-verification', label: 'Batch Verification', icon: Layers },
        { to: '/metadata-intelligence', label: 'Metadata Intel', icon: FileSearch },
      ]
    },
    {
      title: 'Integrity & Key Governance',
      items: [
        { to: '/checkpoints', label: 'Rollback Protection', icon: Lock },
        { to: '/version-history', label: 'Version Re-saves', icon: GitBranch },
        { to: '/key-security', label: 'Key Security Centre', icon: Key },
      ]
    },
    {
      title: 'Knowledge & Threat Hub',
      items: [
        { to: '/learn', label: 'Learn & Explore', icon: BookOpen },
        { to: '/security-risks', label: 'Security & Risks', icon: ShieldAlert },
        { to: '/reports', label: 'Forensic Reports', icon: FileText },
        { to: '/settings', label: 'Platform Settings', icon: Settings },
      ]
    }
  ];

  return (
    <aside
      className={`fixed top-0 left-0 z-40 h-screen transition-all duration-300 ease-in-out border-r border-background-border bg-navy-900/95 backdrop-blur-xl flex flex-col justify-between ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Branding Section */}
      <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col">
        <div className="h-16 flex items-center justify-between px-4 border-b border-background-border/80 sticky top-0 bg-navy-900/95 backdrop-blur-md z-10 flex-shrink-0">
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
                  Enterprise Forensics
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
          <div className="mx-3 mt-3 p-2.5 rounded-lg bg-navy-850/80 border border-cyan-500/20 flex items-center gap-2 text-xs flex-shrink-0">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <div className="flex-1 min-w-0">
              <div className="text-[11px] font-semibold text-slate-300 truncate">Ed25519 Engine Active</div>
              <div className="text-[10px] text-cyan-400/80 font-mono truncate">{keyInfo.keyId}</div>
            </div>
          </div>
        )}

        {/* Navigation Sections */}
        <nav className="mt-3 px-2 space-y-4 pb-4">
          {navSections.map((section, sIdx) => (
            <div key={section.title} className="space-y-1">
              {!collapsed && (
                <div className="px-3 pt-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold">
                  {section.title}
                </div>
              )}
              {collapsed && sIdx > 0 && (
                <div className="border-t border-background-border/50 my-2 mx-2" />
              )}
              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 group relative ${
                        item.isSpecialRoleDash
                          ? isActive
                            ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 font-bold'
                            : 'bg-indigo-950/20 text-indigo-400 hover:bg-indigo-900/30 border border-indigo-900/40'
                          : isActive
                          ? 'bg-gradient-to-r from-cyan-500/15 to-blue-600/10 text-cyan-accent border border-cyan-500/30 shadow-glow-cyan/50 font-semibold'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon
                          className={`w-4 h-4 flex-shrink-0 transition-colors ${
                            item.isSpecialRoleDash
                              ? 'text-indigo-400'
                              : isActive
                              ? 'text-cyan-accent'
                              : 'text-slate-400 group-hover:text-slate-200'
                          }`}
                        />
                        {!collapsed && (
                          <div className="flex-1 flex items-center justify-between min-w-0">
                            <span className="truncate">{item.label}</span>
                            {item.isSpecialRoleDash && (
                              <span className="text-[9px] font-mono uppercase bg-indigo-500/20 text-indigo-300 px-1.5 py-0.2 rounded border border-indigo-500/30">
                                Active
                              </span>
                            )}
                          </div>
                        )}
                        {isActive && !item.isSpecialRoleDash && (
                          <span className="absolute right-0 top-1.5 bottom-1.5 w-1 rounded-l bg-cyan-accent" />
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* User Profile Section at Bottom */}
      <div className="p-3 border-t border-background-border/80 bg-navy-950/70 flex-shrink-0">
        <NavLink
          to="/settings"
          className="flex items-center gap-3 p-2 rounded-lg hover:bg-navy-800/80 transition-colors group"
        >
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1.5px] flex-shrink-0">
            <div className="w-full h-full rounded-full bg-navy-900 flex items-center justify-center text-xs font-bold text-white">
              {user?.name ? user.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() : 'SM'}
            </div>
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-200 truncate group-hover:text-cyan-accent">
                {user?.name || 'Enterprise Analyst'}
              </p>
              <p className="text-[10px] text-slate-400 font-mono truncate">
                {role ? role.replace('_', ' ') : 'USER'} • {user?.department ? user.department.split(' ')[0] : 'Gov'}
              </p>
            </div>
          )}
        </NavLink>
      </div>
    </aside>
  );
}
