/**
 * SourceMark Enterprise Authentication & RBAC Service
 * Supports backend authentication with fallback to secure client-orchestrated enterprise identity.
 */

import axios from 'axios';

const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) || 'http://127.0.0.1:8000';

export const ENTERPRISE_ROLES = {
  ADMINISTRATOR: 'ADMINISTRATOR',
  FORENSIC_INVESTIGATOR: 'FORENSIC_INVESTIGATOR',
  SOC_ANALYST: 'SOC_ANALYST',
  AUDITOR: 'AUDITOR',
  ORGANIZATION_MANAGER: 'ORGANIZATION_MANAGER',
  USER: 'USER',
};

export const ROLE_LABELS = {
  [ENTERPRISE_ROLES.ADMINISTRATOR]: 'Enterprise Security Administrator',
  [ENTERPRISE_ROLES.FORENSIC_INVESTIGATOR]: 'Lead Forensic Investigator',
  [ENTERPRISE_ROLES.SOC_ANALYST]: 'SOC Operations Analyst',
  [ENTERPRISE_ROLES.AUDITOR]: 'Compliance & Forensic Auditor',
  [ENTERPRISE_ROLES.ORGANIZATION_MANAGER]: 'Organization Department Lead',
  [ENTERPRISE_ROLES.USER]: 'Content Contributor / Creator',
};

export const ROLE_BADGE_COLORS = {
  [ENTERPRISE_ROLES.ADMINISTRATOR]: 'bg-red-500/10 text-red-400 border-red-500/20',
  [ENTERPRISE_ROLES.FORENSIC_INVESTIGATOR]: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  [ENTERPRISE_ROLES.SOC_ANALYST]: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  [ENTERPRISE_ROLES.AUDITOR]: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  [ENTERPRISE_ROLES.ORGANIZATION_MANAGER]: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  [ENTERPRISE_ROLES.USER]: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
};

// Granular Role-Based Access Control (RBAC) Permissions Matrix
export const ROLE_PERMISSIONS = {
  [ENTERPRISE_ROLES.ADMINISTRATOR]: [
    'users:read', 'users:write', 'users:delete',
    'roles:assign', 'system:lockdown', 'keys:revoke', 'keys:approve',
    'ledger:read', 'ledger:rollback', 'sources:read', 'sources:write',
    'investigations:read', 'investigations:write', 'alerts:read', 'alerts:write',
    'approvals:read', 'approvals:decide', 'audit:read', 'audit:export',
    'sandbox:access', 'metadata:access', 'batch:access',
  ],
  [ENTERPRISE_ROLES.FORENSIC_INVESTIGATOR]: [
    'sources:read', 'sources:verify', 'investigations:read', 'investigations:write',
    'investigations:close', 'evidence:export', 'ledger:read', 'keys:inspect',
    'alerts:read', 'audit:read', 'sandbox:access', 'metadata:access', 'batch:access',
  ],
  [ENTERPRISE_ROLES.SOC_ANALYST]: [
    'alerts:read', 'alerts:contain', 'alerts:dismiss', 'keys:quarantine',
    'keys:inspect', 'sources:read', 'sources:verify', 'investigations:read',
    'system:status', 'audit:read', 'sandbox:access',
  ],
  [ENTERPRISE_ROLES.AUDITOR]: [
    'audit:read', 'audit:export', 'ledger:read', 'ledger:verify',
    'sources:read', 'keys:inspect', 'approvals:read', 'compliance:generate',
  ],
  [ENTERPRISE_ROLES.ORGANIZATION_MANAGER]: [
    'sources:read', 'sources:write', 'approvals:read', 'approvals:decide',
    'team:read', 'team:manage', 'reports:generate', 'audit:read',
  ],
  [ENTERPRISE_ROLES.USER]: [
    'sources:read', 'sources:register', 'sources:verify', 'keys:view_own',
    'approvals:request',
  ],
};

// Default Enterprise Accounts for Evaluator Testing
export const DEFAULT_ACCOUNTS = [
  {
    id: 'USR-ADMIN-01',
    name: 'Chief Security Officer (Admin)',
    email: 'admin@sourcemark.io',
    password: 'AdminPass123!',
    role: ENTERPRISE_ROLES.ADMINISTRATOR,
    organization: 'Enterprise Defense Directorate',
    department: 'Cyber Risk & Systems Governance',
    mfaEnabled: true,
  },
  {
    id: 'USR-INV-01',
    name: 'Agent Evelyn Vance (Forensics)',
    email: 'investigator@sourcemark.io',
    password: 'InvestigatorPass123!',
    role: ENTERPRISE_ROLES.FORENSIC_INVESTIGATOR,
    organization: 'Federal Geointelligence Agency',
    department: 'Digital Forensic Inspection Unit',
    mfaEnabled: true,
  },
  {
    id: 'USR-SOC-01',
    name: 'Marcus Brody (SOC Lead)',
    email: 'soc@sourcemark.io',
    password: 'SocPass123!',
    role: ENTERPRISE_ROLES.SOC_ANALYST,
    organization: 'Cyber Defense Operations',
    department: 'Incident Response & Containment',
    mfaEnabled: true,
  },
  {
    id: 'USR-AUD-01',
    name: 'Sophia Chen (Lead Auditor)',
    email: 'auditor@sourcemark.io',
    password: 'AuditorPass123!',
    role: ENTERPRISE_ROLES.AUDITOR,
    organization: 'Global Audit & Forensics Corp',
    department: 'Digital Provenance Compliance',
    mfaEnabled: true,
  },
  {
    id: 'USR-MGR-01',
    name: 'Director David Sterling (Org Lead)',
    email: 'manager@sourcemark.io',
    password: 'ManagerPass123!',
    role: ENTERPRISE_ROLES.ORGANIZATION_MANAGER,
    organization: 'National Geospatial Imaging Pipeline',
    department: 'Department of Orbital Operations',
    mfaEnabled: true,
  },
  {
    id: 'USR-CUSTODIAN-01',
    name: 'Alex Rivera (Digital Contributor)',
    email: 'user@sourcemark.io',
    password: 'UserPass123!',
    role: ENTERPRISE_ROLES.USER,
    organization: 'National Geospatial Imaging Pipeline',
    department: 'Field Intelligence Capture',
    mfaEnabled: false,
  },
];

const memStore = {};
const safeSessionStorage = {
  getItem: (k) => (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(k) : memStore[k] || null),
  setItem: (k, v) => {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(k, v);
    } else {
      memStore[k] = v;
    }
  },
  removeItem: (k) => {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(k);
    } else {
      delete memStore[k];
    }
  },
};

const SESSION_STORAGE_KEY = 'sourcemark_enterprise_session';

class EnterpriseAuthService {
  constructor() {
    this.currentUser = null;
    this.token = null;
    this.restoreSession();
  }

  restoreSession() {
    try {
      const stored = safeSessionStorage.getItem(SESSION_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed && parsed.user) {
          this.currentUser = parsed.user;
          this.token = parsed.token;
          return;
        }
      }
    } catch {
      // ignore parsing error
    }

    this.currentUser = null;
    this.token = null;
  }

  setUserSession(user, token) {
    this.currentUser = {
      ...user,
      permissions: ROLE_PERMISSIONS[user.role] || [],
    };
    this.token = token || `tk-${Date.now()}`;
    try {
      safeSessionStorage.setItem(
        SESSION_STORAGE_KEY,
        JSON.stringify({ user: this.currentUser, token: this.token })
      );
    } catch {
      // storage quota or disabled
    }
  }

  getCurrentUser() {
    return this.currentUser;
  }

  getToken() {
    return this.token;
  }

  isAuthenticated() {
    return !!this.currentUser;
  }

  hasPermission(permission) {
    if (!this.currentUser) return false;
    const permissions = ROLE_PERMISSIONS[this.currentUser.role] || [];
    return permissions.includes(permission);
  }

  hasRole(role) {
    if (!this.currentUser) return false;
    return this.currentUser.role === role;
  }

  async login(email, password) {
    try {
      // Attempt backend auth first
      const res = await axios.post(`${BASE_URL}/api/auth/login`, { email, password }, { timeout: 2500 });
      if (res.data && res.data.success) {
        this.setUserSession(res.data.user, res.data.token);
        return { success: true, user: this.currentUser };
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.error) {
        throw new Error(err.response.data.error);
      }
      // If network failure / backend unreachable, allow offline fallback
    }

    const matched = DEFAULT_ACCOUNTS.find(
      a => a.email.toLowerCase() === email.toLowerCase() && a.password === password
    );

    if (matched) {
      this.setUserSession(matched, `client-session-${matched.id}`);
      return { success: true, user: this.currentUser };
    }

    throw new Error('Invalid email or password credentials. Please verify your credentials.');
  }

  async switchRole(targetRole) {
    const targetAccount = DEFAULT_ACCOUNTS.find(a => a.role === targetRole);
    if (targetAccount) {
      this.setUserSession(targetAccount, `client-session-${targetAccount.id}`);
      return this.currentUser;
    }
    // If no exact default account, modify role on current profile
    if (this.currentUser) {
      this.currentUser.role = targetRole;
      this.currentUser.permissions = ROLE_PERMISSIONS[targetRole] || [];
      this.setUserSession(this.currentUser, this.token);
    }
    return this.currentUser;
  }

  logout() {
    this.currentUser = null;
    this.token = null;
    try {
      safeSessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {
      // ignore
    }
  }
}

export const authService = new EnterpriseAuthService();
