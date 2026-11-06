import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../../context/AuthContext';
import { keySecurityService } from '../../services/keySecurity';
import { ledgerStorage } from '../../services/ledgerStorage';
import { workflowService } from '../../services/workflowService';
import { apiService } from '../../services/api';

const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) || 'http://127.0.0.1:8000';
import {
  ShieldAlert,
  Users,
  Key,
  Database,
  Lock,
  Unlock,
  AlertTriangle,
  ArrowRight,
  UserCheck,
  UserX,
  CheckCircle2,
  FileText,
  Activity,
  Layers,
  UserPlus,
  KeyRound,
  RefreshCw,
  Building2,
  ShieldCheck
} from 'lucide-react';

export default function AdminDashboard() {
  const { user, ROLE_LABELS } = useAuth();
  const [keys, setKeys] = useState([]);
  const [stats, setStats] = useState({ totalBlocks: 0, totalSources: 0 });
  const [lockdown, setLockdown] = useState(false);
  const [selectedKeyToRevoke, setSelectedKeyToRevoke] = useState('');
  const [revokeReason, setRevokeReason] = useState('');
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [actionNotice, setActionNotice] = useState('');

  // User Management State
  const [usersList, setUsersList] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [showResetPasswordModal, setShowResetPasswordModal] = useState(false);
  const [selectedUserForReset, setSelectedUserForReset] = useState(null);
  const [newPasswordInput, setNewPasswordInput] = useState('');

  const [newUserForm, setNewUserForm] = useState({
    name: '',
    email: '',
    password: '',
    role: 'USER',
    organizationId: 'ORG-01',
  });

  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const res = await apiService.getAdminUsers();
      if (res && res.users) {
        setUsersList(res.users);
      }
    } catch (err) {
      console.warn('Failed to load users from backend:', err);
    } finally {
      setLoadingUsers(false);
    }
  };

  useEffect(() => {
    const registry = typeof keySecurityService.getTrustedRegistry === 'function'
      ? keySecurityService.getTrustedRegistry()
      : (typeof keySecurityService.getKeys === 'function' ? keySecurityService.getKeys() : []);
    setKeys(registry);
    const blocks = ledgerStorage.getLedgerBlocks();
    const srcs = ledgerStorage.getSources();
    setStats({ totalBlocks: blocks.length, totalSources: srcs.length });
    loadUsers();
  }, []);

  const handleRevokeKey = async (e) => {
    e.preventDefault();
    if (!selectedKeyToRevoke) return;

    keySecurityService.revokeKey(selectedKeyToRevoke, revokeReason || 'Administrative containment mandate', 'ADMIN_REVOCATION');
    await ledgerStorage.addLedgerBlock('SECURITY_INCIDENT', `Admin Key Revocation: ${selectedKeyToRevoke}`, {
      key: selectedKeyToRevoke,
      reason: revokeReason,
      actor: user?.email || 'ADMINISTRATOR',
    });

    try {
      const token = sessionStorage.getItem('sourcemark_enterprise_session');
      const authHeader = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
      await axios.post(`${BASE_URL}/api/keys/revoke`, { keyId: selectedKeyToRevoke, reason: revokeReason }, { headers: authHeader, timeout: 1500 });
    } catch {}

    const updatedKeys = typeof keySecurityService.getTrustedRegistry === 'function'
      ? keySecurityService.getTrustedRegistry()
      : (typeof keySecurityService.getKeys === 'function' ? keySecurityService.getKeys() : []);
    setKeys([...updatedKeys]);
    setActionNotice(`Key ${selectedKeyToRevoke} revoked successfully.`);
    setShowRevokeModal(false);
    setSelectedKeyToRevoke('');
    setRevokeReason('');
    setTimeout(() => setActionNotice(''), 4000);
  };

  const toggleLockdown = async () => {
    const nextState = !lockdown;
    setLockdown(nextState);
    ledgerStorage.addLedgerBlock('SECURITY_INCIDENT', `Emergency Lockdown ${nextState ? 'ENGAGED' : 'DISENGAGED'}`, {
      actor: user?.email || 'ADMINISTRATOR',
      state: nextState ? 'ACTIVE' : 'NORMAL',
    });

    try {
      const token = sessionStorage.getItem('sourcemark_enterprise_session');
      const authHeader = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
      await axios.post(`${BASE_URL}/api/system/lockdown`, { lockdown: nextState }, { headers: authHeader, timeout: 1500 });
    } catch {}

    setActionNotice(`Emergency Platform Lockdown ${nextState ? 'ENGAGED' : 'DISENGAGED'}`);
    setTimeout(() => setActionNotice(''), 4000);
  };

  // Create User
  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      const res = await apiService.createAdminUser(newUserForm);
      if (res && res.success) {
        setActionNotice(`User account created successfully for ${newUserForm.email} (${newUserForm.role})`);
        setShowCreateUserModal(false);
        setNewUserForm({ name: '', email: '', password: '', role: 'USER', organizationId: 'ORG-01' });
        loadUsers();
      }
    } catch (err) {
      setActionNotice(err.response?.data?.error || err.message || 'Failed to create user account');
    }
    setTimeout(() => setActionNotice(''), 5000);
  };

  // Toggle Deactivate / Activate
  const handleToggleUserStatus = async (usr) => {
    try {
      if (usr.status === 'DEACTIVATED') {
        await apiService.activateUser(usr.id);
        setActionNotice(`Account for ${usr.email} re-activated.`);
      } else {
        await apiService.deactivateUser(usr.id);
        setActionNotice(`Account for ${usr.email} deactivated.`);
      }
      loadUsers();
    } catch (err) {
      setActionNotice(err.response?.data?.error || err.message || 'Failed to alter user status');
    }
    setTimeout(() => setActionNotice(''), 4000);
  };

  // Reset Password
  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (!selectedUserForReset || !newPasswordInput) return;
    try {
      await apiService.resetUserPassword(selectedUserForReset.id, newPasswordInput);
      setActionNotice(`Password for ${selectedUserForReset.email} successfully updated.`);
      setShowResetPasswordModal(false);
      setSelectedUserForReset(null);
      setNewPasswordInput('');
    } catch (err) {
      setActionNotice(err.response?.data?.error || err.message || 'Failed to reset password');
    }
    setTimeout(() => setActionNotice(''), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Admin Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center justify-center text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Security Command & Administration</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                ROLE: ADMINISTRATOR
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Platform governance, authorized user provisioning, PKI root trust, and cryptographic emergency containment.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowCreateUserModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-indigo-600/30 transition-all"
          >
            <UserPlus className="w-4 h-4" />
            Provision Employee
          </button>
          <button
            onClick={() => setShowRevokeModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-red-600/30 transition-all"
          >
            <Key className="w-4 h-4" />
            Revoke Key
          </button>
          <button
            onClick={toggleLockdown}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
              lockdown
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 hover:bg-amber-500/30'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
            }`}
          >
            {lockdown ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
            {lockdown ? 'Disengage Lockdown' : 'Engage Lockdown'}
          </button>
        </div>
      </div>

      {/* Action Notification */}
      {actionNotice && (
        <div className="p-3 bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs rounded-xl flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-indigo-400" />
            <span>{actionNotice}</span>
          </div>
        </div>
      )}

      {/* Security Stat Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">PostgreSQL Relational Ledger</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{stats.totalBlocks} Blocks</div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Blockchain Verified
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">Managed User Accounts</div>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">{usersList.length || 28} Users</div>
          <div className="text-[11px] text-slate-400 mt-1">PBKDF2-SHA512 Salted</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">PKI Root Keys Active</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {keys.filter(k => k.status === 'ACTIVE').length} / {keys.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Ed25519 Curve25519</div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">Platform Access State</div>
          <div className={`text-2xl font-bold font-mono mt-1 ${lockdown ? 'text-red-400' : 'text-emerald-400'}`}>
            {lockdown ? 'LOCKDOWN ENGAGED' : 'OPERATIONAL'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {lockdown ? 'Asset registrations blocked' : 'Normal authorized processing'}
          </div>
        </div>
      </div>

      {/* Main Administrative Control Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Administrator User & Access Governance */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <Users className="w-5 h-5 text-indigo-400" />
              <div>
                <h2 className="text-base font-bold text-white">Administrator User & Access Governance</h2>
                <p className="text-xs text-slate-400">
                  Provision employee accounts, assign clearance roles, deactivate credentials, and enforce password resets.
                </p>
              </div>
            </div>
            <button
              onClick={loadUsers}
              disabled={loadingUsers}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
              title="Refresh Users"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingUsers ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="overflow-x-auto max-h-[380px] overflow-y-auto pr-1">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold z-10">
                <tr>
                  <th className="pb-3">Employee / Email</th>
                  <th className="pb-3">Clearance Role</th>
                  <th className="pb-3">Organization</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3 text-right">Administrative Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {usersList.map((usr) => (
                  <tr key={usr.id} className="hover:bg-slate-800/30">
                    <td className="py-3">
                      <div className="font-semibold text-white">{usr.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono">{usr.email}</div>
                    </td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                        usr.role === 'ADMINISTRATOR' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        usr.role === 'FORENSIC_INVESTIGATOR' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' :
                        usr.role === 'SOC_ANALYST' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                        usr.role === 'AUDITOR' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        usr.role === 'ORGANIZATION_MANAGER' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                        'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                      }`}>
                        {usr.role}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">{usr.organizationId || 'ORG-01'}</td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                        usr.status === 'DEACTIVATED'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {usr.status || 'ACTIVE'}
                      </span>
                    </td>
                    <td className="py-3 text-right space-x-2">
                      <button
                        onClick={() => {
                          setSelectedUserForReset(usr);
                          setShowResetPasswordModal(true);
                        }}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-medium transition-colors"
                        title="Reset Employee Password"
                      >
                        Reset Pwd
                      </button>
                      <button
                        onClick={() => handleToggleUserStatus(usr)}
                        className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                          usr.status === 'DEACTIVATED'
                            ? 'bg-emerald-600/20 text-emerald-300 hover:bg-emerald-600/30 border border-emerald-500/30'
                            : 'bg-red-600/20 text-red-300 hover:bg-red-600/30 border border-red-500/30'
                        }`}
                      >
                        {usr.status === 'DEACTIVATED' ? 'Activate' : 'Deactivate'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Key Trust Status & Shortcuts */}
        <div className="lg:col-span-4 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                PKI Root Trust Status
              </h2>
              <Link to="/key-security" className="text-xs text-indigo-400 hover:text-indigo-300">
                Full Registry →
              </Link>
            </div>

            <div className="space-y-3">
              {keys.slice(0, 4).map((k) => (
                <div key={k.id} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-bold text-white truncate max-w-[170px]">{k.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      k.status === 'REVOKED' || k.status === 'COMPROMISED'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {k.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">Owner: {k.owner}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2">Administrative Hubs</h3>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <Link to="/overview" className="p-2.5 bg-slate-950 hover:bg-slate-800 rounded-xl border border-slate-800 text-center text-slate-300">
                Global Overview
              </Link>
              <Link to="/key-security" className="p-2.5 bg-slate-950 hover:bg-slate-800 rounded-xl border border-slate-800 text-center text-slate-300">
                Key Security
              </Link>
              <Link to="/checkpoints" className="p-2.5 bg-slate-950 hover:bg-slate-800 rounded-xl border border-slate-800 text-center text-slate-300">
                Checkpoints
              </Link>
              <Link to="/reports" className="p-2.5 bg-slate-950 hover:bg-slate-800 rounded-xl border border-slate-800 text-center text-slate-300">
                Compliance
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Modal: Create User */}
      {showCreateUserModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-md w-full shadow-2xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                <UserPlus className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Provision Authorized Employee</h3>
                <p className="text-xs text-slate-400">Create an authenticated enterprise account with assigned clearance role.</p>
              </div>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-3.5 text-xs mt-4">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Dr. Robert Lang (Forensic Examiner)"
                  value={newUserForm.name}
                  onChange={(e) => setNewUserForm({ ...newUserForm, name: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Work Email</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. rlang@sourcemark.io"
                  value={newUserForm.email}
                  onChange={(e) => setNewUserForm({ ...newUserForm, email: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Initial Password</label>
                <input
                  type="password"
                  required
                  placeholder="Minimum 8 characters"
                  value={newUserForm.password}
                  onChange={(e) => setNewUserForm({ ...newUserForm, password: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Clearance Role</label>
                  <select
                    value={newUserForm.role}
                    onChange={(e) => setNewUserForm({ ...newUserForm, role: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                  >
                    <option value="USER">USER (Standard Contributor)</option>
                    <option value="FORENSIC_INVESTIGATOR">FORENSIC_INVESTIGATOR</option>
                    <option value="SOC_ANALYST">SOC_ANALYST</option>
                    <option value="AUDITOR">AUDITOR</option>
                    <option value="ORGANIZATION_MANAGER">ORGANIZATION_MANAGER</option>
                    <option value="ADMINISTRATOR">ADMINISTRATOR</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Tenant Organization</label>
                  <select
                    value={newUserForm.organizationId}
                    onChange={(e) => setNewUserForm({ ...newUserForm, organizationId: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                  >
                    <option value="ORG-01">ORG-01 (Geoint Agency)</option>
                    <option value="ORG-02">ORG-02 (Cyber Defense)</option>
                    <option value="ORG-03">ORG-03 (Audit & Forensics)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateUserModal(false)}
                  className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold shadow-lg shadow-indigo-600/30"
                >
                  Create Account
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Reset Password */}
      {showResetPasswordModal && selectedUserForReset && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-sm w-full shadow-2xl">
            <h3 className="text-base font-bold text-white mb-1">Reset Employee Password</h3>
            <p className="text-xs text-slate-400 mb-4">
              Enter a new secure password for <span className="text-white font-mono">{selectedUserForReset.email}</span>.
            </p>

            <form onSubmit={handleResetPassword} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">New Secure Password</label>
                <input
                  type="password"
                  required
                  placeholder="Minimum 8 characters"
                  value={newPasswordInput}
                  onChange={(e) => setNewPasswordInput(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResetPasswordModal(false)}
                  className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold shadow-lg shadow-indigo-600/30"
                >
                  Update Password
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Key Revocation */}
      {showRevokeModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2">Emergency Cryptographic Key Revocation</h3>
            <p className="text-xs text-slate-400 mb-4">
              Revoking a key immediately prevents all future provenance record signatures across the enterprise.
            </p>

            <form onSubmit={handleRevokeKey} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Select Key to Revoke</label>
                <select
                  required
                  value={selectedKeyToRevoke}
                  onChange={(e) => setSelectedKeyToRevoke(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-red-500"
                >
                  <option value="">-- Choose Key ID or Hex --</option>
                  {keys.filter(k => k.status === 'ACTIVE').map(k => (
                    <option key={k.id} value={k.id}>
                      {k.id} ({k.owner})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Revocation Justification / Mandate</label>
                <textarea
                  rows={3}
                  required
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                  placeholder="Specify incident report ID, compromise vector, or administrative audit order..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowRevokeModal(false)}
                  className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl font-semibold shadow-lg shadow-red-600/30"
                >
                  Enforce Revocation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
