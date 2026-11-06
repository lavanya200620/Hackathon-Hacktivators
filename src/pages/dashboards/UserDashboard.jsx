import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { ledgerStorage } from '../../services/ledgerStorage';
import { workflowService } from '../../services/workflowService';
import {
  FileText,
  Upload,
  Search,
  CheckCircle2,
  Clock,
  Key,
  ShieldCheck,
  ArrowRight,
  ExternalLink,
  Layers,
  Send
} from 'lucide-react';

export default function UserDashboard() {
  const { user } = useAuth();
  const [sources, setSources] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [requestForm, setRequestForm] = useState({ title: '', sourceId: '', reason: '' });
  const [requestSubmitted, setRequestSubmitted] = useState(false);

  useEffect(() => {
    const all = ledgerStorage.getSources();
    setSources(all);
    workflowService.getApprovals().then(setApprovals);
  }, []);

  const handleCreateRequest = async (e) => {
    e.preventDefault();
    if (!requestForm.title || !requestForm.sourceId) return;
    await workflowService.submitApprovalRequest(requestForm);
    setRequestSubmitted(true);
    const updated = await workflowService.getApprovals();
    setApprovals(updated);
    setTimeout(() => {
      setShowRequestModal(false);
      setRequestSubmitted(false);
      setRequestForm({ title: '', sourceId: '', reason: '' });
    }, 1500);
  };

  return (
    <div className="space-y-6">
      {/* Role Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-cyan-500/10 border border-cyan-500/20 rounded-xl flex items-center justify-center text-cyan-400">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Contributor Provenance Hub</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                ROLE: USER
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Welcome back, <span className="text-slate-200 font-semibold">{user?.name}</span>. Manage your digital assets, cryptographic signatures, and provenance chains.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/register"
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-indigo-600/20 transition"
          >
            <Upload className="w-4 h-4" />
            Register New Asset
          </Link>
          <Link
            to="/verify"
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition"
          >
            <Search className="w-4 h-4" />
            Verify Asset
          </Link>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">My Registered Assets</span>
            <FileText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{sources.length}</div>
          <div className="text-[11px] text-slate-500 mt-1">Master signed assets in ledger</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Signature Integrity</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">100%</div>
          <div className="text-[11px] text-slate-500 mt-1">Ed25519-EdDSA Verified</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Pending Approvals</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {approvals.filter(a => a.status === 'PENDING').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Derivative requests awaiting review</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Active Key Status</span>
            <Key className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">VALID</div>
          <div className="text-[11px] text-slate-500 mt-1">Catalogued in Trust Registry</div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Registered Assets */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white">Registered Digital Assets</h2>
              <p className="text-xs text-slate-400">Assets sealed with your cryptographic signature</p>
            </div>
            <Link to="/history" className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1">
              View Timeline <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                  <th className="pb-3">Source ID</th>
                  <th className="pb-3">File Name</th>
                  <th className="pb-3">Registered At</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {sources.slice(0, 5).map((src) => (
                  <tr key={src.id} className="hover:bg-slate-800/30">
                    <td className="py-3 font-mono text-indigo-400 font-semibold">{src.id}</td>
                    <td className="py-3 font-medium text-white truncate max-w-[200px]">{src.fileName}</td>
                    <td className="py-3 text-slate-400">{new Date(src.registeredAt || Date.now()).toLocaleDateString()}</td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {src.status || 'ACTIVE'}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                      <Link
                        to={`/verify`}
                        state={{ prefillSourceId: src.id }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                      >
                        Verify
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Authorization Requests & Quick Action */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white">Derivative Requests</h2>
              <button
                onClick={() => setShowRequestModal(true)}
                className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
              >
                + New Request
              </button>
            </div>

            <div className="space-y-3">
              {approvals.slice(0, 3).map((appr) => (
                <div key={appr.id} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-white truncate max-w-[180px]">{appr.title}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      appr.status === 'APPROVED'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : appr.status === 'REJECTED'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {appr.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">Source: <span className="text-indigo-300 font-mono">{appr.sourceId}</span></div>
                  {appr.reason && <div className="text-[11px] text-slate-500 mt-1 italic">"{appr.reason}"</div>}
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gradient-to-br from-indigo-900/30 to-purple-900/20 border border-indigo-500/20 rounded-2xl p-6">
            <div className="flex items-center gap-2 text-indigo-400 font-bold text-xs uppercase tracking-wider mb-2">
              <ShieldCheck className="w-4 h-4" />
              Cryptographic Safeguard
            </div>
            <p className="text-xs text-slate-300 mb-4">
              Your signatures are computed client-side using Ed25519. Private keys never leave your device unencrypted.
            </p>
            <Link
              to="/key-security"
              className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1"
            >
              Inspect Key Security Center <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* Modal for New Approval Request */}
      {showRequestModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2">Request Derivative Asset Authorization</h3>
            <p className="text-xs text-slate-400 mb-4">
              Submit a formal request to create an authorized derivative from an existing master asset.
            </p>

            {requestSubmitted ? (
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400 text-xs">
                Request submitted to Organization Manager for review.
              </div>
            ) : (
              <form onSubmit={handleCreateRequest} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Request Title</label>
                  <input
                    type="text"
                    required
                    value={requestForm.title}
                    onChange={(e) => setRequestForm({ ...requestForm, title: e.target.value })}
                    placeholder="e.g. Multispectral High-Pass Contrast Layer"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Master Source ID</label>
                  <input
                    type="text"
                    required
                    value={requestForm.sourceId}
                    onChange={(e) => setRequestForm({ ...requestForm, sourceId: e.target.value })}
                    placeholder="e.g. SRC-98214"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Justification / Reason</label>
                  <textarea
                    rows={3}
                    value={requestForm.reason}
                    onChange={(e) => setRequestForm({ ...requestForm, reason: e.target.value })}
                    placeholder="Describe transformation reason and target mission requirement..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowRequestModal(false)}
                    className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold flex items-center justify-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" /> Submit Request
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

