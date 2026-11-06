import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { ledgerStorage } from '../../services/ledgerStorage';
import { workflowService } from '../../services/workflowService';
import {
  Building2,
  Users,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  Send,
  Layers,
  ArrowRight,
  Sparkles
} from 'lucide-react';

export default function OrgManagerDashboard() {
  const { user } = useAuth();
  const [approvals, setApprovals] = useState([]);
  const [sources, setSources] = useState([]);
  const [decisionNotice, setDecisionNotice] = useState('');
  const [selectedReq, setSelectedReq] = useState(null);
  const [rejectReason, setRejectReason] = useState('');
  const [showRejectModal, setShowRejectModal] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    const apps = await workflowService.getApprovals();
    setApprovals(apps);
    const allSources = ledgerStorage.getSources();
    setSources(allSources);
  };

  const handleDecision = async (id, decision, reason = '') => {
    await workflowService.decideApproval(id, decision, reason);
    setDecisionNotice(`Request ${id} marked as ${decision}.`);
    loadData();
    setTimeout(() => setDecisionNotice(''), 4000);
  };

  const openRejectModal = (req) => {
    setSelectedReq(req);
    setShowRejectModal(true);
  };

  const submitRejection = async (e) => {
    e.preventDefault();
    if (!selectedReq) return;
    await handleDecision(selectedReq.id, 'REJECT', rejectReason);
    setShowRejectModal(false);
    setSelectedReq(null);
    setRejectReason('');
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-xl flex items-center justify-center text-blue-400">
            <Building2 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Department Operations & Asset Governance</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                ROLE: ORGANIZATION MANAGER
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Department Lead: <span className="text-slate-200 font-semibold">{user?.name}</span>. Team asset custody, contributor authorizations, and mission approvals.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/history"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-600/30 transition"
          >
            <Layers className="w-4 h-4" />
            Asset Provenance Graph
          </Link>
          <Link
            to="/version-history"
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition"
          >
            Lineage & Versions
          </Link>
        </div>
      </div>

      {decisionNotice && (
        <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-2xl text-blue-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          <span>{decisionNotice}</span>
        </div>
      )}

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Department Assets</span>
            <FileText className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">{sources.length}</div>
          <div className="text-[11px] text-slate-500 mt-1">Orbital Reconnaissance Registry</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Pending Authorizations</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {approvals.filter(a => a.status === 'PENDING').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Awaiting managerial sign-off</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Approved Derivatives</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {approvals.filter(a => a.status === 'APPROVED').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Authorized transformation versions</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Team Custodians</span>
            <Users className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">4 Active</div>
          <div className="text-[11px] text-slate-500 mt-1">Verified key holders</div>
        </div>
      </div>

      {/* Main Approval Queue */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-bold text-white mb-1">Authorization & Derivative Approval Queue</h2>
        <p className="text-xs text-slate-400 mb-6">Review team requests to create authorized derivative versions or rotate credentials</p>

        <div className="space-y-3">
          {approvals.map((req) => (
            <div
              key={req.id}
              className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-blue-400">{req.id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                    req.status === 'APPROVED'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : req.status === 'REJECTED'
                      ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {req.status}
                  </span>
                  <span className="text-xs font-semibold text-white">{req.title}</span>
                </div>

                <div className="text-xs text-slate-300">
                  Target Asset: <span className="font-mono text-indigo-300">{req.sourceId}</span>
                  {req.reason && <span className="text-slate-400"> — "{req.reason}"</span>}
                </div>

                <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono">
                  <span>Requested By: <strong className="text-slate-300">{req.requestedBy}</strong></span>
                  <span>Submitted: {new Date(req.timestamp).toLocaleDateString()}</span>
                  {req.decidedBy && (
                    <span className="text-slate-400">Decided by: {req.decidedBy}</span>
                  )}
                </div>
              </div>

              {req.status === 'PENDING' && (
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => handleDecision(req.id, 'APPROVE')}
                    className="px-3.5 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" /> Approve
                  </button>
                  <button
                    onClick={() => openRejectModal(req)}
                    className="px-3.5 py-1.5 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                  >
                    <XCircle className="w-3.5 h-3.5" /> Reject
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Reject Reason Modal */}
      {showRejectModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2">Reject Authorization Request</h3>
            <p className="text-xs text-slate-400 mb-4">
              Provide reason for denying request <span className="font-mono text-indigo-400">{selectedReq?.id}</span>:
            </p>

            <form onSubmit={submitRejection} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Rejection Reason</label>
                <textarea
                  rows={3}
                  required
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  placeholder="e.g. Asset classification restricted; missing clearance from Mission Director..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowRejectModal(false)}
                  className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl font-semibold shadow-lg shadow-red-600/30"
                >
                  Confirm Rejection
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

