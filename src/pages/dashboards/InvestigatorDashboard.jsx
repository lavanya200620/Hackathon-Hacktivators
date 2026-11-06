import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { workflowService } from '../../services/workflowService';
import {
  Search,
  FileSearch,
  AlertOctagon,
  FileText,
  Clock,
  CheckCircle2,
  Send,
  ArrowRight,
  ShieldAlert,
  Cpu,
  Layers,
  Sparkles
} from 'lucide-react';

export default function InvestigatorDashboard() {
  const { user } = useAuth();
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [newCaseForm, setNewCaseForm] = useState({ title: '', sourceId: '', severity: 'HIGH', initialNote: '' });

  useEffect(() => {
    workflowService.getCases().then(res => {
      setCases(res);
      if (res.length > 0) setSelectedCase(res[0]);
    });
  }, []);

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedCase) return;

    const updated = await workflowService.addCaseNote(selectedCase.id, newNote);
    setSelectedCase({ ...updated });
    setNewNote('');
    const all = await workflowService.getCases();
    setCases(all);
  };

  const handleStatusChange = async (newStatus) => {
    if (!selectedCase) return;
    const updated = await workflowService.updateCaseStatus(selectedCase.id, newStatus);
    setSelectedCase({ ...updated });
    const all = await workflowService.getCases();
    setCases(all);
  };

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newCaseForm.title) return;
    const created = await workflowService.createCase(newCaseForm);
    const all = await workflowService.getCases();
    setCases(all);
    setSelectedCase(created);
    setShowNewCaseModal(false);
    setNewCaseForm({ title: '', sourceId: '', severity: 'HIGH', initialNote: '' });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-purple-500/10 border border-purple-500/20 rounded-xl flex items-center justify-center text-purple-400">
            <Search className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Forensic Investigation Directorate</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                ROLE: FORENSIC INVESTIGATOR
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Active Examiner: <span className="text-slate-200 font-semibold">{user?.name}</span>. Deep verification analysis, chain-of-custody, and forensic cases.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowNewCaseModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-purple-600/30 transition"
          >
            <FileSearch className="w-4 h-4" />
            + Open Investigation Case
          </button>
          <Link
            to="/verify"
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition"
          >
            Cryptographic Verifier
          </Link>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Active Cases</span>
            <AlertOctagon className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {cases.filter(c => c.status !== 'RESOLVED' && c.status !== 'CLOSED').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Under active forensic examination</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">High Severity Flags</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400">
            {cases.filter(c => c.severity === 'HIGH' || c.severity === 'CRITICAL').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Bitstream / PKI violations</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Resolved Cases</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {cases.filter(c => c.status === 'RESOLVED' || c.status === 'CLOSED').length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Evidence confirmed & closed</div>
        </div>

        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-400 font-medium">Forensic Toolkit</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">5 Tools</div>
          <div className="text-[11px] text-slate-500 mt-1">Sandbox, Metadata, Timeline, etc.</div>
        </div>
      </div>

      {/* Case Management Console */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Case List */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h2 className="text-sm font-bold text-white mb-1">Active Case Queue</h2>
          <p className="text-xs text-slate-400 mb-4">Click to inspect chain-of-custody and add notes</p>

          <div className="space-y-3">
            {cases.map((c) => (
              <div
                key={c.id}
                onClick={() => setSelectedCase(c)}
                className={`p-4 rounded-xl border text-xs cursor-pointer transition ${
                  selectedCase?.id === c.id
                    ? 'bg-purple-950/30 border-purple-500/50 shadow-md shadow-purple-900/20'
                    : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-purple-400 font-bold">{c.id}</span>
                  <div className="flex items-center gap-1.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      c.severity === 'HIGH' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {c.severity}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      c.status === 'RESOLVED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                    }`}>
                      {c.status.replace('_', ' ')}
                    </span>
                  </div>
                </div>
                <div className="font-semibold text-white truncate mb-1">{c.title}</div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between">
                  <span>Source: <code className="text-slate-300 font-mono">{c.sourceId}</code></span>
                  <span>{new Date(c.updatedAt).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Detailed Case Workspace */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
          {selectedCase ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-purple-400 font-bold text-sm">{selectedCase.id}</span>
                    <span className="text-xs text-slate-400 font-mono">• Source: {selectedCase.sourceId}</span>
                  </div>
                  <h3 className="text-base font-bold text-white">{selectedCase.title}</h3>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={selectedCase.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white focus:outline-none"
                  >
                    <option value="UNDER_INVESTIGATION">UNDER INVESTIGATION</option>
                    <option value="AWAITING_EVIDENCE">AWAITING EVIDENCE</option>
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="CLOSED">CLOSED</option>
                  </select>
                </div>
              </div>

              {/* Evidence Hashes */}
              <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800 space-y-1.5 text-xs font-mono">
                <div className="text-slate-400 text-[11px] uppercase tracking-wider font-sans font-bold">Cryptographic Hashes</div>
                <div className="truncate text-slate-300">
                  <span className="text-slate-500">Master Hash:</span> {selectedCase.evidenceHash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                </div>
                {selectedCase.alteredHash && (
                  <div className="truncate text-red-400">
                    <span className="text-slate-500">Inspected Hash:</span> {selectedCase.alteredHash}
                  </div>
                )}
              </div>

              {/* Examiner Notes Log */}
              <div>
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Examiner Notes & Chain of Custody</h4>
                <div className="space-y-2 max-h-56 overflow-y-auto pr-2">
                  {selectedCase.notes && selectedCase.notes.length > 0 ? (
                    selectedCase.notes.map((n, idx) => (
                      <div key={idx} className="p-3 bg-slate-950/50 rounded-xl border border-slate-800/80 text-xs">
                        <div className="flex items-center justify-between text-slate-400 text-[10px] mb-1 font-mono">
                          <span className="text-purple-300 font-semibold font-sans">{n.author}</span>
                          <span>{new Date(n.timestamp).toLocaleString()}</span>
                        </div>
                        <p className="text-slate-200">{n.text}</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No notes logged yet.</div>
                  )}
                </div>
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="flex gap-2 pt-2 border-t border-slate-800">
                <input
                  type="text"
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Record forensic observation, byte offset, or test finding..."
                  className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-purple-500"
                />
                <button
                  type="submit"
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition"
                >
                  <Send className="w-3.5 h-3.5" /> Log Note
                </button>
              </form>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500">
              Select a case to inspect evidence details
            </div>
          )}
        </div>
      </div>

      {/* Forensic Deep-Link Tools */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Link to="/metadata-intelligence" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition group">
          <div className="font-bold text-white text-xs mb-1 group-hover:text-purple-300 transition">Metadata Inspector</div>
          <div className="text-[11px] text-slate-400">Inspect EXIF, ICC profiles, and stego tags</div>
        </Link>
        <Link to="/compare" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition group">
          <div className="font-bold text-white text-xs mb-1 group-hover:text-purple-300 transition">Tamper Sandbox</div>
          <div className="text-[11px] text-slate-400">Byte-level perturbation and signature failure simulator</div>
        </Link>
        <Link to="/batch-verification" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition group">
          <div className="font-bold text-white text-xs mb-1 group-hover:text-purple-300 transition">Batch Verification</div>
          <div className="text-[11px] text-slate-400">High-throughput bulk asset hash verification</div>
        </Link>
        <Link to="/forensic-intelligence" className="p-4 bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 rounded-2xl transition group">
          <div className="font-bold text-white text-xs mb-1 group-hover:text-purple-300 transition">Signature Explorer</div>
          <div className="text-[11px] text-slate-400">Trace Ed25519 curve parameters & R/S components</div>
        </Link>
      </div>

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2">Open New Forensic Case</h3>
            <form onSubmit={handleCreateCase} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={newCaseForm.title}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, title: e.target.value })}
                  placeholder="e.g. Discrepancy in Satellite Radar Header"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-purple-500"
                />
              </div>
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Target Source ID</label>
                <input
                  type="text"
                  required
                  value={newCaseForm.sourceId}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, sourceId: e.target.value })}
                  placeholder="e.g. SRC-98214"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-purple-500"
                />
              </div>
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Severity Rating</label>
                <select
                  value={newCaseForm.severity}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, severity: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-purple-500"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Initial Examiner Findings</label>
                <textarea
                  rows={3}
                  value={newCaseForm.initialNote}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, initialNote: e.target.value })}
                  placeholder="Initial observations, suspicious byte sequences, or source context..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl font-semibold shadow-lg shadow-purple-600/30"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

