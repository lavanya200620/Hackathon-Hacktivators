import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Search,
  Filter,
  ArrowUpDown,
  History,
  CheckCircle2,
  Clock,
  Shield,
  Key,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  X,
  FileText,
  Calendar,
  Layers,
  Sparkles
} from 'lucide-react';
import StatusBadge from '../components/common/StatusBadge';
import { ledgerStorage } from '../services/ledgerStorage';
import { apiService } from '../services/api';

export default function ProvenanceHistory() {
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [sources, setSources] = useState([]);
  const [searchQuery, setSearchQuery] = useState(initialQuery);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortField, setSortField] = useState('registeredAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedSource, setSelectedSource] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const itemsPerPage = 6;

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (initialQuery) {
      setSearchQuery(initialQuery);
    }
  }, [initialQuery]);

  const loadData = () => {
    const list = ledgerStorage.getSources();
    setSources(list);
  };

  // Filter & Search & Sort
  const filteredSources = sources
    .filter((item) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        item.fileName.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q) ||
        item.creator.toLowerCase().includes(q) ||
        item.sha256.toLowerCase().includes(q);

      const matchesStatus =
        statusFilter === 'ALL' || item.status === statusFilter;

      return matchesSearch && matchesStatus;
    })
    .sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (sortField === 'registeredAt') {
        valA = new Date(valA).getTime();
        valB = new Date(valB).getTime();
      }
      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

  const totalPages = Math.ceil(filteredSources.length / itemsPerPage) || 1;
  const paginatedSources = filteredSources.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Content Provenance Trail
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Explore and inspect registered digital source records, cryptographic fingerprint identities, and verified chronological timelines.
          </p>
        </div>

        <Link
          to="/register"
          className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs flex items-center gap-2 shadow-glow-cyan transition-all self-start sm:self-auto"
        >
          <Shield className="w-4 h-4" />
          Register New Source
        </Link>
      </div>

      {/* Search and Filters Bar */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3 w-full md:w-auto flex-1">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search by filename, Source ID (SRC-...), or creator..."
              className="w-full bg-navy-900 border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-colors font-mono"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-navy-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE_REGISTERED">Active Registered</option>
              <option value="ARCHIVED">Archived</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono self-end md:self-auto">
          <span>{filteredSources.length} records found</span>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-navy-900/90 border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th
                  onClick={() => toggleSort('id')}
                  className="py-3.5 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Source ID</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort('fileName')}
                  className="py-3.5 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>File Artifact</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3.5 px-4">Creator / ID</th>
                <th
                  onClick={() => toggleSort('registeredAt')}
                  className="py-3.5 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Registration Date</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3.5 px-4">SHA-256 Fingerprint</th>
                <th className="py-3.5 px-4">Signature</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-800/80 font-sans">
              {paginatedSources.length > 0 ? (
                paginatedSources.map((item) => (
                  <tr
                    key={item.id}
                    className="hover:bg-navy-850/60 transition-colors group"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 whitespace-nowrap">
                      {item.id}
                    </td>

                    <td className="py-3.5 px-4 max-w-[200px]">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-slate-400 flex-shrink-0" />
                        <span className="font-medium text-slate-200 truncate" title={item.fileName}>
                          {item.fileName}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono block mt-0.5">
                        {item.fileSizeFormatted || '1.2 MB'} • {item.category || 'Asset'}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="text-slate-300 font-medium block truncate max-w-[150px]">
                        {item.creator}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono block">
                        {item.creatorId || 'ANALYST'}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(item.registeredAt).toLocaleDateString([], {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })}
                    </td>

                    <td className="py-3.5 px-4 max-w-[160px]">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] text-slate-400 truncate select-all">
                          {item.sha256.substring(0, 12)}...{item.sha256.substring(56)}
                        </span>
                        <button
                          onClick={() => handleCopy(item.sha256, item.id)}
                          className="p-1 text-slate-500 hover:text-cyan-400 transition-colors"
                          title="Copy full SHA-256 hash"
                        >
                          {copiedId === item.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                        <Key className="w-3 h-3" /> Ed25519
                      </span>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <StatusBadge status={item.status} size="sm" />
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedSource(item)}
                        className="px-3 py-1.5 rounded-lg bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-slate-700 text-xs font-semibold hover:border-cyan-500/40 transition-all"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    No provenance records matching your filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded-lg bg-navy-900 border border-slate-800 hover:bg-navy-850 disabled:opacity-40 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded-lg bg-navy-900 border border-slate-800 hover:bg-navy-850 disabled:opacity-40 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Chronological Timeline Details Drawer / Modal */}
      {selectedSource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="relative w-full max-w-2xl rounded-2xl bg-navy-900 border border-cyan-500/30 p-6 sm:p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setSelectedSource(null)}
              className="absolute top-4 right-4 p-2 text-slate-400 hover:text-white rounded-lg hover:bg-navy-850"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Header */}
            <div className="flex items-start gap-4 mb-6">
              <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <History className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-white">{selectedSource.id}</h2>
                  <StatusBadge status={selectedSource.status} size="sm" />
                </div>
                <p className="text-xs text-slate-400 mt-0.5">{selectedSource.fileName}</p>
              </div>
            </div>

            {/* Full Chronological Provenance Timeline (Stages 1..6) */}
            <div className="space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                Chronological Provenance Events
              </h3>

              <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6 text-xs">
                {/* 1. Content Registered */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-emerald-400 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">1. Content Registered</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Original binary accepted into SourceMark registry by {selectedSource.creator}.
                  </p>
                  <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                    {selectedSource.registeredAt}
                  </span>
                </div>

                {/* 2. Hash Generated */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-cyan-400 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">2. SHA-256 Fingerprint Generated</p>
                  <p className="text-cyan-300 font-mono text-[10px] break-all p-2 rounded bg-navy-950 border border-slate-800 mt-1">
                    {selectedSource.sha256}
                  </p>
                </div>

                {/* 3. Digital Signature Created */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-indigo-400 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">3. Digital Signature Created (Ed25519)</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Signed with private key corresponding to {selectedSource.keyId || 'ED25519-ROOT'}.
                  </p>
                </div>

                {/* 4. Provenance Record Saved */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-blue-400 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">4. Provenance Record Saved & Committed</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Immutable block anchored into cryptographic audit ledger chain.
                  </p>
                </div>

                {/* 5. Verification Events */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-emerald-400 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">5. Verification Inspections ({selectedSource.verificationCount || 1} queries)</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    All incoming bitstream hashes verified against master Ed25519 anchor.
                  </p>
                </div>

                {/* 6. Comparison Events */}
                <div className="relative">
                  <div className="absolute -left-[31px] top-0 w-4 h-4 rounded-full bg-slate-600 ring-4 ring-navy-900" />
                  <p className="font-bold text-slate-200">6. Comparative Analysis</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Ready for side-by-side difference mapping against suspected variants.
                  </p>
                </div>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="mt-8 flex items-center justify-between pt-4 border-t border-slate-800">
              <Link
                to={`/compare?original=${selectedSource.id}`}
                className="px-4 py-2 rounded-xl bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                Launch In Compare Tool <ExternalLink className="w-3.5 h-3.5" />
              </Link>
              <button
                onClick={() => setSelectedSource(null)}
                className="px-4 py-2 rounded-xl bg-navy-800 text-slate-300 hover:text-white text-xs font-semibold"
              >
                Close Trail
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

