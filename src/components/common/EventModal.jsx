import React from 'react';
import { X, CheckCircle2, AlertTriangle, Shield, Clock, Hash, Key, Cpu, Database } from 'lucide-react';
import StatusBadge from './StatusBadge';

export default function EventModal({ isOpen, onClose, block }) {
  if (!isOpen || !block) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-2xl bg-navy-900 border border-slate-700/80 p-6 sm:p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-white rounded-lg hover:bg-navy-800 transition-colors"
          aria-label="Close"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Database className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">{block.id}</h2>
              <StatusBadge status={block.status} size="sm" />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{block.title}</p>
          </div>
        </div>

        <div className="space-y-4 text-xs font-mono">
          <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-navy-950 border border-slate-800">
            <div>
              <span className="text-slate-500 uppercase text-[10px] block">Event Block Type</span>
              <span className="text-cyan-400 font-bold">{block.type}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase text-[10px] block">Timestamp</span>
              <span className="text-slate-300">{block.timestamp}</span>
            </div>
          </div>

          <div className="space-y-2">
            <div>
              <span className="text-slate-400 text-[11px] uppercase flex items-center gap-1.5 mb-1 font-sans font-semibold">
                <Hash className="w-3.5 h-3.5 text-cyan-400" />
                Previous Block Hash (Merkle Chain Parent)
              </span>
              <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800 text-slate-400 break-all select-all text-[11px]">
                {block.prevHash}
              </div>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] uppercase flex items-center gap-1.5 mb-1 font-sans font-semibold">
                <Hash className="w-3.5 h-3.5 text-emerald-400" />
                Current Event Hash (SHA-256 Digest)
              </span>
              <div className="p-2.5 rounded-lg bg-navy-950 border border-emerald-500/30 text-emerald-300 break-all select-all text-[11px]">
                {block.currentHash}
              </div>
            </div>
          </div>

          <div>
            <span className="text-slate-400 text-[11px] uppercase flex items-center gap-1.5 mb-1 font-sans font-semibold">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              Cryptographic Payload Data
            </span>
            <pre className="p-3 rounded-lg bg-navy-950 border border-slate-800 text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {JSON.stringify(block.payload, null, 2)}
            </pre>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-navy-800 hover:bg-navy-750 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

