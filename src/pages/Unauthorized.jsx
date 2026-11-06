import React from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, ArrowLeft, KeyRound, UserCheck, AlertTriangle } from 'lucide-react';

export default function Unauthorized() {
  const { user, ROLE_LABELS } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const requiredRole = location.state?.requiredRole;
  const attemptedPath = location.state?.attemptedPath || 'the requested resource';

  return (
    <div className="min-h-[70vh] flex items-center justify-center p-6">
      <div className="max-w-lg w-full bg-slate-900 border border-red-500/30 rounded-2xl p-8 shadow-2xl text-center backdrop-blur-xl">
        <div className="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6 text-red-400">
          <ShieldAlert className="w-8 h-8" />
        </div>

        <span className="text-xs font-mono uppercase tracking-widest text-red-400 bg-red-500/10 px-3 py-1 rounded-full border border-red-500/20">
          HTTP 403 Forbidden – RBAC Policy Boundary
        </span>

        <h1 className="text-2xl font-bold text-white mt-4 mb-2">Access Restricted</h1>
        <p className="text-slate-400 text-sm mb-6">
          Your current account role <strong className="text-slate-200">({user ? ROLE_LABELS[user.role] : 'Unauthenticated'})</strong> does not possess the requisite clearance to access <span className="text-indigo-400 font-mono">{attemptedPath}</span>.
        </p>

        {requiredRole && (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-left mb-6 text-xs text-slate-300">
            <div className="flex items-center gap-2 text-amber-400 font-semibold mb-1">
              <AlertTriangle className="w-4 h-4" />
              <span>Required Clearance</span>
            </div>
            <div>This module requires <strong>{ROLE_LABELS[requiredRole] || requiredRole}</strong> authorization. Please contact an enterprise administrator to request clearance escalation.</div>
          </div>
        )}

        <div className="flex items-center justify-center gap-4">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm font-medium transition"
          >
            <ArrowLeft className="w-4 h-4" />
            Go Back
          </button>
          <Link
            to="/"
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-medium transition shadow-lg shadow-indigo-500/20"
          >
            Return to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}

