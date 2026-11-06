import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Shield, FileCheck } from 'lucide-react';

export default function StatusBadge({ status, text, size = 'md' }) {
  const norm = (status || '').toUpperCase();

  let colors = 'bg-slate-800/80 text-slate-300 border-slate-700';
  let Icon = Shield;
  let label = text || status;

  if (norm.includes('MODIFIED_AND_COMPROMISED') || (norm.includes('MODIFIED') && norm.includes('COMPROMISED'))) {
    colors = 'bg-rose-950/90 text-rose-300 border-rose-500/70 shadow-glow-red animate-pulse';
    Icon = AlertTriangle;
    label = text || 'Modified & Key Compromised';
  } else if (norm.includes('AUTHORIZED_DERIVATIVE') || norm.includes('DERIVATIVE')) {
    colors = 'bg-cyan-950/70 text-cyan-300 border-cyan-500/40 shadow-glow-cyan';
    Icon = CheckCircle2;
    label = text || 'Authorized Derivative';
  } else if (norm.includes('PRE_COMPROMISE')) {
    colors = 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50 shadow-glow-green';
    Icon = CheckCircle2;
    label = text || 'Pre-Compromise Valid';
  } else if (norm.includes('REQUIRES_INVESTIGATION') || norm.includes('INVESTIGATION')) {
    colors = 'bg-amber-950/80 text-amber-300 border-amber-500/50 shadow-glow-amber';
    Icon = AlertTriangle;
    label = text || 'Requires Investigation';
  } else if (norm.includes('COMPROMISED') || norm.includes('STOLEN')) {
    colors = 'bg-rose-950/80 text-rose-300 border-rose-500/50 shadow-glow-red';
    Icon = AlertTriangle;
    label = text || 'Key Compromised';
  } else if (norm.includes('ORIGINAL') || norm.includes('VERIFIED') || norm === 'VALID' || norm === 'CONFIRMED') {
    colors = 'bg-emerald-950/70 text-emerald-400 border-emerald-500/40 shadow-glow-green';
    Icon = CheckCircle2;
    label = text || 'Original – Cryptographically Verified';
  } else if (norm.includes('EDITED') || norm.includes('TAMPER') || norm === 'INVALID' || norm === 'ALERT') {
    colors = 'bg-rose-950/70 text-rose-400 border-rose-500/40 shadow-glow-red';
    Icon = XCircle;
    label = text || 'Edited – Content Difference Detected';
  } else if (norm.includes('UNKNOWN') || norm.includes('WARNING') || norm.includes('UNVERIFIED')) {
    colors = 'bg-amber-950/70 text-amber-400 border-amber-500/40 shadow-glow-amber';
    Icon = AlertTriangle;
    label = text || 'Unknown – No Trusted Source Found';
  } else if (norm.includes('ACTIVE') || norm.includes('REGISTER')) {
    colors = 'bg-cyan-950/70 text-cyan-400 border-cyan-500/40 shadow-glow-cyan';
    Icon = FileCheck;
    label = text || 'Active Registered';
  }

  const sizeClasses = size === 'sm' 
    ? 'text-xs px-2.5 py-1' 
    : size === 'lg' 
      ? 'text-sm px-4 py-2 font-semibold' 
      : 'text-xs px-3 py-1.5 font-medium';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border backdrop-blur-md transition-all ${colors} ${sizeClasses}`}>
      <Icon className={size === 'sm' ? 'w-3.5 h-3.5' : size === 'lg' ? 'w-5 h-5' : 'w-4 h-4'} />
      <span>{label}</span>
    </span>
  );
}

