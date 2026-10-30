import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import AppLayout from './components/layout/AppLayout';
import Overview from './pages/Overview';
import Register from './pages/Register';
import Verify from './pages/Verify';
import Compare from './pages/Compare';
import ProvenanceHistory from './pages/ProvenanceHistory';
import AuditLedger from './pages/AuditLedger';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<AppLayout />}>
        <Route index element={<Overview />} />
        <Route path="register" element={<Register />} />
        <Route path="verify" element={<Verify />} />
        <Route path="compare" element={<Compare />} />
        <Route path="history" element={<ProvenanceHistory />} />
        <Route path="ledger" element={<AuditLedger />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

