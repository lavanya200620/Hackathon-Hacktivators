import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/auth/ProtectedRoute';
import AppLayout from './components/layout/AppLayout';

// Core Authentication & Error Pages
import Login from './pages/Login';
import Unauthorized from './pages/Unauthorized';

// Enterprise Role Dashboards
import RoleDashboardRouter from './pages/dashboards/RoleDashboardRouter';
import UserDashboard from './pages/dashboards/UserDashboard';
import AdminDashboard from './pages/dashboards/AdminDashboard';
import InvestigatorDashboard from './pages/dashboards/InvestigatorDashboard';
import SocDashboard from './pages/dashboards/SocDashboard';
import AuditorDashboard from './pages/dashboards/AuditorDashboard';
import OrgManagerDashboard from './pages/dashboards/OrgManagerDashboard';

// Enterprise Global Overview (PostgreSQL-backed) & Platform Pages
import GlobalOverview from './pages/GlobalOverview';
import Overview from './pages/Overview';
import Register from './pages/Register';
import Verify from './pages/Verify';
import Compare from './pages/Compare';
import ProvenanceHistory from './pages/ProvenanceHistory';
import AuditLedger from './pages/AuditLedger';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

// Forensic Intelligence & Verification Modules
import ForensicIntelligence from './pages/ForensicIntelligence';
import QRVerification from './pages/QRVerification';
import EvidenceCertificates from './pages/EvidenceCertificates';
import BatchVerification from './pages/BatchVerification';
import MetadataIntelligence from './pages/MetadataIntelligence';

// Integrity, Governance & Key Security Modules
import CheckpointRollback from './pages/CheckpointRollback';
import VersionHistory from './pages/VersionHistory';
import KeySecurityCentre from './pages/KeySecurityCentre';

// Knowledge & Threat Centers
import LearnExplore from './pages/LearnExplore';
import SecurityRiskCentre from './pages/SecurityRiskCentre';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public Authentication Route */}
        <Route path="/login" element={<Login />} />
        <Route path="/unauthorized" element={<Unauthorized />} />

        {/* Protected Enterprise Application Layout */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          {/* Default Dynamic Role Dashboard */}
          <Route index element={<RoleDashboardRouter />} />

          {/* Dedicated PostgreSQL-Backed Enterprise Global Overview */}
          <Route path="overview" element={<GlobalOverview />} />
          <Route path="global-overview" element={<GlobalOverview />} />

          {/* Dedicated Role Dashboards with Explicit RBAC Protections */}
          <Route
            path="dashboard/user"
            element={
              <ProtectedRoute requiredRole="USER">
                <UserDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="dashboard/admin"
            element={
              <ProtectedRoute requiredRole="ADMINISTRATOR">
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="dashboard/investigator"
            element={
              <ProtectedRoute requiredRole="FORENSIC_INVESTIGATOR">
                <InvestigatorDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="dashboard/soc"
            element={
              <ProtectedRoute requiredRole="SOC_ANALYST">
                <SocDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="dashboard/auditor"
            element={
              <ProtectedRoute requiredRole="AUDITOR">
                <AuditorDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="dashboard/manager"
            element={
              <ProtectedRoute requiredRole="ORGANIZATION_MANAGER">
                <OrgManagerDashboard />
              </ProtectedRoute>
            }
          />

          {/* Role Dashboard Direct Navigation Aliases */}
          <Route path="admin" element={<Navigate to="/dashboard/admin" replace />} />
          <Route path="investigator" element={<Navigate to="/dashboard/investigator" replace />} />
          <Route path="soc" element={<Navigate to="/dashboard/soc" replace />} />
          <Route path="auditor" element={<Navigate to="/dashboard/auditor" replace />} />
          <Route path="org-manager" element={<Navigate to="/dashboard/manager" replace />} />

          {/* Core Provenance Modules (Preserved) */}
          <Route path="register" element={<Register />} />
          <Route path="verify" element={<Verify />} />
          <Route path="compare" element={<Compare />} />
          <Route path="history" element={<ProvenanceHistory />} />
          <Route path="ledger" element={<AuditLedger />} />
          <Route path="reports" element={<Reports />} />

          {/* Advanced Verification & Intelligence (Preserved) */}
          <Route path="forensic-intelligence" element={<ForensicIntelligence />} />
          <Route path="qr-verification" element={<QRVerification />} />
          <Route path="evidence-certificates" element={<EvidenceCertificates />} />
          <Route path="batch-verification" element={<BatchVerification />} />
          <Route path="metadata-intelligence" element={<MetadataIntelligence />} />

          {/* Integrity, Governance & Key Security (Preserved) */}
          <Route path="checkpoints" element={<CheckpointRollback />} />
          <Route path="version-history" element={<VersionHistory />} />
          <Route path="key-security" element={<KeySecurityCentre />} />

          {/* Knowledge & Threat Centers (Preserved) */}
          <Route path="learn" element={<LearnExplore />} />
          <Route path="security-risks" element={<SecurityRiskCentre />} />

          {/* Settings (Preserved) */}
          <Route path="settings" element={<Settings />} />

          {/* Unified Route Aliases for 100% Navigation Compatibility */}
          <Route path="audit-ledger" element={<Navigate to="/ledger" replace />} />
          <Route path="pki-trust" element={<Navigate to="/key-security" replace />} />
          <Route path="checkpoint-monitor" element={<Navigate to="/checkpoints" replace />} />
          <Route path="compliance-report" element={<Navigate to="/reports" replace />} />
          <Route path="tamper-sandbox" element={<Navigate to="/compare" replace />} />
          <Route path="historical-verification" element={<Navigate to="/history" replace />} />
          <Route path="metadata-inspector" element={<Navigate to="/metadata-intelligence" replace />} />
          <Route path="signature-audit" element={<Navigate to="/forensic-intelligence" replace />} />
          <Route path="provenance-timeline" element={<Navigate to="/history" replace />} />
          <Route path="version-control" element={<Navigate to="/version-history" replace />} />
          <Route path="integrity-monitor" element={<Navigate to="/forensic-intelligence" replace />} />
          <Route path="revocation-audit" element={<Navigate to="/key-security" replace />} />
          <Route path="dashboard" element={<Navigate to="/" replace />} />

          {/* Catch-all redirect */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
