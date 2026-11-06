import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function RoleDashboardRouter() {
  const { role } = useAuth();

  switch (role) {
    case 'ADMINISTRATOR':
      return <Navigate to="/dashboard/admin" replace />;
    case 'FORENSIC_INVESTIGATOR':
      return <Navigate to="/dashboard/investigator" replace />;
    case 'SOC_ANALYST':
      return <Navigate to="/dashboard/soc" replace />;
    case 'AUDITOR':
      return <Navigate to="/dashboard/auditor" replace />;
    case 'ORGANIZATION_MANAGER':
      return <Navigate to="/dashboard/manager" replace />;
    case 'USER':
    default:
      return <Navigate to="/dashboard/user" replace />;
  }
}

