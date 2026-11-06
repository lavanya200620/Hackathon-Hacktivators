import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function ProtectedRoute({ children, requiredRole, requiredPermission }) {
  const { user, isAuthenticated, hasPermission, hasRole } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && !hasRole(requiredRole) && user.role !== 'ADMINISTRATOR') {
    return <Navigate to="/unauthorized" state={{ requiredRole, attemptedPath: location.pathname }} replace />;
  }

  if (requiredPermission && !hasPermission(requiredPermission) && user.role !== 'ADMINISTRATOR') {
    return <Navigate to="/unauthorized" state={{ requiredPermission, attemptedPath: location.pathname }} replace />;
  }

  return children;
}

