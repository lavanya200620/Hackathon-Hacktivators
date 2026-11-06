import React, { createContext, useContext, useState, useEffect } from 'react';
import { authService, ENTERPRISE_ROLES, ROLE_LABELS, ROLE_BADGE_COLORS, DEFAULT_ACCOUNTS } from '../services/authService.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => authService.getCurrentUser());
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Sync state if session changes
    setUser(authService.getCurrentUser());
  }, []);

  const login = async (email, password) => {
    setLoading(true);
    try {
      const res = await authService.login(email, password);
      setUser(res.user);
      return res;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
  };

  const switchRole = async (targetRole) => {
    setLoading(true);
    try {
      const updated = await authService.switchRole(targetRole);
      setUser({ ...updated });
      return updated;
    } finally {
      setLoading(false);
    }
  };

  const hasPermission = (perm) => {
    return authService.hasPermission(perm);
  };

  const hasRole = (role) => {
    return user && user.role === role;
  };

  const value = {
    user,
    role: user ? user.role : null,
    isAuthenticated: !!user,
    permissions: user ? user.permissions : [],
    login,
    logout,
    switchRole,
    hasPermission,
    hasRole,
    loading,
    ENTERPRISE_ROLES,
    ROLE_LABELS,
    ROLE_BADGE_COLORS,
    DEFAULT_ACCOUNTS,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

