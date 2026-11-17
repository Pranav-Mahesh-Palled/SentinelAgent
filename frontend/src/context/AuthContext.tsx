import React, { createContext, useContext, useState, useCallback } from 'react';
import type { OperatorRole, OperatorPrincipal } from '../types';

interface AuthContextType {
  apiKey: string | null;
  principal: OperatorPrincipal | null;
  isLoading: boolean;
  error: string | null;
  login: (key: string) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // CRITICAL SECURITY INVARIANT:
  // Credentials are held EXCLUSIVELY in transient component memory.
  // Never stored in localStorage, sessionStorage, cookies, or indexedDB.
  // Wiped completely upon page reload or logout.
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [principal, setPrincipal] = useState<OperatorPrincipal | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (key: string): Promise<boolean> => {
    const trimmed = key.trim();
    if (!trimmed) {
      setError('API key cannot be empty');
      return false;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/v1/auth/me', {
        headers: {
          Authorization: `Bearer ${trimmed}`,
        },
      });

      if (!res.ok) {
        if (res.status === 401) {
          setError('Invalid API key: Authentication failed');
        } else if (res.status === 403) {
          setError('Forbidden: Account lacks required permissions');
        } else {
          setError(`Authentication error: HTTP ${res.status}`);
        }
        setIsLoading(false);
        return false;
      }

      const data = await res.json();
      setApiKey(trimmed);
      setPrincipal({
        operator_id: data.operator_id,
        role: data.role as OperatorRole,
        is_authenticated: true,
      });
      setIsLoading(false);
      return true;
    } catch (err: any) {
      setError(`Network error: ${err.message || 'Unable to connect to SentinelAgent backend'}`);
      setIsLoading(false);
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    // Explicitly zero out transient memory
    setApiKey(null);
    setPrincipal(null);
    setError(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        apiKey,
        principal,
        isLoading,
        error,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
