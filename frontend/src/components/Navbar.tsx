import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, LogOut, Terminal } from 'lucide-react';

interface NavbarProps {
  onOpenLogin: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onOpenLogin }) => {
  const { principal, logout } = useAuth();

  const getRoleBadgeClass = (role: string) => {
    switch (role) {
      case 'approver':
        return 'badge-purple';
      case 'admin':
        return 'badge-rose';
      case 'analyst':
      default:
        return 'badge-cyan';
    }
  };

  return (
    <header
      style={{
        backgroundColor: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-subtle)',
        padding: '0.75rem 1.5rem',
      }}
    >
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div
            style={{
              width: '38px',
              height: '38px',
              borderRadius: '8px',
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
              border: '1px solid rgba(6, 182, 212, 0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-cyan)',
            }}
          >
            <Shield size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: 700, fontSize: '1.15rem', letterSpacing: '-0.02em' }}>
                SentinelAgent
              </span>
              <span className="badge badge-indigo">Phase 11</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Response Orchestration & Verification Center
            </p>
          </div>
        </div>

        {/* Status Mode Banner */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1rem',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              backgroundColor: 'var(--bg-card)',
              padding: '0.35rem 0.75rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <Terminal size={14} color="var(--accent-emerald)" />
            <span>Simulation Mode</span>
            <span style={{ color: 'var(--text-muted)' }}>(Safe Local Execution)</span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              backgroundColor: 'var(--bg-card)',
              padding: '0.35rem 0.75rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <Lock size={14} color="var(--accent-amber)" />
            <span>Transient Memory Only</span>
          </div>
        </div>

        {/* Operator Profile / Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {principal ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', justifyContent: 'flex-end' }}>
                  <User size={14} color="var(--text-secondary)" />
                  <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{principal.operator_id}</span>
                </div>
                <div>
                  <span className={`badge ${getRoleBadgeClass(principal.role)}`}>
                    {principal.role}
                  </span>
                </div>
              </div>

              <button
                onClick={logout}
                className="btn btn-outline"
                style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
                title="Wipe transient credentials and log out"
              >
                <LogOut size={14} />
                <span>Disconnect</span>
              </button>
            </div>
          ) : (
            <button onClick={onOpenLogin} className="btn btn-primary">
              <Lock size={15} />
              <span>Connect Operator Key</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
