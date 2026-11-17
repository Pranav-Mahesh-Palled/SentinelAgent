import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Key, AlertTriangle, UserCheck, X } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const { login, isLoading, error } = useAuth();
  const [apiKeyInput, setApiKeyInput] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const success = await login(apiKeyInput);
    if (success) {
      setApiKeyInput('');
      onClose();
    }
  };

  const handleSelectPreset = async (presetKey: string) => {
    setApiKeyInput(presetKey);
    const success = await login(presetKey);
    if (success) {
      setApiKeyInput('');
      onClose();
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Key size={20} color="var(--accent-cyan)" />
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>Operator Authentication</h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '4px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        <div className="alert alert-warning">
          <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Transient Memory Invariant:</strong>
            <p style={{ marginTop: '0.2rem', fontSize: '0.8rem', color: '#fef3c7' }}>
              Your Bearer API key is loaded strictly into volatile React application memory. It is
              NEVER saved to localStorage, sessionStorage, or browser cookies. Closing the tab or
              refreshing wipes all credentials instantly.
            </p>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger">
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="apiKey">
              Bearer API Key
            </label>
            <input
              id="apiKey"
              type="password"
              placeholder="sa_analyst_test_key_secret_..."
              className="form-input font-mono"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              disabled={isLoading}
              autoFocus
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
            <button type="button" onClick={onClose} className="btn btn-outline" disabled={isLoading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isLoading || !apiKeyInput.trim()}>
              {isLoading ? 'Verifying with API...' : 'Authenticate'}
            </button>
          </div>
        </form>

        <div
          style={{
            marginTop: '1.75rem',
            paddingTop: '1.25rem',
            borderTop: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.75rem' }}>
            <UserCheck size={16} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Quick Operator Switch (Demonstration Profiles)
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-outline"
              style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '0.5rem 0.75rem' }}
              onClick={() => handleSelectPreset('sa_analyst_test_key_secret_1234567890abcdef')}
              disabled={isLoading}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                  Analyst Alice
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Proposals & Investigations</div>
              </div>
            </button>

            <button
              type="button"
              className="btn btn-outline"
              style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '0.5rem 0.75rem' }}
              onClick={() => handleSelectPreset('sa_approver1_test_key_secret_abcdef123456789')}
              disabled={isLoading}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--accent-purple)' }}>
                  Approver Bob
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Two-Person Integrity Approver</div>
              </div>
            </button>

            <button
              type="button"
              className="btn btn-outline"
              style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '0.5rem 0.75rem' }}
              onClick={() => handleSelectPreset('sa_approver2_test_key_secret_9876543210fedcba')}
              disabled={isLoading}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--accent-purple)' }}>
                  Approver Dave
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Reconciliation & Replays</div>
              </div>
            </button>

            <button
              type="button"
              className="btn btn-outline"
              style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '0.5rem 0.75rem' }}
              onClick={() => handleSelectPreset('sa_admin_test_key_secret_99999999999999999999')}
              disabled={isLoading}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--accent-rose)' }}>
                  Admin Charlie
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>System Audit & Controls</div>
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
