import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, ApiError } from '../api/client';
import type { ResponseActionDetail, ResponseActionVerificationDetails } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, RefreshCw, Radio } from 'lucide-react';

interface VerificationPanelProps {
  action: ResponseActionDetail | null;
  onVerificationTriggered: () => void;
  refreshTrigger: number;
}

export const VerificationPanel: React.FC<VerificationPanelProps> = ({
  action,
  onVerificationTriggered,
  refreshTrigger,
}) => {
  const { apiKey, principal } = useAuth();
  const [details, setDetails] = useState<ResponseActionVerificationDetails | null>(null);
  const [isReVerifying, setIsReVerifying] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchVerification = async () => {
      if (!apiKey || !action) return;
      try {
        const data = await api.getVerificationDetails(apiKey, action.response_action_id);
        setDetails(data);
      } catch {
        // Handled silently
      }
    };

    fetchVerification();
  }, [apiKey, action?.response_action_id, refreshTrigger]);

  if (!action) return null;

  const canReVerify =
    action.execution_status === 'succeeded' &&
    (principal?.role === 'approver' || principal?.role === 'admin') &&
    action.verification_status !== 'running' &&
    action.verification_status !== 'queued';

  const handleReVerify = async () => {
    if (!apiKey || !canReVerify) return;
    setIsReVerifying(true);
    setError(null);
    try {
      await api.reVerifyAction(apiKey, action.response_action_id);
      onVerificationTriggered();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Re-verification failed');
    } finally {
      setIsReVerifying(false);
    }
  };

  const renderStatusBanner = () => {
    switch (action.verification_status) {
      case 'verified':
        return (
          <div className="alert alert-success">
            <CheckCircle2 size={20} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>CONTAINMENT VERIFIED</div>
              <p style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                Simulated blocklist filter active. 100% of synthetic validation probes were successfully
                intercepted and dropped according to authoritative telemetry.
              </p>
            </div>
          </div>
        );
      case 'failed':
        return (
          <div className="alert alert-danger">
            <XCircle size={20} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>CONTAINMENT FAILED</div>
              <p style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                Zero synthetic probes were intercepted. Filter rule is not effective or simulated traffic
                bypassed enforcement.
              </p>
            </div>
          </div>
        );
      case 'inconclusive':
        return (
          <div className="alert alert-warning">
            <AlertTriangle size={20} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>VERIFICATION INCONCLUSIVE</div>
              <p style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                A mathematical discrepancy exists between expected probes, generated probes, and telemetry
                captures. Manual operator reconciliation is required.
              </p>
            </div>
          </div>
        );
      case 'running':
      case 'queued':
        return (
          <div className="alert alert-info">
            <Radio size={20} className="animate-spin" style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>VERIFICATION IN PROGRESS</div>
              <p style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                Worker is executing synthetic probes from the trusted scenario registry and capturing empirical
                evidence.
              </p>
            </div>
          </div>
        );
      case 'not_started':
      default:
        return (
          <div
            style={{
              padding: '1rem',
              backgroundColor: 'var(--bg-secondary)',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              marginBottom: '1rem',
              fontSize: '0.85rem',
              color: 'var(--text-muted)',
            }}
          >
            Verification has not started yet. Probes execute automatically after simulation succeeds.
          </div>
        );
    }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <div className="card-header">
        <div className="card-title">
          <Radio size={18} color="var(--accent-cyan)" />
          <span>Synthetic Verification & Probing</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {action.execution_status === 'succeeded' && (
            <button
              type="button"
              onClick={handleReVerify}
              className="btn btn-outline"
              disabled={!canReVerify || isReVerifying}
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }}
              title="Enqueue a new verification replay"
            >
              <RefreshCw size={12} className={isReVerifying ? 'animate-spin' : ''} />
              <span>{isReVerifying ? 'Queueing...' : 'Re-verify Containment'}</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {renderStatusBanner()}

      {/* Synthetic Probes Summary */}
      {details?.probes && details.probes.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <div
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-secondary)',
              marginBottom: '0.5rem',
            }}
          >
            SYNTHETIC PROBE EVALUATIONS ({details.probes.length})
          </div>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '0.4rem',
              backgroundColor: 'var(--bg-secondary)',
              padding: '0.5rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              maxHeight: '140px',
              overflowY: 'auto',
            }}
          >
            {details.probes.map((probe) => (
              <div
                key={probe.probe_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  fontSize: '0.8rem',
                  padding: '0.3rem 0.5rem',
                  borderRadius: '4px',
                  backgroundColor: 'var(--bg-card)',
                }}
              >
                <span className="font-mono">{probe.probe_id}</span>
                {probe.intercepted ? (
                  <span className="badge badge-emerald" style={{ fontSize: '0.65rem' }}>
                    INTERCEPTED
                  </span>
                ) : (
                  <span className="badge badge-rose" style={{ fontSize: '0.65rem' }}>
                    NOT INTERCEPTED
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Reconciliation record note */}
      {details?.reconciliation_record && (
        <div
          style={{
            marginTop: '1rem',
            padding: '0.75rem',
            backgroundColor: 'rgba(99, 102, 241, 0.08)',
            border: '1px solid rgba(99, 102, 241, 0.25)',
            borderRadius: '6px',
            fontSize: '0.8rem',
          }}
        >
          <div style={{ fontWeight: 600, color: 'var(--accent-indigo)', marginBottom: '0.2rem' }}>
            MANUAL RECONCILIATION RECORD ATTACHED
          </div>
          <div>Resolution: <strong>{details.reconciliation_record.resolution}</strong></div>
          <div>Reconciled By: <strong>{details.reconciliation_record.actor_operator_id}</strong></div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Reconciled at: {new Date(details.reconciliation_record.reconciled_at).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
};
