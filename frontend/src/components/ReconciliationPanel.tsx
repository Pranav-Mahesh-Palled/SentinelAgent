import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, ApiError } from '../api/client';
import type { ResponseActionDetail } from '../types';
import { Scale, CheckCircle2, AlertTriangle, Send } from 'lucide-react';

interface ReconciliationPanelProps {
  action: ResponseActionDetail | null;
  onReconciliationCompleted: () => void;
}

export const ReconciliationPanel: React.FC<ReconciliationPanelProps> = ({
  action,
  onReconciliationCompleted,
}) => {
  const { apiKey, principal } = useAuth();
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Form states
  const [resolution, setResolution] = useState<string>('confirm_succeeded');
  const [justification, setJustification] = useState<string>('');
  const [scenarioId, setScenarioId] = useState<string>('scenario-syn-manual');
  const [expectedProbes, setExpectedProbes] = useState<number>(1);
  const [generatedProbes, setGeneratedProbes] = useState<number>(1);
  const [capturedProbes, setCapturedProbes] = useState<number>(1);
  const [interceptedProbes, setInterceptedProbes] = useState<number>(1);
  const [telemetryVerified, setTelemetryVerified] = useState<boolean>(true);

  if (!action) return null;

  const isExecutionIndeterminate = action.execution_status === 'indeterminate';
  const isVerificationInconclusive = action.verification_status === 'inconclusive';

  if (!isExecutionIndeterminate && !isVerificationInconclusive) {
    return null;
  }

  const isEligible = principal?.role === 'approver' || principal?.role === 'admin';

  const handleExecutionReconciliation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey || !isEligible) return;

    if (!justification.trim() || justification.trim().length < 10) {
      setError('A comprehensive justification (at least 10 characters) is required.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setSuccess(null);

    try {
      await api.reconcileExecution(apiKey, action.response_action_id, {
        resolution,
        justification: justification.trim(),
        expected_version: action.version,
        evidence_ids: action.payload_json?.evidence_ids || [],
      });

      setSuccess('Execution reconciled successfully.');
      onReconciliationCompleted();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Execution reconciliation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleVerificationReconciliation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey || !isEligible) return;

    if (!justification.trim() || justification.trim().length < 10) {
      setError('A comprehensive justification (at least 10 characters) is required.');
      return;
    }

    // Mathematical invariant preview
    if (resolution === 'confirm_verified') {
      if (interceptedProbes !== generatedProbes || generatedProbes !== expectedProbes) {
        setError(
          'Mathematical Invariant Violation: For confirm_verified, expected_probes, generated_probes, and intercepted_probes must be strictly equal.'
        );
        return;
      }
    } else if (resolution === 'confirm_failed') {
      if (interceptedProbes !== 0) {
        setError('Mathematical Invariant Violation: For confirm_failed, intercepted_probes must be 0.');
        return;
      }
      if (!telemetryVerified) {
        setError('Mathematical Invariant Violation: For confirm_failed, telemetry coverage must be verified.');
        return;
      }
    }

    setIsSubmitting(true);
    setError(null);
    setSuccess(null);

    const now = new Date();
    const tenMinAgo = new Date(now.getTime() - 10 * 60 * 1000);

    try {
      await api.reconcileVerification(apiKey, action.response_action_id, {
        reconciled_action: resolution,
        justification: justification.trim(),
        expected_version: action.version,
        synthetic_scenario_id: scenarioId,
        observation_window_start: tenMinAgo.toISOString(),
        observation_window_end: now.toISOString(),
        expected_probes: expectedProbes,
        generated_probes: generatedProbes,
        captured_probes: capturedProbes,
        intercepted_probes: interceptedProbes,
        telemetry_coverage_verified: telemetryVerified,
        evidence_ids: action.payload_json?.evidence_ids || [],
      });

      setSuccess('Verification reconciled successfully.');
      onReconciliationCompleted();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Verification reconciliation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem', border: '1px solid rgba(245, 158, 11, 0.4)' }}>
      <div className="card-header">
        <div className="card-title">
          <Scale size={18} color="var(--accent-amber)" />
          <span>
            {isExecutionIndeterminate
              ? 'Manual Execution Reconciliation'
              : 'Manual Verification Reconciliation'}
          </span>
        </div>
        <span className="badge badge-amber">ACTION REQUIRED</span>
      </div>

      <div className="alert alert-warning">
        <AlertTriangle size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Operator Intervention Required:</strong> The containment state has reached an indeterminate or
          inconclusive state. Manual reconciliation requires an <strong>APPROVER</strong> or <strong>ADMIN</strong> to
          certify empirical findings with mathematical proof.
        </div>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="alert alert-success">
          <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
          <span>{success}</span>
        </div>
      )}

      {isExecutionIndeterminate ? (
        <form onSubmit={handleExecutionReconciliation}>
          <div className="form-group">
            <label className="form-label">Execution Resolution</label>
            <select
              className="form-select"
              value={resolution}
              onChange={(e) => setResolution(e.target.value)}
              disabled={isSubmitting}
            >
              <option value="confirm_succeeded">confirm_succeeded (Filter verified active via telemetry)</option>
              <option value="confirm_failed">confirm_failed (Filter execution aborted or reverted)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Audit Justification</label>
            <textarea
              className="form-textarea"
              placeholder="Cite telemetry, firewall audit logs, or manual tests justifying this reconciliation..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              disabled={isSubmitting}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button type="submit" className="btn btn-emerald" disabled={isSubmitting || !isEligible}>
              <Send size={15} />
              <span>{isSubmitting ? 'Submitting...' : 'Reconcile Execution'}</span>
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleVerificationReconciliation}>
          <div className="form-group">
            <label className="form-label">Verification Outcome</label>
            <select
              className="form-select"
              value={resolution}
              onChange={(e) => {
                const r = e.target.value;
                setResolution(r);
                if (r === 'confirm_failed') {
                  setInterceptedProbes(0);
                  setTelemetryVerified(true);
                } else if (r === 'confirm_verified') {
                  setInterceptedProbes(expectedProbes);
                }
              }}
              disabled={isSubmitting}
            >
              <option value="confirm_verified">confirm_verified (100% Intercepted & Proven)</option>
              <option value="confirm_failed">confirm_failed (0 Intercepted & Verified Open)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Synthetic Scenario ID</label>
            <input
              type="text"
              className="form-input font-mono"
              value={scenarioId}
              onChange={(e) => setScenarioId(e.target.value)}
              disabled={isSubmitting}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1rem' }}>
            <div>
              <label className="form-label" style={{ fontSize: '0.7rem' }}>Expected</label>
              <input
                type="number"
                className="form-input font-mono"
                value={expectedProbes}
                onChange={(e) => {
                  const val = parseInt(e.target.value) || 0;
                  setExpectedProbes(val);
                  setGeneratedProbes(val);
                  setCapturedProbes(val);
                  if (resolution === 'confirm_verified') setInterceptedProbes(val);
                }}
              />
            </div>
            <div>
              <label className="form-label" style={{ fontSize: '0.7rem' }}>Generated</label>
              <input
                type="number"
                className="form-input font-mono"
                value={generatedProbes}
                readOnly
              />
            </div>
            <div>
              <label className="form-label" style={{ fontSize: '0.7rem' }}>Captured</label>
              <input
                type="number"
                className="form-input font-mono"
                value={capturedProbes}
                readOnly
              />
            </div>
            <div>
              <label className="form-label" style={{ fontSize: '0.7rem' }}>Intercepted</label>
              <input
                type="number"
                className="form-input font-mono"
                value={interceptedProbes}
                readOnly
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Audit Justification & Telemetry Citation</label>
            <textarea
              className="form-textarea"
              placeholder="Cite pcap analysis or scenario execution logs justifying this outcome..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              disabled={isSubmitting}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button type="submit" className="btn btn-emerald" disabled={isSubmitting || !isEligible}>
              <Send size={15} />
              <span>{isSubmitting ? 'Submitting...' : 'Reconcile Verification'}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
