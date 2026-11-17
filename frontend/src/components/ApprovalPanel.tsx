import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, ApiError } from '../api/client';
import type { ResponseActionDetail } from '../types';
import { CheckSquare, XCircle, AlertTriangle, ShieldCheck, UserX, Ban } from 'lucide-react';

interface ApprovalPanelProps {
  pendingAction: ResponseActionDetail | null;
  onActionTransitioned: () => void;
}

export const ApprovalPanel: React.FC<ApprovalPanelProps> = ({
  pendingAction,
  onActionTransitioned,
}) => {
  const { apiKey, principal } = useAuth();
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState<string>('');
  const [showRejectBox, setShowRejectBox] = useState<boolean>(false);
  const [executionTimeout, setExecutionTimeout] = useState<number>(300);

  if (!pendingAction || pendingAction.approval_status !== 'pending_approval') {
    return (
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <CheckSquare size={18} color="var(--accent-purple)" />
            <span>Two-Person Approval Gate</span>
          </div>
          <span className="badge badge-gray">Idle</span>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          No pending containment proposals awaiting operator review.
        </p>
      </div>
    );
  }

  const isProposer = principal?.operator_id === pendingAction.proposed_by_operator_id;
  const isApproverRole = principal?.role === 'approver';
  const canApprove = isApproverRole && !isProposer;

  const handleApprove = async () => {
    if (!apiKey || !canApprove) return;
    setIsProcessing(true);
    setError(null);
    try {
      await api.approveAction(
        apiKey,
        pendingAction.response_action_id,
        pendingAction.version,
        `Approved by ${principal.operator_id} under two-person integrity.`,
        executionTimeout
      );
      onActionTransitioned();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Approval failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleReject = async () => {
    if (!apiKey || !isApproverRole) return;
    if (!rejectReason.trim() || rejectReason.trim().length < 5) {
      setError('A mandatory rejection reason (at least 5 characters) is required.');
      return;
    }

    setIsProcessing(true);
    setError(null);
    try {
      await api.rejectAction(
        apiKey,
        pendingAction.response_action_id,
        pendingAction.version,
        rejectReason.trim()
      );
      setShowRejectBox(false);
      setRejectReason('');
      onActionTransitioned();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Rejection failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCancel = async () => {
    if (!apiKey) return;
    setIsProcessing(true);
    setError(null);
    try {
      await api.cancelAction(
        apiKey,
        pendingAction.response_action_id,
        pendingAction.version,
        `Cancelled by ${principal?.operator_id}`
      );
      onActionTransitioned();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Cancellation failed');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem', border: '1px solid rgba(168, 85, 247, 0.4)' }}>
      <div className="card-header">
        <div className="card-title">
          <CheckSquare size={18} color="var(--accent-purple)" />
          <span>Two-Person Approval Gate</span>
        </div>
        <span className="badge badge-purple">ACTION REQUIRED</span>
      </div>

      {/* Two-Person Integrity Violations / Badges */}
      {isProposer && (
        <div className="alert alert-danger">
          <UserX size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Two-Person Integrity Enforced:</strong> You proposed this containment action as{' '}
            <code>{pendingAction.proposed_by_operator_id}</code>. To prevent single-operator compromise, a
            different authorized approver must inspect and authorize this action.
          </div>
        </div>
      )}

      {!isApproverRole && (
        <div className="alert alert-warning">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Role Restriction:</strong> Only operators with the <code>approver</code> role can authorize
            containment proposals. Your current role is <code>{principal?.role || 'unauthenticated'}</code>.
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Proposal Summary */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          padding: '0.85rem',
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          marginBottom: '1rem',
          fontSize: '0.85rem',
        }}
      >
        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>TARGET VALUE</div>
          <div className="font-mono" style={{ fontWeight: 700, color: 'var(--accent-rose)' }}>
            {pendingAction.target_value}
          </div>
        </div>

        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>PROPOSED BY</div>
          <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
            {pendingAction.proposed_by_operator_id}
          </div>
        </div>

        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>PROPOSAL FINGERPRINT</div>
          <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            {pendingAction.payload_sha256.substring(0, 16)}...
          </div>
        </div>

        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>EXPIRES AT</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-amber)' }}>
            {pendingAction.approval_expires_at
              ? new Date(pendingAction.approval_expires_at).toLocaleTimeString()
              : 'N/A'}
          </div>
        </div>
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
          PROPOSAL JUSTIFICATION:
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontStyle: 'italic' }}>
          "{pendingAction.justification}"
        </p>
      </div>

      {/* Rejection Form Box */}
      {showRejectBox && (
        <div
          style={{
            padding: '1rem',
            backgroundColor: 'rgba(244, 63, 94, 0.08)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '8px',
            marginBottom: '1rem',
          }}
        >
          <label className="form-label" style={{ color: 'var(--accent-rose)' }}>
            Mandatory Rejection Justification
          </label>
          <textarea
            className="form-textarea"
            placeholder="Explain why this proposal is rejected (e.g. false positive, insufficient evidence)..."
            value={rejectReason}
            onChange={(e) => setRejectReason(e.target.value)}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => setShowRejectBox(false)}
              disabled={isProcessing}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-rose"
              onClick={handleReject}
              disabled={isProcessing || !rejectReason.trim()}
            >
              Confirm Rejection
            </button>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button
          type="button"
          onClick={handleCancel}
          className="btn btn-outline"
          disabled={isProcessing}
          title="Cancel proposal"
        >
          <Ban size={15} />
          <span>Cancel Action</span>
        </button>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <span>Timeout:</span>
            <input
              type="number"
              className="form-input font-mono"
              style={{ width: '65px', padding: '0.25rem 0.4rem', fontSize: '0.75rem' }}
              value={executionTimeout}
              onChange={(e) => setExecutionTimeout(Math.max(30, parseInt(e.target.value) || 300))}
              title="Execution deadline timeout in seconds"
            />
            <span>s</span>
          </div>
          {!showRejectBox && (
            <button
              type="button"
              onClick={() => setShowRejectBox(true)}
              className="btn btn-outline"
              disabled={!isApproverRole || isProcessing}
            >
              <XCircle size={15} color="var(--accent-rose)" />
              <span>Reject</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleApprove}
            className="btn btn-emerald"
            disabled={!canApprove || isProcessing}
          >
            <ShieldCheck size={16} />
            <span>{isProcessing ? 'Authorizing...' : 'Authorize Containment'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
