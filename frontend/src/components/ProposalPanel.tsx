import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, ApiError } from '../api/client';
import type { IncidentListItem, EvidenceItem, ResponseActionDetail } from '../types';
import { ShieldAlert, CheckCircle2, AlertTriangle, Send, Clock, Lock } from 'lucide-react';

interface ProposalPanelProps {
  incident: IncidentListItem;
  actions: ResponseActionDetail[];
  onProposalCreated: () => void;
}

export const ProposalPanel: React.FC<ProposalPanelProps> = ({
  incident,
  actions,
  onProposalCreated,
}) => {
  const { apiKey, principal } = useAuth();
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState<string[]>([]);
  const [justification, setJustification] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [invId, setInvId] = useState<string | null>(null);

  const isInvestigationComplete = incident.investigation_status === 'completed';

  // Find any active pending proposal
  const activeProposal = actions.find(
    (a) => a.approval_status === 'pending_approval' || a.execution_status === 'running'
  );

  useEffect(() => {
    const loadEvidence = async () => {
      if (!apiKey) return;
      setError(null);
      try {
        // Find investigation ID from actions or lookup
        const actionsForInc = await api.getActionsForIncident(apiKey, incident.incident_id);
        let currentInvId = actionsForInc[0]?.investigation_id;

        if (!currentInvId) {
          // If no actions exist yet, query incident details
          const incDetail = await api.getIncident(apiKey, incident.incident_id);
          // @ts-ignore
          currentInvId = incDetail.investigation_id;
        }

        if (currentInvId) {
          setInvId(currentInvId);
          const evItems = await api.getInvestigationEvidence(apiKey, currentInvId);
          setEvidenceList(evItems);
          // Default select all available evidence items
          setSelectedEvidenceIds(evItems.map((e) => e.evidence_id));
        }
      } catch (err: any) {
        setError(err instanceof ApiError ? err.message : 'Failed to load investigation evidence');
      }
    };

    loadEvidence();
  }, [apiKey, incident.incident_id]);

  const handleToggleEvidence = (id: string) => {
    setSelectedEvidenceIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handlePropose = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey || !invId) return;

    if (!justification.trim() || justification.trim().length < 10) {
      setError('Justification must be at least 10 characters explaining why containment is required.');
      return;
    }

    if (selectedEvidenceIds.length === 0) {
      setError('You must bind at least one authoritative evidence item to the proposal.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      await api.createProposal(apiKey, incident.incident_id, {
        investigation_id: invId,
        justification: justification.trim(),
        evidence_ids: selectedEvidenceIds,
      });

      setSuccessMsg('Containment proposal created successfully. Awaiting two-person approval.');
      setJustification('');
      onProposalCreated();
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to create proposal');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <div className="card-header">
        <div className="card-title">
          <ShieldAlert size={18} color="var(--accent-cyan)" />
          <span>Response Proposal Generator</span>
        </div>
        <div>
          <span className="badge badge-indigo">simulation.block_source_ip</span>
        </div>
      </div>

      {/* Investigation Status Warning */}
      {!isInvestigationComplete ? (
        <div className="alert alert-warning">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Investigation Incomplete:</strong> Containment proposals are strictly forbidden until
            the incident investigation reaches <code>completed</code> status. Current status:{' '}
            <strong>{incident.investigation_status}</strong>.
          </div>
        </div>
      ) : null}

      {/* Active Proposal Conflict Warning */}
      {activeProposal && (
        <div className="alert alert-info">
          <Clock size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Active Action In Progress:</strong> An active response action is currently in status{' '}
            <code>{activeProposal.approval_status}</code> (Execution: <code>{activeProposal.execution_status}</code>).
            New proposals cannot conflict with active containment.
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="alert alert-success">
          <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
          <span>{successMsg}</span>
        </div>
      )}

      <form onSubmit={handlePropose}>
        {/* Immutable Target IP Field */}
        <div className="form-group">
          <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Lock size={13} color="var(--accent-emerald)" />
            <span>Target IP (Authoritative Provenance — Immutable)</span>
          </label>
          <div
            className="form-input font-mono"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--accent-emerald)',
              fontWeight: 700,
              cursor: 'not-allowed',
            }}
          >
            {incident.source_ip}
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Derived directly from the verified incident record in PostgreSQL. Client override strictly prohibited.
          </p>
        </div>

        {/* Evidence Binding */}
        <div className="form-group">
          <label className="form-label">
            Authoritative Investigation Evidence ({selectedEvidenceIds.length}/{evidenceList.length} Selected)
          </label>

          {evidenceList.length === 0 ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>
              {invId ? 'No evidence items recorded for this investigation.' : 'Loading evidence items...'}
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
                maxHeight: '160px',
                overflowY: 'auto',
                backgroundColor: 'var(--bg-secondary)',
                padding: '0.5rem',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {evidenceList.map((item) => {
                const isChecked = selectedEvidenceIds.includes(item.evidence_id);
                return (
                  <label
                    key={item.evidence_id}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.6rem',
                      padding: '0.4rem',
                      borderRadius: '4px',
                      backgroundColor: isChecked ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
                      cursor: 'pointer',
                      fontSize: '0.8rem',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => handleToggleEvidence(item.evidence_id)}
                      disabled={!isInvestigationComplete || !!activeProposal || isSubmitting}
                      style={{ marginTop: '3px' }}
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {item.evidence_type} ({item.source_artifact})
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {new Date(item.collected_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                        SHA-256: {item.sha256_hash.substring(0, 20)}...
                      </div>
                    </div>
                  </label>
                );
              })}
            </div>
          )}
        </div>

        {/* Justification */}
        <div className="form-group">
          <label className="form-label" htmlFor="justification">
            Security Containment Justification
          </label>
          <textarea
            id="justification"
            placeholder="Explain root cause analysis and why blocking this IP prevents further unauthorized access..."
            className="form-textarea"
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            disabled={!isInvestigationComplete || !!activeProposal || isSubmitting}
          />
        </div>

        {/* Proposer Info & Submit */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Proposing as: <strong style={{ color: 'var(--accent-cyan)' }}>{principal?.operator_id}</strong>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={!isInvestigationComplete || !!activeProposal || isSubmitting || !justification.trim()}
          >
            <Send size={15} />
            <span>{isSubmitting ? 'Submitting SAC-JSON-v1...' : 'Propose Containment Action'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
