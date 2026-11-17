import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import type { ResponseActionDetail, ResponseAuditEvent } from '../types';
import { History, User, Clock, ArrowRight } from 'lucide-react';

interface AuditTrailPanelProps {
  action: ResponseActionDetail | null;
  refreshTrigger: number;
}

export const AuditTrailPanel: React.FC<AuditTrailPanelProps> = ({ action, refreshTrigger }) => {
  const { apiKey } = useAuth();
  const [events, setEvents] = useState<ResponseAuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    const fetchAudit = async () => {
      if (!apiKey || !action) return;
      setIsLoading(true);
      try {
        const data = await api.getAuditEvents(apiKey, action.response_action_id);
        setEvents(data);
      } catch {
        // Silently handled
      } finally {
        setIsLoading(false);
      }
    };

    fetchAudit();
  }, [apiKey, action?.response_action_id, refreshTrigger]);

  if (!action) return null;

  const getEventBadgeClass = (eventType: string) => {
    if (eventType.includes('approved') || eventType.includes('verified') || eventType.includes('succeeded')) {
      return 'badge-emerald';
    }
    if (eventType.includes('rejected') || eventType.includes('failed') || eventType.includes('cancelled')) {
      return 'badge-rose';
    }
    if (eventType.includes('reconcile') || eventType.includes('inconclusive')) {
      return 'badge-amber';
    }
    return 'badge-cyan';
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <History size={18} color="var(--accent-indigo)" />
          <span>Immutable Audit Trail</span>
          <span className="badge badge-gray" style={{ marginLeft: '0.25rem' }}>
            {events.length} Event{events.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Sequence Guaranteed by DB Triggers
        </div>
      </div>

      {events.length === 0 ? (
        <div style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center' }}>
          {isLoading ? 'Loading audit trail...' : 'No audit events recorded yet.'}
        </div>
      ) : (
        <div className="timeline" style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
          {events.map((ev) => (
            <div key={ev.response_audit_event_id} className="timeline-item">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '0.25rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    #{ev.sequence_number}
                  </span>
                  <span className={`badge ${getEventBadgeClass(ev.event_type)}`}>{ev.event_type}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Clock size={12} />
                  <span>{new Date(ev.created_at).toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Status Transition Preview */}
              {(ev.from_approval_status || ev.from_execution_status || ev.from_verification_status) && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontSize: '0.75rem',
                    color: 'var(--text-secondary)',
                    margin: '0.2rem 0',
                  }}
                >
                  <span className="font-mono">
                    {ev.from_approval_status || ev.from_execution_status || ev.from_verification_status}
                  </span>
                  <ArrowRight size={11} />
                  <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {ev.to_approval_status || ev.to_execution_status || ev.to_verification_status}
                  </span>
                </div>
              )}

              {/* Reason / Details */}
              {ev.reason && (
                <div
                  style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                    backgroundColor: 'var(--bg-secondary)',
                    padding: '0.35rem 0.6rem',
                    borderRadius: '4px',
                    margin: '0.3rem 0',
                  }}
                >
                  "{ev.reason}"
                </div>
              )}

              {/* Actor & Role snapshot */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <User size={11} />
                  <span>{ev.actor_operator_id} ({ev.actor_role_snapshot})</span>
                </div>
                <div className="font-mono" style={{ fontSize: '0.7rem' }}>
                  Fingerprint: {ev.payload_sha256_snapshot.substring(0, 12)}...
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
