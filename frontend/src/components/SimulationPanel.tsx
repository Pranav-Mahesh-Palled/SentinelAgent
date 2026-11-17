import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import type { ResponseActionDetail, ResponseActionSimulationDetails } from '../types';
import { Terminal, ShieldCheck, Database, Cpu } from 'lucide-react';

interface SimulationPanelProps {
  action: ResponseActionDetail | null;
  refreshTrigger: number;
}

export const SimulationPanel: React.FC<SimulationPanelProps> = ({ action, refreshTrigger }) => {
  const { apiKey } = useAuth();
  const [details, setDetails] = useState<ResponseActionSimulationDetails | null>(null);

  useEffect(() => {
    const fetchSimulation = async () => {
      if (!apiKey || !action) return;
      try {
        const data = await api.getSimulationDetails(apiKey, action.response_action_id);
        setDetails(data);
      } catch {
        // Handled silently
      }
    };

    fetchSimulation();
  }, [apiKey, action?.response_action_id, refreshTrigger]);

  if (!action) return null;

  const getExecutionBadge = (status: string) => {
    switch (status) {
      case 'succeeded':
        return <span className="badge badge-emerald">SUCCEEDED</span>;
      case 'running':
        return <span className="badge badge-cyan">RUNNING</span>;
      case 'queued':
        return <span className="badge badge-indigo">QUEUED</span>;
      case 'indeterminate':
        return <span className="badge badge-amber">INDETERMINATE</span>;
      case 'failed':
      case 'expired':
        return <span className="badge badge-rose">{status.toUpperCase()}</span>;
      case 'not_queued':
      default:
        return <span className="badge badge-gray">{status.toUpperCase()}</span>;
    }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <div className="card-header">
        <div className="card-title">
          <Terminal size={18} color="var(--accent-emerald)" />
          <span>Local Simulation Engine</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {getExecutionBadge(action.execution_status)}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        {/* Simulation Ledger Record */}
        <div
          style={{
            padding: '1rem',
            backgroundColor: 'var(--bg-secondary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.75rem' }}>
            <Database size={16} color="var(--accent-emerald)" />
            <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Simulated Blocklist Ledger</span>
          </div>

          {details?.simulated_entry ? (
            <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Simulated Rule ID:</span>
                <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                  {details.simulated_entry.simulated_rule_id}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Target IP Filtered:</span>
                <span className="font-mono" style={{ fontWeight: 700, color: 'var(--accent-emerald)' }}>
                  {details.simulated_entry.target_ip}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Simulated At:</span>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {new Date(details.simulated_entry.simulated_at).toLocaleString()}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              {action.execution_status === 'not_queued'
                ? 'Simulation not queued. Awaiting proposal approval.'
                : 'No active simulation ledger entry found for this action.'}
            </div>
          )}
        </div>

        {/* Transactional Outbox Telemetry */}
        <div
          style={{
            padding: '1rem',
            backgroundColor: 'var(--bg-secondary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.75rem' }}>
            <Cpu size={16} color="var(--accent-cyan)" />
            <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Transactional Outbox Telemetry</span>
          </div>

          {details?.outbox ? (
            <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Outbox Status:</span>
                <span className="font-mono" style={{ textTransform: 'uppercase', color: 'var(--accent-cyan)' }}>
                  {details.outbox.status}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Worker Attempts:</span>
                <span className="font-mono">
                  {details.outbox.attempt_count} / {details.outbox.max_attempts}
                </span>
              </div>
              {details.outbox.completed_at && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Completed At:</span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {new Date(details.outbox.completed_at).toLocaleTimeString()}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              No active execution outbox command found.
            </div>
          )}
        </div>
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          fontSize: '0.75rem',
          color: 'var(--accent-emerald)',
          backgroundColor: 'rgba(16, 185, 129, 0.08)',
          padding: '0.4rem 0.75rem',
          borderRadius: '4px',
          border: '1px solid rgba(16, 185, 129, 0.25)',
        }}
      >
        <ShieldCheck size={14} />
        <span>Lease Tokens & Database Secrets Stripped by API Security Gateway</span>
      </div>
    </div>
  );
};
