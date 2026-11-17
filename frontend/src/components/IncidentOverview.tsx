import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, ApiError } from '../api/client';
import type { IncidentListItem } from '../types';
import { AlertCircle, RefreshCw, ShieldAlert, Search } from 'lucide-react';

interface IncidentOverviewProps {
  selectedIncidentId: string | null;
  onSelectIncident: (incident: IncidentListItem) => void;
  refreshTrigger: number;
}

export const IncidentOverview: React.FC<IncidentOverviewProps> = ({
  selectedIncidentId,
  onSelectIncident,
  refreshTrigger,
}) => {
  const { apiKey } = useAuth();
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState<string>('');

  const fetchIncidents = async () => {
    if (!apiKey) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getIncidents(apiKey);
      setIncidents(data);
      if (!selectedIncidentId && data.length > 0) {
        onSelectIncident(data[0]);
      }
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to load incidents');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [apiKey, refreshTrigger]);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <span className="badge badge-rose">CRITICAL</span>;
      case 'high':
        return <span className="badge badge-amber">HIGH</span>;
      case 'medium':
        return <span className="badge badge-indigo">MEDIUM</span>;
      default:
        return <span className="badge badge-gray">{severity}</span>;
    }
  };

  const getInvestigationBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return <span className="badge badge-emerald">INVESTIGATED</span>;
      case 'in_progress':
        return <span className="badge badge-cyan">ANALYZING</span>;
      default:
        return <span className="badge badge-gray">{status}</span>;
    }
  };

  const getVerificationBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'verified':
        return <span className="badge badge-emerald">VERIFIED</span>;
      case 'failed':
        return <span className="badge badge-rose">FAILED</span>;
      case 'inconclusive':
        return <span className="badge badge-amber">INCONCLUSIVE</span>;
      default:
        return <span className="badge badge-gray">{status}</span>;
    }
  };

  const filteredIncidents = incidents.filter(
    (inc) =>
      inc.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      inc.source_ip.toLowerCase().includes(searchFilter.toLowerCase()) ||
      inc.incident_type.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="card" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <div className="card-title">
          <ShieldAlert size={20} color="var(--accent-rose)" />
          <span>Security Incidents</span>
          <span className="badge badge-cyan" style={{ marginLeft: '0.25rem' }}>
            {incidents.length}
          </span>
        </div>
        <button
          onClick={fetchIncidents}
          className="btn btn-outline"
          style={{ padding: '0.35rem 0.6rem' }}
          disabled={isLoading}
          title="Refresh incidents"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Filter */}
      <div style={{ marginBottom: '1rem', position: 'relative' }}>
        <input
          type="text"
          placeholder="Filter by IP, type, or title..."
          className="form-input"
          style={{ paddingLeft: '2rem', fontSize: '0.8rem' }}
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
        />
        <Search
          size={14}
          color="var(--text-muted)"
          style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }}
        />
      </div>

      {error && (
        <div className="alert alert-danger" style={{ fontSize: '0.8rem', padding: '0.5rem 0.75rem' }}>
          <AlertCircle size={15} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Incident List */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
        {filteredIncidents.length === 0 ? (
          <div
            style={{
              padding: '2rem 1rem',
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: '0.875rem',
            }}
          >
            {isLoading ? 'Loading active incidents...' : 'No incidents match your filter'}
          </div>
        ) : (
          filteredIncidents.map((incident) => {
            const isSelected = incident.incident_id === selectedIncidentId;
            return (
              <div
                key={incident.incident_id}
                onClick={() => onSelectIncident(incident)}
                style={{
                  padding: '0.85rem',
                  borderRadius: '8px',
                  backgroundColor: isSelected ? 'var(--bg-card-hover)' : 'var(--bg-secondary)',
                  border: isSelected ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span className="font-mono" style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                    {incident.source_ip}
                  </span>
                  {getSeverityBadge(incident.severity)}
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', fontWeight: 500 }}>
                  {incident.title}
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' }}>
                  {getInvestigationBadge(incident.investigation_status)}
                  {incident.verification_status !== 'not_started' && getVerificationBadge(incident.verification_status)}
                  {incident.response_actions_count > 0 && (
                    <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                      {incident.response_actions_count} Action{incident.response_actions_count > 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
