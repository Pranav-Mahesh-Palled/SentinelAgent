import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { LoginModal } from './components/LoginModal';
import { IncidentOverview } from './components/IncidentOverview';
import { ProposalPanel } from './components/ProposalPanel';
import { ApprovalPanel } from './components/ApprovalPanel';
import { SimulationPanel } from './components/SimulationPanel';
import { VerificationPanel } from './components/VerificationPanel';
import { ReconciliationPanel } from './components/ReconciliationPanel';
import { AuditTrailPanel } from './components/AuditTrailPanel';
import { api } from './api/client';
import type { IncidentListItem, ResponseActionDetail } from './types';
import { Key, RefreshCw } from 'lucide-react';

const DashboardContent: React.FC = () => {
  const { apiKey } = useAuth();
  const [isLoginOpen, setIsLoginOpen] = useState<boolean>(false);
  const [selectedIncident, setSelectedIncident] = useState<IncidentListItem | null>(null);
  const [actions, setActions] = useState<ResponseActionDetail[]>([]);
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  const triggerRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  // Fetch actions whenever selected incident changes or refresh triggers
  useEffect(() => {
    const loadActions = async () => {
      if (!apiKey || !selectedIncident) return;
      try {
        const data = await api.getActionsForIncident(apiKey, selectedIncident.incident_id);
        setActions(data);
        if (data.length > 0) {
          if (!selectedActionId || !data.some((a) => a.response_action_id === selectedActionId)) {
            setSelectedActionId(data[0].response_action_id);
          }
        } else {
          setSelectedActionId(null);
        }
      } catch {
        // Silently handled
      }
    };

    loadActions();
  }, [apiKey, selectedIncident?.incident_id, refreshTrigger]);

  const selectedAction = actions.find((a) => a.response_action_id === selectedActionId) || null;
  const pendingAction = actions.find((a) => a.approval_status === 'pending_approval') || null;

  return (
    <div className="app-container">
      <Navbar onOpenLogin={() => setIsLoginOpen(true)} />

      <LoginModal isOpen={isLoginOpen} onClose={() => setIsLoginOpen(false)} />

      <main className="main-content">
        {!apiKey ? (
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              textAlign: 'center',
              padding: '3rem 1rem',
            }}
          >
            <div
              style={{
                width: '64px',
                height: '64px',
                borderRadius: '16px',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-cyan)',
                marginBottom: '1.5rem',
              }}
            >
              <Key size={32} />
            </div>

            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.5rem' }}>
              SentinelAgent Operator Authentication
            </h1>

            <p style={{ color: 'var(--text-secondary)', maxWidth: '520px', marginBottom: '2rem', fontSize: '0.95rem' }}>
              Connect using your operator API Bearer key to manage containment actions, inspect simulation
              telemetry, authorize response proposals, and verify synthetic scenario interception.
            </p>

            <button onClick={() => setIsLoginOpen(true)} className="btn btn-primary" style={{ padding: '0.75rem 1.5rem' }}>
              <Key size={16} />
              <span>Connect Operator Key</span>
            </button>
          </div>
        ) : (
          <div className="grid-dashboard">
            {/* Left Column: Incidents List */}
            <IncidentOverview
              selectedIncidentId={selectedIncident?.incident_id || null}
              onSelectIncident={(inc) => {
                setSelectedIncident(inc);
                triggerRefresh();
              }}
              refreshTrigger={refreshTrigger}
            />

            {/* Right Column: Selected Incident & Action Panels */}
            {selectedIncident ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                {/* Incident Header Card */}
                <div className="card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <span className="font-mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--accent-emerald)' }}>
                          {selectedIncident.source_ip}
                        </span>
                        <span className="badge badge-cyan">{selectedIncident.incident_type}</span>
                        <span className="badge badge-rose">{selectedIncident.severity}</span>
                      </div>
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        {selectedIncident.title}
                      </p>
                    </div>

                    <button
                      onClick={triggerRefresh}
                      className="btn btn-outline"
                      style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
                      title="Refresh current state"
                    >
                      <RefreshCw size={14} />
                      <span>Refresh</span>
                    </button>
                  </div>

                  {/* Actions Selector Pills if multiple actions */}
                  {actions.length > 0 && (
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        marginTop: '1rem',
                        paddingTop: '0.75rem',
                        borderTop: '1px solid var(--border-subtle)',
                      }}
                    >
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Response Actions:</span>
                      {actions.map((act) => (
                        <button
                          key={act.response_action_id}
                          onClick={() => setSelectedActionId(act.response_action_id)}
                          className={`btn ${act.response_action_id === selectedActionId ? 'btn-primary' : 'btn-outline'}`}
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                        >
                          v{act.action_version} ({act.approval_status})
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Two-Person Approval Panel (Priority Banner when Pending) */}
                {pendingAction && (
                  <ApprovalPanel
                    pendingAction={pendingAction}
                    onActionTransitioned={triggerRefresh}
                  />
                )}

                {/* Manual Reconciliation Panel (When Indeterminate or Inconclusive) */}
                {selectedAction && (
                  <ReconciliationPanel
                    action={selectedAction}
                    onReconciliationCompleted={triggerRefresh}
                  />
                )}

                {/* Containment Proposal Panel */}
                <ProposalPanel
                  incident={selectedIncident}
                  actions={actions}
                  onProposalCreated={triggerRefresh}
                />

                {/* Active Action Inspection & Verification Panels */}
                {selectedAction && (
                  <>
                    <SimulationPanel
                      action={selectedAction}
                      refreshTrigger={refreshTrigger}
                    />

                    <VerificationPanel
                      action={selectedAction}
                      onVerificationTriggered={triggerRefresh}
                      refreshTrigger={refreshTrigger}
                    />

                    <AuditTrailPanel
                      action={selectedAction}
                      refreshTrigger={refreshTrigger}
                    />
                  </>
                )}
              </div>
            ) : (
              <div
                className="card"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: '3rem',
                  color: 'var(--text-muted)',
                }}
              >
                Select an incident from the left panel to inspect response actions.
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
};

export default App;
