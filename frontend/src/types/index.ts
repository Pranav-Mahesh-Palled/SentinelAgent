export type OperatorRole = 'analyst' | 'approver' | 'admin';

export interface OperatorPrincipal {
  operator_id: string;
  role: OperatorRole;
  is_authenticated: boolean;
}

export interface OperatorMeResponse {
  operator_id: string;
  role: OperatorRole;
}

export interface IncidentListItem {
  incident_id: string;
  title: string;
  incident_type: string;
  source_ip: string;
  severity: string;
  detection_method: string;
  status: string;
  investigation_status: string;
  response_status: string;
  verification_status: string;
  created_at: string;
  updated_at: string;
  has_response_action: boolean;
  response_actions_count: number;
}

export interface EvidenceItem {
  evidence_id: string;
  incident_id: string;
  investigation_id: string;
  evidence_type: string;
  sha256_hash: string;
  source_artifact: string;
  collected_at: string;
  description: string;
  metadata_payload?: Record<string, any>;
}

export interface ResponseActionDetail {
  response_action_id: string;
  incident_id: string;
  investigation_id: string;
  correlation_id: string;
  action_type: string;
  action_version: number;
  target_kind: string;
  target_value: string;
  payload_json: Record<string, any>;
  payload_sha256: string;
  justification: string;
  proposed_by_operator_id: string;
  approval_status: 'pending_approval' | 'approved' | 'rejected' | 'cancelled';
  approved_by_operator_id?: string | null;
  approved_at?: string | null;
  rejection_reason?: string | null;
  rejection_at?: string | null;
  execution_status: 'not_queued' | 'queued' | 'running' | 'succeeded' | 'failed' | 'indeterminate' | 'expired' | 'cancelled';
  execution_deadline_at?: string | null;
  executed_at?: string | null;
  verification_status: 'not_started' | 'queued' | 'running' | 'verified' | 'failed' | 'inconclusive';
  verified_at?: string | null;
  approval_expires_at?: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface SimulatedBlocklistEntry {
  entry_id: string;
  target_ip: string;
  simulated_rule_id: string;
  simulated_at: string;
  payload_sha256: string;
}

export interface OutboxTelemetry {
  outbox_id: string;
  status: string;
  attempt_count: number;
  max_attempts: number;
  last_error_code?: string | null;
  next_attempt_at?: string | null;
  completed_at?: string | null;
}

export interface ResponseActionSimulationDetails {
  response_action_id: string;
  execution_status: string;
  executed_at?: string | null;
  execution_deadline_at?: string | null;
  simulated_entry?: SimulatedBlocklistEntry | null;
  outbox?: OutboxTelemetry | null;
}

export interface ReconciliationRecord {
  reconciliation_id: string;
  resolution: string;
  synthetic_scenario_id: string;
  observation_window_start: string;
  observation_window_end: string;
  reconciled_at: string;
  actor_operator_id: string;
}

export interface ReconciliationProbe {
  probe_id: string;
  generation_evidence_id: string;
  capture_evidence_id: string;
  interception_evidence_id?: string | null;
  intercepted: boolean;
}

export interface ResponseActionVerificationDetails {
  response_action_id: string;
  verification_status: string;
  verified_at?: string | null;
  reconciliation_record?: ReconciliationRecord | null;
  probes: ReconciliationProbe[];
}

export interface ResponseAuditEvent {
  response_audit_event_id: string;
  response_action_id: string;
  sequence_number: number;
  event_type: string;
  from_approval_status?: string | null;
  to_approval_status?: string | null;
  from_execution_status?: string | null;
  to_execution_status?: string | null;
  from_verification_status?: string | null;
  to_verification_status?: string | null;
  actor_type: string;
  actor_operator_id: string;
  actor_role_snapshot: string;
  reason?: string | null;
  payload_sha256_snapshot: string;
  created_at: string;
}
