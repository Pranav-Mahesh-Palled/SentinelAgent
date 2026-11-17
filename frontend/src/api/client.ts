/**
 * SentinelAgent Operator Dashboard API Client.
 * All requests pass the active transient Bearer token.
 * All state-mutating requests automatically include a unique Idempotency-Key header.
 */

import type {
  IncidentListItem,
  EvidenceItem,
  ResponseActionDetail,
  ResponseActionSimulationDetails,
  ResponseActionVerificationDetails,
  ResponseAuditEvent,
} from '../types';

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

function generateIdempotencyKey(prefix: string = 'ui'): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return `${prefix}_${crypto.randomUUID()}`;
  }
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}

export async function request<T>(
  endpoint: string,
  apiKey: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${apiKey}`);
  headers.set('Accept', 'application/json');

  if (options.method && options.method.toUpperCase() === 'POST') {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (!headers.has('Idempotency-Key')) {
      headers.set('Idempotency-Key', generateIdempotencyKey());
    }
  }

  const response = await fetch(`/api/v1${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errDetail = `HTTP ${response.status} ${response.statusText}`;
    let errData: any = null;
    try {
      errData = await response.json();
      if (errData && errData.detail) {
        if (typeof errData.detail === 'string') {
          errDetail = errData.detail;
        } else if (Array.isArray(errData.detail)) {
          errDetail = errData.detail.map((e: any) => e.msg || JSON.stringify(e)).join('; ');
        }
      }
    } catch {
      // response was not json
    }
    throw new ApiError(response.status, errDetail, errData);
  }

  return response.json() as Promise<T>;
}

// ============================================================================
// API Endpoints
// ============================================================================

export const api = {
  // Incidents
  getIncidents: (apiKey: string) =>
    request<IncidentListItem[]>('/incidents', apiKey),

  getIncident: (apiKey: string, incidentId: string) =>
    request<IncidentListItem>(`/incidents/${incidentId}`, apiKey),

  // Evidence
  getInvestigationEvidence: (apiKey: string, investigationId: string) =>
    request<EvidenceItem[]>(`/investigations/${investigationId}/evidence`, apiKey),

  // Response Actions
  getActionsForIncident: (apiKey: string, incidentId: string) =>
    request<ResponseActionDetail[]>(`/incidents/${incidentId}/response/actions`, apiKey),

  getAllActions: (apiKey: string) =>
    request<ResponseActionDetail[]>('/response/actions', apiKey),

  getActionDetail: (apiKey: string, actionId: string) =>
    request<ResponseActionDetail>(`/response/actions/${actionId}`, apiKey),

  createProposal: (
    apiKey: string,
    incidentId: string,
    payload: {
      investigation_id: string;
      justification: string;
      evidence_ids: string[];
    },
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/incidents/${incidentId}/response/proposals`, apiKey, {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
    });
  },

  approveAction: (
    apiKey: string,
    actionId: string,
    expectedVersion: number,
    reason?: string,
    executionTimeoutSeconds?: number,
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/approve`, apiKey, {
      method: 'POST',
      body: JSON.stringify({
        expected_version: expectedVersion,
        reason: reason || 'Approved containment action',
        execution_timeout_seconds: executionTimeoutSeconds,
      }),
      headers,
    });
  },

  rejectAction: (
    apiKey: string,
    actionId: string,
    expectedVersion: number,
    reason: string,
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/reject`, apiKey, {
      method: 'POST',
      body: JSON.stringify({
        expected_version: expectedVersion,
        reason,
      }),
      headers,
    });
  },

  cancelAction: (
    apiKey: string,
    actionId: string,
    expectedVersion: number,
    reason: string,
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/cancel`, apiKey, {
      method: 'POST',
      body: JSON.stringify({
        expected_version: expectedVersion,
        reason,
      }),
      headers,
    });
  },

  reVerifyAction: (apiKey: string, actionId: string, idempotencyKey?: string) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/re-verify`, apiKey, {
      method: 'POST',
      headers,
    });
  },

  reconcileExecution: (
    apiKey: string,
    actionId: string,
    payload: {
      resolution: string;
      justification: string;
      expected_version: number;
      evidence_ids: string[];
    },
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/reconcile-execution`, apiKey, {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
    });
  },

  reconcileVerification: (
    apiKey: string,
    actionId: string,
    payload: {
      reconciled_action: string;
      justification: string;
      expected_version?: number;
      synthetic_scenario_id: string;
      observation_window_start: string;
      observation_window_end: string;
      expected_probes: number;
      generated_probes: number;
      captured_probes: number;
      intercepted_probes: number;
      telemetry_coverage_verified: boolean;
      evidence_ids: string[];
      probes?: any[];
    },
    idempotencyKey?: string
  ) => {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request<any>(`/response/actions/${actionId}/reconcile-verification`, apiKey, {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
    });
  },

  // Inspection
  getSimulationDetails: (apiKey: string, actionId: string) =>
    request<ResponseActionSimulationDetails>(`/response/actions/${actionId}/simulation`, apiKey),

  getVerificationDetails: (apiKey: string, actionId: string) =>
    request<ResponseActionVerificationDetails>(`/response/actions/${actionId}/verification`, apiKey),

  getAuditEvents: (apiKey: string, actionId: string) =>
    request<ResponseAuditEvent[]>(`/response/actions/${actionId}/audit-events`, apiKey),
};
