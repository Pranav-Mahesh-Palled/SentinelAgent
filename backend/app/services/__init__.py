"""SentinelAgent backend services module."""

from app.services.detection_orchestrator import (
    DetectionOrchestrator,
    DetectionOrchestratorConfig,
    DetectionOrchestratorConfigurationError,
    DetectionOrchestratorError,
    OrchestrationResult,
)
from app.services.feature_extractor import (
    FeatureExtractor,
    FeatureExtractorConfig,
    WindowFeatures,
    extract_window_features,
)
from app.services.gemini_client import (
    GeminiConfigurationError,
    GeminiProvider,
    create_function_response_part,
    create_gemini_client,
)
from app.services.investigation_agent import (
    ALLOWED_TOOL_NAMES,
    InvestigationAgent,
    InvestigationAgentError,
)
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    IncidentNotFoundError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    InvestigationService,
    InvestigationServiceError,
    InvestigationTerminatedError,
    ProvenanceValidationError,
    ToolRunLifecycleError,
)
from app.services.investigation_sweeper import (
    StaleInvestigationSweeper,
)
from app.services.investigation_tools import (
    INTERNAL_RETRIEVAL_LIMIT,
    INTERNAL_RETRIEVAL_POST_HOURS,
    INTERNAL_RETRIEVAL_PRE_HOURS,
    INTERNAL_RETRIEVAL_TOOL_NAME,
    ActiveInvestigationContext,
    InvestigationContextError,
    get_detection_results,
    get_incident_context,
    get_prior_evidence,
    get_related_incidents_for_ip,
    get_ssh_events,
    readonly_db_session,
    retrieve_incident_ssh_telemetry,
    search_ssh_events_by_username,
)
from app.services.isolation_forest_detector import (
    FEATURE_NAMES,
    IsolationForestConfig,
    IsolationForestDetector,
    MLDetectionResult,
    evaluate_ml_detector,
    evaluate_rule_detector,
    generate_synthetic_evaluation_datasets,
    window_to_feature_vector,
    windows_to_feature_matrix,
)
from app.services.mitre_catalogue_service import (
    MitreCatalogueChecksumError,
    MitreCatalogueError,
    MitreCatalogueNotFoundError,
    MitreCatalogueService,
    MitreCatalogueValidationError,
    MitreReplacementAdvisory,
)
from app.services.mitre_mapping_engine import (
    RULE_MAP_SSH_001,
    RULE_MAP_SSH_002,
    RULE_MAP_SSH_003,
    SENTINEL_MITRE_NAMESPACE,
    EventRetrievalMetadata,
    MitreMappingEngine,
    compute_mapping_uuid5,
)
from app.services.mitre_mapping_validator import (
    MitreMappingValidationError,
    MitreMappingValidator,
)
from app.services.rule_detector import (
    RULE_R001,
    RULE_R002,
    DetectionResult,
    RuleDetector,
    RuleDetectorConfig,
    detect_suspicious_activity,
)
from app.services.ssh_event_generator import (
    SSHEventGenerator,
    SyntheticSSHEvent,
    generate_brute_force_events,
    generate_event_batch,
    generate_failed_events,
    generate_normal_events,
    generate_suspicious_success_events,
)

__all__ = [
    "SSHEventGenerator",
    "SyntheticSSHEvent",
    "generate_normal_events",
    "generate_failed_events",
    "generate_brute_force_events",
    "generate_suspicious_success_events",
    "generate_event_batch",
    "DetectionOrchestrator",
    "DetectionOrchestratorConfig",
    "DetectionOrchestratorError",
    "DetectionOrchestratorConfigurationError",
    "OrchestrationResult",
    "FeatureExtractor",
    "FeatureExtractorConfig",
    "WindowFeatures",
    "extract_window_features",
    "GeminiConfigurationError",
    "GeminiProvider",
    "create_gemini_client",
    "create_function_response_part",
    "StaleInvestigationSweeper",
    "InvestigationService",
    "InvestigationServiceError",
    "InvestigationAgent",
    "InvestigationAgentError",
    "ALLOWED_TOOL_NAMES",
    "IncidentNotFoundError",
    "InvestigationNotFoundError",
    "InvestigationConflictError",
    "InvestigationTerminatedError",
    "ProvenanceValidationError",
    "ToolRunLifecycleError",
    "AuthorizedProvenanceSet",
    "ActiveInvestigationContext",
    "InvestigationContextError",
    "readonly_db_session",
    "get_incident_context",
    "get_ssh_events",
    "get_detection_results",
    "get_prior_evidence",
    "search_ssh_events_by_username",
    "get_related_incidents_for_ip",
    "retrieve_incident_ssh_telemetry",
    "INTERNAL_RETRIEVAL_PRE_HOURS",
    "INTERNAL_RETRIEVAL_POST_HOURS",
    "INTERNAL_RETRIEVAL_LIMIT",
    "INTERNAL_RETRIEVAL_TOOL_NAME",
    "RuleDetector",
    "RuleDetectorConfig",
    "DetectionResult",
    "detect_suspicious_activity",
    "RULE_R001",
    "RULE_R002",
    "FEATURE_NAMES",
    "IsolationForestConfig",
    "IsolationForestDetector",
    "MLDetectionResult",
    "evaluate_ml_detector",
    "evaluate_rule_detector",
    "generate_synthetic_evaluation_datasets",
    "window_to_feature_vector",
    "windows_to_feature_matrix",
    "MitreCatalogueService",
    "MitreCatalogueError",
    "MitreCatalogueNotFoundError",
    "MitreCatalogueChecksumError",
    "MitreCatalogueValidationError",
    "MitreReplacementAdvisory",
    "MitreMappingEngine",
    "EventRetrievalMetadata",
    "compute_mapping_uuid5",
    "RULE_MAP_SSH_001",
    "RULE_MAP_SSH_002",
    "RULE_MAP_SSH_003",
    "SENTINEL_MITRE_NAMESPACE",
    "MitreMappingValidator",
    "MitreMappingValidationError",
    "ResponseServiceError",
    "IdempotencyConflictError",
    "ActiveActionConflictError",
    "OptimisticLockError",
    "InvalidStateTransitionError",
    "FencingTokenError",
    "AuthorizationError",
    "EvidenceProvenanceError",
    "ReconciliationError",
    "ResponseOutboxService",
    "ResponseProposalService",
    "ResponseTransitionService",
    "SimulationAdapter",
    "SimulationExecutionService",
    "VerificationService",
    "ManualReconciliationService",
    "ResponseOutboxDispatcher",
    "SimulationExecutionWorker",
    "VerificationWorker",
    "ResponseSweeper",
    "ResponseWorkerRuntime",
    "WorkerMetrics",
]

from app.services.reconciliation_service import ManualReconciliationService
from app.services.response_idempotency_service import (
    ActiveActionConflictError,
    AuthorizationError,
    EvidenceProvenanceError,
    FencingTokenError,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    OptimisticLockError,
    ReconciliationError,
    ResponseServiceError,
)
from app.services.response_outbox_dispatcher import ResponseOutboxDispatcher
from app.services.response_outbox_service import ResponseOutboxService
from app.services.response_proposal_service import ResponseProposalService
from app.services.response_sweeper import ResponseSweeper
from app.services.response_transition_service import ResponseTransitionService
from app.services.response_worker_runtime import ResponseWorkerRuntime, WorkerMetrics
from app.services.simulation_adapter import SimulationAdapter
from app.services.simulation_execution_service import SimulationExecutionService
from app.services.simulation_execution_worker import SimulationExecutionWorker
from app.services.verification_service import VerificationService
from app.services.verification_worker import VerificationWorker


