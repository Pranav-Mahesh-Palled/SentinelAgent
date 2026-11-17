"""SentinelAgent API - Main Application Entrypoint."""

from contextlib import asynccontextmanager
import inspect
import logging
from typing import Optional
import uuid

from fastapi import FastAPI

from app.api.events import router as events_router
from app.api.health import router as health_router
from app.api.investigations import router as investigations_router
from app.api.response import router as response_router
from app.core.config import get_settings, settings
from app.db.connection import dispose_engine
from app.db.session import get_session_factory
from app.services.gemini_client import (
    GeminiConfigurationError,
    GeminiProvider,
    create_gemini_client,
)
from app.services.hindsight_client import (
    HindsightConfigurationError,
    HindsightClientService,
    create_hindsight_client,
)
from app.services.hmac_pseudonymizer import get_pseudonymizer_from_settings
from app.services.incident_memory_recall_service import IncidentMemoryRecallService
from app.services.investigation_sweeper import StaleInvestigationSweeper
from app.services.memory_outbox_claim_service import MemoryOutboxClaimService
from app.services.memory_outbox_processor import HindsightMemoryOutboxProcessor
from app.services.memory_outbox_worker import HindsightMemoryOutboxWorker
from app.services.mitre_catalogue_service import (
    MitreCatalogueError,
    MitreCatalogueService,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for application startup and shutdown tasks."""
    # -------------------------------------------------------------------------
    # Startup Lifecycle
    # -------------------------------------------------------------------------
    app_settings = get_settings()

    # Validate production configuration contract
    app_settings.validate_production_contract(process_type="api")

    # Pre-initialize state attributes
    app.state.gemini_provider = None
    app.state.sweeper = None
    app.state.mitre_catalogue = None
    app.state.hindsight_client = None
    app.state.hindsight_memory_outbox_worker = None
    app.state.incident_memory_recall_service = None

    try:
        # 1. Initialize Gemini Provider if GEMINI_API_KEY is configured
        if app_settings.GEMINI_API_KEY and app_settings.GEMINI_API_KEY.get_secret_value().strip():
            try:
                provider = create_gemini_client(app_settings)
                app.state.gemini_provider = provider
                logger.info("Google Gemini provider initialized for model '%s'.", provider.model)
            except GeminiConfigurationError as exc:
                logger.warning("Gemini provider not initialized: %s", exc)
                app.state.gemini_provider = None
            except Exception as exc:
                logger.error("Failed to initialize Gemini provider on startup: %s", exc)
                app.state.gemini_provider = None
        else:
            app.state.gemini_provider = None
            logger.info("Gemini provider not configured; starting without active LLM provider.")

        # 2. Initialize Hindsight Persistent Memory Client if configured
        if app_settings.HINDSIGHT_ENABLED:
            try:
                hindsight_service = create_hindsight_client(app_settings)
                app.state.hindsight_client = hindsight_service
                logger.info(
                    "Hindsight client initialized (bank: '%s', base_url: '%s', required: %s).",
                    hindsight_service.bank_id,
                    hindsight_service.base_url,
                    hindsight_service.is_required,
                )
            except HindsightConfigurationError as exc:
                logger.warning("Hindsight client configuration error: %s", exc)
                app.state.hindsight_client = None
                if app_settings.HINDSIGHT_REQUIRED:
                    logger.critical("Hindsight is mandatory but failed configuration: %s", exc)
                    raise
            except Exception as exc:
                logger.error("Failed to initialize Hindsight client on startup: %s", exc)
                app.state.hindsight_client = None
                if app_settings.HINDSIGHT_REQUIRED:
                    logger.critical("Hindsight is mandatory but failed startup initialization: %s", exc)
                    raise
        else:
            app.state.hindsight_client = None
            logger.info("Hindsight persistent incident memory disabled.")

        # 3. Start Periodic Stale Investigation Recovery Sweeper
        sweeper = StaleInvestigationSweeper()
        app.state.sweeper = sweeper
        try:
            sweeper.start()
        except Exception as exc:
            logger.error("Failed to start stale investigation sweeper on startup: %s", exc)

        # 4. Initialize MITRE ATT&CK Catalogue Service
        catalogue_path = app_settings.MITRE_CATALOGUE_PATH
        mitre_required = app_settings.MITRE_REQUIRED
        try:
            catalogue_service = MitreCatalogueService.from_file(catalogue_path)
            app.state.mitre_catalogue = catalogue_service
            logger.info(
                "MITRE ATT&CK catalogue service loaded successfully from '%s' (version %s, domain '%s').",
                catalogue_path,
                catalogue_service.version,
                catalogue_service.domain,
            )
        except (MitreCatalogueError, Exception) as exc:
            if mitre_required:
                logger.critical(
                    "Failed to load mandatory MITRE ATT&CK catalogue from '%s': %s",
                    catalogue_path,
                    exc,
                )
                raise
            else:
                logger.warning(
                    "MITRE ATT&CK catalogue not loaded (optional mode): %s",
                    exc,
                )
                app.state.mitre_catalogue = None

        # 5. Initialize and Start Hindsight Memory Outbox Worker
        if app_settings.HINDSIGHT_ENABLED and app.state.hindsight_client is not None:
            try:
                session_factory = get_session_factory()
                claim_service = MemoryOutboxClaimService(
                    session_factory=session_factory,
                    settings=app_settings,
                )
                worker_id = f"sentinelagent-outbox-worker-{uuid.uuid4()}"
                processor = HindsightMemoryOutboxProcessor(
                    hindsight_service=app.state.hindsight_client,
                    claim_service=claim_service,
                    worker_id=worker_id,
                    settings=app_settings,
                )
                worker = HindsightMemoryOutboxWorker(
                    claim_service=claim_service,
                    processor=processor,
                    worker_id=worker_id,
                    settings=app_settings,
                )
                app.state.hindsight_memory_outbox_worker = worker
                worker.start()
                logger.info(
                    "Hindsight memory outbox worker started (worker_id: '%s', concurrency: %d, batch_size: %d).",
                    worker.worker_id,
                    worker.max_concurrency,
                    worker.batch_size,
                )
            except Exception as exc:
                logger.error(
                    "Failed to initialize or start Hindsight outbox worker on startup: %s",
                    type(exc).__name__,
                )
                active_worker = getattr(app.state, "hindsight_memory_outbox_worker", None)
                if active_worker is not None:
                    try:
                        await active_worker.stop()
                    except Exception:
                        pass
                    finally:
                        app.state.hindsight_memory_outbox_worker = None
                if app_settings.HINDSIGHT_REQUIRED:
                    logger.critical(
                        "Hindsight is mandatory but outbox worker failed to start: %s",
                        type(exc).__name__,
                    )
                    raise
        else:
            app.state.hindsight_memory_outbox_worker = None
            if not app_settings.HINDSIGHT_ENABLED:
                logger.info("Hindsight memory outbox worker disabled.")
            else:
                logger.warning("Hindsight client unavailable; memory outbox worker not started.")

        # 6. Initialize Incident Memory Recall Service if recall is enabled
        if (
            app_settings.HINDSIGHT_ENABLED
            and app_settings.HINDSIGHT_RECALL_ENABLED
            and getattr(app.state, "hindsight_client", None) is not None
        ):
            try:
                pseudonymizer = get_pseudonymizer_from_settings(app_settings)
                recall_service = IncidentMemoryRecallService(
                    hindsight_client=app.state.hindsight_client,
                    pseudonymizer=pseudonymizer,
                    settings=app_settings,
                )
                app.state.incident_memory_recall_service = recall_service
                logger.info(
                    "Incident memory recall service initialized (concurrency: %d).",
                    recall_service.max_concurrency,
                )
            except Exception as exc:
                logger.error(
                    "Failed to initialize incident memory recall service: %s",
                    type(exc).__name__,
                )
                app.state.incident_memory_recall_service = None
                if app_settings.HINDSIGHT_REQUIRED:
                    logger.critical(
                        "Hindsight is mandatory but incident memory recall service failed startup: %s",
                        type(exc).__name__,
                    )
                    raise
        else:
            app.state.incident_memory_recall_service = None
            if not app_settings.HINDSIGHT_RECALL_ENABLED:
                logger.info("Incident memory recall service disabled.")
            elif not app_settings.HINDSIGHT_ENABLED:
                logger.info("Incident memory recall service disabled (Hindsight disabled).")
            else:
                logger.warning("Hindsight client unavailable; incident memory recall service not initialized.")

    except BaseException:
        # Clean up any resources initialized prior to the startup abort
        app.state.incident_memory_recall_service = None

        active_worker = getattr(app.state, "hindsight_memory_outbox_worker", None)
        if active_worker is not None:
            try:
                stop_res = active_worker.stop()
                if inspect.isawaitable(stop_res):
                    await stop_res
            except Exception as exc:
                logger.error("Error stopping outbox worker during startup abort: %s", type(exc).__name__)
            finally:
                app.state.hindsight_memory_outbox_worker = None

        app.state.mitre_catalogue = None

        active_sweeper = getattr(app.state, "sweeper", None)
        if active_sweeper is not None:
            try:
                stop_res = active_sweeper.stop()
                if inspect.isawaitable(stop_res):
                    await stop_res
            except Exception as exc:
                logger.error("Error stopping stale investigation sweeper during startup abort: %s", type(exc).__name__)
            finally:
                app.state.sweeper = None

        active_hindsight = getattr(app.state, "hindsight_client", None)
        if active_hindsight is not None:
            try:
                aclose_res = active_hindsight.aclose()
                if inspect.isawaitable(aclose_res):
                    await aclose_res
            except Exception as exc:
                logger.error("Error closing Hindsight client during startup abort: %s", type(exc).__name__)
            finally:
                app.state.hindsight_client = None

        active_provider = getattr(app.state, "gemini_provider", None)
        if active_provider is not None:
            try:
                active_provider.close()
            except Exception as exc:
                logger.error("Error closing Gemini provider during startup abort: %s", type(exc).__name__)
            finally:
                app.state.gemini_provider = None

        dispose_engine()
        raise

    try:
        yield
    finally:
        # -------------------------------------------------------------------------
        # Shutdown Lifecycle
        # -------------------------------------------------------------------------
        shutdown_errors: list[Exception] = []

        # 1. Stop Hindsight Memory Outbox Worker
        active_worker = getattr(app.state, "hindsight_memory_outbox_worker", None)
        if active_worker is not None:
            try:
                stop_res = active_worker.stop()
                if inspect.isawaitable(stop_res):
                    await stop_res
                logger.info("Hindsight memory outbox worker stopped successfully.")
            except Exception as exc:
                logger.error(
                    "Error stopping Hindsight memory outbox worker during shutdown: %s",
                    type(exc).__name__,
                )
                shutdown_errors.append(exc)
            finally:
                app.state.hindsight_memory_outbox_worker = None

        # 2. Stop Stale Investigation Sweeper cleanly
        active_sweeper = getattr(app.state, "sweeper", None)
        if active_sweeper is not None:
            try:
                stop_res = active_sweeper.stop()
                if inspect.isawaitable(stop_res):
                    await stop_res
                logger.info("Stale investigation sweeper stopped successfully.")
            except Exception as exc:
                logger.error(
                    "Error stopping stale investigation sweeper during shutdown: %s",
                    type(exc).__name__,
                )
                shutdown_errors.append(exc)
            finally:
                app.state.sweeper = None

        # 3. Clear MITRE Catalogue reference
        app.state.mitre_catalogue = None

        # 4. Clear Incident Memory Recall Service
        app.state.incident_memory_recall_service = None

        # 5. Close Hindsight Client session
        active_hindsight = getattr(app.state, "hindsight_client", None)
        if active_hindsight is not None:
            try:
                aclose_res = active_hindsight.aclose()
                if inspect.isawaitable(aclose_res):
                    await aclose_res
                logger.info("Hindsight client resources closed successfully.")
            except Exception as exc:
                logger.error(
                    "Error closing Hindsight client during shutdown: %s",
                    type(exc).__name__,
                )
                shutdown_errors.append(exc)
            finally:
                app.state.hindsight_client = None

        # 5. Close Gemini Provider and release HTTP client resources
        active_provider = getattr(app.state, "gemini_provider", None)
        if active_provider is not None:
            try:
                active_provider.close()
                logger.info("Gemini provider resources closed successfully.")
            except Exception as exc:
                logger.error(
                    "Error closing Gemini provider during shutdown: %s",
                    type(exc).__name__,
                )
                shutdown_errors.append(exc)
            finally:
                app.state.gemini_provider = None

        # 6. Clean up database connection pool
        try:
            dispose_engine()
            logger.info("Database engine disposed successfully.")
        except Exception as exc:
            logger.error(
                "Error disposing database engine during shutdown: %s",
                type(exc).__name__,
            )
            shutdown_errors.append(exc)

        if shutdown_errors:
            if len(shutdown_errors) == 1:
                raise shutdown_errors[0]
            try:
                raise ExceptionGroup("Shutdown cleanup encountered multiple errors", shutdown_errors)
            except NameError:
                raise shutdown_errors[0]


app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# CORS middleware for operator dashboard
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize default state attributes
app.state.gemini_provider = None
app.state.sweeper = None
app.state.mitre_catalogue = None
app.state.hindsight_client = None
app.state.hindsight_memory_outbox_worker = None
app.state.incident_memory_recall_service = None

# Register API routers
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(events_router, prefix=settings.API_PREFIX)
app.include_router(investigations_router, prefix=settings.API_PREFIX)
app.include_router(response_router, prefix="/api/v1")
app.include_router(response_router, prefix=settings.API_PREFIX)


