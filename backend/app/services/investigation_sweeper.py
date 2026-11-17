"""Periodic Stale Investigation Recovery Sweeper (Task 7B.6).

Runs as a lightweight background task during FastAPI lifespan.
Executes an initial sweep on startup, then runs periodically (default 60s),
offloading synchronous database transactions to worker threads to prevent
blocking the event loop.
"""

import asyncio
import logging
from typing import Optional
import uuid

from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_session_factory
from app.services.investigation_service import InvestigationService

logger = logging.getLogger(__name__)

DEFAULT_SWEEPER_INTERVAL_SECONDS: int = 60


class StaleInvestigationSweeper:
    """Manages the periodic recovery of abandoned and stale investigations."""

    def __init__(
        self,
        service: Optional[InvestigationService] = None,
        session_factory: Optional[sessionmaker[Session]] = None,
        interval_seconds: int = DEFAULT_SWEEPER_INTERVAL_SECONDS,
    ) -> None:
        self._service = service
        self._session_factory = session_factory
        self._interval_seconds = max(1, interval_seconds)
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    def _get_service(self) -> Optional[InvestigationService]:
        """Lazily resolve the InvestigationService instance."""
        if self._service is not None:
            return self._service
        try:
            sf = self._session_factory or get_session_factory()
            return InvestigationService(session_factory=sf)
        except Exception as exc:
            logger.debug("Database service not ready for sweeper: %s", exc)
            return None

    @property
    def is_running(self) -> bool:
        """Return True if the sweeper loop task is active and not finished."""
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Start the periodic recovery sweeper if not already running."""
        if self.is_running:
            logger.warning("Stale investigation sweeper is already running; ignoring duplicate start request.")
            return

        self._stop_event.clear()
        self._task = asyncio.create_task(self._sweep_loop(), name="stale_investigation_sweeper")
        logger.info("Stale investigation sweeper started with %ds interval.", self._interval_seconds)

    async def stop(self) -> None:
        """Stop and await completion of the sweeper cleanly."""
        if self._task is None:
            return

        logger.info("Stopping stale investigation sweeper...")
        self._stop_event.set()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Error while stopping stale investigation sweeper: %s", exc)
        finally:
            self._task = None
            logger.info("Stale investigation sweeper stopped.")

    async def _sweep_loop(self) -> None:
        """Main periodic loop."""
        # Initial sweep on startup
        await self._run_single_sweep()

        while not self._stop_event.is_set():
            try:
                # Wait for interval or immediate wakeup on stop_event
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._interval_seconds)
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Interval elapsed, proceed to next sweep

            if not self._stop_event.is_set():
                await self._run_single_sweep()

    async def _run_single_sweep(self) -> dict[str, list[uuid.UUID]]:
        """Execute a single recovery sweep offloaded from the event loop."""
        service = self._get_service()
        if service is None:
            logger.debug("Skipping recovery sweep: database service is unconfigured or unavailable.")
            return {"investigations": [], "incidents": []}

        try:
            recovered = await asyncio.to_thread(service.recover_stale_investigations)
            num_invs = len(recovered.get("investigations", []))
            num_incs = len(recovered.get("incidents", []))
            if num_invs > 0 or num_incs > 0:
                logger.info(
                    "Stale recovery sweep completed: recovered %d investigations, %d incidents.",
                    num_invs,
                    num_incs,
                )
            else:
                logger.debug("Stale recovery sweep completed: no stale investigations.")
            return recovered
        except Exception as exc:
            logger.error("Error during stale investigation recovery sweep: %s", exc, exc_info=True)
            return {"investigations": [], "incidents": []}

