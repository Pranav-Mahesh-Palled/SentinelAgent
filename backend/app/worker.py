"""Standalone Process Entry Point for SentinelAgent Response Worker (Task 11.3B).

Usage:
    python -m app.worker [OPTIONS]
    python backend/app/worker.py [OPTIONS]

Options:
    --worker-id TEXT             Unique worker instance identifier
    --concurrency INTEGER        Maximum concurrent outbox processing tasks (default 5)
    --poll-interval FLOAT        Seconds between queue poll cycles (default 2.0)
    --lease-duration INTEGER     Seconds before an uncompleted lease expires (default 60)
    --sweeper-interval FLOAT     Seconds between periodic expiration/recovery sweeps (default 10.0)
    --once                       Execute a single polling/sweep cycle and exit immediately
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import uuid

# Ensure backend root is in sys.path if run directly
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.config import get_settings
from app.db.connection import dispose_engine
from app.db.session import get_session_factory
from app.services.response_worker_runtime import ResponseWorkerRuntime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s (%(process)d): %(message)s",
)
logger = logging.getLogger("sentinelagent.response_worker")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SentinelAgent Transactional Outbox Background Worker"
    )
    parser.add_argument(
        "--worker-id",
        type=str,
        default=f"resp-worker-{uuid.uuid4().hex[:8]}",
        help="Unique identifier for this worker instance",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Maximum concurrent execution tasks (default from settings: 5)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        help="Seconds between queue polling attempts (default from settings: 2.0)",
    )
    parser.add_argument(
        "--lease-duration",
        type=int,
        default=None,
        help="Seconds before task lease expires (default from settings: 60)",
    )
    parser.add_argument(
        "--sweeper-interval",
        type=float,
        default=None,
        help="Seconds between periodic expiration/recovery sweeps (default from settings: 10.0)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Execute a single synchronous poll and sweep cycle, then exit",
    )
    return parser.parse_args()


async def run_worker(args: argparse.Namespace) -> int:
    settings = get_settings()
    settings.validate_production_contract(process_type="worker")
    session_factory = get_session_factory()

    runtime = ResponseWorkerRuntime(
        session_factory=session_factory,
        worker_id=args.worker_id,
        settings=settings,
        poll_interval_seconds=args.poll_interval,
        max_concurrency=args.concurrency,
        lease_duration_seconds=args.lease_duration,
        sweeper_interval_seconds=args.sweeper_interval,
    )

    if args.once:
        logger.info("Executing single batch cycle for worker '%s'...", runtime.worker_id)
        result = runtime.run_once()
        logger.info("Single batch cycle finished: %s", result)
        dispose_engine()
        return 0

    stop_event = asyncio.Event()

    def handle_signal(sig_name: str) -> None:
        logger.info("Received signal %s; requesting graceful worker shutdown...", sig_name)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig.name: handle_signal(s))
        except NotImplementedError:
            # Signal handling on Windows event loop fallback
            signal.signal(sig, lambda s, f, sname=sig.name: handle_signal(sname))

    await runtime.start()
    logger.info("Worker '%s' running. Press Ctrl+C to stop.", runtime.worker_id)

    try:
        await stop_event.wait()
    finally:
        logger.info("Shutting down worker '%s'...", runtime.worker_id)
        await runtime.stop(timeout_seconds=15.0)
        dispose_engine()
        logger.info("Final worker metrics: %s", runtime.metrics.snapshot())
        logger.info("Worker '%s' terminated cleanly.", runtime.worker_id)

    return 0


def main() -> None:
    args = parse_args()
    try:
        exit_code = asyncio.run(run_worker(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.critical("Fatal error in worker process: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
