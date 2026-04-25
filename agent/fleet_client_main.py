"""
CLI entrypoint for the shaferhund-fleet-client container.

Reads env vars, validates them, then starts the async polling loop.
Exits cleanly on SIGTERM / SIGINT.

Run inside the container as:
    python -m agent.fleet_client_main

Or from the repo root (for dev/testing):
    FLEET_MANIFEST_URL=http://... FLEET_HMAC_KEY=aa...aa python -m agent.fleet_client_main

@decision DEC-FLEET-P6-003
@title Fleet client entrypoint validates env then delegates to run_loop; SIGTERM exits cleanly
@status accepted
@rationale Container orchestrators (Kubernetes, Docker/Podman with restart policies) send
           SIGTERM before SIGKILL. Converting SIGTERM to a CancelledError via asyncio's
           signal handler lets run_loop's clean-exit path log a shutdown message before
           the process exits. This avoids silent kills and gives the operator a log trail
           of each clean shutdown vs. forced kill.
"""

import asyncio
import logging
import os
import signal
import sys

from agent.fleet_client import FleetClientSettings, run_loop

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("fleet_client_main")


# ---------------------------------------------------------------------------
# SIGTERM / SIGINT handler
# ---------------------------------------------------------------------------


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, main_task: asyncio.Task) -> None:
    """Install SIGTERM + SIGINT handlers that cancel *main_task* cleanly."""

    def _handle_signal(sig_name: str) -> None:
        log.info("Received %s — cancelling fleet loop", sig_name)
        main_task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal, sig.name)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _main_async() -> None:
    """Async entry point: build settings, install handlers, run loop."""
    # Validate env vars early — clear error messages before any async work.
    try:
        settings = FleetClientSettings.from_env()
    except EnvironmentError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    poll_interval_raw = os.environ.get("FLEET_POLL_INTERVAL_SECONDS", "300")
    try:
        poll_interval = int(poll_interval_raw)
        if poll_interval < 1:
            raise ValueError("must be >= 1")
    except ValueError as exc:
        log.error(
            "FLEET_POLL_INTERVAL_SECONDS=%r is invalid (%s) — defaulting to 300s",
            poll_interval_raw,
            exc,
        )
        poll_interval = 300

    log.info(
        "Fleet client starting: manifest_url=%s rules_dir=%s poll_interval=%ds",
        settings.manifest_url,
        settings.rules_dir,
        poll_interval,
    )

    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()
    assert main_task is not None  # always true inside async def

    _install_signal_handlers(loop, main_task)

    try:
        await run_loop(settings, interval_seconds=poll_interval)
    except asyncio.CancelledError:
        log.info("Fleet client shut down cleanly")


def main() -> None:
    """Synchronous entry point called by __main__ and setuptools console_scripts."""
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
