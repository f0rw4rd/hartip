"""
Shared pytest fixtures for HART-IP integration testing.

Prerequisites:
    - A HART-IP hipserver reachable on UDP 5094 / TCP 5095
    - Either via ``docker compose -f tests/integration/docker-compose.yml up -d``
      or any other hipserver instance (e.g. from the msf-ics mock stack)

Override host/ports via environment variables::

    HARTIP_TEST_HOST=10.0.0.1 HARTIP_TEST_UDP_PORT=5094 pytest -m integration
"""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration  (overridable via env vars)
# ---------------------------------------------------------------------------

HART_HOST = os.environ.get("HARTIP_TEST_HOST", "127.0.0.1")
HART_UDP_PORT = int(os.environ.get("HARTIP_TEST_UDP_PORT", "5094"))
HART_TCP_PORT = int(os.environ.get("HARTIP_TEST_TCP_PORT", "5094"))

CONTAINER_NAME = os.environ.get("HARTIP_TEST_CONTAINER", "hartip-test-device")
COMPOSE_FILE = Path(__file__).parent / "docker-compose.yml"

# ---------------------------------------------------------------------------
# Runtime checks
# ---------------------------------------------------------------------------


def _container_running(name: str) -> bool:
    """Check if a Docker container with *name* is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "true"
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _port_open(host: str, port: int, *, udp: bool = False, timeout: float = 2.0) -> bool:
    """Check if a port is reachable."""
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            try:
                sock.recvfrom(1024)
            except TimeoutError:
                pass  # UDP timeout is normal — server is likely there
            sock.close()
            return True
        else:
            with socket.create_connection((host, port), timeout=timeout):
                return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


def _hipserver_available() -> bool:
    """Return True if a HART-IP hipserver is reachable.

    Checks (in order):
    1. Container ``hartip-test-device`` running  (own compose stack)
    2. Container ``hart-hipserver`` running       (msf-ics mock stack)
    3. TCP port reachable                         (any hipserver)
    """
    if _container_running(CONTAINER_NAME):
        return True
    if _container_running("hart-hipserver"):
        return True
    return _port_open(HART_HOST, HART_TCP_PORT)


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

skip_no_hipserver = pytest.mark.skipif(
    not _hipserver_available(),
    reason="No HART-IP hipserver reachable (run docker compose up or start msf-ics mocks)",
)

skip_no_udp = pytest.mark.skipif(
    not _port_open(HART_HOST, HART_UDP_PORT, udp=True),
    reason=f"HART-IP UDP port {HART_UDP_PORT} not reachable on {HART_HOST}",
)

skip_no_tcp = pytest.mark.skipif(
    not _port_open(HART_HOST, HART_TCP_PORT),
    reason=f"HART-IP TCP port {HART_TCP_PORT} not reachable on {HART_HOST}",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def hart_host() -> str:
    """Target host for the HART-IP device."""
    return HART_HOST


@pytest.fixture(scope="session")
def hart_udp_port() -> int:
    """UDP port for the HART-IP device."""
    return HART_UDP_PORT


@pytest.fixture(scope="session")
def hart_tcp_port() -> int:
    """TCP port for the HART-IP device."""
    return HART_TCP_PORT
