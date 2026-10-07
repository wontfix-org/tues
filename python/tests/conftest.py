"""Shared fixtures: a Docker `sshd` on an ephemeral host port.

Uses the same image as the Rust integration tests (``docker/sshd``), started
through the `testcontainers` library. Skipped when the Docker daemon is not
reachable. The published host port is chosen by Docker; it is never 22.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

import docker
import docker.errors
import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.image import DockerImage
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

ROOT = Path(__file__).resolve().parents[2]
DOCKER_DIR = ROOT / "docker" / "sshd"
IMAGE = "tues-test-sshd:latest"

USER = "tues"
PASSWORD = "tuespass"
NOPASSWD_USER = "nopw"

# Some Docker proxy setups deny bind mounts (including the docker.sock mount
# used by Testcontainers' Ryuk sidecar). Disable Ryuk unless the environment
# already opted into a specific value.
os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")


@dataclass(frozen=True)
class Sshd:
    host: str
    port: int
    key_path: str
    sudo_available: bool

    def connect_kwargs(self, **overrides):
        kw = dict(
            login_user=USER,
            port=self.port,
            identity_files=[self.key_path],
            identities_only=True,
            use_agent=False,
            ssh_config=False,
            host_key_policy="off",
            connect_timeout=20,
            password=PASSWORD,
        )
        kw.update(overrides)
        return kw


def _daemon_reachable() -> bool:
    client = docker.from_env()
    try:
        client.ping()
        return True
    except docker.errors.DockerException:
        return False
    finally:
        client.close()


def _probe_sudo_available(container_name: str) -> bool:
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        exit_code, output = container.exec_run(["cat", "/proc/1/status"])
        if exit_code != 0:
            return False
        status = output.decode("utf-8", errors="replace") if isinstance(output, (bytes, bytearray)) else str(output)
        for line in status.splitlines():
            if line.startswith("NoNewPrivs:"):
                return line.split(":", 1)[1].strip() == "0"
        return False
    except docker.errors.DockerException:
        return False
    finally:
        client.close()


def require_sudo(sshd: Sshd) -> None:
    if not sshd.sudo_available:
        pytest.skip("in-container sudo unavailable (NoNewPrivs is set)")


@pytest.fixture(scope="session")
def sshd():
    if not _daemon_reachable():
        pytest.skip("Docker daemon is not reachable")

    # Keep the image: the Rust tests build the same tag.
    image = DockerImage(path=str(DOCKER_DIR), tag=IMAGE, clean_up=False)
    try:
        image.build()
    finally:
        image.get_docker_client().client.close()

    container_name = f"tues-pytest-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    container = (
        DockerContainer(IMAGE)
        .with_name(container_name)
        .with_kwargs(security_opt=["no-new-privileges=false"])
        .with_exposed_ports(22)
        .waiting_for(LogMessageWaitStrategy("Server listening on").with_startup_timeout(120))
    )
    container.start()
    sudo_available = _probe_sudo_available(container_name)
    if not sudo_available:
        print("python test fixture: in-container sudo unavailable (NoNewPrivs is set); sudo-dependent tests will be skipped")
    try:
        yield Sshd(
            host=container.get_container_host_ip(),
            port=container.get_exposed_port(22),
            key_path=str(DOCKER_DIR / "id_test"),
            sudo_available=sudo_available,
        )
    finally:
        container.stop()
