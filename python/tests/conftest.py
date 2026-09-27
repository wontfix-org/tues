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


@dataclass(frozen=True)
class Sshd:
    host: str
    port: int
    key_path: str

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

    container = (
        DockerContainer(IMAGE)
        .with_name(f"tues-pytest-{os.getpid()}-{uuid.uuid4().hex[:8]}")
        .with_exposed_ports(22)
        .waiting_for(LogMessageWaitStrategy("Server listening on").with_startup_timeout(120))
    )
    container.start()
    try:
        yield Sshd(
            host=container.get_container_host_ip(),
            port=container.get_exposed_port(22),
            key_path=str(DOCKER_DIR / "id_test"),
        )
    finally:
        container.stop()
