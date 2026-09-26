"""Shared fixtures: a Docker `sshd` on an ephemeral host port.

Uses the same image as the Rust integration tests (``docker/sshd``). Requires
a working ``docker`` CLI; the tests are skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

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
            user=USER,
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


def _docker(*args: str, check: bool = True) -> str:
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture(scope="session")
def sshd() -> Sshd:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    try:
        _docker("info")
    except subprocess.CalledProcessError:
        pytest.skip("docker daemon not reachable")

    build = ["docker", "build", "-q", "-t", IMAGE, str(DOCKER_DIR)]
    result = subprocess.run(build, capture_output=True, text=True)
    if result.returncode != 0:
        # BuildKit needs a writable ~/.docker; fall back to the classic builder.
        result = subprocess.run(
            build, capture_output=True, text=True, env={**os.environ, "DOCKER_BUILDKIT": "0"}
        )
    if result.returncode != 0:
        raise RuntimeError(f"docker build failed:\n{result.stderr}")
    name = f"tues-pytest-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    cid = _docker(
        "run", "-d", "--rm", "-p", "127.0.0.1::22", "--name", name, IMAGE
    )
    try:
        port = int(_docker("port", name, "22/tcp").splitlines()[0].rsplit(":", 1)[1])
        deadline = time.time() + 60
        while time.time() < deadline:
            logs = subprocess.run(
                ["docker", "logs", cid], capture_output=True, text=True
            )
            if "Server listening on" in logs.stdout + logs.stderr:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("sshd did not start")
        yield Sshd(host="127.0.0.1", port=port, key_path=str(DOCKER_DIR / "id_test"))
    finally:
        _docker("rm", "-f", "-v", cid, check=False)
