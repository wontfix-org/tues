"""The ``tues`` command shipped with the Python package."""

from __future__ import annotations

import os
import subprocess
import sys

from tues._tues import cli_main

from conftest import PASSWORD, USER


def test_cli_main_prints_help_in_process(capfd):
    assert cli_main(["tues", "--help"]) == 0
    out, err = capfd.readouterr()
    assert "Providers:" in out
    assert "--script" in out
    assert err == ""


def test_cli_main_reports_usage_errors(capfd):
    assert cli_main(["tues", "--num-jobs", "many", "true", "cl", "h"]) == 2
    out, err = capfd.readouterr()
    assert out == ""
    assert "invalid value 'many'" in err


def test_python_m_tues_runs_a_command(sshd):
    env = dict(os.environ, TUES_PW=PASSWORD)
    proc = subprocess.run(
        [
            sys.executable, "-m", "tues",
            "--no-ssh-config", "--host-key-check", "off",
            "--port", str(sshd.port), "-i", sshd.key_path, "-l", USER,
            "echo hello; echo oops >&2; exit 3",
            "cl", sshd.host,
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 3
    assert proc.stdout == "hello\n"
    assert proc.stderr == "oops\n"
