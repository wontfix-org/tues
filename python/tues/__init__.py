"""Remote command execution over SSH/SFTP with sudo elevation.

The API mirrors the standard library: a :class:`Session` is the
:mod:`subprocess` module for one remote host, an :class:`AsyncSession` is
:mod:`asyncio.subprocess`.

Blocking::

    import tues

    with tues.Session("admin@host", user="root") as s:
        out = s.run(["systemctl", "status", "nginx"], capture_output=True, text=True, check=True)
        print(out.stdout)

        with s.Popen("tail -f /var/log/syslog", shell=True, stdout=tues.PIPE) as p:
            for line in p.stdout:
                ...

asyncio::

    async with await tues.AsyncSession.connect("admin@host") as s:
        proc = await s.create_subprocess_exec("id", "-un", stdout=tues.PIPE)
        out, _ = await proc.communicate()

:func:`run` is the legacy multi-host API from the original tues package
(:mod:`tues.legacy`): one shell command, many hosts, optional ``sudo``,
file upload and output prefixes. It is implemented on :class:`Session`
and kept for existing callers.

Intentional differences from :mod:`subprocess`, all consequences of the
process running on another machine:

* ``stdin=None`` means *no input* (EOF) rather than the local stdin; pass
  ``stdin=sys.stdin`` (blocking API) to forward it.
* ``env`` adds to / overrides the remote environment instead of replacing it
  (``None`` values unset a variable).
* ``pid`` is always ``None``; ``returncode`` is ``-N`` for signal ``N`` as on
  POSIX.
* Extra keyword arguments: ``user`` and ``pty``. ``user`` is a name (run via
  ``sudo -u``) or ``LOGIN_USER`` (run as the login user, never via sudo,
  even when the session has a default ``user``); leaving it out inherits
  the session default.
"""

from __future__ import annotations

import os
import sys


def _load_cargo_extension() -> None:
    """Load the cdylib ``cargo test`` just built when ``TUES_EXTENSION`` is set.

    Cargo writes ``lib_tues.so`` into its target directory. Installing that
    file in ``sys.modules`` before the ``from ._tues`` imports below makes this
    process, and ``python -m tues``, use that build.
    """
    path = os.environ.get("TUES_EXTENSION")
    if not path or "tues._tues" in sys.modules:
        return
    import importlib.machinery
    import importlib.util

    name = "tues._tues"
    loader = importlib.machinery.ExtensionFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise ImportError(f"cannot load extension {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)


_load_cargo_extension()

from ._aio import AsyncSession, Process, StdinWriter
from ._common import (
    DEVNULL,
    LOGIN_USER,
    PIPE,
    STDOUT,
    CalledProcessError,
    CompletedProcess,
    TimeoutExpired,
)
from ._sync import Popen, Session
from ._tues import (
    AsyncFile,
    AsyncSftp,
    AuthError,
    ConnectError,
    DirEntry,
    File,
    HostKeyError,
    Metadata,
    PasswordRequest,
    Sftp,
    SftpError,
    SudoError,
    TuesError,
    __version__,
)
from .legacy import (
    DEFAULT_ENCODING,
    DEFAULT_PATH,
    DIR_ABORT,
    DIR_IGNORE,
    DIR_ROTATE,
    DIR_WIPE,
    Host,
    PasswordManager,
    Script,
    Task,
    TuesErrorGroup,
    TuesLookupError,
    TuesOutputDirExists,
    TuesScriptNotFoundError,
    TuesTaskError,
    TuesUserAbort,
    provider,
    run,
)

__all__ = [
    "PIPE",
    "STDOUT",
    "DEVNULL",
    "LOGIN_USER",
    "Session",
    "Popen",
    "CompletedProcess",
    "CalledProcessError",
    "TimeoutExpired",
    "AsyncSession",
    "Process",
    "StdinWriter",
    "Sftp",
    "File",
    "AsyncSftp",
    "AsyncFile",
    "Metadata",
    "DirEntry",
    "PasswordRequest",
    "TuesError",
    "ConnectError",
    "AuthError",
    "HostKeyError",
    "SudoError",
    "SftpError",
    "__version__",
    "run",
    "Task",
    "Host",
    "Script",
    "PasswordManager",
    "provider",
    "DIR_ABORT",
    "DIR_ROTATE",
    "DIR_WIPE",
    "DIR_IGNORE",
    "DEFAULT_ENCODING",
    "DEFAULT_PATH",
    "TuesErrorGroup",
    "TuesLookupError",
    "TuesScriptNotFoundError",
    "TuesOutputDirExists",
    "TuesUserAbort",
    "TuesTaskError",
]
