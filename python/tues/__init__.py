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
]
