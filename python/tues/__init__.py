"""Remote command execution over SSH/SFTP with sudo elevation.

Blocking API::

    with tues.Session.connect("admin@host", run_as="root") as s:
        out = s.run("id", check=True)
        print(out.text())

asyncio API::

    async with await tues.AsyncSession.connect("admin@host") as s:
        out = await s.run(["ls", "-l"], run_as="root")
"""

from ._tues import (
    AsyncChild,
    AsyncChildStdin,
    AsyncChildStdout,
    AsyncFile,
    AsyncSession,
    AsyncSftp,
    AuthError,
    Child,
    ChildStdin,
    ChildStdout,
    ConnectError,
    DirEntry,
    ExitStatus,
    File,
    HostKeyError,
    Metadata,
    Output,
    PasswordRequest,
    Session,
    Sftp,
    SftpError,
    SudoError,
    TuesError,
    __version__,
)

__all__ = [
    "AsyncChild",
    "AsyncChildStdin",
    "AsyncChildStdout",
    "AsyncFile",
    "AsyncSession",
    "AsyncSftp",
    "AuthError",
    "Child",
    "ChildStdin",
    "ChildStdout",
    "ConnectError",
    "DirEntry",
    "ExitStatus",
    "File",
    "HostKeyError",
    "Metadata",
    "Output",
    "PasswordRequest",
    "Session",
    "Sftp",
    "SftpError",
    "SudoError",
    "TuesError",
    "__version__",
]
