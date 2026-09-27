"""asyncio API: ``AsyncSession`` and ``Process``, shaped like :mod:`asyncio.subprocess`.

``stdout``/``stderr`` are genuine :class:`asyncio.StreamReader` objects;
``stdin`` offers the :class:`asyncio.StreamWriter` methods (``write``,
``drain``, ``close``, ``wait_closed``, ...). As in asyncio, streams are
bytes-only; :meth:`AsyncSession.run` adds text mode on top.
"""

from __future__ import annotations

import asyncio
import collections
import os
import signal
from typing import Any, Mapping, Optional, Union

from . import _common
from ._common import (
    DEVNULL,
    PIPE,
    STDOUT,
    Args,
    CalledProcessError,
    CompletedProcess,
    TimeoutExpired,
)
from ._tues import AsyncChild as _AsyncChild
from ._tues import AsyncChildStdin as _AsyncChildStdin
from ._tues import AsyncChildStdout as _AsyncChildStdout
from ._tues import AsyncSession as _AsyncSession
from ._tues import AsyncSftp, TuesError

__all__ = ["AsyncSession", "Process"]

_DEFAULT_LIMIT = 2**16  # asyncio.streams._DEFAULT_LIMIT
_READ_CHUNK = 64 * 1024


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


class _ReadTransport:
    """Just enough transport for ``StreamReader`` flow control."""

    def __init__(self) -> None:
        self._resumed = asyncio.Event()
        self._resumed.set()

    def pause_reading(self) -> None:
        self._resumed.clear()

    def resume_reading(self) -> None:
        self._resumed.set()

    async def wait_resumed(self) -> None:
        await self._resumed.wait()

    def close(self) -> None:
        pass

    def is_closing(self) -> bool:
        return False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default


def _start_reader(raw: _AsyncChildStdout, limit: int) -> tuple[asyncio.StreamReader, "asyncio.Task[None]"]:
    reader = asyncio.StreamReader(limit=limit)
    transport = _ReadTransport()
    reader.set_transport(transport)

    async def pump() -> None:
        try:
            while True:
                await transport.wait_resumed()
                data = await raw.read(_READ_CHUNK)
                if not data:
                    break
                reader.feed_data(data)
        except Exception as exc:  # pragma: no cover - transport errors
            reader.set_exception(exc)
            return
        reader.feed_eof()

    return reader, asyncio.get_running_loop().create_task(pump())


class StdinWriter:
    """The ``asyncio.StreamWriter`` surface over a remote stdin pipe.

    ``write()`` queues data; ``await drain()`` waits until it has been sent.
    ``close()`` sends EOF once queued data is out; ``await wait_closed()``
    waits for that.
    """

    def __init__(self, raw: _AsyncChildStdin):
        self._raw = raw
        self._queue: collections.deque[bytes] = collections.deque()
        self._wakeup = asyncio.Event()
        self._idle = asyncio.Event()
        self._idle.set()
        self._closing = False
        self._exc: Optional[BaseException] = None
        loop = asyncio.get_running_loop()
        self._closed: asyncio.Future[None] = loop.create_future()
        self._task = loop.create_task(self._run())

    async def _run(self) -> None:
        # Single consumer; `write()`/`close()` are synchronous, so there is no
        # await between checking the queue and waiting for a wake-up.
        try:
            while True:
                while self._queue:
                    item = self._queue.popleft()
                    if self._exc is None:
                        try:
                            await self._raw.write(item)
                        except Exception as exc:
                            self._exc = exc
                if self._closing:
                    try:
                        await self._raw.close()
                    except Exception as exc:
                        if self._exc is None:
                            self._exc = exc
                    return
                self._idle.set()
                self._wakeup.clear()
                await self._wakeup.wait()
                self._idle.clear()
        finally:
            self._idle.set()
            if not self._closed.done():
                self._closed.set_result(None)

    def _kick(self) -> None:
        self._idle.clear()
        self._wakeup.set()

    @property
    def transport(self) -> Any:
        return None

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default

    def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
        if self._closing:
            return
        self._queue.append(bytes(data))
        self._kick()

    def writelines(self, data) -> None:
        for chunk in data:
            self.write(chunk)

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._kick()

    def is_closing(self) -> bool:
        return self._closing

    async def wait_closed(self) -> None:
        await asyncio.shield(self._closed)
        self._raise()

    async def drain(self) -> None:
        """Wait until all queued data has been written."""
        if self._exc is not None:
            raise self._exc
        await self._idle.wait()
        self._raise()

    def _raise(self) -> None:
        if self._exc is not None:
            exc, self._exc = self._exc, None
            raise exc


# ---------------------------------------------------------------------------
# Process
# ---------------------------------------------------------------------------


class Process:
    """A remote process, shaped like :class:`asyncio.subprocess.Process`."""

    def __init__(self, child: _AsyncChild, limit: int):
        self._child = child
        self._tasks: list[asyncio.Task[None]] = []
        self.pid: Optional[int] = None
        self.stdin: Optional[StdinWriter] = StdinWriter(child.stdin) if child.stdin is not None else None
        self.stdout: Optional[asyncio.StreamReader] = None
        self.stderr: Optional[asyncio.StreamReader] = None
        if child.stdout is not None:
            self.stdout, t = _start_reader(child.stdout, limit)
            self._tasks.append(t)
        if child.stderr is not None:
            self.stderr, t = _start_reader(child.stderr, limit)
            self._tasks.append(t)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} returncode={self.returncode}>"

    @property
    def returncode(self) -> Optional[int]:
        """The return code, or None while the process runs.

        Also None if the process failed to start (``wait()`` raises the error).
        """
        try:
            return self._child.returncode
        except TuesError:
            return None

    async def wait(self) -> int:
        """Wait for the process to terminate and return its return code."""
        return await self._child.wait()

    def _done(self) -> bool:
        """True once the process has exited or failed to start."""
        try:
            return self._child.poll() is not None
        except TuesError:
            return True

    def send_signal(self, sig: Union[int, str]) -> None:
        if self._done():
            return
        self._child.send_signal(_common.signal_to_name(sig))

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        if self._done():
            return
        self._child.kill()

    async def _feed_stdin(self, input: Optional[bytes]) -> None:
        assert self.stdin is not None
        if input is not None:
            self.stdin.write(input)
        try:
            await self.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # communicate() ignores broken pipe errors.
        self.stdin.close()
        try:
            await self.stdin.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass

    async def _noop(self) -> None:
        return None

    async def _read_stream(self, stream: asyncio.StreamReader) -> bytes:
        return await stream.read()

    async def communicate(self, input: Optional[bytes] = None) -> tuple[Optional[bytes], Optional[bytes]]:
        """Send ``input``, read stdout/stderr to EOF and wait for exit."""
        stdin = self._feed_stdin(input) if self.stdin is not None else self._noop()
        stdout = self._read_stream(self.stdout) if self.stdout is not None else self._noop()
        stderr = self._read_stream(self.stderr) if self.stderr is not None else self._noop()
        _, out, err = await asyncio.gather(stdin, stdout, stderr)
        await self.wait()
        return (out, err)


# ---------------------------------------------------------------------------
# AsyncSession
# ---------------------------------------------------------------------------


class AsyncSession:
    """An asyncio SSH session; ``asyncio.subprocess`` for one remote host."""

    def __init__(self, inner: _AsyncSession):
        if not isinstance(inner, _AsyncSession):
            raise TypeError("connecting is asynchronous; use `await AsyncSession.connect(destination, ...)`")
        self._inner = inner

    @classmethod
    async def connect(cls, destination: str, **options: Any) -> "AsyncSession":
        """Connect; same arguments as :meth:`tues.Session.connect`."""
        return cls(await _AsyncSession.connect(destination, **options))

    @property
    def login_user(self) -> str:
        """The user the session authenticated as."""
        return self._inner.login_user

    @property
    def host(self) -> str:
        return self._inner.host

    @property
    def port(self) -> int:
        return self._inner.port

    @property
    def user(self) -> Optional[str]:
        """Default user commands run as, or None for the login user."""
        return self._inner.user

    @property
    def closed(self) -> bool:
        return self._inner.closed

    async def close(self) -> None:
        await self._inner.close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    def __repr__(self) -> str:
        return repr(self._inner)

    async def sftp(self) -> AsyncSftp:
        """Open an SFTP session."""
        return await self._inner.sftp()

    # -- asyncio.subprocess surface -------------------------------------------

    async def _spawn(
        self,
        argv: list[str],
        shell: bool,
        *,
        stdin: Optional[int],
        stdout: Optional[int],
        stderr: Optional[int],
        limit: int,
        cwd: Union[str, bytes, "os.PathLike[Any]", None],
        env: Optional[Mapping[str, Optional[str]]],
        user: _common.User,
        pty: bool,
    ) -> Process:
        for name, v in (("stdin", stdin), ("stdout", stdout)):
            if v not in (None, PIPE, DEVNULL):
                raise ValueError(f"{name} must be None, PIPE or DEVNULL in the asyncio API")
        if stderr not in (None, PIPE, DEVNULL, STDOUT):
            raise ValueError("stderr must be None, PIPE, DEVNULL or STDOUT in the asyncio API")
        if stdin is None:
            stdin = DEVNULL
        if stderr == STDOUT:
            argv, shell = _common.merge_stderr(argv, shell)
            stderr = DEVNULL
        child = await self._inner.spawn(
            argv,
            shell=shell,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=_common.normalize_cwd(cwd),
            env=_common.normalize_env(env),
            user=user,
            pty=pty,
        )
        return Process(child, limit)

    async def create_subprocess_exec(
        self,
        program: Union[str, bytes, "os.PathLike[Any]"],
        *args: Union[str, bytes, "os.PathLike[Any]"],
        stdin: Optional[int] = None,
        stdout: Optional[int] = None,
        stderr: Optional[int] = None,
        limit: int = _DEFAULT_LIMIT,
        cwd: Union[str, bytes, "os.PathLike[Any]", None] = None,
        env: Optional[Mapping[str, Optional[str]]] = None,
        user: _common.User = None,
        pty: bool = False,
    ) -> Process:
        """Start ``program`` with ``args``; see :func:`asyncio.create_subprocess_exec`."""
        argv = _common.normalize_args([program, *args])
        return await self._spawn(
            argv, False, stdin=stdin, stdout=stdout, stderr=stderr, limit=limit, cwd=cwd, env=env,
            user=user, pty=pty,
        )

    async def create_subprocess_shell(
        self,
        cmd: Union[str, bytes],
        stdin: Optional[int] = None,
        stdout: Optional[int] = None,
        stderr: Optional[int] = None,
        limit: int = _DEFAULT_LIMIT,
        cwd: Union[str, bytes, "os.PathLike[Any]", None] = None,
        env: Optional[Mapping[str, Optional[str]]] = None,
        user: _common.User = None,
        pty: bool = False,
    ) -> Process:
        """Run ``cmd`` in the remote shell; see :func:`asyncio.create_subprocess_shell`."""
        if not isinstance(cmd, (str, bytes)):
            raise ValueError(f"cmd must be a string, not {type(cmd).__name__}")
        argv = _common.normalize_args(cmd)
        return await self._spawn(
            argv, True, stdin=stdin, stdout=stdout, stderr=stderr, limit=limit, cwd=cwd, env=env,
            user=user, pty=pty,
        )

    async def run(
        self,
        args: Args,
        *,
        stdin: Optional[int] = None,
        input: Union[str, bytes, None] = None,
        stdout: Optional[int] = None,
        stderr: Optional[int] = None,
        capture_output: bool = False,
        shell: bool = False,
        cwd: Union[str, bytes, "os.PathLike[Any]", None] = None,
        timeout: Optional[float] = None,
        check: bool = False,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        text: Optional[bool] = None,
        universal_newlines: Optional[bool] = None,
        env: Optional[Mapping[str, Optional[str]]] = None,
        limit: int = _DEFAULT_LIMIT,
        user: _common.User = None,
        pty: bool = False,
    ) -> CompletedProcess:
        """Run a command to completion; the asyncio twin of :func:`subprocess.run`."""
        if input is not None:
            if stdin is not None:
                raise ValueError("stdin and input arguments may not both be used.")
            stdin = PIPE
        if capture_output:
            if stdout is not None or stderr is not None:
                raise ValueError("stdout and stderr arguments may not be used with capture_output.")
            stdout = PIPE
            stderr = PIPE
        text_mode = _common.is_text_mode(text, encoding, errors, universal_newlines)
        enc = _common.text_encoding(encoding) if text_mode else (encoding or "utf-8")
        data = _common.encode_input(input, text_mode, enc, errors)

        def decode(raw: Optional[bytes]) -> Any:
            if raw is None or not text_mode:
                return raw
            return _common.translate_newlines(raw, enc, errors)

        argv = _common.normalize_args(args)
        process = await self._spawn(
            argv, shell, stdin=stdin, stdout=stdout, stderr=stderr, limit=limit, cwd=cwd, env=env,
            user=user, pty=pty,
        )
        # Chunks are collected outside the awaited coroutine so that output
        # read before a timeout survives the cancellation.
        out_chunks: Optional[list[bytes]] = [] if process.stdout is not None else None
        err_chunks: Optional[list[bytes]] = [] if process.stderr is not None else None

        async def drain(stream: Optional[asyncio.StreamReader], chunks: Optional[list[bytes]]) -> None:
            if stream is None:
                return
            while True:
                chunk = await stream.read(_READ_CHUNK)
                if not chunk:
                    return
                chunks.append(chunk)  # type: ignore[union-attr]

        async def communicate(input: Optional[bytes]) -> None:
            feed = process._feed_stdin(input) if process.stdin is not None else process._noop()
            await asyncio.gather(feed, drain(process.stdout, out_chunks), drain(process.stderr, err_chunks))
            await process.wait()

        def joined(chunks: Optional[list[bytes]]) -> Optional[bytes]:
            return None if chunks is None else b"".join(chunks)

        try:
            if timeout is None:
                await communicate(data)
            else:
                await asyncio.wait_for(communicate(data), timeout)
        except asyncio.TimeoutError:
            process.kill()
            await communicate(None)
            raise TimeoutExpired(args, timeout, output=decode(joined(out_chunks)), stderr=decode(joined(err_chunks))) from None  # type: ignore[arg-type]
        except BaseException:
            process.kill()
            raise
        retcode = await process.wait()
        stdout_data, stderr_data = decode(joined(out_chunks)), decode(joined(err_chunks))
        if check and retcode:
            raise CalledProcessError(retcode, args, output=stdout_data, stderr=stderr_data)
        return CompletedProcess(args, retcode, stdout_data, stderr_data)
