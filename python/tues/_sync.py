"""Blocking API: ``Session`` (connection) and ``Popen`` (remote process).

The shapes follow :mod:`subprocess`; see the module docstring of
:mod:`tues` for the intentional differences.
"""

from __future__ import annotations

import io
import os
import shutil
import signal as _signal
import threading
import time
import warnings
from typing import IO, Any, Mapping, Optional, Union

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
from ._tues import Child as _Child
from ._tues import ChildStdin as _ChildStdin
from ._tues import ChildStdout as _ChildStdout
from ._tues import Session as _Session
from ._tues import Sftp, TuesError

__all__ = ["Session", "Popen"]

_StdioArg = Union[None, int, IO[Any]]


# ---------------------------------------------------------------------------
# Raw pipes as io objects
# ---------------------------------------------------------------------------


class _PipeReader(io.RawIOBase):
    """``RawIOBase`` over a remote stdout/stderr pipe."""

    def __init__(self, raw: _ChildStdout):
        self._raw = raw

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        data = self._raw.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def close(self) -> None:
        if not self.closed:
            self._raw.close()
        super().close()


class _PipeWriter(io.RawIOBase):
    """``RawIOBase`` over a remote stdin pipe."""

    def __init__(self, raw: _ChildStdin):
        self._raw = raw

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        return self._raw.write(bytes(b))

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            finally:
                super().close()


def _copy_to_file(src: IO[bytes], dst: IO[Any]) -> None:
    """Pump a remote output pipe into a caller-supplied file object."""
    with src:
        shutil.copyfileobj(src, dst)


def _copy_from_file(src: IO[Any], dst: IO[bytes]) -> None:
    """Pump a caller-supplied file object into the remote stdin pipe."""
    try:
        with dst:
            shutil.copyfileobj(src, dst)
    except BrokenPipeError:
        pass


# ---------------------------------------------------------------------------
# Popen
# ---------------------------------------------------------------------------


class Popen:
    """A remote process, shaped like :class:`subprocess.Popen`.

    Usually created through :meth:`Session.Popen`. ``stdin``, ``stdout`` and
    ``stderr`` accept ``None``, ``PIPE``, ``DEVNULL``, ``STDOUT`` (stderr
    only) or a file object. ``None`` means the local process's stdout/stderr
    for output; for stdin it means *no input* (EOF), because a remote process
    cannot share the local terminal. Pass ``stdin=sys.stdin`` to forward it.
    """

    def __init__(
        self,
        session: "Session",
        args: Args,
        bufsize: int = -1,
        *,
        stdin: _StdioArg = None,
        stdout: _StdioArg = None,
        stderr: _StdioArg = None,
        shell: bool = False,
        cwd: Union[str, bytes, "os.PathLike[Any]", None] = None,
        env: Optional[Mapping[str, Optional[str]]] = None,
        universal_newlines: Optional[bool] = None,
        text: Optional[bool] = None,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        user: _common.User = None,
        pty: bool = False,
    ):
        if not isinstance(bufsize, int):
            raise TypeError("bufsize must be an integer")
        self.args = args
        self.returncode: Optional[int] = None
        self.pid: Optional[int] = None
        self.stdin: Optional[IO[Any]] = None
        self.stdout: Optional[IO[Any]] = None
        self.stderr: Optional[IO[Any]] = None
        self._communication_started = False
        self._copiers: list[threading.Thread] = []

        self.text_mode = _common.is_text_mode(text, encoding, errors, universal_newlines)
        self.encoding = _common.text_encoding(encoding) if self.text_mode else encoding
        self.errors = errors

        line_buffering = False
        if bufsize == 1:
            line_buffering = True
            if not self.text_mode:
                warnings.warn(
                    "line buffering (buffering=1) is not supported in binary mode, "
                    "the default buffer size will be used",
                    RuntimeWarning,
                    2,
                )
            bufsize = -1
        if bufsize < 0:
            bufsize = io.DEFAULT_BUFFER_SIZE

        argv = _common.normalize_args(args)
        if stderr == STDOUT:
            argv, shell = _common.merge_stderr(argv, shell)
            stderr = DEVNULL

        c_stdin, self._stdin_file = self._core_stdio(stdin, is_input=True)
        c_stdout, self._stdout_file = self._core_stdio(stdout, is_input=False)
        c_stderr, self._stderr_file = self._core_stdio(stderr, is_input=False)

        self._child: _Child = session._inner.spawn(
            argv,
            shell=shell,
            stdin=c_stdin,
            stdout=c_stdout,
            stderr=c_stderr,
            cwd=_common.normalize_cwd(cwd),
            env=_common.normalize_env(env),
            user=user,
            pty=pty,
        )

        raw_in, raw_out, raw_err = self._child.stdin, self._child.stdout, self._child.stderr
        if raw_in is not None:
            if self._stdin_file is not None:
                # Not joined in wait(): a source such as sys.stdin may never
                # reach EOF; the thread ends when the pipe breaks instead.
                self._start_copier(_copy_from_file, self._stdin_file, io.BufferedWriter(_PipeWriter(raw_in)), join=False)
            else:
                self.stdin = self._wrap_writer(raw_in, bufsize, line_buffering)
        if raw_out is not None:
            if self._stdout_file is not None:
                self._start_copier(_copy_to_file, io.BufferedReader(_PipeReader(raw_out)), self._stdout_file)
            else:
                self.stdout = self._wrap_reader(raw_out, bufsize)
        if raw_err is not None:
            if self._stderr_file is not None:
                self._start_copier(_copy_to_file, io.BufferedReader(_PipeReader(raw_err)), self._stderr_file)
            else:
                self.stderr = self._wrap_reader(raw_err, bufsize)

    # -- construction helpers -------------------------------------------------

    @staticmethod
    def _core_stdio(value: _StdioArg, *, is_input: bool) -> tuple[Optional[int], Optional[IO[Any]]]:
        """Map a ``subprocess``-style stdio argument to (core value, file object)."""
        if value is None:
            return (DEVNULL if is_input else None), None
        if value == PIPE or value == DEVNULL:
            return value, None
        if isinstance(value, int):
            raise ValueError(f"unsupported stdio value {value!r}; use PIPE, DEVNULL, STDOUT or a file object")
        if hasattr(value, "read" if is_input else "write"):
            return PIPE, value
        raise TypeError(f"stdio must be None, PIPE, DEVNULL, STDOUT or a file object, not {type(value).__name__}")

    def _start_copier(self, fn, src, dst, *, join: bool = True) -> None:
        t = threading.Thread(target=fn, args=(src, dst), daemon=True, name="tues-stdio-copier")
        t.start()
        if join:
            self._copiers.append(t)

    def _wrap_reader(self, raw: _ChildStdout, bufsize: int) -> IO[Any]:
        f: IO[Any] = _PipeReader(raw)
        if bufsize:
            f = io.BufferedReader(f, bufsize)
        if self.text_mode:
            f = io.TextIOWrapper(f, encoding=self.encoding, errors=self.errors)
        return f

    def _wrap_writer(self, raw: _ChildStdin, bufsize: int, line_buffering: bool) -> IO[Any]:
        f: IO[Any] = _PipeWriter(raw)
        if bufsize:
            f = io.BufferedWriter(f, bufsize)
        if self.text_mode:
            f = io.TextIOWrapper(
                f,
                encoding=self.encoding,
                errors=self.errors,
                write_through=True,
                line_buffering=line_buffering,
            )
        return f

    # -- subprocess.Popen surface ---------------------------------------------

    @property
    def universal_newlines(self) -> bool:
        return self.text_mode

    @universal_newlines.setter
    def universal_newlines(self, value: bool) -> None:
        self.text_mode = bool(value)

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: returncode: {self.returncode} args: {self.args!r}>"

    def __enter__(self) -> "Popen":
        return self

    def __exit__(self, exc_type, value, traceback) -> None:
        if self.stdout:
            self.stdout.close()
        if self.stderr:
            self.stderr.close()
        try:
            if self.stdin:
                self.stdin.close()
        finally:
            if exc_type is KeyboardInterrupt:
                return
            try:
                self.wait()
            except TuesError:
                # A failure to start (e.g. sudo rejected the password) has
                # already been raised from wait()/communicate(); do not
                # replace the exception being propagated.
                if exc_type is None:
                    raise

    def _done(self) -> bool:
        """True once the process has exited or failed to start."""
        try:
            return self.poll() is not None
        except TuesError:
            return True

    def poll(self) -> Optional[int]:
        """Check if the process has terminated; set and return ``returncode``."""
        if self.returncode is None:
            rc = self._child.poll()
            if rc is not None:
                self._finish(rc)
        return self.returncode

    def wait(self, timeout: Optional[float] = None) -> int:
        """Wait for the process to terminate; set and return ``returncode``."""
        if self.returncode is None:
            rc = self._child.wait(timeout)
            if rc is None:
                raise TimeoutExpired(self.args, timeout)  # type: ignore[arg-type]
            self._finish(rc)
        return self.returncode  # type: ignore[return-value]

    def _finish(self, rc: int) -> None:
        self.returncode = rc
        # Caller-supplied file objects: make sure everything has been copied
        # before we report the process as finished.
        for t in self._copiers:
            t.join()
        self._copiers.clear()

    def send_signal(self, sig: Union[int, str]) -> None:
        """Send a signal (``signal.SIGTERM``, ``15`` or ``"TERM"``) to the process."""
        if self._done():
            return
        self._child.send_signal(_common.signal_to_name(sig))

    def terminate(self) -> None:
        """Send SIGTERM. The process may handle it; the exit status is its own."""
        self.send_signal(_signal.SIGTERM)

    def kill(self) -> None:
        """Send SIGKILL and close the channel."""
        if self._done():
            return
        self._child.kill()

    def communicate(self, input=None, timeout: Optional[float] = None):
        """Send ``input`` to stdin, read stdout/stderr to EOF and wait.

        Returns ``(stdout_data, stderr_data)``; entries are ``None`` for
        streams that were not ``PIPE``. Raises :class:`TimeoutExpired` if the
        process has not finished after ``timeout`` seconds; it is not killed,
        and calling ``communicate()`` again (without input) finishes the job.
        """
        if self._communication_started and input:
            raise ValueError("Cannot send input after starting communication")

        # Fast path: at most one pipe and no timeout.
        if timeout is None and not self._communication_started and [self.stdin, self.stdout, self.stderr].count(None) >= 2:
            stdout = None
            stderr = None
            if self.stdin:
                self._stdin_write(input)
            elif self.stdout:
                stdout = self.stdout.read()
                self.stdout.close()
            elif self.stderr:
                stderr = self.stderr.read()
                self.stderr.close()
            self.wait()
        else:
            endtime = time.monotonic() + timeout if timeout is not None else None
            try:
                stdout, stderr = self._communicate(input, endtime, timeout)
            finally:
                self._communication_started = True
            self.wait(timeout=self._remaining_time(endtime))
        return (stdout, stderr)

    @staticmethod
    def _remaining_time(endtime: Optional[float]) -> Optional[float]:
        if endtime is None:
            return None
        return endtime - time.monotonic()

    def _stdin_write(self, input) -> None:
        if input:
            try:
                self.stdin.write(input)  # type: ignore[union-attr]
            except BrokenPipeError:
                pass  # communicate() must ignore broken pipe errors.
            except OSError as exc:
                if exc.errno == 22:  # EINVAL
                    pass
                else:
                    raise
        try:
            self.stdin.close()  # type: ignore[union-attr]
        except BrokenPipeError:
            pass

    @staticmethod
    def _readerthread(fh: IO[Any], buffer: list) -> None:
        buffer.append(fh.read())
        fh.close()

    def _communicate(self, input, endtime: Optional[float], orig_timeout: Optional[float]):
        # Reader threads, started once; a second communicate() after a
        # timeout just keeps waiting for them.
        if self.stdout and not hasattr(self, "_stdout_buff"):
            self._stdout_buff: list = []
            self._stdout_thread = threading.Thread(target=self._readerthread, args=(self.stdout, self._stdout_buff), daemon=True)
            self._stdout_thread.start()
        if self.stderr and not hasattr(self, "_stderr_buff"):
            self._stderr_buff: list = []
            self._stderr_thread = threading.Thread(target=self._readerthread, args=(self.stderr, self._stderr_buff), daemon=True)
            self._stderr_thread.start()

        if self.stdin:
            self._stdin_write(input)

        if self.stdout is not None:
            self._stdout_thread.join(self._remaining_time(endtime))
            if self._stdout_thread.is_alive():
                raise TimeoutExpired(self.args, orig_timeout)  # type: ignore[arg-type]
        if self.stderr is not None:
            self._stderr_thread.join(self._remaining_time(endtime))
            if self._stderr_thread.is_alive():
                raise TimeoutExpired(self.args, orig_timeout)  # type: ignore[arg-type]

        stdout = self._stdout_buff[0] if self.stdout and self._stdout_buff else None
        stderr = self._stderr_buff[0] if self.stderr and self._stderr_buff else None
        return (stdout, stderr)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class Session:
    """A blocking SSH session; the ``subprocess`` module for one remote host.

    ``Session(destination, **options)`` connects immediately;
    ``Session.connect`` is an alias. See :func:`tues.Session.connect` for the
    connection options.
    """

    def __init__(self, destination: str, **options: Any):
        self._inner: _Session = _Session.connect(destination, **options)

    @classmethod
    def connect(cls, destination: str, **options: Any) -> "Session":
        """Connect to ``destination`` (``host``, ``login-user@host``, ``host:port`` or
        an ssh_config alias).

        Options: ``login_user``, ``port``, ``user`` (default user commands
        run as, via sudo), ``host_name``, ``identity_files``, ``identities_only``,
        ``proxy_jump``, ``connect_timeout``, ``server_alive_interval``,
        ``compression``, ``use_agent``, ``pubkey_authentication``,
        ``password_authentication``, ``host_key_policy`` (``"strict"`` |
        ``"accept-new"`` | ``"off"``), ``known_hosts_file``, ``ssh_config``
        (path, or ``False`` to disable), ``password`` (static),
        ``password_manager`` (callable or object with ``get``/``invalidate``).
        """
        return cls(destination, **options)

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

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return repr(self._inner)

    def sftp(self) -> Sftp:
        """Open an SFTP session."""
        return self._inner.sftp()

    # -- subprocess module surface --------------------------------------------

    def Popen(self, args: Args, bufsize: int = -1, **kwargs: Any) -> Popen:
        """Start a remote process; see :class:`Popen`."""
        return Popen(self, args, bufsize, **kwargs)

    def run(
        self,
        args: Args,
        *,
        input=None,
        capture_output: bool = False,
        timeout: Optional[float] = None,
        check: bool = False,
        **kwargs: Any,
    ) -> CompletedProcess:
        """Run a command to completion; see :func:`subprocess.run`.

        Returns a :class:`CompletedProcess`. With ``capture_output=True`` (or
        ``stdout=PIPE`` / ``stderr=PIPE``) the output is captured; otherwise
        it goes to the local stdout/stderr. ``check=True`` raises
        :class:`CalledProcessError` on a non-zero exit. ``timeout`` kills the
        process and raises :class:`TimeoutExpired`.
        """
        if input is not None:
            if kwargs.get("stdin") is not None:
                raise ValueError("stdin and input arguments may not both be used.")
            kwargs["stdin"] = PIPE
        if capture_output:
            if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
                raise ValueError("stdout and stderr arguments may not be used with capture_output.")
            kwargs["stdout"] = PIPE
            kwargs["stderr"] = PIPE

        with self.Popen(args, **kwargs) as process:
            try:
                stdout, stderr = process.communicate(input, timeout=timeout)
            except TimeoutExpired as exc:
                process.kill()
                exc.stdout, exc.stderr = process.communicate()
                raise
            except BaseException:
                process.kill()
                raise
            retcode = process.poll()
            if check and retcode:
                raise CalledProcessError(retcode, process.args, output=stdout, stderr=stderr)
        return CompletedProcess(process.args, retcode, stdout, stderr)  # type: ignore[arg-type]

    def call(self, args: Args, *, timeout: Optional[float] = None, **kwargs: Any) -> int:
        """Run a command and return its return code; see :func:`subprocess.call`."""
        with self.Popen(args, **kwargs) as p:
            try:
                return p.wait(timeout=timeout)
            except BaseException:
                p.kill()
                raise

    def check_call(self, args: Args, *, timeout: Optional[float] = None, **kwargs: Any) -> int:
        """Run a command; raise :class:`CalledProcessError` on a non-zero exit."""
        retcode = self.call(args, timeout=timeout, **kwargs)
        if retcode:
            raise CalledProcessError(retcode, args)
        return 0

    def check_output(self, args: Args, *, timeout: Optional[float] = None, **kwargs: Any):
        """Run a command and return its stdout; see :func:`subprocess.check_output`."""
        if "stdout" in kwargs:
            raise ValueError("stdout argument not allowed, it will be overridden.")
        if "input" in kwargs and kwargs["input"] is None:
            kwargs["input"] = "" if _common.is_text_mode(kwargs.get("text"), kwargs.get("encoding"), kwargs.get("errors"), kwargs.get("universal_newlines")) else b""
        return self.run(args, stdout=PIPE, timeout=timeout, check=True, **kwargs).stdout

    def getstatusoutput(self, cmd: Args, *, encoding: Optional[str] = None, errors: Optional[str] = None, **kwargs: Any) -> tuple[int, str]:
        """Return ``(returncode, output)`` of ``cmd`` run in the remote shell.

        stderr is merged into stdout and a single trailing newline is
        stripped; see :func:`subprocess.getstatusoutput`.
        """
        try:
            data = self.check_output(cmd, shell=True, text=True, stderr=STDOUT, encoding=encoding, errors=errors, **kwargs)
            exitcode = 0
        except CalledProcessError as ex:
            data = ex.output
            exitcode = ex.returncode
        if data[-1:] == "\n":
            data = data[:-1]
        return exitcode, data

    def getoutput(self, cmd: Args, *, encoding: Optional[str] = None, errors: Optional[str] = None, **kwargs: Any) -> str:
        """Return the output of ``cmd`` run in the remote shell; see :func:`subprocess.getoutput`."""
        return self.getstatusoutput(cmd, encoding=encoding, errors=errors, **kwargs)[1]
