"""Legacy multi-host API from the original tues package.

Implemented on :class:`tues.Session` and kept so existing callers keep
working. New code should use :class:`tues.Session` directly; this module is
meant to be removed.

A command is still a shell line (``sh -c``), files are uploaded for the
duration of the command, and ``sudo`` is used when ``user`` is not the login
user. Connection details the original API did not have (identity files, host
keys, timeouts, …) go in ``connect_options`` and are forwarded to
:meth:`Session.connect`.

``tues.run("web01", "id")`` returns one :class:`Task`. A list of hosts returns
a list of tasks, in the same order. ``pool_size`` is how many hosts run at
once. ``check=True`` stops at the first non-zero exit and is only valid with
``pool_size == 1``.

Callers branch on the exceptions, so they match the original package:

* :class:`TuesTaskError` — ``args[0]`` is the :class:`Task`. ``__cause__`` is
  set when the host failed before a status, and left unset when ``check``
  saw a non-zero exit.
* :class:`TuesUserAbort` — the password manager refused a login or sudo
  password. A rejected password is a finished task, not this exception.
* :class:`TuesErrorGroup` — parallel connection failures. ``message``,
  ``exceptions``, and ``results`` are the attributes callers read.
"""

from __future__ import annotations

import errno
import glob
import io
import json
import locale
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import threading
import urllib.parse

try:
    import termios
except ImportError:  # Windows has no termios; the prompt falls back to getpass.
    termios = None  # type: ignore[assignment]
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Mapping, Optional, Sequence, Union

from ._common import DEVNULL, PIPE, STDOUT
from ._sync import Session
from ._tues import PasswordPromptFinish, SudoError, TuesError, password_prompt_finish_bytes

__all__ = [
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
    "PasswordManager",
    "PasswordPromptFinish",
    "Host",
    "Task",
    "Script",
    "provider",
    "run",
]

DIR_ABORT = "abort"
DIR_ROTATE = "rotate"
DIR_WIPE = "wipe"
DIR_IGNORE = "ignore"

DEFAULT_ENCODING = locale.getpreferredencoding(False)

DEFAULT_PATH = [
    os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config/")),
        "tues",
        "scripts",
    ),
]

# Keys a script's ``tues-args`` object may set. Callers of :meth:`Script.run`
# may still pass anything :func:`run` accepts.
_SCRIPT_ARG_KEYS = {
    "login_user",
    "files",
    "outfile",
    "output_dir",
    "output_dir_strategy",
    "prefix",
    "user",
    "pty",
    "input",
    "check",
    "pool_size",
}

_HostSpec = Union[str, tuple]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TuesErrorGroup(TuesError):
    """Failures from a parallel run, plus the tasks that did finish.

    ``exceptions`` is in host order. ``results`` is the tasks that completed
    without raising.
    """

    def __init__(self, message: str, exceptions: Sequence[BaseException], results: Sequence["Task"]):
        super().__init__(message)
        self.message = message
        self.exceptions = list(exceptions)
        self.results = list(results)


class TuesLookupError(TuesError):
    """A host provider could not be run."""


class TuesScriptNotFoundError(TuesError):
    """A script name was not found on the configured path."""


class TuesOutputDirExists(TuesError):
    """``output_dir`` already exists and the strategy is :data:`DIR_ABORT`."""


class TuesUserAbort(TuesError):
    """sudo or login was refused because no password was available."""


class TuesTaskError(TuesError):
    """A host failed, or ``check=True`` saw a non-zero status.

    ``args[0]`` is the :class:`Task`. ``stdout`` and ``stderr`` are that
    task's captured output (``None`` when the stream was not captured).
    ``__cause__`` is set when the host failed before a status. A non-zero
    exit leaves it unset, so callers can tell the two cases apart.
    """

    def __init__(self, task: "Task"):
        super().__init__(task)
        self.args = (task,)

    @property
    def stdout(self):
        return self.args[0].stdout

    @property
    def stderr(self):
        return self.args[0].stderr


# ---------------------------------------------------------------------------
# Password prompt
#
# ``pool_size > 1`` asks on a worker thread. Ctrl+C is delivered to the main
# thread, and exiting from there skips the prompter's ``finally``, which is
# what used to leave the terminal with echo disabled. The snapshot is the
# mode from before we hid the password; the signal handler applies it, then
# writes the wake pipe so the worker's read returns and restores it too.
# The snapshot is published under the GIL and read from the signal handler
# without a lock, so the handler cannot deadlock on the prompt.
# ---------------------------------------------------------------------------

_prompt_gate = threading.Lock()
_tty_snapshot = None
_wake_r, _wake_w = os.pipe()
os.set_blocking(_wake_r, False)
os.set_blocking(_wake_w, False)


def _tty_encoding(fd: int) -> str:
    return os.device_encoding(fd) or "utf-8"


def _apply_tty(attrs) -> None:
    if attrs is None or termios is None:
        return
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return
    try:
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except termios.error:
        pass
    finally:
        os.close(fd)


def _interrupt_prompt() -> None:
    """Restore the terminal and unblock a prompt on another thread."""
    active = _tty_snapshot is not None
    _apply_tty(_tty_snapshot)
    if not active:
        return
    try:
        os.write(_wake_w, b"x")
    except OSError:
        pass


def _drain_wake() -> None:
    while True:
        try:
            chunk = os.read(_wake_r, 64)
        except OSError:
            return
        if not chunk:
            return


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _read_hidden_line(fd: int) -> Optional[str]:
    chunks = []
    while True:
        try:
            ready, _, _ = select.select([fd, _wake_r], [], [])
        except KeyboardInterrupt:
            return None
        if _wake_r in ready:
            _drain_wake()
            return None
        try:
            data = os.read(fd, 1024)
        except InterruptedError:
            continue
        if not data:
            return None
        chunks.append(data)
        if b"\n" in data or b"\r" in data:
            break
    text = b"".join(chunks).split(b"\r", 1)[0].split(b"\n", 1)[0]
    return text.decode(_tty_encoding(fd), "surrogateescape")


def _ask_getpass(message: str) -> Optional[str]:
    import getpass

    try:
        return getpass.getpass(message)
    except (EOFError, KeyboardInterrupt):
        return None


def _finish_prompt(fd: int, finish: PasswordPromptFinish) -> None:
    """Apply ``finish`` on ``fd``. The bytes come from the low-level prompt."""
    _write_all(fd, password_prompt_finish_bytes(finish))


def _ask_tty(message: str, finish: PasswordPromptFinish = PasswordPromptFinish.Newline) -> Optional[str]:
    if termios is None:
        return _ask_getpass(message)
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return _ask_getpass(message)
    try:
        attrs = termios.tcgetattr(fd)
    except termios.error:
        os.close(fd)
        return _ask_getpass(message)

    # Canonical mode stays on (ISIG too) so Ctrl+C is a signal, not a raw
    # byte, and the line discipline still edits the password. ECHONL is
    # cleared so Enter does not move the cursor; ``finish`` does that.
    hidden = attrs[:]
    hidden[3] = attrs[3] & ~termios.ECHO & ~termios.ECHONL
    global _tty_snapshot
    # A Ctrl+C that lands as the previous prompt finishes can leave a wake
    # byte behind. Drop it before this prompt starts waiting.
    _drain_wake()
    _tty_snapshot = attrs
    try:
        termios.tcsetattr(fd, termios.TCSANOW, hidden)
        _write_all(fd, message.encode(_tty_encoding(fd), "replace"))
        line = _read_hidden_line(fd)
        if line is not None:
            _finish_prompt(fd, finish)
        return line
    except (EOFError, KeyboardInterrupt):
        return None
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except termios.error:
            pass
        _tty_snapshot = None
        os.close(fd)
        _drain_wake()


# ---------------------------------------------------------------------------
# Password manager (original get/invalidate, also the Session protocol)
# ---------------------------------------------------------------------------


class PasswordManager:
    """Cache one password for login and sudo.

    A constructed password, or ``TUES_PW`` in the environment, is reused until
    :meth:`invalidate`. Otherwise :meth:`get` prompts once, including when
    several hosts ask together: one caller prompts and the others wait for
    that answer. A refusal (``None``) is remembered the same way, so a
    cancelled prompt is not asked again until :meth:`invalidate`. The same
    object satisfies :meth:`Session.connect`'s ``password_manager`` protocol
    (``get(request)`` / ``invalidate(request)``), so one answer serves every
    host in a run.

    ``prompt`` replaces the default question. It receives the prompt string
    and returns the password, or ``None`` to abort. The default reads from
    ``/dev/tty`` with echo turned off and restores the previous terminal mode
    if the prompt is interrupted. ``prompt_finish`` says what that default
    does with the cursor afterwards: :attr:`PasswordPromptFinish.Newline`
    (the legacy behaviour, so the next write starts on the following line),
    :attr:`PasswordPromptFinish.CurrentLine` (leave the cursor where it is),
    or :attr:`PasswordPromptFinish.Erase` (remove the prompt so later output
    is not prefixed by it). A custom ``prompt`` ignores ``prompt_finish``.
    """

    def __init__(
        self,
        prompt: Optional[Callable[[str], Optional[str]]] = None,
        password: Optional[str] = None,
        *,
        prompt_finish: PasswordPromptFinish = PasswordPromptFinish.Newline,
    ):
        self._lock = threading.Lock()
        self._prompt_finish = prompt_finish
        if prompt is not None:
            self._prompt = prompt
        self._password = password if password else os.environ.get("TUES_PW")
        self._have = self._password is not None

    def _prompt(self, message: str) -> Optional[str]:
        with _prompt_gate:
            return _ask_tty(message, self._prompt_finish)

    def get(self, message: Any = None) -> Optional[str]:
        """Return the cached password, prompting when ``message`` is given.

        ``message`` is a string, or a :class:`tues.PasswordRequest` whose
        ``prompt`` is used. With no message and no cached password, return
        ``None`` without prompting. Concurrent callers share one prompt.
        """
        if message is not None and not isinstance(message, str):
            message = getattr(message, "prompt", None)
        with self._lock:
            if message and not self._have:
                try:
                    self._password = self._prompt(message)
                except KeyboardInterrupt:
                    self._password = None
                    self._have = True
                    raise
                self._have = True
            return self._password

    def invalidate(self, message: Any = None) -> None:
        """Forget the cached password so the next :meth:`get` asks again."""
        del message
        with self._lock:
            self._password = None
            self._have = False


_PM = PasswordManager()


# ---------------------------------------------------------------------------
# Hosts and tasks
# ---------------------------------------------------------------------------


class Host:
    """A host passed to :func:`run`.

    A string uses the same forms as :meth:`Session.connect` (``host``,
    ``login-user@host``, ``host:port``, ``[ipv6]:port``). A ``(host, port)``
    tuple sets the port separately. ``name`` is the hostname used for prefixes
    and output files.
    """

    def __init__(self, spec: _HostSpec):
        self.spec = spec
        if isinstance(spec, tuple):
            self.name, port = spec
            self.port = int(port) if port else None
            self.destination = self.name
        elif isinstance(spec, str):
            parsed = urllib.parse.urlparse(f"ssh://{spec}")
            self.name = parsed.hostname or spec
            self.port = parsed.port
            self.destination = spec
        else:
            raise TypeError(f"host must be a string or (host, port), not {type(spec).__name__}")

    def __repr__(self) -> str:
        return f"Host({self.destination!r}, port={self.port!r})"


class Task:
    """One host's command, and its result after :func:`run` finishes.

    ``stdout`` and ``stderr`` are ``None`` unless that stream was captured
    (``capture_output``, or ``PIPE``). In text mode they are ``str``;
    otherwise ``bytes``. In PTY mode ``stderr`` is always ``None`` because the
    terminal merges it into stdout.
    """

    def __init__(
        self,
        cmd: str,
        host: Host,
        *,
        login_user: Optional[str] = None,
        files: Optional[Sequence[str]] = None,
        outfile: Optional[str] = None,
        prefix: bool = False,
        prefix_width_hint: Optional[int] = None,
        user: Optional[str] = None,
        pty: bool = False,
        universal_newlines: Optional[bool] = None,
        input=None,
        stdin=None,
        text: bool = False,
        errors: Optional[str] = None,
        encoding: Optional[str] = None,
        capture_output: bool = False,
        env: Optional[Mapping[str, Optional[str]]] = None,
        cwd: Optional[str] = None,
        preexec_fn: Optional[Callable[["Task"], None]] = None,
        postexec_fn: Optional[Callable[["Task"], None]] = None,
    ):
        if encoding or errors:
            text = True
        if text:
            if encoding is None:
                encoding = DEFAULT_ENCODING
            if errors is None:
                errors = "strict"
        if pty and (input is not None or stdin is not None):
            raise TuesError("Passing `input` or `stdin` in `pty` mode is not supported")
        if pty and universal_newlines is None:
            universal_newlines = True

        self.host = host.name
        self.port = host.port
        self.destination = host.destination
        self.connection = None
        self.cmd = cmd
        self.login_user = login_user
        self.files = list(files or [])
        self.outfile = outfile
        self.prefix = bool(prefix)
        self.prefix_width_hint = prefix_width_hint or len(self.host)
        self.user = user
        self.pty = pty
        self.universal_newlines = universal_newlines if pty else False
        self.input = input
        self.stdin = stdin
        self.text = text
        self.errors = errors
        self.encoding = encoding
        self.env = dict(env) if env is not None else None
        self.cwd = cwd
        self.capture_output = capture_output
        self.preexec_fn = preexec_fn
        self.postexec_fn = postexec_fn
        self.returncode: Optional[int] = None
        self.authorization_failed = False
        self._stdout: Optional["_Capture"] = None
        self._stderr: Optional["_Capture"] = None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} cmd={self.cmd!r} host={self.host!r} at 0x{id(self):x}>"

    @property
    def sudo(self) -> bool:
        """Whether the command runs through ``sudo``."""
        return self.user is not None and self.user != self.login_user

    @property
    def stdout(self):
        return self._decode(self._stdout)

    @property
    def stderr(self):
        return self._decode(self._stderr)

    def _decode(self, capture: Optional["_Capture"]):
        if capture is None:
            return None
        data = capture.getvalue()
        if self.text:
            return data.decode(self.encoding or DEFAULT_ENCODING, self.errors or "strict")
        return data


class _Capture:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._lock = threading.Lock()

    def write(self, data: bytes) -> None:
        with self._lock:
            self._buf.extend(data)

    def getvalue(self) -> bytes:
        with self._lock:
            return bytes(self._buf)


class _PrefixWriter:
    """Prefix each line, but not an empty line that has not started yet.

    A chunk that ends in ``\\n`` does not grow a prefix until the next byte
    arrives, so a finished line is ``[host]: line\\n`` and not a trailing
    ``[host]:`` with nothing after it.
    """

    def __init__(self, inner: Any, prefix: bytes):
        self._inner = inner
        self._prefix = prefix
        self._fresh = True

    def write(self, data: bytes) -> None:
        if not data:
            return
        eol = b"\n"
        if self._fresh:
            data = self._prefix + data
            self._fresh = False
        if data.endswith(eol):
            data = data[:-1].replace(eol, eol + self._prefix) + eol
            self._fresh = True
        else:
            data = data.replace(eol, eol + self._prefix)
        self._inner.write(data)


class _StreamSink:
    def __init__(self, fileobj: Any, task: Task, lock: threading.Lock):
        self._f = fileobj
        self._task = task
        self._lock = lock

    def write(self, data: bytes) -> None:
        if not data:
            return
        text = isinstance(self._f, io.TextIOBase)
        with self._lock:
            if text:
                encoding = self._task.encoding or DEFAULT_ENCODING
                self._f.write(data.decode(encoding, self._task.errors or "strict"))
            else:
                self._f.write(data)
            flush = getattr(self._f, "flush", None)
            if flush is not None:
                flush()


def _sink_for(
    target: Any,
    task: Task,
    lock: threading.Lock,
    *,
    capture: bool,
    default: Any,
) -> tuple[Any, Optional[_Capture]]:
    """Return ``(sink or None, capture or None)``.

    ``None`` means discard (``DEVNULL``). A capture stores bytes for
    :attr:`Task.stdout` / :attr:`Task.stderr`. ``default`` is the local
    stream used when ``target`` is ``None`` (stdout or stderr).
    """
    if capture or target is PIPE:
        cap = _Capture()
        return cap, cap
    if target is DEVNULL:
        return None, None
    if target is None:
        return _StreamSink(default, task, lock), None
    return _StreamSink(target, task, lock), None


def _open_outfile(task: Task, lock: threading.Lock) -> tuple[Any, list]:
    raw = open(task.outfile, "wb")  # type: ignore[arg-type]
    if task.text:
        wrapped = io.TextIOWrapper(raw, encoding=task.encoding, errors=task.errors)
        return _StreamSink(wrapped, task, lock), [wrapped.close]
    return _StreamSink(raw, task, lock), [raw.close]


# ---------------------------------------------------------------------------
# Providers and scripts
# ---------------------------------------------------------------------------


def _host_lines(text: str) -> list[str]:
    return [line for line in text.split("\n") if line and not line.startswith("#")]


def provider(name: str, args: Sequence[str]) -> list[str]:
    """Resolve ``name`` to a list of hosts.

    ``cl`` uses ``args`` as the hosts. ``file`` reads them from files, one
    host per line (``-`` reads stdin). Any other name runs
    ``tues-provider-<name>`` from ``PATH`` and reads the same line format from
    its stdout. Blank lines and lines starting with ``#`` are dropped.
    """
    args = [os.fsdecode(a) for a in args]
    if name == "cl":
        return _host_lines("\n".join(args))
    if name == "file":
        chunks: list[str] = []
        for path in args:
            try:
                if path == "-":
                    chunks.append(sys.stdin.read())
                else:
                    with open(path) as fh:
                        chunks.append(fh.read())
            except OSError as exc:
                raise TuesLookupError(f"Error reading hosts from {path!r}") from exc
        lines = []
        for chunk in chunks:
            lines.extend(line.strip() for line in chunk.splitlines())
        return _host_lines("\n".join(lines))

    cmd = [f"tues-provider-{name}", *args]
    try:
        output = subprocess.check_output(cmd, text=True)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        raise TuesLookupError(
            f"Provider {name!r} not found, make sure {cmd[0]!r} is on your PATH"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise TuesLookupError(f"Error running provider: {shlex.join(cmd)}") from exc
    return _host_lines(output)


class Script:
    """A local script uploaded and executed by :func:`run`.

    ``cmd`` is a command string or an argv list. The first word is looked up
    in ``paths`` (default :data:`DEFAULT_PATH`). A header line

    ``# tues-args = {"user": "root", "pty": false}``

    sets defaults for :func:`run`. ``# tues-provider`` and
    ``# tues-provider-args`` supply the hosts when :meth:`run` is called
    without any. Runtime keyword arguments override the header; ``None``
    leaves the header value in place.
    """

    def __init__(self, cmd: Union[str, Sequence[str]], paths: Optional[Sequence[str]] = None):
        if not paths:
            paths = DEFAULT_PATH
        if isinstance(cmd, str):
            self.script = shlex.split(cmd)[0]
            self.cmd = cmd
        else:
            argv = [os.fsdecode(a) for a in cmd]
            if not argv:
                raise TuesError("empty script command")
            self.script = argv[0]
            self.cmd = shlex.join(argv)

        for directory in paths:
            self.path = os.path.join(directory, self.script)
            if os.path.exists(self.path):
                break
        else:
            raise TuesScriptNotFoundError(f"Could not find {self.script} in {list(paths)!r}")

        sections = self._get_sections(self.path)
        self.run_args = sections.get("args", {})
        self.provider = sections.get("provider")
        self.provider_args = sections.get("provider-args")

    @staticmethod
    def _get_sections(path: str) -> dict:
        allowed = ["args", "provider", "provider-args"]
        sections: dict = {}
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("# tues-"):
                    continue
                key, sep, value = line[len("# tues-") :].partition("=")
                key = key.strip()
                if sep != "=" or key not in allowed:
                    raise TuesError(f"Error parsing script file, not a valid section name in line: '{line}'")
                sections[key] = json.loads(value.strip())
        return sections

    def run(self, hosts: Optional[Union[_HostSpec, Sequence[_HostSpec]]] = None, **kwargs: Any):
        """Upload this script and run it. See :func:`run`."""
        run_kwargs: dict[str, Any] = {
            key: value for key, value in self.run_args.items() if key in _SCRIPT_ARG_KEYS
        }
        if not hosts:
            if not self.provider:
                raise TuesError("No hosts")
            hosts = provider(self.provider, self.provider_args or [])
        run_kwargs["hosts"] = hosts

        for key, value in kwargs.items():
            if key == "files" or value is None:
                continue
            run_kwargs[key] = value

        files = list(run_kwargs.get("files") or [])
        extra = kwargs.get("files")
        if extra:
            files.extend(extra)
        files.append(self.path)
        run_kwargs["files"] = files
        run_kwargs.pop("hosts")
        # ``./`` applies to the script name; arguments stay behind it.
        command = f"chmod +x $TUES_FILE{len(files)} ; ./{self.cmd}"
        return run(hosts, command, **run_kwargs)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _user_refused(exc: BaseException) -> bool:
    """True when a password manager declined to answer.

    That is :class:`TuesUserAbort`. A wrong password is a finished task.
    """
    text = str(exc).lower()
    return "returned none" in text or "password unavailable" in text or "none was available" in text


def _sudo_status(exc: BaseException) -> int:
    """Exit status of a sudo that never became a command.

    ``NotStarted`` carries ``exit status N``. A rejected password does not;
    sudo exits 1 in that case.
    """
    match = re.search(r"exit status (-?\d+)", str(exc))
    if match:
        return int(match.group(1))
    return 1


def _input_payload(task: Task):
    """Bytes to write, a filesystem path, or ``None`` for no stdin."""
    if task.input is not None:
        return _as_bytes(task.input, task)
    stdin = task.stdin
    if stdin is None:
        return None
    if isinstance(stdin, (str, bytes, os.PathLike)):
        return os.fsdecode(stdin)
    if isinstance(stdin, io.StringIO):
        return _as_bytes(stdin.getvalue(), task)
    if isinstance(stdin, io.BytesIO):
        return stdin.getvalue()
    if hasattr(stdin, "read"):
        data = stdin.read()
        if isinstance(data, str):
            return _as_bytes(data, task)
        return bytes(data)
    raise TypeError(f"stdin must be a path or a file object, not {type(stdin).__name__}")


def _as_bytes(data, task: Task) -> bytes:
    if isinstance(data, str):
        if not task.text:
            raise TypeError("input must be bytes when not in text mode")
        return data.encode(task.encoding or DEFAULT_ENCODING, task.errors or "strict")
    if task.text:
        raise TypeError("input must be str in text mode")
    return bytes(data)


def _feed(proc, payload) -> None:
    try:
        if isinstance(payload, str):
            with open(payload, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
        elif payload:
            proc.stdin.write(payload)
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass


def _pump(stream, sink) -> None:
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if sink is not None:
                sink.write(chunk)
    finally:
        stream.close()


def _prefix(sink, task: Task, label: str):
    if sink is None or not task.prefix:
        return sink
    indent = " " * (task.prefix_width_hint - len(task.host))
    text = f"{indent}[{task.host}{label}]: "
    encoding = task.encoding or "utf-8"
    return _PrefixWriter(sink, text.encode(encoding))


def _execute(task: Task, pm: PasswordManager, stdout_arg, stderr_arg, connect_options: Mapping[str, Any], children: list, lock: threading.Lock) -> None:
    opts = dict(connect_options)
    if task.login_user:
        opts["login_user"] = task.login_user
    if task.port is not None:
        opts["port"] = task.port
    if "password" not in opts and "password_manager" not in opts:
        opts["password_manager"] = pm

    try:
        session = Session.connect(task.destination, **opts)
    except TuesError as exc:
        raise TuesError(f"Could not connect to {task.host}: {exc!r}") from exc

    task.connection = session
    task.login_user = session.login_user
    uploaded: list[str] = []
    closers: list = []
    try:
        if task.files:
            base = session.check_output(["pwd"], cwd=task.cwd, text=True).strip()
            for local in task.files:
                name = os.path.basename(os.fspath(local))
                if name in ("", ".", ".."):
                    raise TuesError(f"Cannot upload {local!r}")
                remote = f"{base.rstrip('/')}/{name}"
                try:
                    session.upload(os.fspath(local), remote)
                except TuesError as exc:
                    raise TuesError(f"Error while uploading files to {task.host}") from exc
                uploaded.append(remote)

        env: dict[str, Optional[str]] = {f"TUES_FILE{i}": path for i, path in enumerate(uploaded, 1)}
        if task.env:
            env.update(task.env)

        out_default = sys.stdout if task.text else sys.stdout.buffer
        err_default = sys.stderr if task.text else sys.stderr.buffer
        if task.outfile:
            stdout_sink, file_closers = _open_outfile(task, lock)
            closers.extend(file_closers)
            stdout_cap = None
        else:
            capture_out = task.capture_output or stdout_arg is PIPE
            stdout_sink, stdout_cap = _sink_for(
                None if capture_out else stdout_arg,
                task,
                lock,
                capture=capture_out,
                default=out_default,
            )
        task._stdout = stdout_cap

        # A PTY merges stderr into stdout on the server, so there is no
        # separate stream to read.
        if task.pty:
            stderr_sink, stderr_cap = None, None
        elif stderr_arg is STDOUT:
            stderr_sink, stderr_cap = stdout_sink, None
        else:
            capture_err = task.capture_output or stderr_arg is PIPE
            stderr_sink, stderr_cap = _sink_for(
                None if capture_err else stderr_arg,
                task,
                lock,
                capture=capture_err,
                default=err_default,
            )
        task._stderr = stderr_cap

        channel = "" if task.pty else "/stdout"
        stdout_sink = _prefix(stdout_sink, task, channel)
        if not task.pty:
            stderr_sink = _prefix(stderr_sink, task, "/stderr")

        if task.preexec_fn:
            task.preexec_fn(task)

        payload = _input_payload(task)
        cmd_user = task.user if task.user is not None and task.user != session.login_user else None
        proc = session.Popen(
            task.cmd,
            shell=True,
            stdin=PIPE if payload is not None else DEVNULL,
            stdout=PIPE if stdout_sink is not None else DEVNULL,
            stderr=DEVNULL if stderr_sink is None else PIPE,
            cwd=task.cwd,
            env=env or None,
            user=cmd_user,
            pty=task.pty,
        )
        children.append(proc)
        threads = []
        thread_errors: list[BaseException] = []

        def spawn(name: str, fn, *args) -> None:
            def body():
                try:
                    fn(*args)
                except BaseException as exc:  # noqa: BLE001 — surfaced after the other pumps finish
                    thread_errors.append(exc)

            thread = threading.Thread(target=body, daemon=True, name=name)
            thread.start()
            threads.append(thread)

        try:
            if payload is not None and proc.stdin is not None:
                spawn("tues-stdin", _feed, proc, payload)
            if proc.stdout is not None:
                spawn("tues-stdout", _pump, proc.stdout, stdout_sink)
            if proc.stderr is not None:
                spawn("tues-stderr", _pump, proc.stderr, stderr_sink)
            for thread in threads:
                thread.join()
            if thread_errors:
                raise thread_errors[0]
            try:
                task.returncode = proc.wait()
            except SudoError as exc:
                # The session API raises. The legacy API finishes the task
                # unless the user refused to provide a password.
                if _user_refused(exc):
                    task.authorization_failed = True
                else:
                    task.returncode = _sudo_status(exc)
        finally:
            if proc in children:
                children.remove(proc)

        if task.postexec_fn:
            task.postexec_fn(task)
    finally:
        for remote in uploaded:
            try:
                session.delete(remote)
            except TuesError:
                pass
        session.close()
        task.connection = None
        for close in closers:
            close()


def _run_one(task, pm, stdout_arg, stderr_arg, connect_options, children, lock) -> None:
    try:
        _execute(task, pm, stdout_arg, stderr_arg, connect_options, children, lock)
    except SudoError as exc:
        if _user_refused(exc):
            task.authorization_failed = True
        else:
            task.returncode = _sudo_status(exc)
    except TuesError as exc:
        if _user_refused(exc):
            task.authorization_failed = True
        else:
            raise


def _prepare_output_dir(path: str, strategy: str) -> None:
    if not os.path.exists(path):
        os.makedirs(path)
        return
    if strategy == DIR_ABORT:
        raise TuesOutputDirExists(f"Output directory {path!r} already exists, aborting")
    if strategy == DIR_IGNORE:
        return
    if strategy == DIR_WIPE:
        for item in glob.glob(os.path.join(path, "*.log")):
            os.unlink(item)
    elif strategy == DIR_ROTATE:
        indices = []
        for candidate in glob.glob(f"{path}.*"):
            suffix = candidate.rsplit(".", 1)[1]
            try:
                indices.append(int(suffix))
            except ValueError:
                pass
        next_index = max(indices, default=0) + 1
        os.rename(path, f"{path}.{next_index}")
        os.mkdir(path)


def _sigint_kills(children: list):
    """Kill remote processes started by this run when the user hits Ctrl+C.

    Also restores the terminal and unblocks a password prompt. With
    ``pool_size > 1`` the prompt runs on a worker, so the main thread is
    the one that sees the signal.
    """
    if threading.current_thread() is not threading.main_thread():
        return _nullcontext()
    previous = signal.getsignal(signal.SIGINT)

    def handler(signum, frame):
        del signum, frame
        _interrupt_prompt()
        for child in list(children):
            try:
                child.kill()
            except Exception:
                pass
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, handler)
    except ValueError:
        return _nullcontext()

    class _Restore:
        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            signal.signal(signal.SIGINT, previous)
            return False

    return _Restore()


class _nullcontext:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return False


def _fail(task: Task, exc: Optional[BaseException] = None) -> TuesTaskError:
    err = TuesTaskError(task)
    if exc is not None:
        err.__cause__ = exc
    return err


def run(
    hosts: Union[_HostSpec, Sequence[_HostSpec]],
    cmd: Union[str, Sequence[str]],
    user: Optional[str] = None,
    pm: PasswordManager = _PM,
    prefix: bool = False,
    files: Optional[Sequence[str]] = None,
    output_dir: Optional[str] = None,
    input=None,
    stdout=None,
    stderr=None,
    stdin=None,
    text: bool = False,
    encoding: Optional[str] = None,
    errors: Optional[str] = None,
    pty: bool = False,
    capture_output: bool = False,
    login_user: Optional[str] = None,
    pool_size: int = 1,
    loop=None,
    check: bool = False,
    align_prefix: bool = False,
    env: Optional[Mapping[str, Optional[str]]] = None,
    cwd: Optional[str] = None,
    preexec_fn: Optional[Callable[[Task], None]] = None,
    postexec_fn: Optional[Callable[[Task], None]] = None,
    output_dir_strategy: str = DIR_IGNORE,
    universal_newlines: Optional[bool] = None,
    connect_options: Optional[Mapping[str, Any]] = None,
):
    """Run ``cmd`` on ``hosts`` and return the :class:`Task` results.

    A single host (a string or a ``(host, port)`` tuple) returns one task.
    A list returns one task per host. The command is a shell line; a list is
    joined with :func:`shlex.join` and run the same way.

    ``stdout`` and ``stderr`` accept ``None`` (the local stdout/stderr),
    :data:`PIPE` (stored on the task), :data:`DEVNULL`, :data:`STDOUT`
    (stderr only: merge into stdout), or a file object. ``capture_output``
    is ``PIPE`` for both. ``text`` decodes with ``encoding`` (the locale
    encoding by default). ``input`` is sent on stdin after sudo has consumed
    any password prompt. ``stdin`` is a path or a :class:`io.StringIO` /
    :class:`io.BytesIO` read once per host.

    ``user`` runs the command with ``sudo -u``. ``login_user`` is who the
    session logs in as. ``files`` are uploaded into the remote working
    directory and removed afterwards; the command sees ``$TUES_FILE1`` and so
    on. ``prefix`` labels each line ``[host/stdout]: `` (or ``[host]: `` in
    PTY mode). ``align_prefix`` pads those labels. ``output_dir`` writes
    ``<host>.log`` per host, subject to ``output_dir_strategy``.

    ``pool_size`` hosts run at a time. They share one password prompt: the
    others wait and reuse that answer. ``check=True`` raises
    :class:`TuesTaskError` on the first non-zero exit and only works when
    ``pool_size`` is 1. ``args[0]`` is the task; ``__cause__`` is set only
    when the host failed before a status. Connection failures in a parallel
    run are collected into :class:`TuesErrorGroup` (``message``,
    ``exceptions``, ``results``). A refused sudo or login password raises
    :class:`TuesUserAbort`. A rejected password finishes the task with
    sudo's status.

    ``connect_options`` is passed to :meth:`Session.connect` (identity files,
    ``host_key_policy``, ``ssh_config``, ``password``, …). A ``password`` or
    ``password_manager`` there replaces ``pm``. ``loop`` is accepted for
    compatibility and ignored: this function is synchronous.
    """
    del loop  # synchronous; the original API took an asyncio loop
    if pool_size > 1 and check:
        raise TuesError("Aborting on errors is not supported when running with a pool size > 1")

    single = isinstance(hosts, (str, tuple))
    if single:
        host_list: Sequence[_HostSpec] = [hosts]  # type: ignore[list-item]
    elif not hosts:
        raise TuesError("No hosts")
    else:
        host_list = list(hosts)  # type: ignore[arg-type]

    parsed = [Host(spec) for spec in host_list]
    if isinstance(cmd, (str, bytes)):
        command = os.fsdecode(cmd)
    else:
        command = shlex.join(os.fsdecode(part) for part in cmd)

    if output_dir:
        _prepare_output_dir(output_dir, output_dir_strategy)

    width = max(len(host.name) for host in parsed)
    tasks = [
        Task(
            command,
            host,
            login_user=login_user,
            files=files,
            outfile=os.path.join(output_dir, host.name + ".log") if output_dir else None,
            prefix=prefix,
            prefix_width_hint=width if align_prefix else None,
            user=user,
            pty=pty,
            universal_newlines=universal_newlines,
            input=input,
            stdin=stdin,
            text=text,
            errors=errors,
            encoding=encoding,
            capture_output=capture_output,
            env=env,
            cwd=cwd,
            preexec_fn=preexec_fn,
            postexec_fn=postexec_fn,
        )
        for host in parsed
    ]

    options = dict(connect_options or {})
    children: list = []
    lock = threading.Lock()

    def one(task: Task) -> None:
        _run_one(task, pm, stdout, stderr, options, children, lock)

    with _sigint_kills(children):
        if pool_size <= 1:
            for task in tasks:
                try:
                    one(task)
                except KeyboardInterrupt as exc:
                    raise _fail(task, exc) from exc
                except TuesUserAbort:
                    raise
                except Exception as exc:
                    raise _fail(task, exc) from exc
                if task.authorization_failed:
                    raise TuesUserAbort("Sudo authorization failed")
                if check and task.returncode != 0:
                    raise TuesTaskError(task)
        else:
            workers = max(1, pool_size)
            errors: list[BaseException] = []
            results: list[Task] = []
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tues") as pool:
                futures = [pool.submit(one, task) for task in tasks]
                try:
                    finished = [(task, fut.exception()) for task, fut in zip(tasks, futures)]
                except KeyboardInterrupt as exc:
                    for child in list(children):
                        try:
                            child.kill()
                        except Exception:
                            pass
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise TuesErrorGroup(
                        "Errors encountered while running tasks with concurrency",
                        [exc],
                        results,
                    ) from exc
            for task, exc in finished:
                if exc:
                    errors.append(exc)
                elif task.authorization_failed:
                    raise TuesUserAbort("Sudo authorization failed")
                else:
                    results.append(task)
            if errors:
                raise TuesErrorGroup(
                    "Errors encountered while running tasks with concurrency",
                    errors,
                    results,
                )

    if single:
        return tasks[0]
    return tasks
