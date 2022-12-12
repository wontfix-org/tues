# coding: utf-8

from __future__ import absolute_import

import os as _os
import re as _re
import io as _io
import sys as _sys
import json as _json
import enum as _enum
import glob as _glob
import shlex as _shlex
import errno as _errno
import traceback as _tb
import functools as _ft
import subprocess as _sp
import locale as _locale
import asyncio as _asyncio
import logging as _logging
import getpass as _getpass
import inspect as _inspect
import tempfile as _tempfile
import urllib.parse as _urlparse

import warnings as _warnings
import cryptography.utils as _crypto_utils

_warnings.filterwarnings(
    "ignore",
    module=r"^asyncssh\..*",
    category=_crypto_utils.CryptographyDeprecationWarning,
)

import click as _click
import asyncssh as _ssh
import async_timeout as _timeout


PIPE = _ssh.PIPE
STDOUT = _ssh.STDOUT
DEVNULL = _ssh.DEVNULL


DIR_ABORT = "abort"
DIR_ROTATE = "rotate"
DIR_WIPE = "wipe"
DIR_IGNORE = "ignore"


DEFAULT_ENCODING = _locale.getpreferredencoding()

_log = _logging.getLogger(__name__)

DEFAULT_PATH = [
    _os.path.join(
        _os.environ.get("XDG_CONFIG_HOME", _os.path.expanduser("~/.config/")),
        "tues",
        "scripts",
    ),
]

_TUES_LOGFILE = _os.environ.get("TUES_LOGFILE")

if _TUES_LOGFILE:
    _log.setLevel(_logging.DEBUG)
    fh = _logging.FileHandler(_TUES_LOGFILE)
    fh.setLevel(_logging.DEBUG)
    _log.addHandler(fh)


class TuesError(Exception):
    pass


class TuesErrorGroup(TuesError):

    def __init__(self, message, exceptions, results):
        self.args = [message]
        self.message = message
        self.exceptions = exceptions
        self.results = results


class TuesLookupError(TuesError):
    pass


class TuesScriptNotFoundError(TuesError):
    pass


class TuesOutputDirExists(TuesError):
    pass


class TuesTaskError(TuesError):

    @property
    def stdout(self):
        return self.args[0].stdout

    @property
    def stderr(self):
        return self.args[0].stderr


def provider(provider, args):
    cmd = ["tues-provider-{}".format(provider)] + list(args)

    try:
        output = _sp.check_output(cmd, text=True)
        return [x for x in output.split("\n") if x and not x.startswith("#")]
    except OSError as e:
        if e.errno != _errno.ENOENT:
            raise
        raise TuesLookupError(f"Provider {provider!r} not found, make sure {cmd[0]!r} is on your PATH") from e
    except _sp.CalledProcessError as e:
        raise TuesLookupError(f"Error running provider: {_shlex_join(cmd)}") from e


class Script:

    def __init__(self, cmd, paths=None):
        if not paths:
            paths = DEFAULT_PATH

        if isinstance(cmd, str):
            self.script, *_ = _shlex.split(cmd)
            self.cmd = cmd
        else:
            self.script, *_ = cmd
            self.cmd = _shlex.join(cmd)


        for path in paths:
            self.path = _os.path.join(path, self.script)
            if _os.path.exists(self.path):
                break
        else:
            raise TuesScriptNotFoundError(f"Could not find {self.script} in {paths!r}")

        sections = self._get_sections(self.path)

        self.run_args = sections.get("args", {})
        self.provider = sections.get("provider")
        self.provider_args = sections.get("provider-args")

    @staticmethod
    def _get_sections(path):
        allowed = ["args", "provider", "provider-args"]
        sections = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("# tues-"):
                    continue

                m = _re.match(rf"^# tues-({'|'.join(allowed)})\s*=\s*(.*)\s*$", line)
                if not m:
                    raise TuesError(f"Error parsing script file, not a valid section name in line: '{line}'")

                sections[m.group(1)] = _json.loads(m.group(2))

        return sections

    def run(
        self,
        hosts=None,
        **kwargs,
    ):
        run_kwargs = {}
        whitelist = [
            "login_user",
            "files",
            "outfile",
            "output_dir",
            "output_dir_strategy",
            "prefix",
            "user",
            "pty",
            "input"
            "check",
            "pool_size",
        ]

        if not hosts:
            hosts = provider(self.provider, self.provider_args)

        run_kwargs["hosts"] = hosts
        run_kwargs.update({k:v for k, v in self.run_args.items() if k in whitelist})

        ignore_cli = (
            "files", # we use "files" to copy our script, so we need to merge instead or replace
            "prefix", # if the script manages this value, it is unlikely to work with prefixes
        )

        # Make sure we "upload ourself", so we can just run the script
        run_kwargs.update({k:v for k, v in kwargs.items() if v is not None and k not in ignore_cli})
        run_kwargs.setdefault("files", [])
        run_kwargs["files"].extend(kwargs.get("files", []))
        run_kwargs["files"].append(self.path)

        return run(cmd="./" + self.cmd, **run_kwargs)


class PasswordManager:

    def __init__(self, prompt=None, password=None):
        if prompt is not None:
            self._prompt = prompt
        self._password = password if password else _os.environ.get("TUES_PW")

    @staticmethod
    def _prompt(message):
        return _click.prompt(message, hide_input=True, err=True)

    def get(self, message=None):
        if message and self._password is None:
            self._password = self._prompt(message)

        return self._password

    def invalidate(self):
        self._password = None


_PM = PasswordManager()


class Task:
    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        cmd,
        host=None,
        connection=None,
        login_user=None,
        files=None,
        outfile=None,
        prefix=False,
        user=None,
        pty=False,
        input=None,
        stdin=None,
        text=False,
        errors=None,
        encoding=None,
        prefix_width_hint=None,
        capture_output=False,
        env=None,
        cwd=None,
        preexec_fn=None,
        postexec_fn=None,
        universal_newlines=None,
    ): # pylint: disable=too-many-locals
        if encoding or errors:
            text = True

        if text:
            if encoding is None:
                encoding = DEFAULT_ENCODING

            if errors is None:
                errors = "strict"

        if pty and (input or stdin):
            raise TuesError("Passing `input` or `stdin` in `pty` mode is not supported")

        if pty and universal_newlines is None:
            universal_newlines = True

        # `asyncssh.connect` wants an empty tuple over `None` as default
        if login_user is None:
            login_user = ()

        if outfile and prefix is None:
            prefix = False
        else:
            prefix = bool(prefix)

        if files is None:
            files = []

        if isinstance(cmd, list):
            cmd = _shlex_join(cmd)

        if host is not None and not isinstance(host, Host):
            host = Host(host)
        elif host is None and connection is None:
            raise RuntimeError("You need to either provide a `host` or `connection` argument")

        self.host = host.name
        self.port = host.port

        self.connection = connection
        self.cmd = cmd
        self.precmds = []
        self.cmdwrapper = lambda x: x
        self.login_user = login_user
        self.files = files
        self.outfile = outfile
        self.prefix = prefix
        self.prefix_width_hint = prefix_width_hint or len(self.host)
        self.user = user
        self.pty = pty
        self.universal_newlines = universal_newlines if pty else False
        self.input = input
        self.stdin = stdin
        self.text = text
        self.errors = errors
        self.encoding = encoding
        self.env = env
        self.cwd = cwd
        self.capture_output = capture_output
        self.returncode = None
        self._stdout = None
        self._stderr = None
        self.preexec_fn = preexec_fn
        self.postexec_fn = postexec_fn
        self._session = None

    @property
    def stdout(self):
        if not self._stdout:
            return None

        if self.text:
            return self._stdout.getvalue().decode(self.encoding, self.errors)
        return self._stdout.getvalue()

    @property
    def stderr(self):
        if not self._stderr:
            return None

        if self.text:
            return self._stderr.getvalue().decode(self.encoding, self.errors)
        return self._stderr.getvalue()

    def build_cmd(self):
        if self.precmds:
            precmds = " ; ".join(self.precmds) + " ; "
        else:
            precmds = ""

        if self.cwd:
            precmds = f"{precmds} cd {_shlex.quote(self.cwd)} ; "

        return self.cmdwrapper(f"{precmds}{self.cmd}")

    def cleanup(self):
        if not self._session:
            return

        if not self.pty:
            if self.user:
                _log.warning("Cannot terminate remote command when running as another user without pty mode, this may lead to hanging processes on the remote server")
            else:
                self._session.terminate()
        else:
            self._session.stdin.write(b"\x03")


class BufferedIO(_tempfile.SpooledTemporaryFile):
    """ Capture output into memory or into a tempfile if output is more than 4kb

        Also borrow the `getvalue` interface from io.BytesIO so we don't have to
        read from this file manually. We keep track of the current file position
        and reset it as if "nothing ever happened" during read access.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_size", 4096)
        super().__init__(*args, **kwargs)

    def getvalue(self):
        try:
            pos = self.tell()
            self.seek(0)
            return self.read()
        finally:
            self.seek(pos)

    def __repr__(self):
        return f"{self.__class__.__name__}({hex(id(self))}, {self.mode})"


class PrefixWriter:
    """ Add a prefix two every line of output produced on the wrapped file

        Special care is taken not to blindly append a prefix every time we see
        a newline. We wait for new bytes on the "next line" to be written before
        we actually add the prefix, in order to not produce prefixes without any
        actual content.
    """
    def __init__(self, f, prefix):
        self._f = f
        self._fresh = True

        self._prefix = prefix.encode() if isinstance(prefix, str) else prefix

    async def write(self, data):
        eol = b"\n"

        if self._fresh:
            data = self._prefix + data
            self._fresh = False

        if data.endswith(eol):
            data = data[:-1].replace(eol, eol + self._prefix) + eol
            self._fresh = True
        else:
            data = data.replace(eol, eol + self._prefix)

        _log.debug("PrefixWriter %r.write(%r)", self._f, data)
        return await self._f.write(data)


class OutputWrapper:
    """ Toplevel wrapper for our output handlers

        This wrapper serves two purposes:

          * Log the "original" writes, so we can easily debug problems in output handling
          * Drop calls to `close`, asyncssh will close files we pass it for stdout/stderr
            but we do not really want those to be closed, because we pass in sys.stdxxx as
            well as files created from the `tempfile` module we can't really open again.
    """

    def __init__(self, f):
        self._f = f

    async def write(self, data):
        try:
            _log.debug("OutputWrapper %r.write(%r)", self._f, data)
            return await self._f.write(data)
        except Exception:
            _log.error("Error during %r.write(%r)", self._f, data, exc_info=True)
            raise

    async def close(self):
        pass


class OutputWriter:
    """ Write output to its final destination

        This class is supposed to be the one that wraps the "real" target of
        our output. Because of that it is the only one doing bytes vs. str
        handling as well as everything necessary to handle all the different
        calling conventions for the `write` call, right now this is just
        checking if `write` is async/a coroutine.
    """
    def __init__(self, f, text, encoding, errors):
        self._f = f
        self._text = text
        self._encoding = encoding
        self._errors = errors

    async def write(self, data):
        _log.debug("OutputWriter.write(%r)", data)
        flush = hasattr(self._f, "flush")
        data = data if self._text is False or isinstance(self._f, BufferedIO) else data.decode(self._encoding, self._errors)
        _log.debug("OutputWriter %r.write(%r)", self._f, data)
        w = self._f.write(data)
        try:
            if _inspect.iscoroutine(w):
                return await w
            return w
        finally:
            if flush:
                self._f.flush()

    def __getattr__(self, name):
        return getattr(self._f, name)

    def __repr__(self):
        return f"OutputWriter({repr(self._f)}, text={self._text!r}, encoding={self._encoding!r}, errors={self._errors!r})"


class SudoWriter:
    """ Handle running `run` via sudo

        This consists of two parts, first wrapping `run.cmd` in a call to sudo,
        as well as intercepting all IO, looking for "sudo output", prompting for
        a password if necessary, sending the password input to stdin of the
        remote process, and finally run the `on_success` callback that is usually
        responsible for sending the held back input to the wrapped programm which
        can only be sent once we are past the prompt.
    """

    # pylint: disable=too-many-instance-attributes
    PROMPT_TOKEN = b"TUES_SUDO_PASSWORD_PROMPT"
    SUCCESS_TOKEN = b"TUES_SUDO_PASSWORD_SUCCESS"
    # No idea why this token it not configurable in sudo, but since we are
    # making our own success token, we do not really need this, we only keep
    # it around so we are able to clean it from the datastream

    def __init__(self, f, run, pm, on_success=None):
        self._f = f
        self.sudo = None
        self._pm = pm
        self.newline = b"\r\n" if run.universal_newlines else b"\n"
        self.failure_token = b"Sorry, try again." + self.newline
        self._post_prompt_filter = (
            self.SUCCESS_TOKEN,
            self.failure_token,
            self.newline,
        )

        self._run = run
        self._on_success = on_success
        self._waiting = False
        run.precmds.append(f"echo -n {self.SUCCESS_TOKEN.decode()} >&2")
        run.cmdwrapper = lambda cmd: f"sudo -S -u {_shlex.quote(run.user)} -p {_shlex.quote(self.PROMPT_TOKEN.decode())} -- bash -c {_shlex.quote(cmd)}"

    async def write(self, data):
        failure_cond = self.failure_token in data
        success_cond = self.SUCCESS_TOKEN in data
        if failure_cond or success_cond:
            _log.debug("SudoWriter found stop token in %r", data)
            # Only invalidate if nobody else has reprompted a password yet
            if failure_cond and self._last_pw_attempted == self._pm.get():
                self._pm.invalidate()

            if success_cond and self._on_success:
                await self._on_success()
                self._on_success = None

        if self._waiting:
            for filter_ in self._post_prompt_filter:
                if data.startswith(filter_):
                    data = data[len(filter_):]

        if not self._on_success:
            self._waiting = False

        if self.PROMPT_TOKEN in data:
            data = data.replace(self.PROMPT_TOKEN, b"")
            self._waiting = True
            _log.debug("SudoWriter prompt reply on %r", self.sudo)
            self._last_pw_attempted = password = self._pm.get("Your remote sudo password")
            self.sudo.write((password + "\n").encode())
            await self.sudo.drain()

        # In the best case scenario, the password prompt is detected
        # and removed from the output, leaving only an empty bytes
        # object we don't need to print
        if data:
            _log.debug("SudoWriter %r.write(%r)", self._f, data)
            return await self._f.write(data)


async def _prepare_io(run, stdout, stderr, env, pm, send_input):
    """ Setup IO for `run`

        Handle `run.outfile` as well as shared `stderr` und `stdout` handles, if set.
        Wrap all handles in `OutputWriter` and ensure `PrefixWriter` and `SudoWriter`
        wrappers are added if necessary.
    """
    # pylint: disable=too-many-branches
    sudo = None
    cleanup = []

    if env:
        run.precmds.extend(env)

    if run.outfile:
        stdout = open(run.outfile, "wb")
        if run.text:
            stdout = _io.TextIOWrapper(stdout, encoding=run.encoding, errors=run.errors)
        cleanup.append(stdout.close)

    def _pick(f):
        if f is DEVNULL:
            f = open("/dev/null", "wt" if run.text else "wb")
        if run.capture_output or f is PIPE:
            buf = BufferedIO(mode="wb+")
            ret = (OutputWriter(buf, run.text, run.encoding, run.errors), buf)
        else:
            ret = (OutputWriter(f, run.text, run.encoding, run.errors), None)

        return ret


    stdout, stdout_buf = _pick(stdout or (_sys.stdout if run.text else _sys.stdout.buffer))

    if stderr is STDOUT:
        stderr, stderr_buf = stdout, stdout_buf
    elif not run.pty:
        stderr, stderr_buf = _pick(stderr or (_sys.stderr if run.text else _sys.stderr.buffer))
    else:
        stderr = stderr_buf = None

    if stdout_buf:
        run._stdout = stdout_buf

    if stderr_buf:
        run._stderr = stderr_buf

    # In pty mode we don't get a seperate stderr, so we need to switch the sudo wrapper
    # to use stdout instead down in the `if user` branch
    if run.prefix:
        indent = " " * (run.prefix_width_hint - len(run.host))
        if not run.pty:
            stderr = PrefixWriter(stderr, f"{indent}[{run.host}/stderr]: " if run.prefix else None)
            outfmt = f"{indent}[{run.host}/stdout]: "
        else:
            outfmt = f"{indent}[{run.host}]: "

        stdout = PrefixWriter(stdout, outfmt if run.prefix else None)

    # If running as another user is requested, bind to the appropriate stream
    # to intercept the password prompt
    config = _os.path.expanduser("~/.ssh/config")
    if _os.path.exists(config):
        config = _ssh.config.SSHClientConfig.load(
            None,
            config,
            False,
            _getpass.getuser(),
            run.login_user,
            run.host,
            run.port,
        )
        run.login_user = config.get("User", run.login_user)

    if run.user and run.user != run.login_user:
        def sudo_wrap(run, writer):
            return SudoWriter(writer, run, pm, send_input)

        if stderr:
            stderr = sudo_wrap(run, stderr)
            sudo = stderr
        else:
            stdout = sudo_wrap(run, stdout)
            sudo = stdout

    return (stdout, stderr, sudo, cleanup)


async def _redirect_io(session, stdout, stderr, sudo):
    """ Setup IO redirection on `session`

        Ensure we at least wrap the files in an `OutputWrapper` so the files
        don't get automatically closed by asyncssh.
    """
    if sudo:
        _log.debug("SUDO TO %r", session.stdin)
        #await session.redirect(stdin=_ssh.PIPE, stdout=None, stderr=None)
        sudo.sudo = session.stdin # pylint: disable=attribute-defined-outside-init
        #_log.debug("SUDO TO %r", session.stdin)

    if stdout:
        stdout = OutputWrapper(stdout)

    if stderr:
        stderr = OutputWrapper(stderr)

    if sudo and not isinstance(sudo, OutputWrapper):
        sudo = OutputWrapper(sudo)

    _log.debug("IO Handle for stdout set to %r", stdout)
    _log.debug("IO Handle for stderr set to  %r", stderr)
    _log.debug("IO Handle for sudo set  %r", sudo)

    await session.redirect(stdin=None, stdout=stdout, stderr=stderr or stdout)


class TuesClient(_ssh.SSHClient):

    def __init__(self, pm, host):
        super().__init__()
        self._pm = pm
        self._host = host

    def password_auth_requested(self):
        return self._pm.get("Login password for {}".format(self._host))


async def _run(run, pm, stdout=None, stderr=None): # pylint: disable=too-many-locals,too-many-branches
    """ The real "runner" function issued for every host """
    env = []

    # Either use an already existing connection on the `run` object
    # or make a new one from `.host` and `.login_user`, in the later
    # case, do *not* write it back to the run, but get rid of it as
    # soon as we are done with the run, so we don't "leak" connections
    # when iterating over a large number of hosts
    if run.connection is None:
        try:
            async with _timeout.timeout(10):
                conn = await _ssh.connect(
                    run.host,
                    known_hosts=None,
                    username=run.login_user,
                    port=run.port or (),
                    client_factory=_ft.partial(TuesClient, pm, run.host),
                )
        except Exception as e:
            raise TuesError(f"Could not connect to {run.host}: {e!r}") from e
    else:
        conn = run.connection

    # Copy files to the remote environment and put their names into `TUES_FILE<x>`,
    # even though you know the name you just put into the `files` list anyway...
    # I have no idea why I added this environment variables to be honest...
    for idx, f in enumerate(run.files, start=1):
        try:
            await _ssh.scp(f, (conn, "./"), preserve=True)
            env.append(f"TUES_FILE{idx}=$PWD{_shlex.quote('/' + _os.path.basename(f))}")
        except _ssh.sftp.SFTPFailure as e:
            raise TuesError(f"Could not upload {f} to {run.host}") from e

    # If there is any input to be written to the executed commands' stdin, we
    # can write it immediately if we don't have to handle sudo situation, otherwise
    # we need to hold back the input until we are past the sudo prompt
    if run.input or run.stdin:
        async def send_input():
            if run.input:
                input = run.input if not run.text else run.input.encode(run.encoding, run.errors)
                session.stdin.write(input)
                await session.stdin.drain()
            elif isinstance(run.stdin, (str, bytes)):
                with open(run.stdin, "rb") as f:
                    while True:
                        buf = f.read(4096)
                        if buf:
                            session.stdin.write(buf)
                            await session.stdin.drain()
                        if len(buf) < 4096:
                            break
            elif isinstance(run.stdin, (_io.StringIO, _io.BytesIO)):
                input = run.stdin.getvalue()
                if isinstance(input, str):
                    input = input.encode(run.encoding, run.errors)
                session.stdin.write(input)
                await session.stdin.drain()
            session.stdin.write_eof()
    else:
        async def send_input():
            pass

    if run.env:
        env.extend(f"{k}={_shlex.quote(v)}" for k, v in run.env.items())

    stdout, stderr, sudo, cleanup = await _prepare_io(
        run,
        stdout,
        stderr,
        env,
        pm,
        send_input,
    )

    try:
        if run.preexec_fn:
            run.preexec_fn(run)

        cmd = run.build_cmd()
        _log.debug("Running %r", cmd)
        _chan, session = await conn.create_session(
            _ssh.SSHClientProcess,
            cmd,
            term_type=_os.environ.get("TERM"),
            term_modes={_ssh.PTY_ONLCR: 0, _ssh.PTY_INLCR: 0} if not run.universal_newlines else (),
            request_pty=run.pty,
            env=env,
            # If we don't "force" them to None, some kind of autodetection will take place
            # and we'll end up receiving `str` objects in some scenarios.
            encoding=None,
            errors=None,
        )
        await _redirect_io(session, stdout, stderr, sudo)
        if not sudo:
            await send_input()

        # Since we won't receive the KeyboardInterrupt here, we need to store the
        # session in a way that will allow us to call `task.session.terminate()`
        # from a location that does see it.
        run._session = session
        completed = await session.wait()
        run._session = None

        run.returncode = completed.returncode

        if run.postexec_fn:
            run.postexec_fn(run)

        return run
    finally:
        if conn:
            if run.files:
                await conn.run(b"rm -f " + b" ".join([_shlex.quote(_os.path.basename(_)).encode() for _ in run.files]))

            # We used a connection from the run object, don't close it
            if not run.connection:
                conn.close()

        for cb in cleanup:
            cb()


async def _wait_with_concurrency(tasks, pool_size):
    """ Make sure we only run `pool_size` tasks at once """
    semaphore = _asyncio.Semaphore(pool_size)

    async def sem_task(task):
        async with semaphore:
            return await task
    return await _asyncio.wait([_asyncio.create_task(sem_task(task)) for task in tasks])


async def run_tasks(tasks, pm=_PM, stdout=None, stderr=None, pool_size=1): # pylint: disable=too-many-locals
    """ Run `tasks` with `pool_size` """
    tasks = (_run(_, pm, stdout, stderr) for _ in tasks)

    (_done, _pending) = await _wait_with_concurrency(tasks, pool_size)

    excs = []
    results = []
    for d in _done:
        exc = d.exception()
        if exc:
            excs.append(exc)
        else:
            results.append(d.result())

    if excs:
        raise TuesErrorGroup("Errors encountered while running tasks with concurrency", excs, results)

    return results


def _prepare_output_dir(path, strategy):
    if not _os.path.exists(path):
        _os.makedirs(path)
        return

    if strategy == DIR_ABORT:
        raise TuesOutputDirExists(f"Output directory {path!r} already exists, aborting")

    if strategy == DIR_IGNORE:
        return

    if strategy == DIR_WIPE:
        for item in _glob.glob(_os.path.join(path, "*.log")):
            _os.unlink(_os.path.join(path, item))
    elif strategy == DIR_ROTATE:
        candidates = _glob.glob(f"{path}.*")
        indices = []
        for index in [_.rsplit(".", 1)[1] for _ in candidates]:
            try:
                indices.append(int(index))
            except ValueError:
                # We ignore paths we cannot cast to int, maybe the user has an
                # unrelated directory matching the glob laying around, but that
                # is no reason to abort the run
                pass
        next_index = max(indices, default=0) + 1
        _os.rename(path, f"{path}.{next_index}")
        _os.mkdir(path)


class Host:

    def __init__(self, spec):
        if isinstance(spec, tuple):
            self.name, self.port = spec
        elif isinstance(spec, str):
            parsed = _urlparse.urlparse(f"ssh://{spec}")
            self.name = parsed.hostname
            self.port = parsed.port


def run(
    hosts,
    cmd,
    user=None,
    pm=_PM,
    prefix=False,
    files=None,
    output_dir=None,
    input=None,
    stdout=None,
    stderr=None,
    stdin=None,
    text=False,
    encoding=None,
    errors=None,
    pty=False,
    capture_output=False,
    login_user=None,
    pool_size=1,
    loop=None,
    check=False,
    align_prefix=False,
    env=None,
    cwd=None,
    preexec_fn=None,
    postexec_fn=None,
    output_dir_strategy=DIR_IGNORE,
    universal_newlines=None,
): # pylint: disable=too-many-locals
    """
        Run `cmd` on all `hosts`.

        If `hosts` is a string, the command is only executed on that single host
        and only a single `Task` instance is returned, instead of a list of `Task`.

        Args:
            cmd (str or list<str>): The command to be executed on the remote host.
                If a list is passed, it is automatically `shlex.join`-ed for your
                convenience. Other than that, there is no difference between list
                and str modes.

            stdout (DEVNULL|PIPE|..): The object to use to store receive command output.
                By default all output goes to stdout of the local process. If
                `PIPE` is passed, the `Task.stdout` property will contain the
                output of the command after completion of the task. The internal
                implementation uses a `tempfile.SpooledTemporaryFile` with a
                4k buffer, so little output will be dealt with in-memory, while
                longer datastreams will be persisted to disk for the lifetime of
                the `Task` object.

                To discard any stdout data, `DEVNULL` may be passed.

                You may also pass any regular file like object, in which case it
                will contain the output of *all* executed commands on all hosts.

            stderr (DEVNULL|STDOUT|PIPE|..): The same as the `stdout` option, but for
                the error channel. If the `pty` option is passed, all stderr output is
                merged into stdout on the serverside, leaving this stream empty.
                If `STDOUT` is passed, stderr is merged into the stdout stream.

            capture_output (bool): Set `PIPE` on both the `stdout` and `stderr` handles.

            input (str|bytes): Data to send to the remote command, if `user` is also
                specified, the input will be sent *after* making sure to work around
                a potential password prompt first.

            stdin (str|bytes|io.StringIO|io.BytesIO): The "file" to connect to stdin of
                the executed process. As we have to send it to many processes on many
                hosts, we do not support file handles, only paths to actual files on
                the filesystem that every task will open and read on its own, or the
                StringIO and BytesIO objects that support `getvalue` without consuming
                the data or having to seek on a shared file descriptor.

            user (str): The user to run the command as. The command will be wrapped
                in a call to `sudo`. If sudo requires a password, you will be either
                prompted for it by the default `PasswordManager`, you can also pass
                your own instance with a preset password or custom prompting code
                with the `pm` argument.

            files (list<str>): A list of files to upload to every host before
                executing `command`. The files will be deleted after the command
                has been run, no matter the exit code of the command, but you
                can move the files out of the way manually without causing any
                errors in the cleanup phase.

            cwd (str): The current working directory of the command executed.

            env (dict): A dict of environment variables to pass to the execute command.
                The variables are defined "inline" inside the shell expression used to
                wrap the original command, so they are not subject to sudo or sshd env
                var filtering.

            check (bool): Abort command execution when the exit code of
                the remote commands is > 0. This will conflict with `pool_size`.
                You have to decide if you want concurrency or cautious execution
                one host after the other. Aborting is implemented by raising a
                `TuesTaskError`.

            text (bool): Handle str instead of bytes data in input and output
                data (see `stdin`, `input`, `stdout`, `stderr`).

            encoding (str): Which encoding to use for `text` encoding. If set, will
                automatically enable `text`.

            errors (str): Set the `errors` argument during `text` encoding. If set, will
                automatically enable `text`.

            pm (PasswordManager): A custom instance of `PasswordManager` to cache and
                prompt for the sudo password in case `user` is specified. By default
                we use the global `_PM` PasswordManager instance, so multiple calls
                to `run` will always reuse previously cached passwords.

            prefix (bool): If `True`, each line of output will be prefixed with a string
                containing the hostname and the channel (stdout/stderr) the output was
                generated on. If `pty` is `True`, the output channels are automatically
                merged and we have no idea which channel it was sent to, so we drop the
                channel information silently.

            align_prefix (bool): Add padding to the output prefix in order to align the
                "real" output of the script on the same column.

            output_dir(str): Store the output of the executed commands in a
                single file `output_dir`/<hostname>` for later inspection.

            pty (bool): I pty the fool who has to use this option. This will
                put the connection into pty mode, faking some form of interactivity.
                This option will conflict with `input` (causing an exception).
                In this mode you will not be able to distinguish between stdout
                and stderr, all output will seem to be coming from stdout.

            universal_newlines (bool): When pty mode is enabled, \n will be automtically
                converted to \r\n in either direction, even when dealing with bytes.
                To prevent the pty layer from manipulating the bytestream, you can
                set `universal_newlines` to `False`.

            login_user (str): The user to log-in with, usual system defaults
                and ssh config settings apply, so you should only very rarely
                need this option.

            pool_size (int): The size of the pool of workers to use for parallel
                execution of commands. This option will conflict with `check`,
                because we don't want to deal with cancelling tasks already scheduled
                for execution.

            loop: The asyncio event loop to run on. by default, the current loop
                is used if executed inside an async application, otherwise a loop
                is created and used internally, you don't need to `await` anything.

    """
    if isinstance(hosts, (str, tuple)):
        hosts = [hosts]

    hosts = [Host(_) for _ in hosts]

    if output_dir:
        _prepare_output_dir(output_dir, output_dir_strategy)

    host_width = max(len(_.name) for _ in hosts)

    tasks = [
        Task(
            host=host,
            cmd=cmd,
            login_user=login_user,
            files=files,
            outfile=_os.path.join(output_dir, host.name + ".log") if output_dir else None,
            prefix=prefix,
            prefix_width_hint=host_width if align_prefix else None,
            user=user,
            pty=pty,
            universal_newlines=universal_newlines,
            input=input,
            text=text,
            errors=errors,
            encoding=encoding,
            capture_output=capture_output,
            env=env,
            cwd=cwd,
            stdin=stdin,
            preexec_fn=preexec_fn,
            postexec_fn=postexec_fn,
        ) for host in hosts
    ]

    if loop is None:
        try:
            loop = _asyncio.get_running_loop()
        except RuntimeError:
            loop = _asyncio.new_event_loop()

    try:
        if pool_size > 1:
            if check:
                raise TuesError("Aborting on errors is not supported when running with a pool size > 1")
            result = loop.run_until_complete(
                run_tasks(tasks, pm, stdout, stderr, pool_size),
            )
        else:
            for task in tasks:
                result = loop.run_until_complete(_run(task, pm, stdout, stderr))
                if check and result.returncode > 0:
                    raise TuesTaskError(task)
    except KeyboardInterrupt as e:
        for task in tasks:
            task.cleanup()

    if len(tasks) > 1:
        return tasks

    return tasks[0]


def _shlex_join(elems):
    return " ".join(_shlex.quote(_) for _ in elems)
