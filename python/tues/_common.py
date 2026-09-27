"""Pieces shared by the blocking and asyncio ``subprocess``-style APIs."""

from __future__ import annotations

import locale
import os
import signal
import subprocess
from typing import Any, Mapping, Optional, Sequence, Union

from ._tues import DEVNULL, LOGIN_USER, PIPE, STDOUT, LoginUser, TuesError

__all__ = [
    "PIPE",
    "STDOUT",
    "DEVNULL",
    "LOGIN_USER",
    "CalledProcessError",
    "TimeoutExpired",
    "CompletedProcess",
]

Args = Union[str, bytes, "os.PathLike[Any]", Sequence[Union[str, bytes, "os.PathLike[Any]"]]]

#: The ``user`` argument of a command: a name (run via ``sudo -u``),
#: :data:`LOGIN_USER` (run as the login user, never via sudo) or ``None``
#: (inherit the session's default user).
User = Union[str, LoginUser, None]


class CalledProcessError(subprocess.CalledProcessError, TuesError):
    """Raised when a process run with ``check=True`` exits non-zero.

    Also a :class:`subprocess.CalledProcessError`, so code written against
    :mod:`subprocess` catches it.
    """


class TimeoutExpired(subprocess.TimeoutExpired, TuesError):
    """Raised when a timeout expires while waiting for a remote process."""


class CompletedProcess(subprocess.CompletedProcess):
    """The return value of :meth:`Session.run`; see :class:`subprocess.CompletedProcess`."""

    def check_returncode(self) -> None:
        if self.returncode:
            raise CalledProcessError(self.returncode, self.args, self.stdout, self.stderr)


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------


def normalize_args(args: Args) -> list[str]:
    """Turn ``subprocess``-style ``args`` into the argv list the core takes.

    A single string is one element: the program (``shell=False``) or the
    shell script (``shell=True``), exactly as in :mod:`subprocess`.
    """
    if isinstance(args, (str, bytes, os.PathLike)):
        argv = [os.fsdecode(args)]
    else:
        argv = [os.fsdecode(a) for a in args]
    if not argv:
        raise ValueError("args must not be empty")
    return argv


def merge_stderr(argv: list[str], shell: bool) -> tuple[list[str], bool]:
    """Rewrite a command so its stderr goes to stdout (``stderr=STDOUT``).

    The remote side has one channel per stream; merging is done in the
    remote shell with ``2>&1``. The result always runs through ``sh``.
    """
    if shell:
        return ["exec 2>&1\n" + argv[0], *argv[1:]], True
    return ['exec "$@" 2>&1', "sh", *argv], True


def normalize_env(env: Optional[Mapping[str, Optional[str]]]) -> Optional[dict[str, Optional[str]]]:
    if env is None:
        return None
    out: dict[str, Optional[str]] = {}
    for k, v in env.items():
        out[os.fsdecode(k)] = None if v is None else os.fsdecode(v)
    return out


def normalize_cwd(cwd: Union[str, bytes, "os.PathLike[Any]", None]) -> Optional[str]:
    return None if cwd is None else os.fsdecode(cwd)


def signal_to_name(sig: Union[int, str, signal.Signals]) -> str:
    """Map ``signal.SIGTERM`` / ``15`` / ``"TERM"`` / ``"SIGTERM"`` to ``"TERM"``."""
    if isinstance(sig, str):
        return sig[3:] if sig.startswith("SIG") else sig
    name = signal.Signals(int(sig)).name
    return name[3:] if name.startswith("SIG") else name


# ---------------------------------------------------------------------------
# Text mode
# ---------------------------------------------------------------------------


def text_encoding(encoding: Optional[str]) -> str:
    """The encoding used in text mode when none is given (as :mod:`subprocess`)."""
    return encoding or locale.getpreferredencoding(False)


def is_text_mode(
    text: Optional[bool],
    encoding: Optional[str],
    errors: Optional[str],
    universal_newlines: Optional[bool],
) -> bool:
    if universal_newlines is not None and text is not None and bool(universal_newlines) != bool(text):
        raise subprocess.SubprocessError(
            "Cannot disambiguate when both text and universal_newlines are supplied but "
            "different. Pass one or the other."
        )
    return bool(text or universal_newlines or encoding or errors)


def translate_newlines(data: bytes, encoding: str, errors: Optional[str]) -> str:
    """Decode and apply universal newlines, like :mod:`subprocess` does."""
    return data.decode(encoding, errors or "strict").replace("\r\n", "\n").replace("\r", "\n")


def encode_input(input: Union[str, bytes, bytearray, memoryview, None], text_mode: bool, encoding: str, errors: Optional[str]) -> Optional[bytes]:
    if input is None:
        return None
    if isinstance(input, str):
        if not text_mode:
            raise TypeError("input must be bytes when not in text mode")
        return input.encode(encoding, errors or "strict")
    if text_mode:
        raise TypeError("input must be str in text mode")
    return bytes(input)
