"""Legacy ``tues.run`` API, the original Python interface on Session."""

import io
import os
import pty
import select
import signal
import stat
import subprocess
import sys
import termios
import threading
import time

import pytest

import tues

from conftest import NOPASSWD_USER, PASSWORD, USER


def _opts(sshd, **extra):
    kw = sshd.connect_kwargs()
    kw.update(extra)
    return kw


def test_password_manager_caches_until_invalidate():
    asked = []
    pm = tues.PasswordManager(prompt=lambda message: asked.append(message) or "secret")
    assert pm.get() is None
    assert asked == []

    class Request:
        prompt = "sudo password: "

    assert pm.get(Request()) == "secret"
    assert pm.get("again") == "secret"
    assert asked == ["sudo password: "]
    pm.invalidate(Request())
    assert pm.get("again") == "secret"
    assert asked == ["sudo password: ", "again"]


def test_password_manager_uses_preset_and_env(monkeypatch):
    assert tues.PasswordManager(password="fixed").get("prompt") == "fixed"
    monkeypatch.setenv("TUES_PW", "from-env")
    assert tues.PasswordManager().get() == "from-env"


def test_password_manager_remembers_a_refusal_until_invalidate():
    answers = iter([None, "later"])
    pm = tues.PasswordManager(prompt=lambda message: next(answers))
    assert pm.get("Password: ") is None
    assert pm.get("again") is None
    pm.invalidate()
    assert pm.get("again") == "later"


def test_password_manager_prompts_once_when_callers_overlap():
    """The pool_size > 1 race: every host used to ask before the first answer was stored."""
    started = threading.Event()
    release = threading.Event()
    entered = threading.Barrier(4)
    calls = []

    def prompt(message):
        calls.append(message)
        started.set()
        assert release.wait(5)
        return "secret"

    pm = tues.PasswordManager(prompt=prompt)
    results = []
    errors = []

    def worker():
        entered.wait()
        try:
            results.append(pm.get("Password: "))
        except Exception as exc:  # noqa: BLE001 — the assertion reports it
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    assert started.wait(2)
    time.sleep(0.05)
    assert calls == ["Password: "]
    release.set()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert errors == []
    assert sorted(results) == ["secret"] * 4


_TTY_CHILD = r"""
import fcntl
import os
import sys
import termios
import threading
import time

import tues
from tues.legacy import _sigint_kills

try:
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
except OSError as exc:
    sys.stderr.write("tty: %s\n" % exc)
    os._exit(2)

mode = sys.argv[1]
if mode == "read":
    if len(sys.argv) > 2:
        finish = getattr(tues.PasswordPromptFinish, sys.argv[2])
        manager = tues.PasswordManager(prompt_finish=finish)
    else:
        manager = tues.PasswordManager()
    password = manager.get("Password: ")
    sys.stdout.write("PW=%s\n" % password)
    sys.stdout.flush()
elif mode == "interrupt":
    def ask():
        tues.PasswordManager().get("Password: ")

    thread = threading.Thread(target=ask)
    thread.start()
    with _sigint_kills([]):
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            thread.join(2)
            os._exit(0 if not thread.is_alive() else 3)
    os._exit(4)
else:
    os._exit(5)
"""


def _prompt_env():
    env = os.environ.copy()
    source = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _open_prompt_pty():
    master, slave = pty.openpty()
    inspect = os.dup(slave)
    return master, slave, inspect


def _read_master(master, timeout, until=None):
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if until is not None and until in buf:
            return buf
        ready, _, _ = select.select([master], [], [], 0.1)
        if not ready:
            continue
        try:
            chunk = os.read(master, 1024)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _screen(data: bytes) -> list[str]:
    """Replay CR, LF, and erase-line sequences the way a terminal would."""
    rows = [""]
    row = 0
    col = 0
    index = 0
    while index < len(data):
        if data.startswith(b"\x1b[2K", index):
            rows[row] = ""
            index += 4
            continue
        if data.startswith(b"\x1b[K", index):
            rows[row] = rows[row][:col]
            index += 3
            continue
        byte = data[index]
        index += 1
        if byte == 0x0D:
            col = 0
        elif byte == 0x0A:
            row += 1
            col = 0
            if row == len(rows):
                rows.append("")
        else:
            ch = chr(byte)
            line = rows[row]
            if col < len(line):
                rows[row] = line[:col] + ch + line[col + 1 :]
            else:
                rows[row] = line + (" " * (col - len(line))) + ch
            col += 1
    return rows


def _wait_flag(inspect, masked, want, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        flags = termios.tcgetattr(inspect)[3]
        if flags & masked == want:
            return flags
        time.sleep(0.02)
    return termios.tcgetattr(inspect)[3]


def test_default_prompt_reads_a_password_and_restores_the_terminal():
    master, slave, inspect = _open_prompt_pty()
    proc = subprocess.Popen(
        [sys.executable, "-c", _TTY_CHILD, "read"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
        env=_prompt_env(),
    )
    os.close(slave)
    try:
        seen = _read_master(master, 3, until=b"Password:")
        assert b"Password:" in seen, seen
        during = _wait_flag(inspect, termios.ECHO | termios.ICANON | termios.ISIG, termios.ICANON | termios.ISIG, 2)
        assert during & termios.ECHO == 0
        assert during & termios.ICANON
        os.write(master, b"s3cret\n")
        seen += _read_master(master, 3, until=b"PW=")
        proc.wait(timeout=3)
        after = termios.tcgetattr(inspect)[3]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        os.close(master)
        os.close(inspect)
    assert proc.returncode == 0, seen
    assert b"PW=s3cret" in seen
    rows = _screen(seen)
    prompt_row = next(i for i, row in enumerate(rows) if "Password:" in row)
    pw_row = next(i for i, row in enumerate(rows) if "PW=s3cret" in row)
    assert pw_row == prompt_row + 1, rows
    assert rows[pw_row].startswith("PW="), rows
    assert after & termios.ECHO
    assert after & termios.ICANON
    assert after & termios.ISIG


def test_interrupted_password_prompt_restores_the_terminal():
    master, slave, inspect = _open_prompt_pty()
    proc = subprocess.Popen(
        [sys.executable, "-c", _TTY_CHILD, "interrupt"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
        env=_prompt_env(),
    )
    os.close(slave)
    try:
        seen = _read_master(master, 3, until=b"Password:")
        assert b"Password:" in seen, seen
        during = _wait_flag(inspect, termios.ECHO | termios.ICANON | termios.ISIG, termios.ICANON | termios.ISIG, 2)
        assert during & termios.ECHO == 0, during
        assert during & termios.ICANON, during
        os.kill(proc.pid, signal.SIGINT)
        proc.wait(timeout=3)
        after = termios.tcgetattr(inspect)[3]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        os.close(master)
        os.close(inspect)
    assert proc.returncode == 0, seen
    assert after & termios.ECHO, after
    assert after & termios.ICANON, after
    assert after & termios.ISIG, after


@pytest.mark.parametrize("finish", ["CurrentLine", "Erase"])
def test_password_prompt_finish(finish):
    master, slave, inspect = _open_prompt_pty()
    proc = subprocess.Popen(
        [sys.executable, "-c", _TTY_CHILD, "read", finish],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
        env=_prompt_env(),
    )
    os.close(slave)
    try:
        seen = _read_master(master, 3, until=b"Password:")
        assert b"Password:" in seen, seen
        os.write(master, b"s3cret\n")
        seen += _read_master(master, 3, until=b"PW=")
        proc.wait(timeout=3)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        os.close(master)
        os.close(inspect)
    assert proc.returncode == 0, seen
    rows = _screen(seen)
    if finish == "CurrentLine":
        assert b"Password: PW=" in seen, seen
        assert any(row.startswith("Password: PW=") for row in rows), rows
    else:
        assert b"\r\x1b[2K" in seen, seen
        assert "Password:" not in "\n".join(rows), rows
        assert any(row.startswith("PW=s3cret") for row in rows), rows


def test_host_parses_destination_and_tuple():
    host = tues.Host("alice@web01:2222")
    assert host.name == "web01"
    assert host.port == 2222
    assert host.destination == "alice@web01:2222"
    host = tues.Host(("localhost", 9))
    assert (host.name, host.port) == ("localhost", 9)
    host = tues.Host("[::1]")
    assert host.name == "::1"
    assert host.port is None


def test_no_hosts():
    with pytest.raises(tues.TuesError, match="No hosts"):
        tues.run([], "true")


def test_check_rejects_a_pool():
    with pytest.raises(tues.TuesError, match="pool size"):
        tues.run(["a", "b"], "true", check=True, pool_size=2)


def test_provider_cl_and_file(tmp_path):
    assert tues.provider("cl", ["web01", "", "#skip", "web02"]) == ["web01", "web02"]
    path = tmp_path / "hosts"
    path.write_text("# comment\n\n web01 \nweb02\n")
    assert tues.provider("file", [str(path)]) == ["web01", "web02"]


def test_provider_missing():
    with pytest.raises(tues.TuesLookupError):
        tues.provider("does-not-exist", [])


def test_script_not_found():
    with pytest.raises(tues.TuesScriptNotFoundError):
        tues.Script("does-not-exist", paths=["/tmp"])


def test_script_header(tmp_path):
    path = tmp_path / "myscript"
    path.write_text(
        "#!/bin/sh\n"
        '# tues-args = {"user": "nobody"}\n'
        '# tues-provider = "cl"\n'
        '# tues-provider-args = ["localhost"]\n'
        "printf %s ok\n"
    )
    script = tues.Script(["myscript", "-n"], paths=[str(tmp_path)])
    assert script.run_args == {"user": "nobody"}
    assert script.provider == "cl"
    assert script.provider_args == ["localhost"]


def test_script_header_rejects_unknown_key(tmp_path):
    path = tmp_path / "myscript"
    path.write_text("# tues-nope = 1\n")
    with pytest.raises(tues.TuesError, match="section"):
        tues.Script("myscript", paths=[str(tmp_path)])


def test_output_dir_abort(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(tues.TuesOutputDirExists):
        tues.run("localhost", "true", output_dir=str(output), output_dir_strategy=tues.DIR_ABORT)


def test_run_text_and_argv(sshd):
    task = tues.run(
        sshd.host,
        ["printf", "%s", "hello"],
        capture_output=True,
        text=True,
        connect_options=_opts(sshd),
    )
    assert isinstance(task, tues.Task)
    assert task.stdout == "hello"
    assert task.stderr == ""
    assert task.returncode == 0
    assert task.login_user == USER


def test_run_sudo_and_prefix(sshd):
    task = tues.run(
        sshd.host,
        "printf %s foo",
        user="root",
        prefix=True,
        capture_output=True,
        text=True,
        connect_options=_opts(sshd),
    )
    assert task.stdout == "[%s/stdout]: foo" % sshd.host
    assert task.stderr == ""
    assert task.sudo


def test_run_pty_merges_stderr(sshd):
    task = tues.run(
        sshd.host,
        "printf %s out; printf %s err >&2",
        pty=True,
        capture_output=True,
        text=True,
        connect_options=_opts(sshd),
    )
    assert task.stderr is None
    assert "out" in task.stdout and "err" in task.stdout


def test_run_sudo_without_password_prompt(sshd):
    task = tues.run(
        sshd.host,
        "id -un",
        user=NOPASSWD_USER,
        capture_output=True,
        text=True,
        check=True,
        connect_options=_opts(sshd, password=None),
    )
    assert task.stdout.strip() == NOPASSWD_USER


def test_run_input_and_stdin(sshd, tmp_path):
    opts = _opts(sshd)
    task = tues.run(sshd.host, "cat", input=b"bytes", capture_output=True, connect_options=opts)
    assert task.stdout == b"bytes"

    task = tues.run(
        sshd.host,
        "cat",
        input="text\n",
        capture_output=True,
        text=True,
        connect_options=opts,
    )
    assert task.stdout == "text\n"

    path = tmp_path / "input"
    path.write_bytes(b"from-file")
    task = tues.run(sshd.host, "cat", stdin=str(path), capture_output=True, connect_options=opts)
    assert task.stdout == b"from-file"

    task = tues.run(
        sshd.host,
        "cat",
        stdin=io.StringIO("stream"),
        capture_output=True,
        text=True,
        connect_options=opts,
    )
    assert task.stdout == "stream"


def test_run_stdio_targets(sshd, capsys):
    opts = _opts(sshd)
    host = sshd.host
    task = tues.run(host, "printf %s out; printf %s err >&2", stdout=tues.PIPE, text=True, connect_options=opts)
    captured = capsys.readouterr()
    assert task.stdout == "out"
    assert captured.err == "err"

    task = tues.run(host, "printf %s out; printf %s err >&2", stderr=tues.PIPE, text=True, connect_options=opts)
    captured = capsys.readouterr()
    assert task.stderr == "err"
    assert captured.out == "out"

    stdout, stderr = io.StringIO(), io.StringIO()
    tues.run(
        host,
        "printf %s out; printf %s err >&2",
        stdout=stdout,
        stderr=stderr,
        text=True,
        connect_options=opts,
    )
    assert stdout.getvalue() == "out"
    assert stderr.getvalue() == "err"

    task = tues.run(
        host,
        "printf %s out; printf %s err >&2",
        stderr=tues.STDOUT,
        text=True,
        connect_options=opts,
    )
    captured = capsys.readouterr()
    assert task.stderr is None
    assert captured.out in ("outerr", "errout")

    task = tues.run(
        host,
        "printf %s out; printf %s err >&2",
        stdout=tues.DEVNULL,
        stderr=tues.PIPE,
        text=True,
        connect_options=opts,
    )
    captured = capsys.readouterr()
    assert task.stdout is None
    assert task.stderr == "err"
    assert captured.out == ""


def test_run_prefix_without_newlines(sshd):
    task = tues.run(
        sshd.host,
        "printf %s out; printf %s err >&2; printf %s out; printf %s err >&2",
        prefix=True,
        capture_output=True,
        text=True,
        connect_options=_opts(sshd),
    )
    assert task.stdout == f"[{sshd.host}/stdout]: outout"
    assert task.stderr == f"[{sshd.host}/stderr]: errerr"


def test_run_env_cwd_and_files(sshd, tmp_path):
    opts = _opts(sshd)
    task = tues.run(
        sshd.host,
        "printf %s \"$VAR\"; pwd",
        env={"VAR": "föö"},
        cwd="/",
        capture_output=True,
        text=True,
        connect_options=opts,
    )
    assert task.stdout == "föö/\n"

    local = tmp_path / "payload"
    local.write_text("payload")
    os.chmod(local, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    task = tues.run(
        sshd.host,
        "cat \"$TUES_FILE1\"",
        files=[str(local)],
        cwd="/tmp",
        capture_output=True,
        text=True,
        user="root",
        connect_options=opts,
    )
    assert task.stdout == "payload"
    # Removed after the command.
    gone = tues.run(
        sshd.host,
        "test ! -e /tmp/" + local.name,
        check=True,
        connect_options=opts,
    )
    assert gone.returncode == 0


def test_run_connect_failure_is_task_error(sshd):
    with pytest.raises(tues.TuesTaskError) as exc:
        tues.run(
            ("127.0.0.1", 1),
            "true",
            connect_options=_opts(sshd, connect_timeout=3),
        )
    task = exc.value.args[0]
    assert task.host == "127.0.0.1"
    assert task.cmd == "true"
    assert exc.value.__cause__ is not None
    assert "Could not connect" in str(exc.value.__cause__)


def test_run_refused_password_aborts(sshd):
    with pytest.raises(tues.TuesUserAbort, match="Sudo authorization failed"):
        tues.run(
            sshd.host,
            "id",
            user="root",
            connect_options=_opts(sshd, password=None, password_manager=lambda request: None),
        )


def test_run_rejected_sudo_password_is_a_task_status(sshd):
    opts = _opts(sshd, password=None, password_manager=lambda request: "nope")
    task = tues.run(sshd.host, "id", user="root", capture_output=True, connect_options=opts)
    assert task.returncode not in (None, 0)

    with pytest.raises(tues.TuesTaskError) as exc:
        tues.run(sshd.host, "id", user="root", check=True, connect_options=opts)
    assert isinstance(exc.value, tues.TuesTaskError)
    assert not isinstance(exc.value, tues.TuesUserAbort)
    assert exc.value.__cause__ is None
    assert exc.value.args[0].returncode not in (None, 0)


def test_run_check_raises_task_error(sshd):
    with pytest.raises(tues.TuesTaskError) as exc:
        tues.run(
            sshd.host,
            "printf %s out; printf %s err >&2; false",
            check=True,
            capture_output=True,
            text=True,
            connect_options=_opts(sshd),
        )
    assert exc.value.args[0] is not None
    assert exc.value.args[0].returncode != 0
    assert exc.value.__cause__ is None
    assert exc.value.stdout == "out"
    assert exc.value.stderr == "err"


def test_run_pool_asks_for_the_password_once(sshd):
    started = threading.Event()
    release = threading.Event()
    calls = []

    def prompt(message):
        calls.append(message)
        started.set()
        assert release.wait(15)
        return PASSWORD

    pm = tues.PasswordManager(prompt=prompt)
    holder = {}
    errors = []

    def invoke():
        try:
            holder["tasks"] = tues.run(
                [sshd.host, sshd.host],
                "id -un",
                user="root",
                pool_size=2,
                capture_output=True,
                text=True,
                connect_options=_opts(sshd, password=None, password_manager=pm),
            )
        except Exception as exc:  # noqa: BLE001 — reported after the prompt is released
            errors.append(exc)

    thread = threading.Thread(target=invoke)
    thread.start()
    try:
        assert started.wait(20)
        time.sleep(1)
        assert len(calls) == 1
    finally:
        release.set()
    thread.join(20)
    assert not thread.is_alive()
    assert errors == []
    assert len(calls) == 1
    assert [task.stdout.strip() for task in holder["tasks"]] == ["root", "root"]


def test_run_pool_and_error_group(sshd):
    opts = _opts(sshd, connect_timeout=3)
    tasks = tues.run(
        [sshd.host, sshd.host],
        "printf %s ok",
        capture_output=True,
        text=True,
        pool_size=2,
        connect_options=opts,
    )
    assert [task.stdout for task in tasks] == ["ok", "ok"]

    with pytest.raises(tues.TuesErrorGroup) as exc:
        tues.run(
            [sshd.host, ("127.0.0.1", 1)],
            "printf %s ok",
            pool_size=2,
            capture_output=True,
            text=True,
            connect_options=opts,
        )
    assert exc.value.message == "Errors encountered while running tasks with concurrency"
    assert len(exc.value.exceptions) == 1
    assert len(exc.value.results) == 1
    assert exc.value.results[0].stdout == "ok"
    assert isinstance(exc.value.exceptions[0], tues.TuesError)
    assert not isinstance(exc.value.exceptions[0], tues.TuesTaskError)


def test_run_output_dir_strategies(sshd, tmp_path):
    opts = _opts(sshd)
    host = tues.Host(sshd.host).name
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep").touch()
    (output / "old.log").touch()
    tues.run(sshd.host, "printf %s hi", output_dir=str(output), output_dir_strategy=tues.DIR_WIPE, connect_options=opts)
    names = {path.name for path in output.iterdir()}
    assert names == {"keep", f"{host}.log"}
    assert (output / f"{host}.log").read_text() == "hi"

    (tmp_path / "output.1").mkdir()
    (tmp_path / "output.unrelated").mkdir()
    tues.run(
        sshd.host,
        "printf %s next",
        output_dir=str(output),
        output_dir_strategy=tues.DIR_ROTATE,
        connect_options=opts,
    )
    assert (output / f"{host}.log").read_text() == "next"
    assert (tmp_path / "output.2" / "keep").exists()


def test_script_runs_on_the_host(sshd, tmp_path):
    path = tmp_path / "myscript"
    path.write_text("#!/bin/sh\nprintf %s \"$*\"\n")
    path.chmod(0o755)
    script = tues.Script(["myscript", "arg"], paths=[str(tmp_path)])
    task = script.run(sshd.host, capture_output=True, text=True, connect_options=_opts(sshd))
    assert task.stdout == "arg"


def test_script_provider_and_user(sshd, tmp_path):
    path = tmp_path / "myscript"
    path.write_text(
        "#!/bin/sh\n"
        '# tues-args = {"user": "root"}\n'
        '# tues-provider = "cl"\n'
        f'# tues-provider-args = ["{sshd.host}"]\n'
        "id -un\n"
    )
    script = tues.Script("myscript", paths=[str(tmp_path)])
    tasks = script.run(capture_output=True, text=True, connect_options=_opts(sshd))
    assert tasks[0].stdout.strip() == "root"
    assert tasks[0].sudo


def test_align_prefix_pads_the_shorter_name():
    from tues.legacy import _Capture, _prefix

    task = tues.Task("true", tues.Host("h"), prefix=True, prefix_width_hint=5, text=True)
    capture = _Capture()
    _prefix(capture, task, "/stdout").write(b"x\n")
    assert capture.getvalue() == b"    [h/stdout]: x\n"


def test_preexec_and_postexec(sshd):
    seen = []
    tues.run(
        sshd.host,
        "true",
        preexec_fn=lambda task: seen.append(("pre", task.host)),
        postexec_fn=lambda task: seen.append(("post", task.returncode)),
        connect_options=_opts(sshd),
    )
    assert seen == [("pre", sshd.host), ("post", 0)]


def test_pty_rejects_input():
    with pytest.raises(tues.TuesError, match="pty"):
        tues.run("localhost", "cat", pty=True, input=b"x")
