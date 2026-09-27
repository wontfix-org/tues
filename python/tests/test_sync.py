import io
import os
import signal
import subprocess
import time

import pytest

import tues

from conftest import NOPASSWD_USER, PASSWORD, USER


@pytest.fixture
def session(sshd):
    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs()) as s:
        yield s


def test_repr_and_properties(session, sshd):
    assert session.login_user == USER
    assert session.host == sshd.host
    assert session.port == sshd.port
    assert session.user is None
    assert not session.closed
    assert repr(session) == f"Session({USER}@{sshd.host}:{sshd.port})"


def test_connect_classmethod(sshd):
    with tues.Session.connect(f"{USER}@{sshd.host}", **sshd.connect_kwargs()) as s:
        assert isinstance(s, tues.Session)
        assert s.run(["true"]).returncode == 0


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------


def test_run_shell(session):
    out = session.run("echo hello; echo err >&2; exit 3", shell=True, capture_output=True)
    assert isinstance(out, tues.CompletedProcess)
    assert isinstance(out, subprocess.CompletedProcess)
    assert out.args == "echo hello; echo err >&2; exit 3"
    assert out.stdout == b"hello\n"
    assert out.stderr == b"err\n"
    assert out.returncode == 3
    with pytest.raises(tues.CalledProcessError):
        out.check_returncode()


def test_run_argv_list_is_quoted(session):
    out = session.run(["printf", "%s|%s", "a b", "$HOME"], stdout=tues.PIPE, check=True)
    assert out.stdout == b"a b|$HOME"
    assert out.stderr is None


def test_run_string_without_shell_is_one_program(session):
    assert session.run("true").returncode == 0
    # Like subprocess: the whole string is the program name.
    assert session.run("echo hello", stderr=tues.DEVNULL).returncode == 127


def test_run_shell_list_positional_params(session):
    out = session.run(['echo "$0:$1"', "zero", "one"], shell=True, capture_output=True)
    assert out.stdout == b"zero:one\n"


def test_run_check_raises_called_process_error(session):
    with pytest.raises(tues.CalledProcessError) as ei:
        session.run(["sh", "-c", "echo bad >&2; exit 7"], check=True, capture_output=True)
    e = ei.value
    assert isinstance(e, subprocess.CalledProcessError)
    assert isinstance(e, tues.TuesError)
    assert e.returncode == 7
    assert e.cmd == ["sh", "-c", "echo bad >&2; exit 7"]
    assert e.stderr == b"bad\n"
    assert e.output == e.stdout == b""


def test_run_text_mode(session):
    out = session.run("printf 'a\\r\\nb\\rc'; echo err >&2", shell=True, capture_output=True, text=True)
    assert out.stdout == "a\nb\nc"  # universal newlines
    assert out.stderr == "err\n"
    out = session.run(["cat"], input="héllo", capture_output=True, encoding="utf-8")
    assert out.stdout == "héllo"
    out = session.run(["cat"], input="x", capture_output=True, universal_newlines=True)
    assert out.stdout == "x"


def test_run_input_bytes(session):
    data = os.urandom(100_000)
    out = session.run(["cat"], input=data, stdout=tues.PIPE, check=True)
    assert out.stdout == data


def test_run_input_and_stdin_conflict(session):
    with pytest.raises(ValueError, match="stdin and input"):
        session.run(["cat"], input=b"x", stdin=tues.PIPE)
    with pytest.raises(ValueError, match="capture_output"):
        session.run(["cat"], capture_output=True, stdout=tues.PIPE)


def test_env_and_cwd(session):
    out = session.run("echo $FOO-$HOME; pwd", shell=True, env={"FOO": "bar"}, cwd="/tmp", capture_output=True, check=True)
    assert out.stdout == f"bar-/home/{USER}\n/tmp\n".encode()
    out = session.run("echo ${HOME-unset}", shell=True, env={"HOME": None}, capture_output=True)
    assert out.stdout == b"unset\n"


def test_stderr_to_stdout(session):
    out = session.run("echo out; echo err >&2", shell=True, stdout=tues.PIPE, stderr=tues.STDOUT)
    assert out.stdout == b"out\nerr\n"
    assert out.stderr is None
    out = session.run(["sh", "-c", "echo out; echo err >&2"], stdout=tues.PIPE, stderr=tues.STDOUT)
    assert out.stdout == b"out\nerr\n"


def test_devnull(session):
    out = session.run("echo out; echo err >&2", shell=True, stdout=tues.DEVNULL, stderr=tues.DEVNULL)
    assert out.stdout is None and out.stderr is None and out.returncode == 0


def test_inherit_local_stdout(session, capfd):
    session.run("echo to-local-stdout; echo to-local-stderr >&2", shell=True)
    captured = capfd.readouterr()
    assert "to-local-stdout" in captured.out
    assert "to-local-stderr" in captured.err


def test_file_objects(session):
    out_f = io.BytesIO()
    err_f = io.BytesIO()
    in_f = io.BytesIO(b"from-a-file")
    out = session.run("cat; echo err >&2", shell=True, stdin=in_f, stdout=out_f, stderr=err_f)
    assert out.returncode == 0
    assert out_f.getvalue() == b"from-a-file"
    assert err_f.getvalue() == b"err\n"


def test_stdin_default_is_eof(session):
    # A remote process cannot share the local stdin: default is no input.
    out = session.run(["cat"], capture_output=True, timeout=10)
    assert out.stdout == b""


def test_timeout(session):
    t0 = time.monotonic()
    with pytest.raises(tues.TimeoutExpired) as ei:
        session.run("echo partial; sleep 30", shell=True, capture_output=True, timeout=1)
    assert time.monotonic() - t0 < 10
    e = ei.value
    assert isinstance(e, subprocess.TimeoutExpired)
    assert e.timeout == 1
    assert e.cmd == "echo partial; sleep 30"
    assert e.stdout == b"partial\n"


def test_sudo_with_static_password(session):
    out = session.run(["id", "-un"], user="root", capture_output=True, check=True)
    assert out.stdout == b"root\n"
    assert out.stderr == b""


def test_sudo_binary_stdout_is_untouched(session):
    data = os.urandom(300_000) + b"[tues-sudo-x] Sorry, try again.\n" + PASSWORD.encode()
    out = session.run(["cat"], input=data, user="root", stdout=tues.PIPE, check=True)
    assert out.stdout == data


def test_sudo_pty(session):
    out = session.run(["id", "-un"], user="root", pty=True, capture_output=True, check=True)
    assert b"root" in out.stdout
    assert b"tues-sudo" not in out.stdout
    assert PASSWORD.encode() not in out.stdout


def test_sudo_nopasswd_user_without_password(sshd):
    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None)) as s:
        out = s.run(["id", "-un"], user=NOPASSWD_USER, capture_output=True, check=True)
        assert out.stdout == NOPASSWD_USER.encode() + b"\n"
        with pytest.raises(tues.SudoError):
            s.run(["id"], user="root", capture_output=True)


def test_session_default_user(sshd):
    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(user="root")) as s:
        assert s.user == "root"
        assert s.check_output(["id", "-un"]) == b"root\n"
        assert s.check_output(["id", "-un"], user=tues.LOGIN_USER) == b"tues\n"
        assert s.check_output(["id", "-un"], user=None) == b"root\n"
        with pytest.raises(TypeError, match="LOGIN_USER"):
            s.check_output(["id"], user=42)  # type: ignore[arg-type]
        assert repr(tues.LOGIN_USER) == "tues.LOGIN_USER"


# ---------------------------------------------------------------------------
# Password managers
# ---------------------------------------------------------------------------


def test_password_prompter_is_memoized(sshd):
    calls = []

    def prompter(req):
        calls.append((req.kind, req.host, req.port, req.login_user, req.user))
        assert "sudo" in req.prompt
        return PASSWORD

    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=prompter)) as s:
        for _ in range(3):
            s.run(["true"], user="root", check=True)
    assert calls == [("sudo", sshd.host, sshd.port, USER, "root")]


def test_wrong_password_is_invalidated_and_retried(sshd):
    class Manager:
        def __init__(self):
            self.answers = ["wrong", PASSWORD]
            self.invalidated = []

        def get(self, req):
            return self.answers.pop(0) if self.answers else PASSWORD

        def invalidate(self, req):
            self.invalidated.append(req.kind)

    pm = Manager()
    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=pm)) as s:
        assert s.check_output(["id", "-un"], user="root") == b"root\n"
    assert pm.invalidated == ["sudo"]


def test_always_wrong_password_fails(sshd):
    with tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=lambda r: "nope")) as s:
        with pytest.raises(tues.SudoError, match="after 3 attempt"):
            s.run(["id"], user="root", capture_output=True)


# ---------------------------------------------------------------------------
# Popen
# ---------------------------------------------------------------------------


def test_popen_streams(session):
    p = session.Popen(["cat"], stdin=tues.PIPE, stdout=tues.PIPE)
    assert isinstance(p, tues.Popen)
    assert p.args == ["cat"]
    assert p.pid is None
    assert p.stderr is None
    assert isinstance(p.stdout, io.BufferedReader)
    assert isinstance(p.stdin, io.BufferedWriter)
    p.stdin.write(b"line1\nline2\n")
    p.stdin.flush()
    assert p.stdout.readline() == b"line1\n"
    p.stdin.close()
    assert p.stdout.read() == b"line2\n"
    assert p.stdout.read() == b""
    assert p.wait() == 0
    assert p.poll() == 0
    assert p.returncode == 0


def test_popen_iter_lines_and_context_manager(session):
    with session.Popen("printf 'a\\nb\\nc'", shell=True, stdout=tues.PIPE) as p:
        assert list(p.stdout) == [b"a\n", b"b\n", b"c"]
    assert p.returncode == 0
    assert p.stdout.closed


def test_popen_text_mode(session):
    with session.Popen(["cat"], stdin=tues.PIPE, stdout=tues.PIPE, text=True, bufsize=1) as p:
        assert isinstance(p.stdout, io.TextIOWrapper)
        assert p.text_mode and p.universal_newlines
        p.stdin.write("héllo\r\n")  # line buffered: flushed on newline
        assert p.stdout.readline() == "héllo\n"
        p.stdin.close()
        assert p.stdout.read() == ""


def test_popen_unbuffered(session):
    with session.Popen(["cat"], bufsize=0, stdin=tues.PIPE, stdout=tues.PIPE) as p:
        assert isinstance(p.stdout, io.RawIOBase)
        p.stdin.write(b"x\n")
        assert p.stdout.readline() == b"x\n"
        p.stdin.close()


def test_popen_communicate(session):
    p = session.Popen("tr a-z A-Z; echo done >&2", shell=True, user="root", stdin=tues.PIPE, stdout=tues.PIPE, stderr=tues.PIPE)
    out, err = p.communicate(b"shout")
    assert out == b"SHOUT"
    assert err == b"done\n"
    assert p.returncode == 0
    assert p.poll() == 0


def test_popen_communicate_without_pipes(session):
    p = session.Popen(["true"])
    assert p.communicate() == (None, None)
    assert p.returncode == 0
    with pytest.raises(ValueError):
        session.Popen(["true"], stdout=42)


def test_popen_communicate_timeout_then_finish(session):
    p = session.Popen("echo start; sleep 2; echo end", shell=True, stdout=tues.PIPE)
    with pytest.raises(tues.TimeoutExpired):
        p.communicate(timeout=0.5)
    assert p.poll() is None
    out, err = p.communicate()
    assert out == b"start\nend\n"
    assert err is None
    assert p.returncode == 0
    with pytest.raises(ValueError, match="Cannot send input"):
        p.communicate(b"x")


def test_popen_wait_timeout(session):
    p = session.Popen(["sleep", "30"])
    with pytest.raises(tues.TimeoutExpired) as ei:
        p.wait(timeout=0.3)
    assert ei.value.timeout == 0.3
    assert p.poll() is None
    p.kill()
    assert p.wait(timeout=10) == -signal.SIGKILL
    assert p.returncode == -9
    p.kill()  # idempotent once finished


def test_popen_terminate_and_send_signal(session):
    # Give the remote shell time to exec `sleep`; a signal that lands during
    # process start-up may be swallowed by the remote side.
    p = session.Popen(["sleep", "30"])
    time.sleep(0.5)
    p.terminate()
    assert p.wait(timeout=10) == -signal.SIGTERM

    p = session.Popen(["sleep", "30"])
    time.sleep(0.5)
    p.send_signal("USR1")
    assert p.wait(timeout=10) == -signal.SIGUSR1

    p = session.Popen("trap 'echo got-term; exit 42' TERM; sleep 30 & wait", shell=True, stdout=tues.PIPE)
    time.sleep(0.5)
    p.send_signal(signal.SIGTERM)
    out, _ = p.communicate(timeout=10)
    assert out == b"got-term\n"
    assert p.returncode == 42


def test_popen_kill_closes_pipes(session):
    with session.Popen("echo a; sleep 30", shell=True, stdout=tues.PIPE) as p:
        assert p.stdout.readline() == b"a\n"
        p.kill()
        assert p.stdout.read() == b""
    assert p.returncode == -9


def test_popen_repr(session):
    p = session.Popen(["true"])
    assert repr(p).startswith("<Popen: returncode: None args: ['true']>")
    p.wait()
    assert "returncode: 0" in repr(p)


# ---------------------------------------------------------------------------
# call / check_call / check_output / getoutput
# ---------------------------------------------------------------------------


def test_call_family(session):
    assert session.call(["false"]) == 1
    assert session.check_call(["true"]) == 0
    with pytest.raises(tues.CalledProcessError) as ei:
        session.check_call(["sh", "-c", "exit 4"])
    assert ei.value.returncode == 4
    assert session.check_output(["echo", "hi"]) == b"hi\n"
    assert session.check_output(["echo", "hi"], text=True) == "hi\n"
    assert session.check_output(["cat"], input=None, text=True) == ""
    with pytest.raises(ValueError, match="stdout argument not allowed"):
        session.check_output(["true"], stdout=tues.PIPE)


def test_getoutput(session):
    assert session.getoutput("echo out; echo err >&2") == "out\nerr"
    assert session.getstatusoutput("echo x; exit 5") == (5, "x")
    assert session.getstatusoutput("echo -n") == (0, "")


# ---------------------------------------------------------------------------
# SFTP (unchanged API)
# ---------------------------------------------------------------------------


def test_session_files(session, tmp_path):
    src = tmp_path / "tree"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"aaa")
    (src / "sub" / "b.txt").write_bytes(b"bbb")
    (src / "link").symlink_to("a.txt")
    remote = f"/tmp/pytest-files-{os.getpid()}"
    session.upload(src, remote)
    assert session.stat(f"{remote}/a.txt").size == 3
    assert session.stat(f"{remote}/sub").is_dir
    dest = tmp_path / "down"
    session.download(remote, dest)
    assert (dest / "a.txt").read_bytes() == b"aaa"
    assert (dest / "sub" / "b.txt").read_bytes() == b"bbb"
    assert os.readlink(dest / "link") == "a.txt"
    session.rename(f"{remote}/a.txt", f"{remote}/c.txt")
    explicit = session.sftp()
    explicit.close()
    assert session.stat(f"{remote}/c.txt").is_file
    session.delete(remote)
    with pytest.raises(tues.SftpError):
        session.stat(remote)


def test_sftp(session):
    with session.sftp() as sftp:
        path = "/tmp/pytest-sync.txt"
        sftp.write(path, b"abc")
        assert sftp.read(path) == b"abc"
        assert sftp.read_text(path) == "abc"
        with sftp.open(path, "a") as f:
            assert f.write(b"def") == 3
        with sftp.open(path) as f:
            assert f.seek(2) == 2
            assert f.tell() == 2
            assert f.read(2) == b"cd"
            assert f.read() == b"ef"
        assert f.closed
        md = sftp.stat(path)
        assert md.size == 6 and md.is_file and not md.is_dir
        assert md.mtime is not None
        names = [e.name for e in sftp.listdir("/tmp")]
        assert "pytest-sync.txt" in names
        sftp.symlink(path, path + ".lnk")
        assert sftp.readlink(path + ".lnk") == path
        assert sftp.lstat(path + ".lnk").is_symlink
        assert sftp.realpath(path + ".lnk") == path
        sftp.rename(path, path + ".2")
        assert not sftp.exists(path)
        assert sftp.exists(path + ".2")
        sftp.mkdir("/tmp/pytest-dir")
        assert sftp.stat("/tmp/pytest-dir").is_dir
        sftp.rmdir("/tmp/pytest-dir")
        sftp.remove(path + ".2")
        sftp.remove(path + ".lnk")
        with pytest.raises(tues.SftpError):
            sftp.read("/tmp/does-not-exist")


def test_sftp_open_modes(session):
    with session.sftp() as sftp:
        with sftp.open("/tmp/pytest-x", "w") as f:
            f.write(b"1")
        with pytest.raises(tues.SftpError):
            sftp.open("/tmp/pytest-x", "x")
        with pytest.raises(ValueError):
            sftp.open("/tmp/pytest-x", "q")
        sftp.remove("/tmp/pytest-x")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_closed_session(sshd):
    s = tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs())
    s.close()
    assert s.closed
    with pytest.raises(tues.TuesError):
        s.run(["true"])


def test_auth_error(sshd):
    with pytest.raises(tues.AuthError):
        tues.Session(f"{USER}@{sshd.host}", **sshd.connect_kwargs(identity_files=[], password="wrong"))


def test_connect_error(sshd):
    with pytest.raises(tues.ConnectError, match="could not connect"):
        tues.Session("127.0.0.1", **sshd.connect_kwargs(port=1, connect_timeout=2))


def test_unknown_kwargs_rejected(sshd):
    with pytest.raises(ValueError, match="bogus"):
        tues.Session("127.0.0.1", bogus=1, **sshd.connect_kwargs())
    with pytest.raises(ValueError, match="host_key_policy"):
        tues.Session("127.0.0.1", **sshd.connect_kwargs(host_key_policy="maybe"))


def test_destination_port_and_user(sshd):
    with tues.Session(f"{USER}@{sshd.host}:{sshd.port}", **sshd.connect_kwargs(port=None, login_user=None)) as s:
        assert s.port == sshd.port
        assert s.check_output(["id", "-un"]) == b"tues\n"
