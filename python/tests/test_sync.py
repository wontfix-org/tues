import os

import pytest

import tues

from conftest import NOPASSWD_USER, PASSWORD, USER


@pytest.fixture
def session(sshd):
    with tues.Session.connect(f"{USER}@{sshd.host}", **sshd.connect_kwargs()) as s:
        yield s


def test_repr_and_properties(session, sshd):
    assert session.user == USER
    assert session.host == sshd.host
    assert session.port == sshd.port
    assert session.run_as is None
    assert not session.closed
    assert repr(session) == f"Session({USER}@{sshd.host}:{sshd.port})"


def test_run_shell_string(session):
    out = session.run("echo hello; echo err >&2; exit 3")
    assert out.stdout == b"hello\n"
    assert out.stderr == b"err\n"
    assert out.returncode == 3
    assert out.status.code == 3
    assert not out.success
    assert not out.status
    assert out.text() == "hello\n"


def test_run_argv_list(session):
    out = session.run(["printf", "%s|%s", "a b", "$HOME"], check=True)
    assert out.stdout == b"a b|$HOME"


def test_run_check_raises(session):
    with pytest.raises(tues.TuesError, match="exit status: 1"):
        session.run("false", check=True)


def test_env_and_cwd(session):
    out = session.run("echo $FOO; pwd", env={"FOO": "bar"}, cwd="/tmp", check=True)
    assert out.stdout == b"bar\n/tmp\n"


def test_input(session):
    data = os.urandom(100_000)
    out = session.run("cat", input=data, check=True)
    assert out.stdout == data


def test_sudo_with_static_password(session):
    out = session.run(["id", "-un"], run_as="root", check=True)
    assert out.stdout == b"root\n"
    assert out.stderr == b""


def test_sudo_binary_stdout_is_untouched(session):
    data = os.urandom(300_000) + b"[tues-sudo-x] Sorry, try again.\n" + PASSWORD.encode()
    out = session.run("cat", input=data, run_as="root", check=True)
    assert out.stdout == data


def test_sudo_pty(session):
    out = session.run("id -un", run_as="root", pty=True, check=True)
    assert b"root" in out.stdout
    assert b"tues-sudo" not in out.stdout
    assert PASSWORD.encode() not in out.stdout


def test_sudo_nopasswd_user_without_password(sshd):
    with tues.Session.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None)
    ) as s:
        out = s.run("id -un", run_as=NOPASSWD_USER, check=True)
        assert out.stdout == NOPASSWD_USER.encode() + b"\n"
        with pytest.raises(tues.SudoError):
            s.run("id", run_as="root")


def test_session_default_run_as(sshd):
    with tues.Session.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(run_as="root")
    ) as s:
        assert s.run_as == "root"
        assert s.run("id -un", check=True).stdout == b"root\n"
        assert s.run("id -un", run_as_login_user=True, check=True).stdout == b"tues\n"


def test_password_prompter_is_memoized(sshd):
    calls = []

    def prompter(req):
        calls.append((req.kind, req.host, req.port, req.user, req.run_as))
        assert "sudo" in req.prompt
        return PASSWORD

    with tues.Session.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=prompter)
    ) as s:
        for _ in range(3):
            s.run("true", run_as="root", check=True)
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
    with tues.Session.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=pm)
    ) as s:
        assert s.run("id -un", run_as="root", check=True).stdout == b"root\n"
    assert pm.invalidated == ["sudo"]


def test_always_wrong_password_fails(sshd):
    with tues.Session.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(password=None, password_manager=lambda r: "nope")
    ) as s:
        with pytest.raises(tues.SudoError, match="after 3 attempt"):
            s.run("id", run_as="root")


def test_spawn_streams(session):
    child = session.spawn("cat")
    child.stdin.write(b"line1\nline2\n")
    child.stdin.close()
    assert child.stdin.closed
    assert child.stdout.readline() == b"line1\n"
    assert child.stdout.read() == b"line2\n"
    assert child.stdout.read() == b""
    assert child.wait().code == 0
    assert child.poll().success


def test_spawn_iter_lines(session):
    child = session.spawn("printf 'a\\nb\\nc'")
    assert list(child.stdout) == [b"a\n", b"b\n", b"c"]
    child.wait()


def test_communicate(session):
    child = session.spawn("tr a-z A-Z; echo done >&2", run_as="root")
    out, err = child.communicate(b"shout")
    assert out == b"SHOUT"
    assert err == b"done\n"
    assert child.poll().code == 0


def test_stdio_modes(session):
    child = session.spawn("echo out; echo err >&2", stdout="null", stderr="pipe")
    assert child.stdout is None
    assert child.stdin is not None
    assert child.stderr.read() == b"err\n"
    child.wait()


def test_kill(session):
    child = session.spawn("sleep 30")
    assert child.poll() is None
    child.kill()
    status = child.wait()
    assert not status.success
    assert status.signal == "KILL"
    assert status.code is None


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


def test_closed_session(sshd):
    s = tues.Session.connect(f"{USER}@{sshd.host}", **sshd.connect_kwargs())
    s.close()
    assert s.closed
    with pytest.raises(tues.TuesError):
        s.run("true")


def test_auth_error(sshd):
    with pytest.raises(tues.AuthError):
        tues.Session.connect(
            f"{USER}@{sshd.host}",
            **sshd.connect_kwargs(identity_files=[], password="wrong"),
        )


def test_connect_error(sshd):
    with pytest.raises(tues.ConnectError, match="could not connect"):
        tues.Session.connect("127.0.0.1", **sshd.connect_kwargs(port=1, connect_timeout=2))


def test_unknown_kwargs_rejected(sshd):
    with pytest.raises(ValueError, match="bogus"):
        tues.Session.connect("127.0.0.1", bogus=1, **sshd.connect_kwargs())
    with pytest.raises(ValueError, match="host_key_policy"):
        tues.Session.connect("127.0.0.1", **sshd.connect_kwargs(host_key_policy="maybe"))


def test_destination_port_and_user(sshd):
    with tues.Session.connect(
        f"{USER}@{sshd.host}:{sshd.port}", **sshd.connect_kwargs(port=None, user=None)
    ) as s:
        assert s.port == sshd.port
        assert s.run("id -un", check=True).stdout == b"tues\n"
