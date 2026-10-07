import asyncio
import os
import signal
import subprocess

import pytest

import tues

from conftest import PASSWORD, USER, require_sudo


def run(coro):
    return asyncio.run(coro)


async def connect(sshd, **overrides):
    return await tues.AsyncSession.connect(f"{USER}@{sshd.host}", **sshd.connect_kwargs(**overrides))


def test_executable_selects_the_shell(sshd):
    async def main():
        async with await connect(sshd) as s:
            out = await s.run(
                "cat <<<foo", shell=True, executable="bash", capture_output=True, text=True
            )
            assert out.returncode == 0 and out.stdout == "foo\n"
            out = await s.run("cat <<<foo", shell=True, capture_output=True, text=True)
            assert out.returncode != 0

    run(main())


def test_run_and_properties(sshd):
    async def main():
        async with await connect(sshd) as s:
            assert isinstance(s, tues.AsyncSession)
            assert s.login_user == USER and s.port == sshd.port and not s.closed
            assert s.host == sshd.host and s.user is None
            assert repr(s) == f"AsyncSession({USER}@{sshd.host}:{sshd.port})"
            out = await s.run("echo hello; exit 2", shell=True, capture_output=True)
            assert isinstance(out, tues.CompletedProcess)
            assert out.stdout == b"hello\n" and out.stderr == b"" and out.returncode == 2
            require_sudo(sshd)
            out = await s.run(["id", "-un"], user="root", stdout=tues.PIPE, check=True)
            assert out.stdout == b"root\n" and out.stderr is None
            out = await s.run("printf 'a\\r\\nb'; echo e >&2", shell=True, capture_output=True, text=True)
            assert out.stdout == "a\nb" and out.stderr == "e\n"
            out = await s.run(["cat"], input="héllo", capture_output=True, encoding="utf-8")
            assert out.stdout == "héllo"
            out = await s.run("echo o; echo e >&2", shell=True, stdout=tues.PIPE, stderr=tues.STDOUT)
            assert out.stdout == b"o\ne\n"
            assert (await s.run(["cat"], capture_output=True)).stdout == b""  # stdin defaults to EOF
            with pytest.raises(tues.CalledProcessError) as ei:
                await s.run(["false"], check=True)
            assert isinstance(ei.value, subprocess.CalledProcessError)
            assert ei.value.cmd == ["false"] and ei.value.returncode == 1
        assert s.closed

    run(main())


def test_session_default_user(sshd):
    require_sudo(sshd)

    async def main():
        async with await connect(sshd, user="root") as s:
            assert s.user == "root"
            out = await s.run(["id", "-un"], capture_output=True, check=True)
            assert out.stdout == b"root\n"

    run(main())


def test_raw_child_streams(sshd):
    """The `tues._tues.AsyncChild` layer under `tues.Process`."""
    from tues._tues import AsyncSession as RawAsyncSession

    async def main():
        raw = await RawAsyncSession.connect(f"{USER}@{sshd.host}", **sshd.connect_kwargs())
        child = await raw.spawn(["cat"], stdin=tues.PIPE, stdout=tues.PIPE, stderr=tues.DEVNULL)
        assert repr(child) == "AsyncChild(...)"
        assert child.stderr is None
        assert child.returncode is None and child.poll() is None
        assert not child.stdin.closed
        assert await child.stdin.write(b"abc") == 3
        assert await child.stdout.read(2) == b"ab"
        await child.stdin.close()
        await child.stdin.close()  # idempotent
        assert child.stdin.closed
        with pytest.raises(ValueError, match="closed stdin"):
            await child.stdin.write(b"x")
        assert await child.stdout.read() == b"c"
        assert await child.wait() == 0
        assert child.poll() == 0 and child.returncode == 0
        await raw.close()

    run(main())


def test_run_timeout(sshd):
    async def main():
        async with await connect(sshd) as s:
            with pytest.raises(tues.TimeoutExpired) as ei:
                await s.run("echo partial; sleep 30", shell=True, capture_output=True, timeout=1)
            assert ei.value.stdout == b"partial\n"
            assert ei.value.timeout == 1

    run(main())


def test_concurrent_sudo_commands(sshd):
    require_sudo(sshd)

    async def main():
        calls = []

        def prompter(req):
            calls.append(req.kind)
            return PASSWORD

        async with await connect(sshd, password=None, password_manager=prompter) as s:
            outs = await asyncio.gather(*(s.run(["echo", str(i)], user="root", capture_output=True) for i in range(10)))
            assert [o.stdout for o in outs] == [f"{i}\n".encode() for i in range(10)]
        # Concurrent first-use may prompt more than once, but never per command.
        assert 1 <= len(calls) < 10

    run(main())


def test_binary_input_through_sudo(sshd):
    require_sudo(sshd)

    async def main():
        async with await connect(sshd) as s:
            data = os.urandom(200_000) + b"[tues-ok-abc]"
            out = await s.run(["cat"], input=data, user="root", stdout=tues.PIPE, check=True)
            assert out.stdout == data

    run(main())


def test_create_subprocess_exec_streams(sshd):
    async def main():
        async with await connect(sshd) as s:
            proc = await s.create_subprocess_exec("cat", stdin=tues.PIPE, stdout=tues.PIPE)
            assert isinstance(proc, tues.Process)
            assert isinstance(proc.stdout, asyncio.StreamReader)
            assert proc.stderr is None and proc.pid is None and proc.returncode is None
            proc.stdin.write(b"a\nb\n")
            await proc.stdin.drain()
            assert await proc.stdout.readline() == b"a\n"
            assert await proc.stdout.readexactly(1) == b"b"
            proc.stdin.close()
            await proc.stdin.wait_closed()
            assert proc.stdin.is_closing()
            assert await proc.stdout.read() == b"\n"
            assert proc.stdout.at_eof()
            assert await proc.wait() == 0
            assert proc.returncode == 0

    run(main())


def test_create_subprocess_shell_iter_lines(sshd):
    async def main():
        async with await connect(sshd) as s:
            proc = await s.create_subprocess_shell("printf 'a\\nb\\nc'; echo err >&2", stdout=tues.PIPE, stderr=tues.PIPE)
            lines = [line async for line in proc.stdout]
            assert lines == [b"a\n", b"b\n", b"c"]
            assert await proc.stderr.read() == b"err\n"
            await proc.wait()
            with pytest.raises(ValueError):
                await s.create_subprocess_shell(["not", "a", "string"])

    run(main())


def test_large_output_flow_control(sshd):
    async def main():
        async with await connect(sshd) as s:
            proc = await s.create_subprocess_exec("head", "-c", "3000000", "/dev/zero", stdout=tues.PIPE, limit=4096)
            n = 0
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                n += len(chunk)
            assert n == 3_000_000
            assert await proc.wait() == 0

    run(main())


def test_communicate_and_signals(sshd):
    require_sudo(sshd)

    async def main():
        async with await connect(sshd) as s:
            proc = await s.create_subprocess_shell("tr a-z A-Z", user="root", stdin=tues.PIPE, stdout=tues.PIPE, stderr=tues.PIPE)
            out, err = await proc.communicate(b"shout")
            assert out == b"SHOUT" and err == b""
            assert proc.returncode == 0

            proc = await s.create_subprocess_exec("sleep", "30")
            assert proc.returncode is None
            proc.kill()
            assert await proc.wait() == -signal.SIGKILL

            proc = await s.create_subprocess_exec("sleep", "30")
            proc.terminate()
            assert await proc.wait() == -signal.SIGTERM

            proc = await s.create_subprocess_exec("sleep", "30")
            waiter = asyncio.create_task(proc.wait())
            await asyncio.sleep(0.2)
            proc.send_signal("USR1")  # while another task waits
            assert await waiter == -signal.SIGUSR1

            proc = await s.create_subprocess_exec("sleep", "30")
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), 0.3)
            proc.kill()
            assert await proc.wait() == -9

    run(main())


def test_session_files(sshd, tmp_path):
    async def main():
        async with await connect(sshd) as s:
            src = tmp_path / "f.txt"
            src.write_bytes(b"hi")
            remote = f"/tmp/pytest-async-file-{os.getpid()}"
            await s.upload(src, remote)
            assert (await s.stat(remote)).size == 2
            dest = tmp_path / "out.txt"
            await s.download(remote, dest)
            assert dest.read_bytes() == b"hi"
            explicit = await s.sftp()
            await explicit.close()
            renamed = remote + ".2"
            await s.rename(remote, renamed)
            assert (await s.stat(renamed)).is_file
            await s.delete(renamed)
            with pytest.raises(tues.SftpError):
                await s.stat(renamed)

    run(main())


def test_sftp(sshd):
    async def main():
        async with await connect(sshd) as s:
            async with await s.sftp() as sftp:
                path = "/tmp/pytest-async.txt"
                await sftp.write(path, b"xyz")
                assert await sftp.read(path) == b"xyz"
                assert await sftp.read_text(path) == "xyz"
                async with await sftp.open(path, "r+") as f:
                    assert await f.seek(1) == 1
                    assert await f.tell() == 1
                    assert await f.read() == b"yz"
                    await f.seek(0, 2)
                    assert await f.write(b"!") == 1
                    await f.flush()
                assert f.closed
                with pytest.raises(ValueError, match="closed file"):
                    await f.read()
                f = await sftp.open(path)
                assert not f.closed
                assert await f.read(2) == b"xy"
                assert await f.read(10) == b"z!"  # short read at EOF
                assert await f.read(2) == b""
                await f.close()
                await f.close()  # idempotent
                assert f.closed
                with pytest.raises(ValueError, match="closed file"):
                    await f.write(b"x")
                assert (await sftp.stat(path)).size == 4
                assert any(e.name == "pytest-async.txt" for e in await sftp.listdir("/tmp"))
                await sftp.mkdir("/tmp/pytest-adir")
                assert (await sftp.stat("/tmp/pytest-adir")).is_dir
                await sftp.rmdir("/tmp/pytest-adir")
                await sftp.symlink(path, path + ".lnk")
                assert await sftp.readlink(path + ".lnk") == path
                assert (await sftp.lstat(path + ".lnk")).is_symlink
                assert not (await sftp.stat(path + ".lnk")).is_symlink
                assert await sftp.realpath(path + ".lnk") == path
                await sftp.remove(path + ".lnk")
                await sftp.rename(path, path + ".2")
                assert not await sftp.exists(path)
                await sftp.remove(path + ".2")
                with pytest.raises(tues.SftpError):
                    await sftp.read(path)

    run(main())


def test_errors(sshd):
    async def main():
        with pytest.raises(tues.ConnectError):
            await tues.AsyncSession.connect("127.0.0.1", **sshd.connect_kwargs(port=1, connect_timeout=2))
        with pytest.raises(tues.AuthError):
            await connect(sshd, identity_files=[], password="wrong")
        with pytest.raises(ValueError):
            await tues.AsyncSession.connect("127.0.0.1", bogus=1, **sshd.connect_kwargs())
        async with await connect(sshd) as s:
            with pytest.raises(ValueError, match="stdout must be"):
                await s.create_subprocess_exec("true", stdout=42)

    run(main())
