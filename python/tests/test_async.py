import asyncio
import os

import pytest

import tues

from conftest import PASSWORD, USER


def run(coro):
    return asyncio.run(coro)


async def connect(sshd, **overrides):
    return await tues.AsyncSession.connect(
        f"{USER}@{sshd.host}", **sshd.connect_kwargs(**overrides)
    )


def test_run_and_properties(sshd):
    async def main():
        async with await connect(sshd) as s:
            assert s.user == USER and s.port == sshd.port and not s.closed
            out = await s.run("echo hello; exit 2")
            assert out.stdout == b"hello\n" and out.returncode == 2
            out = await s.run(["id", "-un"], run_as="root", check=True)
            assert out.stdout == b"root\n"
            with pytest.raises(tues.TuesError):
                await s.run("false", check=True)
        assert s.closed

    run(main())


def test_concurrent_sudo_commands(sshd):
    async def main():
        calls = []

        def prompter(req):
            calls.append(req.kind)
            return PASSWORD

        async with await connect(sshd, password=None, password_manager=prompter) as s:
            outs = await asyncio.gather(*(s.run(f"echo {i}", run_as="root") for i in range(10)))
            assert [o.stdout for o in outs] == [f"{i}\n".encode() for i in range(10)]
        # Concurrent first-use may prompt more than once, but never per command.
        assert 1 <= len(calls) < 10

    run(main())


def test_binary_input_through_sudo(sshd):
    async def main():
        async with await connect(sshd) as s:
            data = os.urandom(200_000) + b"[tues-ok-abc]"
            out = await s.run("cat", input=data, run_as="root", check=True)
            assert out.stdout == data

    run(main())


def test_spawn_streams(sshd):
    async def main():
        async with await connect(sshd) as s:
            child = await s.spawn("cat")
            assert await child.stdin.write(b"a\nb\n") == 4
            await child.stdin.close()
            assert await child.stdout.readline() == b"a\n"
            assert await child.stdout.read_exact(1) == b"b"
            assert await child.stdout.read() == b"\n"
            status = await child.wait()
            assert status.code == 0
            assert child.poll().success

    run(main())


def test_communicate_and_kill(sshd):
    async def main():
        async with await connect(sshd) as s:
            child = await s.spawn("tr a-z A-Z", run_as="root")
            out, err = await child.communicate(b"shout")
            assert out == b"SHOUT" and err == b""

            child = await s.spawn("sleep 30")
            assert child.poll() is None
            child.kill()
            status = await child.wait()
            assert status.signal == "KILL"

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
                assert f.closed
                assert (await sftp.stat(path)).size == 4
                assert any(e.name == "pytest-async.txt" for e in await sftp.listdir("/tmp"))
                await sftp.mkdir("/tmp/pytest-adir")
                assert (await sftp.stat("/tmp/pytest-adir")).is_dir
                await sftp.rmdir("/tmp/pytest-adir")
                await sftp.rename(path, path + ".2")
                assert not await sftp.exists(path)
                await sftp.remove(path + ".2")
                with pytest.raises(tues.SftpError):
                    await sftp.read(path)

    run(main())


def test_errors(sshd):
    async def main():
        with pytest.raises(tues.ConnectError):
            await tues.AsyncSession.connect(
                "127.0.0.1", **sshd.connect_kwargs(port=1, connect_timeout=2)
            )
        with pytest.raises(tues.AuthError):
            await connect(sshd, identity_files=[], password="wrong")
        with pytest.raises(ValueError):
            await tues.AsyncSession.connect("127.0.0.1", bogus=1, **sshd.connect_kwargs())

    run(main())
