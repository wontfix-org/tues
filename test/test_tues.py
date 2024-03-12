# coding: utf-8

import os as _os
import io as _io
import tempfile as _tempfile
import time as _time
import threading as _threading

import tues as _tues

import pytest as _pytest


user_param = _pytest.mark.parametrize("user", [None, "nobody"])
pty_param = _pytest.mark.parametrize("pty", [True, False])
text_param = _pytest.mark.parametrize("text", [True, False])
encoding_param = _pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])

def all_params(func):
    func = user_param(func)
    func = pty_param(func)
    func = text_param(func)
    return func


@_pytest.fixture(autouse=True)
def patch_password_manager(monkeypatch):
    def _prompt(_message):
        assert False, "Should not prompt interactively"

    monkeypatch.setattr("tues._PM._prompt", _prompt)


def assert_output(actual_stdout, wanted_stdout, actual_stderr, wanted_stderr, pty=False, text=False, encoding="utf-8"):
    # In pty mode, the server will send "\r\n" instead of just plain "\n", and since
    # we do support writing to BytesIO objects, too, we need to take care to do the
    # replacements with the correct datatype
    if isinstance(actual_stdout, bytes):
        target = b"\r"
        replacement = b""
    else:
        target = "\r"
        replacement = ""

    if pty:
        actual_stdout = actual_stdout.replace(target, replacement)
        if actual_stderr:
            actual_stderr = actual_stderr.replace(target, replacement)

    if not text:
        wanted_stdout = wanted_stdout.encode(encoding)
        wanted_stderr = wanted_stderr.encode(encoding)

    if pty:
        assert actual_stderr is None
        assert wanted_stdout + wanted_stderr == actual_stdout
    else:
        assert actual_stdout == wanted_stdout
        assert actual_stderr == wanted_stderr


@pty_param
@text_param
def test_tues_run(host, username, pty, text):
    run = _tues.run(host, "whoami", login_user=username, capture_output=True, pty=pty, text=text)
    out = run.stdout
    if not text:
        out = out.decode()
    assert out.strip() == username


def test_tues_run_with_cmdlist(host):
    run = _tues.run(host, ["echo", "-n", "test"], capture_output=True, text=True)
    assert "test" in run.stdout


@pty_param
@text_param
def test_tues_run_as_user(host, pm, pty, text):
    user = "nobody"
    run = _tues.run(host, "id", capture_output=True, user=user, pty=pty, text=text, pm=pm)
    uid = 65534
    assert f"uid={uid}({user})" in run.stdout if text else run.stdout.decode()


@pty_param
@text_param
def test_tues_run_as_user_filters_sudo_output_with_prefix_and_capture(host, pm, pty, text):
    run = _tues.run(
        host,
        "echo foo",
        capture_output=True,
        prefix=True,
        user="nobody",
        pty=pty,
        text=text,
        pm=pm,
    )
    assert_output(
        run.stdout,
        f"[localhost{'/stdout' if not pty else ''}]: foo\n",
        run.stderr,
        "",
        pty=pty,
        text=text,
    )


@pty_param
@text_param
def test_tues_run_as_user_filters_sudo_output_with_prefix(capsys, host, pm, pty, text):
    _run = _tues.run(host, "echo -n foo", prefix=True, user="nobody", pty=pty, text=text, pm=pm)
    captured = capsys.readouterr()
    assert_output(
        captured.out if text else captured.out.encode(),
        f"[localhost{'/stdout' if not pty else ''}]: foo",
        (captured.err if text else captured.err.encode()) if not pty else None,
        "",
        pty,
        text=text, # capsys always returns strings
    )


@user_param
@text_param
@encoding_param
def test_tues_run_with_stdin_filename(host, pm, user, text, encoding, tmp_path):
    f = tmp_path / f"input{encoding}"
    input = "föö"

    f.write_bytes(input.encode(encoding))

    run = _tues.run(
        host,
        "cat",
        stdin=str(f),
        capture_output=True,
        user=user,
        text=text,
        encoding=encoding if text else None,
        pm=pm,
    )

    assert_output(
        run.stdout,
        "föö",
        "" if text else b"",
        "",
        text=text,
        encoding=encoding,
    )


@user_param
@text_param
@encoding_param
def test_tues_run_with_stdin_ioobj(host, pm, user, text, encoding):
    input = "föö"
    if text:
        input = _io.StringIO(input)
    else:
        input = _io.BytesIO(input.encode(encoding))

    run = _tues.run(
        host,
        "cat",
        stdin=input,
        capture_output=True,
        user=user,
        text=text,
        encoding=encoding if text else None,
        pm=pm,
    )

    assert_output(
        run.stdout,
        "föö",
        "" if text else b"",
        "",
        text=text,
        encoding=encoding,
    )


@user_param
@text_param
@encoding_param
def test_tues_run_with_input(host, pm, user, text, encoding):
    wanted = "föö\n"
    if not text:
        wanted = wanted.encode(encoding)

    run = _tues.run(
        host,
        "cat",
        input=wanted,
        capture_output=True,
        user=user,
        text=text,
        encoding=encoding if text else None,
        pm=pm,
    )
    assert_output(
        run.stdout,
        "föö\n",
        "" if text else b"",
        "",
        text=text,
        encoding=encoding,
    )


@all_params
def test_tues_run_with_stdout_and_stderr(host, pm, user, pty, text):
    run = _tues.run(
        host,
        "echo -n test ; echo -n testerr >&2",
        capture_output=True,
        user=user,
        pty=pty,
        text=text,
        pm=pm,
    )
    assert_output(run.stdout, "test", run.stderr, "testerr", pty, text=text)


@all_params
def test_tues_run_with_stdout_and_stderr_and_prefix(host, pm, user, pty, text):
    run = _tues.run(
        host,
        # The `sleep 0.1` is used in order to force the two strings
        # to be delivered to tues in two seperate `write` calls, which
        # is important to test line prefixing
        "echo -n out ; sleep 0.1 ; echo -n err >&2 ; sleep 0.1 ; echo -n out ; sleep 0.1 ; echo -n err >&2",
        prefix=True,
        capture_output=True,
        user=user,
        pty=pty,
        text=text,
        pm=pm,
    )

    if not pty:
        assert_output(
            run.stdout,
            f"[localhost{'/stdout' if not pty else ''}]: outout",
            run.stderr,
            f"[localhost{'/stderr' if not pty else ''}]: errerr",
            pty,
            text=text,
        )
    else:
        wanted = "[localhost]: outerrouterr"
        if not text:
            wanted = wanted.encode("utf-8")
        assert run.stdout == wanted


@pty_param
@user_param
def test_tues_run_with_stdout_stderr_stringio(host, pm, user, pty):
    stdout = _io.StringIO()
    stderr = _io.StringIO()
    _run = _tues.run(
        host,
        "echo -n test ; echo -n testerr >&2",
        stdout=stdout,
        stderr=stderr,
        user=user,
        text=True,
        pty=pty,
        pm=pm,
    )
    assert_output(
        stdout.getvalue(),
        "test",
        None if pty else stderr.getvalue(),
        "testerr",
        pty,
        text=True,
    )


@pty_param
@user_param
def test_tues_run_with_stdout_stderr_bytesio(host, pm, user, pty):
    stdout = _io.BytesIO()
    stderr = _io.BytesIO()
    _run = _tues.run(
        host,
        "echo -n test ; echo -n testerr >&2",
        stdout=stdout,
        stderr=stderr,
        user=user,
        pty=pty,
        pm=pm,
    )
    assert_output(
        stdout.getvalue(),
        "test",
        None if pty else stderr.getvalue(),
        "testerr",
        pty,
        text=False,
    )


@user_param
@text_param
@pty_param
def test_tues_run_with_files(host, pm, user, text, pty):
    stdout_file = _tempfile.NamedTemporaryFile()
    stdout_file.write(b"test")
    stdout_file.flush()
    # so "nobody" can read the files
    _os.chmod(stdout_file.name, 0o444)

    stderr_file = _tempfile.NamedTemporaryFile()
    stderr_file.write(b"testerr")
    stderr_file.flush()
    _os.chmod(stderr_file.name, 0o444)

    run = _tues.run(
        host,
        "cat $TUES_FILE1 ; cat $TUES_FILE2 >&2",
        user=user,
        capture_output=True,
        files=[
            stdout_file.name,
            stderr_file.name,
        ],
        pty=pty,
        text=text,
        cwd="/tmp",
        pm=pm,
    )
    assert_output(run.stdout, "test", run.stderr, "testerr", pty=pty, text=text)


@user_param
@text_param
@pty_param
def test_tues_run_with_check(host, pm, user, text, pty):
    with _pytest.raises(_tues.TuesTaskError):
        _tues.run(host, "false", user=user, text=text, pty=pty, check=True, pm=pm)


@user_param
def test_tues_run_with_stdout_pipe(capsys, host, pm, user):
    run = _tues.run(
        host,
        "echo -n out ; echo -n err >&2",
        stdout=_tues.PIPE,
        text=True,
        user=user,
        check=True,
        pm=pm,
    )
    captured = capsys.readouterr()
    assert run.stdout == "out"
    assert captured.err == "err"


@user_param
def test_tues_run_with_stderr_pipe(capsys, host, pm, user):
    run = _tues.run(
        host,
        "echo -n out ; echo -n err >&2",
        stderr=_tues.PIPE,
        text=True,
        user=user,
        check=True,
        pm=pm,
    )
    captured = capsys.readouterr()
    assert run.stderr == "err"
    assert captured.out == "out"


@user_param
def test_tues_run_with_stderr_stdout(capsys, host, pm, user):
    run = _tues.run(
        host,
        "echo -n out ; echo -n err >&2",
        stderr=_tues.STDOUT,
        text=True,
        user=user,
        check=True,
        pm=pm,
    )
    captured = capsys.readouterr()
    assert run.stderr is None
    assert captured.out in ("outerr", "errout")


@user_param
def test_tues_run_with_stdout_devnull(capsys, host, pm, user):
    run = _tues.run(
        host,
        "echo -n out ; echo -n err >&2",
        stdout=_tues.DEVNULL,
        stderr=_tues.PIPE,
        text=True,
        user=user,
        check=True,
        pm=pm,
    )
    captured = capsys.readouterr()
    assert run.stdout is None
    assert run.stderr == "err"
    assert captured.out == ""


@user_param
def test_tues_run_with_stderr_devnull(capsys, host, pm, user):
    run = _tues.run(
        host,
        "echo -n out ; echo -n err >&2",
        stdout=_tues.PIPE,
        stderr=_tues.DEVNULL,
        text=True,
        user=user,
        check=True,
        pm=pm,
    )
    captured = capsys.readouterr()
    assert run.stderr is None
    assert run.stdout == "out"
    assert captured.err == ""


@user_param
@text_param
def test_tues_run_with_env(host, pm, user, text):
    env = {"VAR1": "foo", "VAR2": "föö"}
    run = _tues.run(
        host,
        "env",
        capture_output=True,
        text=text,
        user=user,
        check=True,
        env=env,
        pm=pm,
    )
    out = run.stdout
    if not text:
        out = out.decode("utf-8")
    res = dict(line.split("=", 1) for line in out.splitlines())
    for var, value in env.items():
        assert res[var] == value

    assert not run.stderr


@user_param
@pty_param
@encoding_param
def test_tues_run_with_encoding(host, pm, user, pty, encoding):
    run = _tues.run(
        host,
        f"echo -n 'föö' | iconv -t {encoding}",
        check=True,
        user=user,
        pty=pty,
        encoding=encoding,
        capture_output=True,
        pm=pm,
    )
    assert_output(run.stdout, "föö", run.stderr, "", pty=pty, text=True)


@user_param
def test_tues_run_with_cwd(host, pm, user):
    run = _tues.run(host, "pwd", cwd="/", user=user, capture_output=True, text=True, pm=pm)
    assert run.stdout.strip() == "/"


def test_tues_run_multi_host(host):
    runs = _tues.run(
        [host, host],
        "echo -n test",
        capture_output=True,
        text=True,
        pool_size=2,
    )
    assert ["test", "test"] == [_.stdout for _ in runs]


@_pytest.mark.skipif(_os.environ.get("CI"), reason="Probably not stable")
@_pytest.mark.parametrize("pool_size", [1, 2])
def test_tues_run_cancel(host, pool_size):
    def background():
        _time.sleep(1)
        _os.kill(0, 2)

    thread = _threading.Thread(target=background)
    thread.start()
    with _pytest.raises(_tues.TuesError) as exc_info:
        _tues.run(
            [host, host],
            "sleep 5",
            capture_output=True,
            text=True,
            pool_size=pool_size,
        )
    thread.join()

    if pool_size > 1:
        assert isinstance(exc_info.value, _tues.TuesErrorGroup)
    else:
        assert isinstance(exc_info.value, _tues.TuesTaskError)


@user_param
@pty_param
@text_param
@encoding_param
def test_tues_run_with_output_dir(host, pm, user, pty, tmp_path, text, encoding):
    _tues.run(
        host,
        f"echo -n 'föö' | iconv -t {encoding}",
        user=user,
        output_dir=str(tmp_path),
        text=text,
        pty=pty,
        encoding=encoding if text else None,
        pm=pm,
    )
    output = (tmp_path / "localhost.log").read_text(encoding=encoding)
    assert output.strip() == "föö"


def test_provider():
    assert _tues.provider("cl", ["foo"]) == ["foo"]


def test_provider_not_found():
    with _pytest.raises(_tues.TuesLookupError):
        _tues.provider("does-not-exist", [])


def test_script_not_found():
    with _pytest.raises(_tues.TuesScriptNotFoundError):
        _tues.Script("does-not-exist").run("localhost")


def test_script(tmp_path, host):
    sf = tmp_path / "myscript"

    sf.write_text("#!/usr/bin/env bash\necho -n foo")
    sf.chmod(0o777)

    script = _tues.Script("myscript", paths=[str(tmp_path)])
    run = script.run(host, capture_output=True, text=True)
    assert run.stdout == "foo"


def test_script_with_cmdlist(tmp_path, host):
    sf = tmp_path / "myscript"

    sf.write_text("#!/usr/bin/env bash\necho \"$@\" foo")
    sf.chmod(0o777)

    script = _tues.Script(["myscript", "-n"], paths=[str(tmp_path)])
    run = script.run(host, capture_output=True, text=True)
    assert run.stdout == "foo"


def test_script_parsing(tmp_path, host, pm):
    sf = tmp_path / "myscript"
    hostname, port = host
    hoststr = f"{hostname}:{port}"

    sf.write_text(
        "#!/usr/bin/env bash\n"
        "# tues-args = {\"user\": \"nobody\"}\n"
        "# tues-provider = \"cl\"\n"
        f"# tues-provider-args = [\"{hoststr}\"]\n"
        "echo \"$@\" foo"
    )
    sf.chmod(0o777)

    script = _tues.Script(["myscript", "-n"], paths=[str(tmp_path)])
    assert (
        script.run_args == {"user": "nobody"}
        and script.provider == "cl"
        and script.provider_args == [hoststr]
    )

    run = script.run(capture_output=True, text=True, pm=pm)[0]
    assert run.stdout == "foo"


def test_taskerror_handles(host):
    with _pytest.raises(_tues.TuesTaskError) as e:
        _tues.run(host, "echo -n out ; echo -n err >&2 ; false", check=True, capture_output=True, text=True, cwd="/tmp")

    assert e.value.stdout == "out" and e.value.stderr == "err"


def test_output_dir_strategy_abort(tmp_path, host):
    o = (tmp_path / "output")
    o.mkdir()
    with _pytest.raises(_tues.TuesOutputDirExists):
        _tues.run(host, "id", output_dir=str(o), output_dir_strategy=_tues.DIR_ABORT)


def test_output_dir_strategy_ignore(tmp_path, host):
    o = (tmp_path / "output")
    o.mkdir()
    (o / "foo.log").touch()
    _tues.run(host, "id", output_dir=str(o), output_dir_strategy=_tues.DIR_IGNORE)
    assert (o / "localhost.log").exists() and (o / "foo.log").exists()


def test_output_dir_strategy_wipe(tmp_path, host):
    o = (tmp_path / "output")
    o.mkdir()
    (o / "foo").touch()
    (o / "foo.log").touch()
    _tues.run(host, "id", output_dir=str(o), output_dir_strategy=_tues.DIR_WIPE)
    assert set([_.name for _ in o.iterdir()]) == set(["localhost.log", "foo"])


def test_output_dir_strategy_rotate(tmp_path, host):
    o = (tmp_path / "output")
    o.mkdir()
    (o / "old_dir" ).touch()
    (tmp_path / "output.1").mkdir()
    (tmp_path / "output.unrelated").mkdir()
    (tmp_path / "output.unrelatedfile").touch()
    _tues.run(host, "id", output_dir=str(o), output_dir_strategy=_tues.DIR_ROTATE)
    assert (o / "localhost.log").exists() and (tmp_path / "output.2" / "old_dir").exists()


def test_tues_error_group(host):
    with _pytest.raises(_tues.TuesErrorGroup) as e:
        _tues.run([host, ("localhost", 9)], "id", pool_size=2, capture_output=True)
    assert len(e.value.exceptions) == 1 and len(e.value.results) == 1
