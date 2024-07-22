import click.testing as _ct
import pytest as _pytest

import tues as _tues
import tues.cli.tues as _cli


@_pytest.fixture()
def tues():
    def _tues_runner(*args, _exit_code=0, **kwargs):
        kwargs.setdefault("catch_exceptions", False)
        result = _ct.CliRunner().invoke(_cli.cli, *args, **kwargs)
        if _exit_code is not None:
            assert result.exit_code == _exit_code
        return result

    return _tues_runner


def test_cli(tues):
    result = tues(["echo foo", "cl", "localhost"])
    assert result.output == "[localhost]: foo\n"


def test_cli_debug(tues):
    with _pytest.raises(_tues.TuesTaskError) as e:
        result = tues(["--debug", "echo foo", "cl", "localhosttt"], _exit_code=1)
