"""The ``tues-provider-fm`` console script."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from tues.provider_fm import cli, hosts, main


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        server = self.server
        assert isinstance(server, Foreman)
        server.requests.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "accept": self.headers.get("Accept"),
                "content_type": self.headers.get("Content-Type"),
            }
        )
        body = server.body if isinstance(server.body, bytes) else json.dumps(server.body).encode()
        self.send_response(server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class Foreman(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.status = 200
        self.body: object = {"results": [{"name": "web01.example"}, {"name": "web02.example"}]}
        self.requests: list[dict[str, str | None]] = []

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self.server_address[1]


@pytest.fixture
def foreman():
    server = Foreman()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _search(foreman: Foreman) -> str:
    from urllib.parse import parse_qs, urlsplit

    hit = foreman.requests[-1]
    path = hit["path"]
    assert path is not None
    query = parse_qs(urlsplit(path).query)
    assert urlsplit(path).path == "/api/v2/hosts"
    assert query["per_page"] == ["10000"]
    assert query["thin"] == ["1"]
    assert hit["accept"] == "application/json"
    assert hit["content_type"] == "application/json"
    return query["search"][0]


def test_hosts_reads_results_and_legacy_list(foreman: Foreman):
    assert hosts(foreman.url, "name ~ web") == ["web01.example", "web02.example"]
    assert _search(foreman) == "name ~ web"

    foreman.body = [{"host": {"name": "old.example"}}]
    assert hosts(foreman.url) == ["old.example"]
    path = foreman.requests[-1]["path"]
    assert path is not None and "search=" not in path


def test_hosts_sends_basic_auth_from_the_url(foreman: Foreman):
    url = "http://user:s3cret@127.0.0.1:%d" % foreman.server_address[1]
    assert hosts(url, "name = web01") == ["web01.example", "web02.example"]
    token = base64.b64encode(b"user:s3cret").decode()
    assert foreman.requests[-1]["authorization"] == "Basic " + token


def test_hosts_reports_a_failed_call(foreman: Foreman):
    foreman.status = 401
    foreman.body = b"denied"
    with pytest.raises(Exception, match=r"Could not get host list, call returned\(401\): 'denied'"):
        hosts(foreman.url, "name = web")


def test_cli_expression_class_and_both(foreman: Foreman, monkeypatch):
    monkeypatch.delenv("FOREMAN_URL", raising=False)
    runner = CliRunner()

    result = runner.invoke(cli, ["-f", foreman.url, "name ~ web"])
    assert result.exit_code == 0
    assert result.output == "web01.example\nweb02.example\n"
    assert _search(foreman) == "name ~ web"

    result = runner.invoke(cli, ["-f", foreman.url, "-c", "role::web"])
    assert result.exit_code == 0
    assert _search(foreman) == 'puppetclass = "role::web"'

    result = runner.invoke(cli, ["-f", foreman.url, "-c", "role::*"])
    assert result.exit_code == 0
    assert _search(foreman) == 'puppetclass ~ "role::*"'

    result = runner.invoke(cli, ["-f", foreman.url, "-c", "role::web", "facts.os = Debian"])
    assert result.exit_code == 0
    assert _search(foreman) == '(puppetclass = "role::web") and (facts.os = Debian)'


def test_cli_uses_foreman_url_from_the_environment(foreman: Foreman, monkeypatch):
    monkeypatch.setenv("FOREMAN_URL", foreman.url)
    result = CliRunner().invoke(cli, ["name = web01"])
    assert result.exit_code == 0
    assert result.output == "web01.example\nweb02.example\n"
    assert _search(foreman) == "name = web01"


def test_cli_requires_a_query_and_a_url(monkeypatch):
    monkeypatch.delenv("FOREMAN_URL", raising=False)
    runner = CliRunner()

    result = runner.invoke(cli, ["-f", "http://foreman.example"])
    assert result.exit_code == 1
    assert "No query specified" in result.output

    result = runner.invoke(cli, ["name = web"])
    assert result.exit_code == 2
    assert "foreman-url" in result.output


def test_help_describes_the_search():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Foreman search" in result.output
    assert "--foreman-url" in result.output
    assert "--class" in result.output
    assert "EXPRESSION" in result.output
    assert "globbing" in result.output


def test_main_prints_hosts(foreman: Foreman, monkeypatch, capsys):
    monkeypatch.setenv("FOREMAN_URL", foreman.url)
    monkeypatch.setattr("sys.argv", ["tues-provider-fm", "name ~ web"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert capsys.readouterr().out == "web01.example\nweb02.example\n"
