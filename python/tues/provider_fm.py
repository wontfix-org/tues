"""Tues provider that selects hosts via Foreman search

The search query can be provided in the free-form EXPRESSION parameter or as a class name or pattern
passed to the -c/--class option. When both variants are combined, only hosts that match both
criteria are returned.
"""

from __future__ import annotations

import functools

import click
import requests


def hosts(url: str, query: str | None = None) -> list[str]:
    """Return host names from Foreman's ``/api/v2/hosts`` for ``query``.

    ``query`` is a Foreman search string. ``None`` lists hosts with no
    search filter. A ``results`` object is the current API; a list of
    ``{"host": ...}`` objects is the older one.
    """
    params: dict[str, object] = {"per_page": 10000, "thin": 1}
    if query is not None:
        params["search"] = query

    get = functools.partial(
        requests.get,
        params=params,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    response = get("%s/api/v2/hosts" % (url,))

    if response.status_code != 200:
        raise Exception(
            "Could not get host list, call returned(%r): %r" % (response.status_code, response.text)
        )

    payload = response.json()
    if isinstance(payload, dict) and "results" in payload:
        return [host["name"] for host in payload["results"]]

    return [host["host"]["name"] for host in payload]


@click.command(help=__doc__)
@click.option("-f", "--foreman-url", required=True, envvar="FOREMAN_URL")
@click.option(
    "-c",
    "--class",
    "class_",
    help="Select hosts with the given Puppet class. Use * for globbing.",
)
@click.argument("expression", required=False)
def cli(foreman_url: str, expression: str | None, class_: str | None) -> None:
    if class_:
        op = "~" if "*" in class_ else "="
        class_query = f'puppetclass {op} "{class_}"'

        if expression:
            expression = f"({class_query}) and ({expression})"
        else:
            expression = class_query
    elif expression is None:
        raise click.ClickException("No query specified")

    for host in hosts(foreman_url, expression):
        click.echo(host)


def main() -> None:
    cli()
