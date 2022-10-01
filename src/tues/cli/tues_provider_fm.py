#!/usr/bin/env python3

import functools as _ft

import click as _click
import requests as _requests


def hosts(url, query=None):
    params = {"per_page": 10000, "thin": 1}
    if query is not None:
        params["search"] = query

    get = _ft.partial(
        _requests.get,
        params=params,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    response = get("%s/api/v2/hosts" % (url,))

    if response.status_code != 200:
        raise Exception("Could not get host list, call returned(%r): %r" % (response.status_code, response.text))

    hosts = response.json()
    if isinstance(hosts, dict) and "results" in hosts:
        return [host["name"] for host in hosts["results"]]

    return [host["host"]["name"] for host in hosts]


@_click.command()
@_click.option("-f", "--foreman-url", required=True, envvar="FOREMAN_URL")
@_click.argument("expression")
def cli(foreman_url, expression):
    for host in hosts(foreman_url, expression):
        _click.echo(host)


def main():
    cli() # pylint: disable=no-value-for-parameter
