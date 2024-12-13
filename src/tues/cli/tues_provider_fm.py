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
@_click.option("-c", "--class", "class_", help="Select hosts with the given Puppet class. Use * for globbing.")
@_click.argument("expression", required=False)
def cli(foreman_url, expression, class_):
    if class_:
        op = "~" if "*" in class_ else "="
        class_query = f"puppetclass {op} \"{class_}\""

        if expression:
            expression = f"({class_query}) and ({expression})"
        else:
            expression = class_query
    elif not expression:
        raise _click.ClickException("No query specified")

    for host in hosts(foreman_url, expression):
        _click.echo(host)


def main():
    cli() # pylint: disable=no-value-for-parameter
