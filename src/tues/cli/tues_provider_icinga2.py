#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

import urllib3 as _urllib3

_urllib3.disable_warnings()

import click as _click
import icinga2api.client as _icinga2


@_click.command()
@_click.option("--url", envvar="ICINGA_API_URL", help="Icinga API URL")
@_click.option("--user", envvar="ICINGA_API_USER", help="Icinga API user")
@_click.option("--pw", envvar="ICINGA_API_PW", help="Icinga API password")
@_click.argument("service_name", required=False)
def cli(url, user, pw, service_name):
    """ Return hostnames for the selected icinga services """
    client = _icinga2.Client(url, user, pw)

    if service_name:
        filters = """ service.state >= 1 && service.name == "{}" """.format(service_name)
    else:
        filters = """ service.state >= 1 """

    for service in client.objects.list(
        "Service",
        attrs=["host_name"],
        filters=filters,
    ):
        print(service["attrs"]["host_name"])


def main():
    cli() # pylint: disable=no-value-for-parameter
