#!/usr/bin/env python3
# coding: utf-8

import click as _click


@_click.command()
@_click.argument("hosts", nargs=-1)
def cli(hosts):
    for host in hosts:
        _click.echo(host)


def main():
    cli() # pylint: disable=no-value-for-parameter
