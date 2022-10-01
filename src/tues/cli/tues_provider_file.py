#!/usr/bin/env python3
# coding: utf-8

import click as _click


@_click.command()
@_click.argument("files", nargs=-1, type=_click.Path(readable=True))
def cli(files):
    for f in files:
        with open(f, "rt") as f:
            for line in f:
                # Don't use echo(line, nl=False), last record might not have a trailing newline
                _click.echo(line.strip())


def main():
    cli() # pylint: disable=no-value-for-parameter
