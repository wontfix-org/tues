#!/usr/bin/env python3
# coding: utf-8
# pylint: disable=c-extension-no-member

from __future__ import print_function, absolute_import

import os as _os
import sys as _sys
import functools as _ft
import asyncio as _asyncio
import logging as _logging

import click as _click
import pkg_resources as _pr

import tues as _tues # pylint: disable=import-self


def get_hosts(provider, args):
    try:
        return _tues.provider(provider, args)
    except _tues.TuesError as e:
        _click.echo(e.args[0])
        _sys.exit(2)


@_click.command(context_settings={"ignore_unknown_options": True, "auto_envvar_prefix": "TUES"})
@_click.option("-u", "--user", help="The user to run the command as")
@_click.option("-l", "--login-user", help="The user to login with")
@_click.option("-n", "--pool-size", default=1, help="The number of concurrent tasks")
@_click.option("-A", "--align-prefix", default=False, is_flag=True, help="Align all prefixes so output starts in the same column for all hosts")
@_click.option("--pty/--no-pty", default=True, help="Don't allocate pseudo tty")
@_click.option("--universal-newlines/--no-universal-newlines", default=False, help="When using a pseudo tty, should \\n be converted to \\r\\n?")
@_click.option("-c", "--check/--no-check", "check", is_flag=True, default=True, help="Do not abort execution on errors, only issue warnings")
@_click.option("-P/-N", "--prefix/--no-prefix", default=True, is_flag=True, help="Don't output a prefix at the start of remote output lines")
@_click.option("-d", "--output-dir", help="Store stdout into one file per host", type=_click.Path(dir_okay=True, file_okay=False, exists=True, writable=True))
@_click.option("-s", "--script", is_flag=True, default=False, help="Consider <cmd> to be a local script to upload to and execute on the remote machines")
@_click.option("-p", "--parallel", is_flag=True, default=False, help="Deprecated: Will set `-n 10` to cause parallel execution of tasks")
@_click.option("-w", "--wait", is_flag=True, default=False, help="Wait after execution on every host before moving on")
@_click.option("-v/-q", "--verbose/--quiet", default=None, help="Do not output additional information like start/finish indicators")
@_click.option(
    "-S",
    "--output-dir-strategy",
    default=_tues.DIR_IGNORE,
    type=_click.Choice([_tues.DIR_IGNORE, _tues.DIR_ABORT, _tues.DIR_WIPE, _tues.DIR_ROTATE]),
    help="How to handle an existing output directory",
)
@_click.version_option(_pr.get_distribution("tues").version) # pylint: disable=c-extension-no-member
@_click.option(
    "-f",
    "--file",
    "files",
    multiple=True,
    default=[],
    type=_click.Path(readable=True),
    help="File(s) to copy to the remove server. Paths are available on the remote as $TUES_FILE1 etc.",
)
@_click.option("--path", "path", multiple=True, type=_click.Path(), default=_tues.DEFAULT_PATH)
@_click.argument("cmd", nargs=1, type=str)
@_click.argument("provider", nargs=1, type=str, required=False)
@_click.argument("provider_args", nargs=-1, type=_click.UNPROCESSED, required=False)
@_click.pass_context
def cli(
    ctx,
    user,
    login_user,
    pool_size,
    pty,
    check,
    verbose,
    files,
    cmd,
    provider,
    provider_args,
    prefix,
    output_dir,
    align_prefix,
    script,
    path,
    parallel,
    wait,
    output_dir_strategy,
    universal_newlines,
): # pylint: disable=too-many-locals
    if verbose is None:
        if output_dir:
            verbose = True
        else:
            verbose = False

    if output_dir:
        prefix = False
        ctx.set_parameter_source("prefix", ctx.get_parameter_source("output_dir"))

    if parallel and pool_size == 1:
        pool_size = 10
        # Since this is a compat option that influence a value of another option
        # we need to "fix" the parameter source in order for the overrides detection
        # down in the `if script` branch to work properly
        ctx.set_parameter_source("pool_size", ctx.get_parameter_source("parallel"))

    if pool_size > 1 and wait:
        raise _click.UsageError("Unable to run in parallel mode while also waiting after each host")

    def start_host(task):
        if verbose:
            _click.secho(f"Starting {task.host}", bold=True)

    def finish_host(task):
        if verbose:
            _click.secho(f"Finished {task.host}", bold=True)

    try:
        if provider:
            hosts = get_hosts(provider, provider_args)
        else:
            hosts = None

        if wait and hosts:
            last_host = hosts[-1]

            def wait(func):
                def _wait(task):
                    func(task)
                    if task.host != last_host:
                        _click.prompt("Press <ENTER> to continue", default="", show_default=False)
                return _wait

            finish_host = wait(finish_host)

        if script:
            def pick(name, value, default=None):
                if ctx.get_parameter_source(name) == _click.core.ParameterSource.DEFAULT:
                    return default
                else:
                    return value

            # This is list of settings that will "override" settings in a script file only
            # if they have been specified on the command line explicitly, we still prefer
            # the scripts value over the options default value
            overrides = [
                ("user", user),
                ("files", files),
                ("output_dir", output_dir),
                ("pty", pty),
                ("pool_size", pool_size),
                ("check", check),
                ("output_dir_strategy", output_dir_strategy),
                ("login_user", login_user),
                ("universal_newlines", universal_newlines),
            ]

            overrides = {
                k:v for k, v in overrides if ctx.get_parameter_source(k) != _click.core.ParameterSource.DEFAULT
            }

            script = _tues.Script(cmd, paths=path)
            script.run(
                hosts,
                prefix=prefix,
                align_prefix=align_prefix,
                preexec_fn=start_host,
                postexec_fn=finish_host,
                **overrides,
            )
        else:
            _tues.run(
                hosts,
                cmd=cmd,
                user=user,
                prefix=prefix,
                files=files,
                output_dir=output_dir,
                pty=pty,
                pool_size=pool_size,
                check=not check and pool_size == 1,
                align_prefix=align_prefix,
                preexec_fn=start_host,
                postexec_fn=finish_host,
                output_dir_strategy=output_dir_strategy,
                login_user=login_user,
                universal_newlines=universal_newlines,
            )
    except _tues.TuesErrorGroup as e:
        _click.echo(e)
        for exc in e.exceptions:
            _click.echo(exc)
    except _tues.TuesError as e:
        raise _click.ClickException(str(e))


def main():
    cli() # pylint: disable=no-value-for-parameter
