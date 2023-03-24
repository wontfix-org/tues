# tues

Run any remote command via ssh and sudo

## Install

 * Run `pip install tues`

## Getting Started


### As a commandline tool

Tues expects a command to execute, followed by the name of a hostname provider and its arguments.

Run `id` on localhost as user root, using the IPv4/IPv6 adresses is not required, just passing localhost three times would work as well, you are only prompted for a password once and the original sudo prompt is stripped from the output.
The login user will be derived from your ssh configuration (or if you really need to, manually with the `--login-user`/`-l` switch), while the user specified by `-u` is the user to run the command as on the remote host.

```
$ tues -u root id cl localhost 127.0.0.1 [::1]
[::1/stdout]: uid=0(root) gid=0(root) groups=0(root)
[127.0.0.1/stdout]: uid=0(root) gid=0(root) groups=0(root)
[localhost/stdout]: uid=0(root) gid=0(root) groups=0(root)
$
```

There are switches to send output to a directory, one file per host (`-d <dir>`), run on multiple hosts at a time `-n <num>`, upload files to the remote host before executing the command `-f <file>` and also a mechanic to treat the executed command as a local script in `TUES_PATH` that needs to be uploaded to the host first.

```
$ echo 'ls "$@"' > myls
$ chmod +x myls
$ echo foo > myfile
$ mkdir output
$ tues --path=. -d output -f myfile -s 'myls -la $TUES_FILE1' localhost 127.0.0.1
Starting localhost
Finished localhost
Starting 127.0.0.1
Finished 127.0.0.1
$ cat output/*
[127.0.0.1/stdout]: -rw-rw-r-- 1 mvb mvb 4 Jul 26 12:59 myfile
[localhost/stdout]: -rw-rw-r-- 1 mvb mvb 4 Jul 26 12:59 myfile
$
```

Running with an output directory automatically enables verbose mode to show at least a bit of progress, while disabling prefixing because with one file per host, you probably won't need the prefix.
For this simple example, we set `TUES_PATH` to `.` on the commandline, by default, scripts should be placed in `$HOME/.config/tues/scripts/`.

### From Python

When running from python, tues will behave mostly the same, with slight differences where it makes sense. In Python mode, we need to explicitly request output prefixing for example:

```python
import tues

tues.run(
    ["localhost", "127.0.0.1", "[::1]"],
    "id",
    user="root",
    prefix=True,
)
```

```$ python3 tues.py
Your remote sudo password:
[localhost/stdout]: uid=0(root) gid=0(root) groups=0(root)
[127.0.0.1/stdout]: uid=0(root) gid=0(root) groups=0(root)
[::1/stdout]: uid=0(root) gid=0(root) groups=0(root)
$
```

Output is usually kept "clean" (except for the sudo output of course) for later processing:

```python
import sys

import tues

runs = tues.run(
    ["localhost", "127.0.0.1", "[::1]"],
    "id",
    user="root",
    text=True,
    capture_output=True,
)

for run in runs:
    sys.stdout.write(run.stdout)
```

The interface tries to mimic `subprocess.run` where possible, the fact that it can run a command on multiple hosts will always require details to be handle diffrently though.


```
$ python3 tues.py
Your remote sudo password:
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
$
```

For a detailed description of the `run` Arguments, please [check out the docstring](https://github.com/wontfix-org/tues/blob/master/tues/__init__.py#L800) for now, while I procastinate on creating proper docs. :-(

## Providers

### File

The `file` provider assumes all files passed on the commandline contain one host per line.

### Commandline

The `cl` provider assumes all arguments passed on the commandline are hosts to connect to.

### Foreman

Execute on all hosts matching a certain foreman expression.

```
export FOREMAN_URL="https://user:password@foreman.domain/"
tues "ls" fm "class = my::class"
```

### Custom Providers

New providers may be added by putting a new executable with a name like "tues-provider-<name>"
on your PATH. A provider is expected to return a newline seperated list of hosts.

If the provider returns with an error, the output is considered to be an error message and/or
it's help output. If '--help' is passed through to the provider the output is displayed no matter
what exit code is used.
