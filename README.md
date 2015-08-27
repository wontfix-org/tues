# tues

Easily run commands on collections of hosts

## Install

 * Clone the repository
 * Run `python setup.py install` or `python setup.py develop` in a virtualenv

## Getting Started

Tues expects a command to execute, followed by the name of a hostname provider and its arguments.

Execute on all hosts in file hostnames.

```
echo "localhost" > hostnames
tues "ls" file hostnames
```

## Providers

### Foreman

Execute on all hosts matching a certain foreman expression.

```
export FOREMAN_URL="https://user:password@foreman.domain/"
tues "ls" fm "class = my::class"
```

### Nagios (via livestatus)

Execute on all hosts with a given service pattern not in state OK

```
export NAGIOS_HOST="nagios"
export NAGIOS_LIVESTATUS_SOCKET="/var/lib/nagios3/rw/livestatus"
tues -u root "puppet agent run --test" nagios puppet_status
```

The values of the environment variables above are the defaults, you do not need to specify them if they match your setup.

### Custom Providers

New providers may be added by putting a new executable with a name like "tues-provider-<name>"
on your PATH. A provider is expected to return a newline seperated list of hosts.

If the provider returns with an error, the output is considered to be an error message and/or
it's help output. If '--help' is passed through to the provider the output is displayed no matter
what exit code is used.
