# ssh_config coverage

What OpenSSH 10.0 accepts and what tues does with it. Difficulty is the
cost of a faithful behavior: **1** easy, **2** medium, **3** hard. Fit is
how much the keyword matters to a library that fans out commands, compared
with an interactive `ssh` client.

`Status` is the implementation tracker. Update it in the same change that
implements the keyword.

| Status | Meaning |
|---|---|
| done | Parsed and applied |
| not started | Not applied |
| blocked | Waiting on another keyword before it can do anything |

Precedence is destination string, then the builder, then `ssh_config`, then
defaults. The first obtained value wins, except `IdentityFile` and `SetEnv`,
which accumulate. A `Match` other than `all` is skipped, so settings that
live only inside it never apply. Unknown directives are kept on
`HostParams::unknown` and otherwise ignored.

## Implemented

| Setting | Status | Notes |
|---|---|---|
| `Host`, `Include`, `Match all` | done | Other `Match` criteria are not started (see below). |
| `HostName`, `User`, `Port` | done | |
| `IdentityFile`, `IdentitiesOnly` | done | Identity files accumulate. |
| `ProxyJump` | done | |
| `StrictHostKeyChecking` | done | `ask` is stored as strict. tues does not prompt. |
| `UserKnownHostsFile`, `GlobalKnownHostsFile` | done | User files win. A changed key in a user file is final. `GlobalKnownHostsFile none` is an empty list. New keys are written only to the first user file. |
| `ConnectTimeout` | done | |
| `ServerAliveInterval`, `ServerAliveCountMax` | done | |
| `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms` | done | `+`, `-`, and `^` work. Host certificate names are offered as certificates. Unknown names are skipped. |
| `RekeyLimit` | done | Clamped to russh's 1 GiB byte cap. `none` and `default` stay at russh's defaults. |
| `Compression` | done | |
| `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication` | done | |
| `RequestTTY` | done | Simplified: `yes` and `force` request a pty; `no` and `auto` do not. |
| `ForwardAgent` | not started | Parsed, then ignored. See Medium fit. |

## High fit

These change whether a real `~/.ssh/config` connects, authenticates, or stays
up. A fan-out runner hits them as often as an interactive client does.

| Setting | Difficulty | Status | Why it belongs here |
|---|---|---|---|
| `BatchMode` | 1 | done | `yes` refuses a password manager that would prompt, including sudo. A password the manager already has is still used. |
| `ConnectionAttempts` | 1 | done | Retries the TCP connect, one second apart. Authentication is not retried. `0` is rejected. The default is 1. |
| `PreferredAuthentications` | 1 | done | Reorders `publickey`, `password`, and `keyboard-interactive`. `gssapi-with-mic` and `hostbased` are skipped. Unset keeps publickey, then password, then keyboard-interactive. |
| `SetEnv` | 1 | not started | `Channel::set_env` before exec. Literal `NAME=value` from the config, applied to every command on that host. |
| `TCPKeepAlive` | 1 | not started | `SO_KEEPALIVE` on the socket. Complements `ServerAliveInterval` for half-open connections. |
| `CertificateFile` | 2 | not started | `authenticate_openssh_cert` exists. The work is pairing each certificate with its key and honoring `IdentitiesOnly`. Cert fleets put this in config. |
| `IdentityAgent` | 2 | not started | Point the agent client at a socket other than `SSH_AUTH_SOCK`, or `none` to disable it. Per-host agents are normal in configs. |
| `ProxyCommand` | 2 | not started | `connect_stream` can take the stdio of a child process. `%` tokens, stderr, and the process lifetime are ours. Many bastions still use this instead of `ProxyJump`. |
| `PubkeyAcceptedAlgorithms` | 2 | not started | This filters the user keys we offer, and for RSA which hash goes into `PrivateKeyWithHashAlg`. It is separate from `HostKeyAlgorithms`, which is the server host key. |
| `Match` `host`, `user`, `localuser`, `originalhost` | 2 | not started | These blocks are dropped today, so every option inside them is invisible. Real configs select hosts this way. |
| `Match` `exec` | 3 | not started | Same gap, plus the criterion runs a local command. That is how some configs choose a bastion or an identity. |

## Medium fit

Useful when someone points tues at the same config `ssh` uses. Each one is a
feature of its own, and several have a sharp edge on a tool that talks to
many hosts.

| Setting | Difficulty | Status | Why it is only a maybe |
|---|---|---|---|
| `NumberOfPasswordPrompts` | 1 | not started | Cap how often the password manager is asked. Matters for unattended runs that should stop after one failure. |
| `NoHostAuthenticationForLocalhost` | 1 | not started | Skip host-key checks for `localhost`. Used by tests and by forwarded local services. |
| `RequiredRSASize` | 1 | not started | Reject an RSA host key shorter than N bits inside the check we already do. |
| `SendEnv` | 2 | not started | Same `set_env` as `SetEnv`, but the value is a glob against the local environment. A pattern of `*` would copy the runner's environment onto every host. |
| `AddressFamily` | 2 | not started | Filter DNS results to IPv4 or IPv6 before connect. Dual-stack hosts in config depend on it. |
| `BindAddress` | 2 | not started | Bind the local socket before connect. Multi-homed runners and source-address firewall rules need it. |
| `BindInterface` | 2 | not started | Bind to a named interface (`SO_BINDTODEVICE` on Linux). Same job as `BindAddress`, less portable. |
| `ForwardAgent` | 2 | not started | Parsed, unused. The request is one call; the server then opens a channel that has to be relayed to the local agent. Many configs set this globally, so turning it on means every tues target receives the agent. |
| `KnownHostsCommand` | 2 | not started | Run a command whose stdout is extra `known_hosts` lines. Used for generated or fetched host keys. |
| `ChannelTimeout` | 2 | not started | Close an idle channel of a given type. Useful for a session stuck after the remote command dies. |
| `LocalForward`, `RemoteForward` | 2 | not started | russh can open `direct-tcpip` and request `tcpip-forward`. tues would own the local listener. A command runner rarely needs this; a session you keep open and then tunnel through does. |
| `ClearAllForwardings` | 1 | blocked | Policy around forwards. Nothing to clear until `LocalForward` and `RemoteForward` exist. |
| `ExitOnForwardFailure` | 1 | blocked | Fail the session when a forward cannot be set up. Nothing to fail until forwards exist. |
| `GatewayPorts` | 1 | blocked | Whether a remote forward listens beyond localhost. Needs `RemoteForward`. |
| `PermitRemoteOpen` | 1 | blocked | Which hosts a remote forward may target. Needs `RemoteForward`. |
| `CanonicalizeHostname`, `CanonicalDomains`, `CanonicalizeFallbackLocal`, `CanonicalizeMaxDots`, `CanonicalizePermittedCNAMEs` | 3 | not started | Rewrite the short name through DNS, then match `Host` blocks against the result. Without it, `Host *.example.com` misses a short name. It has to run before config resolution. |
| `UpdateHostKeys` | 3 | not started | Accept replacement host keys from the server's host-key rotation extension. Long-lived configs rely on it; russh does not handle that extension. |
| `RevokedHostKeys` | 3 | not started | Honor an OpenSSH key-revocation list during host-key check. The file format is its own parser. |

## Low fit

A full interactive client implements these. A library that runs commands can
leave them unread without surprising the people who use tues as `ssh`.

| Setting | Difficulty | Status | Why it can wait |
|---|---|---|---|
| `FingerprintHash`, `VisualHostKey` | 1 | not started | They only change how a host key is displayed. tues reports a changed key by file and line. |
| `LogLevel`, `LogVerbose`, `SyslogFacility` | 1 | not started | OpenSSH's own logging. tues already logs through `tracing`. |
| `StdinNull` | 1 | not started | Force remote stdin from `/dev/null`. Callers already choose that with the `Stdio` API. |
| `RemoteCommand` | 1 | not started | Replace the remote command with one from the config. The command is the tues API; a config value would override `command("id")`. |
| `SessionType` | 2 | not started | Force `default`, `none`, or `subsystem` instead of the exec or SFTP channel the caller opened. |
| `AddKeysToAgent` | 2 | not started | After a successful key login, add that key to the agent, sometimes after a prompt. A library run should not mutate the user's agent. |
| `HashKnownHosts` | 2 | not started | Hash new `known_hosts` lines. Privacy for a laptop's host file, irrelevant to a service account. |
| `CheckHostIP` | 2 | not started | Also record the address next to the hostname. OpenSSH now defaults this off. |
| `IPQoS` | 2 | not started | Set DSCP/`IP_TOS` on the socket. Rare outside interactive latency tuning. |
| `KbdInteractiveDevices` | 2 | not started | Choose PAM or other keyboard-interactive devices. tues treats keyboard-interactive as a password prompt. |
| `LocalCommand`, `PermitLocalCommand` | 2 | not started | Run a local command as a side effect of connecting. A library call should not execute arbitrary local commands because a config line says so. |
| `DynamicForward` | 3 | not started | SOCKS proxy on a local port. russh has no SOCKS. |
| `StreamLocalBindMask`, `StreamLocalBindUnlink` | 3 | not started | Unix-socket forwards. Same class as TCP forwards, with filesystem permissions on top. |
| `CASignatureAlgorithms` | 3 | not started | Which signature algorithms to accept on a host certificate. Useful only once tues trusts `@cert-authority` lines; the known_hosts helper does not. |
| `VerifyHostKeyDNS` | 3 | not started | Look up SSHFP records and require DNSSEC. A separate resolver and trust decision. |
| `GSSAPIAuthentication`, `GSSAPIDelegateCredentials`, `GSSAPIKexAlgorithms`, `GSSAPIKeyExchange`, `GSSAPIRenewalForcesRekey`, `GSSAPITrustDNS` | 3 | not started | russh exposes a GSSAPI trait and no Kerberos. The other five keywords sit idle until that backend exists. Worth it only for a Kerberos estate. |
| `HostbasedAuthentication`, `HostbasedAcceptedAlgorithms`, `EnableSSHKeysign` | 3 | not started | Host-based auth needs a setuid `ssh-keysign` helper and a host key. Unusual for a command runner. |
| `PKCS11Provider` | 3 | not started | Talk to a smart card. The operator is not sitting there to enter a PIN. |
| `SecurityKeyProvider` | 3 | not started | FIDO/U2F keys. Same problem: the key wants a human touch. |
| `ProxyUseFdpass` | 3 | not started | `ProxyCommand` passes the socket back with `SCM_RIGHTS`. Rare even among people who use `ProxyCommand`. |
| `Tag` | 1 | not started | A label for `Match tagged`. It does nothing until that `Match` criterion exists. |

## No fit

These exist so a person at a terminal can escape, display a picture, or
background the process. Implementing them would imitate the OpenSSH client,
not make tues a better library.

| Setting | Difficulty | Status | Why a library skips it |
|---|---|---|---|
| `EscapeChar`, `EnableEscapeCommandline` | 2 | not started | The `~.` escape hatch while a terminal session is in the foreground. tues commands have no such console. |
| `ObscureKeystrokeTiming` | 3 | not started | Hide inter-keystroke timing on an interactive session. Exec and SFTP have no keystrokes. |
| `ForkAfterAuthentication` | 3 | not started | Fork the client into the background after login. The caller already owns the process and the session handle. |
| `ForwardX11`, `ForwardX11Timeout`, `ForwardX11Trusted`, `XAuthLocation` | 3 | not started | X11 cookie and display forwarding. Desktop ssh. |
| `Tunnel`, `TunnelDevice` | 3 | not started | A `tun` device on both sides. A VPN feature, not a command runner. |
| `ControlMaster`, `ControlPath`, `ControlPersist` | 3 | not started | OpenSSH's multiplex socket. Sharing one TCP connection across processes is real, and it is a different design from speaking that socket protocol. Pooling inside one tues process does not require these keywords. |
