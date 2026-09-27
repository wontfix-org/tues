# tues

Run commands on remote hosts over SSH, with transparent `sudo` elevation, and
move files over SFTP. Available as a Rust library (blocking and async), a
Python package (blocking and asyncio) and a fan-out command-line tool.

Key points:

- **Sans-IO core.** The exec protocol (`ExecMachine`) is a pure state machine:
  bytes and channel events in, effects out. The tokio driver (`tues-async`)
  and the blocking facade (`tues-sync`) share it.
- **Login user vs. user.** A session logs in as the login user and runs
  commands as the user, via `sudo` when they differ. The sudo prompt is intercepted in both plain
  and PTY mode; the prompt, the password, and any `Sorry, try again.` noise are
  removed from the conversation, so binary data on stdout stays intact.
- **Pluggable, memoizing password manager.** Passwords for login, sudo and key
  passphrases are requested through the `PasswordManager` trait. The default
  prompts once on the TTY and caches per host and login user; swap in your own.
- **OpenSSH configuration.** `~/.ssh/config` (`Host`, `Match all`, `Include`,
  `ProxyJump`, `IdentityFile`, `User`, `Port`, `StrictHostKeyChecking`,
  `UserKnownHostsFile`, …) is honoured, and everything can be overridden from
  the API.
- **Standard-library-shaped APIs.** In Rust, `Command`, `Child`, `Output`,
  `ExitStatus`, `Stdio` behave like `std::process`. In Python, `Session.run`,
  `Popen`, `CompletedProcess`, `PIPE`/`STDOUT`/`DEVNULL`, `check_output`, …
  behave like `subprocess` (and `asyncio.subprocess`).
- **Pure Rust SSH** via [`russh`](https://crates.io/crates/russh); no `libssh2`
  or OpenSSL to link.

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `crates/tues-core` | Sans-IO state machine, sudo filter, `Command`, options, ssh_config parser, password manager. No I/O. |
| `crates/tues-async` | tokio driver on `russh`: connect, auth, known_hosts, ProxyJump, exec pump, SFTP. |
| `crates/tues-sync` | Blocking API; a private tokio runtime drives `tues-async`. |
| `crates/tues` | Facade crate: blocking API at the root, async API in `tues::aio`. |
| `crates/tues-cli` | The `tues` binary. |
| `crates/tues-python` | PyO3 extension module (`tues._tues`): sessions, raw child handles, SFTP. |
| `python/tues` | The Python package: the `subprocess`-shaped API on top of `tues._tues`. |
| `crates/tues-testsupport` | Docker `sshd` fixture for the integration tests. |

## Command line

```text
tues [OPTIONS] <COMMAND> <PROVIDER> [ARGS]...

  -l, --login-user <USER>    Login user
  -u, --user <USER>          User to run the command as, via sudo
  -j, --jobs <N>             Hosts worked on concurrently (default: 1)
      --check                Stop after the first failure (one job only)
      --no-check             Keep going after a failure (default)
  -p, --port <PORT>          SSH port
  -i, --identity <FILE>      Identity file; may be repeated
  -F, --config <FILE>        Read this ssh_config instead of ~/.ssh/config
      --no-ssh-config        Do not read any ssh_config
      --file <SRC[:DST]>     Upload a file or directory first; may be repeated
      --pty                  Request a pseudo-terminal (default)
      --no-pty               Do not request a pseudo-terminal
      --host-key-check <P>   strict | accept-new | off
      --known-hosts <FILE>   known_hosts file
      --password-env <VAR>   Take passwords from this environment variable
      --connect-timeout <S>  Connection timeout in seconds
      --no-prefix            Do not prefix output lines with the host name
      --show-hosts           Print the hosts on stderr, then run the command
  -v, --verbose...           Verbose logging
```

The provider, named after the command, supplies the hosts. `cl` takes them as
the remaining arguments. `file` reads them from files, one host per line, and
`-` reads stdin. Any other name runs `tues-provider-<name>` from `PATH`, with
the remaining arguments and options passed through, and reads the same
newline-separated list from its stdout. tues options come before the command.
`--show-hosts` prints the resolved list before connecting; without it the
command runs directly.

A host is `host`, `login-user@host`, `host:port`, `[2001:db8::1]:2222`, or an
alias from `~/.ssh/config`.

```sh
# Restart a service on three hosts, four at a time, as root.
tues -l deploy -u root -j 4 'systemctl restart nginx' cl web01 web02 web03

# One host, without a PTY: raw stdout/stderr, the remote exit status becomes ours.
tues --no-pty 'tar cz /var/log' cl backup01 > logs.tgz

# Passwords from the environment instead of the terminal.
TUES_PW=s3cret tues --password-env TUES_PW -u root 'apt-get update' cl db01 db02

# Hosts from a file, and from a provider executable (tues-provider-netbox).
tues 'uptime' file web.list
tues --show-hosts 'uptime' netbox --site nyc

# Upload first. `deploy.sh` lands in the remote working directory and is
# removed afterwards; `app.conf` is kept at its destination.
tues --file ./deploy.sh --file ./app.conf:/etc/app/app.conf 'sh deploy.sh' cl web01
```

`--file SRC` uploads a file or directory (recursively) into the remote working
directory under its own name and deletes it once the command has finished.
`--file SRC:DST` uploads to `DST` and leaves it in place; an existing remote
directory receives the file inside it, like `cp`. Escape a literal `:` as `\:`
and a literal `\` as `\\`. Uploads run as the command user.

Hosts are visited one after another. `-j` raises how many run at once. With
several hosts each output line is prefixed with `host: `, and the exit status
is `0` only if every host succeeded. With one host, output is passed through
unchanged and the exit status is the remote one (`255` on connection errors,
like `ssh`). `--check` stops at the first host that fails or exits non-zero;
it is rejected when more than one job runs at a time.

```sh
cargo install --path crates/tues-cli
```

## Rust

```toml
[dependencies]
tues = { path = "crates/tues" }   # or the published crate
```

### Blocking API

```rust
use std::io::Read;
use tues::{ConnectOptions, HostKeyPolicy, Session, Stdio};

fn main() -> tues::Result<()> {
    // `alice@web01` is resolved against ~/.ssh/config; builder values win.
    let opts = ConnectOptions::new("alice@web01")
        .identity_file("/home/alice/.ssh/id_ed25519")
        .host_key_policy(HostKeyPolicy::AcceptNew)
        .user("root"); // commands run as root unless told otherwise

    let session = Session::connect(opts)?;

    // Capture output (std::process::Command-style).
    let out = session
        .command("systemctl")
        .args(["restart", "nginx"])
        .output()?; // runs as root because of the session default
    assert!(out.status.success(), "nginx restart failed: {}", out.stderr_lossy());

    // A shell line, as the login user, with env and cwd.
    let out = session
        .shell("echo $GREETING from $(pwd)")
        .env("GREETING", "hello")
        .current_dir("/tmp")
        .as_login_user()
        .output()?;
    println!("{}", out.stdout_lossy());

    // Streaming: binary stdout through sudo stays byte-exact.
    let mut child = session
        .command("cat")
        .arg("/var/lib/secret.bin")
        .user("root")
        .stdout(Stdio::Piped)
        .spawn()?;
    let mut data = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut data)?;
    let status = child.wait()?;
    assert!(status.success());

    // Interactive: write to stdin, read stdout.
    let mut child = session.command("wc").arg("-c").spawn()?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"12345")?;
        stdin.close()?; // EOF
    }
    let out = child.wait_with_output()?;
    assert_eq!(out.stdout_lossy().trim(), "5");

    // SFTP.
    let sftp = session.sftp()?;
    sftp.write("/tmp/hello.txt", b"hello")?;
    for entry in sftp.read_dir("/tmp")? {
        println!("{} {}", entry.metadata.size, entry.file_name);
    }
    sftp.close()?;

    // File helpers use their own SFTP channel, opened on first use.
    session.upload("notes.txt", "/tmp/notes.txt")?;
    let meta = session.stat("/tmp/notes.txt")?;
    assert!(meta.is_file());
    session.download("/tmp/notes.txt", "notes-copy.txt")?;
    session.rename("/tmp/notes.txt", "/tmp/notes-2.txt")?;
    session.delete("/tmp/notes-2.txt")?;

    session.close()
}
```

### Async API (tokio)

```rust
use tokio::io::AsyncReadExt;
use tues::aio::Session;
use tues::{ConnectOptions, Stdio};

#[tokio::main]
async fn main() -> tues::Result<()> {
    let session = Session::connect(ConnectOptions::new("alice@web01").user("root")).await?;

    // Fan out: commands on one session run concurrently on separate channels.
    let uptime = session.command("uptime");
    let df = session.command("df").arg("-h");
    let (a, b) = tokio::join!(uptime.output(), df.output());
    println!("{}{}", a?.stdout_lossy(), b?.stdout_lossy());

    // Stream a process.
    let mut child = session
        .command("journalctl")
        .args(["-f", "-n", "0"])
        .stdout(Stdio::Piped)
        .spawn()
        .await?;
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 8192];
    for _ in 0..3 {
        let n = stdout.read(&mut buf).await?;
        print!("{}", String::from_utf8_lossy(&buf[..n]));
    }
    child.kill()?;
    child.wait().await?;

    // SFTP with tokio's AsyncRead/AsyncWrite/AsyncSeek.
    let sftp = session.sftp().await?;
    let mut f = sftp.create("/tmp/data.bin").await?;
    tokio::io::AsyncWriteExt::write_all(&mut f, &[0u8; 1024]).await?;
    tokio::io::AsyncWriteExt::shutdown(&mut f).await?;
    sftp.close().await?;

    session.close().await
}
```

### Connection options

Everything `ssh` reads from `~/.ssh/config` can be set on the builder; the
precedence is destination string (`login-user@host:port`) > builder > ssh_config >
defaults.

```rust
use std::time::Duration;
use tues::{ConnectOptions, HostKeyPolicy, SshConfigSource};

let opts = ConnectOptions::new("db01")
    .login_user("deploy")
    .port(2222)
    .host_name("10.0.0.5")                      // like HostName
    .identity_file("~/.ssh/deploy_ed25519")
    .identities_only(true)
    .proxy_jump("bastion.example.com")          // or "a,b,c" for several hops
    .connect_timeout(Duration::from_secs(10))
    .server_alive_interval(Duration::from_secs(30))
    .compression(true)
    .use_agent(false)
    .host_key_policy(HostKeyPolicy::Strict)
    .known_hosts_file("/etc/ssh/ssh_known_hosts")
    .ssh_config(SshConfigSource::File("/etc/tues/ssh_config".into())); // or .no_ssh_config()

// Inspect what will actually be used:
let resolved = opts.resolve()?;
println!("{}@{}:{}", resolved.login_user, resolved.host_name, resolved.port);
# Ok::<(), tues::Error>(())
```

### Password managers

Any `PasswordManager` can be plugged in. The built-ins:

- `MemoizingPasswordManager<P: PasswordPrompter>` — asks the prompter once per
  host/user, caches the answer, forgets it when sudo/sshd rejects it. Default,
  with `TtyPrompter` (reads from `/dev/tty`).
- `StaticPasswordManager` — one fixed password for everything.
- `NoPasswordManager` — never answers; sudo without `NOPASSWD` fails with
  `SudoError::PasswordRequired`.

```rust
use tues::{
    ConnectOptions, MemoizingPasswordManager, PasswordKind, PasswordPrompter, PasswordRequest,
    SecretString, Session, shared,
};

/// Fetches passwords from a vault; `MemoizingPasswordManager` handles caching.
struct Vault;

impl PasswordPrompter for Vault {
    fn prompt(&mut self, req: &PasswordRequest) -> tues::Result<SecretString> {
        let key = match req.kind {
            PasswordKind::Login | PasswordKind::Sudo => format!("ssh/{}/{}", req.host, req.login_user),
            PasswordKind::KeyPassphrase => format!("keys/{}", req.key_path.as_ref().unwrap().display()),
        };
        let secret = lookup_in_vault(&key).map_err(|e| tues::Error::Password(e.to_string()))?;
        Ok(SecretString::from(secret))
    }
}

let manager = shared(MemoizingPasswordManager::new(Vault));
let session = Session::connect(
    ConnectOptions::new("alice@web01").password_manager(manager.clone()),
)?;
// The same manager can be shared between sessions to reuse cached passwords.
```

Implement `PasswordManager` directly (`get` + `invalidate`) if you want to own
the caching policy.

### Sans-IO core

`tues-core` has no I/O and no runtime. If you want to drive the exec protocol
over your own transport, feed `ExecMachine` events and act on its effects:

```rust
use tues::core::{Bytes, Command, Effect, Event, ExecMachine, Stdio};

let plan = Command::new("id").user("root").plan(Stdio::Piped, None);
let mut m = ExecMachine::new(&plan);

// Exec `plan.command_line` on a freshly opened SSH channel, then loop: feed
// m.handle(Event::Stdout(bytes)) / Event::Stderr / Event::ExitStatus(n) / Event::Eof / Event::Close
// and drain `m.poll_effect()` after every event:
m.handle(Event::Stdout(Bytes::from_static(b"...")));
while let Some(effect) = m.poll_effect() {
    match effect {
        Effect::Stdout(_bytes) => { /* clean stdout, sudo prompt already removed */ }
        Effect::Stderr(_bytes) => { /* clean stderr */ }
        Effect::WriteChannel(_bytes) => { /* send to the channel */ }
        Effect::WriteChannelSecret(_password) => { /* send to the channel, never log */ }
        Effect::ChannelEof => { /* send EOF */ }
        Effect::RequestPassword { retry: _ } => { /* obtain a password, then m.handle(Event::Password(pw)) */ }
        Effect::Finished(_result) => { /* exit status or SudoError */ }
    }
}
```

## Python

```sh
pip install maturin
maturin develop --release        # or: pip install .
```

The Python API is shaped like the standard library: a `Session` is the
`subprocess` module for one remote host, an `AsyncSession` is
`asyncio.subprocess`. `run`, `Popen`, `CompletedProcess`, `CalledProcessError`,
`TimeoutExpired`, `PIPE`, `STDOUT`, `DEVNULL`, `check_output`, `communicate`,
`text=`, `shell=`, `timeout=`, … all work as you know them. `Popen.stdout` is
a real `io.BufferedReader`/`TextIOWrapper`, `Process.stdout` a real
`asyncio.StreamReader`. The exceptions subclass their `subprocess` namesakes.

### Blocking

```python
import tues

with tues.Session("alice@web01", user="root", host_key_policy="accept-new") as s:
    # subprocess.run, on the remote host (as root because of the session default).
    s.run(["systemctl", "restart", "nginx"], check=True)

    out = s.run("df -h | tail -n +2", shell=True, capture_output=True, text=True)
    print(out.returncode, out.stdout)

    # Bytes stay bytes, even through sudo.
    out = s.run(["cat"], input=b"\x00\x01binary", stdout=tues.PIPE)
    assert out.stdout == b"\x00\x01binary"

    # Errors and output are the familiar ones.
    try:
        s.check_output(["false"])
    except tues.CalledProcessError as e:        # also a subprocess.CalledProcessError
        print(e.returncode, e.cmd)

    # Popen: stream, signal, wait.
    with s.Popen(["tail", "-f", "/var/log/syslog"], stdout=tues.PIPE, stderr=tues.DEVNULL, text=True) as p:
        for line in p.stdout:
            print(line, end="")
            break
        p.terminate()                           # SIGTERM; p.kill() for SIGKILL
    print(p.returncode)                         # -15

    # Local files as stdio; the login user instead of the session default.
    with open("logs.tgz", "wb") as f:
        s.run(["tar", "cz", "/var/log"], stdout=f, user=tues.LOGIN_USER, check=True)

    with s.sftp() as sftp:
        sftp.write("/tmp/hello.txt", b"hello")
        with sftp.open("/tmp/hello.txt", "a") as f:
            f.write(b" world")
        print(sftp.read("/tmp/hello.txt"), sftp.stat("/tmp/hello.txt").size)
        print([e.name for e in sftp.listdir("/tmp")])

    # Or skip the client. These share one cached channel, separate from sftp().
    s.upload("notes.txt", "/tmp/notes.txt")
    print(s.stat("/tmp/notes.txt").size)
    s.download("/tmp/notes.txt", "notes-copy.txt")
    s.rename("/tmp/notes.txt", "/tmp/notes-2.txt")
    s.delete("/tmp/notes-2.txt")
```

Also available: `call`, `check_call`, `getoutput`, `getstatusoutput`,
`Popen.communicate(input, timeout)`, `Popen.wait(timeout)`, `Popen.poll()`,
`Popen.send_signal("USR1")`, `bufsize=`, `encoding=`/`errors=`, `env=`, `cwd=`.

### asyncio

```python
import asyncio, tues

async def main():
    async with await tues.AsyncSession.connect("alice@web01", user="root") as s:
        # asyncio.subprocess, on the remote host.
        proc = await s.create_subprocess_exec("wc", "-c", stdin=tues.PIPE, stdout=tues.PIPE)
        proc.stdin.write(b"12345")
        await proc.stdin.drain()
        proc.stdin.close()
        stdout, _ = await proc.communicate()
        assert stdout.strip() == b"5" and proc.returncode == 0

        proc = await s.create_subprocess_shell("journalctl -f -n 0", stdout=tues.PIPE)
        async for line in proc.stdout:
            print(line.decode(), end="")
            break
        proc.kill()
        await proc.wait()

        # run() is the asyncio twin of subprocess.run; commands on one session
        # run concurrently on separate channels.
        results = await asyncio.gather(*(s.run(["echo", str(i)], capture_output=True, text=True) for i in range(10)))
        print([r.stdout.strip() for r in results])

        async with await s.sftp() as sftp:
            await sftp.write("/tmp/x", b"data")
            print(await sftp.read_text("/tmp/x"))

asyncio.run(main())
```

### Differences from `subprocess`

Consequences of the process running on another machine:

- `stdin=None` means *no input* (EOF), not the local stdin; pass
  `stdin=sys.stdin` (blocking API) to forward it. `stdout`/`stderr=None`
  do go to the local stdout/stderr.
- `env` adds to / overrides the remote environment instead of replacing it;
  a `None` value unsets a variable.
- `pid` is always `None`. `returncode` is `-N` when the process died of
  signal `N`, as on POSIX.
- `terminate()`/`send_signal()` need a server that implements SSH channel
  signals (OpenSSH ≥ 7.9); `kill()` also closes the channel.
- Extra keyword arguments: `user` and `pty`. `user` is a name (via `sudo -u`)
  or `tues.LOGIN_USER` (the login user, never via sudo, even when the session
  has a default `user`); leaving it out inherits the session default. With a
  PTY, stderr is merged into stdout by the terminal.
- The asyncio API is bytes-only like `asyncio.subprocess`; `AsyncSession.run`
  adds `text=`/`encoding=`.

### Passwords

```python
import getpass, tues

# Prompt once per host/user; Rust memoizes and re-prompts after a wrong password.
s = tues.Session("alice@web01", password_manager=lambda req: getpass.getpass(req.prompt))

# Fixed password for login and sudo.
s = tues.Session("alice@web01", password="s3cret")

# Own the caching: an object with get() and invalidate() is called every time.
class Keyring:
    def get(self, req: tues.PasswordRequest) -> str: ...
    def invalidate(self, req: tues.PasswordRequest) -> None: ...

s = tues.Session("alice@web01", password_manager=Keyring())
```

Errors are raised as `tues.TuesError` subclasses: `ConnectError`, `AuthError`,
`HostKeyError`, `SudoError`, `SftpError`, and `CalledProcessError` /
`TimeoutExpired` (which are also `subprocess.CalledProcessError` /
`subprocess.TimeoutExpired`). A sudo failure surfaces from `run()` /
`wait()` / `communicate()` as `SudoError`.

## How sudo is made invisible

For a command running as a user other than the login user the driver executes

```text
sudo -S -k -p '[tues-sudo-<nonce>]' -u <user> -- /bin/sh -c 'printf %s "[tues-ok-<nonce>]"; <command>'
```

and runs the channel through `SudoFilter`:

1. Output is **held** until either the prompt nonce or the OK marker appears.
2. On the prompt, the password is written to the channel (never surfaced to the
   caller) and the prompt bytes are dropped; `Sorry, try again.` and echoed
   passwords in PTY mode are dropped too and the password manager is told to
   invalidate its cache. After three failures the command fails with
   `SudoError::AuthFailed`.
3. On the marker, the filter switches to **passthrough**: the marker is
   stripped and no further scanning happens, so the command's own output — even
   if it contains the nonces or the password — is delivered byte-exact.
4. Caller stdin is buffered until the marker has been seen, so nothing meant for
   the command can be swallowed by `sudo`.

Because the nonces are random per invocation, remote output cannot forge a
prompt.

SFTP follows the same rule. With no session user it is the server's `sftp`
subsystem, as the login user. With a session user, `tues` starts `sftp-server`
through that sudo handshake (the marker is stripped before the SFTP greeting),
so uploads and downloads run as the command user rather than the login user.

## Development

Requirements: Rust 1.90+, Docker (for the integration tests), Python 3.9+ with
[`uv`](https://docs.astral.sh/uv/) or `maturin` (for the Python package).

```sh
cargo test --workspace                       # unit + Docker sshd integration tests
cargo clippy --workspace --all-targets

# Source coverage for the Rust tests (HTML report: target/llvm-cov/html).
# One-time setup: rustup component add llvm-tools-preview
#                 cargo install cargo-llvm-cov --locked
cargo coverage

uv venv && source .venv/bin/activate
uv pip install maturin pytest 'testcontainers>=4.10'
maturin develop --release
pytest                                       # Python tests, also against Docker sshd
```

## Release

`scripts/release` sets the workspace version (the Python package reads it from
there), commits it, and tags `v<version>`. It then builds an sdist and one
wheel per CPython into `dist/` for an internal index. The tag is not pushed
and the artifacts are not uploaded.

```sh
scripts/release 0.2.0
git push origin HEAD v0.2.0
twine upload --repository-url "$TUES_PYPI_URL" dist/*
```

By default that is Python 3.9, 3.11, 3.12 and 3.13. `uv python install`
fetches a managed CPython for each of those, ignoring the project virtualenv,
and `uvx` runs maturin against those binaries. Each wheel is tagged for that
interpreter (`cp39`, `cp311`, `cp312`, `cp313`) and for the platform where the
helper runs. The sdist is built first and the wheels are built from it. Change
the set with `--python 3.12,3.13` or `TUES_PYTHON_VERSIONS`. `uv` is required.

The integration tests build `docker/sshd/Dockerfile` (Debian `sshd` with a
`tues` user that may sudo, and a `nopw` NOPASSWD target) and start it on an
ephemeral host port. The Rust tests do this through the `testcontainers` crate;
the pytest suite uses the `testcontainers` Python library (Python 3.10+).
Containers are removed when the test process exits.

## License

MIT OR Apache-2.0
