# tues

Run commands on remote hosts over SSH, with transparent `sudo` elevation, and
move files over SFTP. Available as a Rust library (blocking and async), a
Python package (blocking and asyncio) and a fan-out command-line tool.

Key points:

- **Sans-IO core.** The exec protocol (`ExecMachine`) is a pure state machine:
  bytes and channel events in, effects out. The tokio driver (`tues-async`)
  and the blocking facade (`tues-sync`) share it.
- **Login user vs. run-as user.** A session logs in as one user and runs
  commands as another via `sudo`. The sudo prompt is intercepted in both plain
  and PTY mode; the prompt, the password, and any `Sorry, try again.` noise are
  removed from the conversation, so binary data on stdout stays intact.
- **Pluggable, memoizing password manager.** Passwords for login, sudo and key
  passphrases are requested through the `PasswordManager` trait. The default
  prompts once on the TTY and caches per host/user; swap in your own.
- **OpenSSH configuration.** `~/.ssh/config` (`Host`, `Match all`, `Include`,
  `ProxyJump`, `IdentityFile`, `User`, `Port`, `StrictHostKeyChecking`,
  `UserKnownHostsFile`, …) is honoured, and everything can be overridden from
  the API.
- **`std::process`-shaped API.** `Command`, `Child`, `Output`, `ExitStatus`,
  `Stdio` behave like their standard-library counterparts.
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
| `crates/tues-python` | PyO3 extension module (`tues._tues`). |
| `crates/tues-testsupport` | Docker `sshd` fixture for the integration tests. |

## Command line

```text
tues [OPTIONS] <COMMAND> <SERVERS>...

  -u, --user <USER>          SSH login user
  -r, --run-as <RUN_AS>      Run the command as this user via sudo
  -j, --jobs <JOBS>          Maximum number of hosts worked on concurrently
  -p, --port <PORT>          SSH port
  -i, --identity <FILE>      Identity file; may be repeated
  -F, --config <FILE>        Read this ssh_config instead of ~/.ssh/config
      --no-ssh-config        Do not read any ssh_config
      --pty                  Request a pseudo-terminal
      --host-key-check <P>   strict | accept-new | off
      --known-hosts <FILE>   known_hosts file
      --password-env <VAR>   Take passwords from this environment variable
      --connect-timeout <S>  Connection timeout in seconds
      --no-prefix            Do not prefix output lines with the host name
  -v, --verbose...           Verbose logging
```

Servers can be `host`, `user@host`, `host:port`, `[2001:db8::1]:2222`, or an
alias from `~/.ssh/config`.

```sh
# Restart a service on three hosts, four at a time, as root.
tues -u deploy -r root -j 4 'systemctl restart nginx' web01 web02 web03

# One host: raw stdout/stderr, the remote exit status becomes ours.
tues 'tar cz /var/log' backup01 > logs.tgz

# Passwords from the environment instead of the terminal.
TUES_PW=s3cret tues --password-env TUES_PW -r root 'apt-get update' db01 db02
```

With several hosts each output line is prefixed with `host: `, and the exit
status is `0` only if every host succeeded. With one host, output is passed
through unchanged and the exit status is the remote one (`255` on connection
errors, like `ssh`).

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
        .run_as("root"); // default sudo user for this session

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
        .run_as_login_user()
        .output()?;
    println!("{}", out.stdout_lossy());

    // Streaming: binary stdout through sudo stays byte-exact.
    let mut child = session
        .command("cat")
        .arg("/var/lib/secret.bin")
        .run_as("root")
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
    let session = Session::connect(ConnectOptions::new("alice@web01").run_as("root")).await?;

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
precedence is destination string (`user@host:port`) > builder > ssh_config >
defaults.

```rust
use std::time::Duration;
use tues::{ConnectOptions, HostKeyPolicy, SshConfigSource};

let opts = ConnectOptions::new("db01")
    .user("deploy")
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
println!("{}@{}:{}", resolved.user, resolved.host_name, resolved.port);
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
            PasswordKind::Login | PasswordKind::Sudo => format!("ssh/{}/{}", req.host, req.user),
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

let plan = Command::new("id").run_as("root").plan(Stdio::Piped, None);
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

### Blocking

```python
import tues

with tues.Session.connect("alice@web01", run_as="root", host_key_policy="accept-new") as s:
    out = s.run("systemctl restart nginx", check=True)   # str → remote shell
    out = s.run(["id", "-un"])                            # list → argv
    print(out.returncode, out.stdout, out.stderr)

    out = s.run("cat", input=b"\x00\x01binary", run_as="root")
    assert out.stdout == b"\x00\x01binary"

    child = s.spawn("tail -f /var/log/syslog", stderr="null")
    for line in child.stdout:
        print(line.decode(), end="")
        break
    child.kill()
    child.wait()

    with s.sftp() as sftp:
        sftp.write("/tmp/hello.txt", b"hello")
        with sftp.open("/tmp/hello.txt", "a") as f:
            f.write(b" world")
        print(sftp.read("/tmp/hello.txt"), sftp.stat("/tmp/hello.txt").size)
        print([e.name for e in sftp.listdir("/tmp")])
```

### asyncio

```python
import asyncio, tues

async def main():
    async with await tues.AsyncSession.connect("alice@web01", run_as="root") as s:
        results = await asyncio.gather(*(s.run(f"echo {i}") for i in range(10)))
        print([r.stdout for r in results])

        child = await s.spawn("cat")
        await child.stdin.write(b"ping")
        await child.stdin.close()
        stdout, stderr = await child.communicate()

        async with await s.sftp() as sftp:
            await sftp.write("/tmp/x", b"data")
            print(await sftp.read_text("/tmp/x"))

asyncio.run(main())
```

### Passwords

```python
import getpass, tues

# Prompt once per host/user; Rust memoizes and re-prompts after a wrong password.
s = tues.Session.connect("alice@web01", password_manager=lambda req: getpass.getpass(req.prompt))

# Fixed password for login and sudo.
s = tues.Session.connect("alice@web01", password="s3cret")

# Own the caching: an object with get() and invalidate() is called every time.
class Keyring:
    def get(self, req: tues.PasswordRequest) -> str: ...
    def invalidate(self, req: tues.PasswordRequest) -> None: ...

s = tues.Session.connect("alice@web01", password_manager=Keyring())
```

Errors are raised as `tues.TuesError` subclasses: `ConnectError`, `AuthError`,
`HostKeyError`, `SudoError`, `SftpError`. `run(..., check=True)` raises
`TuesError` on a non-zero exit status.

## How sudo is made invisible

For a command with a run-as user the driver executes

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

The integration tests build `docker/sshd/Dockerfile` (Debian `sshd` with a
`tues` user that may sudo, and a `nopw` NOPASSWD target) and start it on an
ephemeral host port. The Rust tests do this through the `testcontainers` crate;
the pytest suite uses the `testcontainers` Python library (Python 3.10+).
Containers are removed when the test process exits.

## License

MIT OR Apache-2.0
