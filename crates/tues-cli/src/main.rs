//! `tues` — run a command on many hosts over SSH, optionally via sudo.
//!
//! ```text
//! tues [OPTIONS] <COMMAND> <SERVER>...
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};

use tues_async::Session;
use tues_core::{
    ConnectOptions, Error, HostKeyPolicy, PasswordKind, PasswordManager, PasswordPrompter,
    PasswordRequest, SecretString, StaticPasswordManager, Stdio, TtyPrompter, shared,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HostKeyCheck {
    Strict,
    AcceptNew,
    Off,
}

impl From<HostKeyCheck> for HostKeyPolicy {
    fn from(v: HostKeyCheck) -> Self {
        match v {
            HostKeyCheck::Strict => HostKeyPolicy::Strict,
            HostKeyCheck::AcceptNew => HostKeyPolicy::AcceptNew,
            HostKeyCheck::Off => HostKeyPolicy::Off,
        }
    }
}

/// Run a command on one or more servers over SSH.
#[derive(Debug, Parser)]
#[command(name = "tues", version, about, long_about = None)]
struct Cli {
    /// The command line to run (interpreted by the remote shell).
    command: String,

    /// Servers: `host`, `login-user@host`, `host:port`, or an ssh_config alias.
    #[arg(required = true)]
    servers: Vec<String>,

    /// Login user (default: from ssh_config or the local user).
    #[arg(short = 'l', long = "login-user")]
    login_user: Option<String>,

    /// User to run the command as, via sudo.
    #[arg(short = 'u', long)]
    user: Option<String>,

    /// Maximum number of hosts worked on concurrently (default: all).
    #[arg(short = 'j', long)]
    jobs: Option<usize>,

    /// SSH port.
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Identity (private key) file; may be repeated.
    #[arg(short = 'i', long = "identity")]
    identity: Vec<PathBuf>,

    /// Read this ssh_config instead of ~/.ssh/config.
    #[arg(short = 'F', long = "config")]
    config: Option<PathBuf>,

    /// Do not read any ssh_config.
    #[arg(long)]
    no_ssh_config: bool,

    /// Request a pseudo-terminal (the default).
    #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "no_pty")]
    pty: bool,

    /// Do not request a pseudo-terminal.
    #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "pty")]
    no_pty: bool,

    /// Host key verification policy (default: ssh_config, else strict).
    #[arg(long, value_enum)]
    host_key_check: Option<HostKeyCheck>,

    /// known_hosts file.
    #[arg(long)]
    known_hosts: Option<PathBuf>,

    /// Take passwords (login and sudo) from this environment variable
    /// instead of prompting on the terminal.
    #[arg(long, value_name = "VAR")]
    password_env: Option<String>,

    /// Connection timeout in seconds.
    #[arg(long, value_name = "SECS")]
    connect_timeout: Option<u64>,

    /// Do not prefix output lines with the host name when running on
    /// several hosts.
    #[arg(long)]
    no_prefix: bool,

    /// Verbose logging (repeat for more).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Prompts once per (kind, login user) and reuses the answer across hosts, since a
/// fleet usually shares credentials. A rejection on any host clears it.
struct FleetPasswordManager<P: PasswordPrompter> {
    prompter: P,
    cache: HashMap<(PasswordKind, String, Option<PathBuf>), SecretString>,
}

impl<P: PasswordPrompter> PasswordManager for FleetPasswordManager<P> {
    fn get(&mut self, req: &PasswordRequest) -> tues_core::Result<SecretString> {
        let key = fleet_key(req);
        if let Some(pw) = self.cache.get(&key) {
            return Ok(pw.clone());
        }
        let pw = self.prompter.prompt(req)?;
        self.cache.insert(key, pw.clone());
        Ok(pw)
    }

    fn invalidate(&mut self, req: &PasswordRequest) {
        self.cache.remove(&fleet_key(req));
    }
}

fn fleet_key(req: &PasswordRequest) -> (PasswordKind, String, Option<PathBuf>) {
    let kind = match req.kind {
        PasswordKind::Sudo => PasswordKind::Login,
        k => k,
    };
    (kind, req.login_user.clone(), req.key_path.clone())
}

/// Prompter that names the host on the first prompt only.
struct FleetPrompter;

impl PasswordPrompter for FleetPrompter {
    fn prompt(&mut self, req: &PasswordRequest) -> tues_core::Result<SecretString> {
        let mut inner = TtyPrompter;
        let generic = PasswordRequest {
            host: "all hosts".to_string(),
            ..req.clone()
        };
        inner.prompt(&generic)
    }
}

struct HostResult {
    server: String,
    outcome: Result<tues_core::ExitStatus, Error>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("tues={level},tues_async={level}"))
            }),
        )
        .with_writer(std::io::stderr)
        .init();

    let password_manager = match &cli.password_env {
        Some(var) => {
            let pw = std::env::var(var)
                .with_context(|| format!("environment variable {var} is not set"))?;
            shared(StaticPasswordManager::new(pw))
        }
        None => shared(FleetPasswordManager {
            prompter: FleetPrompter,
            cache: HashMap::new(),
        }),
    };

    let multi = cli.servers.len() > 1;
    let prefix = multi && !cli.no_prefix;
    let jobs = cli.jobs.unwrap_or(cli.servers.len()).max(1);
    let sem = Arc::new(Semaphore::new(jobs));
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let stderr = Arc::new(Mutex::new(tokio::io::stderr()));
    let cli = Arc::new(cli);

    let mut tasks = Vec::with_capacity(cli.servers.len());
    for server in cli.servers.clone() {
        let sem = sem.clone();
        let cli = cli.clone();
        let pm = password_manager.clone();
        let stdout = stdout.clone();
        let stderr = stderr.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore");
            let outcome = run_host(&cli, &server, pm, prefix, stdout, stderr).await;
            HostResult { server, outcome }
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for t in tasks {
        results.push(t.await.expect("host task panicked"));
    }

    let mut exit_code = 0i32;
    for r in &results {
        match &r.outcome {
            Ok(status) => {
                if !status.success() {
                    exit_code = if multi { 1 } else { status.code().unwrap_or(1) };
                    if multi && cli.verbose > 0 {
                        eprintln!("{}: {}", r.server, status);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}: error: {e}", r.server);
                exit_code = if multi { 1 } else { 255 };
            }
        }
    }
    std::process::exit(exit_code);
}

impl Cli {
    /// A PTY is allocated unless `--no-pty` was given last.
    fn use_pty(&self) -> bool {
        self.pty || !self.no_pty
    }
}

fn connect_options(
    cli: &Cli,
    server: &str,
    pm: tues_core::SharedPasswordManager,
) -> ConnectOptions {
    let mut o = ConnectOptions::new(server).password_manager(pm);
    if let Some(u) = &cli.login_user {
        o = o.login_user(u.clone());
    }
    if let Some(p) = cli.port {
        o = o.port(p);
    }
    for i in &cli.identity {
        o = o.identity_file(i.clone());
    }
    if cli.no_ssh_config {
        o = o.no_ssh_config();
    } else if let Some(f) = &cli.config {
        o = o.ssh_config_file(f.clone());
    }
    if let Some(h) = cli.host_key_check {
        o = o.host_key_policy(h.into());
    }
    if let Some(k) = &cli.known_hosts {
        o = o.known_hosts_file(k.clone());
    }
    if let Some(t) = cli.connect_timeout {
        o = o.connect_timeout(Duration::from_secs(t));
    }
    if let Some(u) = &cli.user {
        o = o.user(u.clone());
    }
    o
}

async fn run_host(
    cli: &Cli,
    server: &str,
    pm: tues_core::SharedPasswordManager,
    prefix: bool,
    stdout: Arc<Mutex<tokio::io::Stdout>>,
    stderr: Arc<Mutex<tokio::io::Stderr>>,
) -> Result<tues_core::ExitStatus, Error> {
    let session = Session::connect(connect_options(cli, server, pm)).await?;
    let mut cmd = session
        .shell(&cli.command)
        .pty(cli.use_pty())
        .stdin(Stdio::Null);

    let result = if prefix {
        cmd = cmd.stdout(Stdio::Piped).stderr(Stdio::Piped);
        let mut child = cmd.spawn().await?;
        let out = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        let label = server.to_string();
        let out_task = tokio::spawn(prefix_lines(out, format!("{label}: "), stdout));
        let err_task = tokio::spawn(prefix_lines(err, format!("{label}: "), stderr));
        let status = child.wait().await;
        let _ = out_task.await;
        let _ = err_task.await;
        status
    } else {
        cmd = cmd.stdout(Stdio::Inherit).stderr(Stdio::Inherit);
        cmd.status().await
    };
    let _ = session.close().await;
    result
}

/// Copy `reader` to `sink`, prefixing every line. Partial trailing lines are
/// flushed with a newline at EOF so prefixes stay aligned.
async fn prefix_lines<R, W>(mut reader: R, prefix: String, sink: Arc<Mutex<W>>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut partial: Vec<u8> = Vec::new();
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        partial.extend_from_slice(&buf[..n]);
        let mut out = Vec::new();
        while let Some(pos) = partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = partial.drain(..=pos).collect();
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(&line);
        }
        if !out.is_empty() {
            let mut w = sink.lock().await;
            let _ = w.write_all(&out).await;
            let _ = w.flush().await;
        }
    }
    if !partial.is_empty() {
        let mut out = Vec::from(prefix.as_bytes());
        out.extend_from_slice(&partial);
        out.push(b'\n');
        let mut w = sink.lock().await;
        let _ = w.write_all(&Bytes::from(out)).await;
        let _ = w.flush().await;
    }
}
