//! `tues` — run a command on many hosts over SSH, optionally via sudo.
//!
//! ```text
//! tues [OPTIONS] [--script <SPEC> | <COMMAND>] [PROVIDER [ARGS]...]
//! ```
//!
//! The provider decides which hosts to connect to. `cl` takes them as
//! arguments, `file` reads newline-separated files (`-` is stdin), and any
//! other name runs `tues-provider-<name>` from `PATH`. Options that appear
//! before the command belong to tues; everything after the provider name is
//! passed to the provider.
//!
//! `--script` replaces the remote command. The script is found on `TUES_PATH`,
//! uploaded, run, and removed. A text script can set `user`, `pty`, `prefix`,
//! and `prefix-format` defaults in a `tues-args` line in its top comment block,
//! and can name the hosts with `tues-provider` and `tues-provider-args` when
//! the command line does not.
//!
//! [`run`] is the whole program: the `tues` binary calls it with its
//! arguments, and the Python extension exposes it as `tues._tues.cli_main`.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
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
#[command(
    name = "tues",
    version,
    about,
    long_about = None,
    override_usage = "tues [OPTIONS] [--script <SPEC> | <COMMAND>] [PROVIDER [ARGS]...]",
    max_term_width = 120,
    after_help = "\
Providers:
  cl       remaining arguments are hosts
  file     remaining arguments are files of hosts, one per line; - reads stdin
  <name>   run tues-provider-<name> and read hosts from its stdout

tues options come before the command. Arguments and options after the provider
name are passed through to that provider.

A --script file may set the provider in its header (tues-provider and
tues-provider-args). A provider on the command line overrides that header.

When TUES_PW is set, tues uses it for login and sudo passwords instead of prompting."
)]
struct Cli {
    /// Login user (default: from ssh_config or the local user).
    #[arg(short = 'l', long = "login-user", env = "TUES_LOGIN_USER")]
    login_user: Option<String>,

    /// User to run the command as, via sudo.
    #[arg(short = 'u', long, env = "TUES_USER")]
    user: Option<String>,

    /// Hosts worked on concurrently (default: 1, or 20 with `-p`).
    ///
    /// `--pool-size` and `TUES_POOL_SIZE` are accepted for compatibility with
    /// older tues releases.
    #[arg(
        short = 'n',
        long = "num-jobs",
        visible_alias = "pool-size",
        env = "TUES_POOL_SIZE",
        value_name = "N"
    )]
    num_jobs: Option<usize>,

    /// Work on up to 20 hosts at once. Has no effect when `-n` is set.
    #[arg(short = 'p', long, action = clap::ArgAction::SetTrue, env = "TUES_PARALLEL")]
    parallel: bool,

    /// Stop after the first host that fails or exits non-zero.
    /// Only valid with one job at a time.
    #[arg(
        short = 'c',
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "no_check",
        env = "TUES_CHECK"
    )]
    check: bool,

    /// Keep going after a host fails or exits non-zero (the default).
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "check",
        env = "TUES_NO_CHECK"
    )]
    no_check: bool,

    /// SSH port.
    #[arg(long, env = "TUES_PORT")]
    port: Option<u16>,

    /// Identity (private key) file; may be repeated.
    #[arg(short = 'i', long = "identity", env = "TUES_IDENTITY")]
    identity: Vec<PathBuf>,

    /// Read this ssh_config instead of ~/.ssh/config.
    #[arg(short = 'F', long = "config", env = "TUES_CONFIG")]
    config: Option<PathBuf>,

    /// Do not read any ssh_config.
    #[arg(long, action = clap::ArgAction::SetTrue, env = "TUES_NO_SSH_CONFIG")]
    no_ssh_config: bool,

    /// Upload a file or directory (recursively) before running the command;
    /// may be repeated. `SRC` goes into the remote working directory and is
    /// removed afterwards. `SRC:DST` is uploaded to `DST` and kept. Write a
    /// literal `:` as `\:` and a literal `\` as `\\`.
    #[arg(
        short = 'f',
        long = "file",
        env = "TUES_FILE",
        value_name = "SRC[:DST]",
        value_parser = FileSpec::parse
    )]
    files: Vec<FileSpec>,

    /// Request a pseudo-terminal.
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "no_pty",
        env = "TUES_PTY"
    )]
    pty: bool,

    /// Do not request a pseudo-terminal.
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "pty",
        env = "TUES_NO_PTY"
    )]
    no_pty: bool,

    /// With a PTY, leave the remote TTY's default `\n` → `\r\n` translation.
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "no_universal_newlines",
        env = "TUES_UNIVERSAL_NEWLINES"
    )]
    universal_newlines: bool,

    /// With a PTY, disable `INLCR`/`ONLCR` so `\n` is not translated to `\r\n`
    /// (the default).
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "universal_newlines",
        env = "TUES_NO_UNIVERSAL_NEWLINES"
    )]
    no_universal_newlines: bool,

    /// Host key verification policy (default: ssh_config, else strict).
    #[arg(long, value_enum, env = "TUES_HOST_KEY_CHECK")]
    host_key_check: Option<HostKeyCheck>,

    /// known_hosts file.
    #[arg(long, env = "TUES_KNOWN_HOSTS")]
    known_hosts: Option<PathBuf>,

    /// Connection timeout in seconds.
    #[arg(long, value_name = "SECS", env = "TUES_CONNECT_TIMEOUT")]
    connect_timeout: Option<u64>,

    /// Prefix output lines even when running on a single host.
    #[arg(
        short = 'P',
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "no_prefix",
        env = "TUES_PREFIX"
    )]
    prefix: bool,

    /// Do not prefix output lines, even when running on several hosts.
    #[arg(
        short = 'N',
        long,
        action = clap::ArgAction::SetTrue,
        overrides_with = "prefix",
        env = "TUES_NO_PREFIX"
    )]
    no_prefix: bool,

    /// Format for per-host output line prefixes.
    ///
    /// Placeholders: `<name>` (provider host string), `<server-ip>`,
    /// `<client-port>`, `<server-port>`, and `<stream>` (`stdout`, `stderr`,
    /// or `pty`). Default: `[<name>/<stream>]: `.
    #[arg(long, value_name = "FORMAT", env = "TUES_PREFIX_FORMAT")]
    prefix_format: Option<String>,

    /// Run a script from `TUES_PATH` instead of a remote command.
    ///
    /// `SPEC` is a shell-quoted command: the first word is the script name
    /// (looked up like `PATH`) and the rest are its arguments. Example:
    /// `--script "my-script --my-option arg"` uploads `my-script`, runs
    /// `./my-script --my-option arg`, and removes it afterwards.
    ///
    /// A text script may set defaults in its top comment block:
    /// `# tues-args = {"user": "root", "pty": false, "prefix": true}`.
    /// `--user`, `--pty` / `--no-pty`, `--prefix` / `--no-prefix`, and
    /// `--prefix-format` override those. `# tues-provider = "cl"` and
    /// `# tues-provider-args = ["web01"]` name the hosts when the command line
    /// does not. A provider after `--script` overrides both lines.
    #[arg(short = 's', long, value_name = "SPEC", env = "TUES_SCRIPT")]
    script: Option<String>,

    /// Verbose logging (repeat for more).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, env = "TUES_VERBOSE")]
    verbose: u8,

    /// Print the resolved hosts on stderr, then run the command.
    #[arg(long, action = clap::ArgAction::SetTrue, env = "TUES_SHOW_HOSTS")]
    show_hosts: bool,

    /// Sort hosts alphabetically before running the command.
    #[arg(long, action = clap::ArgAction::SetTrue, env = "TUES_SORT_HOSTS")]
    sort_hosts: bool,

    /// Remote shell command, then a provider, then that provider's arguments.
    ///
    /// The provider is `cl` (the arguments are hosts), `file` (the arguments
    /// are newline-separated host files, `-` for stdin), or a name resolved as
    /// the executable `tues-provider-<name>` on `PATH`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND PROVIDER [ARGS]...",
        num_args = 0..
    )]
    args: Vec<String>,
}

/// One `--file` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSpec {
    src: PathBuf,
    /// Remote name used when no destination was given.
    name: String,
    /// Explicit destination; `None` means the working directory, temporary.
    dst: Option<String>,
}

impl FileSpec {
    /// Parse `SRC` or `SRC:DST`. A backslash escapes the next character, so
    /// `\:` is a literal colon and `\\` a literal backslash.
    fn parse(spec: &str) -> Result<FileSpec, String> {
        let mut parts: Vec<String> = vec![String::new()];
        let mut chars = spec.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(next) => parts.last_mut().expect("one part").push(next),
                    None => return Err("trailing backslash".into()),
                },
                ':' if parts.len() == 1 => parts.push(String::new()),
                c => parts.last_mut().expect("one part").push(c),
            }
        }
        let mut parts = parts.into_iter();
        let src = parts.next().expect("one part");
        if src.is_empty() {
            return Err("empty source path".into());
        }
        let dst = parts.next().filter(|d| !d.is_empty());
        let src = PathBuf::from(src);
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| format!("{}: cannot derive a file name", src.display()))?;
        Ok(FileSpec { src, name, dst })
    }

    fn is_temporary(&self) -> bool {
        self.dst.is_none()
    }
}

/// Default line prefix when more than one host runs (or when `prefix` is on).
const DEFAULT_PREFIX_FORMAT: &str = "[<name>/<stream>]: ";

/// What one invocation runs on each host, after `--script` defaults are applied.
#[derive(Debug, Clone)]
struct Run {
    command: String,
    /// Temporary upload of the `--script` file. `None` for a plain command.
    script: Option<FileSpec>,
    user: Option<String>,
    pty: bool,
    /// When a PTY is used, whether the remote may translate `\n` to `\r\n`.
    universal_newlines: bool,
    /// `None` means prefix only when more than one host is selected.
    prefix: Option<bool>,
    /// Template for each output line prefix; see [`DEFAULT_PREFIX_FORMAT`].
    prefix_format: String,
}

/// Defaults read from a script header: `tues-args`, `tues-provider`, and
/// `tues-provider-args`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ScriptDefaults {
    user: Option<String>,
    pty: Option<bool>,
    prefix: Option<bool>,
    prefix_format: Option<String>,
    provider: Option<String>,
    /// Absent when the header has no `tues-provider-args` line.
    provider_args: Option<Vec<String>>,
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
        let mut inner = TtyPrompter::new();
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

/// Run `tues` with `args` (the program name first) and return its exit code.
///
/// This is the entire program: it parses the command line, prints clap's
/// help and usage errors, runs the hosts on a fresh tokio runtime, and
/// reports failures on stderr. Nothing here terminates the process, so the
/// caller decides how to exit; the `tues` binary passes the code to
/// `std::process::exit`, and the Python console script returns it from
/// `sys.exit`.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let code = run_inner(args);
    // Rust flushes stdout when a Rust program exits. Inside another program
    // (the Python interpreter) nobody does, so a final partial line would be
    // lost without this.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    code
}

fn run_inner<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return e.exit_code();
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to start the async runtime: {e}");
            return 1;
        }
    };
    let code = match runtime.block_on(run_cli(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            1
        }
    };
    // The process (or the Python caller) is about to exit. Do not wait for
    // idle connection tasks to wind down.
    runtime.shutdown_background();
    code
}

async fn run_cli(cli: Cli) -> anyhow::Result<i32> {
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    // A host program may already have installed a subscriber; keep it.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("tues={level},tues_async={level}"))
            }),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let password_manager = match std::env::var("TUES_PW") {
        Ok(pw) => shared(StaticPasswordManager::new(pw)),
        Err(std::env::VarError::NotPresent) => shared(FleetPasswordManager {
            prompter: FleetPrompter,
            cache: HashMap::new(),
        }),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("TUES_PW is not valid Unicode");
        }
    };

    let jobs = cli.job_count();
    if cli.fail_fast() && jobs != 1 {
        anyhow::bail!("--check only works with one job at a time");
    }
    let (run, defaults) = prepare_run(&cli)?;
    let mut hosts = resolve_hosts(&cli, defaults.as_ref())?;
    if cli.sort_hosts {
        hosts.sort();
    }
    if cli.show_hosts {
        let noun = if hosts.len() == 1 { "host" } else { "hosts" };
        eprintln!("{} {noun}:", hosts.len());
        for host in &hosts {
            eprintln!("{host}");
        }
    }
    let multi = hosts.len() > 1;
    let prefix = run.prefix.unwrap_or(multi);
    let run = Arc::new(run);
    let sem = Arc::new(Semaphore::new(jobs));
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let stderr = Arc::new(Mutex::new(tokio::io::stderr()));
    let cli = Arc::new(cli);

    if cli.fail_fast() {
        let mut exit_code = 0i32;
        for server in &hosts {
            let outcome = run_host(
                &cli,
                &run,
                server,
                password_manager.clone(),
                prefix,
                stdout.clone(),
                stderr.clone(),
            )
            .await;
            if note_failure(server, &outcome, multi, cli.verbose, &mut exit_code) {
                break;
            }
        }
        return Ok(exit_code);
    }

    let mut tasks = Vec::with_capacity(hosts.len());
    for server in hosts {
        let sem = sem.clone();
        let cli = cli.clone();
        let run = run.clone();
        let pm = password_manager.clone();
        let stdout = stdout.clone();
        let stderr = stderr.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore");
            let outcome = run_host(&cli, &run, &server, pm, prefix, stdout, stderr).await;
            HostResult { server, outcome }
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for t in tasks {
        results.push(t.await.expect("host task panicked"));
    }

    let mut exit_code = 0i32;
    for r in &results {
        note_failure(&r.server, &r.outcome, multi, cli.verbose, &mut exit_code);
    }
    Ok(exit_code)
}

/// Record a host that failed or exited non-zero. Returns whether this host was unsuccessful.
fn note_failure(
    server: &str,
    outcome: &Result<tues_core::ExitStatus, Error>,
    multi: bool,
    verbose: u8,
    exit_code: &mut i32,
) -> bool {
    match outcome {
        Ok(status) if status.success() => false,
        Ok(status) => {
            *exit_code = if multi { 1 } else { status.code().unwrap_or(1) };
            if multi && verbose > 0 {
                eprintln!("{server}: {status}");
            }
            true
        }
        Err(e) => {
            eprintln!("{server}: error: {e}");
            *exit_code = if multi { 1 } else { 255 };
            true
        }
    }
}

impl Cli {
    /// A PTY is allocated only when `--pty` was given last.
    fn use_pty(&self) -> bool {
        self.pty && !self.no_pty
    }

    /// `--universal-newlines` wins when given last; otherwise `\n` stays `\n`.
    fn use_universal_newlines(&self) -> bool {
        self.universal_newlines && !self.no_universal_newlines
    }

    /// Explicit `--prefix` / `--no-prefix`, or `None` to follow host count / script defaults.
    fn prefix_setting(&self) -> Option<bool> {
        if self.prefix {
            Some(true)
        } else if self.no_prefix {
            Some(false)
        } else {
            None
        }
    }

    /// Stop at the first unsuccessful host unless `--no-check` was given last.
    fn fail_fast(&self) -> bool {
        self.check && !self.no_check
    }

    /// `-n` chooses the count. `-p` means 20 when neither was given.
    fn job_count(&self) -> usize {
        const PARALLEL_JOBS: usize = 20;
        match self.num_jobs {
            Some(n) => n.max(1),
            None if self.parallel => PARALLEL_JOBS,
            None => 1,
        }
    }
}

/// Hosts from the provider named after the command (or after `--script`).
///
/// A command-line provider replaces a `tues-provider` line in the script.
/// With `--script` and no command-line provider, that line is used instead.
fn resolve_hosts(cli: &Cli, defaults: Option<&ScriptDefaults>) -> anyhow::Result<Vec<String>> {
    let (provider, pargs) = selected_provider(cli, defaults)?;
    let hosts = match provider.as_str() {
        "cl" => pargs.iter().filter(|h| !h.is_empty()).cloned().collect(),
        "file" => hosts_from_files(&pargs)?,
        name => {
            let hosts = hosts_from_program(name, &pargs)?;
            if hosts.is_empty() {
                anyhow::bail!("tues-provider-{name} produced no hosts");
            }
            hosts
        }
    };
    if hosts.is_empty() {
        anyhow::bail!("no hosts");
    }
    Ok(hosts)
}

/// Non-empty lines, with surrounding whitespace removed.
fn host_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn hosts_from_files(files: &[String]) -> anyhow::Result<Vec<String>> {
    if files.is_empty() {
        anyhow::bail!("file provider requires at least one file");
    }
    let mut hosts = Vec::new();
    let mut saw_stdin = false;
    for path in files {
        let text = if path == "-" {
            if saw_stdin {
                anyhow::bail!("stdin can only be used once");
            }
            saw_stdin = true;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading hosts from stdin")?;
            buf
        } else {
            std::fs::read_to_string(path).with_context(|| format!("reading hosts from {path}"))?
        };
        hosts.extend(host_lines(&text));
    }
    Ok(hosts)
}

fn hosts_from_program(name: &str, args: &[String]) -> anyhow::Result<Vec<String>> {
    if !provider_name_ok(name) {
        anyhow::bail!("not a provider name: {name}");
    }
    let bin = format!("tues-provider-{name}");
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Some(exe) = find_executable(&path, &bin) else {
        anyhow::bail!("no provider executable {bin} on PATH");
    };
    let output = std::process::Command::new(&exe)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .with_context(|| format!("running {bin}"))?;
    if !output.status.success() {
        let detail = match output.status.code() {
            Some(code) => format!("exited with {code}"),
            None => "was terminated by a signal".to_string(),
        };
        anyhow::bail!("{bin} {detail}");
    }
    let text = String::from_utf8(output.stdout)
        .with_context(|| format!("{bin} wrote hosts that are not utf-8"))?;
    Ok(host_lines(&text))
}

/// A provider name is one path segment, so it cannot point at another program.
fn provider_name_ok(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\')
}

/// First executable named `name` on `path_var` (`PATH` syntax).
fn find_executable(path_var: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var).find_map(|dir| {
        let candidate = dir.join(name);
        is_executable(&candidate).then_some(candidate)
    })
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn connect_options(
    cli: &Cli,
    server: &str,
    pm: tues_core::SharedPasswordManager,
    user: Option<&str>,
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
    if let Some(u) = user {
        o = o.user(u.to_string());
    }
    o
}

/// Command-line provider, or the script header when `--script` omits one.
fn selected_provider(
    cli: &Cli,
    defaults: Option<&ScriptDefaults>,
) -> anyhow::Result<(String, Vec<String>)> {
    if let Some((name, args)) = positional_provider(cli)? {
        return Ok((name.to_string(), args.to_vec()));
    }
    if cli.script.is_some() {
        if let Some(name) = defaults.and_then(|d| d.provider.clone()) {
            let args = defaults
                .and_then(|d| d.provider_args.clone())
                .unwrap_or_default();
            return Ok((name, args));
        }
        anyhow::bail!(
            "a provider is required after --script (`cl`, `file`, or a name), or set tues-provider in the script header"
        );
    }
    anyhow::bail!("a provider is required after the command (`cl`, `file`, or a name)");
}

/// Provider token and the arguments that belong to it, when the command line
/// has one. With `--script` the remote command is not a positional, so the
/// provider is the first one.
fn positional_provider(cli: &Cli) -> anyhow::Result<Option<(&str, &[String])>> {
    let provider_at = if cli.script.is_some() { 0 } else { 1 };
    let Some(name) = cli.args.get(provider_at) else {
        return Ok(None);
    };
    // clap's trailing_var_arg + allow_hyphen_values swallows unknown flags into
    // `args`. A provider name that looks like an option is almost always one of
    // those, not a real provider.
    if looks_like_cli_option(name) {
        anyhow::bail!("unexpected argument '{name}'");
    }
    Ok(Some((name, cli.args.get(provider_at + 1..).unwrap_or(&[]))))
}

/// `-` / `--` are positionals; anything else that starts with `-` looks like a flag.
///
/// Unknown tues options must not be taken as the command or provider: with
/// `allow_hyphen_values` on the trailing args, clap would otherwise treat
/// `tues -Q …` as a command of `-Q`.
fn looks_like_cli_option(s: &str) -> bool {
    s.starts_with('-') && s != "-" && s != "--"
}

fn prepare_run(cli: &Cli) -> anyhow::Result<(Run, Option<ScriptDefaults>)> {
    let Some(spec) = cli.script.as_deref() else {
        let Some(command) = cli.args.first() else {
            anyhow::bail!("a command is required");
        };
        if looks_like_cli_option(command) {
            anyhow::bail!("unexpected argument '{command}'");
        }
        return Ok((
            Run {
                command: command.clone(),
                script: None,
                user: cli.user.clone(),
                pty: cli.use_pty(),
                universal_newlines: cli.use_universal_newlines(),
                prefix: cli.prefix_setting(),
                prefix_format: effective_prefix_format(cli, None),
            },
            None,
        ));
    };
    let resolved = resolve_script(spec)?;
    let (user, pty, prefix, prefix_format) = effective_settings(cli, &resolved.defaults);
    let defaults = resolved.defaults;
    Ok((
        Run {
            command: resolved.command,
            script: Some(resolved.file),
            user,
            pty,
            universal_newlines: cli.use_universal_newlines(),
            prefix,
            prefix_format,
        },
        Some(defaults),
    ))
}

/// Command-line flags win. Unset flags keep the script header, and unset
/// header fields keep the usual defaults (no pty, prefix when there are
/// several hosts, default prefix format).
fn effective_settings(
    cli: &Cli,
    defaults: &ScriptDefaults,
) -> (Option<String>, bool, Option<bool>, String) {
    let user = cli.user.clone().or_else(|| defaults.user.clone());
    let pty = if cli.pty || cli.no_pty {
        cli.use_pty()
    } else {
        defaults.pty.unwrap_or(false)
    };
    let prefix = cli.prefix_setting().or(defaults.prefix);
    let prefix_format = effective_prefix_format(cli, Some(defaults));
    (user, pty, prefix, prefix_format)
}

/// `--prefix-format` wins over the script header; otherwise the default template.
fn effective_prefix_format(cli: &Cli, defaults: Option<&ScriptDefaults>) -> String {
    cli.prefix_format
        .clone()
        .or_else(|| defaults.and_then(|d| d.prefix_format.clone()))
        .unwrap_or_else(|| DEFAULT_PREFIX_FORMAT.to_string())
}

struct ResolvedScript {
    file: FileSpec,
    command: String,
    defaults: ScriptDefaults,
}

fn resolve_script(spec: &str) -> anyhow::Result<ResolvedScript> {
    let (name, args) = split_script_spec(spec)?;
    let path = lookup_script(&name)?;
    let remote_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{}: cannot derive a file name", path.display()))?;
    if remote_name == "." || remote_name == ".." {
        anyhow::bail!("{name}: cannot derive a file name");
    }
    let defaults = load_script_defaults(&path)?;
    let command = script_command(&remote_name, &args);
    Ok(ResolvedScript {
        file: FileSpec {
            src: path,
            name: remote_name,
            dst: None,
        },
        command,
        defaults,
    })
}

/// `chmod` so `./name` can run, then the script and the arguments from `SPEC`.
fn script_command(name: &str, args: &[String]) -> String {
    let path = format!("./{name}");
    let mut words = Vec::with_capacity(args.len() + 1);
    words.push(path.clone());
    words.extend(args.iter().cloned());
    format!(
        "chmod u+x {} && {}",
        tues_core::shell::quote(&path),
        tues_core::shell::join(words)
    )
}

fn split_script_spec(spec: &str) -> anyhow::Result<(String, Vec<String>)> {
    let mut words = split_words(spec)?;
    if words.is_empty() {
        anyhow::bail!("empty --script");
    }
    let name = words.remove(0);
    if name.is_empty() {
        anyhow::bail!("empty script name");
    }
    Ok((name, words))
}

/// Split `SPEC` into words. Single and double quotes group a word; a backslash
/// escapes the next character outside quotes, and inside double quotes it
/// escapes `$`, `` ` ``, `"`, `\`, and newline.
fn split_words(spec: &str) -> anyhow::Result<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut chars = spec.chars().peekable();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    cur.push(c);
                }
                in_word = true;
            }
            Some('"') => {
                if c == '\\' {
                    match chars.next() {
                        Some(next @ ('$' | '`' | '"' | '\\' | '\n')) => cur.push(next),
                        Some(next) => {
                            cur.push('\\');
                            cur.push(next);
                        }
                        None => anyhow::bail!("trailing backslash in --script"),
                    }
                } else if c == '"' {
                    quote = None;
                } else {
                    cur.push(c);
                }
                in_word = true;
            }
            Some(_) => unreachable!("only ' and \" open a quote"),
            None => match c {
                ' ' | '\t' | '\n' | '\r' => {
                    if in_word {
                        words.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                '\'' | '"' => quote = Some(c),
                '\\' => match chars.next() {
                    Some(next) => {
                        cur.push(next);
                        in_word = true;
                    }
                    None => anyhow::bail!("trailing backslash in --script"),
                },
                c => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
    }
    if quote.is_some() {
        anyhow::bail!("unclosed quote in --script");
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

fn lookup_script(name: &str) -> anyhow::Result<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        let path = PathBuf::from(name);
        if path.is_file() {
            return Ok(path);
        }
        anyhow::bail!("{}: not a file", path.display());
    }
    let Some(path_var) = std::env::var_os("TUES_PATH") else {
        anyhow::bail!("TUES_PATH is not set");
    };
    find_file(&path_var, name).ok_or_else(|| anyhow::anyhow!("{name}: not found on TUES_PATH"))
}

/// First regular file named `name` on a `PATH`-style list.
fn find_file(path_var: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn load_script_defaults(path: &Path) -> anyhow::Result<ScriptDefaults> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut buf = Vec::new();
    file.by_ref()
        .take(64 * 1024)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading {}", path.display()))?;
    // A NUL means a binary: run it, but do not look for a header.
    if buf.contains(&0) {
        return Ok(ScriptDefaults::default());
    }
    let text = std::str::from_utf8(&buf)
        .with_context(|| format!("{}: script header is not utf-8", path.display()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let header = header_directives(text)?;
    let mut defaults = match header.args {
        Some(json) => {
            parse_tues_args(json).with_context(|| format!("{}: tues-args", path.display()))?
        }
        None => ScriptDefaults::default(),
    };
    if let Some(json) = header.provider {
        defaults.provider = Some(
            parse_provider(json).with_context(|| format!("{}: tues-provider", path.display()))?,
        );
    }
    if let Some(json) = header.provider_args {
        defaults.provider_args = Some(
            parse_provider_args(json)
                .with_context(|| format!("{}: tues-provider-args", path.display()))?,
        );
    }
    if defaults.provider.is_none() && defaults.provider_args.is_some() {
        anyhow::bail!(
            "{}: tues-provider-args requires tues-provider",
            path.display()
        );
    }
    Ok(defaults)
}

/// JSON values from `tues-*` lines in the first comment block.
struct HeaderDirectives<'a> {
    args: Option<&'a str>,
    provider: Option<&'a str>,
    provider_args: Option<&'a str>,
}

fn header_directives(text: &str) -> anyhow::Result<HeaderDirectives<'_>> {
    let mut in_block = false;
    let mut args = None;
    let mut provider = None;
    let mut provider_args = None;
    for line in text.lines() {
        if let Some(body) = comment_body(line) {
            in_block = true;
            // The longer key first: `tues-provider` is a prefix of
            // `tues-provider-args`, and a failed match does not consume the line.
            if let Some(json) = directive_value(body, "tues-provider-args") {
                if provider_args.is_some() {
                    anyhow::bail!("multiple tues-provider-args lines in the script header");
                }
                provider_args = Some(json);
            } else if let Some(json) = directive_value(body, "tues-provider") {
                if provider.is_some() {
                    anyhow::bail!("multiple tues-provider lines in the script header");
                }
                provider = Some(json);
            } else if let Some(json) = directive_value(body, "tues-args") {
                if args.is_some() {
                    anyhow::bail!("multiple tues-args lines in the script header");
                }
                args = Some(json);
            }
        } else if line.trim().is_empty() {
            if in_block {
                break;
            }
        } else {
            break;
        }
    }
    Ok(HeaderDirectives {
        args,
        provider,
        provider_args,
    })
}

/// JSON after `tues-args =` in the first comment block, if that line exists.
#[cfg(test)]
fn header_json(text: &str) -> anyhow::Result<Option<&str>> {
    Ok(header_directives(text)?.args)
}

/// Body of a `#` or `//` comment line, after the marker.
fn comment_body(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    trimmed
        .strip_prefix("//")
        .or_else(|| trimmed.strip_prefix('#'))
}

/// Text after `tues-args =`, ignoring whitespace around the key and the sign.
#[cfg(test)]
fn tues_args_value(body: &str) -> Option<&str> {
    directive_value(body, "tues-args")
}

/// Text after `key =` in a comment body. The next character after the key,
/// aside from whitespace, must be `=`, so `tues-provider` does not match
/// `tues-provider-args`.
fn directive_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let rest = body.trim().strip_prefix(key)?.trim_start();
    Some(rest.strip_prefix('=')?.trim())
}

fn parse_tues_args(json: &str) -> anyhow::Result<ScriptDefaults> {
    let value: serde_json::Value = serde_json::from_str(json).context("invalid tues-args JSON")?;
    let obj = value
        .as_object()
        .context("tues-args must be a JSON object")?;
    let mut defaults = ScriptDefaults::default();
    for (key, value) in obj {
        match key.as_str() {
            "user" => {
                let Some(user) = value.as_str() else {
                    anyhow::bail!("tues-args user must be a string");
                };
                if user.is_empty() {
                    anyhow::bail!("tues-args user must not be empty");
                }
                defaults.user = Some(user.to_string());
            }
            "pty" => {
                let Some(pty) = value.as_bool() else {
                    anyhow::bail!("tues-args pty must be a boolean");
                };
                defaults.pty = Some(pty);
            }
            "prefix" => {
                let Some(prefix) = value.as_bool() else {
                    anyhow::bail!("tues-args prefix must be a boolean");
                };
                defaults.prefix = Some(prefix);
            }
            "prefix-format" => {
                let Some(format) = value.as_str() else {
                    anyhow::bail!("tues-args prefix-format must be a string");
                };
                defaults.prefix_format = Some(format.to_string());
            }
            other => anyhow::bail!("unknown tues-args key: {other}"),
        }
    }
    Ok(defaults)
}

fn parse_provider(json: &str) -> anyhow::Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid tues-provider JSON")?;
    let Some(name) = value.as_str() else {
        anyhow::bail!("tues-provider must be a string");
    };
    if !provider_name_ok(name) {
        anyhow::bail!("not a provider name: {name}");
    }
    Ok(name.to_string())
}

fn parse_provider_args(json: &str) -> anyhow::Result<Vec<String>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid tues-provider-args JSON")?;
    let Some(items) = value.as_array() else {
        anyhow::bail!("tues-provider-args must be a JSON array");
    };
    let mut args = Vec::with_capacity(items.len());
    for item in items {
        let Some(arg) = item.as_str() else {
            anyhow::bail!("tues-provider-args must be an array of strings");
        };
        args.push(arg.to_string());
    }
    Ok(args)
}

async fn run_host(
    cli: &Cli,
    run: &Run,
    server: &str,
    pm: tues_core::SharedPasswordManager,
    prefix: bool,
    stdout: Arc<Mutex<tokio::io::Stdout>>,
    stderr: Arc<Mutex<tokio::io::Stderr>>,
) -> Result<tues_core::ExitStatus, Error> {
    let session = Session::connect(connect_options(cli, server, pm, run.user.as_deref())).await?;
    let mut temporary = Vec::new();
    let uploaded = match upload_files(&session, &cli.files, &mut temporary).await {
        Ok(()) => match &run.script {
            Some(spec) => upload_files(&session, std::slice::from_ref(spec), &mut temporary).await,
            None => Ok(()),
        },
        Err(e) => Err(e),
    };
    let result = match uploaded {
        Ok(()) => {
            run_command(
                &run.command,
                run.pty,
                run.universal_newlines,
                &session,
                server,
                prefix,
                &run.prefix_format,
                stdout,
                stderr,
            )
            .await
        }
        Err(e) => Err(e),
    };
    for path in temporary {
        if let Err(e) = session.delete(&path).await {
            eprintln!("{server}: warning: could not remove {path}: {e}");
        }
    }
    let _ = session.close().await;
    result
}

/// Upload every `--file`. Remote paths of temporary uploads are appended to
/// `temporary` as they succeed, so a failure halfway still cleans up.
async fn upload_files(
    session: &Session,
    files: &[FileSpec],
    temporary: &mut Vec<String>,
) -> Result<(), Error> {
    for spec in files {
        let target = match &spec.dst {
            None => spec.name.clone(),
            Some(dst) => match session.stat(dst).await {
                // Like `cp`: an existing directory receives the file inside it.
                Ok(md) if md.is_dir() => format!("{}/{}", dst.trim_end_matches('/'), spec.name),
                _ => dst.clone(),
            },
        };
        session
            .upload(&spec.src, &target)
            .await
            .map_err(|e| Error::Other(format!("upload {} to {target}: {e}", spec.src.display())))?;
        if spec.is_temporary() {
            temporary.push(target);
        }
    }
    Ok(())
}

async fn run_command(
    command: &str,
    pty: bool,
    universal_newlines: bool,
    session: &Session,
    server: &str,
    prefix: bool,
    prefix_format: &str,
    stdout: Arc<Mutex<tokio::io::Stdout>>,
    stderr: Arc<Mutex<tokio::io::Stderr>>,
) -> Result<tues_core::ExitStatus, Error> {
    let mut cmd = session.shell(command).stdin(Stdio::Null);
    if pty {
        cmd = cmd.pty_config(tues_core::PtyConfig {
            universal_newlines,
            ..tues_core::PtyConfig::default()
        });
    }

    if prefix {
        cmd = cmd.stdout(Stdio::Piped).stderr(Stdio::Piped);
        let mut child = cmd.spawn().await?;
        let out = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        let ctx = PrefixContext::from_session(server, session);
        let out_stream = if pty { "pty" } else { "stdout" };
        let err_stream = if pty { "pty" } else { "stderr" };
        let out_task = tokio::spawn(prefix_lines(
            out,
            render_prefix(prefix_format, &ctx, out_stream),
            stdout,
        ));
        let err_task = tokio::spawn(prefix_lines(
            err,
            render_prefix(prefix_format, &ctx, err_stream),
            stderr,
        ));
        let status = child.wait().await;
        let _ = out_task.await;
        let _ = err_task.await;
        status
    } else {
        cmd = cmd.stdout(Stdio::Inherit).stderr(Stdio::Inherit);
        cmd.status().await
    }
}

/// Host and connection values substituted into a prefix format template.
#[derive(Debug)]
struct PrefixContext<'a> {
    name: &'a str,
    server_ip: String,
    client_port: String,
    server_port: String,
}

impl<'a> PrefixContext<'a> {
    fn from_session(name: &'a str, session: &Session) -> Self {
        let server_ip = session
            .peer_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| session.host().to_string());
        let client_port = session
            .local_port()
            .map(|p| p.to_string())
            .unwrap_or_default();
        let server_port = session.options().port.to_string();
        Self {
            name,
            server_ip,
            client_port,
            server_port,
        }
    }
}

/// Replace `<name>`, `<server-ip>`, `<client-port>`, `<server-port>`, and
/// `<stream>` in `format`. Unknown angle-bracket tokens are left unchanged.
fn render_prefix(format: &str, ctx: &PrefixContext<'_>, stream: &str) -> String {
    let mut out = String::with_capacity(format.len() + ctx.name.len());
    let mut rest = format;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else {
            out.push('<');
            rest = after;
            continue;
        };
        let token = &after[..end];
        let replacement = match token {
            "name" => ctx.name,
            "server-ip" => ctx.server_ip.as_str(),
            "client-port" => ctx.client_port.as_str(),
            "server-port" => ctx.server_port.as_str(),
            "stream" => stream,
            _ => {
                out.push('<');
                out.push_str(token);
                out.push('>');
                rest = &after[end + 1..];
                continue;
            }
        };
        out.push_str(replacement);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use clap::{CommandFactory, Parser};
    use tues_core::{
        Error, ExitStatus, HostKeyPolicy, PasswordKind, PasswordManager, PasswordPrompter,
        PasswordRequest, SecretString,
    };

    use super::{FileSpec, FleetPasswordManager, HostKeyCheck};

    #[test]
    fn host_key_check_maps_onto_the_core_policy() {
        assert_eq!(
            HostKeyPolicy::from(HostKeyCheck::Strict),
            HostKeyPolicy::Strict
        );
        assert_eq!(
            HostKeyPolicy::from(HostKeyCheck::AcceptNew),
            HostKeyPolicy::AcceptNew
        );
        assert_eq!(HostKeyPolicy::from(HostKeyCheck::Off), HostKeyPolicy::Off);
    }

    /// Answers `<login user>-<n>` for the n-th prompt.
    struct CountingPrompter {
        prompts: usize,
    }

    impl PasswordPrompter for CountingPrompter {
        fn prompt(&mut self, req: &PasswordRequest) -> tues_core::Result<SecretString> {
            self.prompts += 1;
            Ok(SecretString::from(format!(
                "{}-{}",
                req.login_user, self.prompts
            )))
        }
    }

    fn reveal(pw: &SecretString) -> &str {
        use tues_core::ExposeSecret;
        pw.expose_secret()
    }

    #[test]
    fn fleet_password_manager_prompts_once_per_login_user_until_invalidated() {
        let mut pm = FleetPasswordManager {
            prompter: CountingPrompter { prompts: 0 },
            cache: HashMap::new(),
        };
        let login = PasswordRequest::login("a.example", 22, "alice");
        let sudo = PasswordRequest {
            kind: PasswordKind::Sudo,
            host: "b.example".into(),
            user: Some("root".into()),
            ..login.clone()
        };
        // A sudo prompt reuses the login password of the same user, on any host.
        assert_eq!(reveal(&pm.get(&login).unwrap()), "alice-1");
        assert_eq!(reveal(&pm.get(&sudo).unwrap()), "alice-1");
        assert_eq!(pm.prompter.prompts, 1);

        // Another login user is a different credential.
        let other = PasswordRequest::login("a.example", 22, "bob");
        assert_eq!(reveal(&pm.get(&other).unwrap()), "bob-2");

        // Rejected on one host: prompt again for everyone.
        pm.invalidate(&sudo);
        assert_eq!(reveal(&pm.get(&login).unwrap()), "alice-3");
        assert_eq!(reveal(&pm.get(&other).unwrap()), "bob-2");

        // Key passphrases are cached per key file.
        let key_a = PasswordRequest {
            kind: PasswordKind::KeyPassphrase,
            key_path: Some("/k/a".into()),
            ..login.clone()
        };
        let key_b = PasswordRequest {
            key_path: Some("/k/b".into()),
            ..key_a.clone()
        };
        assert_eq!(reveal(&pm.get(&key_a).unwrap()), "alice-4");
        assert_eq!(reveal(&pm.get(&key_b).unwrap()), "alice-5");
        assert_eq!(reveal(&pm.get(&key_a).unwrap()), "alice-4");
    }

    #[test]
    fn note_failure_sets_the_exit_code_by_outcome_and_host_count() {
        let mut code = 0;
        assert!(!super::note_failure(
            "h",
            &Ok(ExitStatus::from_code(0)),
            false,
            0,
            &mut code
        ));
        assert_eq!(code, 0);

        // Alone, the host's own exit code is passed through.
        assert!(super::note_failure(
            "h",
            &Ok(ExitStatus::from_code(7)),
            false,
            0,
            &mut code
        ));
        assert_eq!(code, 7);
        assert!(super::note_failure(
            "h",
            &Ok(ExitStatus::from_signal("TERM")),
            false,
            0,
            &mut code
        ));
        assert_eq!(code, 1);
        assert!(super::note_failure(
            "h",
            &Err(Error::Other("boom".into())),
            false,
            0,
            &mut code
        ));
        assert_eq!(code, 255);

        // Among several hosts any failure is 1, quietly unless verbose.
        for verbose in [0, 1] {
            code = 0;
            assert!(super::note_failure(
                "h",
                &Ok(ExitStatus::from_code(7)),
                true,
                verbose,
                &mut code
            ));
            assert_eq!(code, 1);
        }
        code = 0;
        assert!(super::note_failure(
            "h",
            &Err(Error::Other("boom".into())),
            true,
            0,
            &mut code
        ));
        assert_eq!(code, 1);
    }

    #[test]
    fn help_option_text_is_at_most_120_columns() {
        fn assert_width(label: &str, render: impl FnOnce(&mut Vec<u8>)) {
            let mut buf = Vec::new();
            render(&mut buf);
            let help = String::from_utf8(buf).unwrap();
            for (n, line) in help.lines().enumerate() {
                let width = line.chars().count();
                assert!(
                    width <= 120,
                    "{label} line {} is {width} columns:\n{line}",
                    n + 1
                );
            }
        }

        // A wide COLUMNS must not stretch option text past the cap. When this
        // process has no terminal, clap reads COLUMNS; a real terminal is
        // still limited by max_term_width.
        let previous = std::env::var_os("COLUMNS");
        unsafe { std::env::set_var("COLUMNS", "200") };
        assert_width("long help", |buf| {
            super::Cli::command().write_long_help(buf).unwrap();
        });
        assert_width("short help", |buf| {
            super::Cli::command().write_help(buf).unwrap();
        });
        match previous {
            Some(value) => unsafe { std::env::set_var("COLUMNS", value) },
            None => unsafe { std::env::remove_var("COLUMNS") },
        }
    }

    #[test]
    fn parallel_flag_sets_twenty_jobs_unless_a_count_is_given() {
        let cli = super::Cli::try_parse_from(["tues", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.job_count(), 1);

        let cli = super::Cli::try_parse_from(["tues", "-p", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.job_count(), 20);

        let cli = super::Cli::try_parse_from(["tues", "-n", "4", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.job_count(), 4);

        let cli = super::Cli::try_parse_from(["tues", "-p", "--num-jobs", "3", "true", "cl", "h"])
            .unwrap();
        assert_eq!(cli.job_count(), 3);

        let cli =
            super::Cli::try_parse_from(["tues", "--pool-size", "7", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.job_count(), 7);

        let cli = super::Cli::try_parse_from(["tues", "-n", "0", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.job_count(), 1);
    }

    #[test]
    fn legacy_short_aliases_for_check_and_no_prefix() {
        let cli = super::Cli::try_parse_from(["tues", "-c", "true", "cl", "h"]).unwrap();
        assert!(cli.fail_fast());
        let cli = super::Cli::try_parse_from(["tues", "-N", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.prefix_setting(), Some(false));
        let cli = super::Cli::try_parse_from(["tues", "-N", "-P", "true", "cl", "h"]).unwrap();
        assert_eq!(cli.prefix_setting(), Some(true));
    }

    #[test]
    fn universal_newlines_defaults_off_and_overrides() {
        let plain = super::Cli::try_parse_from(["tues", "--pty", "true", "cl", "h"]).unwrap();
        assert!(!plain.use_universal_newlines());
        let on = super::Cli::try_parse_from([
            "tues",
            "--pty",
            "--universal-newlines",
            "true",
            "cl",
            "h",
        ])
        .unwrap();
        assert!(on.use_universal_newlines());
        let off = super::Cli::try_parse_from([
            "tues",
            "--universal-newlines",
            "--no-universal-newlines",
            "true",
            "cl",
            "h",
        ])
        .unwrap();
        assert!(!off.use_universal_newlines());
    }

    #[test]
    fn file_spec_parsing() {
        let plain = FileSpec::parse("dir/app.tar").unwrap();
        assert_eq!(plain.src.to_str(), Some("dir/app.tar"));
        assert_eq!(plain.name, "app.tar");
        assert!(plain.is_temporary());

        let mapped = FileSpec::parse("a.txt:/etc/a").unwrap();
        assert_eq!(mapped.dst.as_deref(), Some("/etc/a"));
        assert!(!mapped.is_temporary());

        let escaped = FileSpec::parse(r"C\:\\x:/tmp/y\:z").unwrap();
        assert_eq!(escaped.src.to_str(), Some(r"C:\x"));
        assert_eq!(escaped.dst.as_deref(), Some("/tmp/y:z"));

        // Only the first unescaped colon separates; the rest belong to DST.
        let colons = FileSpec::parse("f:/a:b").unwrap();
        assert_eq!(colons.dst.as_deref(), Some("/a:b"));

        assert_eq!(FileSpec::parse("f:").unwrap().dst, None);
        assert!(FileSpec::parse("").is_err());
        assert!(FileSpec::parse(r"f\").is_err());
        assert!(FileSpec::parse("..").is_err());
    }

    #[test]
    fn host_lines_skip_blank_lines() {
        assert_eq!(
            super::host_lines(" a \n\n\tb\r\n\n"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn provider_names_are_single_path_segments() {
        assert!(super::provider_name_ok("netbox"));
        assert!(super::provider_name_ok("my.inv"));
        assert!(!super::provider_name_ok(""));
        assert!(!super::provider_name_ok("."));
        assert!(!super::provider_name_ok(".."));
        assert!(!super::provider_name_ok("a/b"));
        assert!(!super::provider_name_ok("a\\b"));
    }

    #[test]
    fn command_and_provider_parse_and_later_options_stay_provider_args() {
        let cli = super::Cli::try_parse_from([
            "tues",
            "--show-hosts",
            "--no-pty",
            "echo hi",
            "netbox",
            "--site",
            "nyc",
            "-",
        ])
        .unwrap();
        assert!(cli.show_hosts);
        assert!(!cli.use_pty());

        let plain = super::Cli::try_parse_from(["tues", "true", "cl", "h"]).unwrap();
        assert!(!plain.use_pty());
        let with_pty = super::Cli::try_parse_from(["tues", "--pty", "true", "cl", "h"]).unwrap();
        assert!(with_pty.use_pty());
        assert_eq!(cli.args[0], "echo hi");
        assert_eq!(
            cli.args,
            vec![
                "echo hi".to_string(),
                "netbox".to_string(),
                "--site".to_string(),
                "nyc".to_string(),
                "-".to_string(),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn find_executable_requires_the_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("tues-provider-lookup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("tues-provider-demo");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = dir.as_os_str();
        assert!(super::find_executable(path, "tues-provider-demo").is_none());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            super::find_executable(path, "tues-provider-demo").as_deref(),
            Some(bin.as_path())
        );
        assert!(super::find_executable(path, "tues-provider-missing").is_none());
        // A directory with the right name is not a provider.
        std::fs::create_dir(dir.join("tues-provider-dir")).unwrap();
        assert!(super::find_executable(path, "tues-provider-dir").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_spec_splits_quoted_words() {
        let (name, args) = super::split_script_spec("my-script --my-option arg").unwrap();
        assert_eq!(name, "my-script");
        assert_eq!(args, ["--my-option", "arg"]);

        let (name, args) = super::split_script_spec("my-script --opt \"a b\" 'c d' e\\ f").unwrap();
        assert_eq!(name, "my-script");
        assert_eq!(args, ["--opt", "a b", "c d", "e f"]);

        assert!(super::split_script_spec("my-script 'unterminated").is_err());
        assert!(super::split_script_spec("   ").is_err());
        assert!(super::split_script_spec("''").is_err());
    }

    #[test]
    fn script_spec_backslashes_follow_shell_rules() {
        // Outside quotes a backslash escapes anything; inside double quotes
        // only the shell's special characters, otherwise it is kept.
        let words = super::split_words(r#"a\ b "c\$d\"e\\f\qg" 'h\i' "j'k""#).unwrap();
        assert_eq!(words, ["a b", r#"c$d"e\f\qg"#, r"h\i", "j'k"]);
        assert_eq!(super::split_words("\"a\\\nb\"").unwrap(), ["a\nb"]);
        assert_eq!(super::split_words("a\tb\r\nc").unwrap(), ["a", "b", "c"]);
        assert_eq!(super::split_words("\"\" x").unwrap(), ["", "x"]);
        assert!(super::split_words("a\\").is_err());
        assert!(super::split_words("\"a\\").is_err());
        assert!(super::split_words("\"open").is_err());
    }

    #[test]
    fn script_with_a_path_is_used_directly() {
        let dir = std::env::temp_dir().join(format!("tues-script-direct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("tool");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        let spec = script.to_str().unwrap();
        assert_eq!(super::lookup_script(spec).unwrap(), script);

        let resolved = super::resolve_script(&format!("{spec} arg")).unwrap();
        assert_eq!(resolved.file.src, script);
        assert_eq!(resolved.file.name, "tool");
        assert!(resolved.file.is_temporary());
        assert_eq!(resolved.command, "chmod u+x ./tool && ./tool arg");
        assert_eq!(resolved.defaults, super::ScriptDefaults::default());

        let missing = dir.join("missing");
        let err = super::lookup_script(missing.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().ends_with("missing: not a file"), "{err}");
        let err = super::lookup_script(dir.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("not a file"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tues_args_values_are_type_checked() {
        fn err(json: &str) -> String {
            super::parse_tues_args(json).unwrap_err().to_string()
        }
        assert!(err("[]").contains("must be a JSON object"));
        assert!(err("nope").contains("invalid tues-args JSON"));
        assert!(err("{\"user\": 1}").contains("user must be a string"));
        assert!(err("{\"user\": \"\"}").contains("user must not be empty"));
        assert!(err("{\"pty\": \"yes\"}").contains("pty must be a boolean"));
        assert!(err("{\"prefix\": 0}").contains("prefix must be a boolean"));
        assert!(err("{\"prefix-format\": true}").contains("prefix-format must be a string"));
        assert!(err("{\"nope\": true}").contains("unknown tues-args key: nope"));
        assert_eq!(
            super::parse_tues_args("{}").unwrap(),
            super::ScriptDefaults::default()
        );
        let parsed =
            super::parse_tues_args("{\"prefix-format\": \"[<name>/<stream>]: \"}").unwrap();
        assert_eq!(parsed.prefix_format.as_deref(), Some("[<name>/<stream>]: "));
    }

    #[test]
    fn prefix_format_interpolates_known_tokens() {
        let ctx = super::PrefixContext {
            name: "web01",
            server_ip: "10.0.0.1".into(),
            client_port: "54321".into(),
            server_port: "22".into(),
        };
        assert_eq!(
            super::render_prefix(super::DEFAULT_PREFIX_FORMAT, &ctx, "stdout"),
            "[web01/stdout]: "
        );
        assert_eq!(
            super::render_prefix(
                "<name> <server-ip>:<server-port> from :<client-port> <stream> <unknown>",
                &ctx,
                "stderr",
            ),
            "web01 10.0.0.1:22 from :54321 stderr <unknown>"
        );
        assert_eq!(super::render_prefix("plain", &ctx, "pty"), "plain");
        assert_eq!(super::render_prefix("a < b", &ctx, "stdout"), "a < b");
    }

    #[test]
    fn script_header_stops_at_a_blank_line_or_code() {
        // No header at all.
        assert_eq!(super::header_json("echo hi\n").unwrap(), None);
        assert_eq!(super::header_json("").unwrap(), None);
        // Blank lines before the first comment do not end the block.
        let leading = "\n\n# tues-args = {\"pty\": true}\n";
        assert_eq!(
            super::header_json(leading).unwrap(),
            Some("{\"pty\": true}")
        );
        // A BOM and a comment marker with nothing after it are fine.
        assert_eq!(super::comment_body("   #"), Some(""));
        assert_eq!(super::comment_body("code # not a comment"), None);
        assert_eq!(super::tues_args_value("tues-args"), None);
        assert_eq!(super::tues_args_value("tues-args-x = {}"), None);
        assert_eq!(super::tues_args_value("  tues-args={ }  "), Some("{ }"));
    }

    #[test]
    fn script_defaults_reject_a_non_utf8_header() {
        let dir = std::env::temp_dir().join(format!("tues-script-utf8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("latin1");
        std::fs::write(&path, b"# caf\xe9\n").unwrap();
        let err = super::load_script_defaults(&path).unwrap_err();
        assert!(err.to_string().contains("not utf-8"), "{err}");

        let bom = dir.join("bom");
        std::fs::write(&bom, "\u{feff}# tues-args = {\"prefix\": false}\n").unwrap();
        assert_eq!(
            super::load_script_defaults(&bom).unwrap().prefix,
            Some(false)
        );

        let err = super::load_script_defaults(&dir.join("absent")).unwrap_err();
        assert!(err.to_string().contains("reading"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_header_is_only_the_top_comment_block() {
        let text = "\
#!/bin/sh
# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": true}

# tues-args = {\"user\": \"other\"}
echo hi
";
        let defaults = super::parse_tues_args(super::header_json(text).unwrap().unwrap()).unwrap();
        assert_eq!(defaults.user.as_deref(), Some("root"));
        assert_eq!(defaults.pty, Some(false));
        assert_eq!(defaults.prefix, Some(true));
        assert_eq!(defaults.prefix_format, None);

        let loose = "#\ttues-args\t=\t{\"pty\": false}\n";
        let defaults = super::parse_tues_args(super::header_json(loose).unwrap().unwrap()).unwrap();
        assert_eq!(defaults.pty, Some(false));

        let slash = "// tues-args={\"user\":\"bob\"}\ncode\n";
        let defaults = super::parse_tues_args(super::header_json(slash).unwrap().unwrap()).unwrap();
        assert_eq!(defaults.user.as_deref(), Some("bob"));

        let after = "#!/bin/sh\necho hi\n# tues-args = {\"user\": \"root\"}\n";
        assert_eq!(super::header_json(after).unwrap(), None);

        let note = "# note tues-args = {\"user\": \"root\"}\n";
        assert_eq!(super::header_json(note).unwrap(), None);

        assert!(super::header_json("# tues-args = {}\n# tues-args = {}\n").is_err());
        assert!(super::parse_tues_args("{\"user\": 1}").is_err());
        assert!(super::parse_tues_args("{\"nope\": true}").is_err());
    }

    #[test]
    fn script_header_reads_provider_lines() {
        let text = "\
#!/bin/sh
# tues-args = {\"pty\": false}
# tues-provider = \"cl\"
# tues-provider-args = [\"web01\", \"web02\"]
echo hi
";
        let header = super::header_directives(text).unwrap();
        assert_eq!(header.args, Some("{\"pty\": false}"));
        assert_eq!(header.provider, Some("\"cl\""));
        assert_eq!(header.provider_args, Some("[\"web01\", \"web02\"]"));

        let loose = "#\ttues-provider\t=\t\"file\"\n// tues-provider-args=[\"hosts\"]\n";
        let header = super::header_directives(loose).unwrap();
        assert_eq!(header.provider, Some("\"file\""));
        assert_eq!(header.provider_args, Some("[\"hosts\"]"));

        let after = "#!/bin/sh\necho hi\n# tues-provider = \"cl\"\n";
        assert_eq!(super::header_directives(after).unwrap().provider, None);

        assert!(
            super::header_directives("# tues-provider = \"a\"\n# tues-provider = \"b\"\n").is_err()
        );
        assert!(
            super::header_directives("# tues-provider-args = []\n# tues-provider-args = []\n")
                .is_err()
        );
        assert_eq!(
            super::directive_value("tues-provider-args = []", "tues-provider"),
            None
        );
    }

    #[test]
    fn provider_values_are_type_checked() {
        fn err_name(json: &str) -> String {
            super::parse_provider(json).unwrap_err().to_string()
        }
        fn err_args(json: &str) -> String {
            super::parse_provider_args(json).unwrap_err().to_string()
        }
        assert!(err_name("[]").contains("must be a string"));
        assert!(err_name("nope").contains("invalid tues-provider JSON"));
        assert!(err_name("\"\"").contains("not a provider name"));
        assert!(err_name("\"a/b\"").contains("not a provider name"));
        assert_eq!(super::parse_provider("\"cl\"").unwrap(), "cl");

        assert!(err_args("{}").contains("must be a JSON array"));
        assert!(err_args("nope").contains("invalid tues-provider-args JSON"));
        assert!(err_args("[1]").contains("array of strings"));
        assert_eq!(
            super::parse_provider_args("[]").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            super::parse_provider_args("[\"a\", \"b\"]").unwrap(),
            ["a", "b"]
        );
    }

    #[test]
    fn command_line_provider_overrides_the_script_header() {
        let defaults = super::ScriptDefaults {
            provider: Some("file".into()),
            provider_args: Some(vec!["header".into()]),
            ..Default::default()
        };
        let cli = super::Cli::try_parse_from(["tues", "-s", "tool", "cl", "web01"]).unwrap();
        let (name, args) = super::selected_provider(&cli, Some(&defaults)).unwrap();
        assert_eq!(name, "cl");
        assert_eq!(args, ["web01"]);

        let cli = super::Cli::try_parse_from(["tues", "-s", "tool"]).unwrap();
        let (name, args) = super::selected_provider(&cli, Some(&defaults)).unwrap();
        assert_eq!(name, "file");
        assert_eq!(args, ["header"]);

        let bare = super::ScriptDefaults {
            provider: Some("cl".into()),
            ..Default::default()
        };
        let (name, args) = super::selected_provider(&cli, Some(&bare)).unwrap();
        assert_eq!(name, "cl");
        assert!(args.is_empty());

        let err = super::selected_provider(&cli, None).unwrap_err();
        assert!(err.to_string().contains("tues-provider"), "{err}");

        let cli = super::Cli::try_parse_from(["tues", "true"]).unwrap();
        let err = super::selected_provider(&cli, None).unwrap_err();
        assert!(err.to_string().contains("after the command"), "{err}");
    }

    #[test]
    fn option_looking_command_or_provider_is_an_unexpected_argument() {
        // Unknown flags must not become the command / provider via trailing_var_arg.
        let cli = super::Cli::try_parse_from(["tues", "-Q", "-p", "-s", "tool", "cl", "h"]).unwrap();
        let err = super::prepare_run(&cli).unwrap_err();
        assert!(
            err.to_string().contains("unexpected argument '-Q'"),
            "{err}"
        );

        let cli = super::Cli::try_parse_from(["tues", "--no-such-flag", "true", "cl", "h"]).unwrap();
        let err = super::prepare_run(&cli).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected argument '--no-such-flag'"),
            "{err}"
        );

        let cli = super::Cli::try_parse_from(["tues", "true", "-Z", "h"]).unwrap();
        let err = super::selected_provider(&cli, None).unwrap_err();
        assert!(
            err.to_string().contains("unexpected argument '-Z'"),
            "{err}"
        );

        let cli = super::Cli::try_parse_from(["tues", "-s", "tool", "--bad", "x"]).unwrap();
        let err = super::selected_provider(&cli, None).unwrap_err();
        assert!(
            err.to_string().contains("unexpected argument '--bad'"),
            "{err}"
        );

        // Provider args may still look like options.
        let cli =
            super::Cli::try_parse_from(["tues", "true", "cl", "--site", "nyc", "-x"]).unwrap();
        let (name, args) = super::selected_provider(&cli, None).unwrap();
        assert_eq!(name, "cl");
        assert_eq!(args, ["--site", "nyc", "-x"]);
    }

    #[test]
    fn provider_args_without_a_provider_are_rejected() {
        let dir = std::env::temp_dir().join(format!("tues-script-provider-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("only-args");
        std::fs::write(&path, "# tues-provider-args = [\"web01\"]\n").unwrap();
        let err = super::load_script_defaults(&path).unwrap_err();
        assert!(
            err.to_string()
                .contains("tues-provider-args requires tues-provider"),
            "{err}"
        );

        let path = dir.join("both");
        std::fs::write(
            &path,
            "# tues-provider = \"cl\"\n# tues-provider-args = [\"web01\"]\n",
        )
        .unwrap();
        let defaults = super::load_script_defaults(&path).unwrap();
        assert_eq!(defaults.provider.as_deref(), Some("cl"));
        assert_eq!(defaults.provider_args.unwrap(), ["web01"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_script_skips_the_header() {
        let dir = std::env::temp_dir().join(format!("tues-script-bin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tool");
        let mut bytes = b"\0ELF".to_vec();
        bytes.extend(b"\n# tues-args = {\"user\": \"root\"}\n");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            super::load_script_defaults(&path).unwrap(),
            super::ScriptDefaults::default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tues_path_finds_the_first_matching_file() {
        let root = std::env::temp_dir().join(format!("tues-script-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let first = root.join("a");
        let second = root.join("b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("tool"), b"first\n").unwrap();
        std::fs::write(second.join("tool"), b"second\n").unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();
        assert_eq!(
            super::find_file(&path, "tool").as_deref(),
            Some(first.join("tool").as_path())
        );
        assert!(super::find_file(&path, "missing").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn script_command_runs_the_uploaded_name() {
        assert_eq!(
            super::script_command("my-script", &["--my-option".into(), "arg".into()]),
            "chmod u+x ./my-script && ./my-script --my-option arg"
        );
        assert_eq!(
            super::script_command("my-script", &["a b".into()]),
            "chmod u+x ./my-script && ./my-script 'a b'"
        );
    }

    #[test]
    fn command_line_overrides_script_defaults() {
        let defaults = super::ScriptDefaults {
            user: Some("root".into()),
            pty: Some(true),
            prefix: Some(true),
            prefix_format: Some("<name>: ".into()),
            ..Default::default()
        };
        let cli = super::Cli::try_parse_from([
            "tues",
            "-u",
            "alice",
            "--no-pty",
            "--no-prefix",
            "--prefix-format",
            "[<stream>] ",
            "-s",
            "tool",
            "cl",
            "h",
        ])
        .unwrap();
        let (user, pty, prefix, prefix_format) = super::effective_settings(&cli, &defaults);
        assert_eq!(user.as_deref(), Some("alice"));
        assert!(!pty);
        assert_eq!(prefix, Some(false));
        assert_eq!(prefix_format, "[<stream>] ");

        let cli = super::Cli::try_parse_from(["tues", "-s", "tool", "cl", "h"]).unwrap();
        let (user, pty, prefix, prefix_format) = super::effective_settings(&cli, &defaults);
        assert_eq!(user.as_deref(), Some("root"));
        assert!(pty);
        assert_eq!(prefix, Some(true));
        assert_eq!(prefix_format, "<name>: ");

        let defaults_off = super::ScriptDefaults {
            prefix: Some(false),
            ..Default::default()
        };
        let cli =
            super::Cli::try_parse_from(["tues", "--prefix", "-s", "tool", "cl", "h"]).unwrap();
        let (user, pty, prefix, prefix_format) = super::effective_settings(&cli, &defaults_off);
        assert_eq!(user, None);
        assert!(!pty);
        assert_eq!(prefix, Some(true));
        assert_eq!(prefix_format, super::DEFAULT_PREFIX_FORMAT);

        let cli = super::Cli::try_parse_from(["tues", "-s", "tool", "cl", "h"]).unwrap();
        let (user, pty, prefix, prefix_format) =
            super::effective_settings(&cli, &super::ScriptDefaults::default());
        assert_eq!(user, None);
        assert!(!pty);
        assert_eq!(prefix, None);
        assert_eq!(prefix_format, super::DEFAULT_PREFIX_FORMAT);
    }

    #[test]
    fn prefix_flag_overrides_no_prefix() {
        let on = super::Cli::try_parse_from(["tues", "--no-prefix", "--prefix", "true", "cl", "h"])
            .unwrap();
        assert_eq!(on.prefix_setting(), Some(true));
        let off =
            super::Cli::try_parse_from(["tues", "--prefix", "--no-prefix", "true", "cl", "h"])
                .unwrap();
        assert_eq!(off.prefix_setting(), Some(false));
        let short = super::Cli::try_parse_from(["tues", "-P", "true", "cl", "h"]).unwrap();
        assert_eq!(short.prefix_setting(), Some(true));
        let plain = super::Cli::try_parse_from(["tues", "true", "cl", "h"]).unwrap();
        assert_eq!(plain.prefix_setting(), None);
    }
}
