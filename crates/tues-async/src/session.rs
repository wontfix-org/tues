use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use tues_core::password::PasswordKind;
use tues_core::{
    ConnectOptions, Effect, Error, Event, ExecMachine, ExitStatus, HostKeyPolicy, Output,
    PasswordRequest, ResolvedOptions, Result, SecretString, SharedPasswordManager, Stdio,
};

use crate::child::{Child, spawn_child};
use crate::command::Command;
use crate::sftp::Sftp;

/// An authenticated SSH session.
///
/// Cheap to clone; all clones share one connection. Dropping the last clone
/// closes the connection.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) handle: Handle<ClientHandler>,
    pub(crate) opts: ResolvedOptions,
    closed: AtomicBool,
    /// SFTP channel for [`Session::stat`] and the other file helpers.
    /// Separate from channels returned by [`Session::sftp`].
    files: Mutex<Option<Sftp>>,
    /// Keeps the jump host connection alive for the lifetime of this session.
    _via: Option<Session>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("login_user", &self.inner.opts.login_user)
            .field("host", &self.inner.opts.host_name)
            .field("port", &self.inner.opts.port)
            .finish()
    }
}

impl Session {
    /// Resolve `opts` (including `~/.ssh/config`), connect through any
    /// `ProxyJump` chain, verify the host key and authenticate.
    pub async fn connect(opts: ConnectOptions) -> Result<Session> {
        let resolved = opts.resolve()?;
        Self::connect_resolved(resolved).await
    }

    /// Connect with already resolved options.
    pub async fn connect_resolved(opts: ResolvedOptions) -> Result<Session> {
        let mut via: Option<Session> = None;
        for hop in &opts.proxy_jump {
            let mut hop_opts = opts.for_jump(hop).resolve()?;
            // Nested ProxyJump on a jump host is not followed (loop safety).
            hop_opts.proxy_jump.clear();
            debug!(host = %hop_opts.host_name, port = hop_opts.port, "connecting to jump host");
            via = Some(Self::connect_direct(hop_opts, via).await?);
        }
        Self::connect_direct(opts, via).await
    }

    async fn connect_direct(opts: ResolvedOptions, via: Option<Session>) -> Result<Session> {
        let config = Arc::new(build_config(&opts));
        let handler = ClientHandler {
            host: opts.host_name.clone(),
            port: opts.port,
            policy: opts.host_key_policy,
            user_known_hosts: opts.known_hosts_files.clone(),
            global_known_hosts: opts.global_known_hosts_files.clone(),
        };

        let connect_err = |e: russh::Error| map_connect_error(e, &opts);

        let mut handle = match &via {
            None => {
                let stream = tcp_connect(&opts).await?;
                with_timeout(
                    opts.connect_timeout,
                    client::connect_stream(config, stream, handler),
                )
                .await
                .ok_or_else(|| Error::ConnectTimeout {
                    host: opts.host_name.clone(),
                    port: opts.port,
                })?
                .map_err(connect_err)?
            }
            Some(jump) => {
                let channel = jump
                    .inner
                    .handle
                    .channel_open_direct_tcpip(
                        opts.host_name.clone(),
                        opts.port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| Error::Connect {
                        host: opts.host_name.clone(),
                        port: opts.port,
                        reason: format!("via {}: {e}", jump.inner.opts.host_name),
                    })?;
                let stream = channel.into_stream();
                with_timeout(
                    opts.connect_timeout,
                    client::connect_stream(config, stream, handler),
                )
                .await
                .ok_or_else(|| Error::ConnectTimeout {
                    host: opts.host_name.clone(),
                    port: opts.port,
                })?
                .map_err(connect_err)?
            }
        };

        authenticate(&mut handle, &opts).await?;

        Ok(Session {
            inner: Arc::new(Inner {
                handle,
                opts,
                closed: AtomicBool::new(false),
                files: Mutex::new(None),
                _via: via,
            }),
        })
    }

    /// The resolved connection settings.
    pub fn options(&self) -> &ResolvedOptions {
        &self.inner.opts
    }

    /// The login user.
    pub fn login_user(&self) -> &str {
        &self.inner.opts.login_user
    }

    /// The host name connected to.
    pub fn host(&self) -> &str {
        &self.inner.opts.host_name
    }

    /// The default user commands run as, or `None` for the login user.
    pub fn user(&self) -> Option<&str> {
        self.inner.opts.user.as_deref()
    }

    /// Build a command bound to this session.
    pub fn command(&self, program: impl Into<String>) -> Command {
        Command::new(self.clone(), tues_core::Command::new(program))
    }

    /// Build a raw shell command (`sh -c`) bound to this session.
    pub fn shell(&self, command_line: impl Into<String>) -> Command {
        Command::new(self.clone(), tues_core::Command::shell(command_line))
    }

    /// Spawn a remote process. Unconfigured stdio streams are piped.
    pub async fn spawn(&self, cmd: &tues_core::Command) -> Result<Child> {
        self.spawn_with(cmd, Stdio::Piped).await
    }

    /// Run to completion, capturing stdout and stderr. Stdin is closed.
    pub async fn output(&self, cmd: &tues_core::Command) -> Result<Output> {
        let mut cmd = cmd.clone();
        if cmd.get_stdin().is_none() {
            cmd.stdin(Stdio::Null);
        }
        let child = self.spawn_with(&cmd, Stdio::Piped).await?;
        child.wait_with_output().await
    }

    /// Run to completion with stdout/stderr inherited. Stdin is closed unless
    /// explicitly set to [`Stdio::Inherit`].
    pub async fn status(&self, cmd: &tues_core::Command) -> Result<ExitStatus> {
        let mut cmd = cmd.clone();
        if cmd.get_stdin().is_none() {
            cmd.stdin(Stdio::Null);
        }
        let mut child = self.spawn_with(&cmd, Stdio::Inherit).await?;
        child.wait().await
    }

    pub(crate) async fn spawn_with(
        &self,
        cmd: &tues_core::Command,
        default_stdio: Stdio,
    ) -> Result<Child> {
        self.ensure_open()?;
        let opts = &self.inner.opts;
        let plan = cmd.plan(default_stdio, opts.user.as_deref());
        let password_request = plan.sudo.as_ref().map(|s| {
            PasswordRequest::sudo(
                opts.alias.clone(),
                opts.port,
                opts.login_user.clone(),
                s.user.clone(),
            )
        });

        let channel = self
            .inner
            .handle
            .channel_open_session()
            .await
            .map_err(map_channel_error)?;
        apply_set_env(&channel, &opts.set_env).await?;
        if let Some(pty) = &plan.pty {
            channel
                .request_pty(true, &pty.term, pty.cols, pty.rows, 0, 0, &[])
                .await
                .map_err(map_channel_error)?;
        }
        channel
            .exec(true, plan.command_line.as_bytes().to_vec())
            .await
            .map_err(map_channel_error)?;

        Ok(spawn_child(
            channel,
            plan,
            opts.password_manager.clone(),
            password_request,
            opts.batch_mode,
        ))
    }

    /// Open an SFTP channel.
    ///
    /// With no session user this is the server's `sftp` subsystem, running as
    /// the login user. When the session has a default user, `sftp-server` is
    /// started through the same `sudo -u` handshake as a command, so file
    /// access matches command execution.
    pub async fn sftp(&self) -> Result<Sftp> {
        self.ensure_open()?;
        self.open_sftp().await
    }

    /// Metadata for a remote file or directory (follows symlinks).
    ///
    /// This, [`Session::upload`], [`Session::download`], [`Session::delete`]
    /// and [`Session::rename`] share one SFTP channel. It is opened on the
    /// first call and kept separate from channels returned by [`Session::sftp`].
    pub async fn stat(&self, path: impl Into<String>) -> Result<tues_core::Metadata> {
        self.file_client().await?.metadata(path).await
    }

    /// Copy a local file or directory to `remote`.
    ///
    /// A directory is copied recursively. Symlinks are recreated as symlinks
    /// and are not followed.
    pub async fn upload(&self, local: impl AsRef<Path>, remote: impl Into<String>) -> Result<()> {
        crate::files::upload(&self.file_client().await?, local.as_ref(), &remote.into()).await
    }

    /// Copy a remote file or directory to `local`.
    ///
    /// A directory is copied recursively. Symlinks are recreated as symlinks
    /// and are not followed.
    pub async fn download(&self, remote: impl Into<String>, local: impl AsRef<Path>) -> Result<()> {
        crate::files::download(&self.file_client().await?, &remote.into(), local.as_ref()).await
    }

    /// Remove a remote file, symlink or directory tree.
    ///
    /// A symlink is removed itself; its target is left in place.
    pub async fn delete(&self, path: impl Into<String>) -> Result<()> {
        crate::files::delete(&self.file_client().await?, &path.into()).await
    }

    /// Rename a remote file or directory.
    pub async fn rename(&self, from: impl Into<String>, to: impl Into<String>) -> Result<()> {
        self.file_client().await?.rename(from, to).await
    }

    /// The cached SFTP channel for the file helpers. Opened on first use.
    async fn file_client(&self) -> Result<Sftp> {
        self.ensure_open()?;
        let mut slot = self.inner.files.lock().await;
        if let Some(sftp) = slot.as_ref() {
            return Ok(sftp.clone());
        }
        let sftp = self.open_sftp().await?;
        *slot = Some(sftp.clone());
        Ok(sftp)
    }

    async fn open_sftp(&self) -> Result<Sftp> {
        match self.inner.opts.user.as_deref() {
            Some(user) => self.open_sftp_as(user).await,
            None => self.open_sftp_subsystem().await,
        }
    }

    async fn open_sftp_subsystem(&self) -> Result<Sftp> {
        let channel = self
            .inner
            .handle
            .channel_open_session()
            .await
            .map_err(map_channel_error)?;
        apply_set_env(&channel, &self.inner.opts.set_env).await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(map_channel_error)?;
        Sftp::new(channel.into_stream()).await
    }

    /// Exec `sftp-server` as `user` via sudo, finish the password conversation,
    /// then speak SFTP on the same channel.
    async fn open_sftp_as(&self, user: &str) -> Result<Sftp> {
        let opts = &self.inner.opts;
        let mut cmd = tues_core::Command::shell(SFTP_SERVER_SCRIPT);
        cmd.user(user)
            .stdin(Stdio::Piped)
            .stdout(Stdio::Piped)
            .stderr(Stdio::Piped);
        let plan = cmd.plan(Stdio::Piped, None);
        let password_request = plan.sudo.as_ref().map(|s| {
            PasswordRequest::sudo(
                opts.alias.clone(),
                opts.port,
                opts.login_user.clone(),
                s.user.clone(),
            )
        });

        let mut channel = self
            .inner
            .handle
            .channel_open_session()
            .await
            .map_err(map_channel_error)?;
        apply_set_env(&channel, &opts.set_env).await?;
        channel
            .exec(true, plan.command_line.as_bytes().to_vec())
            .await
            .map_err(map_channel_error)?;

        let mut machine = ExecMachine::new(&plan);
        let mut prefix = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        loop {
            while let Some(effect) = machine.poll_effect() {
                match effect {
                    Effect::Stdout(b) => prefix.extend_from_slice(&b),
                    Effect::Stderr(b) => stderr.extend_from_slice(&b),
                    Effect::WriteChannel(b) => {
                        channel.data(&b[..]).await.map_err(map_channel_error)?;
                    }
                    Effect::WriteChannelSecret(z) => {
                        channel.data(&z[..]).await.map_err(map_channel_error)?;
                    }
                    Effect::ChannelEof => {
                        // Only the failure path (sudo rejected, server missing)
                        // closes stdin. After elevation the server needs it.
                        if !machine.stdin_open() {
                            channel.eof().await.map_err(map_channel_error)?;
                        }
                    }
                    Effect::RequestPassword { retry } => {
                        let Some(req) = password_request.clone() else {
                            machine.handle(Event::PasswordUnavailable(Error::Password(
                                "no sudo context".into(),
                            )));
                            continue;
                        };
                        match request_password(&opts.password_manager, req, retry, opts.batch_mode)
                            .await
                        {
                            Ok(pw) => machine.handle(Event::Password(pw)),
                            Err(e) => machine.handle(Event::PasswordUnavailable(e)),
                        }
                    }
                    Effect::Finished(result) => {
                        let _ = channel.close().await;
                        return Err(sftp_start_error(result, &stderr));
                    }
                }
            }
            if machine.stdin_open() {
                break;
            }
            match channel.wait().await {
                None => machine.handle(Event::Close),
                Some(msg) => {
                    if let Some(ev) = channel_event(msg) {
                        machine.handle(ev);
                    }
                }
            }
        }
        Sftp::with_prefix(prefix, channel.into_stream()).await
    }

    /// Disconnect. Further use of this session (or its clones) fails with
    /// [`Error::Disconnected`].
    pub async fn close(&self) -> Result<()> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(sftp) = self.inner.files.lock().await.take() {
            let _ = sftp.close().await;
        }
        self.inner
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(map_channel_error)
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst) || self.inner.handle.is_closed()
    }

    fn ensure_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(Error::Disconnected)
        } else {
            Ok(())
        }
    }
}

async fn with_timeout<F: std::future::Future>(
    t: Option<std::time::Duration>,
    fut: F,
) -> Option<F::Output> {
    match t {
        Some(t) => tokio::time::timeout(t, fut).await.ok(),
        None => Some(fut.await),
    }
}

fn build_config(opts: &ResolvedOptions) -> client::Config {
    crate::transport::build_client_config(&crate::transport::TransportConfig {
        server_alive_interval: opts.server_alive_interval,
        server_alive_count_max: opts.server_alive_count_max,
        compression: opts.compression,
        ciphers: opts.ciphers.as_deref(),
        macs: opts.macs.as_deref(),
        kex_algorithms: opts.kex_algorithms.as_deref(),
        host_key_algorithms: opts.host_key_algorithms.as_deref(),
        rekey_limit: opts.rekey_limit.as_deref(),
    })
}

fn map_connect_error(e: russh::Error, opts: &ResolvedOptions) -> Error {
    match e {
        russh::Error::UnknownKey => Error::UnknownHostKey {
            host: opts.host_name.clone(),
            port: opts.port,
        },
        russh::Error::KeyChanged { line } => Error::HostKeyChanged {
            host: opts.host_name.clone(),
            port: opts.port,
            line,
        },
        russh::Error::Keys(russh::keys::Error::KeyChanged { line }) => Error::HostKeyChanged {
            host: opts.host_name.clone(),
            port: opts.port,
            line,
        },
        russh::Error::IO(e) => Error::Connect {
            host: opts.host_name.clone(),
            port: opts.port,
            reason: e.to_string(),
        },
        other => Error::Connect {
            host: opts.host_name.clone(),
            port: opts.port,
            reason: other.to_string(),
        },
    }
}

pub(crate) fn map_channel_error(e: russh::Error) -> Error {
    match e {
        russh::Error::SendError | russh::Error::Disconnect | russh::Error::HUP => {
            Error::Disconnected
        }
        russh::Error::IO(e) => Error::Io(e),
        other => Error::protocol(other),
    }
}

/// russh event handler: only host key verification is customised.
pub(crate) struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    /// `UserKnownHostsFile`. A new key is written to the first path.
    user_known_hosts: Vec<PathBuf>,
    /// `GlobalKnownHostsFile`. Consulted only when the user files do not
    /// mention the host, and never written.
    global_known_hosts: Vec<PathBuf>,
}

enum HostKeySeen {
    Match,
    Changed { line: usize },
    Absent,
}

/// Search `files` for `key`. A match wins over a changed key in a later file.
fn lookup_host_key(
    host: &str,
    port: u16,
    key: &PublicKey,
    files: &[PathBuf],
) -> std::result::Result<HostKeySeen, russh::Error> {
    let mut changed = None;
    for path in files {
        match russh::keys::check_known_hosts_path(host, port, key, path) {
            Ok(true) => return Ok(HostKeySeen::Match),
            Ok(false) => {}
            Err(russh::keys::Error::KeyChanged { line }) => changed = Some(line),
            Err(russh::keys::Error::IO(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(match changed {
        Some(line) => HostKeySeen::Changed { line },
        None => HostKeySeen::Absent,
    })
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key: PublicKey = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        match self.policy {
            HostKeyPolicy::Off => Ok(true),
            HostKeyPolicy::Strict | HostKeyPolicy::AcceptNew => {
                // A changed key in a user file is final. The global files are
                // only consulted when the user files do not mention this host.
                match lookup_host_key(&self.host, self.port, &key, &self.user_known_hosts)? {
                    HostKeySeen::Match => return Ok(true),
                    HostKeySeen::Changed { line } => {
                        return Err(russh::Error::KeyChanged { line });
                    }
                    HostKeySeen::Absent => {}
                }
                match lookup_host_key(&self.host, self.port, &key, &self.global_known_hosts)? {
                    HostKeySeen::Match => return Ok(true),
                    HostKeySeen::Changed { line } => {
                        return Err(russh::Error::KeyChanged { line });
                    }
                    HostKeySeen::Absent => {}
                }
                if self.policy == HostKeyPolicy::AcceptNew {
                    let Some(path) = self.user_known_hosts.first() else {
                        return Err(russh::Error::UnknownKey);
                    };
                    warn!(host = %self.host, port = self.port, "adding new host key to {}", path.display());
                    russh::keys::known_hosts::learn_known_hosts_path(
                        &self.host, self.port, &key, path,
                    )?;
                    return Ok(true);
                }
                Err(russh::Error::UnknownKey)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Send `SetEnv` before exec or a subsystem request.
///
/// `want_reply` is false so a server that does not accept the variable does
/// not fail the channel.
async fn apply_set_env(
    channel: &russh::Channel<russh::client::Msg>,
    env: &[(String, String)],
) -> Result<()> {
    for (name, value) in env {
        channel
            .set_env(false, name.as_str(), value.as_str())
            .await
            .map_err(map_channel_error)?;
    }
    Ok(())
}

/// TCP connect, retried `ConnectionAttempts` times with one second between
/// failures. A refused or timed-out socket is retried. Authentication is not.
async fn tcp_connect(opts: &ResolvedOptions) -> Result<TcpStream> {
    let attempts = opts.connection_attempts.max(1);
    let mut last = None;
    for attempt in 1..=attempts {
        match tcp_connect_once(opts).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last = Some(e);
                if attempt < attempts {
                    debug!(
                        attempt,
                        attempts, host = %opts.host_name, "tcp connect failed, retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    Err(last.expect("at least one connection attempt"))
}

async fn tcp_connect_once(opts: &ResolvedOptions) -> Result<TcpStream> {
    let connect = TcpStream::connect((opts.host_name.as_str(), opts.port));
    let stream = match opts.connect_timeout {
        Some(t) => tokio::time::timeout(t, connect)
            .await
            .map_err(|_| Error::ConnectTimeout {
                host: opts.host_name.clone(),
                port: opts.port,
            })?
            .map_err(|e| Error::Connect {
                host: opts.host_name.clone(),
                port: opts.port,
                reason: e.to_string(),
            })?,
        None => connect.await.map_err(|e| Error::Connect {
            host: opts.host_name.clone(),
            port: opts.port,
            reason: e.to_string(),
        })?,
    };
    let _ = stream.set_nodelay(true);
    if opts.tcp_keepalive {
        set_tcp_keepalive(&stream);
    }
    Ok(stream)
}

#[cfg(unix)]
fn set_tcp_keepalive(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    let _ = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
}

#[cfg(not(unix))]
fn set_tcp_keepalive(_stream: &TcpStream) {}

/// Ask the password manager off the executor.
pub(crate) async fn request_password(
    pm: &SharedPasswordManager,
    req: PasswordRequest,
    invalidate_first: bool,
    batch_mode: bool,
) -> Result<SecretString> {
    let pm = pm.clone();
    tokio::task::spawn_blocking(move || {
        let mut guard = pm
            .lock()
            .map_err(|_| Error::Password("password manager lock poisoned".into()))?;
        if invalidate_first {
            guard.invalidate(&req);
        }
        if batch_mode && guard.prompts_for(&req) {
            return Err(Error::Password(
                "batch mode refuses to prompt for a password".into(),
            ));
        }
        guard.get(&req)
    })
    .await
    .map_err(|e| Error::Password(format!("password task failed: {e}")))?
}

async fn authenticate(handle: &mut Handle<ClientHandler>, opts: &ResolvedOptions) -> Result<()> {
    let login_user = opts.login_user.clone();
    let auth_err = |reason: String| Error::Auth {
        login_user: login_user.clone(),
        host: opts.host_name.clone(),
        reason,
    };
    let proto = |e: russh::Error| match e {
        russh::Error::Disconnect
        | russh::Error::HUP
        | russh::Error::RecvError
        | russh::Error::SendError
        | russh::Error::IO(_) => auth_err(
            "server closed the connection during authentication (too many failed attempts?)"
                .to_string(),
        ),
        other => auth_err(format!("protocol error: {other}")),
    };

    let mut tried: Vec<String> = Vec::new();

    // "none" first: succeeds on open servers and tells us the allowed methods.
    match handle
        .authenticate_none(login_user.clone())
        .await
        .map_err(proto)?
    {
        r if r.success() => return Ok(()),
        _ => {}
    }

    for method in &opts.preferred_authentications {
        match method {
            tues_core::AuthMethod::PublicKey => {
                // SSH agent.
                if opts.pubkey_authentication && opts.use_agent && !opts.identities_only {
                    match AgentClient::connect_env().await {
                        Ok(mut agent) => match agent.request_identities().await {
                            Ok(ids) => {
                                for id in ids {
                                    let AgentIdentity::PublicKey { key, comment } = id else {
                                        continue;
                                    };
                                    tried.push(format!("agent key {comment}"));
                                    let hash = rsa_hash(handle, key.algorithm().is_rsa()).await;
                                    match handle
                                        .authenticate_publickey_with(
                                            login_user.clone(),
                                            key,
                                            hash,
                                            &mut agent,
                                        )
                                        .await
                                    {
                                        Ok(r) if r.success() => return Ok(()),
                                        Ok(_) => {}
                                        Err(e) => debug!("agent auth error: {e}"),
                                    }
                                }
                            }
                            Err(e) => debug!("agent identities unavailable: {e}"),
                        },
                        Err(e) => debug!("no ssh agent: {e}"),
                    }
                }

                // Identity files.
                if opts.pubkey_authentication {
                    for path in &opts.identity_files {
                        if !path.is_file() {
                            continue;
                        }
                        tried.push(format!("key {}", path.display()));
                        let key = match load_identity(path, opts).await {
                            Ok(k) => k,
                            Err(e) => {
                                debug!(path = %path.display(), "skipping identity: {e}");
                                continue;
                            }
                        };
                        let hash = rsa_hash(handle, key.algorithm().is_rsa()).await;
                        let r = handle
                            .authenticate_publickey(
                                login_user.clone(),
                                PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                            )
                            .await
                            .map_err(proto)?;
                        if r.success() {
                            return Ok(());
                        }
                    }
                }
            }
            tues_core::AuthMethod::Password => {
                // Password.
                if opts.password_authentication {
                    let req =
                        PasswordRequest::login(opts.alias.clone(), opts.port, login_user.clone());
                    for attempt in 0..3u32 {
                        tried.push("password".into());
                        let pw = match request_password(
                            &opts.password_manager,
                            req.clone(),
                            attempt > 0,
                            opts.batch_mode,
                        )
                        .await
                        {
                            Ok(pw) => pw,
                            Err(e) => {
                                debug!("no login password: {e}");
                                break;
                            }
                        };
                        use tues_core::ExposeSecret;
                        let r = handle
                            .authenticate_password(
                                login_user.clone(),
                                pw.expose_secret().to_string(),
                            )
                            .await
                            .map_err(proto)?;
                        if r.success() {
                            return Ok(());
                        }
                        if let russh::client::AuthResult::Failure {
                            remaining_methods, ..
                        } = &r
                            && !remaining_methods.contains(&russh::MethodKind::Password)
                        {
                            break;
                        }
                    }
                }
            }
            tues_core::AuthMethod::KeyboardInteractive => {
                // Keyboard-interactive, answering every prompt with the login password.
                if opts.kbd_interactive_authentication {
                    let req =
                        PasswordRequest::login(opts.alias.clone(), opts.port, login_user.clone());
                    'outer: for attempt in 0..3u32 {
                        let mut resp = handle
                            .authenticate_keyboard_interactive_start(login_user.clone(), None)
                            .await
                            .map_err(proto)?;
                        let mut pw: Option<SecretString> = None;
                        loop {
                            match resp {
                                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                                KeyboardInteractiveAuthResponse::Failure {
                                    remaining_methods,
                                    ..
                                } => {
                                    tried.push("keyboard-interactive".into());
                                    if !remaining_methods
                                        .contains(&russh::MethodKind::KeyboardInteractive)
                                        || pw.is_none()
                                    {
                                        break 'outer;
                                    }
                                    break;
                                }
                                KeyboardInteractiveAuthResponse::InfoRequest {
                                    prompts, ..
                                } => {
                                    let mut answers = Vec::with_capacity(prompts.len());
                                    for p in &prompts {
                                        if p.echo {
                                            answers.push(String::new());
                                        } else {
                                            if pw.is_none() {
                                                match request_password(
                                                    &opts.password_manager,
                                                    req.clone(),
                                                    attempt > 0,
                                                    opts.batch_mode,
                                                )
                                                .await
                                                {
                                                    Ok(p) => pw = Some(p),
                                                    Err(e) => {
                                                        debug!("no login password: {e}");
                                                        break 'outer;
                                                    }
                                                }
                                            }
                                            use tues_core::ExposeSecret;
                                            answers.push(
                                                pw.as_ref()
                                                    .map(|p| p.expose_secret().to_string())
                                                    .unwrap_or_default(),
                                            );
                                        }
                                    }
                                    resp = handle
                                        .authenticate_keyboard_interactive_respond(answers)
                                        .await
                                        .map_err(proto)?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let reason = if tried.is_empty() {
        "no authentication method available".to_string()
    } else {
        format!("all methods failed ({})", tried.join(", "))
    };
    Err(auth_err(reason))
}

async fn rsa_hash(handle: &Handle<ClientHandler>, is_rsa: bool) -> Option<russh::keys::HashAlg> {
    if !is_rsa {
        return None;
    }
    match handle.best_supported_rsa_hash().await {
        Ok(Some(h)) => h,
        _ => Some(russh::keys::HashAlg::Sha256),
    }
}

/// Load a private key, asking the password manager for a passphrase when needed.
async fn load_identity(path: &Path, opts: &ResolvedOptions) -> Result<PrivateKey> {
    match load_secret_key(path, None) {
        Ok(k) => return Ok(k),
        Err(russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
    }
    let req = PasswordRequest::key_passphrase(
        opts.alias.clone(),
        opts.port,
        opts.login_user.clone(),
        path.to_path_buf(),
    );
    debug_assert_eq!(req.kind, PasswordKind::KeyPassphrase);
    for attempt in 0..3u32 {
        let pw = request_password(
            &opts.password_manager,
            req.clone(),
            attempt > 0,
            opts.batch_mode,
        )
        .await?;
        use tues_core::ExposeSecret;
        match load_secret_key(path, Some(pw.expose_secret())) {
            Ok(k) => return Ok(k),
            Err(russh::keys::Error::KeyIsEncrypted) => continue,
            Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
        }
    }
    Err(Error::Password(format!(
        "could not decrypt {}",
        path.display()
    )))
}

/// Shell snippet that replaces itself with the first `sftp-server` binary found.
const SFTP_SERVER_SCRIPT: &str = "\
for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server \
/usr/libexec/sftp-server /usr/lib/ssh/sftp-server; do \
if [ -x \"$p\" ]; then exec \"$p\"; fi; \
done; \
echo 'tues: sftp-server binary not found' >&2; exit 127";

fn sftp_start_error(result: Result<ExitStatus>, stderr: &[u8]) -> Error {
    let detail = String::from_utf8_lossy(stderr).trim().to_string();
    match result {
        Err(e) if detail.is_empty() => e,
        Err(e) => Error::Sftp(format!("{e} ({detail})")),
        Ok(status) if detail.is_empty() => Error::Sftp(format!("sftp server exited ({status})")),
        Ok(status) => Error::Sftp(format!("sftp server exited ({status}): {detail}")),
    }
}

/// Convert a russh channel message into a machine event.
pub(crate) fn channel_event(msg: ChannelMsg) -> Option<tues_core::Event> {
    use tues_core::Event;
    Some(match msg {
        ChannelMsg::Data { data } => Event::Stdout(data),
        ChannelMsg::ExtendedData { data, ext } => {
            if ext == 1 {
                Event::Stderr(data)
            } else {
                return None;
            }
        }
        ChannelMsg::Eof => Event::Eof,
        ChannelMsg::Close => Event::Close,
        ChannelMsg::ExitStatus { exit_status } => Event::ExitStatus(exit_status),
        ChannelMsg::ExitSignal { signal_name, .. } => Event::ExitSignal(sig_name(&signal_name)),
        _ => return None,
    })
}

fn sig_name(sig: &russh::Sig) -> String {
    match sig {
        russh::Sig::Custom(c) => c.clone(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler;
    use russh::keys::PublicKeyOrCertificate;
    use russh::keys::{HashAlg, PublicKey};

    const RIGHT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAoIklq5yCSn6F3wL5UfOaCzeTBwcAtrGXrBgd1goMPE";
    const WRONG: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMaDVVxNQwFJldz6Ol9xCq13sCcXGR2we7DpTeCxDXd";

    fn key(openssh: &str) -> PublicKey {
        PublicKey::from_openssh(openssh).unwrap()
    }

    fn write_host(path: &Path, host: &str, openssh: &str) {
        std::fs::write(path, format!("{host} {openssh}\n")).unwrap();
    }

    fn handler(user: PathBuf, global: PathBuf, policy: HostKeyPolicy) -> ClientHandler {
        ClientHandler {
            host: "box.example".into(),
            port: 22,
            policy,
            user_known_hosts: vec![user],
            global_known_hosts: vec![global],
        }
    }

    async fn check(
        handler: &mut ClientHandler,
        openssh: &str,
    ) -> std::result::Result<bool, russh::Error> {
        handler
            .check_server_key(&PublicKeyOrCertificate::PublicKey {
                key: key(openssh),
                hash_alg: None::<HashAlg>,
            })
            .await
    }

    #[tokio::test]
    async fn global_file_is_used_only_when_the_user_file_does_not_mention_the_host() {
        let dir = std::env::temp_dir().join(format!("tues-gkh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let user = dir.join("user");
        let global = dir.join("global");
        write_host(&global, "box.example", RIGHT);
        std::fs::write(&user, "").unwrap();

        let mut strict = handler(user.clone(), global.clone(), HostKeyPolicy::Strict);
        assert!(check(&mut strict, RIGHT).await.unwrap());

        write_host(&user, "box.example", WRONG);
        // Unreadable as a known_hosts line. A user-file match must not open it.
        std::fs::write(&global, "not a known_hosts file\n").unwrap();
        assert!(check(&mut strict, WRONG).await.unwrap());

        write_host(&global, "box.example", RIGHT);
        let err = check(&mut strict, RIGHT).await.unwrap_err();
        assert!(matches!(err, russh::Error::KeyChanged { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn accept_new_appends_to_the_user_file_only() {
        let dir = std::env::temp_dir().join(format!("tues-gkh-learn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let user = dir.join("user");
        let global = dir.join("global");
        std::fs::write(&user, "").unwrap();
        std::fs::write(&global, "").unwrap();
        let mut learning = handler(user.clone(), global.clone(), HostKeyPolicy::AcceptNew);
        assert!(check(&mut learning, RIGHT).await.unwrap());
        assert!(
            std::fs::read_to_string(&user)
                .unwrap()
                .contains("box.example")
        );
        assert!(std::fs::read_to_string(&global).unwrap().is_empty());

        learning.user_known_hosts.clear();
        let err = check(&mut learning, WRONG).await.unwrap_err();
        assert!(matches!(err, russh::Error::UnknownKey));
        assert!(std::fs::read_to_string(&global).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct Prompting;
    impl tues_core::PasswordManager for Prompting {
        fn get(&mut self, _: &PasswordRequest) -> Result<SecretString> {
            panic!("batch mode must not prompt");
        }
        fn invalidate(&mut self, _: &PasswordRequest) {}
    }

    #[tokio::test]
    async fn batch_mode_refuses_a_prompt_and_keeps_a_known_password() {
        let req = PasswordRequest::login("h", 22, "u");
        let prompting = tues_core::shared(Prompting);
        let err = request_password(&prompting, req.clone(), false, true)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Password(_)));

        let known = tues_core::shared(tues_core::StaticPasswordManager::new("secret"));
        let pw = request_password(&known, req, false, true).await.unwrap();
        use tues_core::ExposeSecret;
        assert_eq!(pw.expose_secret(), "secret");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tcp_keepalive_sets_so_keepalive() {
        use std::os::fd::AsRawFd;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        set_tcp_keepalive(&stream);
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&val) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(val, 1);
    }
}
