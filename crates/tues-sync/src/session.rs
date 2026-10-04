use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use tues_core::{ConnectOptions, ExitStatus, Metadata, Output, ResolvedOptions, Result};

use crate::Runtime;
use crate::child::Child;
use crate::command::Command;
use crate::sftp::Sftp;

/// A blocking SSH session.
///
/// Cheap to clone; clones share the connection and runtime.
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: tues_async::Session,
    pub(crate) rt: Arc<Runtime>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl Session {
    /// Resolve options, connect (through any `ProxyJump`), verify the host
    /// key and authenticate.
    pub fn connect(opts: ConnectOptions) -> Result<Session> {
        let rt = Runtime::new()?;
        let inner = rt.block_on(tues_async::Session::connect(opts))?;
        Ok(Session { inner, rt })
    }

    /// Connect with already resolved options.
    pub fn connect_resolved(opts: ResolvedOptions) -> Result<Session> {
        let rt = Runtime::new()?;
        let inner = rt.block_on(tues_async::Session::connect_resolved(opts))?;
        Ok(Session { inner, rt })
    }

    /// The underlying async session, usable from `self.runtime()`.
    pub fn async_session(&self) -> &tues_async::Session {
        &self.inner
    }

    /// Handle of the runtime driving this session.
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        self.rt.handle()
    }

    /// Run a future on this session's runtime, blocking the caller.
    pub fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    pub fn options(&self) -> &ResolvedOptions {
        self.inner.options()
    }

    pub fn login_user(&self) -> &str {
        self.inner.login_user()
    }

    pub fn host(&self) -> &str {
        self.inner.host()
    }

    /// Peer IP of a direct TCP connection, or `None` when connected via a jump host.
    pub fn peer_ip(&self) -> Option<IpAddr> {
        self.inner.peer_ip()
    }

    /// Local TCP port of a direct connection, or `None` when connected via a jump host.
    pub fn local_port(&self) -> Option<u16> {
        self.inner.local_port()
    }

    pub fn user(&self) -> Option<&str> {
        self.inner.user()
    }

    pub fn command(&self, program: impl Into<String>) -> Command {
        Command::new(self.clone(), tues_core::Command::new(program))
    }

    pub fn shell(&self, command_line: impl Into<String>) -> Command {
        Command::new(self.clone(), tues_core::Command::shell(command_line))
    }

    /// Spawn with piped stdio by default.
    pub fn spawn(&self, cmd: &tues_core::Command) -> Result<Child> {
        let child = self.rt.block_on(self.inner.spawn(cmd))?;
        Ok(Child::new(child, self.rt.clone()))
    }

    /// Run to completion, capturing output.
    pub fn output(&self, cmd: &tues_core::Command) -> Result<Output> {
        self.rt.block_on(self.inner.output(cmd))
    }

    /// Run to completion with inherited stdout/stderr.
    pub fn status(&self, cmd: &tues_core::Command) -> Result<ExitStatus> {
        self.rt.block_on(self.inner.status(cmd))
    }

    /// Metadata for a remote file or directory (follows symlinks).
    ///
    /// This, [`Session::upload`], [`Session::download`], [`Session::delete`]
    /// and [`Session::rename`] share one SFTP channel, opened on the first
    /// call and kept separate from [`Session::sftp`].
    pub fn stat(&self, path: impl Into<String>) -> Result<Metadata> {
        let path = path.into();
        let inner = self.inner.clone();
        self.rt.block_on(inner.stat(path))
    }

    /// Copy a local file or directory to `remote`.
    ///
    /// A directory is copied recursively. Symlinks are recreated as symlinks
    /// and are not followed.
    pub fn upload(&self, local: impl AsRef<Path>, remote: impl Into<String>) -> Result<()> {
        let local = local.as_ref().to_path_buf();
        let remote = remote.into();
        let inner = self.inner.clone();
        self.rt.block_on(inner.upload(local, remote))
    }

    /// Copy a remote file or directory to `local`.
    ///
    /// A directory is copied recursively. Symlinks are recreated as symlinks
    /// and are not followed.
    pub fn download(&self, remote: impl Into<String>, local: impl AsRef<Path>) -> Result<()> {
        let remote = remote.into();
        let local = local.as_ref().to_path_buf();
        let inner = self.inner.clone();
        self.rt.block_on(inner.download(remote, local))
    }

    /// Remove a remote file, symlink or directory tree.
    ///
    /// A symlink is removed itself; its target is left in place.
    pub fn delete(&self, path: impl Into<String>) -> Result<()> {
        let path = path.into();
        let inner = self.inner.clone();
        self.rt.block_on(inner.delete(path))
    }

    /// Rename a remote file or directory.
    pub fn rename(&self, from: impl Into<String>, to: impl Into<String>) -> Result<()> {
        let from = from.into();
        let to = to.into();
        let inner = self.inner.clone();
        self.rt.block_on(inner.rename(from, to))
    }

    /// Open an SFTP channel.
    ///
    /// Runs as the session's default user (via `sudo`) when one is set, and
    /// as the login user otherwise. This channel is not the one used by
    /// [`Session::stat`] and the other file helpers.
    pub fn sftp(&self) -> Result<Sftp> {
        let sftp = self.rt.block_on(self.inner.sftp())?;
        Ok(Sftp::new(sftp, self.rt.clone()))
    }

    pub fn close(&self) -> Result<()> {
        self.rt.block_on(self.inner.close())
    }

    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}
