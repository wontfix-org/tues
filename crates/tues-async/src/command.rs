use tues_core::{ExitStatus, Output, PtyConfig, Result, Stdio};

use crate::child::Child;
use crate::session::Session;

/// A [`tues_core::Command`] bound to a [`Session`], mirroring
/// [`std::process::Command`] with async launch methods.
#[derive(Debug, Clone)]
pub struct Command {
    session: Session,
    inner: tues_core::Command,
}

impl Command {
    pub(crate) fn new(session: Session, inner: tues_core::Command) -> Self {
        Command { session, inner }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inner.args(args);
        self
    }

    pub fn env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.inner.env(key, val);
        self
    }

    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.inner.envs(vars);
        self
    }

    pub fn env_remove(mut self, key: impl Into<String>) -> Self {
        self.inner.env_remove(key);
        self
    }

    pub fn env_clear(mut self) -> Self {
        self.inner.env_clear();
        self
    }

    pub fn current_dir(mut self, dir: impl Into<String>) -> Self {
        self.inner.current_dir(dir);
        self
    }

    pub fn stdin(mut self, cfg: Stdio) -> Self {
        self.inner.stdin(cfg);
        self
    }

    pub fn stdout(mut self, cfg: Stdio) -> Self {
        self.inner.stdout(cfg);
        self
    }

    pub fn stderr(mut self, cfg: Stdio) -> Self {
        self.inner.stderr(cfg);
        self
    }

    pub fn pty(mut self, enable: bool) -> Self {
        self.inner.pty(enable);
        self
    }

    pub fn pty_config(mut self, cfg: PtyConfig) -> Self {
        self.inner.pty_config(cfg);
        self
    }

    /// Run as `user` via `sudo -u`.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.inner.user(user);
        self
    }

    /// Run as the login user even if the session has a default user.
    pub fn as_login_user(mut self) -> Self {
        self.inner.as_login_user();
        self
    }

    /// Run a shell command with `shell` instead of `sh`.
    pub fn shell_program(mut self, shell: impl Into<String>) -> Self {
        self.inner.shell_program(shell);
        self
    }

    /// The underlying driver-independent command.
    pub fn as_inner(&self) -> &tues_core::Command {
        &self.inner
    }

    pub fn into_inner(self) -> tues_core::Command {
        self.inner
    }

    /// Spawn with piped stdio by default.
    pub async fn spawn(&self) -> Result<Child> {
        self.session.spawn(&self.inner).await
    }

    /// Run and capture output.
    pub async fn output(&self) -> Result<Output> {
        self.session.output(&self.inner).await
    }

    /// Run with inherited stdout/stderr and return the exit status.
    pub async fn status(&self) -> Result<ExitStatus> {
        self.session.status(&self.inner).await
    }
}
