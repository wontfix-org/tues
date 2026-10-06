//! Remote process model, shaped after [`std::process`].
//!
//! [`Command`] is pure data. Drivers turn it into an [`ExecPlan`] via
//! [`Command::plan`], which renders the remote shell line (with `sudo`
//! wrapping when the command runs as a user other than the login user) and
//! decides how stdio is handled.

use std::fmt;

use crate::shell;

/// How a child stdio stream is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stdio {
    /// Connect the stream to the local process stdio.
    Inherit,
    /// Expose the stream as a pipe on the [`Child`](crate) handle.
    #[default]
    Piped,
    /// Discard output / send EOF immediately.
    Null,
}

impl Stdio {
    pub fn inherit() -> Self {
        Stdio::Inherit
    }
    pub fn piped() -> Self {
        Stdio::Piped
    }
    pub fn null() -> Self {
        Stdio::Null
    }
}

/// Pseudo-terminal request parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyConfig {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

impl Default for PtyConfig {
    fn default() -> Self {
        PtyConfig {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()),
            cols: 80,
            rows: 24,
        }
    }
}

/// Exit status of a remote process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatus(ExitKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExitKind {
    Code(i32),
    Signal(String),
}

impl ExitStatus {
    pub fn from_code(code: i32) -> Self {
        ExitStatus(ExitKind::Code(code))
    }

    pub fn from_signal(name: impl Into<String>) -> Self {
        ExitStatus(ExitKind::Signal(name.into()))
    }

    /// `true` when the process exited with status 0.
    pub fn success(&self) -> bool {
        matches!(self.0, ExitKind::Code(0))
    }

    /// Exit code, if the process exited normally.
    pub fn code(&self) -> Option<i32> {
        match &self.0 {
            ExitKind::Code(c) => Some(*c),
            ExitKind::Signal(_) => None,
        }
    }

    /// Signal name (without `SIG` prefix), if the process was killed by a signal.
    pub fn signal(&self) -> Option<&str> {
        match &self.0 {
            ExitKind::Code(_) => None,
            ExitKind::Signal(s) => Some(s),
        }
    }

    /// Mirror of [`std::process::ExitStatus::exit_ok`] semantics as a plain result.
    pub fn exit_ok(&self) -> Result<(), ExitStatusError> {
        if self.success() {
            Ok(())
        } else {
            Err(ExitStatusError(self.clone()))
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ExitKind::Code(c) => write!(f, "exit status: {c}"),
            ExitKind::Signal(s) => write!(f, "signal: {s}"),
        }
    }
}

/// Error returned by [`ExitStatus::exit_ok`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("process exited unsuccessfully: {0}")]
pub struct ExitStatusError(pub ExitStatus);

/// Captured output of a finished remote process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Program {
    /// `program` + args, quoted individually.
    Argv(String),
    /// A raw shell line, run through `sh -c`.
    Shell(String),
}

/// A remote process builder.
///
/// Mirrors [`std::process::Command`]. All methods are plain data mutations;
/// launching is done by a driver session (`spawn`, `output`, `status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    program: Program,
    args: Vec<String>,
    env: Vec<(String, Option<String>)>,
    env_clear: bool,
    cwd: Option<String>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    pty: Option<PtyConfig>,
    user: CommandUser,
    /// Interpreter for a shell command. `None` means `sh`.
    shell_program: Option<String>,
}

/// Which user a command runs as.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CommandUser {
    /// Use the session's default user (if any).
    #[default]
    Inherit,
    /// Run as the login user, never via `sudo`.
    LoginUser,
    /// Run as this user via `sudo -u`.
    User(String),
}

impl Command {
    /// A command for `program`, which will be executed with no arguments.
    pub fn new(program: impl Into<String>) -> Self {
        Command {
            program: Program::Argv(program.into()),
            args: Vec::new(),
            env: Vec::new(),
            env_clear: false,
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
            pty: None,
            user: CommandUser::Inherit,
            shell_program: None,
        }
    }

    /// A raw shell command line, interpreted by `sh -c` on the remote host.
    ///
    /// [`Command::shell_program`] selects another interpreter. The default
    /// stays `sh` so a shell command is POSIX wherever `sh` is.
    pub fn shell(command_line: impl Into<String>) -> Self {
        let mut c = Command::new("");
        c.program = Program::Shell(command_line.into());
        c
    }

    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(&mut self, key: impl Into<String>, val: impl Into<String>) -> &mut Self {
        self.env.push((key.into(), Some(val.into())));
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env(k, v);
        }
        self
    }

    pub fn env_remove(&mut self, key: impl Into<String>) -> &mut Self {
        self.env.push((key.into(), None));
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.env_clear = true;
        self.env.clear();
        self
    }

    pub fn current_dir(&mut self, dir: impl Into<String>) -> &mut Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn stdin(&mut self, cfg: Stdio) -> &mut Self {
        self.stdin = Some(cfg);
        self
    }

    pub fn stdout(&mut self, cfg: Stdio) -> &mut Self {
        self.stdout = Some(cfg);
        self
    }

    pub fn stderr(&mut self, cfg: Stdio) -> &mut Self {
        self.stderr = Some(cfg);
        self
    }

    /// Request a pseudo-terminal with default settings (`$TERM`, 80x24).
    pub fn pty(&mut self, enable: bool) -> &mut Self {
        self.pty = if enable {
            Some(PtyConfig::default())
        } else {
            None
        };
        self
    }

    /// Request a pseudo-terminal with explicit settings.
    pub fn pty_config(&mut self, cfg: PtyConfig) -> &mut Self {
        self.pty = Some(cfg);
        self
    }

    /// Run the command as `user` via `sudo -u`.
    pub fn user(&mut self, user: impl Into<String>) -> &mut Self {
        self.user = CommandUser::User(user.into());
        self
    }

    /// Run the command as the login user, ignoring the session default.
    pub fn as_login_user(&mut self) -> &mut Self {
        self.user = CommandUser::LoginUser;
        self
    }

    /// Run a shell command with `shell` instead of `sh`.
    ///
    /// `shell` is a program name or path (`bash`, `/bin/zsh`). It is quoted
    /// and invoked as `{shell} -c`. An empty string selects `sh`. Argv
    /// commands ignore this. A session that has resolved the target user's
    /// login shell uses that only when this is unset.
    pub fn shell_program(&mut self, shell: impl Into<String>) -> &mut Self {
        let shell = shell.into();
        self.shell_program = if shell.is_empty() { None } else { Some(shell) };
        self
    }

    /// Interpreter set with [`Command::shell_program`], if any.
    pub fn get_shell_program(&self) -> Option<&str> {
        self.shell_program.as_deref()
    }

    /// Whether this is a shell command (`sh -c` or another interpreter).
    pub fn is_shell(&self) -> bool {
        matches!(self.program, Program::Shell(_))
    }

    pub fn get_program(&self) -> &str {
        match &self.program {
            Program::Argv(p) => p,
            Program::Shell(_) => self.interpreter(None),
        }
    }

    pub fn get_args(&self) -> &[String] {
        &self.args
    }

    pub fn get_current_dir(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    pub fn get_envs(&self) -> &[(String, Option<String>)] {
        &self.env
    }

    pub fn get_user(&self) -> &CommandUser {
        &self.user
    }

    /// The user the command runs as, given the session default.
    ///
    /// `None` means the login user (no `sudo`).
    pub fn effective_user<'a>(&'a self, session_default: Option<&'a str>) -> Option<&'a str> {
        match &self.user {
            CommandUser::Inherit => session_default,
            CommandUser::LoginUser => None,
            CommandUser::User(u) => Some(u.as_str()),
        }
    }

    pub fn get_pty(&self) -> Option<&PtyConfig> {
        self.pty.as_ref()
    }

    pub fn get_stdin(&self) -> Option<Stdio> {
        self.stdin
    }
    pub fn get_stdout(&self) -> Option<Stdio> {
        self.stdout
    }
    pub fn get_stderr(&self) -> Option<Stdio> {
        self.stderr
    }

    /// Program that runs a shell command: the one set on the command, else
    /// `fallback` (a session-resolved login shell), else `sh`.
    fn interpreter<'a>(&'a self, fallback: Option<&'a str>) -> &'a str {
        self.shell_program
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(fallback)
            .unwrap_or("sh")
    }

    /// The command line as it would run without `sudo`, including `cd` and `env`.
    ///
    /// `shell` is used for a shell command when the command did not set one.
    fn plain_command_line(&self, shell: Option<&str>) -> String {
        let mut line = String::new();
        if let Some(dir) = &self.cwd {
            line.push_str("cd ");
            line.push_str(&shell::quote(dir));
            line.push_str(" && ");
        }
        let has_env = self.env_clear || !self.env.is_empty();
        if has_env {
            line.push_str("env");
            if self.env_clear {
                line.push_str(" -i");
            }
            for (k, v) in &self.env {
                match v {
                    Some(v) => {
                        line.push(' ');
                        line.push_str(&shell::quote(&format!("{k}={v}")));
                    }
                    None => {
                        line.push_str(" -u ");
                        line.push_str(&shell::quote(k));
                    }
                }
            }
            line.push(' ');
        }
        match &self.program {
            Program::Argv(p) => {
                line.push_str(&shell::quote(p));
                for a in &self.args {
                    line.push(' ');
                    line.push_str(&shell::quote(a));
                }
            }
            Program::Shell(s) => {
                line.push_str(&shell::quote(self.interpreter(shell)));
                line.push_str(" -c ");
                line.push_str(&shell::quote(s));
                for a in &self.args {
                    line.push(' ');
                    line.push_str(&shell::quote(a));
                }
            }
        }
        line
    }

    /// Render the command into a driver-ready plan.
    ///
    /// `default_stdio` applies to streams the caller did not configure
    /// (e.g. `Piped` for `spawn`, `Inherit` for `status`). `session_user`
    /// is the session's default user for commands that do not set one.
    pub fn plan(&self, default_stdio: Stdio, session_user: Option<&str>) -> ExecPlan {
        self.plan_with(default_stdio, session_user, None)
    }

    /// Like [`Command::plan`], using `shell` for a shell command that did not
    /// set [`Command::shell_program`].
    ///
    /// `shell` is the target user's login shell when the session resolved one.
    /// `None` keeps the default, `sh`.
    pub fn plan_with(
        &self,
        default_stdio: Stdio,
        session_user: Option<&str>,
        shell: Option<&str>,
    ) -> ExecPlan {
        let sudo = self
            .effective_user(session_user)
            .map(|user| SudoPlan::new(user.to_string()));
        let command_line = match &sudo {
            None => self.plain_command_line(shell),
            Some(s) => {
                let script = format!(
                    "printf %s {}; {}",
                    shell::quote(&s.marker_str()),
                    self.plain_command_line(shell)
                );
                format!(
                    "sudo -S -k -p {} -u {} -- /bin/sh -c {}",
                    shell::quote(&s.prompt_str()),
                    shell::quote(&s.user),
                    shell::quote(&script)
                )
            }
        };
        ExecPlan {
            command_line,
            pty: self.pty.clone(),
            stdin: self.stdin.unwrap_or(default_stdio),
            stdout: self.stdout.unwrap_or(default_stdio),
            stderr: self.stderr.unwrap_or(default_stdio),
            sudo,
        }
    }
}

/// Everything the sudo filter needs to know about one elevated execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoPlan {
    /// The user passed to `sudo -u`.
    pub user: String,
    /// The exact bytes sudo prints when asking for a password (`-p`).
    pub prompt: Vec<u8>,
    /// The exact bytes the wrapper script prints once sudo succeeded.
    pub marker: Vec<u8>,
}

impl SudoPlan {
    pub fn new(user: String) -> Self {
        let nonce = nonce();
        SudoPlan {
            user,
            prompt: format!("[tues-sudo-{nonce}]").into_bytes(),
            marker: format!("[tues-ok-{nonce}]").into_bytes(),
        }
    }

    /// Construct with explicit prompt and marker (tests).
    pub fn with_markers(user: String, prompt: &str, marker: &str) -> Self {
        SudoPlan {
            user,
            prompt: prompt.as_bytes().to_vec(),
            marker: marker.as_bytes().to_vec(),
        }
    }

    fn prompt_str(&self) -> String {
        String::from_utf8_lossy(&self.prompt).into_owned()
    }

    fn marker_str(&self) -> String {
        String::from_utf8_lossy(&self.marker).into_owned()
    }
}

/// A rendered command ready for a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    /// The line passed to the SSH `exec` request.
    pub command_line: String,
    pub pty: Option<PtyConfig>,
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,
    pub sudo: Option<SudoPlan>,
}

/// A random hex nonce (128 bits).
pub fn nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_argv_is_quoted() {
        let mut c = Command::new("echo");
        c.arg("hello world").arg("$X");
        assert_eq!(
            c.plan(Stdio::Piped, None).command_line,
            "echo 'hello world' '$X'"
        );
    }

    #[test]
    fn shell_line_goes_through_sh() {
        let c = Command::shell("ls -l | wc -l");
        assert_eq!(
            c.plan(Stdio::Piped, None).command_line,
            "sh -c 'ls -l | wc -l'"
        );
    }

    #[test]
    fn shell_program_replaces_sh_and_wins_over_the_session_shell() {
        let mut c = Command::shell("cat <<<foo");
        c.shell_program("bash");
        assert_eq!(c.get_program(), "bash");
        assert_eq!(c.get_shell_program(), Some("bash"));
        assert_eq!(
            c.plan_with(Stdio::Piped, None, Some("/bin/zsh"))
                .command_line,
            "bash -c 'cat <<<foo'"
        );
        let mut c = Command::shell("echo hi");
        c.user("root").shell_program("/bin/bash");
        let line = c.plan(Stdio::Piped, None).command_line;
        assert!(line.starts_with("sudo "), "{line}");
        assert!(line.contains("/bin/sh -c "), "{line}");
        assert!(line.contains("/bin/bash -c "), "{line}");
        assert!(line.contains("echo hi"), "{line}");
    }

    #[test]
    fn session_shell_is_used_when_the_command_does_not_set_one() {
        let c = Command::shell("echo hi");
        assert_eq!(
            c.plan_with(Stdio::Piped, None, Some("/bin/bash"))
                .command_line,
            "/bin/bash -c 'echo hi'"
        );
        let mut c = Command::shell("echo hi");
        c.shell_program("");
        assert_eq!(c.get_shell_program(), None);
        assert_eq!(
            c.plan_with(Stdio::Piped, None, Some("/bin/bash"))
                .command_line,
            "/bin/bash -c 'echo hi'"
        );
    }

    #[test]
    fn env_and_cwd_are_applied() {
        let mut c = Command::new("prog");
        c.current_dir("/tmp/x y").env("A", "1 2").env_remove("B");
        assert_eq!(
            c.plan(Stdio::Piped, None).command_line,
            "cd '/tmp/x y' && env 'A=1 2' -u B prog"
        );
        let mut c = Command::new("prog");
        c.env_clear().env("A", "1");
        assert_eq!(c.plan(Stdio::Piped, None).command_line, "env -i A=1 prog");
    }

    #[test]
    fn sudo_wraps_and_applies_env_after_elevation() {
        let mut c = Command::new("id");
        c.user("root").env("A", "1");
        let plan = c.plan(Stdio::Piped, None);
        let sudo = plan.sudo.as_ref().unwrap();
        let prompt = String::from_utf8(sudo.prompt.clone()).unwrap();
        let marker = String::from_utf8(sudo.marker.clone()).unwrap();
        assert_eq!(
            plan.command_line,
            format!(
                "sudo -S -k -p '{prompt}' -u root -- /bin/sh -c 'printf %s '\\''{marker}'\\''; env A=1 id'"
            )
        );
    }

    #[test]
    fn stdio_defaults_apply_when_unset() {
        let mut c = Command::new("x");
        c.stdin(Stdio::Null);
        let p = c.plan(Stdio::Inherit, None);
        assert_eq!(p.stdin, Stdio::Null);
        assert_eq!(p.stdout, Stdio::Inherit);
    }

    #[test]
    fn user_precedence() {
        let c = Command::new("id");
        assert!(c.plan(Stdio::Piped, None).sudo.is_none());
        assert_eq!(
            c.plan(Stdio::Piped, Some("root")).sudo.unwrap().user,
            "root"
        );
        let mut c = Command::new("id");
        c.as_login_user();
        assert!(c.plan(Stdio::Piped, Some("root")).sudo.is_none());
        let mut c = Command::new("id");
        c.user("www");
        assert_eq!(c.plan(Stdio::Piped, Some("root")).sudo.unwrap().user, "www");
    }

    #[test]
    fn exit_status_semantics() {
        assert!(ExitStatus::from_code(0).success());
        assert_eq!(ExitStatus::from_code(3).code(), Some(3));
        assert_eq!(ExitStatus::from_signal("KILL").signal(), Some("KILL"));
        assert!(ExitStatus::from_signal("KILL").code().is_none());
        assert_eq!(ExitStatus::from_code(1).to_string(), "exit status: 1");
    }
}
