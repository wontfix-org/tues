//! The Sans-IO execution state machine.
//!
//! A driver opens an SSH channel, sends the `exec` request from an
//! [`ExecPlan`], and then feeds every channel message into
//! [`ExecMachine::handle`]. After each event it drains
//! [`ExecMachine::poll_effect`] and performs the effects: writing bytes to the
//! channel, forwarding stdout/stderr to the caller, asking the password
//! manager, and reporting completion.

use std::collections::VecDeque;

use bytes::Bytes;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{Error, Result, SudoError};
use crate::process::{ExecPlan, ExitStatus, Stdio};
use crate::sudo::{Phase, SudoFilter, SudoOutput};

/// Maximum number of sudo password prompts answered before giving up.
pub const MAX_PASSWORD_ATTEMPTS: u32 = 3;

/// Input to the machine.
#[derive(Debug)]
pub enum Event {
    /// Channel data (stdout, or the PTY stream).
    Stdout(Bytes),
    /// Channel extended data type 1 (stderr).
    Stderr(Bytes),
    /// Remote sent EOF.
    Eof,
    /// Remote reported an exit status.
    ExitStatus(u32),
    /// Remote reported termination by signal.
    ExitSignal(String),
    /// Channel closed (or the channel handle was dropped).
    Close,
    /// Reply to [`Effect::RequestPassword`].
    Password(SecretString),
    /// The password manager could not supply a password.
    PasswordUnavailable(Error),
    /// Caller wrote to the child's stdin.
    StdinData(Bytes),
    /// Caller closed the child's stdin.
    StdinEof,
}

/// Output of the machine.
#[derive(Debug)]
pub enum Effect {
    /// Deliver bytes to the caller's stdout handle.
    Stdout(Bytes),
    /// Deliver bytes to the caller's stderr handle.
    Stderr(Bytes),
    /// Write bytes to the channel (remote stdin).
    WriteChannel(Bytes),
    /// Write secret bytes to the channel (the sudo password line).
    WriteChannelSecret(Zeroizing<Vec<u8>>),
    /// Send EOF on the channel.
    ChannelEof,
    /// Ask the password manager for the sudo password. When `retry` is
    /// `true` the previously supplied password was rejected and must be
    /// invalidated first.
    RequestPassword { retry: bool },
    /// The process is finished. Emitted exactly once.
    Finished(Result<ExitStatus>),
}

/// See the [module documentation](self).
#[derive(Debug)]
pub struct ExecMachine {
    sudo: Option<SudoFilter>,
    stdin_null: bool,
    gate_open: bool,
    pending_stdin: Vec<Bytes>,
    pending_stdin_eof: bool,
    channel_eof_sent: bool,
    effects: VecDeque<Effect>,
    exit: Option<ExitStatus>,
    eof: bool,
    finished: bool,
    password_requests: u32,
    password_error: Option<Error>,
}

impl ExecMachine {
    pub fn new(plan: &ExecPlan) -> Self {
        let sudo = plan
            .sudo
            .as_ref()
            .map(|s| SudoFilter::new(s, plan.pty.is_some()));
        let mut m = ExecMachine {
            gate_open: sudo.is_none(),
            sudo,
            stdin_null: plan.stdin == Stdio::Null,
            pending_stdin: Vec::new(),
            pending_stdin_eof: false,
            channel_eof_sent: false,
            effects: VecDeque::new(),
            exit: None,
            eof: false,
            finished: false,
            password_requests: 0,
            password_error: None,
        };
        if m.gate_open && m.stdin_null {
            m.send_channel_eof();
        }
        m
    }

    /// `true` once [`Effect::Finished`] has been produced.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// `true` when caller stdin is being forwarded (no sudo, or sudo done).
    pub fn stdin_open(&self) -> bool {
        self.gate_open
    }

    /// Take the next pending effect.
    pub fn poll_effect(&mut self) -> Option<Effect> {
        self.effects.pop_front()
    }

    pub fn handle(&mut self, event: Event) {
        if self.finished {
            return;
        }
        match event {
            Event::Stdout(b) => self.on_stdout(b),
            Event::Stderr(b) => self.on_stderr(b),
            Event::Eof => {
                self.eof = true;
                self.maybe_finish();
            }
            Event::ExitStatus(code) => {
                self.exit = Some(ExitStatus::from_code(code as i32));
                self.maybe_finish();
            }
            Event::ExitSignal(name) => {
                self.exit = Some(ExitStatus::from_signal(name));
                self.maybe_finish();
            }
            Event::Close => self.finish(),
            Event::Password(secret) => {
                if let Some(f) = &mut self.sudo {
                    let line = f.password_line(secret.expose_secret().as_bytes());
                    self.effects.push_back(Effect::WriteChannelSecret(line));
                }
            }
            Event::PasswordUnavailable(e) => {
                self.password_error = Some(Error::Sudo(SudoError::PasswordRequired {
                    reason: e.to_string(),
                }));
                self.send_channel_eof();
            }
            Event::StdinData(b) => {
                if self.gate_open {
                    self.effects.push_back(Effect::WriteChannel(b));
                } else {
                    self.pending_stdin.push(b);
                }
            }
            Event::StdinEof => {
                if self.gate_open {
                    self.send_channel_eof();
                } else {
                    self.pending_stdin_eof = true;
                }
            }
        }
    }

    fn on_stdout(&mut self, b: Bytes) {
        match &mut self.sudo {
            None => self.effects.push_back(Effect::Stdout(b)),
            Some(f) if f.phase() == Phase::Passthrough => self.effects.push_back(Effect::Stdout(b)),
            Some(f) => {
                let mut outs = Vec::new();
                f.stdout(&b, &mut outs);
                self.apply_sudo_outputs(outs);
            }
        }
    }

    fn on_stderr(&mut self, b: Bytes) {
        match &mut self.sudo {
            None => self.effects.push_back(Effect::Stderr(b)),
            Some(f) if f.phase() == Phase::Passthrough => self.effects.push_back(Effect::Stderr(b)),
            Some(f) => {
                let mut outs = Vec::new();
                f.stderr(&b, &mut outs);
                self.apply_sudo_outputs(outs);
            }
        }
    }

    fn apply_sudo_outputs(&mut self, outs: Vec<SudoOutput>) {
        for o in outs {
            match o {
                SudoOutput::Stdout(b) => self.effects.push_back(Effect::Stdout(b)),
                SudoOutput::Stderr(b) => self.effects.push_back(Effect::Stderr(b)),
                SudoOutput::NeedPassword { retry } => {
                    if self.password_requests >= MAX_PASSWORD_ATTEMPTS {
                        self.password_error = Some(Error::Sudo(SudoError::AuthFailed {
                            attempts: self.password_requests,
                        }));
                        self.send_channel_eof();
                    } else {
                        self.password_requests += 1;
                        self.effects.push_back(Effect::RequestPassword { retry });
                    }
                }
                SudoOutput::Elevated => self.open_gate(),
            }
        }
    }

    fn open_gate(&mut self) {
        if self.gate_open {
            return;
        }
        self.gate_open = true;
        for b in std::mem::take(&mut self.pending_stdin) {
            self.effects.push_back(Effect::WriteChannel(b));
        }
        if self.pending_stdin_eof || self.stdin_null {
            self.send_channel_eof();
        }
    }

    fn send_channel_eof(&mut self) {
        if !self.channel_eof_sent {
            self.channel_eof_sent = true;
            self.effects.push_back(Effect::ChannelEof);
        }
    }

    fn maybe_finish(&mut self) {
        if self.exit.is_some() && self.eof {
            self.finish();
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(f) = &mut self.sudo {
            let mut outs = Vec::new();
            f.finish(&mut outs);
            // Only data can come out of finish(); route it directly.
            for o in outs {
                match o {
                    SudoOutput::Stdout(b) => self.effects.push_back(Effect::Stdout(b)),
                    SudoOutput::Stderr(b) => self.effects.push_back(Effect::Stderr(b)),
                    _ => {}
                }
            }
        }
        let result = self.final_result();
        self.effects.push_back(Effect::Finished(result));
    }

    fn final_result(&mut self) -> Result<ExitStatus> {
        let status = self.exit.clone();
        match &self.sudo {
            Some(f) if !f.elevated() => {
                if let Some(e) = self.password_error.take() {
                    return Err(e);
                }
                if f.prompts_seen() > 0 {
                    return Err(Error::Sudo(SudoError::AuthFailed {
                        attempts: f.passwords_sent(),
                    }));
                }
                Err(Error::Sudo(SudoError::NotStarted {
                    exit_status: status.and_then(|s| s.code()).unwrap_or(-1),
                }))
            }
            _ => status.ok_or_else(|| Error::protocol("channel closed without an exit status")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{Command, SudoPlan};

    fn sudo_plan(pty: bool) -> ExecPlan {
        let mut c = Command::new("cat");
        c.user("root").pty(pty);
        let mut plan = c.plan(Stdio::Piped, None);
        plan.sudo = Some(SudoPlan::with_markers("root".into(), "[P]", "[M]"));
        plan
    }

    fn drain(m: &mut ExecMachine) -> Vec<Effect> {
        let mut v = Vec::new();
        while let Some(e) = m.poll_effect() {
            v.push(e);
        }
        v
    }

    fn stdout_bytes(effects: &[Effect]) -> Vec<u8> {
        let mut v = Vec::new();
        for e in effects {
            if let Effect::Stdout(b) = e {
                v.extend_from_slice(b);
            }
        }
        v
    }

    fn stderr_bytes(effects: &[Effect]) -> Vec<u8> {
        let mut v = Vec::new();
        for e in effects {
            if let Effect::Stderr(b) = e {
                v.extend_from_slice(b);
            }
        }
        v
    }

    #[test]
    fn no_sudo_is_pure_passthrough() {
        let mut c = Command::new("cat");
        c.stdin(Stdio::Null);
        let mut m = ExecMachine::new(&c.plan(Stdio::Piped, None));
        assert!(matches!(drain(&mut m).as_slice(), [Effect::ChannelEof]));
        m.handle(Event::Stdout(Bytes::from_static(
            b"[tues-sudo-x] binary\x00",
        )));
        m.handle(Event::Stderr(Bytes::from_static(b"err")));
        let e = drain(&mut m);
        assert_eq!(stdout_bytes(&e), b"[tues-sudo-x] binary\x00");
        assert_eq!(stderr_bytes(&e), b"err");
        m.handle(Event::ExitStatus(3));
        assert!(drain(&mut m).is_empty());
        m.handle(Event::Eof);
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::Finished(Ok(s))] if s.code() == Some(3)));
        assert!(m.is_finished());
    }

    #[test]
    fn stdin_flows_immediately_without_sudo() {
        let c = Command::new("cat");
        let mut m = ExecMachine::new(&c.plan(Stdio::Piped, None));
        m.handle(Event::StdinData(Bytes::from_static(b"hi")));
        m.handle(Event::StdinEof);
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::WriteChannel(b), Effect::ChannelEof] if b == "hi"));
    }

    #[test]
    fn sudo_conversation_is_removed_and_stdin_is_gated() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        assert!(drain(&mut m).is_empty());
        // Caller writes before sudo is done: must be held.
        m.handle(Event::StdinData(Bytes::from_static(b"input")));
        assert!(drain(&mut m).is_empty());
        m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::RequestPassword { retry: false }]));
        m.handle(Event::Password(SecretString::from("pw")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::WriteChannelSecret(l)] if &l[..] == b"pw\n"));
        // Marker split across chunks, followed by binary payload containing the nonce.
        m.handle(Event::Stdout(Bytes::from_static(b"[M")));
        assert!(drain(&mut m).is_empty());
        m.handle(Event::Stdout(Bytes::from_static(b"]\x00[P][M]pw\n\xff")));
        let e = drain(&mut m);
        assert!(matches!(&e[0], Effect::WriteChannel(b) if b == "input"));
        assert_eq!(stdout_bytes(&e), b"\x00[P][M]pw\n\xff");
        assert!(m.stdin_open());
        m.handle(Event::StdinEof);
        assert!(matches!(drain(&mut m).as_slice(), [Effect::ChannelEof]));
        m.handle(Event::Eof);
        m.handle(Event::ExitStatus(0));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::Finished(Ok(s))] if s.success()));
    }

    #[test]
    fn wrong_password_requests_retry() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
        drain(&mut m);
        m.handle(Event::Password(SecretString::from("bad")));
        drain(&mut m);
        m.handle(Event::Stderr(Bytes::from_static(b"Sorry, try again.\n[P]")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::RequestPassword { retry: true }]));
        m.handle(Event::Password(SecretString::from("good")));
        drain(&mut m);
        m.handle(Event::Stdout(Bytes::from_static(b"[M]ok")));
        let e = drain(&mut m);
        assert_eq!(stdout_bytes(&e), b"ok");
        assert!(stderr_bytes(&e).is_empty());
    }

    #[test]
    fn three_failures_report_auth_failed() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        for _ in 0..3 {
            m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
            let e = drain(&mut m);
            assert!(matches!(&e[..], [Effect::RequestPassword { .. }]));
            m.handle(Event::Password(SecretString::from("bad")));
            drain(&mut m);
            m.handle(Event::Stderr(Bytes::from_static(b"Sorry, try again.\n")));
        }
        m.handle(Event::Stderr(Bytes::from_static(
            b"sudo: 3 incorrect password attempts\n",
        )));
        m.handle(Event::ExitStatus(1));
        m.handle(Event::Eof);
        let e = drain(&mut m);
        assert_eq!(stderr_bytes(&e), b"sudo: 3 incorrect password attempts\n");
        assert!(matches!(
            e.last(),
            Some(Effect::Finished(Err(Error::Sudo(SudoError::AuthFailed {
                attempts: 3
            }))))
        ));
    }

    #[test]
    fn fourth_prompt_is_refused() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        for _ in 0..3 {
            m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
            drain(&mut m);
            m.handle(Event::Password(SecretString::from("bad")));
            drain(&mut m);
        }
        m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::ChannelEof]));
    }

    #[test]
    fn password_unavailable_sends_eof_and_fails() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        m.handle(Event::Stderr(Bytes::from_static(b"[P]")));
        drain(&mut m);
        m.handle(Event::PasswordUnavailable(Error::Password("none".into())));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::ChannelEof]));
        m.handle(Event::Stderr(Bytes::from_static(
            b"\nsudo: no password was provided\n",
        )));
        m.handle(Event::Close);
        let e = drain(&mut m);
        assert!(matches!(
            e.last(),
            Some(Effect::Finished(Err(Error::Sudo(
                SudoError::PasswordRequired { .. }
            ))))
        ));
    }

    #[test]
    fn not_in_sudoers_is_not_started() {
        let mut m = ExecMachine::new(&sudo_plan(false));
        m.handle(Event::Stderr(Bytes::from_static(
            b"x is not in the sudoers file.\n",
        )));
        m.handle(Event::ExitStatus(1));
        m.handle(Event::Eof);
        let e = drain(&mut m);
        assert_eq!(stderr_bytes(&e), b"x is not in the sudoers file.\n");
        assert!(matches!(
            e.last(),
            Some(Effect::Finished(Err(Error::Sudo(SudoError::NotStarted {
                exit_status: 1
            }))))
        ));
    }

    #[test]
    fn nopasswd_opens_gate_without_prompt() {
        let mut plan = sudo_plan(false);
        plan.stdin = Stdio::Null;
        let mut m = ExecMachine::new(&plan);
        assert!(drain(&mut m).is_empty());
        m.handle(Event::Stdout(Bytes::from_static(b"[M]data")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::ChannelEof, Effect::Stdout(b)] if b == "data"));
    }

    #[test]
    fn pty_conversation_is_removed() {
        let mut m = ExecMachine::new(&sudo_plan(true));
        m.handle(Event::Stdout(Bytes::from_static(b"[P]")));
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::RequestPassword { retry: false }]));
        m.handle(Event::Password(SecretString::from("pw")));
        drain(&mut m);
        m.handle(Event::Stdout(Bytes::from_static(b"pw\r\n[M]out\r\n[P]")));
        let e = drain(&mut m);
        assert_eq!(stdout_bytes(&e), b"out\r\n[P]");
        m.handle(Event::ExitStatus(0));
        m.handle(Event::Close);
        let e = drain(&mut m);
        assert!(matches!(&e[..], [Effect::Finished(Ok(_))]));
    }
}
