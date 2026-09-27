//! Stream filter that removes the sudo password conversation from a
//! remote command's output.
//!
//! The filter has two phases:
//!
//! * **Hold** — output is buffered and scanned for the sudo prompt and for
//!   the success marker printed by the wrapper script. Prompts, wrong-password
//!   diagnostics and password echoes are deleted. Other diagnostics (lecture,
//!   warnings) are kept.
//! * **Passthrough** — once the marker has been seen every byte is forwarded
//!   untouched. No scanning happens in this phase, so binary payloads that
//!   happen to contain the nonce are never altered.
//!
//! In non-PTY mode sudo prompts on stderr and the marker arrives on stdout;
//! the two streams are filtered independently. In PTY mode everything shares
//! one stream and the same scanner handles both.

use bytes::Bytes;
use zeroize::Zeroizing;

use crate::process::SudoPlan;

const SORRY: &[u8] = b"Sorry, try again.";
/// Fail-safe: if this much output accumulates before a marker, give up
/// scanning and pass everything through.
const MAX_HOLD: usize = 1 << 20;

/// Filter phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Hold,
    Passthrough,
    Done,
}

/// Output of feeding bytes to the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SudoOutput {
    Stdout(Bytes),
    Stderr(Bytes),
    /// sudo printed its prompt. `retry` is `true` when a password had already
    /// been sent, i.e. the previous one was wrong.
    NeedPassword {
        retry: bool,
    },
    /// The success marker was seen; the command is running.
    Elevated,
}

/// See the [module documentation](self).
#[derive(Debug)]
pub struct SudoFilter {
    prompt: Vec<u8>,
    marker: Vec<u8>,
    pty: bool,
    phase: Phase,
    out_buf: Vec<u8>,
    err_buf: Vec<u8>,
    prompts_seen: u32,
    passwords_sent: u32,
    last_password: Option<Zeroizing<Vec<u8>>>,
    /// Strip leading CR/LF from the next held segment (echo of our newline).
    after_prompt: bool,
    elevated: bool,
}

impl SudoFilter {
    pub fn new(plan: &SudoPlan, pty: bool) -> Self {
        SudoFilter {
            prompt: plan.prompt.clone(),
            marker: plan.marker.clone(),
            pty,
            phase: Phase::Hold,
            out_buf: Vec::new(),
            err_buf: Vec::new(),
            prompts_seen: 0,
            passwords_sent: 0,
            last_password: None,
            after_prompt: false,
            elevated: false,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// `true` once the marker has been observed.
    pub fn elevated(&self) -> bool {
        self.elevated
    }

    pub fn prompts_seen(&self) -> u32 {
        self.prompts_seen
    }

    pub fn passwords_sent(&self) -> u32 {
        self.passwords_sent
    }

    /// Record a password about to be written to the channel and return the
    /// exact line to write. The recorded bytes are used to remove a PTY echo.
    pub fn password_line(&mut self, password: &[u8]) -> Zeroizing<Vec<u8>> {
        self.passwords_sent += 1;
        self.last_password = Some(Zeroizing::new(password.to_vec()));
        let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        line.extend_from_slice(password);
        line.push(b'\n');
        line
    }

    /// Feed bytes received on the channel's stdout (or the PTY stream).
    pub fn stdout(&mut self, data: &[u8], out: &mut Vec<SudoOutput>) {
        match self.phase {
            Phase::Passthrough => out.push(SudoOutput::Stdout(Bytes::copy_from_slice(data))),
            Phase::Done => {}
            Phase::Hold => {
                self.out_buf.extend_from_slice(data);
                if self.pty {
                    self.scan_pty(out);
                } else {
                    self.scan_stdout_for_marker(out);
                }
            }
        }
    }

    /// Feed bytes received on the channel's stderr.
    pub fn stderr(&mut self, data: &[u8], out: &mut Vec<SudoOutput>) {
        match self.phase {
            Phase::Passthrough => out.push(SudoOutput::Stderr(Bytes::copy_from_slice(data))),
            Phase::Done => {}
            Phase::Hold => {
                self.err_buf.extend_from_slice(data);
                while let Some(i) = find(&self.err_buf, &self.prompt) {
                    let pre = self.err_buf[..i].to_vec();
                    self.err_buf.drain(..i + self.prompt.len());
                    let pre = self.clean(&pre);
                    if !pre.is_empty() {
                        out.push(SudoOutput::Stderr(Bytes::from(pre)));
                    }
                    self.on_prompt(out);
                }
                if self.err_buf.len() > MAX_HOLD {
                    self.flush_err(out);
                }
            }
        }
    }

    /// The channel is finished: release everything still held.
    pub fn finish(&mut self, out: &mut Vec<SudoOutput>) {
        if self.phase == Phase::Hold {
            let held = std::mem::take(&mut self.out_buf);
            let held = if self.pty { self.clean(&held) } else { held };
            if !held.is_empty() {
                out.push(SudoOutput::Stdout(Bytes::from(held)));
            }
            self.flush_err(out);
        }
        self.phase = Phase::Done;
        self.last_password = None;
    }

    fn on_prompt(&mut self, out: &mut Vec<SudoOutput>) {
        self.prompts_seen += 1;
        self.after_prompt = true;
        out.push(SudoOutput::NeedPassword {
            retry: self.passwords_sent > 0,
        });
    }

    fn enter_passthrough(&mut self, elevated: bool, out: &mut Vec<SudoOutput>) {
        self.flush_err(out);
        self.phase = Phase::Passthrough;
        self.elevated = elevated;
        self.last_password = None;
        out.push(SudoOutput::Elevated);
    }

    fn flush_err(&mut self, out: &mut Vec<SudoOutput>) {
        let held = std::mem::take(&mut self.err_buf);
        let held = self.clean(&held);
        if !held.is_empty() {
            out.push(SudoOutput::Stderr(Bytes::from(held)));
        }
    }

    /// Non-PTY stdout: nothing but the marker may legitimately arrive before
    /// the command starts.
    fn scan_stdout_for_marker(&mut self, out: &mut Vec<SudoOutput>) {
        if self.out_buf.starts_with(&self.marker) {
            let rest = self.out_buf.split_off(self.marker.len());
            self.out_buf.clear();
            self.enter_passthrough(true, out);
            if !rest.is_empty() {
                out.push(SudoOutput::Stdout(Bytes::from(rest)));
            }
        } else if self.marker.starts_with(&self.out_buf) {
            // Still a prefix of the marker: wait for more bytes.
        } else {
            // Unexpected stdout before the marker. Never lose data: pass it on.
            let held = std::mem::take(&mut self.out_buf);
            self.enter_passthrough(false, out);
            out.push(SudoOutput::Stdout(Bytes::from(held)));
        }
    }

    /// PTY: prompt, echo, diagnostics and marker all share one stream.
    fn scan_pty(&mut self, out: &mut Vec<SudoOutput>) {
        loop {
            let p = find(&self.out_buf, &self.prompt);
            let m = find(&self.out_buf, &self.marker);
            enum Next {
                Prompt(usize),
                Marker(usize),
                Nothing,
            }
            let next = match (p, m) {
                (Some(i), Some(j)) if i < j => Next::Prompt(i),
                (Some(i), None) => Next::Prompt(i),
                (_, Some(j)) => Next::Marker(j),
                (None, None) => Next::Nothing,
            };
            match next {
                Next::Prompt(i) => {
                    let pre = self.out_buf[..i].to_vec();
                    self.out_buf.drain(..i + self.prompt.len());
                    let pre = self.clean(&pre);
                    if !pre.is_empty() {
                        out.push(SudoOutput::Stdout(Bytes::from(pre)));
                    }
                    self.on_prompt(out);
                }
                Next::Marker(j) => {
                    let pre = self.out_buf[..j].to_vec();
                    let rest = self.out_buf.split_off(j + self.marker.len());
                    self.out_buf.clear();
                    let pre = self.clean(&pre);
                    if !pre.is_empty() {
                        out.push(SudoOutput::Stdout(Bytes::from(pre)));
                    }
                    self.enter_passthrough(true, out);
                    if !rest.is_empty() {
                        out.push(SudoOutput::Stdout(Bytes::from(rest)));
                    }
                    return;
                }
                Next::Nothing => {
                    if self.out_buf.len() > MAX_HOLD {
                        let held = std::mem::take(&mut self.out_buf);
                        self.enter_passthrough(false, out);
                        out.push(SudoOutput::Stdout(Bytes::from(held)));
                    }
                    return;
                }
            }
        }
    }

    /// Remove wrong-password diagnostics, password echoes and echo residue
    /// from a held segment.
    fn clean(&mut self, data: &[u8]) -> Vec<u8> {
        let mut v = remove_all_followed_by_newline(data, SORRY);
        if let Some(pw) = self.last_password.as_ref().filter(|pw| !pw.is_empty()) {
            v = remove_all_followed_by_newline(&v, pw);
        }
        if self.after_prompt {
            let skip = v
                .iter()
                .take_while(|b| **b == b'\r' || **b == b'\n')
                .count();
            v.drain(..skip);
            self.after_prompt = false;
        }
        if v.iter().all(|b| *b == b'\r' || *b == b'\n') {
            v.clear();
        }
        v
    }
}

/// Position of the first occurrence of `needle` in `hay`.
pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Remove every occurrence of `needle` plus any CR/LF immediately after it.
fn remove_all_followed_by_newline(data: &[u8], needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(i) = find(rest, needle) {
        out.extend_from_slice(&rest[..i]);
        rest = &rest[i + needle.len()..];
        let skip = rest
            .iter()
            .take_while(|b| **b == b'\r' || **b == b'\n')
            .count();
        rest = &rest[skip..];
    }
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> SudoPlan {
        SudoPlan::with_markers("root".into(), "[P]", "[M]")
    }

    #[test]
    fn find_works() {
        assert_eq!(find(b"abcdef", b"cd"), Some(2));
        assert_eq!(find(b"abc", b"abcd"), None);
        assert_eq!(find(b"abc", b""), None);
    }

    #[test]
    fn remove_followed_by_newline() {
        assert_eq!(
            remove_all_followed_by_newline(b"xSorry, try again.\r\ny", SORRY),
            b"xy"
        );
    }

    #[test]
    fn nonpty_prompt_then_marker() {
        let mut f = SudoFilter::new(&plan(), false);
        let mut out = Vec::new();
        f.stderr(b"[P", &mut out);
        assert!(out.is_empty());
        f.stderr(b"]", &mut out);
        assert_eq!(out, vec![SudoOutput::NeedPassword { retry: false }]);
        out.clear();
        let line = f.password_line(b"secret");
        assert_eq!(&line[..], b"secret\n");
        f.stdout(b"[M", &mut out);
        assert!(out.is_empty());
        f.stdout(b"]payload [P] [M] secret\n", &mut out);
        assert_eq!(
            out,
            vec![
                SudoOutput::Elevated,
                SudoOutput::Stdout(Bytes::from_static(b"payload [P] [M] secret\n"))
            ]
        );
        assert!(f.elevated());
    }

    #[test]
    fn nonpty_wrong_password_and_lecture() {
        let mut f = SudoFilter::new(&plan(), false);
        let mut out = Vec::new();
        f.stderr(b"lecture\n[P]", &mut out);
        assert_eq!(
            out,
            vec![
                SudoOutput::Stderr(Bytes::from_static(b"lecture\n")),
                SudoOutput::NeedPassword { retry: false }
            ]
        );
        out.clear();
        let _ = f.password_line(b"wrong");
        f.stderr(b"Sorry, try again.\n[P]", &mut out);
        assert_eq!(out, vec![SudoOutput::NeedPassword { retry: true }]);
        out.clear();
        let _ = f.password_line(b"right");
        f.stdout(b"[M]", &mut out);
        assert_eq!(out, vec![SudoOutput::Elevated]);
        out.clear();
        f.stderr(b"cmd stderr", &mut out);
        assert_eq!(
            out,
            vec![SudoOutput::Stderr(Bytes::from_static(b"cmd stderr"))]
        );
    }

    #[test]
    fn pty_prompt_echo_and_marker() {
        let mut f = SudoFilter::new(&plan(), true);
        let mut out = Vec::new();
        f.stdout(b"[P]", &mut out);
        assert_eq!(out, vec![SudoOutput::NeedPassword { retry: false }]);
        out.clear();
        let _ = f.password_line(b"pw");
        f.stdout(b"pw\r\nSorry, try again.\r\n[P]", &mut out);
        assert_eq!(out, vec![SudoOutput::NeedPassword { retry: true }]);
        out.clear();
        let _ = f.password_line(b"pw2");
        f.stdout(b"pw2\r\n[M]\x00\x01[P]pw2\r\n", &mut out);
        assert_eq!(
            out,
            vec![
                SudoOutput::Elevated,
                SudoOutput::Stdout(Bytes::from_static(b"\x00\x01[P]pw2\r\n"))
            ]
        );
    }

    #[test]
    fn pty_keeps_diagnostics_between_prompt_and_marker() {
        let mut f = SudoFilter::new(&plan(), true);
        let mut out = Vec::new();
        f.stdout(b"[P]", &mut out);
        out.clear();
        let _ = f.password_line(b"pw");
        f.stdout(b"\r\nsudo: warning\r\n[M]", &mut out);
        assert_eq!(
            out,
            vec![
                SudoOutput::Stdout(Bytes::from_static(b"sudo: warning\r\n")),
                SudoOutput::Elevated
            ]
        );
    }

    #[test]
    fn finish_flushes_held_bytes() {
        let mut f = SudoFilter::new(&plan(), false);
        let mut out = Vec::new();
        f.stderr(b"user is not in the sudoers file.\n", &mut out);
        assert!(out.is_empty());
        f.finish(&mut out);
        assert_eq!(
            out,
            vec![SudoOutput::Stderr(Bytes::from_static(
                b"user is not in the sudoers file.\n"
            ))]
        );
        assert!(!f.elevated());
    }

    #[test]
    fn nonpty_unexpected_stdout_is_not_lost() {
        let mut f = SudoFilter::new(&plan(), false);
        let mut out = Vec::new();
        f.stdout(b"XYZ", &mut out);
        assert_eq!(
            out,
            vec![
                SudoOutput::Elevated,
                SudoOutput::Stdout(Bytes::from_static(b"XYZ"))
            ]
        );
        assert!(!f.elevated());
    }
}
