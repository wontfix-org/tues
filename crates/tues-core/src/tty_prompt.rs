//! Hidden password prompt on the controlling terminal.
//!
//! Echo is disabled only while the password is read. Canonical mode and
//! `ISIG` stay on, so Ctrl-C is delivered as `SIGINT` instead of a raw byte.
//! The signal handler puts the previous terminal mode back before the
//! default action kills the process: `Drop` does not run in that case, which
//! is what used to leave the terminal in non-canonical mode.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use crate::error::{Error, Result};

#[cfg(unix)]
use std::os::fd::AsRawFd;

/// Where the cursor goes after a hidden password has been read.
///
/// Echo is off while the password is typed, and `ECHONL` is cleared, so the
/// newline from Enter is not displayed. The next write would otherwise
/// continue on the prompt line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PasswordPromptFinish {
    /// Continue at column 0 of the next line.
    ///
    /// This is what the legacy password prompt did, and what `getpass` does:
    /// later output starts at the beginning of the next line.
    #[default]
    Newline,
    /// Leave the cursor where the prompt ended.
    CurrentLine,
    /// Erase the prompt and leave the cursor where it started, so later
    /// output is not prefixed by the question.
    Erase,
}

impl PasswordPromptFinish {
    /// Bytes written to the terminal once the password has been read.
    ///
    /// [`Self::Erase`] is carriage return plus erase-entire-line. The
    /// password itself was not echoed, so the line holds only the prompt.
    pub fn terminal_sequence(self) -> &'static [u8] {
        match self {
            PasswordPromptFinish::CurrentLine => b"",
            PasswordPromptFinish::Newline => b"\n",
            PasswordPromptFinish::Erase => b"\r\x1b[2K",
        }
    }
}

fn write_finish(tty: &mut impl Write, finish: PasswordPromptFinish) -> Result<()> {
    let sequence = finish.terminal_sequence();
    if sequence.is_empty() {
        return Ok(());
    }
    tty.write_all(sequence)?;
    tty.flush()?;
    Ok(())
}

#[cfg(not(unix))]
pub fn read_hidden(prompt: &str, finish: PasswordPromptFinish) -> Result<String> {
    // `rpassword` always continues on the next line; the other finishes are
    // implemented for the Unix prompt below.
    let _ = finish;
    rpassword::prompt_password(prompt)
        .map_err(|e| Error::Password(format!("reading from tty failed: {e}")))
}

#[cfg(unix)]
pub fn read_hidden(prompt: &str, finish: PasswordPromptFinish) -> Result<String> {
    // One prompt at a time: the signal handler restores a single saved mode.
    let _gate = PROMPT_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| Error::Password(format!("cannot open /dev/tty: {e}")))?;
    let _guard = TermiosGuard::arm(tty.as_raw_fd())?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let password = read_line(&mut tty)?;
    write_finish(&mut tty, finish)?;
    Ok(password)
}

#[cfg(unix)]
fn read_line(tty: &mut impl Read) -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => break,
            Ok(_) => buf.push(byte[0]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                return Err(Error::Password("interrupted".into()));
            }
            Err(err) => {
                return Err(Error::Password(format!("reading from tty failed: {err}")));
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(unix)]
mod unix {
    use super::*;

    use std::cell::UnsafeCell;
    use std::mem::{self, MaybeUninit};
    use std::sync::atomic::{AtomicI32, Ordering};

    pub(super) static PROMPT_LOCK: Mutex<()> = Mutex::new(());

    struct Slot<T>(UnsafeCell<MaybeUninit<T>>);
    // SAFETY: `FD`'s release store happens after the slots are written, and the
    // handler acquire-loads `FD` before reading them. The prompt mutex keeps a
    // second prompt from writing the slots while a handler is in progress.
    unsafe impl<T> Sync for Slot<T> {}

    static ORIG: Slot<libc::termios> = Slot(UnsafeCell::new(MaybeUninit::uninit()));
    static OLD_ACTION: Slot<libc::sigaction> = Slot(UnsafeCell::new(MaybeUninit::uninit()));
    static FD: AtomicI32 = AtomicI32::new(-1);

    pub(super) struct TermiosGuard;

    impl TermiosGuard {
        pub(super) fn arm(fd: libc::c_int) -> Result<Self> {
            let orig = tcgetattr(fd)?;
            let mut hidden = orig;
            // Leave ICANON and ISIG set. Clearing them is cbreak/raw mode,
            // and a fatal SIGINT would skip Drop and stick there. Also drop
            // ECHONL so Enter does not move the cursor; [`PasswordPromptFinish`]
            // decides that.
            hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
            let mut action: libc::sigaction = unsafe { mem::zeroed() };
            action.sa_sigaction = on_sigint as *const () as usize;
            action.sa_flags = 0;
            unsafe {
                if libc::sigemptyset(&mut action.sa_mask) != 0 {
                    return Err(Error::Password(format!(
                        "installing signal handler failed: {}",
                        io::Error::last_os_error()
                    )));
                }
                let mut old_action: libc::sigaction = mem::zeroed();
                (*ORIG.0.get()).write(orig);
                if libc::sigaction(libc::SIGINT, &action, &mut old_action) != 0 {
                    return Err(Error::Password(format!(
                        "installing signal handler failed: {}",
                        io::Error::last_os_error()
                    )));
                }
                (*OLD_ACTION.0.get()).write(old_action);
                // Publish the fd after the saved mode is visible to the handler.
                FD.store(fd, Ordering::Release);
                if libc::tcsetattr(fd, libc::TCSANOW, &hidden) != 0 {
                    FD.store(-1, Ordering::Release);
                    libc::sigaction(libc::SIGINT, &old_action, std::ptr::null_mut());
                    return Err(Error::Password(format!(
                        "hiding the password failed: {}",
                        io::Error::last_os_error()
                    )));
                }
            }
            Ok(TermiosGuard)
        }
    }

    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe { restore_termios() }
            FD.store(-1, Ordering::Release);
            unsafe {
                let old = (*OLD_ACTION.0.get()).assume_init_ref();
                libc::sigaction(libc::SIGINT, old, std::ptr::null_mut());
            }
        }
    }

    fn tcgetattr(fd: libc::c_int) -> Result<libc::termios> {
        let mut term = unsafe { mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            return Err(Error::Password(format!(
                "reading terminal attributes failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(term)
    }

    /// Async-signal-safe: `tcsetattr` only, and only when a prompt is active.
    unsafe fn restore_termios() {
        let fd = FD.load(Ordering::Acquire);
        if fd < 0 {
            return;
        }
        let orig = unsafe { (*ORIG.0.get()).assume_init_ref() };
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, orig);
        }
    }

    extern "C" fn on_sigint(sig: libc::c_int) {
        unsafe { restore_termios() }
        // Hand the signal to whoever owned it. SIG_DFL kills the process
        // before Drop, so the mode has to be back already. Unblock first:
        // the signal is masked for the duration of this handler.
        unsafe {
            let old = (*OLD_ACTION.0.get()).assume_init_ref();
            libc::sigaction(sig, old, std::ptr::null_mut());
            let mut set = mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, sig);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::raise(sig);
        }
    }
}

#[cfg(unix)]
use unix::{PROMPT_LOCK, TermiosGuard};

#[cfg(all(test, unix))]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use secrecy::ExposeSecret;

    use crate::{PasswordPrompter, PasswordRequest, TtyPrompter};

    #[test]
    fn tty_prompter_keeps_canonical_mode_and_restores_echo_on_interrupt() {
        let outcome = drive_prompt(
            "tty_prompt::tests::tty_prompter_keeps_canonical_mode_and_restores_echo_on_interrupt",
            "interrupt",
            None,
        );
        assert!(
            outcome.saw_prompt,
            "child never prompted; output {:?}",
            String::from_utf8_lossy(&outcome.output)
        );
        assert_eq!(
            outcome.during & (libc::ECHO | libc::ICANON | libc::ISIG),
            libc::ICANON | libc::ISIG,
            "prompt should hide echo without entering cbreak"
        );
        assert_eq!(
            outcome.after & (libc::ECHO | libc::ICANON | libc::ISIG),
            libc::ECHO | libc::ICANON | libc::ISIG,
            "terminal mode after interrupt: status {:?} output {:?}",
            outcome.status,
            String::from_utf8_lossy(&outcome.output)
        );
        let stopped = outcome.status.signal() == Some(libc::SIGINT) || !outcome.status.success();
        assert!(
            stopped,
            "interrupt should stop the prompt, status {:?}",
            outcome.status
        );
    }

    #[test]
    fn tty_prompter_reads_the_password_and_restores_echo() {
        let path = std::env::temp_dir().join(format!("tues-tty-prompt-{}", std::process::id()));
        let outcome = drive_prompt(
            "tty_prompt::tests::tty_prompter_reads_the_password_and_restores_echo",
            "read",
            Some(&path),
        );
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        assert!(
            outcome.status.success(),
            "status {:?} output {:?}",
            outcome.status,
            String::from_utf8_lossy(&outcome.output)
        );
        assert_eq!(body, "s3cret");
        assert_eq!(
            outcome.during & (libc::ECHO | libc::ICANON | libc::ISIG),
            libc::ICANON | libc::ISIG
        );
        assert_eq!(
            outcome.after & (libc::ECHO | libc::ICANON | libc::ISIG),
            libc::ECHO | libc::ICANON | libc::ISIG
        );
    }

    #[test]
    fn tty_prompter_finish_places_the_cursor() {
        let name = "tty_prompt::tests::tty_prompter_finish_places_the_cursor";
        for finish in ["newline", "current", "erase"] {
            let outcome = drive_prompt_finish(name, "read", None, Some(finish));
            let shown = String::from_utf8_lossy(&outcome.output);
            assert!(
                outcome.status.success(),
                "{finish}: status {:?} output {shown}",
                outcome.status
            );
            assert!(
                outcome.output.windows(5).any(|window| window == b"AFTER"),
                "{finish}: marker missing in {shown}"
            );
            let screen = render_screen(&outcome.output);
            match finish {
                "newline" => {
                    let prompt_row = screen
                        .iter()
                        .position(|row| row.contains("password:"))
                        .unwrap_or_else(|| panic!("{finish}: {screen:?}"));
                    let after_row = screen
                        .iter()
                        .position(|row| row.contains("AFTER"))
                        .unwrap_or_else(|| panic!("{finish}: {screen:?}"));
                    assert_eq!(after_row, prompt_row + 1, "{screen:?}");
                    assert!(screen[after_row].starts_with("AFTER"), "{screen:?}");
                }
                "current" => assert!(
                    outcome
                        .output
                        .windows(15)
                        .any(|window| window == b"password: AFTER"),
                    "{shown}"
                ),
                "erase" => {
                    let flat = screen.join("\n");
                    assert!(!flat.contains("password"), "{screen:?}");
                    assert!(flat.contains("AFTER"), "{screen:?}");
                }
                _ => unreachable!(),
            }
        }
    }

    fn render_screen(data: &[u8]) -> Vec<String> {
        let mut rows = vec![String::new()];
        let mut row = 0;
        let mut col = 0;
        let mut index = 0;
        while index < data.len() {
            if data[index..].starts_with(b"\x1b[2K") {
                rows[row].clear();
                index += 4;
                continue;
            }
            if data[index..].starts_with(b"\x1b[K") {
                rows[row].truncate(col);
                index += 3;
                continue;
            }
            match data[index] {
                b'\r' => col = 0,
                b'\n' => {
                    row += 1;
                    col = 0;
                    if row == rows.len() {
                        rows.push(String::new());
                    }
                }
                byte => {
                    let line = &mut rows[row];
                    let ch = byte as char;
                    if col < line.len() {
                        line.replace_range(col..col + 1, &ch.to_string());
                    } else {
                        line.extend(std::iter::repeat_n(' ', col - line.len()));
                        line.push(ch);
                    }
                    col += 1;
                }
            }
            index += 1;
        }
        rows
    }

    struct Outcome {
        status: std::process::ExitStatus,
        during: libc::tcflag_t,
        after: libc::tcflag_t,
        output: Vec<u8>,
        saw_prompt: bool,
    }

    fn drive_prompt(test_name: &str, mode: &str, result: Option<&std::path::Path>) -> Outcome {
        drive_prompt_finish(test_name, mode, result, None)
    }

    fn drive_prompt_finish(
        test_name: &str,
        mode: &str,
        result: Option<&std::path::Path>,
        finish: Option<&str>,
    ) -> Outcome {
        if std::env::var("TUES_TTY_PROMPT_CHILD").as_deref() == Ok(mode) {
            child_main(mode);
        }
        let (master, slave) = open_pty();
        let inspect = unsafe { libc::dup(slave) };
        assert!(inspect >= 0, "{}", std::io::Error::last_os_error());
        set_cloexec(master);
        set_cloexec(inspect);
        set_cloexec(slave);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg(test_name)
            .arg("--exact")
            .env("TUES_TTY_PROMPT_CHILD", mode)
            .stdin(unsafe { Stdio::from(File::from_raw_fd(slave)) })
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(path) = result {
            command.env("TUES_TTY_RESULT", path);
        }
        if let Some(finish) = finish {
            command.env("TUES_TTY_FINISH", finish);
            command.env("TUES_TTY_MARKER", "1");
        }
        let mut child = command.spawn().unwrap();
        let mut output = Vec::new();
        read_until(master, &mut output, b"password", Duration::from_secs(5));
        let saw_prompt = output.windows(8).any(|window| window == b"password");
        let during = lflag(inspect);
        if mode == "read" {
            write_all(master, b"s3cret\n");
            if finish.is_some() {
                read_until(master, &mut output, b"AFTER", Duration::from_secs(5));
            }
        } else if saw_prompt {
            write_all(master, &[0x03]);
        }
        let status = wait_child(&mut child, Duration::from_secs(5));
        let after = lflag(inspect);
        unsafe {
            libc::close(master);
            libc::close(inspect);
        }
        Outcome {
            status,
            during,
            after,
            output,
            saw_prompt,
        }
    }

    fn child_main(mode: &str) -> ! {
        if let Err(err) = claim_controlling_tty() {
            eprintln!("tty: {err}");
            std::process::exit(2);
        }
        let finish = match std::env::var("TUES_TTY_FINISH").ok().as_deref() {
            Some("current") => super::PasswordPromptFinish::CurrentLine,
            Some("erase") => super::PasswordPromptFinish::Erase,
            _ => super::PasswordPromptFinish::Newline,
        };
        let mut prompter = TtyPrompter::with(finish);
        match prompter.prompt(&PasswordRequest::login("h", 22, "alice")) {
            Ok(password) => {
                if mode == "read"
                    && let Ok(path) = std::env::var("TUES_TTY_RESULT")
                {
                    std::fs::write(path, password.expose_secret()).unwrap();
                }
                if std::env::var_os("TUES_TTY_MARKER").is_some() {
                    let mut tty = std::fs::OpenOptions::new()
                        .write(true)
                        .open("/dev/tty")
                        .unwrap();
                    tty.write_all(b"AFTER").unwrap();
                    tty.flush().unwrap();
                }
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("prompt: {err}");
                std::process::exit(1);
            }
        }
    }

    fn claim_controlling_tty() -> std::io::Result<()> {
        unsafe {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn open_pty() -> (libc::c_int, libc::c_int) {
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "{}", std::io::Error::last_os_error());
            assert_eq!(
                libc::grantpt(master),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::unlockpt(master),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            let mut name = [0u8; 64];
            assert_eq!(
                libc::ptsname_r(master, name.as_mut_ptr().cast(), name.len()),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            let slave = libc::open(name.as_ptr().cast(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "{}", std::io::Error::last_os_error());
            (master, slave)
        }
    }

    fn set_cloexec(fd: libc::c_int) {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }

    fn lflag(fd: libc::c_int) -> libc::tcflag_t {
        let mut term = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut term) }, 0);
        term.c_lflag
    }

    fn write_all(fd: libc::c_int, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
            assert!(n > 0, "{}", std::io::Error::last_os_error());
            rest = &rest[n as usize..];
        }
    }

    fn read_until(fd: libc::c_int, buf: &mut Vec<u8>, needle: &[u8], timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if needle.len() <= buf.len() && buf.windows(needle.len()).any(|window| window == needle)
            {
                return;
            }
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let left = timeout.saturating_sub(start.elapsed()).as_millis().min(200) as libc::c_int;
            let rc = unsafe { libc::poll(&mut pollfd, 1, left) };
            if rc <= 0 {
                continue;
            }
            let mut tmp = [0u8; 256];
            let n = unsafe { libc::read(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
            if n > 0 {
                buf.extend_from_slice(&tmp[..n as usize]);
            }
        }
    }

    fn wait_child(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                return child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod sequence {
    use super::PasswordPromptFinish;

    #[test]
    fn terminal_sequences() {
        assert_eq!(PasswordPromptFinish::Newline.terminal_sequence(), b"\n");
        assert_eq!(PasswordPromptFinish::CurrentLine.terminal_sequence(), b"");
        assert_eq!(
            PasswordPromptFinish::Erase.terminal_sequence(),
            b"\r\x1b[2K"
        );
    }
}
