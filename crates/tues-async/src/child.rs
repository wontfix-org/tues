use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use russh::{Channel, client::Msg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;
use tracing::debug;

use tues_core::{
    Effect, Error, Event, ExecMachine, ExecPlan, ExitStatus, Output, PasswordRequest, Result,
    SharedPasswordManager, Stdio,
};

use crate::session::{channel_event, request_password};

/// Capacity (in chunks) of the stdio pipes between the caller and the pump.
const PIPE_CHUNKS: usize = 64;

/// A running remote process, modelled after [`std::process::Child`].
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    ctrl: mpsc::UnboundedSender<Ctrl>,
    exit: Option<oneshot::Receiver<Result<ExitStatus>>>,
    /// The final outcome once known; repeated `wait`/`try_wait` calls
    /// return it again (including failures such as a rejected sudo password).
    outcome: Option<Result<ExitStatus>>,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Child")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

enum Ctrl {
    Kill,
    Signal(String),
}

/// A cheap, cloneable handle for signalling a running [`Child`].
///
/// Obtained from [`Child::signaller`]; lets one task wait on the child while
/// another kills it.
#[derive(Clone, Debug)]
pub struct ChildSignaller {
    ctrl: mpsc::UnboundedSender<Ctrl>,
}

impl ChildSignaller {
    /// Send SIGKILL (if the server supports channel signals) and close the channel.
    pub fn kill(&self) -> Result<()> {
        self.ctrl.send(Ctrl::Kill).map_err(|_| Error::Disconnected)
    }

    /// Deliver a signal by name (`"TERM"`, `"INT"`, ...; no `SIG` prefix).
    ///
    /// Unlike [`ChildSignaller::kill`] the channel is left open so the
    /// process may handle the signal and report its own exit status.
    /// Servers that do not implement signal requests silently ignore it.
    pub fn signal(&self, name: impl Into<String>) -> Result<()> {
        self.ctrl
            .send(Ctrl::Signal(name.into()))
            .map_err(|_| Error::Disconnected)
    }
}

impl Child {
    /// Wait for the process to exit.
    ///
    /// If stdout/stderr are piped and not being read, the remote process may
    /// block on a full pipe; use [`Child::wait_with_output`] instead.
    ///
    /// Cancel-safe: dropping the future (e.g. from a timeout) and calling
    /// `wait` again later resumes waiting.
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        if let Some(r) = &self.outcome {
            return r.clone();
        }
        let rx = self.exit.as_mut().ok_or(Error::Disconnected)?;
        let r = rx.await;
        // The receiver is consumed once it has resolved.
        self.exit = None;
        let r = match r {
            Ok(r) => r,
            Err(_pump_gone) => Err(Error::Disconnected),
        };
        self.outcome = Some(r.clone());
        r
    }

    /// Non-blocking status check.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(r) = &self.outcome {
            return r.clone().map(Some);
        }
        let Some(rx) = self.exit.as_mut() else {
            return Err(Error::Disconnected);
        };
        match rx.try_recv() {
            Ok(r) => {
                self.exit = None;
                self.outcome = Some(r.clone());
                r.map(Some)
            }
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            Err(oneshot::error::TryRecvError::Closed) => {
                self.exit = None;
                self.outcome = Some(Err(Error::Disconnected));
                Err(Error::Disconnected)
            }
        }
    }

    /// Close stdin, read stdout and stderr to the end, and wait.
    pub async fn wait_with_output(mut self) -> Result<Output> {
        drop(self.stdin.take());
        let mut stdout = self.stdout.take();
        let mut stderr = self.stderr.take();
        let out_fut = async {
            let mut v = Vec::new();
            if let Some(s) = stdout.as_mut() {
                s.read_to_end(&mut v).await?;
            }
            Ok::<_, io::Error>(v)
        };
        let err_fut = async {
            let mut v = Vec::new();
            if let Some(s) = stderr.as_mut() {
                s.read_to_end(&mut v).await?;
            }
            Ok::<_, io::Error>(v)
        };
        let (out, err, status) = tokio::join!(out_fut, err_fut, self.wait());
        Ok(Output {
            status: status?,
            stdout: out?,
            stderr: err?,
        })
    }

    /// Send SIGKILL (if the server supports channel signals) and close the channel.
    pub fn kill(&self) -> Result<()> {
        self.signaller().kill()
    }

    /// Deliver a signal by name; see [`ChildSignaller::signal`].
    pub fn signal(&self, name: impl Into<String>) -> Result<()> {
        self.signaller().signal(name)
    }

    /// A handle that can kill or signal this child from elsewhere.
    pub fn signaller(&self) -> ChildSignaller {
        ChildSignaller {
            ctrl: self.ctrl.clone(),
        }
    }

    /// Remote processes have no accessible pid over SSH.
    pub fn id(&self) -> Option<u32> {
        None
    }
}

/// Write half of the child's stdin pipe. Dropping it sends EOF.
pub struct ChildStdin {
    tx: PollSender<Bytes>,
}

impl ChildStdin {
    /// Explicitly send EOF.
    pub async fn close(mut self) -> io::Result<()> {
        self.shutdown().await
    }
}

impl std::fmt::Debug for ChildStdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChildStdin")
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "remote process stdin closed")
}

impl AsyncWrite for ChildStdin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.tx.poll_reserve(cx)).map_err(|_| closed())?;
        self.tx
            .send_item(Bytes::copy_from_slice(buf))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

/// Read half of an output pipe.
pub struct PipeReader {
    rx: mpsc::Receiver<Bytes>,
    buf: Bytes,
}

impl AsyncRead for PipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.buf.is_empty() {
            match ready!(self.rx.poll_recv(cx)) {
                Some(b) => self.buf = b,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = self.buf.len().min(out.remaining());
        out.put_slice(&self.buf.split_to(n));
        Poll::Ready(Ok(()))
    }
}

/// The child's stdout pipe.
pub struct ChildStdout(PipeReader);
/// The child's stderr pipe.
pub struct ChildStderr(PipeReader);

impl std::fmt::Debug for ChildStdout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChildStdout")
    }
}
impl std::fmt::Debug for ChildStderr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChildStderr")
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncRead for ChildStderr {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// Where pump output goes.
enum Sink {
    Pipe(mpsc::Sender<Bytes>),
    Stdout(tokio::io::Stdout),
    Stderr(tokio::io::Stderr),
    Null,
}

impl Sink {
    async fn write(&mut self, b: Bytes) {
        match self {
            Sink::Pipe(tx) => {
                if tx.send(b).await.is_err() {
                    // Reader dropped: discard from now on.
                    *self = Sink::Null;
                }
            }
            Sink::Stdout(s) => {
                if s.write_all(&b).await.is_err() {
                    *self = Sink::Null;
                } else {
                    let _ = s.flush().await;
                }
            }
            Sink::Stderr(s) => {
                if s.write_all(&b).await.is_err() {
                    *self = Sink::Null;
                } else {
                    let _ = s.flush().await;
                }
            }
            Sink::Null => {}
        }
    }
}

fn make_out(kind: Stdio, is_stdout: bool) -> (Sink, Option<PipeReader>) {
    match kind {
        Stdio::Piped => {
            let (tx, rx) = mpsc::channel(PIPE_CHUNKS);
            (
                Sink::Pipe(tx),
                Some(PipeReader {
                    rx,
                    buf: Bytes::new(),
                }),
            )
        }
        Stdio::Inherit => (
            if is_stdout {
                Sink::Stdout(tokio::io::stdout())
            } else {
                Sink::Stderr(tokio::io::stderr())
            },
            None,
        ),
        Stdio::Null => (Sink::Null, None),
    }
}

/// Spawn a reader for process stdin. The `PipeWriter` wakes that reader when dropped.
#[cfg(unix)]
fn inherited_stdin() -> (
    Option<mpsc::Sender<Bytes>>,
    Option<mpsc::Receiver<Bytes>>,
    Option<std::io::PipeWriter>,
) {
    let (tx, rx) = mpsc::channel::<Bytes>(PIPE_CHUNKS);
    let (wake_read, wake_write) = std::io::pipe().expect("inherited stdin wake pipe");
    tokio::task::spawn_blocking(move || forward_inherited_stdin(tx, wake_read));
    (None, Some(rx), Some(wake_write))
}

/// Copy process stdin to `tx` until EOF or until `wake` is closed.
///
/// Waits in `poll(2)` and only then calls `read(2)`. A blocking read on a
/// terminal cannot be cancelled, and dropping a `Runtime` waits for
/// `spawn_blocking` tasks, so the read must be interruptible or shutdown
/// sits until the next keypress. Closing `wake` (the pump task ending, or
/// runtime shutdown aborting it) makes `poll` return.
#[cfg(unix)]
fn forward_inherited_stdin(tx: mpsc::Sender<Bytes>, wake: std::io::PipeReader) {
    use std::io::Read;

    let mut buf = vec![0u8; 32 * 1024];
    while let Ok(true) = poll_inherited_stdin(&wake) {
        match std::io::stdin().lock().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx.blocking_send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// `Ok(true)` when stdin has bytes to read. `Ok(false)` when the wake pipe closed.
#[cfg(unix)]
fn poll_inherited_stdin(wake: &std::io::PipeReader) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    let mut fds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a live two-element array for this call, and `wake`
        // keeps its fd open for the whole poll.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[1].revents != 0 {
            return Ok(false);
        }
        if (fds[0].revents & libc::POLLIN) != 0 {
            return Ok(true);
        }
        return Ok(false);
    }
}

/// Copy process stdin until EOF. Targets without `poll(2)` cannot interrupt
/// that read, so runtime shutdown waits until stdin reaches EOF.
#[cfg(not(unix))]
fn inherited_stdin() -> (
    Option<mpsc::Sender<Bytes>>,
    Option<mpsc::Receiver<Bytes>>,
    Option<std::io::PipeWriter>,
) {
    let (tx, rx) = mpsc::channel::<Bytes>(PIPE_CHUNKS);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (None, Some(rx), None)
}

/// Start the pump task for an exec'd channel and hand back the child handle.
pub(crate) fn spawn_child(
    channel: Channel<Msg>,
    plan: ExecPlan,
    password_manager: SharedPasswordManager,
    password_request: Option<PasswordRequest>,
) -> Child {
    let machine = ExecMachine::new(&plan);

    let (stdin_tx, stdin_rx, stdin_wake) = match plan.stdin {
        Stdio::Piped => {
            let (tx, rx) = mpsc::channel::<Bytes>(PIPE_CHUNKS);
            (Some(tx), Some(rx), None)
        }
        Stdio::Inherit => inherited_stdin(),
        Stdio::Null => (None, None, None),
    };
    let (stdout_sink, stdout_rx) = make_out(plan.stdout, true);
    let (stderr_sink, stderr_rx) = make_out(plan.stderr, false);
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    let (exit_tx, exit_rx) = oneshot::channel();

    tokio::spawn(pump(
        channel,
        machine,
        PumpIo {
            stdin_rx,
            stdin_wake,
            stdout: stdout_sink,
            stderr: stderr_sink,
            ctrl_rx,
            exit_tx,
        },
        password_manager,
        password_request,
    ));

    Child {
        stdin: stdin_tx.map(|tx| ChildStdin {
            tx: PollSender::new(tx),
        }),
        stdout: stdout_rx.map(ChildStdout),
        stderr: stderr_rx.map(ChildStderr),
        ctrl: ctrl_tx,
        exit: Some(exit_rx),
        outcome: None,
    }
}

struct PumpIo {
    stdin_rx: Option<mpsc::Receiver<Bytes>>,
    /// Write end of the pipe that wakes the inherited-stdin reader. Dropping
    /// it (task completion, or abort during runtime shutdown) makes that
    /// reader return so `Runtime` drop does not wait on the terminal.
    stdin_wake: Option<std::io::PipeWriter>,
    stdout: Sink,
    stderr: Sink,
    ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
    exit_tx: oneshot::Sender<Result<ExitStatus>>,
}

/// Drive the machine: channel messages and caller stdin in, effects out.
async fn pump(
    mut channel: Channel<Msg>,
    mut machine: ExecMachine,
    mut io: PumpIo,
    password_manager: SharedPasswordManager,
    password_request: Option<PasswordRequest>,
) {
    let mut pw_task: Option<tokio::task::JoinHandle<Result<tues_core::SecretString>>> = None;
    let mut stdin_open = io.stdin_rx.is_some();
    let mut killed = false;
    let mut channel_gone = false;
    let mut ctrl_open = true;

    loop {
        // Apply pending effects.
        while let Some(effect) = machine.poll_effect() {
            match effect {
                Effect::Stdout(b) => io.stdout.write(b).await,
                Effect::Stderr(b) => io.stderr.write(b).await,
                Effect::WriteChannel(b) => {
                    if !channel_gone && channel.data(&b[..]).await.is_err() {
                        channel_gone = true;
                    }
                }
                Effect::WriteChannelSecret(z) => {
                    if !channel_gone && channel.data(&z[..]).await.is_err() {
                        channel_gone = true;
                    }
                }
                Effect::ChannelEof => {
                    if !channel_gone && channel.eof().await.is_err() {
                        channel_gone = true;
                    }
                }
                Effect::RequestPassword { retry } => {
                    let Some(req) = password_request.clone() else {
                        machine.handle(Event::PasswordUnavailable(Error::Password(
                            "no sudo context".into(),
                        )));
                        continue;
                    };
                    let pm = password_manager.clone();
                    pw_task = Some(tokio::spawn(async move {
                        request_password(&pm, req, retry).await
                    }));
                }
                Effect::Finished(result) => {
                    // Unblock the inherited-stdin reader before waiting on the
                    // channel close, so runtime shutdown is not stuck in read.
                    drop(io.stdin_wake.take());
                    let result = match result {
                        Err(Error::Protocol(_)) if killed => Ok(ExitStatus::from_signal("KILL")),
                        r => r,
                    };
                    let _ = io.exit_tx.send(result);
                    let _ = channel.close().await;
                    return;
                }
            }
        }

        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    None => {
                        channel_gone = true;
                        machine.handle(Event::Close);
                    }
                    Some(m) => {
                        if let Some(ev) = channel_event(m) {
                            machine.handle(ev);
                        }
                    }
                }
            }
            data = async { io.stdin_rx.as_mut().expect("stdin_open implies receiver").recv().await }, if stdin_open => {
                match data {
                    Some(b) => machine.handle(Event::StdinData(b)),
                    None => {
                        stdin_open = false;
                        machine.handle(Event::StdinEof);
                    }
                }
            }
            res = async { pw_task.as_mut().expect("guarded").await }, if pw_task.is_some() => {
                pw_task = None;
                match res {
                    Ok(Ok(pw)) => machine.handle(Event::Password(pw)),
                    Ok(Err(e)) => machine.handle(Event::PasswordUnavailable(e)),
                    Err(e) => machine.handle(Event::PasswordUnavailable(Error::Password(e.to_string()))),
                }
            }
            ctrl = io.ctrl_rx.recv(), if ctrl_open => {
                match ctrl {
                    Some(Ctrl::Kill) => {
                        killed = true;
                        debug!("killing remote process");
                        if !channel_gone {
                            let _ = channel.signal(russh::Sig::KILL).await;
                            let _ = channel.close().await;
                            channel_gone = true;
                        }
                        // Do not wait for the server's close confirmation.
                        machine.handle(Event::Close);
                    }
                    Some(Ctrl::Signal(name)) => {
                        debug!(signal = %name, "signalling remote process");
                        if !channel_gone && channel.signal(russh::Sig::Custom(name)).await.is_err() {
                            channel_gone = true;
                        }
                    }
                    None => {
                        // Child handle dropped. Keep pumping so the remote
                        // command completes (like std::process).
                        ctrl_open = false;
                    }
                }
            }
        }
    }
}
