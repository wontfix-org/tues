use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use tues_async::ChildSignaller;
use tues_core::{ExitStatus, Output, Result};

use crate::Runtime;

/// A running remote process with blocking stdio.
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    inner: tues_async::Child,
    rt: Arc<Runtime>,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl Child {
    pub(crate) fn new(mut inner: tues_async::Child, rt: Arc<Runtime>) -> Self {
        let stdin = inner.stdin.take().map(|s| ChildStdin {
            inner: s,
            rt: rt.clone(),
        });
        let stdout = inner.stdout.take().map(|s| ChildStdout {
            inner: s,
            rt: rt.clone(),
        });
        let stderr = inner.stderr.take().map(|s| ChildStderr {
            inner: s,
            rt: rt.clone(),
        });
        Child {
            stdin,
            stdout,
            stderr,
            inner,
            rt,
        }
    }

    /// Wait for exit. Read piped output concurrently or use
    /// [`Child::wait_with_output`] to avoid a full-pipe stall.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        self.rt.block_on(self.inner.wait())
    }

    /// Wait for exit for at most `timeout`; `Ok(None)` if the process is still
    /// running when the timeout expires.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<ExitStatus>> {
        self.rt.block_on(async {
            match tokio::time::timeout(timeout, self.inner.wait()).await {
                Ok(r) => r.map(Some),
                Err(_elapsed) => Ok(None),
            }
        })
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    /// Close stdin, collect stdout/stderr and wait.
    pub fn wait_with_output(mut self) -> Result<Output> {
        let mut inner = self.inner;
        drop(self.stdin.take());
        inner.stdout = self.stdout.take().map(|s| s.inner);
        inner.stderr = self.stderr.take().map(|s| s.inner);
        self.rt.block_on(inner.wait_with_output())
    }

    /// Send SIGKILL (if the server supports channel signals) and close the channel.
    pub fn kill(&self) -> Result<()> {
        self.inner.kill()
    }

    /// Deliver a signal by name (`"TERM"`, `"INT"`, ...); see
    /// [`ChildSignaller::signal`].
    pub fn signal(&self, name: impl Into<String>) -> Result<()> {
        self.inner.signal(name)
    }

    /// A handle that can kill or signal this child from another thread.
    pub fn signaller(&self) -> ChildSignaller {
        self.inner.signaller()
    }

    pub fn id(&self) -> Option<u32> {
        None
    }
}

/// Blocking stdin pipe. Dropping it sends EOF.
pub struct ChildStdin {
    inner: tues_async::ChildStdin,
    rt: Arc<Runtime>,
}

impl ChildStdin {
    /// Send EOF explicitly.
    pub fn close(self) -> io::Result<()> {
        self.rt.block_on(self.inner.close())
    }
}

impl Write for ChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rt.block_on(self.inner.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Blocking stdout pipe.
pub struct ChildStdout {
    inner: tues_async::ChildStdout,
    rt: Arc<Runtime>,
}

impl Read for ChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.rt.block_on(self.inner.read(buf))
    }
}

/// Blocking stderr pipe.
pub struct ChildStderr {
    inner: tues_async::ChildStderr,
    rt: Arc<Runtime>,
}

impl Read for ChildStderr {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.rt.block_on(self.inner.read(buf))
    }
}

impl std::fmt::Debug for ChildStdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChildStdin")
    }
}
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
