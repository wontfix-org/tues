//! Blocking Python API.
//!
//! This is the low-level layer under `tues.Session` / `tues.Popen`: the
//! Python package wraps `Child` and its raw pipes in `io` objects and adds
//! the `subprocess`-shaped surface (text mode, `communicate`, timeouts,
//! `CompletedProcess`, ...).

use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::common::{
    self, Metadata, command, connect_options, io_to_pyerr, returncode, signal_name,
    timeout_duration, to_pyerr,
};

fn lock<T>(m: &Mutex<T>) -> PyResult<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| PyValueError::new_err("internal lock poisoned"))
}

/// A blocking SSH session.
#[pyclass(name = "Session", module = "tues._tues")]
pub struct Session {
    inner: tues_sync::Session,
}

#[pymethods]
impl Session {
    /// Connect to `destination` (`host`, `login-user@host`, `host:port`, or an
    /// ssh_config alias).
    ///
    /// Keyword arguments: login_user, port, user, user_shell (look up the
    /// target user's login shell and run shell commands with it; default
    /// keeps ``sh``), host_name, identity_files,
    /// identities_only, proxy_jump, connect_timeout, server_alive_interval,
    /// compression, use_agent, pubkey_authentication,
    /// password_authentication, host_key_policy ("strict" | "accept-new" |
    /// "off"), known_hosts_file, ssh_config (path, or False to disable),
    /// password (static), password_manager.
    ///
    /// `password_manager` is either a callable `request -> str` (or an object
    /// with `get(request)`), whose answers are memoized per host/user, or an
    /// object with both `get(request)` and `invalidate(request)`, which then
    /// owns caching itself.
    #[staticmethod]
    #[pyo3(signature = (destination, **kwargs))]
    fn connect(
        py: Python<'_>,
        destination: &str,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let opts = connect_options(destination, kwargs)?;
        let inner = py
            .detach(move || tues_sync::Session::connect(opts))
            .map_err(to_pyerr)?;
        Ok(Session { inner })
    }

    #[getter]
    fn login_user(&self) -> String {
        self.inner.login_user().to_string()
    }

    #[getter]
    fn host(&self) -> String {
        self.inner.host().to_string()
    }

    #[getter]
    fn port(&self) -> u16 {
        self.inner.options().port
    }

    /// Default user commands run as, or None for the login user.
    #[getter]
    fn user(&self) -> Option<String> {
        self.inner.user().map(str::to_string)
    }

    #[getter]
    fn closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Start a remote process.
    ///
    /// `args` is an argv list; with `shell=True`, `args[0]` is a shell
    /// script and the rest are its positional parameters. Keyword arguments:
    /// user, pty, env (dict; None removes), cwd, executable (shell when
    /// `shell` is true; default `sh`), and
    /// stdin/stdout/stderr (None = inherit, PIPE, DEVNULL).
    #[pyo3(signature = (args, shell = false, **kwargs))]
    fn spawn(
        &self,
        py: Python<'_>,
        args: Vec<String>,
        shell: bool,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Child> {
        let c = command(args, shell, kwargs)?;
        let session = self.inner.clone();
        let mut child = py.detach(move || session.spawn(&c)).map_err(to_pyerr)?;
        let stdin = match child.stdin.take() {
            Some(s) => Some(Py::new(
                py,
                ChildStdin {
                    inner: Mutex::new(Some(s)),
                },
            )?),
            None => None,
        };
        let stdout = match child.stdout.take() {
            Some(s) => Some(Py::new(
                py,
                ChildStdout {
                    inner: Mutex::new(Some(Reader::Stdout(s))),
                },
            )?),
            None => None,
        };
        let stderr = match child.stderr.take() {
            Some(s) => Some(Py::new(
                py,
                ChildStdout {
                    inner: Mutex::new(Some(Reader::Stderr(s))),
                },
            )?),
            None => None,
        };
        Ok(Child {
            signaller: child.signaller(),
            inner: Mutex::new(child),
            stdin,
            stdout,
            stderr,
        })
    }

    /// Metadata for a remote file or directory.
    ///
    /// Shares a cached SFTP channel with `upload`, `download`, `delete` and
    /// `rename`, separate from `sftp()`.
    fn stat(&self, py: Python<'_>, path: String) -> PyResult<Metadata> {
        let session = self.inner.clone();
        py.detach(move || session.stat(path))
            .map(Metadata)
            .map_err(to_pyerr)
    }

    /// Copy a local file or directory to `remote`.
    fn upload(&self, py: Python<'_>, local: PathBuf, remote: String) -> PyResult<()> {
        let session = self.inner.clone();
        py.detach(move || session.upload(local, remote))
            .map_err(to_pyerr)
    }

    /// Copy a remote file or directory to `local`.
    fn download(&self, py: Python<'_>, remote: String, local: PathBuf) -> PyResult<()> {
        let session = self.inner.clone();
        py.detach(move || session.download(remote, local))
            .map_err(to_pyerr)
    }

    /// Remove a remote file, symlink or directory tree.
    fn delete(&self, py: Python<'_>, path: String) -> PyResult<()> {
        let session = self.inner.clone();
        py.detach(move || session.delete(path)).map_err(to_pyerr)
    }

    /// Rename a remote file or directory.
    fn rename(&self, py: Python<'_>, src: String, dst: String) -> PyResult<()> {
        let session = self.inner.clone();
        py.detach(move || session.rename(src, dst))
            .map_err(to_pyerr)
    }

    /// Open an SFTP session.
    fn sftp(&self, py: Python<'_>) -> PyResult<Sftp> {
        let session = self.inner.clone();
        let inner = py.detach(move || session.sftp()).map_err(to_pyerr)?;
        Ok(Sftp { inner })
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let session = self.inner.clone();
        py.detach(move || session.close()).map_err(to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!(
            "Session({}@{}:{})",
            self.inner.login_user(),
            self.inner.host(),
            self.inner.options().port
        )
    }
}

/// A running remote process (raw handle; see `tues.Popen`).
#[pyclass(name = "Child", module = "tues._tues")]
pub struct Child {
    inner: Mutex<tues_sync::Child>,
    signaller: tues_sync::ChildSignaller,
    stdin: Option<Py<ChildStdin>>,
    stdout: Option<Py<ChildStdout>>,
    stderr: Option<Py<ChildStdout>>,
}

#[pymethods]
impl Child {
    /// Writable stdin pipe, or None.
    #[getter]
    fn stdin(&self, py: Python<'_>) -> Option<Py<ChildStdin>> {
        self.stdin.as_ref().map(|s| s.clone_ref(py))
    }

    /// Readable stdout pipe, or None.
    #[getter]
    fn stdout(&self, py: Python<'_>) -> Option<Py<ChildStdout>> {
        self.stdout.as_ref().map(|s| s.clone_ref(py))
    }

    /// Readable stderr pipe, or None.
    #[getter]
    fn stderr(&self, py: Python<'_>) -> Option<Py<ChildStdout>> {
        self.stderr.as_ref().map(|s| s.clone_ref(py))
    }

    /// Wait for the process to exit and return its return code (negative
    /// signal number if it was killed). With a `timeout` (seconds), returns
    /// None if the process is still running when it expires.
    #[pyo3(signature = (timeout = None))]
    fn wait(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<i32>> {
        py.detach(|| {
            let mut g = lock(&self.inner)?;
            let status = match timeout_duration(timeout) {
                None => Some(g.wait().map_err(to_pyerr)?),
                Some(d) => g.wait_timeout(d).map_err(to_pyerr)?,
            };
            Ok(status.as_ref().map(returncode))
        })
    }

    /// Return the return code if the process has finished, else None.
    ///
    /// Never blocks: if another thread is currently in `wait()`, None is
    /// returned.
    fn poll(&self) -> PyResult<Option<i32>> {
        match self.inner.try_lock() {
            Ok(mut g) => Ok(g.try_wait().map_err(to_pyerr)?.as_ref().map(returncode)),
            Err(std::sync::TryLockError::WouldBlock) => Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(PyValueError::new_err("internal lock poisoned"))
            }
        }
    }

    /// The return code if known, else None (alias of `poll()`).
    #[getter]
    fn returncode(&self) -> PyResult<Option<i32>> {
        self.poll()
    }

    /// Send a signal by name ("TERM", "SIGTERM", ...). The channel stays
    /// open so the process can report its own exit status.
    fn send_signal(&self, name: &str) -> PyResult<()> {
        self.signaller.signal(signal_name(name)?).map_err(to_pyerr)
    }

    /// Send SIGKILL and close the channel.
    fn kill(&self) -> PyResult<()> {
        self.signaller.kill().map_err(to_pyerr)
    }

    fn __repr__(&self) -> String {
        "Child(...)".to_string()
    }
}

/// Raw writable stdin of a `Child`.
#[pyclass(name = "ChildStdin", module = "tues._tues")]
pub struct ChildStdin {
    inner: Mutex<Option<tues_sync::ChildStdin>>,
}

#[pymethods]
impl ChildStdin {
    /// Write all of `data`; returns the number of bytes written.
    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        py.detach(|| {
            let mut g = lock(&self.inner)?;
            let Some(w) = g.as_mut() else {
                return Err(PyValueError::new_err("write to closed stdin"));
            };
            w.write_all(data).map_err(io_to_pyerr)?;
            Ok(data.len())
        })
    }

    /// Send EOF. Idempotent.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            let w = lock(&self.inner)?.take();
            match w {
                Some(w) => w.close().map_err(io_to_pyerr),
                None => Ok(()),
            }
        })
    }

    #[getter]
    fn closed(&self) -> PyResult<bool> {
        Ok(lock(&self.inner)?.is_none())
    }
}

enum Reader {
    Stdout(tues_sync::ChildStdout),
    Stderr(tues_sync::ChildStderr),
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Reader::Stdout(r) => r.read(buf),
            Reader::Stderr(r) => r.read(buf),
        }
    }
}

/// Raw readable stdout/stderr of a `Child`.
#[pyclass(name = "ChildStdout", module = "tues._tues")]
pub struct ChildStdout {
    inner: Mutex<Option<Reader>>,
}

#[pymethods]
impl ChildStdout {
    /// Read up to `n` bytes, blocking until at least one is available
    /// (empty at EOF). A negative `n` reads everything up to EOF.
    #[pyo3(signature = (n = -1))]
    fn read(&self, py: Python<'_>, n: isize) -> PyResult<Py<PyBytes>> {
        let v = py.detach(|| {
            let mut g = lock(&self.inner)?;
            let Some(r) = g.as_mut() else {
                return Err(PyValueError::new_err("read from closed pipe"));
            };
            let mut buf = if n < 0 {
                let mut v = Vec::new();
                r.read_to_end(&mut v).map_err(io_to_pyerr)?;
                v
            } else {
                let mut v = vec![0u8; n as usize];
                let got = r.read(&mut v).map_err(io_to_pyerr)?;
                v.truncate(got);
                v
            };
            buf.shrink_to_fit();
            Ok::<_, PyErr>(buf)
        })?;
        Ok(PyBytes::new(py, &v).unbind())
    }

    /// Drop the pipe; further output from the process is discarded.
    fn close(&self) -> PyResult<()> {
        lock(&self.inner)?.take();
        Ok(())
    }

    #[getter]
    fn closed(&self) -> PyResult<bool> {
        Ok(lock(&self.inner)?.is_none())
    }
}

/// Blocking SFTP session.
#[pyclass(name = "Sftp", module = "tues")]
pub struct Sftp {
    inner: tues_sync::Sftp,
}

#[pymethods]
impl Sftp {
    fn read(&self, py: Python<'_>, path: String) -> PyResult<Py<PyBytes>> {
        let s = self.inner.clone();
        let v = py.detach(move || s.read(path)).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &v).unbind())
    }

    fn read_text(&self, py: Python<'_>, path: String) -> PyResult<String> {
        let s = self.inner.clone();
        py.detach(move || s.read_to_string(path)).map_err(to_pyerr)
    }

    /// Create or truncate `path` and write `data`.
    fn write(&self, py: Python<'_>, path: String, data: Vec<u8>) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.write(path, &data)).map_err(to_pyerr)
    }

    /// Open a remote file. `mode` follows Python conventions ("r", "w", "a",
    /// "r+", "w+", "a+", "x"); binary only.
    #[pyo3(signature = (path, mode = "r"))]
    fn open(&self, py: Python<'_>, path: String, mode: &str) -> PyResult<File> {
        let opts = common::open_options(mode)?;
        let s = self.inner.clone();
        let f = py
            .detach(move || s.open_with(path, opts))
            .map_err(to_pyerr)?;
        Ok(File {
            inner: Mutex::new(Some(f)),
        })
    }

    fn listdir(&self, py: Python<'_>, path: String) -> PyResult<Py<PyList>> {
        let s = self.inner.clone();
        let entries = py.detach(move || s.read_dir(path)).map_err(to_pyerr)?;
        common::dir_entries(py, entries)
    }

    fn mkdir(&self, py: Python<'_>, path: String) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.create_dir(path)).map_err(to_pyerr)
    }

    fn remove(&self, py: Python<'_>, path: String) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.remove_file(path)).map_err(to_pyerr)
    }

    fn rmdir(&self, py: Python<'_>, path: String) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.remove_dir(path)).map_err(to_pyerr)
    }

    fn rename(&self, py: Python<'_>, src: String, dst: String) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.rename(src, dst)).map_err(to_pyerr)
    }

    fn symlink(&self, py: Python<'_>, target: String, link: String) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.symlink(target, link)).map_err(to_pyerr)
    }

    fn readlink(&self, py: Python<'_>, path: String) -> PyResult<String> {
        let s = self.inner.clone();
        py.detach(move || s.read_link(path)).map_err(to_pyerr)
    }

    fn stat(&self, py: Python<'_>, path: String) -> PyResult<Metadata> {
        let s = self.inner.clone();
        py.detach(move || s.metadata(path))
            .map(Metadata)
            .map_err(to_pyerr)
    }

    fn lstat(&self, py: Python<'_>, path: String) -> PyResult<Metadata> {
        let s = self.inner.clone();
        py.detach(move || s.symlink_metadata(path))
            .map(Metadata)
            .map_err(to_pyerr)
    }

    fn exists(&self, py: Python<'_>, path: String) -> PyResult<bool> {
        let s = self.inner.clone();
        py.detach(move || s.try_exists(path)).map_err(to_pyerr)
    }

    fn realpath(&self, py: Python<'_>, path: String) -> PyResult<String> {
        let s = self.inner.clone();
        py.detach(move || s.canonicalize(path)).map_err(to_pyerr)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let s = self.inner.clone();
        py.detach(move || s.close()).map_err(to_pyerr)
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type, _exc, _tb))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close(py)?;
        Ok(false)
    }
}

/// An open remote file (binary).
#[pyclass(name = "File", module = "tues")]
pub struct File {
    inner: Mutex<Option<tues_sync::File>>,
}

impl File {
    fn with<R>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut tues_sync::File) -> std::io::Result<R> + Send,
    ) -> PyResult<R>
    where
        R: Send,
    {
        py.detach(|| {
            let mut g = lock(&self.inner)?;
            let file = g
                .as_mut()
                .ok_or_else(|| PyValueError::new_err("I/O operation on closed file"))?;
            f(file).map_err(io_to_pyerr)
        })
    }
}

#[pymethods]
impl File {
    #[pyo3(signature = (n = -1))]
    fn read(&self, py: Python<'_>, n: isize) -> PyResult<Py<PyBytes>> {
        let v = self.with(py, |f| {
            if n < 0 {
                let mut v = Vec::new();
                f.read_to_end(&mut v)?;
                Ok(v)
            } else {
                let mut v = vec![0u8; n as usize];
                let mut filled = 0;
                while filled < v.len() {
                    let got = f.read(&mut v[filled..])?;
                    if got == 0 {
                        break;
                    }
                    filled += got;
                }
                v.truncate(filled);
                Ok(v)
            }
        })?;
        Ok(PyBytes::new(py, &v).unbind())
    }

    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        self.with(py, |f| {
            f.write_all(data)?;
            Ok(data.len())
        })
    }

    #[pyo3(signature = (offset, whence = 0))]
    fn seek(&self, py: Python<'_>, offset: i64, whence: i32) -> PyResult<u64> {
        let pos = common::seek_from(offset, whence)?;
        self.with(py, |f| f.seek(pos))
    }

    fn tell(&self, py: Python<'_>) -> PyResult<u64> {
        self.with(py, |f| f.stream_position())
    }

    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        self.with(py, |f| f.flush())
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            let f = lock(&self.inner)?.take();
            match f {
                Some(f) => f.close().map_err(io_to_pyerr),
                None => Ok(()),
            }
        })
    }

    #[getter]
    fn closed(&self) -> PyResult<bool> {
        Ok(lock(&self.inner)?.is_none())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type, _exc, _tb))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close(py)?;
        Ok(false)
    }
}
