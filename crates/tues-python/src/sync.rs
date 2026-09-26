//! Blocking Python API.

use std::io::{Read, Seek, Write};
use std::sync::Mutex;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::common::{
    self, ExitStatus, Metadata, Output, check_output, command, connect_options, io_to_pyerr,
    run_check, run_input, to_pyerr,
};

fn lock<T>(m: &Mutex<T>) -> PyResult<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| PyValueError::new_err("internal lock poisoned"))
}

/// A blocking SSH session.
#[pyclass(name = "Session", module = "tues")]
pub struct Session {
    inner: tues_sync::Session,
}

#[pymethods]
impl Session {
    /// Connect to `destination` (`host`, `user@host`, `host:port`, or an
    /// ssh_config alias).
    ///
    /// Keyword arguments: user, port, run_as, host_name, identity_files,
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
    fn user(&self) -> String {
        self.inner.user().to_string()
    }

    #[getter]
    fn host(&self) -> String {
        self.inner.host().to_string()
    }

    #[getter]
    fn port(&self) -> u16 {
        self.inner.options().port
    }

    /// Default sudo user for commands.
    #[getter]
    fn run_as(&self) -> Option<String> {
        self.inner.default_run_as().map(str::to_string)
    }

    #[getter]
    fn closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Run `cmd` (a shell string or an argv list) to completion.
    ///
    /// Keyword arguments: run_as, run_as_login_user, pty, env (dict), cwd,
    /// input (bytes for stdin), check (raise on non-zero exit).
    #[pyo3(signature = (cmd, **kwargs))]
    fn run(
        &self,
        py: Python<'_>,
        cmd: &Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Output> {
        let c = command(cmd, kwargs)?;
        let input = run_input(kwargs)?;
        let check = run_check(kwargs)?;
        let session = self.inner.clone();
        let out = py
            .detach(move || {
                let a = session.async_session().clone();
                session.block_on(common::run_async(&a, c, input))
            })
            .map_err(to_pyerr)?;
        check_output(check, &out)?;
        Ok(Output::from_core(py, out))
    }

    /// Spawn `cmd` and return a `Child` with piped stdio by default.
    ///
    /// Keyword arguments: run_as, run_as_login_user, pty, env, cwd, and
    /// stdin/stdout/stderr ("pipe" | "null" | "inherit").
    #[pyo3(signature = (cmd, **kwargs))]
    fn spawn(
        &self,
        py: Python<'_>,
        cmd: &Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Child> {
        let c = command(cmd, kwargs)?;
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
                    inner: Mutex::new(Reader::Stdout(s)),
                },
            )?),
            None => None,
        };
        let stderr = match child.stderr.take() {
            Some(s) => Some(Py::new(
                py,
                ChildStdout {
                    inner: Mutex::new(Reader::Stderr(s)),
                },
            )?),
            None => None,
        };
        Ok(Child {
            inner: Mutex::new(child),
            stdin,
            stdout,
            stderr,
        })
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

    fn __repr__(&self) -> String {
        format!(
            "Session({}@{}:{})",
            self.inner.user(),
            self.inner.host(),
            self.inner.options().port
        )
    }
}

/// A running remote process.
#[pyclass(name = "Child", module = "tues")]
pub struct Child {
    inner: Mutex<tues_sync::Child>,
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

    /// Wait for the process to exit.
    fn wait(&self, py: Python<'_>) -> PyResult<ExitStatus> {
        let status = py
            .detach(|| lock(&self.inner)?.wait().map_err(to_pyerr))
            .map(ExitStatus)?;
        Ok(status)
    }

    /// Return the exit status if the process has finished, else None.
    fn poll(&self) -> PyResult<Option<ExitStatus>> {
        Ok(lock(&self.inner)?
            .try_wait()
            .map_err(to_pyerr)?
            .map(ExitStatus))
    }

    /// Send SIGKILL and close the channel.
    fn kill(&self) -> PyResult<()> {
        lock(&self.inner)?.kill().map_err(to_pyerr)
    }

    /// Write `input` (if any) to stdin, close it, read stdout and stderr to
    /// EOF and wait. Returns `(stdout, stderr)`.
    #[pyo3(signature = (input = None))]
    fn communicate(
        &self,
        py: Python<'_>,
        input: Option<Vec<u8>>,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let stdin = self.stdin.as_ref().map(|s| s.clone_ref(py));
        let stdout = self.stdout.as_ref().map(|s| s.clone_ref(py));
        let stderr = self.stderr.as_ref().map(|s| s.clone_ref(py));
        let (out, err) = py.detach(move || -> PyResult<(Vec<u8>, Vec<u8>)> {
            // Writer thread so a large input cannot deadlock against unread output.
            let writer = std::thread::spawn(move || -> std::io::Result<()> {
                if let Some(s) = stdin {
                    let guard = Python::attach(|py| s.bind(py).borrow().take_inner());
                    if let Some(mut w) = guard {
                        if let Some(data) = input {
                            w.write_all(&data)?;
                        }
                        w.close()?;
                    }
                }
                Ok(())
            });
            let err_reader = std::thread::spawn(move || -> PyResult<Vec<u8>> {
                match stderr {
                    Some(s) => Python::attach(|py| s.bind(py).borrow().read_all_detached(py)),
                    None => Ok(Vec::new()),
                }
            });
            let out = match stdout {
                Some(s) => Python::attach(|py| s.bind(py).borrow().read_all_detached(py))?,
                None => Vec::new(),
            };
            let err = err_reader
                .join()
                .map_err(|_| PyValueError::new_err("stderr reader panicked"))??;
            writer
                .join()
                .map_err(|_| PyValueError::new_err("stdin writer panicked"))?
                .map_err(io_to_pyerr)?;
            Ok((out, err))
        })?;
        let _ = self.wait(py)?;
        Ok((PyBytes::new(py, &out).unbind(), PyBytes::new(py, &err).unbind()))
    }

    fn __repr__(&self) -> String {
        "Child(...)".to_string()
    }
}

/// Writable stdin of a `Child`.
#[pyclass(name = "ChildStdin", module = "tues")]
pub struct ChildStdin {
    inner: Mutex<Option<tues_sync::ChildStdin>>,
}

impl ChildStdin {
    fn take_inner(&self) -> Option<tues_sync::ChildStdin> {
        self.inner.lock().ok().and_then(|mut g| g.take())
    }
}

#[pymethods]
impl ChildStdin {
    /// Write bytes; returns the number written.
    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        py.detach(|| {
            let mut g = lock(&self.inner)?;
            let Some(w) = g.as_mut() else {
                return Err(PyValueError::new_err("stdin is closed"));
            };
            w.write_all(data).map_err(io_to_pyerr)?;
            Ok(data.len())
        })
    }

    fn flush(&self) -> PyResult<()> {
        Ok(())
    }

    /// Send EOF.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| match self.take_inner() {
            Some(w) => w.close().map_err(io_to_pyerr),
            None => Ok(()),
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

/// Readable stdout/stderr of a `Child`.
#[pyclass(name = "ChildStdout", module = "tues")]
pub struct ChildStdout {
    inner: Mutex<Reader>,
}

impl ChildStdout {
    fn read_all_detached(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            let mut v = Vec::new();
            lock(&self.inner)?.read_to_end(&mut v).map_err(io_to_pyerr)?;
            Ok(v)
        })
    }

    fn read_n(&self, py: Python<'_>, n: usize) -> PyResult<Vec<u8>> {
        py.detach(|| {
            let mut buf = vec![0u8; n];
            let got = lock(&self.inner)?.read(&mut buf).map_err(io_to_pyerr)?;
            buf.truncate(got);
            Ok(buf)
        })
    }
}

#[pymethods]
impl ChildStdout {
    /// Read up to `n` bytes (at least one unless EOF), or everything when
    /// `n` is negative.
    #[pyo3(signature = (n = -1))]
    fn read(&self, py: Python<'_>, n: isize) -> PyResult<Py<PyBytes>> {
        let v = if n < 0 {
            self.read_all_detached(py)?
        } else {
            self.read_n(py, n as usize)?
        };
        Ok(PyBytes::new(py, &v).unbind())
    }

    /// Read exactly `n` bytes (fewer only at EOF).
    fn read_exact(&self, py: Python<'_>, n: usize) -> PyResult<Py<PyBytes>> {
        let v = py.detach(|| {
            let mut out = Vec::with_capacity(n);
            let mut g = lock(&self.inner)?;
            let mut buf = vec![0u8; 16 * 1024];
            while out.len() < n {
                let want = (n - out.len()).min(buf.len());
                let got = g.read(&mut buf[..want]).map_err(io_to_pyerr)?;
                if got == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..got]);
            }
            Ok::<_, PyErr>(out)
        })?;
        Ok(PyBytes::new(py, &v).unbind())
    }

    /// Read one line including the newline (empty at EOF).
    fn readline(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let v = py.detach(|| {
            let mut out = Vec::new();
            let mut g = lock(&self.inner)?;
            let mut b = [0u8; 1];
            loop {
                let got = g.read(&mut b).map_err(io_to_pyerr)?;
                if got == 0 {
                    break;
                }
                out.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Ok::<_, PyErr>(out)
        })?;
        Ok(PyBytes::new(py, &v).unbind())
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        let line = self.readline(py)?;
        if line.bind(py).is_empty()? {
            Ok(None)
        } else {
            Ok(Some(line))
        }
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
        let f = py.detach(move || s.open_with(path, opts)).map_err(to_pyerr)?;
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
