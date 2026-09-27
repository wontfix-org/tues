//! asyncio Python API.
//!
//! Every method returns an awaitable backed by a tokio future. This is the
//! low-level layer under `tues.AsyncSession` / `tues.Process`.

use std::path::PathBuf;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_async_runtimes::tokio::future_into_py;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::common::{
    self, Metadata, command, connect_options, io_to_pyerr, returncode, signal_name, to_pyerr,
};

fn bytes(v: &[u8]) -> Py<PyBytes> {
    Python::attach(|py| PyBytes::new(py, v).unbind())
}

/// An asyncio SSH session.
#[pyclass(name = "AsyncSession", module = "tues._tues", skip_from_py_object)]
#[derive(Clone)]
pub struct AsyncSession {
    inner: tues_async::Session,
}

#[pymethods]
impl AsyncSession {
    /// Connect to `destination`. Accepts the same keyword arguments as
    /// `Session.connect`.
    #[staticmethod]
    #[pyo3(signature = (destination, **kwargs))]
    fn connect<'py>(
        py: Python<'py>,
        destination: &str,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let opts = connect_options(destination, kwargs)?;
        future_into_py(py, async move {
            let inner = tues_async::Session::connect(opts).await.map_err(to_pyerr)?;
            Ok(AsyncSession { inner })
        })
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

    #[getter]
    fn user(&self) -> Option<String> {
        self.inner.user().map(str::to_string)
    }

    #[getter]
    fn closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Start a remote process; resolves to an `AsyncChild`. Same arguments
    /// as `Session.spawn`.
    #[pyo3(signature = (args, shell = false, **kwargs))]
    fn spawn<'py>(
        &self,
        py: Python<'py>,
        args: Vec<String>,
        shell: bool,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let c = command(args, shell, kwargs)?;
        let session = self.inner.clone();
        future_into_py(py, async move {
            let mut child = session.spawn(&c).await.map_err(to_pyerr)?;
            Python::attach(|py| {
                let stdin = match child.stdin.take() {
                    Some(s) => Some(Py::new(
                        py,
                        AsyncChildStdin {
                            inner: Arc::new(Mutex::new(Some(s))),
                        },
                    )?),
                    None => None,
                };
                let stdout = match child.stdout.take() {
                    Some(s) => Some(Py::new(
                        py,
                        AsyncChildStdout {
                            inner: Arc::new(Mutex::new(Reader::Stdout(s))),
                        },
                    )?),
                    None => None,
                };
                let stderr = match child.stderr.take() {
                    Some(s) => Some(Py::new(
                        py,
                        AsyncChildStdout {
                            inner: Arc::new(Mutex::new(Reader::Stderr(s))),
                        },
                    )?),
                    None => None,
                };
                Ok(AsyncChild {
                    signaller: child.signaller(),
                    inner: Arc::new(Mutex::new(child)),
                    stdin,
                    stdout,
                    stderr,
                })
            })
        })
    }

    /// Metadata for a remote file or directory.
    ///
    /// Shares a cached SFTP channel with `upload`, `download`, `delete` and
    /// `rename`, separate from `sftp()`.
    fn stat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move {
            session.stat(path).await.map(Metadata).map_err(to_pyerr)
        })
    }

    /// Copy a local file or directory to `remote`.
    fn upload<'py>(
        &self,
        py: Python<'py>,
        local: PathBuf,
        remote: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move {
            session.upload(local, remote).await.map_err(to_pyerr)
        })
    }

    /// Copy a remote file or directory to `local`.
    fn download<'py>(
        &self,
        py: Python<'py>,
        remote: String,
        local: PathBuf,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move {
            session.download(remote, local).await.map_err(to_pyerr)
        })
    }

    /// Remove a remote file, symlink or directory tree.
    fn delete<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(
            py,
            async move { session.delete(path).await.map_err(to_pyerr) },
        )
    }

    /// Rename a remote file or directory.
    fn rename<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move {
            session.rename(src, dst).await.map_err(to_pyerr)
        })
    }

    /// Open an SFTP session.
    fn sftp<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move {
            let inner = session.sftp().await.map_err(to_pyerr)?;
            Ok(AsyncSftp { inner })
        })
    }

    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        future_into_py(py, async move { session.close().await.map_err(to_pyerr) })
    }

    fn __repr__(&self) -> String {
        format!(
            "AsyncSession({}@{}:{})",
            self.inner.login_user(),
            self.inner.host(),
            self.inner.options().port
        )
    }
}

/// A running remote process (raw asyncio handle; see `tues.Process`).
#[pyclass(name = "AsyncChild", module = "tues._tues")]
pub struct AsyncChild {
    inner: Arc<Mutex<tues_async::Child>>,
    signaller: tues_async::ChildSignaller,
    stdin: Option<Py<AsyncChildStdin>>,
    stdout: Option<Py<AsyncChildStdout>>,
    stderr: Option<Py<AsyncChildStdout>>,
}

#[pymethods]
impl AsyncChild {
    #[getter]
    fn stdin(&self, py: Python<'_>) -> Option<Py<AsyncChildStdin>> {
        self.stdin.as_ref().map(|s| s.clone_ref(py))
    }

    #[getter]
    fn stdout(&self, py: Python<'_>) -> Option<Py<AsyncChildStdout>> {
        self.stdout.as_ref().map(|s| s.clone_ref(py))
    }

    #[getter]
    fn stderr(&self, py: Python<'_>) -> Option<Py<AsyncChildStdout>> {
        self.stderr.as_ref().map(|s| s.clone_ref(py))
    }

    /// Await the return code (negative signal number if killed).
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let status = inner.lock().await.wait().await.map_err(to_pyerr)?;
            Ok(returncode(&status))
        })
    }

    /// Non-blocking status check: the return code, or None while running
    /// (or while another task is inside `wait()`).
    fn poll(&self) -> PyResult<Option<i32>> {
        match self.inner.try_lock() {
            Ok(mut g) => Ok(g.try_wait().map_err(to_pyerr)?.as_ref().map(returncode)),
            Err(_) => Ok(None),
        }
    }

    /// The return code if known, else None (alias of `poll()`).
    #[getter]
    fn returncode(&self) -> PyResult<Option<i32>> {
        self.poll()
    }

    /// Send a signal by name ("TERM", "SIGTERM", ...).
    fn send_signal(&self, name: &str) -> PyResult<()> {
        self.signaller.signal(signal_name(name)?).map_err(to_pyerr)
    }

    /// Send SIGKILL and close the channel.
    fn kill(&self) -> PyResult<()> {
        self.signaller.kill().map_err(to_pyerr)
    }

    fn __repr__(&self) -> String {
        "AsyncChild(...)".to_string()
    }
}

/// Raw writable stdin of an `AsyncChild`.
#[pyclass(name = "AsyncChildStdin", module = "tues._tues")]
pub struct AsyncChildStdin {
    inner: Arc<Mutex<Option<tues_async::ChildStdin>>>,
}

#[pymethods]
impl AsyncChildStdin {
    /// Write all of `data`; resolves to the number of bytes written.
    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let w = g
                .as_mut()
                .ok_or_else(|| PyValueError::new_err("write to closed stdin"))?;
            w.write_all(&data).await.map_err(io_to_pyerr)?;
            Ok(data.len())
        })
    }

    /// Send EOF. Idempotent.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            if let Some(w) = inner.lock().await.take() {
                w.close().await.map_err(io_to_pyerr)?;
            }
            Ok(())
        })
    }

    #[getter]
    fn closed(&self) -> bool {
        match self.inner.try_lock() {
            Ok(g) => g.is_none(),
            Err(_) => false,
        }
    }
}

enum Reader {
    Stdout(tues_async::ChildStdout),
    Stderr(tues_async::ChildStderr),
}

impl tokio::io::AsyncRead for Reader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Reader::Stdout(r) => std::pin::Pin::new(r).poll_read(cx, buf),
            Reader::Stderr(r) => std::pin::Pin::new(r).poll_read(cx, buf),
        }
    }
}

/// Raw readable stdout/stderr of an `AsyncChild`.
#[pyclass(name = "AsyncChildStdout", module = "tues._tues")]
pub struct AsyncChildStdout {
    inner: Arc<Mutex<Reader>>,
}

#[pymethods]
impl AsyncChildStdout {
    /// Read up to `n` bytes (at least one unless EOF), or everything when
    /// `n` is negative.
    #[pyo3(signature = (n = -1))]
    fn read<'py>(&self, py: Python<'py>, n: isize) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let v = if n < 0 {
                let mut v = Vec::new();
                g.read_to_end(&mut v).await.map_err(io_to_pyerr)?;
                v
            } else {
                let mut v = vec![0u8; n as usize];
                let got = g.read(&mut v).await.map_err(io_to_pyerr)?;
                v.truncate(got);
                v
            };
            Ok(bytes(&v))
        })
    }
}

/// asyncio SFTP session.
#[pyclass(name = "AsyncSftp", module = "tues")]
pub struct AsyncSftp {
    inner: tues_async::Sftp,
}

#[pymethods]
impl AsyncSftp {
    fn read<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            let v = s.read(path).await.map_err(to_pyerr)?;
            Ok(bytes(&v))
        })
    }

    fn read_text<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.read_to_string(path).await.map_err(to_pyerr) },
        )
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.write(path, &data).await.map_err(to_pyerr) },
        )
    }

    #[pyo3(signature = (path, mode = "r"))]
    fn open<'py>(&self, py: Python<'py>, path: String, mode: &str) -> PyResult<Bound<'py, PyAny>> {
        let opts = common::open_options(mode)?;
        let s = self.inner.clone();
        future_into_py(py, async move {
            let f = s.open_with(path, opts).await.map_err(to_pyerr)?;
            Ok(AsyncFile {
                inner: Arc::new(Mutex::new(Some(f))),
            })
        })
    }

    fn listdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            let entries = s.read_dir(path).await.map_err(to_pyerr)?;
            Python::attach(|py| common::dir_entries(py, entries))
        })
    }

    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.create_dir(path).await.map_err(to_pyerr) },
        )
    }

    fn remove<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.remove_file(path).await.map_err(to_pyerr) },
        )
    }

    fn rmdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.remove_dir(path).await.map_err(to_pyerr) },
        )
    }

    fn rename<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.rename(src, dst).await.map_err(to_pyerr) },
        )
    }

    fn symlink<'py>(
        &self,
        py: Python<'py>,
        target: String,
        link: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            s.symlink(target, link).await.map_err(to_pyerr)
        })
    }

    fn readlink<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move { s.read_link(path).await.map_err(to_pyerr) })
    }

    fn stat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            s.metadata(path).await.map(Metadata).map_err(to_pyerr)
        })
    }

    fn lstat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            s.symlink_metadata(path)
                .await
                .map(Metadata)
                .map_err(to_pyerr)
        })
    }

    fn exists<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.try_exists(path).await.map_err(to_pyerr) },
        )
    }

    fn realpath<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(
            py,
            async move { s.canonicalize(path).await.map_err(to_pyerr) },
        )
    }

    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move { s.close().await.map_err(to_pyerr) })
    }

    fn __aenter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (_exc_type, _exc, _tb))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc: Option<&Bound<'py, PyAny>>,
        _tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.inner.clone();
        future_into_py(py, async move {
            s.close().await.map_err(to_pyerr)?;
            Ok(false)
        })
    }
}

/// An open remote file (asyncio, binary).
#[pyclass(name = "AsyncFile", module = "tues")]
pub struct AsyncFile {
    inner: Arc<Mutex<Option<tues_async::File>>>,
}

fn closed_file() -> PyErr {
    PyValueError::new_err("I/O operation on closed file")
}

#[pymethods]
impl AsyncFile {
    #[pyo3(signature = (n = -1))]
    fn read<'py>(&self, py: Python<'py>, n: isize) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let f = g.as_mut().ok_or_else(closed_file)?;
            let v = if n < 0 {
                let mut v = Vec::new();
                f.read_to_end(&mut v).await.map_err(io_to_pyerr)?;
                v
            } else {
                let mut v = vec![0u8; n as usize];
                let mut filled = 0;
                while filled < v.len() {
                    let got = f.read(&mut v[filled..]).await.map_err(io_to_pyerr)?;
                    if got == 0 {
                        break;
                    }
                    filled += got;
                }
                v.truncate(filled);
                v
            };
            Ok(bytes(&v))
        })
    }

    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let f = g.as_mut().ok_or_else(closed_file)?;
            f.write_all(&data).await.map_err(io_to_pyerr)?;
            Ok(data.len())
        })
    }

    #[pyo3(signature = (offset, whence = 0))]
    fn seek<'py>(&self, py: Python<'py>, offset: i64, whence: i32) -> PyResult<Bound<'py, PyAny>> {
        let pos = common::seek_from(offset, whence)?;
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let f = g.as_mut().ok_or_else(closed_file)?;
            f.seek(pos).await.map_err(io_to_pyerr)
        })
    }

    fn tell<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let f = g.as_mut().ok_or_else(closed_file)?;
            f.stream_position().await.map_err(io_to_pyerr)
        })
    }

    fn flush<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut g = inner.lock().await;
            let f = g.as_mut().ok_or_else(closed_file)?;
            f.flush().await.map_err(io_to_pyerr)
        })
    }

    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            if let Some(mut f) = inner.lock().await.take() {
                f.shutdown().await.map_err(io_to_pyerr)?;
            }
            Ok(())
        })
    }

    #[getter]
    fn closed(&self) -> bool {
        match self.inner.try_lock() {
            Ok(g) => g.is_none(),
            Err(_) => false,
        }
    }

    fn __aenter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (_exc_type, _exc, _tb))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc: Option<&Bound<'py, PyAny>>,
        _tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            if let Some(mut f) = inner.lock().await.take() {
                f.shutdown().await.map_err(io_to_pyerr)?;
            }
            Ok(false)
        })
    }
}
