//! Shared conversions between Python and `tues-core` types.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use pyo3::conversion::FromPyObjectOwned;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use tues_core::{
    ConnectOptions, Error, HostKeyPolicy, MemoizingPasswordManager, PasswordKind,
    PasswordManager, PasswordPrompter, SecretString, SshConfigSource, StaticPasswordManager,
    Stdio, shared,
};

create_exception!(tues, TuesError, PyException, "Base class for tues errors.");
create_exception!(tues, ConnectError, TuesError, "Connection failed.");
create_exception!(tues, AuthError, TuesError, "Authentication failed.");
create_exception!(tues, HostKeyError, TuesError, "Host key unknown or changed.");
create_exception!(tues, SudoError, TuesError, "Privilege elevation failed.");
create_exception!(tues, SftpError, TuesError, "SFTP operation failed.");

pub fn to_pyerr(e: Error) -> PyErr {
    let msg = e.to_string();
    match e {
        Error::Connect { .. } | Error::ConnectTimeout { .. } | Error::Disconnected => {
            ConnectError::new_err(msg)
        }
        Error::Auth { .. } => AuthError::new_err(msg),
        Error::UnknownHostKey { .. } | Error::HostKeyChanged { .. } => HostKeyError::new_err(msg),
        Error::Sudo(_) => SudoError::new_err(msg),
        Error::Sftp(_) => SftpError::new_err(msg),
        Error::Io(e) => e.into(),
        _ => TuesError::new_err(msg),
    }
}

pub fn io_to_pyerr(e: std::io::Error) -> PyErr {
    e.into()
}

/// Fetch and extract an optional keyword argument.
pub fn kw<'py, T: FromPyObjectOwned<'py>>(
    kwargs: Option<&Bound<'py, PyDict>>,
    key: &str,
) -> PyResult<Option<T>> {
    let Some(d) = kwargs else {
        return Ok(None);
    };
    match d.get_item(key)? {
        None => Ok(None),
        Some(v) if v.is_none() => Ok(None),
        Some(v) => v
            .extract::<T>()
            .map(Some)
            .map_err(|e| PyValueError::new_err(format!("{key}: {}", e.into()))),
    }
}

fn check_keys(kwargs: Option<&Bound<'_, PyDict>>, allowed: &[&str]) -> PyResult<()> {
    if let Some(d) = kwargs {
        for k in d.keys() {
            let k: String = k.extract()?;
            if !allowed.contains(&k.as_str()) {
                return Err(PyValueError::new_err(format!("unexpected keyword argument {k:?}")));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exit status / output
// ---------------------------------------------------------------------------

/// Exit status of a remote process.
#[pyclass(name = "ExitStatus", module = "tues", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct ExitStatus(pub tues_core::ExitStatus);

#[pymethods]
impl ExitStatus {
    /// Exit code, or None if killed by a signal.
    #[getter]
    fn code(&self) -> Option<i32> {
        self.0.code()
    }

    /// Signal name (without SIG), or None.
    #[getter]
    fn signal(&self) -> Option<String> {
        self.0.signal().map(str::to_string)
    }

    #[getter]
    fn success(&self) -> bool {
        self.0.success()
    }

    fn __bool__(&self) -> bool {
        self.0.success()
    }

    fn __repr__(&self) -> String {
        format!("ExitStatus({})", self.0)
    }
}

/// Captured output of a finished remote process.
#[pyclass(name = "Output", module = "tues", frozen)]
pub struct Output {
    #[pyo3(get)]
    pub status: ExitStatus,
    #[pyo3(get)]
    pub stdout: Py<PyBytes>,
    #[pyo3(get)]
    pub stderr: Py<PyBytes>,
}

impl Output {
    pub fn from_core(py: Python<'_>, o: tues_core::Output) -> Self {
        Output {
            status: ExitStatus(o.status),
            stdout: PyBytes::new(py, &o.stdout).unbind(),
            stderr: PyBytes::new(py, &o.stderr).unbind(),
        }
    }
}

#[pymethods]
impl Output {
    /// Exit code (None if killed by a signal).
    #[getter]
    fn returncode(&self) -> Option<i32> {
        self.status.0.code()
    }

    #[getter]
    fn success(&self) -> bool {
        self.status.0.success()
    }

    /// stdout decoded as UTF-8 (lossy).
    fn text(&self, py: Python<'_>) -> String {
        String::from_utf8_lossy(self.stdout.bind(py).as_bytes()).into_owned()
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "Output(status={}, stdout={} bytes, stderr={} bytes)",
            self.status.0,
            self.stdout.bind(py).len().unwrap_or(0),
            self.stderr.bind(py).len().unwrap_or(0)
        )
    }
}

// ---------------------------------------------------------------------------
// SFTP metadata
// ---------------------------------------------------------------------------

fn to_epoch(t: Option<SystemTime>) -> Option<f64> {
    t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
}

/// Remote file metadata.
#[pyclass(name = "Metadata", module = "tues", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct Metadata(pub tues_core::Metadata);

#[pymethods]
impl Metadata {
    #[getter]
    fn size(&self) -> u64 {
        self.0.size
    }
    #[getter]
    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
    #[getter]
    fn is_file(&self) -> bool {
        self.0.is_file()
    }
    #[getter]
    fn is_symlink(&self) -> bool {
        self.0.is_symlink()
    }
    /// Full mode bits (type + permissions), if reported.
    #[getter]
    fn mode(&self) -> Option<u32> {
        self.0.mode
    }
    /// Permission bits only.
    #[getter]
    fn permissions(&self) -> Option<u32> {
        self.0.permissions()
    }
    #[getter]
    fn uid(&self) -> Option<u32> {
        self.0.uid
    }
    #[getter]
    fn gid(&self) -> Option<u32> {
        self.0.gid
    }
    /// Modification time as seconds since the epoch.
    #[getter]
    fn mtime(&self) -> Option<f64> {
        to_epoch(self.0.modified)
    }
    #[getter]
    fn atime(&self) -> Option<f64> {
        to_epoch(self.0.accessed)
    }
    fn __repr__(&self) -> String {
        format!("Metadata(size={}, type={:?})", self.0.size, self.0.file_type)
    }
}

/// A directory entry.
#[pyclass(name = "DirEntry", module = "tues", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct DirEntry {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub metadata: Metadata,
}

impl From<tues_core::DirEntry> for DirEntry {
    fn from(e: tues_core::DirEntry) -> Self {
        DirEntry {
            name: e.file_name,
            metadata: Metadata(e.metadata),
        }
    }
}

#[pymethods]
impl DirEntry {
    fn __repr__(&self) -> String {
        format!("DirEntry({:?})", self.name)
    }
}

pub fn dir_entries(py: Python<'_>, entries: Vec<tues_core::DirEntry>) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);
    for e in entries {
        list.append(Py::new(py, DirEntry::from(e))?)?;
    }
    Ok(list.unbind())
}

// ---------------------------------------------------------------------------
// Password manager bridge
// ---------------------------------------------------------------------------

/// Context of a password request handed to a Python password manager.
#[pyclass(name = "PasswordRequest", module = "tues", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PasswordRequest(pub tues_core::PasswordRequest);

#[pymethods]
impl PasswordRequest {
    /// "login", "sudo" or "key_passphrase".
    #[getter]
    fn kind(&self) -> &'static str {
        match self.0.kind {
            PasswordKind::Login => "login",
            PasswordKind::Sudo => "sudo",
            PasswordKind::KeyPassphrase => "key_passphrase",
        }
    }
    #[getter]
    fn host(&self) -> &str {
        &self.0.host
    }
    #[getter]
    fn port(&self) -> u16 {
        self.0.port
    }
    #[getter]
    fn user(&self) -> &str {
        &self.0.user
    }
    #[getter]
    fn run_as(&self) -> Option<&str> {
        self.0.run_as.as_deref()
    }
    #[getter]
    fn key_path(&self) -> Option<String> {
        self.0.key_path.as_ref().map(|p| p.display().to_string())
    }
    /// A human readable prompt.
    #[getter]
    fn prompt(&self) -> String {
        self.0.prompt_text()
    }
    fn __repr__(&self) -> String {
        format!("PasswordRequest({:?})", self.0.prompt_text().trim_end())
    }
}

/// Calls a Python object to obtain a password.
///
/// Implements both [`PasswordPrompter`] (used when the object is a plain
/// callable or only has `get`, in which case Rust memoizes the answers) and
/// [`PasswordManager`] (used when the object also has `invalidate`, in which
/// case it owns caching).
pub struct PyPasswordSource {
    obj: Py<PyAny>,
}

impl PyPasswordSource {
    fn ask(&self, req: &tues_core::PasswordRequest) -> tues_core::Result<SecretString> {
        let result: PyResult<Option<String>> = Python::attach(|py| {
            let obj = self.obj.bind(py);
            let request = Py::new(py, PasswordRequest(req.clone()))?;
            let result = if obj.hasattr("get")? {
                obj.call_method1("get", (request,))?
            } else {
                obj.call1((request,))?
            };
            if result.is_none() {
                return Ok(None);
            }
            Ok(Some(result.extract::<String>()?))
        });
        result
            .map_err(|e| Error::Password(format!("python password manager: {e}")))?
            .map(SecretString::from)
            .ok_or_else(|| Error::Password("password manager returned None".into()))
    }
}

impl PasswordPrompter for PyPasswordSource {
    fn prompt(&mut self, req: &tues_core::PasswordRequest) -> tues_core::Result<SecretString> {
        self.ask(req)
    }
}

impl PasswordManager for PyPasswordSource {
    fn get(&mut self, req: &tues_core::PasswordRequest) -> tues_core::Result<SecretString> {
        self.ask(req)
    }

    fn invalidate(&mut self, req: &tues_core::PasswordRequest) {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            if let Ok(request) = Py::new(py, PasswordRequest(req.clone())) {
                let _ = obj.call_method1("invalidate", (request,));
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Connection options from kwargs
// ---------------------------------------------------------------------------

const CONNECT_KEYS: &[&str] = &[
    "user",
    "port",
    "run_as",
    "host_name",
    "identity_files",
    "identities_only",
    "proxy_jump",
    "connect_timeout",
    "server_alive_interval",
    "compression",
    "use_agent",
    "pubkey_authentication",
    "password_authentication",
    "host_key_policy",
    "known_hosts_file",
    "ssh_config",
    "password",
    "password_manager",
];

fn v_has_invalidate(src: &PyPasswordSource) -> PyResult<bool> {
    Python::attach(|py| src.obj.bind(py).hasattr("invalidate"))
}

pub fn connect_options(
    destination: &str,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<ConnectOptions> {
    check_keys(kwargs, CONNECT_KEYS)?;
    let mut o = ConnectOptions::new(destination);
    o.user = kw(kwargs, "user")?;
    o.port = kw(kwargs, "port")?;
    o.run_as = kw(kwargs, "run_as")?;
    o.host_name = kw(kwargs, "host_name")?;
    if let Some(files) = kw::<Vec<PathBuf>>(kwargs, "identity_files")? {
        o.identity_files = files;
    }
    o.identities_only = kw(kwargs, "identities_only")?;
    if let Some(pj) = kw::<String>(kwargs, "proxy_jump")? {
        o = if pj.eq_ignore_ascii_case("none") {
            o.no_proxy_jump()
        } else {
            o.proxy_jump(pj)
        };
    }
    o.connect_timeout = kw::<f64>(kwargs, "connect_timeout")?.map(Duration::from_secs_f64);
    o.server_alive_interval =
        kw::<f64>(kwargs, "server_alive_interval")?.map(Duration::from_secs_f64);
    o.compression = kw(kwargs, "compression")?;
    o.use_agent = kw(kwargs, "use_agent")?;
    o.pubkey_authentication = kw(kwargs, "pubkey_authentication")?;
    o.password_authentication = kw(kwargs, "password_authentication")?;
    if let Some(p) = kw::<String>(kwargs, "host_key_policy")? {
        o.host_key_policy = Some(
            HostKeyPolicy::parse(&p)
                .ok_or_else(|| PyValueError::new_err(format!("host_key_policy: unknown value {p:?}")))?,
        );
    }
    o.known_hosts_file = kw(kwargs, "known_hosts_file")?;
    if let Some(d) = kwargs
        && let Some(v) = d.get_item("ssh_config")?
    {
        if v.is_none() {
            o.ssh_config = SshConfigSource::Default;
        } else if let Ok(b) = v.extract::<bool>() {
            o.ssh_config = if b {
                SshConfigSource::Default
            } else {
                SshConfigSource::None
            };
        } else {
            let p: PathBuf = v.extract()?;
            o.ssh_config = SshConfigSource::File(p);
        }
    }
    if let Some(pw) = kw::<String>(kwargs, "password")? {
        o.password_manager = Some(shared(StaticPasswordManager::new(pw)));
    }
    if let Some(d) = kwargs
        && let Some(v) = d.get_item("password_manager")?
        && !v.is_none()
    {
        let has_get = v.hasattr("get")?;
        if !has_get && !v.is_callable() {
            return Err(PyValueError::new_err(
                "password_manager must have a get(request) method or be callable",
            ));
        }
        let source = PyPasswordSource { obj: v.unbind() };
        o.password_manager = Some(if has_get && v_has_invalidate(&source)? {
            shared(source)
        } else {
            shared(MemoizingPasswordManager::new(source))
        });
    }
    Ok(o)
}

// ---------------------------------------------------------------------------
// Command from Python
// ---------------------------------------------------------------------------

const COMMAND_KEYS: &[&str] = &[
    "run_as",
    "run_as_login_user",
    "pty",
    "env",
    "cwd",
    "stdin",
    "stdout",
    "stderr",
    "input",
    "check",
];

pub fn parse_stdio(v: &str) -> PyResult<Stdio> {
    match v {
        "pipe" | "piped" => Ok(Stdio::Piped),
        "null" | "devnull" => Ok(Stdio::Null),
        "inherit" => Ok(Stdio::Inherit),
        other => Err(PyValueError::new_err(format!(
            "stdio must be 'pipe', 'null' or 'inherit', not {other:?}"
        ))),
    }
}

/// Build a command from `str` (shell line) or `list[str]` (argv) plus kwargs.
pub fn command(
    cmd: &Bound<'_, PyAny>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<tues_core::Command> {
    check_keys(kwargs, COMMAND_KEYS)?;
    let mut c = if let Ok(s) = cmd.extract::<String>() {
        tues_core::Command::shell(s)
    } else {
        let argv: Vec<String> = cmd.extract().map_err(|_| {
            PyValueError::new_err("command must be a str or a non-empty list of str")
        })?;
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| PyValueError::new_err("command list must not be empty"))?;
        let mut c = tues_core::Command::new(program);
        c.args(args.iter().cloned());
        c
    };
    if let Some(u) = kw::<String>(kwargs, "run_as")? {
        c.run_as(u);
    }
    if kw::<bool>(kwargs, "run_as_login_user")?.unwrap_or(false) {
        c.run_as_login_user();
    }
    if kw::<bool>(kwargs, "pty")?.unwrap_or(false) {
        c.pty(true);
    }
    if let Some(env) = kw::<std::collections::HashMap<String, Option<String>>>(kwargs, "env")? {
        for (k, v) in env {
            match v {
                Some(v) => c.env(k, v),
                None => c.env_remove(k),
            };
        }
    }
    if let Some(d) = kw::<String>(kwargs, "cwd")? {
        c.current_dir(d);
    }
    if let Some(s) = kw::<String>(kwargs, "stdin")? {
        c.stdin(parse_stdio(&s)?);
    }
    if let Some(s) = kw::<String>(kwargs, "stdout")? {
        c.stdout(parse_stdio(&s)?);
    }
    if let Some(s) = kw::<String>(kwargs, "stderr")? {
        c.stderr(parse_stdio(&s)?);
    }
    Ok(c)
}

/// The `input=` bytes for `run`, if any.
pub fn run_input(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Option<Vec<u8>>> {
    kw::<Vec<u8>>(kwargs, "input")
}

/// The `check=` flag for `run`.
pub fn run_check(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
    Ok(kw::<bool>(kwargs, "check")?.unwrap_or(false))
}

/// Run a command to completion, feeding `input` to stdin concurrently.
pub async fn run_async(
    session: &tues_async::Session,
    mut cmd: tues_core::Command,
    input: Option<Vec<u8>>,
) -> tues_core::Result<tues_core::Output> {
    use tokio::io::AsyncWriteExt;
    match input {
        None => session.output(&cmd).await,
        Some(data) => {
            cmd.stdin(Stdio::Piped);
            if cmd.get_stdout().is_none() {
                cmd.stdout(Stdio::Piped);
            }
            if cmd.get_stderr().is_none() {
                cmd.stderr(Stdio::Piped);
            }
            let mut child = session.spawn(&cmd).await?;
            let mut stdin = child.stdin.take();
            let writer = async move {
                if let Some(s) = stdin.as_mut() {
                    s.write_all(&data).await?;
                    s.shutdown().await?;
                }
                Ok::<_, std::io::Error>(())
            };
            let (w, out) = tokio::join!(writer, child.wait_with_output());
            // A closed pipe while writing means the command exited early; the
            // output/status tells the caller what happened.
            let _ = w;
            out
        }
    }
}

pub fn check_output(check: bool, out: &tues_core::Output) -> PyResult<()> {
    if check && !out.status.success() {
        return Err(TuesError::new_err(format!(
            "command failed with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim_end()
        )));
    }
    Ok(())
}

/// Parse a Python-style open mode into [`tues_core::OpenOptions`].
pub fn open_options(mode: &str) -> PyResult<tues_core::OpenOptions> {
    let m = mode.replace('b', "");
    let o = tues_core::OpenOptions::new();
    Ok(match m.as_str() {
        "r" | "" => o.read(true),
        "r+" => o.read(true).write(true),
        "w" => o.write(true).create(true).truncate(true),
        "w+" => o.read(true).write(true).create(true).truncate(true),
        "a" => o.append(true).create(true),
        "a+" => o.read(true).append(true).create(true),
        "x" => o.write(true).create_new(true),
        "x+" => o.read(true).write(true).create_new(true),
        other => return Err(PyValueError::new_err(format!("invalid mode {other:?}"))),
    })
}

pub fn seek_from(offset: i64, whence: i32) -> PyResult<std::io::SeekFrom> {
    Ok(match whence {
        0 => std::io::SeekFrom::Start(u64::try_from(offset).map_err(|_| PyValueError::new_err("negative seek"))?),
        1 => std::io::SeekFrom::Current(offset),
        2 => std::io::SeekFrom::End(offset),
        _ => return Err(PyValueError::new_err("whence must be 0, 1 or 2")),
    })
}
