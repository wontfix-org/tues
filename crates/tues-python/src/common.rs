//! Shared conversions between Python and `tues-core` types.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use pyo3::conversion::FromPyObjectOwned;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use tues_core::{
    ConnectOptions, Error, HostKeyPolicy, MemoizingPasswordManager, NoPasswordManager,
    PasswordKind, PasswordManager, PasswordPromptFinish as CorePasswordPromptFinish,
    PasswordPrompter, SecretString, SshConfigSource, StaticPasswordManager, Stdio, shared,
};

create_exception!(tues, TuesError, PyException, "Base class for tues errors.");
create_exception!(tues, ConnectError, TuesError, "Connection failed.");
create_exception!(tues, AuthError, TuesError, "Authentication failed.");
create_exception!(
    tues,
    HostKeyError,
    TuesError,
    "Host key unknown or changed."
);
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
                return Err(PyValueError::new_err(format!(
                    "unexpected keyword argument {k:?}"
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exit status
// ---------------------------------------------------------------------------

/// Linux signal numbers for the names SSH servers report in `exit-signal`.
fn signal_number(name: &str) -> Option<i32> {
    // OpenSSH may suffix non-standard names with "@domain"; be lenient about
    // a "SIG" prefix too.
    let name = name.split('@').next().unwrap_or(name);
    let name = name.strip_prefix("SIG").unwrap_or(name);
    Some(match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        _ => return None,
    })
}

/// `subprocess`-style return code: the exit code, or `-N` when the process
/// was terminated by signal `N`. Signals that cannot be mapped to a number
/// become `-1`.
pub fn returncode(status: &tues_core::ExitStatus) -> i32 {
    match status.code() {
        Some(c) => c,
        None => status
            .signal()
            .and_then(signal_number)
            .map(|n| -n)
            .unwrap_or(-1),
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
        format!(
            "Metadata(size={}, type={:?})",
            self.0.size, self.0.file_type
        )
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
    fn login_user(&self) -> &str {
        &self.0.login_user
    }
    /// The user the command runs as, for a sudo request.
    #[getter]
    fn user(&self) -> Option<&str> {
        self.0.user.as_deref()
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

/// What the terminal shows after a hidden password has been read.
///
/// Echo is off while the password is typed, so Enter does not move the
/// cursor. The legacy password prompt continues on the next line.
#[pyclass(
    eq,
    eq_int,
    frozen,
    from_py_object,
    module = "tues",
    name = "PasswordPromptFinish"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordPromptFinish {
    /// Continue at column 0 of the next line.
    Newline,
    /// Leave the cursor at the end of the prompt.
    CurrentLine,
    /// Erase the prompt so later output is not prefixed by it.
    Erase,
}

impl From<PasswordPromptFinish> for CorePasswordPromptFinish {
    fn from(finish: PasswordPromptFinish) -> Self {
        match finish {
            PasswordPromptFinish::Newline => Self::Newline,
            PasswordPromptFinish::CurrentLine => Self::CurrentLine,
            PasswordPromptFinish::Erase => Self::Erase,
        }
    }
}

/// The type of the `LOGIN_USER` sentinel.
///
/// Passing `user=LOGIN_USER` to a command runs it as the login user, never
/// via `sudo`, even when the session has a default user. It is the Python
/// spelling of [`tues_core::CommandUser::LoginUser`]; a string is
/// `CommandUser::User` and leaving `user` out is `CommandUser::Inherit`.
#[pyclass(frozen, module = "tues", name = "LoginUser")]
pub struct LoginUser;

#[pymethods]
impl LoginUser {
    fn __repr__(&self) -> &'static str {
        "tues.LOGIN_USER"
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

    fn prompts_for(&self, _req: &tues_core::PasswordRequest) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Connection options from kwargs
// ---------------------------------------------------------------------------

const CONNECT_KEYS: &[&str] = &[
    "login_user",
    "port",
    "user",
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
    o.login_user = kw(kwargs, "login_user")?;
    o.port = kw(kwargs, "port")?;
    o.user = kw(kwargs, "user")?;
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
        o.host_key_policy = Some(HostKeyPolicy::parse(&p).ok_or_else(|| {
            PyValueError::new_err(format!("host_key_policy: unknown value {p:?}"))
        })?);
    }
    if let Some(p) = kw::<PathBuf>(kwargs, "known_hosts_file")? {
        o.known_hosts_file = Some(vec![p]);
    }
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
    if let Some(d) = kwargs
        && let Some(v) = d.get_item("password")?
    {
        // `password=None` means there is no password. Leaving the argument
        // out keeps the default, which prompts on the terminal.
        if v.is_none() {
            o.password_manager = Some(shared(NoPasswordManager));
        } else {
            let pw: String = v
                .extract()
                .map_err(|e: PyErr| PyValueError::new_err(format!("password: {e}")))?;
            o.password_manager = Some(shared(StaticPasswordManager::new(pw)));
        }
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

const COMMAND_KEYS: &[&str] = &["user", "pty", "env", "cwd", "stdin", "stdout", "stderr"];

/// `subprocess.PIPE`.
pub const PIPE: i32 = -1;
/// `subprocess.STDOUT` (handled in the Python layer; rejected here).
pub const STDOUT: i32 = -2;
/// `subprocess.DEVNULL`.
pub const DEVNULL: i32 = -3;

/// Map a `subprocess`-style stdio argument (`None`, `PIPE`, `DEVNULL`) to
/// [`Stdio`]. `None` means "inherit the local process stream".
fn parse_stdio(name: &str, v: Option<i32>) -> PyResult<Stdio> {
    match v {
        None => Ok(Stdio::Inherit),
        Some(PIPE) => Ok(Stdio::Piped),
        Some(DEVNULL) => Ok(Stdio::Null),
        Some(STDOUT) => Err(PyValueError::new_err(format!(
            "{name}: STDOUT is only valid for stderr and is resolved by the Python layer"
        ))),
        Some(other) => Err(PyValueError::new_err(format!(
            "{name}: expected None, PIPE or DEVNULL, not {other}"
        ))),
    }
}

/// Build a command from an argv list plus kwargs.
///
/// With `shell=True`, `argv[0]` is a shell script run by `sh -c` and the
/// remaining elements become its positional parameters (`$0`, `$1`, ...),
/// exactly like `subprocess` with `shell=True`.
pub fn command(
    argv: Vec<String>,
    shell: bool,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<tues_core::Command> {
    check_keys(kwargs, COMMAND_KEYS)?;
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| PyValueError::new_err("args must not be empty"))?;
    let mut c = if shell {
        tues_core::Command::shell(program)
    } else {
        tues_core::Command::new(program)
    };
    c.args(args.iter().cloned());
    if let Some(u) = kw::<Bound<'_, PyAny>>(kwargs, "user")? {
        if u.is_instance_of::<LoginUser>() {
            c.as_login_user();
        } else if let Ok(name) = u.extract::<String>() {
            c.user(name);
        } else {
            return Err(PyTypeError::new_err(format!(
                "user must be a str or LOGIN_USER, not {}",
                u.get_type().name()?
            )));
        }
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
    c.stdin(parse_stdio("stdin", kw(kwargs, "stdin")?)?);
    c.stdout(parse_stdio("stdout", kw(kwargs, "stdout")?)?);
    c.stderr(parse_stdio("stderr", kw(kwargs, "stderr")?)?);
    Ok(c)
}

/// Convert an optional Python timeout (seconds) to a `Duration`.
pub fn timeout_duration(timeout: Option<f64>) -> Option<Duration> {
    timeout.map(|t| Duration::from_secs_f64(t.max(0.0)))
}

/// Normalise a signal name for the SSH `signal` request: accepts `"TERM"`
/// or `"SIGTERM"`.
pub fn signal_name(name: &str) -> PyResult<String> {
    let name = name.strip_prefix("SIG").unwrap_or(name);
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '@' || c == '.' || c == '-')
    {
        return Err(PyValueError::new_err(format!(
            "invalid signal name {name:?}"
        )));
    }
    Ok(name.to_string())
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
        0 => std::io::SeekFrom::Start(
            u64::try_from(offset).map_err(|_| PyValueError::new_err("negative seek"))?,
        ),
        1 => std::io::SeekFrom::Current(offset),
        2 => std::io::SeekFrom::End(offset),
        _ => return Err(PyValueError::new_err("whence must be 0, 1 or 2")),
    })
}
