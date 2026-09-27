//! Python bindings for `tues`.
//!
//! This extension module (`tues._tues`) is the low-level layer: sessions,
//! raw child handles with byte pipes, SFTP. The `subprocess`-shaped public
//! API (`tues.Session.run`, `tues.Popen`, `tues.CompletedProcess`, text
//! mode, timeouts, ...) is implemented in the Python package on top of it.

use pyo3::prelude::*;

mod aio;
mod common;
mod sync;

/// Run the `tues` command line with `argv` (program name first) and return
/// its exit code. Backs the `tues` console script and `python -m tues`.
///
/// The interpreter's attach state is released for the duration: the CLI runs
/// on its own tokio runtime and never calls back into Python.
#[pyfunction]
fn cli_main(py: Python<'_>, argv: Vec<std::ffi::OsString>) -> i32 {
    py.detach(move || tues_cli::run(argv))
}

#[pymodule]
fn _tues(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(cli_main, m)?)?;

    m.add("PIPE", common::PIPE)?;
    m.add("STDOUT", common::STDOUT)?;
    m.add("DEVNULL", common::DEVNULL)?;
    m.add_class::<common::LoginUser>()?;
    m.add("LOGIN_USER", Py::new(py, common::LoginUser)?)?;

    m.add("TuesError", py.get_type::<common::TuesError>())?;
    m.add("ConnectError", py.get_type::<common::ConnectError>())?;
    m.add("AuthError", py.get_type::<common::AuthError>())?;
    m.add("HostKeyError", py.get_type::<common::HostKeyError>())?;
    m.add("SudoError", py.get_type::<common::SudoError>())?;
    m.add("SftpError", py.get_type::<common::SftpError>())?;

    m.add_class::<common::Metadata>()?;
    m.add_class::<common::DirEntry>()?;
    m.add_class::<common::PasswordRequest>()?;

    m.add_class::<sync::Session>()?;
    m.add_class::<sync::Child>()?;
    m.add_class::<sync::ChildStdin>()?;
    m.add_class::<sync::ChildStdout>()?;
    m.add_class::<sync::Sftp>()?;
    m.add_class::<sync::File>()?;

    m.add_class::<aio::AsyncSession>()?;
    m.add_class::<aio::AsyncChild>()?;
    m.add_class::<aio::AsyncChildStdin>()?;
    m.add_class::<aio::AsyncChildStdout>()?;
    m.add_class::<aio::AsyncSftp>()?;
    m.add_class::<aio::AsyncFile>()?;
    Ok(())
}
