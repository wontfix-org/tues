//! Python bindings for `tues`.
//!
//! Exposes a blocking API (`Session`, `Child`, `Sftp`, `File`) built on
//! `tues-sync`, and an asyncio API (`AsyncSession`, `AsyncChild`,
//! `AsyncSftp`, `AsyncFile`) built on `tues-async`.

use pyo3::prelude::*;

mod aio;
mod common;
mod sync;

#[pymodule]
fn _tues(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add("TuesError", py.get_type::<common::TuesError>())?;
    m.add("ConnectError", py.get_type::<common::ConnectError>())?;
    m.add("AuthError", py.get_type::<common::AuthError>())?;
    m.add("HostKeyError", py.get_type::<common::HostKeyError>())?;
    m.add("SudoError", py.get_type::<common::SudoError>())?;
    m.add("SftpError", py.get_type::<common::SftpError>())?;

    m.add_class::<common::ExitStatus>()?;
    m.add_class::<common::Output>()?;
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
