//! Async driver for `tues`, built on tokio and [`russh`].
//!
//! ```no_run
//! use tues_async::Session;
//! use tues_core::ConnectOptions;
//!
//! # async fn run() -> tues_core::Result<()> {
//! let session = Session::connect(ConnectOptions::new("alice@web01")).await?;
//! let out = session.command("id").user("root").output().await?;
//! println!("{}", out.stdout_lossy());
//! session.close().await?;
//! # Ok(()) }
//! ```

mod child;
mod command;
mod files;
mod session;
mod sftp;

pub use child::{Child, ChildSignaller, ChildStderr, ChildStdin, ChildStdout};
pub use command::Command;
pub use session::Session;
pub use sftp::{File, Sftp};

pub use tues_core::{
    self as core, ConnectOptions, Error, ExitStatus, HostKeyPolicy, Output, PasswordManager,
    PasswordRequest, PtyConfig, Result, SharedPasswordManager, Stdio,
};
