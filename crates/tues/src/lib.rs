//! # tues
//!
//! Run commands on remote hosts over SSH, with transparent `sudo`
//! elevation, and move files over SFTP.
//!
//! * The blocking API lives at the crate root ([`Session`], [`Command`],
//!   [`Child`], [`Sftp`]).
//! * The async (tokio) API lives in [`aio`].
//! * Driver-independent types ([`ConnectOptions`], [`Stdio`], [`ExitStatus`],
//!   [`PasswordManager`], ...) are shared by both and re-exported here; the
//!   full Sans-IO core is available as [`core`].
//!
//! ```no_run
//! use tues::{ConnectOptions, Session};
//!
//! # fn main() -> tues::Result<()> {
//! let session = Session::connect(ConnectOptions::new("alice@web01"))?;
//! let out = session.command("systemctl").args(["restart", "nginx"]).user("root").output()?;
//! assert!(out.status.success());
//! # Ok(()) }
//! ```

pub use tues_core as core;

pub use tues_core::{
    Command as CommandSpec, CommandUser, ConnectOptions, DirEntry, Error, ExitStatus, ExposeSecret,
    FileType, HostKeyPolicy, JumpHost, MemoizingPasswordManager, Metadata, NoPasswordManager,
    OpenOptions, Output, PasswordKind, PasswordManager, PasswordPrompter, PasswordRequest,
    PtyConfig, ResolvedOptions, Result, SecretString, SharedPasswordManager, SshConfig,
    SshConfigSource, StaticPasswordManager, Stdio, SudoError, TtyPrompter, shared,
};

pub use tues_sync::{
    Child, ChildSignaller, ChildStderr, ChildStdin, ChildStdout, Command, File, Session, Sftp,
};

/// Async API (tokio).
pub mod aio {
    pub use tues_async::{
        Child, ChildSignaller, ChildStderr, ChildStdin, ChildStdout, Command, File, Session, Sftp,
    };
}
