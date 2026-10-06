//! Sans-IO core of `tues`.
//!
//! This crate contains no networking. It models remote processes after
//! [`std::process`], turns a [`Command`] into a remote shell line (optionally
//! wrapped in `sudo`), and drives the sudo password conversation through a
//! state machine ([`ExecMachine`]) that consumes channel events and produces
//! effects. Drivers (`tues-async`, `tues-sync`) move bytes between the machine
//! and an SSH channel and never interpret them.
//!
//! It also hosts the exchangeable [`PasswordManager`] interface, the
//! `~/.ssh/config` parser, and the [`ConnectOptions`] resolution logic.

pub mod algo_list;
pub mod error;
pub mod exec;
pub mod fs;
pub mod options;
pub mod password;
pub mod process;
pub mod shell;
pub mod ssh_config;
pub mod sudo;
mod tty_prompt;

/// Byte buffer type used by [`Event`] and [`Effect`].
pub use bytes::Bytes;
pub use error::{Error, Result, SudoError};
pub use exec::{Effect, Event, ExecMachine};
pub use fs::{DirEntry, FileType, Metadata, OpenOptions};
pub use options::{
    AuthMethod, ConnectOptions, HostKeyPolicy, JumpHost, ResolvedOptions, SshConfigSource,
};
pub use password::{
    MemoizingPasswordManager, NoPasswordManager, PasswordKind, PasswordManager, PasswordPrompter,
    PasswordRequest, SharedPasswordManager, StaticPasswordManager, TtyPrompter, shared,
};
pub use process::{
    Command, CommandUser, ExecPlan, ExitStatus, ExitStatusError, Output, PtyConfig, Stdio, SudoPlan,
};
pub use secrecy::{ExposeSecret, SecretString};
pub use ssh_config::{HostParams, SshConfig};
pub use tty_prompt::PasswordPromptFinish;
