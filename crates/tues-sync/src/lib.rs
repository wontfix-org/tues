//! Blocking driver for `tues`.
//!
//! Every [`Session`] owns a small tokio runtime (one worker thread) that hosts
//! the async driver. Calls block the current thread until the corresponding
//! async operation completes; child stdio implements [`std::io::Read`] /
//! [`std::io::Write`].
//!
//! The blocking API must not be used from inside an async runtime thread;
//! use `tues_async` there instead.
//!
//! ```no_run
//! use std::io::Read;
//! use tues_sync::Session;
//! use tues_core::ConnectOptions;
//!
//! # fn run() -> tues_core::Result<()> {
//! let session = Session::connect(ConnectOptions::new("alice@web01"))?;
//! let out = session.command("id").user("root").output()?;
//! println!("{}", out.stdout_lossy());
//! # Ok(()) }
//! ```

mod child;
mod command;
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

use std::sync::Arc;

/// Owns the runtime and shuts it down without blocking on drop.
pub(crate) struct Runtime {
    rt: Option<tokio::runtime::Runtime>,
}

impl Runtime {
    fn new() -> Result<Arc<Self>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("tues-sync")
            .enable_all()
            .build()?;
        Ok(Arc::new(Runtime { rt: Some(rt) }))
    }

    pub(crate) fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt
            .as_ref()
            .expect("runtime alive while handles exist")
            .block_on(fut)
    }

    pub(crate) fn handle(&self) -> &tokio::runtime::Handle {
        self.rt.as_ref().expect("runtime alive").handle()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}
