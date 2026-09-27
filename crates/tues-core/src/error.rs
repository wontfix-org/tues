use std::fmt;

/// Result alias used throughout `tues`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors produced by `tues`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("could not connect to {host}:{port}: {reason}")]
    Connect {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("connection to {host}:{port} timed out")]
    ConnectTimeout { host: String, port: u16 },

    #[error("authentication failed for {login_user}@{host}: {reason}")]
    Auth {
        login_user: String,
        host: String,
        reason: String,
    },

    #[error("host key for {host}:{port} is not in known_hosts")]
    UnknownHostKey { host: String, port: u16 },

    #[error("host key for {host}:{port} has changed (known_hosts line {line})")]
    HostKeyChanged {
        host: String,
        port: u16,
        line: usize,
    },

    #[error("sudo: {0}")]
    Sudo(#[from] SudoError),

    #[error("password unavailable: {0}")]
    Password(String),

    #[error("sftp: {0}")]
    Sftp(String),

    #[error("ssh protocol error: {0}")]
    Protocol(String),

    #[error("session is closed")]
    Disconnected,

    #[error("{0}")]
    Other(String),
}

impl Clone for Error {
    /// `std::io::Error` is not `Clone`; the copy keeps its kind and message.
    fn clone(&self) -> Self {
        match self {
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), e.to_string())),
            Error::Config(s) => Error::Config(s.clone()),
            Error::Connect { host, port, reason } => Error::Connect {
                host: host.clone(),
                port: *port,
                reason: reason.clone(),
            },
            Error::ConnectTimeout { host, port } => Error::ConnectTimeout {
                host: host.clone(),
                port: *port,
            },
            Error::Auth {
                login_user,
                host,
                reason,
            } => Error::Auth {
                login_user: login_user.clone(),
                host: host.clone(),
                reason: reason.clone(),
            },
            Error::UnknownHostKey { host, port } => Error::UnknownHostKey {
                host: host.clone(),
                port: *port,
            },
            Error::HostKeyChanged { host, port, line } => Error::HostKeyChanged {
                host: host.clone(),
                port: *port,
                line: *line,
            },
            Error::Sudo(e) => Error::Sudo(e.clone()),
            Error::Password(s) => Error::Password(s.clone()),
            Error::Sftp(s) => Error::Sftp(s.clone()),
            Error::Protocol(s) => Error::Protocol(s.clone()),
            Error::Disconnected => Error::Disconnected,
            Error::Other(s) => Error::Other(s.clone()),
        }
    }
}

impl Error {
    /// Convenience constructor for one-off errors.
    pub fn other(msg: impl fmt::Display) -> Self {
        Error::Other(msg.to_string())
    }

    /// Convenience constructor for protocol errors.
    pub fn protocol(msg: impl fmt::Display) -> Self {
        Error::Protocol(msg.to_string())
    }
}

/// Failures of the privilege elevation step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SudoError {
    /// Every password offered was rejected.
    #[error("sudo rejected the password after {attempts} attempt(s)")]
    AuthFailed { attempts: u32 },

    /// A password was required but the password manager could not supply one.
    #[error("sudo requires a password but none was available: {reason}")]
    PasswordRequired { reason: String },

    /// sudo exited before starting the command (not in sudoers, unknown user, ...).
    #[error("sudo did not start the command (exit status {exit_status})")]
    NotStarted { exit_status: i32 },
}
