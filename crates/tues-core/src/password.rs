//! Password acquisition and memoization.
//!
//! Drivers never read passwords themselves. They ask a [`PasswordManager`],
//! which can be replaced by any implementation. The default is
//! [`MemoizingPasswordManager`] wrapping a [`TtyPrompter`]: it prompts once on
//! `/dev/tty` and remembers the answer per (kind, host, user, run-as) until
//! a driver reports that it was rejected.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use secrecy::SecretString;

use crate::error::{Error, Result};

/// What the password is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordKind {
    /// SSH password / keyboard-interactive authentication of the login user.
    Login,
    /// The login user's password as required by `sudo`.
    Sudo,
    /// Passphrase for an encrypted private key file.
    KeyPassphrase,
}

/// Context for a password request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PasswordRequest {
    pub kind: PasswordKind,
    pub host: String,
    pub port: u16,
    /// The SSH login user.
    pub user: String,
    /// The sudo target user (for [`PasswordKind::Sudo`]).
    pub run_as: Option<String>,
    /// The key file (for [`PasswordKind::KeyPassphrase`]).
    pub key_path: Option<PathBuf>,
}

impl PasswordRequest {
    pub fn login(host: impl Into<String>, port: u16, user: impl Into<String>) -> Self {
        PasswordRequest {
            kind: PasswordKind::Login,
            host: host.into(),
            port,
            user: user.into(),
            run_as: None,
            key_path: None,
        }
    }

    pub fn sudo(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        run_as: impl Into<String>,
    ) -> Self {
        PasswordRequest {
            kind: PasswordKind::Sudo,
            host: host.into(),
            port,
            user: user.into(),
            run_as: Some(run_as.into()),
            key_path: None,
        }
    }

    pub fn key_passphrase(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key_path: PathBuf,
    ) -> Self {
        PasswordRequest {
            kind: PasswordKind::KeyPassphrase,
            host: host.into(),
            port,
            user: user.into(),
            run_as: None,
            key_path: Some(key_path),
        }
    }

    /// Cache key: sudo passwords are the login user's password, so they are
    /// shared with [`PasswordKind::Login`] for the same user and host.
    fn cache_key(&self) -> CacheKey {
        match self.kind {
            PasswordKind::Login | PasswordKind::Sudo => CacheKey {
                kind: PasswordKind::Login,
                host: self.host.clone(),
                port: self.port,
                user: self.user.clone(),
                key_path: None,
            },
            PasswordKind::KeyPassphrase => CacheKey {
                kind: self.kind,
                host: String::new(),
                port: 0,
                user: String::new(),
                key_path: self.key_path.clone(),
            },
        }
    }

    /// A human readable prompt.
    pub fn prompt_text(&self) -> String {
        match self.kind {
            PasswordKind::Login => format!("{}@{}'s password: ", self.user, self.host),
            PasswordKind::Sudo => format!(
                "[sudo] password for {}@{} (run as {}): ",
                self.user,
                self.host,
                self.run_as.as_deref().unwrap_or("root")
            ),
            PasswordKind::KeyPassphrase => format!(
                "Enter passphrase for key '{}': ",
                self.key_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ),
        }
    }
}

impl fmt::Display for PasswordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.prompt_text())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    kind: PasswordKind,
    host: String,
    port: u16,
    user: String,
    key_path: Option<PathBuf>,
}

/// Supplies passwords to drivers.
///
/// Implementations may block (prompting a user); drivers call them off the
/// async executor.
pub trait PasswordManager: Send {
    /// Return the password for `req`.
    fn get(&mut self, req: &PasswordRequest) -> Result<SecretString>;

    /// The last password returned for `req` was rejected.
    fn invalidate(&mut self, req: &PasswordRequest);
}

/// A shareable, thread-safe password manager handle.
pub type SharedPasswordManager = Arc<Mutex<dyn PasswordManager>>;

/// Wrap a manager into a [`SharedPasswordManager`].
pub fn shared<M: PasswordManager + 'static>(manager: M) -> SharedPasswordManager {
    Arc::new(Mutex::new(manager))
}

/// Something that can ask a human (or another system) for a password.
pub trait PasswordPrompter: Send {
    fn prompt(&mut self, req: &PasswordRequest) -> Result<SecretString>;
}

impl<F> PasswordPrompter for F
where
    F: FnMut(&PasswordRequest) -> Result<SecretString> + Send,
{
    fn prompt(&mut self, req: &PasswordRequest) -> Result<SecretString> {
        (self)(req)
    }
}

/// Prompts on the controlling terminal (`/dev/tty`), never on stdin.
#[derive(Debug, Default, Clone, Copy)]
pub struct TtyPrompter;

impl PasswordPrompter for TtyPrompter {
    fn prompt(&mut self, req: &PasswordRequest) -> Result<SecretString> {
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| Error::Password(format!("cannot open /dev/tty: {e}")))?;
        tty.write_all(req.prompt_text().as_bytes())?;
        tty.flush()?;
        let pw = rpassword::read_password()
            .map_err(|e| Error::Password(format!("reading from tty failed: {e}")))?;
        Ok(SecretString::from(pw))
    }
}

/// Caches passwords per request key and re-prompts after invalidation.
pub struct MemoizingPasswordManager<P: PasswordPrompter> {
    prompter: P,
    cache: HashMap<CacheKey, SecretString>,
}

impl<P: PasswordPrompter> MemoizingPasswordManager<P> {
    pub fn new(prompter: P) -> Self {
        MemoizingPasswordManager {
            prompter,
            cache: HashMap::new(),
        }
    }

    /// Pre-seed the cache.
    pub fn insert(&mut self, req: &PasswordRequest, password: SecretString) {
        self.cache.insert(req.cache_key(), password);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

impl Default for MemoizingPasswordManager<TtyPrompter> {
    fn default() -> Self {
        Self::new(TtyPrompter)
    }
}

impl<P: PasswordPrompter> PasswordManager for MemoizingPasswordManager<P> {
    fn get(&mut self, req: &PasswordRequest) -> Result<SecretString> {
        let key = req.cache_key();
        if let Some(pw) = self.cache.get(&key) {
            return Ok(pw.clone());
        }
        let pw = self.prompter.prompt(req)?;
        self.cache.insert(key, pw.clone());
        Ok(pw)
    }

    fn invalidate(&mut self, req: &PasswordRequest) {
        self.cache.remove(&req.cache_key());
    }
}

/// Always returns the same password (automation, tests).
#[derive(Clone)]
pub struct StaticPasswordManager(pub SecretString);

impl StaticPasswordManager {
    pub fn new(password: impl Into<String>) -> Self {
        StaticPasswordManager(SecretString::from(password.into()))
    }
}

impl PasswordManager for StaticPasswordManager {
    fn get(&mut self, _req: &PasswordRequest) -> Result<SecretString> {
        Ok(self.0.clone())
    }

    fn invalidate(&mut self, _req: &PasswordRequest) {}
}

/// Refuses every request.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPasswordManager;

impl PasswordManager for NoPasswordManager {
    fn get(&mut self, req: &PasswordRequest) -> Result<SecretString> {
        Err(Error::Password(format!(
            "no password manager configured ({})",
            req.prompt_text().trim_end()
        )))
    }

    fn invalidate(&mut self, _req: &PasswordRequest) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn memoizes_and_reprompts_after_invalidate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let mut pm = MemoizingPasswordManager::new(move |_req: &PasswordRequest| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from(format!("pw{n}")))
        });
        let req = PasswordRequest::sudo("h", 22, "u", "root");
        assert_eq!(pm.get(&req).unwrap().expose_secret(), "pw0");
        assert_eq!(pm.get(&req).unwrap().expose_secret(), "pw0");
        // Login and sudo share the login user's password.
        let login = PasswordRequest::login("h", 22, "u");
        assert_eq!(pm.get(&login).unwrap().expose_secret(), "pw0");
        pm.invalidate(&req);
        assert_eq!(pm.get(&req).unwrap().expose_secret(), "pw1");
        // Other hosts are separate.
        let other = PasswordRequest::sudo("h2", 22, "u", "root");
        assert_eq!(pm.get(&other).unwrap().expose_secret(), "pw2");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn no_password_manager_errors() {
        let mut pm = NoPasswordManager;
        assert!(matches!(
            pm.get(&PasswordRequest::login("h", 22, "u")),
            Err(Error::Password(_))
        ));
    }
}
