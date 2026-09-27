//! Connection settings and their resolution against `ssh_config`.
//!
//! [`ConnectOptions`] is what callers build. [`ConnectOptions::resolve`]
//! merges it with the matching `~/.ssh/config` entry (explicit API values
//! win, then the config, then OpenSSH defaults) into [`ResolvedOptions`],
//! which drivers consume.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::password::{MemoizingPasswordManager, SharedPasswordManager, TtyPrompter, shared};
use crate::ssh_config::{self, SshConfig};

/// How to treat the server host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyPolicy {
    /// Key must be present and match `known_hosts` (`StrictHostKeyChecking yes`).
    #[default]
    Strict,
    /// Unknown keys are added; changed keys are rejected (`accept-new`).
    AcceptNew,
    /// Accept anything (`StrictHostKeyChecking no`). Insecure.
    Off,
}

impl HostKeyPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" | "ask" | "strict" => Some(HostKeyPolicy::Strict),
            "accept-new" | "acceptnew" => Some(HostKeyPolicy::AcceptNew),
            "no" | "off" | "false" => Some(HostKeyPolicy::Off),
            _ => None,
        }
    }
}

/// Where to read `ssh_config` from.
#[derive(Debug, Clone, Default)]
pub enum SshConfigSource {
    /// `~/.ssh/config` if it exists.
    #[default]
    Default,
    /// A specific file (`ssh -F`).
    File(PathBuf),
    /// Do not read any config.
    None,
    /// An already parsed config.
    Parsed(SshConfig),
}

/// One hop of a `ProxyJump` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpHost {
    /// Login user for this hop, if the jump string gave one.
    pub login_user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl JumpHost {
    /// Parse `[login-user@]host[:port]` or `ssh://[login-user@]host[:port]`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let s = s.strip_prefix("ssh://").unwrap_or(s);
        if s.is_empty() {
            return Err(Error::Config("empty ProxyJump entry".into()));
        }
        let (login_user, rest) = match s.rsplit_once('@') {
            Some((u, r)) => (Some(u.to_string()), r),
            None => (None, s),
        };
        let (host, port) = split_host_port(rest)?;
        Ok(JumpHost {
            login_user,
            host,
            port,
        })
    }
}

/// Split `host[:port]`, tolerating `[v6::addr]:port`.
fn split_host_port(s: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(Error::Config(format!("malformed host {s:?}")));
        };
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None => None,
        };
        return Ok((host.to_string(), port));
    }
    // A bare IPv6 address has several colons; only treat a single colon as a port separator.
    if s.matches(':').count() == 1 {
        let (h, p) = s.split_once(':').expect("one colon");
        return Ok((h.to_string(), Some(parse_port(p)?)));
    }
    Ok((s.to_string(), None))
}

fn parse_port(p: &str) -> Result<u16> {
    p.parse()
        .map_err(|_| Error::Config(format!("invalid port {p:?}")))
}

/// Connection settings as supplied by the caller. Unset values fall back to
/// `ssh_config` and then to OpenSSH defaults.
#[derive(Clone, Default)]
pub struct ConnectOptions {
    /// Host alias as written on the command line, optionally `login-user@host[:port]`.
    pub destination: String,
    /// Login user. Falls back to the destination string, then `ssh_config`, then the local user.
    pub login_user: Option<String>,
    pub port: Option<u16>,
    /// Override the real host name (like `HostName`).
    pub host_name: Option<String>,
    pub identity_files: Vec<PathBuf>,
    pub identities_only: Option<bool>,
    /// `Some(vec![])` disables jumping even if the config sets `ProxyJump`.
    pub proxy_jump: Option<Vec<String>>,
    pub connect_timeout: Option<Duration>,
    pub server_alive_interval: Option<Duration>,
    pub compression: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub password_authentication: Option<bool>,
    pub kbd_interactive_authentication: Option<bool>,
    pub use_agent: Option<bool>,
    pub host_key_policy: Option<HostKeyPolicy>,
    /// Explicit known_hosts files, replacing ssh_config and the default.
    /// `None` consults `UserKnownHostsFile`, then `~/.ssh/known_hosts`.
    pub known_hosts_file: Option<Vec<PathBuf>>,
    pub ssh_config: SshConfigSource,
    /// Default user commands run as. `None` means the login user; any other
    /// value runs commands via `sudo -u`.
    pub user: Option<String>,
    pub password_manager: Option<SharedPasswordManager>,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("destination", &self.destination)
            .field("login_user", &self.login_user)
            .field("port", &self.port)
            .field("host_name", &self.host_name)
            .field("identity_files", &self.identity_files)
            .field("proxy_jump", &self.proxy_jump)
            .field("host_key_policy", &self.host_key_policy)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl ConnectOptions {
    /// `destination` may be `host`, `login-user@host`, `host:port`, or `login-user@host:port`.
    pub fn new(destination: impl Into<String>) -> Self {
        ConnectOptions {
            destination: destination.into(),
            ..Default::default()
        }
    }

    /// Set the login user.
    pub fn login_user(mut self, login_user: impl Into<String>) -> Self {
        self.login_user = Some(login_user.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn host_name(mut self, host: impl Into<String>) -> Self {
        self.host_name = Some(host.into());
        self
    }

    pub fn identity_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_files.push(path.into());
        self
    }

    pub fn identities_only(mut self, yes: bool) -> Self {
        self.identities_only = Some(yes);
        self
    }

    /// Set the jump chain (`[login-user@]host[:port]`, comma separated or repeated).
    pub fn proxy_jump(mut self, spec: impl Into<String>) -> Self {
        let spec = spec.into();
        let list = self.proxy_jump.get_or_insert_with(Vec::new);
        list.extend(
            spec.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        );
        self
    }

    /// Disable ProxyJump even if configured.
    pub fn no_proxy_jump(mut self) -> Self {
        self.proxy_jump = Some(Vec::new());
        self
    }

    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    pub fn server_alive_interval(mut self, d: Duration) -> Self {
        self.server_alive_interval = Some(d);
        self
    }

    pub fn compression(mut self, yes: bool) -> Self {
        self.compression = Some(yes);
        self
    }

    pub fn pubkey_authentication(mut self, yes: bool) -> Self {
        self.pubkey_authentication = Some(yes);
        self
    }

    pub fn password_authentication(mut self, yes: bool) -> Self {
        self.password_authentication = Some(yes);
        self
    }

    pub fn kbd_interactive_authentication(mut self, yes: bool) -> Self {
        self.kbd_interactive_authentication = Some(yes);
        self
    }

    pub fn use_agent(mut self, yes: bool) -> Self {
        self.use_agent = Some(yes);
        self
    }

    pub fn host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = Some(policy);
        self
    }

    pub fn known_hosts_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts_file = Some(vec![path.into()]);
        self
    }

    pub fn ssh_config(mut self, source: SshConfigSource) -> Self {
        self.ssh_config = source;
        self
    }

    /// Read a specific `ssh_config` file (`ssh -F`).
    pub fn ssh_config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.ssh_config = SshConfigSource::File(path.into());
        self
    }

    /// Do not consult any `ssh_config`.
    pub fn no_ssh_config(mut self) -> Self {
        self.ssh_config = SshConfigSource::None;
        self
    }

    /// Run commands as `user` via `sudo -u`, unless a command says otherwise.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn password_manager(mut self, manager: SharedPasswordManager) -> Self {
        self.password_manager = Some(manager);
        self
    }

    /// Resolve against `ssh_config` and defaults.
    pub fn resolve(&self) -> Result<ResolvedOptions> {
        let config = match &self.ssh_config {
            SshConfigSource::Default => SshConfig::load_default()?,
            SshConfigSource::File(p) => Some(SshConfig::load(p)?),
            SshConfigSource::None => None,
            SshConfigSource::Parsed(c) => Some(c.clone()),
        };
        self.resolve_with(config.as_ref())
    }

    /// Resolve with an already loaded config (or none).
    pub fn resolve_with(&self, config: Option<&SshConfig>) -> Result<ResolvedOptions> {
        // destination: [login-user@]host[:port]
        let dest = self.destination.trim();
        if dest.is_empty() {
            return Err(Error::Config("empty destination".into()));
        }
        let dest = dest.strip_prefix("ssh://").unwrap_or(dest);
        let (dest_login_user, rest) = match dest.rsplit_once('@') {
            Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
            _ => (None, dest),
        };
        let (alias, dest_port) = split_host_port(rest)?;

        let params = config.map(|c| c.query(&alias)).unwrap_or_default();

        // The destination string is the most specific source, then the
        // builder, then ssh_config, then defaults.
        let login_user = dest_login_user
            .or(self.login_user.clone())
            .or(params.login_user.clone())
            .unwrap_or_else(ssh_config::local_user);
        let port = dest_port.or(self.port).or(params.port).unwrap_or(22);
        let host_name = self
            .host_name
            .clone()
            .or(params.host_name.clone())
            .unwrap_or_else(|| alias.clone());

        let mut identity_files: Vec<PathBuf> = self
            .identity_files
            .iter()
            .map(|p| ssh_config::expand_path(&p.to_string_lossy()))
            .collect();
        let explicit_identities = !identity_files.is_empty();
        identity_files.extend(params.identity_file.iter().cloned());
        if identity_files.is_empty() {
            let ssh_dir = ssh_config::home_dir().join(".ssh");
            for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                identity_files.push(ssh_dir.join(name));
            }
        }

        let proxy_jump = match self.proxy_jump.clone().or(params.proxy_jump.clone()) {
            Some(list) => list
                .iter()
                .map(|s| JumpHost::parse(s))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };

        let password_manager = self
            .password_manager
            .clone()
            .unwrap_or_else(|| shared(MemoizingPasswordManager::new(TtyPrompter)));

        Ok(ResolvedOptions {
            alias,
            host_name,
            port,
            login_user,
            identity_files,
            identities_only: self
                .identities_only
                .or(params.identities_only)
                .unwrap_or(false),
            explicit_identities,
            proxy_jump,
            connect_timeout: self.connect_timeout.or(params.connect_timeout),
            server_alive_interval: self.server_alive_interval.or(params.server_alive_interval),
            compression: self.compression.or(params.compression).unwrap_or(false),
            pubkey_authentication: self
                .pubkey_authentication
                .or(params.pubkey_authentication)
                .unwrap_or(true),
            password_authentication: self
                .password_authentication
                .or(params.password_authentication)
                .unwrap_or(true),
            kbd_interactive_authentication: self
                .kbd_interactive_authentication
                .or(params.kbd_interactive_authentication)
                .unwrap_or(true),
            use_agent: self.use_agent.unwrap_or(true),
            host_key_policy: self
                .host_key_policy
                .or(params.strict_host_key_checking)
                .unwrap_or_default(),
            known_hosts_files: match &self.known_hosts_file {
                Some(files) => files
                    .iter()
                    .map(|p| ssh_config::expand_path(&p.to_string_lossy()))
                    .collect(),
                None if !params.user_known_hosts_file.is_empty() => {
                    params.user_known_hosts_file.clone()
                }
                None => vec![ssh_config::home_dir().join(".ssh").join("known_hosts")],
            },
            request_tty: params.request_tty.unwrap_or(false),
            user: self.user.clone(),
            password_manager,
            ssh_config: config.cloned(),
        })
    }
}

/// Fully resolved connection settings.
#[derive(Clone)]
pub struct ResolvedOptions {
    /// The alias the user typed (used for `known_hosts` and prompts).
    pub alias: String,
    /// The address to connect to.
    pub host_name: String,
    pub port: u16,
    /// The login user.
    pub login_user: String,
    pub identity_files: Vec<PathBuf>,
    pub identities_only: bool,
    /// Identity files were given explicitly (not defaults).
    pub explicit_identities: bool,
    pub proxy_jump: Vec<JumpHost>,
    pub connect_timeout: Option<Duration>,
    pub server_alive_interval: Option<Duration>,
    pub compression: bool,
    pub pubkey_authentication: bool,
    pub password_authentication: bool,
    pub kbd_interactive_authentication: bool,
    pub use_agent: bool,
    pub host_key_policy: HostKeyPolicy,
    /// Files checked for the server host key, in order. A new key is written
    /// to the first one.
    pub known_hosts_files: Vec<PathBuf>,
    pub request_tty: bool,
    /// Default user commands run as. `None` means the login user.
    pub user: Option<String>,
    pub password_manager: SharedPasswordManager,
    /// The config used, so jump hosts resolve against the same file.
    pub ssh_config: Option<SshConfig>,
}

impl std::fmt::Debug for ResolvedOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOptions")
            .field("alias", &self.alias)
            .field("host_name", &self.host_name)
            .field("port", &self.port)
            .field("login_user", &self.login_user)
            .field("identity_files", &self.identity_files)
            .field("proxy_jump", &self.proxy_jump)
            .field("host_key_policy", &self.host_key_policy)
            .field("known_hosts_files", &self.known_hosts_files)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl ResolvedOptions {
    /// Options for connecting to a jump host, inheriting everything that
    /// makes sense (config, policy, password manager).
    pub fn for_jump(&self, hop: &JumpHost) -> ConnectOptions {
        ConnectOptions {
            destination: hop.host.clone(),
            login_user: hop.login_user.clone(),
            port: hop.port,
            host_name: None,
            identity_files: if self.explicit_identities {
                self.identity_files.clone()
            } else {
                Vec::new()
            },
            identities_only: Some(self.identities_only),
            proxy_jump: None,
            connect_timeout: self.connect_timeout,
            server_alive_interval: self.server_alive_interval,
            compression: Some(self.compression),
            pubkey_authentication: Some(self.pubkey_authentication),
            password_authentication: Some(self.password_authentication),
            kbd_interactive_authentication: Some(self.kbd_interactive_authentication),
            use_agent: Some(self.use_agent),
            host_key_policy: Some(self.host_key_policy),
            known_hosts_file: Some(self.known_hosts_files.clone()),
            ssh_config: match &self.ssh_config {
                Some(c) => SshConfigSource::Parsed(c.clone()),
                None => SshConfigSource::None,
            },
            user: None,
            password_manager: Some(self.password_manager.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_parsing() {
        let r = ConnectOptions::new("alice@example.com:2222")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.login_user, "alice");
        assert_eq!(r.host_name, "example.com");
        assert_eq!(r.port, 2222);
        let r = ConnectOptions::new("[::1]:2200")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.host_name, "::1");
        assert_eq!(r.port, 2200);
        // Destination beats builder values.
        let r = ConnectOptions::new("bob@h:2200")
            .login_user("api")
            .port(22)
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.login_user, "bob");
        assert_eq!(r.port, 2200);
    }

    #[test]
    fn ipv6_destinations() {
        // Bare address: every colon belongs to the address.
        let r = ConnectOptions::new("fe80::1")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.host_name, "fe80::1");
        assert_eq!(r.port, 22);
        let r = ConnectOptions::new("2001:db8::1")
            .port(2222)
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.host_name, "2001:db8::1");
        assert_eq!(r.port, 2222);
        // Bracketed with port and user.
        let r = ConnectOptions::new("bob@[2001:db8::1]:2200")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.login_user, "bob");
        assert_eq!(r.host_name, "2001:db8::1");
        assert_eq!(r.port, 2200);
        // Bracketed without port.
        let r = ConnectOptions::new("[::1]")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(r.host_name, "::1");
        assert_eq!(r.port, 22);
        // ssh:// URI form.
        let r = ConnectOptions::new("ssh://bob@[::1]:2022")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert_eq!(
            (r.login_user.as_str(), r.host_name.as_str(), r.port),
            ("bob", "::1", 2022)
        );
        // Malformed bracket.
        assert!(
            ConnectOptions::new("[::1")
                .no_ssh_config()
                .resolve()
                .is_err()
        );
        assert!(
            ConnectOptions::new("[::1]:x")
                .no_ssh_config()
                .resolve()
                .is_err()
        );
        // Jump hosts use the same rules.
        assert_eq!(
            JumpHost::parse("j@[fe80::2]:2201").unwrap(),
            JumpHost {
                login_user: Some("j".into()),
                host: "fe80::2".into(),
                port: Some(2201)
            }
        );
        assert_eq!(JumpHost::parse("fe80::2").unwrap().host, "fe80::2");
        assert_eq!(JumpHost::parse("fe80::2").unwrap().port, None);
    }

    #[test]
    fn api_beats_config_beats_default() {
        let cfg = SshConfig::parse_str(
            "Host web\n HostName 10.1.1.1\n User cfg\n Port 2022\n ProxyJump j@jump:22\n StrictHostKeyChecking no\n",
            None,
        )
        .unwrap();
        let r = ConnectOptions::new("web")
            .login_user("api")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(r.login_user, "api");
        assert_eq!(r.host_name, "10.1.1.1");
        assert_eq!(r.port, 2022);
        assert_eq!(
            r.proxy_jump,
            vec![JumpHost {
                login_user: Some("j".into()),
                host: "jump".into(),
                port: Some(22)
            }]
        );
        assert_eq!(r.host_key_policy, HostKeyPolicy::Off);
        assert!(r.identity_files.iter().any(|p| p.ends_with("id_ed25519")));

        let r = ConnectOptions::new("web")
            .no_proxy_jump()
            .resolve_with(Some(&cfg))
            .unwrap();
        assert!(r.proxy_jump.is_empty());

        let r = ConnectOptions::new("other")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(r.port, 22);
        assert_eq!(r.host_key_policy, HostKeyPolicy::Strict);
    }

    #[test]
    fn jump_host_parsing() {
        assert_eq!(
            JumpHost::parse("ssh://u@h:2200").unwrap(),
            JumpHost {
                login_user: Some("u".into()),
                host: "h".into(),
                port: Some(2200)
            }
        );
        assert_eq!(
            JumpHost::parse("h").unwrap(),
            JumpHost {
                login_user: None,
                host: "h".into(),
                port: None
            }
        );
        assert!(JumpHost::parse("h:notaport").is_err());
    }

    #[test]
    fn jump_options_inherit() {
        let r = ConnectOptions::new("web")
            .proxy_jump("a@jump")
            .host_key_policy(HostKeyPolicy::Off)
            .no_ssh_config()
            .resolve()
            .unwrap();
        let j = r.for_jump(&r.proxy_jump[0]).resolve().unwrap();
        assert_eq!(j.login_user, "a");
        assert_eq!(j.host_name, "jump");
        assert_eq!(j.host_key_policy, HostKeyPolicy::Off);
        assert!(Arc::ptr_eq(&j.password_manager, &r.password_manager));
    }

    use std::sync::Arc;
}
