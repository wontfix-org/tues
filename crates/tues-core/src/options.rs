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

/// One method from `PreferredAuthentications`.
///
/// `gssapi-with-mic` and `hostbased` are not offered. `none` is probed before
/// this list and is not a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    PublicKey,
    Password,
    KeyboardInteractive,
}

impl AuthMethod {
    /// Methods tried when the keyword is unset.
    ///
    /// This keeps tues's existing order. OpenSSH's own default puts
    /// keyboard-interactive ahead of password.
    pub fn default_order() -> Vec<Self> {
        vec![
            AuthMethod::PublicKey,
            AuthMethod::Password,
            AuthMethod::KeyboardInteractive,
        ]
    }

    /// Parse a comma-separated list. Unknown names are skipped. Duplicates
    /// are dropped. An empty result means nothing in the list is usable.
    pub fn parse_list(list: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for part in list.split(',') {
            let method = match part.trim().to_ascii_lowercase().as_str() {
                "publickey" => AuthMethod::PublicKey,
                "password" => AuthMethod::Password,
                "keyboard-interactive" => AuthMethod::KeyboardInteractive,
                _ => continue,
            };
            if !out.contains(&method) {
                out.push(method);
            }
        }
        out
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

fn expand_known_hosts_list(files: &[PathBuf]) -> Vec<PathBuf> {
    files
        .iter()
        .map(|p| ssh_config::expand_path(&p.to_string_lossy()))
        .collect()
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
    /// `ServerAliveCountMax`. Unset keeps russh's default of 3.
    pub server_alive_count_max: Option<usize>,
    /// `Ciphers` list, including a leading `+`, `-`, or `^`.
    pub ciphers: Option<String>,
    /// `MACs` list.
    pub macs: Option<String>,
    /// `KexAlgorithms` list.
    pub kex_algorithms: Option<String>,
    /// `HostKeyAlgorithms` list. Certificate names are offered as certificates.
    pub host_key_algorithms: Option<String>,
    /// `RekeyLimit` arguments, for example `512M 30m`.
    pub rekey_limit: Option<String>,
    pub compression: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub password_authentication: Option<bool>,
    pub kbd_interactive_authentication: Option<bool>,
    pub use_agent: Option<bool>,
    pub host_key_policy: Option<HostKeyPolicy>,
    /// Explicit user known_hosts files, replacing `UserKnownHostsFile` and
    /// `~/.ssh/known_hosts`. Does not replace `GlobalKnownHostsFile`.
    pub known_hosts_file: Option<Vec<PathBuf>>,
    /// Explicit `GlobalKnownHostsFile` list. `None` uses ssh_config, then
    /// `/etc/ssh/ssh_known_hosts` and `ssh_known_hosts2`. `Some` empty is `none`.
    pub global_known_hosts_file: Option<Vec<PathBuf>>,
    pub ssh_config: SshConfigSource,
    /// Default user commands run as. `None` means the login user; any other
    /// value runs commands via `sudo -u`.
    pub user: Option<String>,
    pub password_manager: Option<SharedPasswordManager>,
    /// `BatchMode`. `yes` refuses a password manager that would prompt.
    pub batch_mode: Option<bool>,
    /// `ConnectionAttempts`. `None` means unset (default 1).
    pub connection_attempts: Option<u32>,
    /// `PreferredAuthentications`. `None` means the default order.
    pub preferred_authentications: Option<Vec<AuthMethod>>,
    /// `SetEnv` assignments. The builder's names win over `ssh_config`.
    pub set_env: Vec<(String, String)>,
    /// `TCPKeepAlive`. `None` means unset (OpenSSH default is yes).
    pub tcp_keepalive: Option<bool>,
    /// `NumberOfPasswordPrompts`. `None` means unset (default 3). `0` asks never.
    pub password_prompts: Option<u32>,
    /// `NoHostAuthenticationForLocalhost`. `None` means unset (default no).
    pub no_host_auth_localhost: Option<bool>,
    /// `RequiredRSASize`, in bits. `None` means unset (default 1024).
    /// Below 1024 is rejected at resolve time.
    pub required_rsa_size: Option<u32>,
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

    /// Unanswered server-alive messages before the connection is closed.
    pub fn server_alive_count_max(mut self, n: usize) -> Self {
        self.server_alive_count_max = Some(n);
        self
    }

    /// Symmetric ciphers, in OpenSSH list syntax.
    pub fn ciphers(mut self, list: impl Into<String>) -> Self {
        self.ciphers = Some(list.into());
        self
    }

    /// MAC algorithms, in OpenSSH list syntax.
    pub fn macs(mut self, list: impl Into<String>) -> Self {
        self.macs = Some(list.into());
        self
    }

    /// Key exchange algorithms, in OpenSSH list syntax.
    pub fn kex_algorithms(mut self, list: impl Into<String>) -> Self {
        self.kex_algorithms = Some(list.into());
        self
    }

    /// Host key algorithms, in OpenSSH list syntax.
    pub fn host_key_algorithms(mut self, list: impl Into<String>) -> Self {
        self.host_key_algorithms = Some(list.into());
        self
    }

    /// Data and time limits before rekey, in `RekeyLimit` syntax.
    pub fn rekey_limit(mut self, spec: impl Into<String>) -> Self {
        self.rekey_limit = Some(spec.into());
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

    /// Replace `GlobalKnownHostsFile`. An empty iterator is `none`.
    pub fn global_known_hosts_files<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.global_known_hosts_file = Some(paths.into_iter().map(Into::into).collect());
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

    /// Refuse to prompt for a password or key passphrase (`BatchMode yes`).
    ///
    /// A password the manager already has is still used.
    pub fn batch_mode(mut self, yes: bool) -> Self {
        self.batch_mode = Some(yes);
        self
    }

    /// How many times to try the TCP connect (`ConnectionAttempts`).
    ///
    /// `0` is rejected at resolve time. Authentication is not retried.
    pub fn connection_attempts(mut self, n: u32) -> Self {
        self.connection_attempts = Some(n);
        self
    }

    /// Order of `publickey`, `password`, and `keyboard-interactive`.
    ///
    /// Other OpenSSH method names are ignored. A list with none of the three
    /// leaves authentication with nothing to try after the `none` probe.
    pub fn preferred_authentications(mut self, list: impl AsRef<str>) -> Self {
        self.preferred_authentications = Some(AuthMethod::parse_list(list.as_ref()));
        self
    }

    /// Send `name=value` to the remote session before exec (`SetEnv`).
    ///
    /// Repeat the call for several variables. The first value for a name wins.
    pub fn set_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_env.push((name.into(), value.into()));
        self
    }

    /// Set `SO_KEEPALIVE` on the TCP socket (`TCPKeepAlive`).
    ///
    /// The default is yes, matching OpenSSH. A connection made through
    /// `ProxyJump` is not a TCP socket, so the option applies to each hop's
    /// own TCP connection.
    pub fn tcp_keepalive(mut self, yes: bool) -> Self {
        self.tcp_keepalive = Some(yes);
        self
    }

    /// How many times to ask for a password, keyboard-interactive answer, or
    /// key passphrase (`NumberOfPasswordPrompts`). The default is 3. `0`
    /// does not ask.
    pub fn number_of_password_prompts(mut self, n: u32) -> Self {
        self.password_prompts = Some(n);
        self
    }

    /// Skip host-key checks when the host is localhost (`NoHostAuthenticationForLocalhost`).
    pub fn no_host_authentication_for_localhost(mut self, yes: bool) -> Self {
        self.no_host_auth_localhost = Some(yes);
        self
    }

    /// Minimum RSA host-key size in bits (`RequiredRSASize`).
    ///
    /// The OpenSSH default is 1024, and the value cannot be lowered.
    pub fn required_rsa_size(mut self, bits: u32) -> Self {
        self.required_rsa_size = Some(bits);
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

        let mut set_env = self.set_env.clone();
        for (name, value) in &params.set_env {
            if set_env.iter().any(|(existing, _)| existing == name) {
                continue;
            }
            set_env.push((name.clone(), value.clone()));
        }

        let connection_attempts = self
            .connection_attempts
            .or(params.connection_attempts)
            .unwrap_or(1);
        if connection_attempts == 0 {
            return Err(Error::Config(
                "ConnectionAttempts must be at least 1".into(),
            ));
        }
        let required_rsa_size = self
            .required_rsa_size
            .or(params.required_rsa_size)
            .unwrap_or(1024);
        if required_rsa_size < 1024 {
            return Err(Error::Config(format!(
                "RequiredRSASize {required_rsa_size} is below the minimum of 1024"
            )));
        }

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
            server_alive_count_max: self
                .server_alive_count_max
                .or(params.server_alive_count_max),
            ciphers: self.ciphers.clone().or(params.ciphers.clone()),
            macs: self.macs.clone().or(params.macs.clone()),
            kex_algorithms: self
                .kex_algorithms
                .clone()
                .or(params.kex_algorithms.clone()),
            host_key_algorithms: self
                .host_key_algorithms
                .clone()
                .or(params.host_key_algorithms.clone()),
            rekey_limit: self.rekey_limit.clone().or(params.rekey_limit.clone()),
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
                Some(files) => expand_known_hosts_list(files),
                None if !params.user_known_hosts_file.is_empty() => {
                    params.user_known_hosts_file.clone()
                }
                None => vec![ssh_config::home_dir().join(".ssh").join("known_hosts")],
            },
            global_known_hosts_files: match &self.global_known_hosts_file {
                Some(files) => expand_known_hosts_list(files),
                None => params
                    .global_known_hosts_file
                    .clone()
                    .unwrap_or_else(ssh_config::default_global_known_hosts_files),
            },
            request_tty: params.request_tty.unwrap_or(false),
            user: self.user.clone(),
            password_manager,
            ssh_config: config.cloned(),
            batch_mode: self.batch_mode.or(params.batch_mode).unwrap_or(false),
            connection_attempts,
            preferred_authentications: self
                .preferred_authentications
                .clone()
                .or(params.preferred_authentications.clone())
                .unwrap_or_else(AuthMethod::default_order),
            set_env,
            tcp_keepalive: self.tcp_keepalive.or(params.tcp_keepalive).unwrap_or(true),
            password_prompts: self
                .password_prompts
                .or(params.password_prompts)
                .unwrap_or(3),
            no_host_auth_localhost: self
                .no_host_auth_localhost
                .or(params.no_host_auth_localhost)
                .unwrap_or(false),
            required_rsa_size,
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
    pub server_alive_count_max: Option<usize>,
    pub ciphers: Option<String>,
    pub macs: Option<String>,
    pub kex_algorithms: Option<String>,
    pub host_key_algorithms: Option<String>,
    pub rekey_limit: Option<String>,
    pub compression: bool,
    pub pubkey_authentication: bool,
    pub password_authentication: bool,
    pub kbd_interactive_authentication: bool,
    pub use_agent: bool,
    pub host_key_policy: HostKeyPolicy,
    /// User known_hosts files, searched first. A new key is written to the
    /// first one, never to [`Self::global_known_hosts_files`].
    pub known_hosts_files: Vec<PathBuf>,
    /// System known_hosts files. Searched only when [`Self::known_hosts_files`]
    /// does not mention the host.
    pub global_known_hosts_files: Vec<PathBuf>,
    pub request_tty: bool,
    /// Default user commands run as. `None` means the login user.
    pub user: Option<String>,
    pub password_manager: SharedPasswordManager,
    /// The config used, so jump hosts resolve against the same file.
    pub ssh_config: Option<SshConfig>,
    /// `BatchMode yes`: do not prompt for a password or key passphrase.
    pub batch_mode: bool,
    /// TCP connect attempts. Authentication is not retried.
    pub connection_attempts: u32,
    /// Authentication methods after the initial `none` probe, in try order.
    pub preferred_authentications: Vec<AuthMethod>,
    /// Environment variables sent on each session channel before exec.
    pub set_env: Vec<(String, String)>,
    /// `SO_KEEPALIVE` on the direct TCP socket. Default yes.
    pub tcp_keepalive: bool,
    /// Password, keyboard-interactive, and key-passphrase attempts.
    pub password_prompts: u32,
    /// Skip host-key checks for a localhost destination.
    pub no_host_auth_localhost: bool,
    /// Minimum RSA host-key size in bits. Non-RSA keys are unaffected.
    pub required_rsa_size: u32,
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
            server_alive_count_max: self.server_alive_count_max,
            ciphers: self.ciphers.clone(),
            macs: self.macs.clone(),
            kex_algorithms: self.kex_algorithms.clone(),
            host_key_algorithms: self.host_key_algorithms.clone(),
            rekey_limit: self.rekey_limit.clone(),
            compression: Some(self.compression),
            pubkey_authentication: Some(self.pubkey_authentication),
            password_authentication: Some(self.password_authentication),
            kbd_interactive_authentication: Some(self.kbd_interactive_authentication),
            use_agent: Some(self.use_agent),
            host_key_policy: Some(self.host_key_policy),
            known_hosts_file: Some(self.known_hosts_files.clone()),
            global_known_hosts_file: Some(self.global_known_hosts_files.clone()),
            ssh_config: match &self.ssh_config {
                Some(c) => SshConfigSource::Parsed(c.clone()),
                None => SshConfigSource::None,
            },
            user: None,
            password_manager: Some(self.password_manager.clone()),
            batch_mode: Some(self.batch_mode),
            connection_attempts: Some(self.connection_attempts),
            preferred_authentications: Some(self.preferred_authentications.clone()),
            // The jump only forwards a socket. Its own config supplies SetEnv
            // if a later exec on that hop needs it.
            set_env: Vec::new(),
            tcp_keepalive: Some(self.tcp_keepalive),
            password_prompts: Some(self.password_prompts),
            no_host_auth_localhost: Some(self.no_host_auth_localhost),
            required_rsa_size: Some(self.required_rsa_size),
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
    fn transport_keywords_builder_beats_config() {
        let cfg = SshConfig::parse_str(
            "Host *\n ServerAliveCountMax 9\n Ciphers aes128-ctr\n MACs hmac-sha2-256\n KexAlgorithms curve25519-sha256\n HostKeyAlgorithms ssh-ed25519\n RekeyLimit 512M\n",
            None,
        )
        .unwrap();
        let r = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(r.server_alive_count_max, Some(9));
        assert_eq!(r.ciphers.as_deref(), Some("aes128-ctr"));
        assert_eq!(r.macs.as_deref(), Some("hmac-sha2-256"));
        assert_eq!(r.kex_algorithms.as_deref(), Some("curve25519-sha256"));
        assert_eq!(r.host_key_algorithms.as_deref(), Some("ssh-ed25519"));
        assert_eq!(r.rekey_limit.as_deref(), Some("512M"));

        let r = ConnectOptions::new("h")
            .server_alive_count_max(2)
            .ciphers("^aes256-ctr")
            .rekey_limit("1G 10m")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(r.server_alive_count_max, Some(2));
        assert_eq!(r.ciphers.as_deref(), Some("^aes256-ctr"));
        assert_eq!(r.rekey_limit.as_deref(), Some("1G 10m"));
        assert_eq!(r.macs.as_deref(), Some("hmac-sha2-256"));

        let jump = r.for_jump(&JumpHost {
            login_user: None,
            host: "jump".into(),
            port: None,
        });
        assert_eq!(jump.ciphers.as_deref(), Some("^aes256-ctr"));
        assert_eq!(jump.server_alive_count_max, Some(2));
        assert_eq!(jump.rekey_limit.as_deref(), Some("1G 10m"));
    }

    #[test]
    fn global_known_hosts_file_defaults_and_overrides() {
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert_eq!(
            defaults.global_known_hosts_files,
            ssh_config::default_global_known_hosts_files()
        );

        let cfg =
            SshConfig::parse_str("Host *\n GlobalKnownHostsFile /etc/ssh/custom\n", None).unwrap();
        let configured = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(
            configured.global_known_hosts_files,
            vec![PathBuf::from("/etc/ssh/custom")]
        );

        let cleared = ConnectOptions::new("h")
            .global_known_hosts_files(Vec::<PathBuf>::new())
            .resolve_with(Some(&cfg))
            .unwrap();
        assert!(cleared.global_known_hosts_files.is_empty());

        let user_only = ConnectOptions::new("h")
            .known_hosts_file("/tmp/user_known_hosts")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(
            user_only.known_hosts_files,
            vec![PathBuf::from("/tmp/user_known_hosts")]
        );
        assert_eq!(
            user_only.global_known_hosts_files,
            vec![PathBuf::from("/etc/ssh/custom")]
        );
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

    #[test]
    fn batch_mode_defaults_off_and_builder_wins() {
        let cfg = SshConfig::parse_str("Host *\n BatchMode yes\n", None).unwrap();
        let off = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert!(!off.batch_mode);
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert!(from_config.batch_mode);
        let forced = ConnectOptions::new("h")
            .batch_mode(false)
            .resolve_with(Some(&cfg))
            .unwrap();
        assert!(!forced.batch_mode);
        let jump = from_config.for_jump(&JumpHost {
            login_user: None,
            host: "jump".into(),
            port: None,
        });
        assert_eq!(jump.batch_mode, Some(true));
    }

    #[test]
    fn connection_attempts_default_and_override() {
        let cfg = SshConfig::parse_str("Host *\n ConnectionAttempts 3\n", None).unwrap();
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert_eq!(defaults.connection_attempts, 1);
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(from_config.connection_attempts, 3);
        let forced = ConnectOptions::new("h")
            .connection_attempts(2)
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(forced.connection_attempts, 2);
        assert!(
            ConnectOptions::new("h")
                .connection_attempts(0)
                .no_ssh_config()
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn preferred_authentications_order_and_unknown_names() {
        assert_eq!(
            AuthMethod::parse_list("password, publickey, gssapi-with-mic, password"),
            vec![AuthMethod::Password, AuthMethod::PublicKey]
        );
        assert!(AuthMethod::parse_list("gssapi-with-mic,hostbased").is_empty());

        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert_eq!(
            defaults.preferred_authentications,
            AuthMethod::default_order()
        );

        let cfg = SshConfig::parse_str(
            "Host *\n PreferredAuthentications password,publickey\n",
            None,
        )
        .unwrap();
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(
            from_config.preferred_authentications,
            vec![AuthMethod::Password, AuthMethod::PublicKey]
        );
        let forced = ConnectOptions::new("h")
            .preferred_authentications("keyboard-interactive")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(
            forced.preferred_authentications,
            vec![AuthMethod::KeyboardInteractive]
        );
        let none_usable = ConnectOptions::new("h")
            .preferred_authentications("hostbased")
            .no_ssh_config()
            .resolve()
            .unwrap();
        assert!(none_usable.preferred_authentications.is_empty());
    }

    #[test]
    fn set_env_builder_wins_per_name() {
        let cfg = SshConfig::parse_str("Host *\n SetEnv A=cfg B=fromcfg\n", None).unwrap();
        let r = ConnectOptions::new("h")
            .set_env("A", "api")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(
            r.set_env,
            vec![("A".into(), "api".into()), ("B".into(), "fromcfg".into())]
        );
    }

    #[test]
    fn tcp_keepalive_defaults_on() {
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert!(defaults.tcp_keepalive);
        let cfg = SshConfig::parse_str("Host *\n TCPKeepAlive no\n", None).unwrap();
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert!(!from_config.tcp_keepalive);
        let forced = ConnectOptions::new("h")
            .tcp_keepalive(true)
            .resolve_with(Some(&cfg))
            .unwrap();
        assert!(forced.tcp_keepalive);
    }

    #[test]
    fn password_prompts_default_to_three() {
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert_eq!(defaults.password_prompts, 3);
        let cfg = SshConfig::parse_str("Host *\n NumberOfPasswordPrompts 1\n", None).unwrap();
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(from_config.password_prompts, 1);
        let none = ConnectOptions::new("h")
            .number_of_password_prompts(0)
            .resolve_with(Some(&cfg))
            .unwrap();
        assert_eq!(none.password_prompts, 0);
    }

    #[test]
    fn no_host_auth_localhost_defaults_off() {
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert!(!defaults.no_host_auth_localhost);
        let cfg =
            SshConfig::parse_str("Host *\n NoHostAuthenticationForLocalhost yes\n", None).unwrap();
        let from_config = ConnectOptions::new("localhost")
            .resolve_with(Some(&cfg))
            .unwrap();
        assert!(from_config.no_host_auth_localhost);
    }

    #[test]
    fn required_rsa_size_defaults_to_1024_and_cannot_be_lowered() {
        let defaults = ConnectOptions::new("h").no_ssh_config().resolve().unwrap();
        assert_eq!(defaults.required_rsa_size, 1024);
        let cfg = SshConfig::parse_str("Host *\n RequiredRSASize 2048\n", None).unwrap();
        let from_config = ConnectOptions::new("h").resolve_with(Some(&cfg)).unwrap();
        assert_eq!(from_config.required_rsa_size, 2048);
        assert!(
            ConnectOptions::new("h")
                .required_rsa_size(512)
                .no_ssh_config()
                .resolve()
                .is_err()
        );
    }

    use std::sync::Arc;
}
