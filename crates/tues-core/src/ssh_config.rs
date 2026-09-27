//! A parser for OpenSSH `ssh_config(5)` files.
//!
//! Supports `Host` blocks with `*`/`?` globs and `!` negation, `Include`
//! (with globbing in the last path component), `Match all`, and the client
//! options `tues` understands. Unknown directives are retained in
//! [`HostParams::unknown`] so a normal config still loads. Other `Match`
//! blocks are skipped.
//!
//! Resolution follows OpenSSH: the first obtained value for a key wins,
//! except `IdentityFile`, which accumulates.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::options::HostKeyPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    negate: bool,
    glob: String,
}

impl Pattern {
    fn parse(s: &str) -> Self {
        match s.strip_prefix('!') {
            Some(rest) => Pattern {
                negate: true,
                glob: rest.to_string(),
            },
            None => Pattern {
                negate: false,
                glob: s.to_string(),
            },
        }
    }
}

/// `*` and `?` glob match (case-insensitive, as OpenSSH does for hostnames).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b) && rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

#[derive(Debug, Clone)]
struct Block {
    /// `None` means the block applies to every host (`Match all`, or
    /// directives before the first `Host`).
    patterns: Option<Vec<Pattern>>,
    entries: Vec<(String, String)>,
}

impl Block {
    fn matches(&self, host: &str) -> bool {
        let Some(patterns) = &self.patterns else {
            return true;
        };
        let mut matched = false;
        for p in patterns {
            if glob_match(&p.glob, host) {
                if p.negate {
                    return false;
                }
                matched = true;
            }
        }
        matched
    }
}

/// A parsed `ssh_config` file.
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    blocks: Vec<Block>,
}

/// Effective options for one host alias.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostParams {
    pub host_name: Option<String>,
    /// Login user, from the `User` directive.
    pub login_user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Vec<PathBuf>,
    pub identities_only: Option<bool>,
    pub proxy_jump: Option<Vec<String>>,
    pub strict_host_key_checking: Option<HostKeyPolicy>,
    pub user_known_hosts_file: Option<PathBuf>,
    pub connect_timeout: Option<Duration>,
    pub server_alive_interval: Option<Duration>,
    pub compression: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub password_authentication: Option<bool>,
    pub kbd_interactive_authentication: Option<bool>,
    pub forward_agent: Option<bool>,
    pub request_tty: Option<bool>,
    /// Directives `tues` does not interpret, in file order (lowercased keys).
    pub unknown: Vec<(String, String)>,
}

impl SshConfig {
    /// Parse config text. `base_dir` resolves relative `Include` paths
    /// (OpenSSH uses `~/.ssh` for user configs).
    pub fn parse_str(text: &str, base_dir: Option<&Path>) -> Result<Self> {
        let mut cfg = SshConfig::default();
        let mut seen = HashSet::new();
        cfg.parse_into(text, base_dir, &mut seen, 0)?;
        Ok(cfg)
    }

    /// Load and parse a config file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("cannot read ssh config {}: {e}", path.display()))
        })?;
        let base = default_base_dir().or_else(|| path.parent().map(Path::to_path_buf));
        let mut cfg = SshConfig::default();
        let mut seen = HashSet::new();
        if let Ok(canon) = path.canonicalize() {
            seen.insert(canon);
        }
        cfg.parse_into(&text, base.as_deref(), &mut seen, 0)?;
        Ok(cfg)
    }

    /// Load `~/.ssh/config` if it exists.
    pub fn load_default() -> Result<Option<Self>> {
        match default_path() {
            Some(p) if p.is_file() => Ok(Some(Self::load(p)?)),
            _ => Ok(None),
        }
    }

    fn parse_into(
        &mut self,
        text: &str,
        base_dir: Option<&Path>,
        seen: &mut HashSet<PathBuf>,
        depth: usize,
    ) -> Result<()> {
        if depth > 16 {
            return Err(Error::Config("ssh config Include nesting too deep".into()));
        }
        let mut current = Block {
            patterns: None,
            entries: Vec::new(),
        };
        // Directives inside an unsupported Match block are dropped.
        let mut skipping = false;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = split_directive(line) else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            match key.as_str() {
                "host" => {
                    self.push_block(std::mem::replace(
                        &mut current,
                        Block {
                            patterns: Some(
                                split_words(&value)
                                    .iter()
                                    .map(|s| Pattern::parse(s))
                                    .collect(),
                            ),
                            entries: Vec::new(),
                        },
                    ));
                    skipping = false;
                }
                "match" => {
                    self.push_block(std::mem::replace(
                        &mut current,
                        Block {
                            patterns: None,
                            entries: Vec::new(),
                        },
                    ));
                    skipping = !value.trim().eq_ignore_ascii_case("all");
                }
                "include" => {
                    if skipping {
                        continue;
                    }
                    for pat in split_words(&value) {
                        for file in expand_include(&pat, base_dir) {
                            let canon = file.canonicalize().unwrap_or(file.clone());
                            if !seen.insert(canon) {
                                continue;
                            }
                            let Ok(text) = std::fs::read_to_string(&file) else {
                                continue;
                            };
                            // Included blocks inherit the current Host context.
                            let mut sub = SshConfig::default();
                            sub.parse_into(&text, base_dir, seen, depth + 1)?;
                            for mut b in sub.blocks {
                                if b.patterns.is_none() {
                                    current.entries.append(&mut b.entries);
                                } else {
                                    // Keep file order: flush what we have, then
                                    // continue the current Host context afterwards.
                                    let cont = Block {
                                        patterns: current.patterns.clone(),
                                        entries: Vec::new(),
                                    };
                                    self.push_block(std::mem::replace(&mut current, cont));
                                    self.blocks.push(b);
                                }
                            }
                        }
                    }
                }
                _ => {
                    if !skipping {
                        current.entries.push((key, value));
                    }
                }
            }
        }
        self.push_block(current);
        Ok(())
    }

    fn push_block(&mut self, b: Block) {
        if !b.entries.is_empty() {
            self.blocks.push(b);
        }
    }

    /// Effective parameters for `host`, with `%` tokens expanded.
    pub fn query(&self, host: &str) -> HostParams {
        let mut p = HostParams::default();
        let mut identity_raw: Vec<String> = Vec::new();
        for block in self.blocks.iter().filter(|b| b.matches(host)) {
            for (k, v) in &block.entries {
                apply(&mut p, &mut identity_raw, k, v);
            }
        }
        let hostname = p.host_name.clone().unwrap_or_else(|| host.to_string());
        let login_user = p.login_user.clone().unwrap_or_else(local_user);
        let port = p.port.unwrap_or(22);
        p.host_name = Some(expand_tokens(&hostname, host, &hostname, &login_user, port));
        p.identity_file = identity_raw
            .iter()
            .map(|f| expand_path(&expand_tokens(f, host, &hostname, &login_user, port)))
            .collect();
        if let Some(k) = &p.user_known_hosts_file {
            let s = k.to_string_lossy().into_owned();
            p.user_known_hosts_file = Some(expand_path(&expand_tokens(
                &s,
                host,
                &hostname,
                &login_user,
                port,
            )));
        }
        p
    }
}

fn apply(p: &mut HostParams, identity_raw: &mut Vec<String>, key: &str, value: &str) {
    macro_rules! first {
        ($field:expr, $val:expr) => {
            if $field.is_none() {
                $field = $val;
            }
        };
    }
    match key {
        "hostname" => first!(p.host_name, Some(value.to_string())),
        "user" => first!(p.login_user, Some(value.to_string())),
        "port" => first!(p.port, value.parse().ok()),
        "identityfile" => identity_raw.push(value.to_string()),
        "identitiesonly" => first!(p.identities_only, yes_no(value)),
        "proxyjump" => first!(
            p.proxy_jump,
            Some(if value.eq_ignore_ascii_case("none") {
                Vec::new()
            } else {
                value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        ),
        "stricthostkeychecking" => first!(p.strict_host_key_checking, HostKeyPolicy::parse(value)),
        "userknownhostsfile" => first!(
            p.user_known_hosts_file,
            split_words(value).first().map(PathBuf::from)
        ),
        "connecttimeout" => first!(
            p.connect_timeout,
            value.parse().ok().map(Duration::from_secs)
        ),
        "serveraliveinterval" => first!(
            p.server_alive_interval,
            value
                .parse()
                .ok()
                .filter(|s: &u64| *s > 0)
                .map(Duration::from_secs)
        ),
        "compression" => first!(p.compression, yes_no(value)),
        "pubkeyauthentication" => first!(p.pubkey_authentication, yes_no(value)),
        "passwordauthentication" => first!(p.password_authentication, yes_no(value)),
        "kbdinteractiveauthentication" => first!(p.kbd_interactive_authentication, yes_no(value)),
        "forwardagent" => first!(p.forward_agent, yes_no(value)),
        "requesttty" => first!(
            p.request_tty,
            match value.to_ascii_lowercase().as_str() {
                "yes" | "force" => Some(true),
                "no" | "auto" => Some(false),
                _ => None,
            }
        ),
        _ => p.unknown.push((key.to_string(), value.to_string())),
    }
}

fn yes_no(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

/// Split `Key Value`, `Key=Value` or `Key = Value`.
fn split_directive(line: &str) -> Option<(&str, String)> {
    let key_end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..key_end];
    let rest = line[key_end..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    let rest = rest.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, unquote(rest)))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Split on whitespace, honouring double quotes.
fn split_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn expand_tokens(s: &str, alias: &str, hostname: &str, login_user: &str, port: u16) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(hostname),
            Some('n') => out.push_str(alias),
            Some('r') => out.push_str(login_user),
            Some('p') => out.push_str(&port.to_string()),
            Some('u') => out.push_str(&local_user()),
            Some('d') => out.push_str(&home_dir().to_string_lossy()),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Expand a leading `~` or `~/`.
pub fn expand_path(s: &str) -> PathBuf {
    if s == "~" {
        return home_dir();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    PathBuf::from(s)
}

fn expand_include(pattern: &str, base_dir: Option<&Path>) -> Vec<PathBuf> {
    let expanded = expand_path(pattern);
    let path = if expanded.is_absolute() {
        expanded
    } else {
        match base_dir {
            Some(b) => b.join(expanded),
            None => expanded,
        }
    };
    let has_glob = path
        .file_name()
        .map(|n| n.to_string_lossy().contains(['*', '?']))
        .unwrap_or(false);
    if !has_glob {
        return vec![path];
    }
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let Some(pat) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .map(|n| glob_match(&pat, &n.to_string_lossy()))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

pub(crate) fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

pub(crate) fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

/// `~/.ssh/config`
pub fn default_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh").join("config"))
}

fn default_base_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_semantics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web*", "web01"));
        assert!(glob_match("web??", "web01"));
        assert!(!glob_match("web??", "web001"));
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("HOST", "host"));
    }

    #[test]
    fn first_match_wins_and_identity_files_accumulate() {
        let text = r#"
# comment
Host web01
    HostName 10.0.0.1
    User alice
    IdentityFile ~/.ssh/web
    Port 2222

Host web*
    User bob
    IdentityFile ~/.ssh/fleet
    ProxyJump jump.example.com

Host *
    User carol
    ServerAliveInterval 30
    StrictHostKeyChecking accept-new
    Compression yes
    ConnectTimeout 5
    SomethingUnknown value
"#;
        let cfg = SshConfig::parse_str(text, None).unwrap();
        let p = cfg.query("web01");
        assert_eq!(p.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(p.login_user.as_deref(), Some("alice"));
        assert_eq!(p.port, Some(2222));
        assert_eq!(
            p.identity_file,
            vec![home_dir().join(".ssh/web"), home_dir().join(".ssh/fleet")]
        );
        assert_eq!(p.proxy_jump, Some(vec!["jump.example.com".to_string()]));
        assert_eq!(p.server_alive_interval, Some(Duration::from_secs(30)));
        assert_eq!(p.strict_host_key_checking, Some(HostKeyPolicy::AcceptNew));
        assert_eq!(p.compression, Some(true));
        assert_eq!(p.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(
            p.unknown,
            vec![("somethingunknown".to_string(), "value".to_string())]
        );

        let p = cfg.query("web02");
        assert_eq!(p.login_user.as_deref(), Some("bob"));
        assert_eq!(p.host_name.as_deref(), Some("web02"));
        assert_eq!(p.port, None);

        let p = cfg.query("db");
        assert_eq!(p.login_user.as_deref(), Some("carol"));
        assert!(p.proxy_jump.is_none());
    }

    #[test]
    fn negation_and_equals_syntax() {
        let text = "Host * !bastion\n  ProxyJump=bastion\nHost bastion\n  User=root\n";
        let cfg = SshConfig::parse_str(text, None).unwrap();
        assert_eq!(cfg.query("x").proxy_jump, Some(vec!["bastion".into()]));
        assert_eq!(cfg.query("bastion").proxy_jump, None);
        assert_eq!(cfg.query("bastion").login_user.as_deref(), Some("root"));
    }

    #[test]
    fn tokens_are_expanded() {
        let text = "Host h\n  HostName real.example\n  User u\n  IdentityFile /keys/%r@%h:%p\n";
        let cfg = SshConfig::parse_str(text, None).unwrap();
        assert_eq!(
            cfg.query("h").identity_file,
            vec![PathBuf::from("/keys/u@real.example:22")]
        );
    }

    #[test]
    fn match_blocks_are_skipped_except_all() {
        let text = "Match exec \"true\"\n  User skipped\nMatch all\n  User everyone\n";
        let cfg = SshConfig::parse_str(text, None).unwrap();
        assert_eq!(cfg.query("x").login_user.as_deref(), Some("everyone"));
    }

    #[test]
    fn include_is_followed() {
        let dir = std::env::temp_dir().join(format!("tues-sshcfg-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::write(dir.join("conf.d/a.conf"), "Host inc\n  Port 2200\n").unwrap();
        std::fs::write(dir.join("conf.d/b.conf"), "Port 9\n").unwrap();
        let main = dir.join("config");
        std::fs::write(&main, "Host inc\n  User me\n  Include conf.d/*.conf\n").unwrap();
        let mut cfg = SshConfig::default();
        let mut seen = HashSet::new();
        cfg.parse_into(
            &std::fs::read_to_string(&main).unwrap(),
            Some(&dir),
            &mut seen,
            0,
        )
        .unwrap();
        let p = cfg.query("inc");
        assert_eq!(p.login_user.as_deref(), Some("me"));
        // Includes are spliced in file order: a.conf (Host inc, Port 2200)
        // precedes b.conf (no Host line, inherits Host inc, Port 9).
        assert_eq!(p.port, Some(2200));
        assert_eq!(cfg.query("other").port, None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
