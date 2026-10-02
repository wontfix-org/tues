//! Map resolved `ssh_config` transport keywords onto `russh::client::Config`.

use std::borrow::Cow;
use std::time::Duration;

use russh::client::Config;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use tracing::warn;
use tues_core::algo_list::{parse_algo_directive, parse_rekey_limit, resolve_algo_list};

/// The subset of [`tues_core::ResolvedOptions`] that changes the SSH transport.
pub(crate) struct TransportConfig<'a> {
    pub server_alive_interval: Option<Duration>,
    pub server_alive_count_max: Option<usize>,
    pub compression: bool,
    pub ciphers: Option<&'a str>,
    pub macs: Option<&'a str>,
    pub kex_algorithms: Option<&'a str>,
    pub host_key_algorithms: Option<&'a str>,
    pub rekey_limit: Option<&'a str>,
}

/// Russh's built-in client preference order, without the kex extension names.
/// Those two are appended after the user's list so strict kex and `ext-info`
/// stay offered.
const DEFAULT_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
];

const KNOWN_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "none",
];

const DEFAULT_MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
];

const KNOWN_MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1",
    "none",
];

const DEFAULT_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group17-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group15-sha512",
    "diffie-hellman-group14-sha256",
];

const KNOWN_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group17-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group15-sha512",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
    "none",
];

const DEFAULT_HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

const KNOWN_HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
];

const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

pub(crate) fn build_client_config(prefs: &TransportConfig<'_>) -> Config {
    let mut config = Config {
        inactivity_timeout: None,
        keepalive_interval: prefs.server_alive_interval,
        keepalive_max: prefs.server_alive_count_max.unwrap_or(3),
        nodelay: true,
        ..Config::default()
    };
    if prefs.compression {
        config.preferred.compression = Cow::Borrowed(&[
            russh::compression::ZLIB_LEGACY,
            russh::compression::ZLIB,
            russh::compression::NONE,
        ]);
    }
    apply_name_list(
        &mut config,
        "Ciphers",
        prefs.ciphers,
        DEFAULT_CIPHERS,
        KNOWN_CIPHERS,
        |config, names| {
            config.preferred.cipher = Cow::Owned(
                names
                    .iter()
                    .filter_map(|name| russh::cipher::Name::try_from(name.as_str()).ok())
                    .collect(),
            );
        },
    );
    apply_name_list(
        &mut config,
        "MACs",
        prefs.macs,
        DEFAULT_MACS,
        KNOWN_MACS,
        |config, names| {
            config.preferred.mac = Cow::Owned(
                names
                    .iter()
                    .filter_map(|name| russh::mac::Name::try_from(name.as_str()).ok())
                    .collect(),
            );
        },
    );
    apply_name_list(
        &mut config,
        "KexAlgorithms",
        prefs.kex_algorithms,
        DEFAULT_KEX,
        KNOWN_KEX,
        |config, names| {
            let mut kex: Vec<russh::kex::Name> = names
                .iter()
                .filter_map(|name| russh::kex::Name::try_from(name.as_str()).ok())
                .collect();
            kex.push(russh::kex::EXTENSION_SUPPORT_AS_CLIENT);
            kex.push(russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT);
            config.preferred.kex = Cow::Owned(kex);
        },
    );
    apply_host_keys(&mut config, prefs.host_key_algorithms);
    if let Some(spec) = prefs.rekey_limit {
        match parse_rekey_limit(spec) {
            Some(limit) => {
                if limit.bytes_clamped {
                    warn!(value = spec, "RekeyLimit exceeds 1 GiB and was clamped");
                }
                config.limits = russh::Limits::new(limit.bytes, limit.bytes, limit.time);
            }
            None => warn!(value = spec, "ignoring unusable RekeyLimit"),
        }
    }
    config
}

fn apply_name_list(
    config: &mut Config,
    keyword: &'static str,
    spec: Option<&str>,
    default: &[&str],
    known: &[&str],
    assign: impl FnOnce(&mut Config, &[String]),
) {
    let Some(names) = resolve_spec(keyword, spec, default, known) else {
        return;
    };
    assign(config, &names);
}

fn apply_host_keys(config: &mut Config, spec: Option<&str>) {
    let Some(names) = resolve_spec(
        "HostKeyAlgorithms",
        spec,
        DEFAULT_HOST_KEYS,
        KNOWN_HOST_KEYS,
    ) else {
        return;
    };
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for name in &names {
        let Some(algo) = host_key_algo(name) else {
            warn!(
                keyword = "HostKeyAlgorithms",
                algorithm = %name,
                "ignoring unsupported ssh_config algorithm"
            );
            continue;
        };
        if name.ends_with(CERT_SUFFIX) {
            certs.push(algo);
        } else {
            keys.push(algo);
        }
    }
    config.preferred.host_key_certificates = Cow::Owned(certs);
    config.preferred.key = Cow::Owned(keys);
}

/// `None` keeps russh's built-in list: the directive was absent, unusable, or
/// named only algorithms this build does not implement.
fn resolve_spec(
    keyword: &'static str,
    spec: Option<&str>,
    default: &[&str],
    known: &[&str],
) -> Option<Vec<String>> {
    let spec = spec?;
    let Some(directive) = parse_algo_directive(spec) else {
        warn!(
            keyword,
            value = spec,
            "ignoring unusable ssh_config algorithm list"
        );
        return None;
    };
    let resolved = resolve_algo_list(&directive, default, known);
    for name in &resolved.unknown {
        warn!(
            keyword,
            algorithm = %name,
            "ignoring unsupported ssh_config algorithm"
        );
    }
    if resolved.names.is_empty() && resolved.unknown.len() == directive.patterns().len() {
        warn!(
            keyword,
            value = spec,
            "ssh_config algorithm list matched nothing; keeping the default"
        );
        return None;
    }
    if resolved.names.is_empty() {
        warn!(keyword, value = spec, "ssh_config algorithm list is empty");
    }
    Some(resolved.names)
}

fn host_key_algo(name: &str) -> Option<Algorithm> {
    let plain = name.strip_suffix(CERT_SUFFIX).unwrap_or(name);
    Some(match plain {
        "ssh-ed25519" => Algorithm::Ed25519,
        "ecdsa-sha2-nistp256" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        "ecdsa-sha2-nistp384" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        "ecdsa-sha2-nistp521" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        "rsa-sha2-256" => Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
        "rsa-sha2-512" => Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        "ssh-rsa" => Algorithm::Rsa { hash: None },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare() -> TransportConfig<'static> {
        TransportConfig {
            server_alive_interval: None,
            server_alive_count_max: None,
            compression: false,
            ciphers: None,
            macs: None,
            kex_algorithms: None,
            host_key_algorithms: None,
            rekey_limit: None,
        }
    }

    fn names<'a, T: AsRef<str> + 'a>(list: &'a [T]) -> Vec<&'a str> {
        list.iter().map(|n| n.as_ref()).collect()
    }

    #[test]
    fn known_names_are_implemented() {
        for name in KNOWN_CIPHERS {
            assert!(russh::cipher::Name::try_from(*name).is_ok(), "{name}");
        }
        for name in KNOWN_MACS {
            assert!(russh::mac::Name::try_from(*name).is_ok(), "{name}");
        }
        for name in KNOWN_KEX {
            assert!(russh::kex::Name::try_from(*name).is_ok(), "{name}");
        }
        for name in KNOWN_HOST_KEYS {
            assert!(host_key_algo(name).is_some(), "{name}");
        }
    }

    #[test]
    fn defaults_match_russh() {
        let pref = russh::Preferred::DEFAULT;
        assert_eq!(names(&pref.cipher), DEFAULT_CIPHERS);
        assert_eq!(names(&pref.mac), DEFAULT_MACS);
        let kex = names(&pref.kex);
        assert_eq!(&kex[..DEFAULT_KEX.len()], DEFAULT_KEX);
        assert_eq!(
            &kex[DEFAULT_KEX.len()..],
            [
                "ext-info-c",
                "ext-info-s",
                "kex-strict-c-v00@openssh.com",
                "kex-strict-s-v00@openssh.com",
            ]
        );
        let keys: Vec<String> = pref.key.iter().map(ToString::to_string).collect();
        assert_eq!(keys, DEFAULT_HOST_KEYS);
        assert!(pref.host_key_certificates.is_empty());
    }

    #[test]
    fn count_max_ciphers_and_rekey_are_applied() {
        let mut prefs = bare();
        prefs.server_alive_count_max = Some(5);
        prefs.server_alive_interval = Some(Duration::from_secs(15));
        prefs.ciphers = Some("+aes128-cbc,umac-128");
        prefs.macs = Some("^hmac-sha1");
        prefs.kex_algorithms = Some("curve25519-sha256");
        prefs.host_key_algorithms = Some("ssh-rsa,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256");
        prefs.rekey_limit = Some("2G 30m");
        prefs.compression = true;

        let config = build_client_config(&prefs);
        assert_eq!(config.keepalive_max, 5);
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(config.limits.rekey_write_limit, 1 << 30);
        assert_eq!(config.limits.rekey_read_limit, 1 << 30);
        assert_eq!(config.limits.rekey_time_limit, Duration::from_secs(1800));

        let mut ciphers = DEFAULT_CIPHERS.to_vec();
        ciphers.push("aes128-cbc");
        assert_eq!(names(&config.preferred.cipher), ciphers);

        let mut macs = vec!["hmac-sha1"];
        macs.extend(DEFAULT_MACS.iter().copied().filter(|n| *n != "hmac-sha1"));
        assert_eq!(names(&config.preferred.mac), macs);

        assert_eq!(
            names(&config.preferred.kex),
            vec![
                "curve25519-sha256",
                "ext-info-c",
                "kex-strict-c-v00@openssh.com",
            ]
        );

        let certs: Vec<String> = config
            .preferred
            .host_key_certificates
            .iter()
            .map(Algorithm::to_certificate_type)
            .collect();
        assert_eq!(certs, vec!["ssh-ed25519-cert-v01@openssh.com"]);
        let keys: Vec<String> = config
            .preferred
            .key
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(keys, vec!["ssh-rsa", "rsa-sha2-256"]);

        assert_eq!(
            names(&config.preferred.compression),
            vec!["zlib@openssh.com", "zlib", "none"]
        );
    }

    #[test]
    fn unknown_only_list_keeps_the_default() {
        let mut prefs = bare();
        prefs.ciphers = Some("umac-128");
        prefs.rekey_limit = Some("not-a-limit");
        let config = build_client_config(&prefs);
        assert_eq!(names(&config.preferred.cipher), DEFAULT_CIPHERS);
        assert_eq!(
            config.limits.rekey_write_limit,
            russh::Limits::default().rekey_write_limit
        );
        assert_eq!(config.keepalive_max, 3);
    }

    #[test]
    fn removing_every_cipher_does_not_restore_the_default() {
        let mut prefs = bare();
        prefs.ciphers = Some("-*");
        let config = build_client_config(&prefs);
        assert!(config.preferred.cipher.is_empty());
    }

    #[test]
    fn rekey_none_stays_at_the_russh_default() {
        let mut prefs = bare();
        prefs.rekey_limit = Some("default none");
        let config = build_client_config(&prefs);
        let defaults = russh::Limits::default();
        assert_eq!(config.limits.rekey_write_limit, defaults.rekey_write_limit);
        assert_eq!(config.limits.rekey_time_limit, defaults.rekey_time_limit);
    }
}
