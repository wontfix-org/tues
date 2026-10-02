//! OpenSSH algorithm-list syntax (`+` / `-` / `^`) and `RekeyLimit`.
//!
//! The lists name algorithms. Which names a driver can actually offer is
//! decided by the caller (`default` is the built-in preference order,
//! `known` is every name that driver implements).

use std::time::Duration;

/// How an `ssh_config` algorithm list relates to the built-in default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgoDirective {
    /// The list replaces the default. Order is the order written.
    Replace(Vec<String>),
    /// Append these algorithms to the default (`+`).
    Append(Vec<String>),
    /// Remove these algorithms from the default (`-`). Patterns may use `*` and `?`.
    Remove(Vec<String>),
    /// Place these algorithms at the head of the default (`^`).
    Prepend(Vec<String>),
}

impl AlgoDirective {
    /// The comma-separated entries, without the leading `+`, `-`, or `^`.
    pub fn patterns(&self) -> &[String] {
        match self {
            Self::Replace(p) | Self::Append(p) | Self::Remove(p) | Self::Prepend(p) => p,
        }
    }
}

/// Names to offer, plus patterns that matched nothing the driver supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgoResolution {
    pub names: Vec<String>,
    pub unknown: Vec<String>,
}

/// Parse one algorithm-list value. `None` when the value has no algorithms
/// (empty, or a bare `+` / `-` / `^`).
pub fn parse_algo_directive(value: &str) -> Option<AlgoDirective> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (kind, rest) = match value.as_bytes()[0] {
        b'+' => (Kind::Append, &value[1..]),
        b'-' => (Kind::Remove, &value[1..]),
        b'^' => (Kind::Prepend, &value[1..]),
        _ => (Kind::Replace, value),
    };
    let patterns: Vec<String> = rest
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if patterns.is_empty() {
        return None;
    }
    Some(match kind {
        Kind::Replace => AlgoDirective::Replace(patterns),
        Kind::Append => AlgoDirective::Append(patterns),
        Kind::Remove => AlgoDirective::Remove(patterns),
        Kind::Prepend => AlgoDirective::Prepend(patterns),
    })
}

enum Kind {
    Replace,
    Append,
    Remove,
    Prepend,
}

/// Apply `directive` to `default`.
///
/// Exact names keep the order they were written. A pattern containing `*` or
/// `?` expands to the matching entries of `known`, in `known` order. Names
/// that are not in `known` are reported in [`AlgoResolution::unknown`] and
/// left out. Removal matches against the default list; a known name that is
/// already absent is not an error.
pub fn resolve_algo_list(
    directive: &AlgoDirective,
    default: &[&str],
    known: &[&str],
) -> AlgoResolution {
    let mut unknown = Vec::new();
    for pattern in directive.patterns() {
        if expand(pattern, known).is_empty() {
            unknown.push(pattern.clone());
        }
    }
    let names = match directive {
        AlgoDirective::Replace(patterns) => collect_new(patterns, known),
        AlgoDirective::Append(patterns) => {
            let mut names: Vec<String> = default.iter().map(|s| (*s).to_string()).collect();
            push_new(&mut names, &collect_new(patterns, known));
            names
        }
        AlgoDirective::Remove(patterns) => default
            .iter()
            .copied()
            .filter(|name| !patterns.iter().any(|p| pattern_matches(p, name)))
            .map(str::to_string)
            .collect(),
        AlgoDirective::Prepend(patterns) => {
            let mut names = collect_new(patterns, known);
            for name in default {
                if !names.iter().any(|have| have == name) {
                    names.push((*name).to_string());
                }
            }
            names
        }
    };
    AlgoResolution { names, unknown }
}

fn collect_new(patterns: &[String], known: &[&str]) -> Vec<String> {
    let mut names = Vec::new();
    for pattern in patterns {
        push_new(&mut names, &expand(pattern, known));
    }
    names
}

fn push_new(out: &mut Vec<String>, items: &[String]) {
    for item in items {
        if !out.iter().any(|have| have == item) {
            out.push(item.clone());
        }
    }
}

fn expand(pattern: &str, known: &[&str]) -> Vec<String> {
    if pattern.contains('*') || pattern.contains('?') {
        known
            .iter()
            .copied()
            .filter(|name| algo_glob(pattern, name))
            .map(str::to_string)
            .collect()
    } else if known.contains(&pattern) {
        vec![pattern.to_string()]
    } else {
        Vec::new()
    }
}

fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        algo_glob(pattern, name)
    } else {
        pattern == name
    }
}

/// Case-sensitive `*` / `?` match. Algorithm names are protocol identifiers.
fn algo_glob(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) => a == b && rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Russh refuses a rekey threshold above 1 GiB, and it has no "never rekey".
pub const REKEY_MAX_BYTES: usize = 1 << 30;

/// Russh's default time between rekeys. `none` maps here, not to "never".
pub const REKEY_DEFAULT_TIME: Duration = Duration::from_secs(3600);

/// Byte and time caps for one `RekeyLimit` directive.
///
/// Both directions use `bytes`. `none` and `default` stay at russh's own
/// defaults (1 GiB and one hour) instead of disabling rekey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyLimit {
    pub bytes: usize,
    pub time: Duration,
    /// The configured byte value was above [`REKEY_MAX_BYTES`] and was reduced.
    pub bytes_clamped: bool,
}

/// Parse `RekeyLimit`'s arguments (`[bytes] [time]`).
///
/// Bytes take a `K` / `M` / `G` / `T` suffix (1024-based) or the tokens
/// `default` and `none`. Time is a number of seconds or an OpenSSH time
/// sequence (`1h30m`); `none` is one hour.
pub fn parse_rekey_limit(value: &str) -> Option<RekeyLimit> {
    let words: Vec<&str> = value.split_whitespace().collect();
    if words.is_empty() || words.len() > 2 {
        return None;
    }
    let (bytes, bytes_clamped) = parse_bytes(words[0])?;
    let time = if words.len() == 2 {
        parse_time(words[1])?
    } else {
        REKEY_DEFAULT_TIME
    };
    Some(RekeyLimit {
        bytes,
        time,
        bytes_clamped,
    })
}

fn parse_bytes(s: &str) -> Option<(usize, bool)> {
    if s.eq_ignore_ascii_case("default") || s.eq_ignore_ascii_case("none") {
        return Some((REKEY_MAX_BYTES, false));
    }
    let n = parse_scaled_bytes(s)?;
    if n == 0 {
        return None;
    }
    if n > REKEY_MAX_BYTES as u128 {
        Some((REKEY_MAX_BYTES, true))
    } else {
        Some((n as usize, false))
    }
}

fn parse_scaled_bytes(s: &str) -> Option<u128> {
    let split_at = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, suffix) = s.split_at(split_at);
    if suffix.chars().count() > 1 || num.is_empty() {
        return None;
    }
    let mult: u128 = match suffix {
        "" => 1,
        "k" | "K" => 1024,
        "m" | "M" => 1024 * 1024,
        "g" | "G" => 1024 * 1024 * 1024,
        "t" | "T" => 1024u128 * 1024 * 1024 * 1024,
        _ => return None,
    };
    let (whole, frac) = match num.split_once('.') {
        Some((w, f)) => (w, f),
        None => (num, ""),
    };
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 9 {
        return None;
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac_val: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    let mut frac_div = 1u128;
    for _ in 0..frac.len() {
        frac_div = frac_div.checked_mul(10)?;
    }
    let base = match whole.checked_mul(mult) {
        Some(v) => v,
        None => return Some(u128::MAX),
    };
    let extra = match frac_val.checked_mul(mult) {
        Some(v) => v / frac_div,
        None => return Some(u128::MAX),
    };
    Some(base.saturating_add(extra))
}

fn parse_time(s: &str) -> Option<Duration> {
    if s.eq_ignore_ascii_case("none") {
        return Some(REKEY_DEFAULT_TIME);
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let n: u64 = s.parse().ok()?;
        return Some(Duration::from_secs(n));
    }
    let mut total: u64 = 0;
    let mut rest = s;
    let mut saw = false;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let (num, after) = rest.split_at(digits);
        let n: u64 = num.parse().ok()?;
        let mut chars = after.chars();
        let unit = chars.next()?;
        let mult: u64 = match unit.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 86_400 * 7,
            _ => return None,
        };
        total = total.checked_add(n.checked_mul(mult)?)?;
        rest = chars.as_str();
        saw = true;
    }
    if !saw {
        return None;
    }
    Some(Duration::from_secs(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &[&str] = &["a", "b", "c"];
    const KNOWN: &[&str] = &["a", "b", "c", "d", "ee"];

    fn resolve(spec: &str) -> AlgoResolution {
        resolve_algo_list(&parse_algo_directive(spec).unwrap(), DEFAULT, KNOWN)
    }

    #[test]
    fn modifiers_follow_openssh() {
        assert_eq!(resolve("b,d").names, vec!["b", "d"]);
        assert_eq!(resolve("+d,b").names, vec!["a", "b", "c", "d"]);
        assert_eq!(resolve("-b").names, vec!["a", "c"]);
        assert_eq!(resolve("^c,d").names, vec!["c", "d", "a", "b"]);
        assert_eq!(resolve("-*").names, Vec::<String>::new());
        assert_eq!(resolve("e*").names, vec!["ee"]);
        assert_eq!(resolve("nope").unknown, vec!["nope"]);
        assert!(resolve("nope").names.is_empty());
        // Known, but not in the default: removal is a no-op and not a warning.
        assert!(resolve("-d").unknown.is_empty());
        assert_eq!(resolve("-d").names, vec!["a", "b", "c"]);
        assert!(parse_algo_directive("+").is_none());
        assert!(parse_algo_directive("").is_none());
    }

    #[test]
    fn rekey_limit_suffixes_and_sentinels() {
        let limit = parse_rekey_limit("512M").unwrap();
        assert_eq!(limit.bytes, 512 * 1024 * 1024);
        assert_eq!(limit.time, REKEY_DEFAULT_TIME);
        assert!(!limit.bytes_clamped);

        let limit = parse_rekey_limit("2G 30m").unwrap();
        assert_eq!(limit.bytes, REKEY_MAX_BYTES);
        assert!(limit.bytes_clamped);
        assert_eq!(limit.time, Duration::from_secs(1800));

        let limit = parse_rekey_limit("default none").unwrap();
        assert_eq!(limit.bytes, REKEY_MAX_BYTES);
        assert!(!limit.bytes_clamped);
        assert_eq!(limit.time, REKEY_DEFAULT_TIME);

        let limit = parse_rekey_limit("none 1h30m").unwrap();
        assert_eq!(limit.bytes, REKEY_MAX_BYTES);
        assert_eq!(limit.time, Duration::from_secs(5400));

        let limit = parse_rekey_limit("1.5M 90").unwrap();
        assert_eq!(limit.bytes, (1.5 * 1024.0 * 1024.0) as usize);
        assert_eq!(limit.time, Duration::from_secs(90));

        assert!(parse_rekey_limit("").is_none());
        assert!(parse_rekey_limit("0").is_none());
        assert!(parse_rekey_limit("512M later").is_none());
        assert!(parse_rekey_limit("512M 1h30").is_none());
    }
}
