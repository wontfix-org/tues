//! POSIX shell quoting.

use std::borrow::Cow;

fn is_safe(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '-' | '.' | '/' | '=' | ':' | '@' | '%' | '+' | ',')
}

/// Quote a single word for a POSIX shell.
///
/// Words consisting only of safe characters are returned unchanged. Anything
/// else is wrapped in single quotes, with embedded single quotes spliced as
/// `'\''`.
pub fn quote(word: &str) -> Cow<'_, str> {
    if !word.is_empty() && word.chars().all(is_safe) {
        return Cow::Borrowed(word);
    }
    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');
    for c in word.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Cow::Owned(out)
}

/// Quote and join words into one command line.
pub fn join<I, S>(words: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::new();
    for w in words {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&quote(w.as_ref()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_words_are_untouched() {
        assert_eq!(quote("ls"), "ls");
        assert_eq!(quote("/usr/bin/env"), "/usr/bin/env");
        assert_eq!(quote("A=b"), "A=b");
    }

    #[test]
    fn unsafe_words_are_single_quoted() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote("$HOME"), "'$HOME'");
        assert_eq!(quote("a\nb"), "'a\nb'");
    }

    #[test]
    fn join_quotes_each_word() {
        assert_eq!(join(["echo", "hello world", "x"]), "echo 'hello world' x");
    }
}
