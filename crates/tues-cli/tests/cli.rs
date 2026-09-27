//! End-to-end tests of the `tues` binary against the Docker sshd fixture.

use std::process::Command;

use tues_testsupport::{PASSWORD, USER, sshd};

fn tues() -> Command {
    let f = sshd();
    let mut c = Command::new(env!("CARGO_BIN_EXE_tues"));
    c.arg("--no-ssh-config")
        .arg("--host-key-check")
        .arg("off")
        .arg("-p")
        .arg(f.port.to_string())
        .arg("-i")
        .arg(&f.key_path)
        .arg("-l")
        .arg(USER)
        .env("TUES_TEST_PW", PASSWORD)
        .arg("--password-env")
        .arg("TUES_TEST_PW");
    c
}

#[test]
fn single_host_streams_raw_output_and_exit_code() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("echo hello; echo oops >&2; exit 3")
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "oops\n");
}

#[test]
fn multiple_hosts_with_sudo_and_prefixes() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("-j")
        .arg("2")
        .arg("-u")
        .arg("root")
        .arg("id -un")
        .arg(&f.host)
        .arg(format!("{}@{}", USER, f.host))
        .arg(format!("{}:{}", f.host, f.port))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort();
    assert_eq!(
        lines,
        vec![
            format!("{}: root", f.host),
            format!("{}:{}: root", f.host, f.port),
            format!("{}@{}: root", USER, f.host),
        ]
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn failing_host_yields_nonzero_exit() {
    let f = sshd();
    let out = tues()
        .arg("exit 4")
        .arg(&f.host)
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn unreachable_hosts_report_errors_and_ipv6_ports_are_parsed() {
    let f = sshd();
    // `host:port` in the server list beats the global `-p`; port 1 is
    // closed, so both entries must fail with a connection error while the
    // fixture host still succeeds.
    let out = tues()
        .arg("--connect-timeout")
        .arg("2")
        .arg("true")
        .arg(&f.host)
        .arg("127.0.0.1:1")
        .arg("[::1]:1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("127.0.0.1:1: error: could not connect to 127.0.0.1:1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("[::1]:1: error: could not connect to ::1:1"),
        "{stderr}"
    );
    assert!(!stderr.contains(&format!("{}: error", f.host)), "{stderr}");
}

#[test]
fn check_stops_after_the_first_failure() {
    let f = sshd();
    let out = tues()
        .arg("--check")
        .arg("--connect-timeout")
        .arg("2")
        .arg("exit 4")
        .arg(&f.host)
        .arg("127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("127.0.0.1"),
        "later host must not be started: {stderr}"
    );
}

#[test]
fn check_rejects_more_than_one_job() {
    let f = sshd();
    let out = tues()
        .arg("--check")
        .arg("-j")
        .arg("2")
        .arg("true")
        .arg(&f.host)
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--check only works with one job at a time"),
        "{stderr}"
    );
}

#[test]
fn wrong_sudo_password_is_an_error() {
    let f = sshd();
    let out = tues()
        .env("TUES_TEST_PW", "wrong")
        .arg("-u")
        .arg("root")
        .arg("id")
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sudo rejected the password"), "{stderr}");
}

#[test]
fn pty_is_the_default_with_sudo() {
    let f = sshd();
    let out = tues()
        .arg("-u")
        .arg("root")
        .arg("id -un")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "root\r\n");
}
