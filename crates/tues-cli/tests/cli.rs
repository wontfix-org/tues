//! End-to-end tests of the `tues` binary against the Docker sshd fixture.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use tues_testsupport::{PASSWORD, USER, sshd};

fn tues() -> Command {
    let f = sshd();
    let mut c = Command::new(env!("CARGO_BIN_EXE_tues"));
    c.arg("--no-ssh-config")
        .arg("--host-key-check")
        .arg("off")
        .arg("--port")
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
        .arg("cl")
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
        .arg("cl")
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
        .arg("cl")
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
        .arg("cl")
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
        .arg("cl")
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
        .arg("cl")
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
fn file_uploads_are_temporary_unless_mapped() {
    let f = sshd();
    let id = std::process::id();
    let dir = std::env::temp_dir().join(format!("tues-cli-files-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tree").join("sub")).unwrap();
    std::fs::write(dir.join("tree").join("sub").join("x.txt"), b"tree").unwrap();
    std::fs::write(dir.join("a:b"), b"colon").unwrap();
    std::fs::write(dir.join("kept"), b"kept").unwrap();
    let kept = format!("/tmp/tues-cli-kept-{id}");

    let out = tues()
        .arg("--no-pty")
        .arg("--file")
        .arg(dir.join("tree"))
        .arg("--file")
        .arg(dir.join("a\\:b"))
        .arg("--file")
        .arg(format!("{}:{kept}", dir.join("kept").display()))
        .arg(format!("cat tree/sub/x.txt a:b {kept}; pwd"))
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("treecolonkept/home/{USER}\n")
    );

    // Temporary uploads are gone; the mapped one stays.
    let out = tues()
        .arg("--no-pty")
        .arg(format!(
            "test ! -e tree && test ! -e a:b && cat {kept} && rm {kept}"
        ))
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "kept");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_file_upload_fails_before_the_command() {
    let f = sshd();
    let out = tues()
        .arg("--file")
        .arg("/nonexistent/tues-file")
        .arg("echo ran")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("upload /nonexistent/tues-file"), "{stderr}");
}

#[test]
fn wrong_sudo_password_is_an_error() {
    let f = sshd();
    let out = tues()
        .env("TUES_TEST_PW", "wrong")
        .arg("-u")
        .arg("root")
        .arg("id")
        .arg("cl")
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
        .arg("cl")
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

fn tues_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tues"))
}

fn write_provider(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(format!("tues-provider-{name}"));
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn path_with(dir: &std::path::Path) -> std::ffi::OsString {
    let mut path = std::ffi::OsString::from(dir);
    if let Some(rest) = std::env::var_os("PATH") {
        path.push(":");
        path.push(rest);
    }
    path
}

#[test]
fn file_provider_reads_files_and_stdin_and_show_hosts_prints_them() {
    let f = sshd();
    let dir = std::env::temp_dir().join(format!("tues-cli-hosts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("hosts");
    std::fs::write(&list, format!("\n{}\n\n", f.host)).unwrap();

    let mut child = tues()
        .arg("--show-hosts")
        .arg("--no-pty")
        .arg("echo ok")
        .arg("file")
        .arg(&list)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{}\n", f.host).as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout, format!("{}: ok\n{}: ok\n", f.host, f.host));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with(&format!("2 hosts:\n{}\n{}\n", f.host, f.host)),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_provider_and_host_file_are_errors() {
    let out = tues_bin().arg("true").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("a provider is required after the command"),
        "{stderr}"
    );

    let out = tues_bin()
        .arg("true")
        .arg("file")
        .arg("/nonexistent/tues-hosts")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reading hosts from /nonexistent/tues-hosts"),
        "{stderr}"
    );

    let out = tues_bin()
        .arg("true")
        .arg("file")
        .arg("-")
        .arg("-")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("stdin can only be used once"), "{stderr}");

    let out = tues_bin().arg("true").arg("a/b").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a provider name: a/b"), "{stderr}");

    let out = tues_bin().arg("true").arg("nosuch").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no provider executable tues-provider-nosuch on PATH"),
        "{stderr}"
    );
}

#[test]
fn external_provider_supplies_hosts_and_receives_its_options() {
    let f = sshd();
    let dir = std::env::temp_dir().join(format!("tues-cli-provider-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_provider(
        &dir,
        "inv",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TUES_PROVIDER_LOG\"\nprintf '%s\\n' \"$TUES_TEST_HOST\"\n",
    );
    let log = dir.join("args");
    let out = tues()
        .env("PATH", path_with(&dir))
        .env("TUES_PROVIDER_LOG", &log)
        .env("TUES_TEST_HOST", &f.host)
        .arg("--show-hosts")
        .arg("--no-pty")
        .arg("echo from-provider")
        .arg("inv")
        .arg("--site")
        .arg("nyc")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-provider\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with(&format!("1 host:\n{}\n", f.host)),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "--site\nnyc\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn external_provider_failure_is_reported() {
    let dir = std::env::temp_dir().join(format!("tues-cli-provider-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_provider(&dir, "inv", "#!/bin/sh\necho provider broke >&2\nexit 4\n");
    let out = tues_bin()
        .env("PATH", path_with(&dir))
        .arg("true")
        .arg("inv")
        .arg("--x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("provider broke"), "{stderr}");
    assert!(
        stderr.contains("tues-provider-inv exited with 4"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn script_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tues-cli-script-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn script_is_uploaded_with_its_arguments_and_removed() {
    let f = sshd();
    let dir = script_dir("run");
    let name = format!("tues-scr-{}", std::process::id());
    std::fs::write(
        dir.join(&name),
        "#!/bin/sh\n# tues-args = {\"pty\": false}\nprintf '%s\\n' \"$@\"\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("--script")
        .arg(format!("{name} --my-option 'a b'"))
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "--my-option\na b\n");

    let out = tues()
        .arg("--no-pty")
        .arg(format!("test ! -e {name}"))
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn script_header_supplies_defaults_until_the_command_line_overrides_them() {
    let f = sshd();
    let dir = script_dir("defaults");
    std::fs::write(
        dir.join("who"),
        "#!/bin/sh\n# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": false}\nid -un\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who")
        .arg("cl")
        .arg(&f.host)
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "root\nroot\n");

    std::fs::write(
        dir.join("who"),
        "#!/bin/sh\n# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": true}\nid -un\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}: root\n", f.host)
    );

    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-u")
        .arg(USER)
        .arg("--pty")
        .arg("--no-prefix")
        .arg("-s")
        .arg("who")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{USER}\r\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn script_header_below_code_is_ignored() {
    let f = sshd();
    let dir = script_dir("late");
    std::fs::write(
        dir.join("who"),
        "#!/bin/sh\nid -un\n# tues-args = {\"user\": \"root\", \"pty\": false}\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{USER}\r\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_or_invalid_script_is_an_error() {
    let out = tues_bin()
        .env_remove("TUES_PATH")
        .arg("-s")
        .arg("nope")
        .arg("cl")
        .arg("h")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TUES_PATH is not set"), "{stderr}");

    let dir = script_dir("missing");
    let out = tues_bin()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("nope")
        .arg("cl")
        .arg("h")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nope: not found on TUES_PATH"), "{stderr}");

    std::fs::write(dir.join("bad"), "# tues-args = {nope}\n").unwrap();
    let out = tues_bin()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("bad")
        .arg("cl")
        .arg("h")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid tues-args JSON"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
