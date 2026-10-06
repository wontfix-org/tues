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
        .env("TUES_PW", PASSWORD);
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
fn prefix_forces_labels_on_a_single_host() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("--prefix")
        .arg("echo hello; echo oops >&2")
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
        format!("[{}/stdout]: hello\n", f.host)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("[{}/stderr]: oops\n", f.host)
    );
}

#[test]
fn multiple_hosts_with_sudo_and_prefixes() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("-n")
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
            format!("[{}/stdout]: root", f.host),
            format!("[{}:{}/stdout]: root", f.host, f.port),
            format!("[{}@{}/stdout]: root", USER, f.host),
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
        .arg("-n")
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
    // Mapped onto an existing directory: lands inside it, like `cp`.
    let into_dir = format!("tues-cli-into-dir-{id}");
    std::fs::write(dir.join(&into_dir), b"indir").unwrap();

    let out = tues()
        .arg("--no-pty")
        .arg("--file")
        .arg(dir.join("tree"))
        .arg("--file")
        .arg(dir.join("a\\:b"))
        .arg("--file")
        .arg(format!("{}:{kept}", dir.join("kept").display()))
        .arg("--file")
        .arg(format!("{}:/tmp/", dir.join(&into_dir).display()))
        .arg(format!(
            "cat tree/sub/x.txt a:b {kept} /tmp/{into_dir}; pwd"
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
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("treecolonkeptindir/home/{USER}\n")
    );

    // Temporary uploads are gone; the mapped ones stay.
    let out = tues()
        .arg("--no-pty")
        .arg(format!(
            "test ! -e tree && test ! -e a:b && cat {kept} && rm {kept} /tmp/{into_dir}"
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
fn removing_a_temporary_upload_yourself_is_only_a_warning() {
    let f = sshd();
    let id = std::process::id();
    let dir = std::env::temp_dir().join(format!("tues-cli-selfrm-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let name = format!("tues-cli-selfrm-{id}.txt");
    std::fs::write(dir.join(&name), b"x").unwrap();
    let out = tues()
        .arg("--no-pty")
        .arg("--file")
        .arg(dir.join(&name))
        .arg(format!("rm {name} && echo gone"))
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "gone\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("{}: warning: could not remove {name}", f.host)),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prefixed_output_completes_partial_last_lines() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("-n")
        .arg("2")
        .arg("printf 'a\\nb'; printf 'e' >&2")
        .arg("cl")
        .arg(&f.host)
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
    let second = format!("{}:{}", f.host, f.port);
    assert_eq!(
        lines,
        vec![
            format!("[{}/stdout]: a", f.host),
            format!("[{}/stdout]: b", f.host),
            format!("[{second}/stdout]: a"),
            format!("[{second}/stdout]: b"),
        ]
    );
    assert!(stdout.ends_with('\n'), "{stdout:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut lines: Vec<&str> = stderr.lines().collect();
    lines.sort();
    assert_eq!(
        lines,
        vec![
            format!("[{}/stderr]: e", f.host),
            format!("[{second}/stderr]: e")
        ]
    );
}

#[test]
fn prefix_format_interpolates_connection_fields() {
    let f = sshd();
    let out = tues()
        .arg("--no-pty")
        .arg("--prefix-format")
        .arg("<name>|<server-ip>|<server-port>|<client-port>|<stream>|")
        .arg("printf out; printf err >&2")
        .arg("cl")
        .arg(&f.host)
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
    assert_eq!(lines.len(), 2, "{stdout:?}");
    let named = format!("{}:{}", f.host, f.port);
    for line in &lines {
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(parts.len(), 6, "{line}");
        assert!(parts[0] == f.host || parts[0] == named, "{line}");
        assert_eq!(parts[1], f.host);
        assert_eq!(parts[2], f.port.to_string());
        assert!(parts[3].parse::<u16>().is_ok(), "client port: {}", parts[3]);
        assert_eq!(parts[4], "stdout");
        assert_eq!(parts[5], "out");
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut lines: Vec<&str> = stderr.lines().collect();
    lines.sort();
    assert_eq!(lines.len(), 2, "{stderr:?}");
    for line in &lines {
        assert!(line.ends_with("|stderr|err"), "{line}");
    }
}

#[test]
fn verbose_reports_the_status_of_each_failed_host() {
    let f = sshd();
    let out = tues()
        .arg("-v")
        .arg("exit 4")
        .arg("cl")
        .arg(&f.host)
        .arg(&f.host)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|l| *l == format!("{}: exit status: 4", f.host))
            .count(),
        2,
        "{stderr}"
    );
}

#[test]
fn ssh_config_file_and_known_hosts_options_reach_the_connection() {
    let f = sshd();
    let id = std::process::id();
    let dir = std::env::temp_dir().join(format!("tues-cli-cfg-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let alias = format!("tues-cfg-alias-{id}");
    let config = dir.join("ssh_config");
    std::fs::write(
        &config,
        format!(
            "Host {alias}\n  HostName {}\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
            f.host,
            f.port,
            USER,
            f.key_path.display()
        ),
    )
    .unwrap();
    let known_hosts = dir.join("known_hosts");

    let run = |policy: &str, kh: &std::path::Path| {
        tues_bin()
            .env("TUES_PW", PASSWORD)
            .arg("-F")
            .arg(&config)
            .arg("--known-hosts")
            .arg(kh)
            .arg("--host-key-check")
            .arg(policy)
            .arg("--no-pty")
            .arg("echo via-config")
            .arg("cl")
            .arg(&alias)
            .output()
            .unwrap()
    };

    // Unknown key: strict refuses, accept-new learns it, then strict is happy.
    let out = run("strict", &known_hosts);
    assert_eq!(out.status.code(), Some(255));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("{alias}: error:")), "{stderr}");

    let out = run("accept-new", &known_hosts);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "via-config\n");
    let learned = std::fs::read_to_string(&known_hosts).unwrap();
    assert!(
        learned.contains(&format!("[{}]:{}", f.host, f.port)),
        "{learned}"
    );

    let out = run("strict", &known_hosts);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "via-config\n");
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
        .env("TUES_PW", "wrong")
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
fn sudo_runs_without_a_pty_unless_requested() {
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
    assert_eq!(String::from_utf8_lossy(&out.stdout), "root\n");

    let out = tues()
        .arg("--pty")
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
    let mut c = Command::new(env!("CARGO_BIN_EXE_tues"));
    c.env_remove("TUES_PW");
    c
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
    assert_eq!(
        stdout,
        format!("[{0}/stdout]: ok\n[{0}/stdout]: ok\n", f.host)
    );
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
fn unknown_options_are_not_taken_as_command_or_provider() {
    // clap would otherwise fold an unknown flag into trailing_var_arg and look
    // for tues-provider--q (or similar).
    let out = tues_bin()
        .args(["-Q", "-p", "-s", "kick-wait", "cl", "h"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument '-Q'"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("tues-provider-"),
        "must not invent a provider from the unknown option: {stderr}"
    );

    let out = tues_bin().args(["true", "-Z", "host"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument '-Z'"),
        "{stderr}"
    );

    let dir = std::env::temp_dir().join(format!("tues-cli-unknown-opt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("tool");
    std::fs::write(&script, "#!/bin/sh\n").unwrap();
    let out = tues_bin()
        .args([
            "-s",
            script.to_str().unwrap(),
            "--not-a-flag",
            "cl",
            "h",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument '--not-a-flag'"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
fn empty_host_lists_are_errors() {
    for args in [
        vec!["true", "cl"],
        vec!["true", "cl", "", ""],
        vec!["-v", "true", "cl"],
        vec!["-vv", "true", "cl"],
        vec!["-vvv", "true", "cl"],
    ] {
        let out = tues_bin().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Error: no hosts"), "{args:?}: {stderr}");
    }

    let out = tues_bin().arg("true").arg("file").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("file provider requires at least one file"),
        "{stderr}"
    );
}

#[test]
fn tues_pw_must_be_unicode() {
    use std::os::unix::ffi::OsStrExt;

    let out = tues_bin()
        .env("TUES_PW", std::ffi::OsStr::from_bytes(b"\xff\xfe"))
        .arg("true")
        .arg("cl")
        .arg("h")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TUES_PW is not valid Unicode"), "{stderr}");
}

#[test]
fn external_provider_output_is_validated() {
    let dir = std::env::temp_dir().join(format!("tues-cli-provider-odd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_provider(&dir, "empty", "#!/bin/sh\nprintf '\\n  \\n'\n");
    write_provider(&dir, "binary", "#!/bin/sh\nprintf 'h\\377\\n'\n");
    write_provider(&dir, "killed", "#!/bin/sh\nkill -9 $$\n");

    let out = tues_bin()
        .env("PATH", path_with(&dir))
        .arg("true")
        .arg("empty")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tues-provider-empty produced no hosts"),
        "{stderr}"
    );

    let out = tues_bin()
        .env("PATH", path_with(&dir))
        .arg("true")
        .arg("binary")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tues-provider-binary wrote hosts that are not utf-8"),
        "{stderr}"
    );

    let out = tues_bin()
        .env("PATH", path_with(&dir))
        .arg("true")
        .arg("killed")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tues-provider-killed was terminated by a signal"),
        "{stderr}"
    );
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
        dir.join("who-defaults"),
        "#!/bin/sh\n# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": false}\nid -un\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who-defaults")
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
        dir.join("who-defaults"),
        "#!/bin/sh\n# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": true}\nid -un\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who-defaults")
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
        format!("[{}/stdout]: root\n", f.host)
    );

    std::fs::write(
        dir.join("who-defaults"),
        "#!/bin/sh\n# tues-args = {\"user\": \"root\", \"pty\": false, \"prefix\": true, \"prefix-format\": \"<name>/<stream>|\"}\nid -un\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who-defaults")
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
        format!("{}/stdout|root\n", f.host)
    );

    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-u")
        .arg(USER)
        .arg("--pty")
        .arg("--no-prefix")
        .arg("--prefix-format")
        .arg("[<name>/<stream>]: ")
        .arg("-s")
        .arg("who-defaults")
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
        dir.join("who-late"),
        "#!/bin/sh\nid -un\n# tues-args = {\"user\": \"root\", \"pty\": false}\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("who-late")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{USER}\n"));
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

    std::fs::write(dir.join("bad-provider"), "# tues-provider = nope\n").unwrap();
    let out = tues_bin()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("bad-provider")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid tues-provider JSON"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn script_header_provider_supplies_hosts_until_the_command_line_overrides_it() {
    let f = sshd();
    let dir = script_dir("provider");
    let providers = dir.join("bin");
    write_provider(&providers, "echo", "#!/bin/sh\nprintf '%s\\n' \"$@\"\n");
    std::fs::write(
        dir.join("from-header"),
        format!(
            "#!/bin/sh\n# tues-provider = \"echo\"\n# tues-provider-args = [\"{}\"]\necho from-header\n",
            f.host
        ),
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .env("PATH", path_with(&providers))
        .arg("-s")
        .arg("from-header")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-header\n");

    std::fs::write(
        dir.join("from-cli"),
        "#!/bin/sh\n# tues-provider = \"cl\"\n# tues-provider-args = [\"no-such-host.invalid\"]\necho from-cli\n",
    )
    .unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("from-cli")
        .arg("cl")
        .arg(&f.host)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-cli\n");

    std::fs::write(dir.join("bare"), "#!/bin/sh\necho hi\n").unwrap();
    let out = tues()
        .env("TUES_PATH", &dir)
        .arg("-s")
        .arg("bare")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("or set tues-provider in the script header"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sort_hosts_runs_in_alphabetical_order() {
    fn run(sort: bool) -> String {
        let mut cmd = tues_bin();
        cmd.arg("--show-hosts")
            .arg("--check")
            .arg("--no-ssh-config")
            .arg("--host-key-check")
            .arg("off")
            .arg("--connect-timeout")
            .arg("1");
        if sort {
            cmd.arg("--sort-hosts");
        }
        let out = cmd
            .arg("true")
            .arg("cl")
            .arg("b.invalid")
            .arg("a.invalid")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    let unsorted = run(false);
    assert!(
        unsorted.starts_with("2 hosts:\nb.invalid\na.invalid\n"),
        "{unsorted}"
    );
    assert!(unsorted.contains("b.invalid: error:"), "{unsorted}");
    assert!(!unsorted.contains("a.invalid: error:"), "{unsorted}");

    let sorted = run(true);
    assert!(
        sorted.starts_with("2 hosts:\na.invalid\nb.invalid\n"),
        "{sorted}"
    );
    assert!(sorted.contains("a.invalid: error:"), "{sorted}");
    assert!(!sorted.contains("b.invalid: error:"), "{sorted}");
}
