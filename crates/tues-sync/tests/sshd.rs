//! Blocking-API integration tests against the Docker sshd fixture.

use std::io::{Read, Write};
use std::time::Duration;

use tues_core::{
    CommandUser, Error, OpenOptions, PtyConfig, StaticPasswordManager, Stdio, SudoError, shared,
};
use tues_sync::Session;
use tues_testsupport::{PASSWORD, USER, require_sudo, sshd};

fn connect() -> Session {
    Session::connect(sshd().connect_options()).expect("connect")
}

#[test]
fn simple_exec_and_close() {
    let s = connect();
    let out = s.command("id").arg("-un").output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout_lossy().trim(), USER);
    s.close().unwrap();
    assert!(s.is_closed());
}

#[test]
fn stdio_pipes_are_blocking_readers_and_writers() {
    let s = connect();
    let mut child = s.command("cat").spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin.write_all(b"one\ntwo\n").unwrap();
    stdin.close().unwrap();
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "one\ntwo\n");
    assert!(child.wait().unwrap().success());
}

#[test]
fn sudo_conversation_is_hidden_and_stdin_is_gated() {
    require_sudo!();
    let s = connect();
    let mut child = s.command("cat").user("root").spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&[0u8, 1, 2, 3, 255]).unwrap();
    stdin.write_all(PASSWORD.as_bytes()).unwrap();
    drop(stdin); // EOF
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let mut expected = vec![0u8, 1, 2, 3, 255];
    expected.extend_from_slice(PASSWORD.as_bytes());
    assert_eq!(out.stdout, expected);
    assert!(out.stderr.is_empty());
}

#[test]
fn sudo_with_pty_sync() {
    require_sudo!();
    let s = connect();
    let out = s
        .command("id")
        .arg("-un")
        .user("root")
        .pty(true)
        .output()
        .unwrap();
    assert_eq!(out.stdout_lossy(), "root\r\n");
}

#[test]
fn sudo_failure_is_reported() {
    require_sudo!();
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(StaticPasswordManager::new("bad")));
    let s = Session::connect(o).unwrap();
    let err = s.command("id").user("root").output().err().unwrap();
    assert!(
        matches!(err, Error::Sudo(SudoError::AuthFailed { .. })),
        "{err}"
    );
}

#[test]
fn kill_and_try_wait() {
    let s = connect();
    let mut child = s.command("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    let st = child.wait().unwrap();
    assert!(!st.success());
}

#[test]
fn wait_timeout_and_signal_from_another_thread() {
    let s = connect();
    let mut child = s.command("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child
            .wait_timeout(Duration::from_millis(200))
            .unwrap()
            .is_none()
    );
    let signaller = child.signaller();
    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        signaller.signal("TERM").unwrap();
    });
    // Blocks in wait() while the other thread signals.
    let st = child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .expect("exited");
    assert_eq!(st.signal(), Some("TERM"), "{st:?}");
    killer.join().unwrap();
}

#[test]
fn child_handles_debug_flush_id_and_signal_by_name() {
    let s = connect();
    let mut child = s
        .command("sh")
        .arg("-c")
        .arg("cat; echo done >&2")
        .stderr(Stdio::Piped)
        .spawn()
        .unwrap();
    assert!(child.id().is_none());
    assert!(format!("{child:?}").contains("Child"));
    assert_eq!(format!("{:?}", child.stdin.as_ref().unwrap()), "ChildStdin");
    assert_eq!(
        format!("{:?}", child.stdout.as_ref().unwrap()),
        "ChildStdout"
    );
    assert_eq!(
        format!("{:?}", child.stderr.as_ref().unwrap()),
        "ChildStderr"
    );
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"ping").unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"ping");
    assert_eq!(out.stderr, b"done\n");

    let mut child = s.command("sleep").arg("30").spawn().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    child.signal("TERM").unwrap();
    let st = child.wait().unwrap();
    assert_eq!(st.signal(), Some("TERM"), "{st:?}");
}

#[test]
fn session_file_helpers() {
    let s = connect();
    let id = std::process::id();
    let local = std::env::temp_dir().join(format!("tues-sync-up-{id}"));
    let down = std::env::temp_dir().join(format!("tues-sync-down-{id}"));
    std::fs::write(&local, b"sync").unwrap();
    let remote = format!("/tmp/tues-sync-file-{id}");
    s.upload(&local, &remote).unwrap();
    assert_eq!(s.stat(&remote).unwrap().len(), 4);
    s.download(&remote, &down).unwrap();
    assert_eq!(std::fs::read(&down).unwrap(), b"sync");
    let renamed = format!("{remote}.2");
    s.rename(&remote, &renamed).unwrap();
    let explicit = s.sftp().unwrap();
    explicit.close().unwrap();
    s.delete(&renamed).unwrap();
    assert!(s.stat(&renamed).is_err());
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&down);
}

#[test]
fn sftp_blocking_file_io() {
    let s = connect();
    let sftp = s.sftp().unwrap();
    let path = format!("/tmp/tues-sync-{}.txt", std::process::id());
    let _ = sftp.remove_file(&path);
    {
        let mut f = sftp.create(&path).unwrap();
        f.write_all(b"hello ").unwrap();
        f.write_all(b"world").unwrap();
        f.close().unwrap();
    }
    assert_eq!(sftp.read_to_string(&path).unwrap(), "hello world");
    {
        let mut f = sftp
            .open_with(&path, OpenOptions::new().read(true).write(true))
            .unwrap();
        f.seek(std::io::SeekFrom::Start(6)).unwrap();
        f.write_all(b"WORLD").unwrap();
        f.close().unwrap();
    }
    let mut f = sftp.open(&path).unwrap();
    let mut buf = String::new();
    f.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "hello WORLD");
    assert_eq!(sftp.metadata(&path).unwrap().len(), 11);
    sftp.remove_file(&path).unwrap();
    assert!(!sftp.try_exists(&path).unwrap());
}

#[test]
fn sessions_are_usable_from_multiple_threads() {
    require_sudo!();
    let s = connect();
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let s = s.clone();
            std::thread::spawn(move || s.shell(format!("echo {i}")).user("root").output().unwrap())
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        assert_eq!(h.join().unwrap().stdout_lossy(), format!("{i}\n"));
    }
}

#[test]
fn command_builder_reaches_the_remote_shell() {
    let s = connect();
    let built = s
        .command("sh")
        .arg("-c")
        .args(["printf %s \"$KEEP:$(pwd)\""])
        .env("OLD", "x")
        .env_remove("DROP")
        .env_clear()
        .envs([("KEEP", "yes")])
        .current_dir("/tmp")
        .stdin(Stdio::Null)
        .stdout(Stdio::Piped)
        .stderr(Stdio::Null)
        .pty(true)
        .pty_config(PtyConfig {
            term: "dumb".into(),
            cols: 20,
            rows: 5,
            universal_newlines: true,
        })
        .user("root")
        .as_login_user();
    let _ = format!("{built:?}");
    assert_eq!(built.as_inner().get_program(), "sh");
    assert_eq!(built.as_inner().get_current_dir(), Some("/tmp"));
    let inner = built.clone().into_inner();
    assert!(matches!(inner.get_user(), CommandUser::LoginUser));
    assert_eq!(inner.get_pty().map(|p| p.term.as_str()), Some("dumb"));
    let out = built.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout_lossy().contains("yes:/tmp"), "{out:?}");
    let status = s.command("true").stdin(Stdio::Inherit).status().unwrap();
    assert!(status.success());
}

use std::io::Seek;
