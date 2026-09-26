//! Blocking-API integration tests against the Docker sshd fixture.

use std::io::{Read, Write};
use std::time::Duration;

use tues_core::{Error, OpenOptions, SudoError, StaticPasswordManager, shared};
use tues_sync::Session;
use tues_testsupport::{PASSWORD, USER, sshd};

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
    let s = connect();
    let mut child = s.command("cat").run_as("root").spawn().unwrap();
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
    let s = connect();
    let out = s.command("id").arg("-un").run_as("root").pty(true).output().unwrap();
    assert_eq!(out.stdout_lossy(), "root\r\n");
}

#[test]
fn sudo_failure_is_reported() {
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(StaticPasswordManager::new("bad")));
    let s = Session::connect(o).unwrap();
    let err = s.command("id").run_as("root").output().err().unwrap();
    assert!(matches!(err, Error::Sudo(SudoError::AuthFailed { .. })), "{err}");
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
    let s = connect();
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let s = s.clone();
            std::thread::spawn(move || s.shell(format!("echo {i}")).run_as("root").output().unwrap())
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        assert_eq!(h.join().unwrap().stdout_lossy(), format!("{i}\n"));
    }
}

use std::io::Seek;
