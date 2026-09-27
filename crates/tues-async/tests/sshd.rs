//! Integration tests against the Docker sshd fixture.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tues_async::Session;
use tues_core::password::{PasswordManager, PasswordRequest};
use tues_core::{
    ConnectOptions, Error, HostKeyPolicy, MemoizingPasswordManager, OpenOptions, SecretString,
    SshConfig, SshConfigSource, StaticPasswordManager, Stdio, SudoError, shared,
};
use tues_testsupport::{NOPASSWD_USER, PASSWORD, USER, sshd};

async fn connect() -> Session {
    Session::connect(sshd().connect_options())
        .await
        .expect("connect")
}

#[tokio::test]
async fn pubkey_auth_and_simple_exec() {
    let s = connect().await;
    let out = s.command("id").arg("-un").output().await.unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout_lossy().trim(), USER);
    assert!(out.stderr.is_empty());
    s.close().await.unwrap();
}

#[tokio::test]
async fn password_auth() {
    let mut o = sshd().connect_options();
    o.identity_files.clear();
    o.pubkey_authentication = Some(false);
    let s = Session::connect(o).await.expect("password auth");
    let out = s.command("true").output().await.unwrap();
    assert!(out.status.success());
}

#[tokio::test]
async fn wrong_password_fails_auth() {
    let mut o = sshd().connect_options();
    o.identity_files.clear();
    o.pubkey_authentication = Some(false);
    o.password_manager = Some(shared(StaticPasswordManager::new("nope")));
    let err = Session::connect(o).await.expect_err("must fail");
    assert!(matches!(err, Error::Auth { .. }), "{err}");
}

#[tokio::test]
async fn stderr_and_exit_status() {
    let s = connect().await;
    let out = s
        .shell("echo out; echo err 1>&2; exit 7")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
}

#[tokio::test]
async fn env_and_cwd() {
    let s = connect().await;
    let out = s
        .shell("echo \"$FOO\" && pwd")
        .env("FOO", "bar baz")
        .current_dir("/tmp")
        .output()
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), "bar baz\n/tmp\n");
}

#[tokio::test]
async fn stdin_is_forwarded() {
    let s = connect().await;
    let mut child = s.command("cat").spawn().await.unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"hello\nworld\n").await.unwrap();
    stdin.close().await.unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert_eq!(out.stdout, b"hello\nworld\n");
}

#[tokio::test]
async fn large_binary_roundtrip() {
    let s = connect().await;
    let data: Vec<u8> = (0..2_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut child = s.command("cat").spawn().await.unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let payload = data.clone();
    let writer = tokio::spawn(async move {
        stdin.write_all(&payload).await.unwrap();
        stdin.close().await.unwrap();
    });
    let out = child.wait_with_output().await.unwrap();
    writer.await.unwrap();
    assert_eq!(out.stdout.len(), data.len());
    assert!(out.stdout == data);
}

#[tokio::test]
async fn sudo_with_password_removes_conversation() {
    let s = connect().await;
    let out = s
        .command("id")
        .arg("-un")
        .user("root")
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout_lossy(), "root\n");
    assert_eq!(out.stderr_lossy(), "", "stderr must not contain the prompt");
}

#[tokio::test]
async fn sudo_binary_stdout_containing_nonces_is_intact() {
    let s = connect().await;
    // Generate a payload that includes the literal prompt/marker prefixes and
    // the password, plus every byte value.
    let script = format!(
        "printf '[tues-sudo-'; printf '[tues-ok-'; printf '%s' '{PASSWORD}'; printf 'Sorry, try again.\\n'; head -c 300000 /dev/urandom; for i in $(seq 0 255); do printf \"\\\\$(printf %03o $i)\"; done"
    );
    let out = s.shell(&script).user("root").output().await.unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        out.stdout
            .starts_with(b"[tues-sudo-[tues-ok-tuespassSorry, try again.\n")
    );
    assert_eq!(
        out.stdout.len(),
        "[tues-sudo-[tues-ok-tuespassSorry, try again.\n".len() + 300000 + 256
    );
    let tail = &out.stdout[out.stdout.len() - 256..];
    let expected: Vec<u8> = (0..=255u8).collect();
    assert_eq!(tail, &expected[..]);
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr_lossy());
}

#[tokio::test]
async fn sudo_stdin_is_delivered_after_password() {
    let s = connect().await;
    let mut child = s.command("cat").user("root").spawn().await.unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Written before sudo has asked for anything: must not be eaten as the password.
    stdin.write_all(b"payload line\n").await.unwrap();
    stdin.close().await.unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"payload line\n");
}

/// Prompter that returns a wrong password first, then the right one, and
/// counts calls.
struct FlakyPrompter {
    calls: Arc<Mutex<Vec<PasswordRequest>>>,
}

impl tues_core::PasswordPrompter for FlakyPrompter {
    fn prompt(&mut self, req: &PasswordRequest) -> tues_core::Result<SecretString> {
        let mut calls = self.calls.lock().unwrap();
        calls.push(req.clone());
        Ok(SecretString::from(if calls.len() == 1 {
            "wrong"
        } else {
            PASSWORD
        }))
    }
}

#[tokio::test]
async fn sudo_wrong_password_is_invalidated_and_retried() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pm = shared(MemoizingPasswordManager::new(FlakyPrompter {
        calls: calls.clone(),
    }));
    let mut o = sshd().connect_options();
    o.password_manager = Some(pm);
    let s = Session::connect(o).await.unwrap();
    let out = s
        .command("id")
        .arg("-un")
        .user("root")
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout_lossy(), "root\n");
    assert_eq!(out.stderr_lossy(), "");
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "one wrong, one right");
        assert_eq!(calls[0].kind, tues_core::PasswordKind::Sudo);
        assert_eq!(calls[0].user.as_deref(), Some("root"));
    }
    // Second command must use the memoized password (no new prompt).
    let out = s
        .command("id")
        .arg("-un")
        .user("root")
        .output()
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), "root\n");
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn sudo_always_wrong_password_reports_auth_failed() {
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(StaticPasswordManager::new("definitely-wrong")));
    let s = Session::connect(o).await.unwrap();
    let err = s
        .command("id")
        .user("root")
        .output()
        .await
        .expect_err("must fail");
    assert!(
        matches!(err, Error::Sudo(SudoError::AuthFailed { attempts: 3 })),
        "{err}"
    );
}

struct NoPassword;
impl PasswordManager for NoPassword {
    fn get(&mut self, _r: &PasswordRequest) -> tues_core::Result<SecretString> {
        Err(Error::Password("nope".into()))
    }
    fn invalidate(&mut self, _r: &PasswordRequest) {}
}

#[tokio::test]
async fn sudo_without_password_manager_fails_cleanly() {
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(NoPassword));
    let s = Session::connect(o).await.unwrap();
    let err = s
        .command("id")
        .user("root")
        .output()
        .await
        .expect_err("must fail");
    assert!(
        matches!(err, Error::Sudo(SudoError::PasswordRequired { .. })),
        "{err}"
    );
}

#[tokio::test]
async fn sudo_nopasswd_target_needs_no_prompt() {
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(NoPassword));
    let s = Session::connect(o).await.unwrap();
    let out = s
        .command("id")
        .arg("-un")
        .user(NOPASSWD_USER)
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout_lossy().trim(), NOPASSWD_USER);
}

#[tokio::test]
async fn sudo_with_pty() {
    let s = connect().await;
    let out = s
        .shell("id -un; tty >/dev/null && echo has-tty")
        .user("root")
        .pty(true)
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout_lossy(), "root\r\nhas-tty\r\n");
    assert!(out.stderr.is_empty());
}

#[tokio::test]
async fn pty_without_sudo() {
    let s = connect().await;
    let out = s
        .shell("tty >/dev/null && echo has-tty")
        .pty(true)
        .output()
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), "has-tty\r\n");
}

#[tokio::test]
async fn session_default_user_and_override() {
    let mut o = sshd().connect_options();
    o.user = Some("root".into());
    let s = Session::connect(o).await.unwrap();
    let out = s.command("id").arg("-un").output().await.unwrap();
    assert_eq!(out.stdout_lossy(), "root\n");
    let out = s
        .command("id")
        .arg("-un")
        .as_login_user()
        .output()
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), format!("{USER}\n"));
}

#[tokio::test]
async fn kill_terminates_remote_process() {
    let s = connect().await;
    let mut child = s.command("sleep").arg("30").spawn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("wait after kill")
        .unwrap();
    assert!(!status.success());
}

#[tokio::test]
async fn signal_is_delivered_and_status_reports_it() {
    let s = connect().await;
    let mut child = s.command("sleep").arg("30").spawn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Signalling through a separate handle while another task waits.
    let signaller = child.signaller();
    let waiter = tokio::spawn(async move { child.wait().await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    signaller.signal("TERM").unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("wait after TERM")
        .unwrap()
        .unwrap();
    assert_eq!(status.signal(), Some("TERM"), "{status:?}");
    assert_eq!(status.code(), None);
}

#[tokio::test]
async fn wait_is_cancel_safe() {
    let s = connect().await;
    let mut child = s.shell("sleep 1; exit 3").spawn().await.unwrap();
    let timed_out = tokio::time::timeout(Duration::from_millis(100), child.wait()).await;
    assert!(timed_out.is_err());
    // The child must still be waitable after the timed-out wait was dropped.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("second wait")
        .unwrap();
    assert_eq!(status.code(), Some(3));
    // And repeated calls keep returning the outcome.
    assert_eq!(child.wait().await.unwrap().code(), Some(3));
    assert_eq!(child.try_wait().unwrap().unwrap().code(), Some(3));
}

#[tokio::test]
async fn failed_child_keeps_reporting_its_error() {
    let mut o = sshd().connect_options();
    o.password_manager = Some(shared(StaticPasswordManager::new("definitely-wrong")));
    let s = Session::connect(o).await.unwrap();
    let mut child = s.command("id").user("root").spawn().await.unwrap();
    let err = child.wait().await.expect_err("sudo must fail");
    assert!(matches!(err, Error::Sudo(_)), "{err}");
    // Not `Disconnected`: the outcome is remembered.
    let err = child.try_wait().expect_err("still the sudo error");
    assert!(matches!(err, Error::Sudo(_)), "{err}");
    let err = child.wait().await.expect_err("still the sudo error");
    assert!(matches!(err, Error::Sudo(_)), "{err}");
}

#[tokio::test]
async fn status_with_null_stdio() {
    let s = connect().await;
    let st = s
        .command("true")
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .status()
        .await
        .unwrap();
    assert!(st.success());
}

#[tokio::test]
async fn sftp_as_session_user_uses_sudo() {
    // `tues` cannot create files in another user's home. Both targets succeed
    // only because the SFTP server itself runs as that user.
    for (user, path) in [
        (NOPASSWD_USER, format!("/home/{NOPASSWD_USER}/tues-sftp")),
        ("root", format!("/root/tues-sftp-{}", std::process::id())),
    ] {
        let mut opts = sshd().connect_options();
        opts.user = Some(user.into());
        let s = Session::connect(opts).await.unwrap();
        let sftp = s.sftp().await.unwrap();
        sftp.write(&path, b"owned").await.unwrap();
        let owner = s
            .command("stat")
            .arg("-c")
            .arg("%U")
            .arg(&path)
            .output()
            .await
            .unwrap();
        assert!(owner.status.success(), "{owner:?}");
        assert_eq!(owner.stdout_lossy().trim(), user);
        sftp.remove_file(&path).await.unwrap();
        s.close().await.unwrap();
    }

    let s = connect().await;
    let err = s
        .sftp()
        .await
        .unwrap()
        .write(format!("/home/{NOPASSWD_USER}/tues-denied"), b"no")
        .await
        .unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("denied")
            || err.to_string().to_ascii_lowercase().contains("permission"),
        "{err}"
    );
}

#[tokio::test]
async fn session_file_helpers_use_their_own_channel() {
    let s = connect().await;
    let id = std::process::id();
    let local = std::env::temp_dir().join(format!("tues-up-{id}"));
    let downloaded = std::env::temp_dir().join(format!("tues-down-{id}"));
    let _ = std::fs::remove_dir_all(&local);
    let _ = std::fs::remove_dir_all(&downloaded);
    std::fs::create_dir(&local).unwrap();
    std::fs::write(local.join("a.txt"), b"aaa").unwrap();
    std::fs::create_dir(local.join("sub")).unwrap();
    std::fs::write(local.join("sub").join("b.txt"), b"bbb").unwrap();
    std::os::unix::fs::symlink("a.txt", local.join("link")).unwrap();

    let remote = format!("/tmp/tues-files-{id}");
    s.upload(&local, &remote).await.unwrap();
    let md = s.stat(format!("{remote}/a.txt")).await.unwrap();
    assert!(md.is_file());
    assert_eq!(md.len(), 3);
    assert!(s.stat(format!("{remote}/sub")).await.unwrap().is_dir());
    assert!(s.stat(format!("{remote}/link")).await.unwrap().is_file());

    s.download(&remote, &downloaded).await.unwrap();
    assert_eq!(std::fs::read(downloaded.join("a.txt")).unwrap(), b"aaa");
    assert_eq!(
        std::fs::read(downloaded.join("sub").join("b.txt")).unwrap(),
        b"bbb"
    );
    assert_eq!(
        std::fs::read_link(downloaded.join("link"))
            .unwrap()
            .as_os_str(),
        "a.txt"
    );

    s.rename(format!("{remote}/a.txt"), format!("{remote}/c.txt"))
        .await
        .unwrap();
    // Closing an explicit client must not drop the cached one.
    let explicit = s.sftp().await.unwrap();
    explicit.close().await.unwrap();
    assert!(s.stat(format!("{remote}/c.txt")).await.unwrap().is_file());
    s.delete(&remote).await.unwrap();
    assert!(s.stat(&remote).await.is_err());
    let _ = std::fs::remove_dir_all(&local);
    let _ = std::fs::remove_dir_all(&downloaded);

    let mut opts = sshd().connect_options();
    opts.user = Some(NOPASSWD_USER.into());
    let s = Session::connect(opts).await.unwrap();
    let one = std::env::temp_dir().join(format!("tues-one-{id}"));
    std::fs::write(&one, b"z").unwrap();
    let path = format!("/home/{NOPASSWD_USER}/tues-up-{id}");
    s.upload(&one, &path).await.unwrap();
    let owner = s
        .command("stat")
        .arg("-c")
        .arg("%U")
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert_eq!(owner.stdout_lossy().trim(), NOPASSWD_USER);
    s.delete(&path).await.unwrap();
    let _ = std::fs::remove_file(&one);
}

#[tokio::test]
async fn sftp_roundtrip() {
    let s = connect().await;
    let sftp = s.sftp().await.unwrap();
    let dir = format!("/tmp/tues-sftp-{}", std::process::id());
    let _ = sftp.remove_dir(&dir).await;
    sftp.create_dir(&dir).await.unwrap();
    let path = format!("{dir}/file.bin");
    let data: Vec<u8> = (0..70000u32).map(|i| i as u8).collect();
    sftp.write(&path, &data).await.unwrap();
    assert_eq!(sftp.read(&path).await.unwrap(), data);
    let md = sftp.metadata(&path).await.unwrap();
    assert!(md.is_file());
    assert_eq!(md.len(), data.len() as u64);

    // Streamed append via File.
    let mut f = sftp
        .open_with(&path, OpenOptions::new().write(true).append(true))
        .await
        .unwrap();
    f.write_all(b"tail").await.unwrap();
    f.shutdown().await.unwrap();
    let mut f = sftp.open(&path).await.unwrap();
    let mut all = Vec::new();
    f.read_to_end(&mut all).await.unwrap();
    assert_eq!(all.len(), data.len() + 4);
    assert!(all.ends_with(b"tail"));

    let entries = sftp.read_dir(&dir).await.unwrap();
    assert!(entries.iter().any(|e| e.file_name == "file.bin"));
    sftp.rename(&path, format!("{dir}/renamed")).await.unwrap();
    assert!(sftp.try_exists(format!("{dir}/renamed")).await.unwrap());
    assert!(!sftp.try_exists(&path).await.unwrap());
    sftp.remove_file(format!("{dir}/renamed")).await.unwrap();
    sftp.remove_dir(&dir).await.unwrap();
    sftp.close().await.unwrap();
}

#[tokio::test]
async fn ssh_config_host_entry_is_used() {
    let f = sshd();
    let text = format!(
        "Host testbox\n  HostName {}\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  StrictHostKeyChecking no\n",
        f.host,
        f.port,
        USER,
        f.key_path.display()
    );
    let cfg = SshConfig::parse_str(&text, None).unwrap();
    let opts = ConnectOptions::new("testbox")
        .use_agent(false)
        .ssh_config(SshConfigSource::Parsed(cfg))
        .password_manager(shared(NoPassword));
    let s = Session::connect(opts).await.expect("connect via config");
    assert_eq!(s.login_user(), USER);
    let out = s.command("true").output().await.unwrap();
    assert!(out.status.success());
}

#[tokio::test]
async fn strict_host_key_policy_rejects_unknown_and_accept_new_learns() {
    let f = sshd();
    let kh = std::env::temp_dir().join(format!("tues-kh-{}", std::process::id()));
    let _ = std::fs::remove_file(&kh);

    let mut o = f.connect_options();
    o.host_key_policy = Some(HostKeyPolicy::Strict);
    o.known_hosts_file = Some(kh.clone());
    let err = Session::connect(o)
        .await
        .expect_err("unknown key must be rejected");
    assert!(matches!(err, Error::UnknownHostKey { .. }), "{err}");

    let mut o = f.connect_options();
    o.host_key_policy = Some(HostKeyPolicy::AcceptNew);
    o.known_hosts_file = Some(kh.clone());
    Session::connect(o).await.expect("accept-new");
    let content = std::fs::read_to_string(&kh).unwrap();
    assert!(
        content.contains(&format!("[{}]:{}", f.host, f.port)),
        "{content}"
    );

    let mut o = f.connect_options();
    o.host_key_policy = Some(HostKeyPolicy::Strict);
    o.known_hosts_file = Some(kh.clone());
    Session::connect(o).await.expect("now known");
    let _ = std::fs::remove_file(&kh);
}

#[tokio::test]
async fn proxy_jump_through_second_container() {
    let s = Session::connect(sshd().via_jump_options())
        .await
        .expect("connect via jump");
    let out = s.command("hostname").output().await.unwrap();
    assert!(out.status.success(), "{out:?}");
    // Sudo still works through the jump.
    let out = s
        .command("id")
        .arg("-un")
        .user("root")
        .output()
        .await
        .unwrap();
    assert_eq!(out.stdout_lossy(), "root\n");
}

#[tokio::test]
async fn concurrent_commands_on_one_session() {
    let s = connect().await;
    let mut handles = Vec::new();
    for i in 0..8 {
        let s = s.clone();
        handles.push(tokio::spawn(async move {
            s.shell(format!("echo {i}"))
                .user("root")
                .output()
                .await
                .unwrap()
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        let out = h.await.unwrap();
        assert_eq!(out.stdout_lossy(), format!("{i}\n"));
    }
}

#[tokio::test]
async fn closed_session_errors() {
    let s = connect().await;
    s.close().await.unwrap();
    let err = s.command("true").output().await.expect_err("closed");
    assert!(matches!(err, Error::Disconnected), "{err}");
}
