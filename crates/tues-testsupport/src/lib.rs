//! Docker-backed `sshd` fixture for integration tests.
//!
//! The first call to [`sshd`] builds the image in `docker/sshd`, starts two
//! containers (a target and a jump host on a private network) with ephemeral
//! host ports, and keeps them alive for the rest of the test process. All
//! Docker interaction happens on a dedicated thread with its own runtime so
//! tests can use any executor.
//!
//! The test harness ends the process with `exit`, so container guards are
//! never dropped. Containers are therefore labelled with the owning pid and
//! removed by an `atexit` hook; stale containers/networks left by crashed
//! runs are removed the next time the fixture starts.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use testcontainers::core::{ContainerPort, IntoContainerPort, WaitFor};
use testcontainers::runners::{AsyncBuilder, AsyncRunner};
use testcontainers::{GenericBuildableImage, GenericImage, ImageExt};

use tues_core::{ConnectOptions, HostKeyPolicy, StaticPasswordManager, shared};

pub const USER: &str = "tues";
pub const PASSWORD: &str = "tuespass";
pub const NOPASSWD_USER: &str = "nopw";

/// A running `sshd` pair.
#[derive(Debug, Clone)]
pub struct SshdFixture {
    /// Address of the Docker host side of the port mappings.
    pub host: String,
    /// Ephemeral host port of the target container's sshd.
    pub port: u16,
    /// Ephemeral host port of the jump container's sshd.
    pub jump_port: u16,
    /// Name under which the target is reachable from the jump container.
    pub target_name: String,
    /// Absolute path of the fixture private key authorised for [`USER`].
    pub key_path: PathBuf,
}

impl SshdFixture {
    /// Options for the target host: fixture key, no ssh_config, host key
    /// checking off, and a static password manager with the login password.
    pub fn connect_options(&self) -> ConnectOptions {
        ConnectOptions::new(&self.host)
            .login_user(USER)
            .port(self.port)
            .identity_file(&self.key_path)
            .identities_only(true)
            .use_agent(false)
            .no_ssh_config()
            .host_key_policy(HostKeyPolicy::Off)
            .connect_timeout(Duration::from_secs(20))
            .password_manager(shared(StaticPasswordManager::new(PASSWORD)))
    }

    /// Like [`connect_options`](Self::connect_options) but for the jump host.
    pub fn jump_connect_options(&self) -> ConnectOptions {
        let mut o = self.connect_options();
        o.port = Some(self.jump_port);
        o
    }

    /// Options that reach the target only via the jump container.
    pub fn via_jump_options(&self) -> ConnectOptions {
        ConnectOptions::new(&self.target_name)
            .login_user(USER)
            .port(22)
            .identity_file(&self.key_path)
            .identities_only(true)
            .use_agent(false)
            .no_ssh_config()
            .host_key_policy(HostKeyPolicy::Off)
            .connect_timeout(Duration::from_secs(20))
            .proxy_jump(format!("{}@{}:{}", USER, self.host, self.jump_port))
            .password_manager(shared(StaticPasswordManager::new(PASSWORD)))
    }
}

fn docker_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docker")
        .join("sshd")
        .canonicalize()
        .expect("docker/sshd directory")
}

static FIXTURE: OnceLock<SshdFixture> = OnceLock::new();

/// Start (once) and return the shared fixture.
pub fn sshd() -> &'static SshdFixture {
    FIXTURE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Result<SshdFixture, String>>();
        std::thread::Builder::new()
            .name("tues-docker-fixture".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("fixture runtime");
                rt.block_on(async move {
                    match start().await {
                        Ok((fixture, keep)) => {
                            let _ = tx.send(Ok(fixture));
                            // Keep containers alive for the process lifetime.
                            let _keep = keep;
                            std::future::pending::<()>().await;
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e));
                        }
                    }
                });
            })
            .expect("spawn fixture thread");
        match rx.recv() {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => panic!("could not start sshd fixture: {e}"),
            Err(_) => panic!("sshd fixture thread died"),
        }
    })
}

type Keep = Vec<Arc<Mutex<Box<dyn std::any::Any + Send>>>>;

async fn start() -> Result<(SshdFixture, Keep), String> {
    let dir = docker_dir();
    let key_path = dir.join("id_test");

    let image: GenericImage = GenericBuildableImage::new("tues-test-sshd", "latest")
        .with_dockerfile(dir.join("Dockerfile"))
        .with_file(dir.join("sshd_config"), "sshd_config")
        .with_file(dir.join("authorized_keys"), "authorized_keys")
        .build_image()
        .await
        .map_err(|e| format!("docker build: {e}"))?;

    remove_stale();

    let pid = std::process::id();
    let suffix = format!("{pid}-{}", nonce());
    let network = format!("tues-test-{suffix}");
    let target_name = format!("tues-target-{suffix}");
    let jump_name = format!("tues-jump-{suffix}");
    register_cleanup(
        vec![target_name.clone(), jump_name.clone()],
        network.clone(),
    );

    let base = |name: &str| {
        image
            .clone()
            .with_exposed_port(ContainerPort::Tcp(22))
            .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
            .with_network(&network)
            .with_container_name(name)
            .with_label(LABEL, "1")
            .with_label(PID_LABEL, pid.to_string())
            .with_startup_timeout(Duration::from_secs(120))
    };

    let target = base(&target_name)
        .start()
        .await
        .map_err(|e| format!("start target: {e}"))?;
    let jump = base(&jump_name)
        .start()
        .await
        .map_err(|e| format!("start jump: {e}"))?;

    let port = target
        .get_host_port_ipv4(22.tcp())
        .await
        .map_err(|e| format!("target port: {e}"))?;
    let jump_port = jump
        .get_host_port_ipv4(22.tcp())
        .await
        .map_err(|e| format!("jump port: {e}"))?;

    let fixture = SshdFixture {
        host: "127.0.0.1".to_string(),
        port,
        jump_port,
        target_name,
        key_path,
    };
    let keep: Keep = vec![
        Arc::new(Mutex::new(Box::new(target))),
        Arc::new(Mutex::new(Box::new(jump))),
    ];
    Ok((fixture, keep))
}

const LABEL: &str = "tues.test";
const PID_LABEL: &str = "tues.test.pid";

struct Cleanup {
    containers: Vec<String>,
    network: String,
}

static CLEANUP: Mutex<Option<Cleanup>> = Mutex::new(None);

fn docker(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Remove this process's containers and network. Runs from `atexit`.
extern "C" fn cleanup_at_exit() {
    let Some(c) = CLEANUP.lock().ok().and_then(|mut g| g.take()) else {
        return;
    };
    let mut args = vec!["rm", "-f", "-v"];
    args.extend(c.containers.iter().map(String::as_str));
    docker(&args);
    docker(&["network", "rm", &c.network]);
}

fn register_cleanup(containers: Vec<String>, network: String) {
    if let Ok(mut g) = CLEANUP.lock() {
        let first = g.is_none();
        *g = Some(Cleanup {
            containers,
            network,
        });
        if first {
            // SAFETY: `cleanup_at_exit` is a plain `extern "C"` function that
            // does not unwind and only touches process-global state.
            unsafe {
                libc::atexit(cleanup_at_exit);
            }
        }
    }
}

fn pid_alive(pid: &str) -> bool {
    pid.parse::<u32>()
        .map(|p| Path::new(&format!("/proc/{p}")).exists())
        .unwrap_or(true)
}

/// Remove containers and networks left behind by test processes that no
/// longer exist (e.g. killed with SIGKILL).
fn remove_stale() {
    let filter = format!("label={LABEL}");
    let format = format!("{{{{.ID}}}} {{{{.Label \"{PID_LABEL}\"}}}}");
    if let Some(list) = docker(&["ps", "-a", "--filter", &filter, "--format", &format]) {
        let stale: Vec<&str> = list
            .lines()
            .filter_map(|l| {
                let (id, pid) = l.split_once(' ')?;
                (!pid_alive(pid.trim())).then_some(id)
            })
            .collect();
        if !stale.is_empty() {
            let mut args = vec!["rm", "-f", "-v"];
            args.extend(stale);
            docker(&args);
        }
    }
    if let Some(list) = docker(&["network", "ls", "--format", "{{.Name}}"]) {
        let stale: Vec<&str> = list
            .lines()
            .filter(|n| {
                n.strip_prefix("tues-test-")
                    .and_then(|rest| rest.split('-').next())
                    .is_some_and(|pid| !pid_alive(pid))
            })
            .collect();
        if !stale.is_empty() {
            let mut args = vec!["network", "rm"];
            args.extend(stale);
            docker(&args);
        }
    }
}

fn nonce() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", t & 0xffff_ffff)
}
