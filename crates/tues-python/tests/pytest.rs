//! Runs the Python suite so `cargo test` covers the bindings too.
//!
//! Pytest loads the cdylib this build just produced (`lib_tues.so` next to the
//! test binary's profile directory) instead of a previously installed wheel.
//! Set `TUES_COVERAGE=1` to record coverage.py data for `python/tues`.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn runs_pytest() {
    let workspace = workspace_root();
    let python = python_bin(&workspace);
    let extension = cdylib(&profile_dir());

    let mut command = Command::new(&python);
    if coverage_requested() {
        command.args(["-m", "coverage", "run", "--source"]);
        command.arg(workspace.join("python/tues"));
        command.args(["-m", "pytest"]);
    } else {
        command.args(["-m", "pytest"]);
    }
    command
        .arg("-q")
        .arg("--tb=short")
        .current_dir(&workspace)
        .env("TUES_EXTENSION", &extension)
        .env("PYTHONPATH", pythonpath(&workspace));
    if coverage_requested() {
        // `python -m tues` is a second interpreter. coverage's site hook
        // starts when this points at the project config.
        command.env("COVERAGE_PROCESS_START", workspace.join("pyproject.toml"));
    }

    let output = command.output().unwrap_or_else(|err| {
        panic!("failed to spawn {}: {err}", python.display());
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pytest exited {}\n{stdout}{stderr}",
        output.status,
    );
}

fn coverage_requested() -> bool {
    env::var("TUES_COVERAGE").ok().as_deref() == Some("1")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn python_bin(workspace: &Path) -> PathBuf {
    let venv = workspace.join(".venv/bin/python");
    if venv.is_file() {
        venv
    } else {
        PathBuf::from("python3")
    }
}

fn pythonpath(workspace: &Path) -> OsString {
    let mut paths = vec![workspace.join("python")];
    if let Some(existing) = env::var_os("PYTHONPATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).expect("PYTHONPATH")
}

fn profile_dir() -> PathBuf {
    let exe = env::current_exe().expect("current test executable");
    exe.parent()
        .and_then(Path::parent)
        .expect("profile directory")
        .to_path_buf()
}

fn cdylib(profile: &Path) -> PathBuf {
    // A normal `cargo test` copies the cdylib to the profile directory.
    // `cargo llvm-cov` leaves it in `deps/`.
    let names = ["lib_tues.so", "lib_tues.dylib", "_tues.dll"];
    for dir in [profile, &profile.join("deps")] {
        for name in names {
            let path = dir.join(name);
            if path.is_file() {
                return path;
            }
        }
    }
    panic!(
        "built extension not found in {} or {} (expected lib_tues.so)",
        profile.display(),
        profile.join("deps").display(),
    );
}
