# Agent notes

Prefer this file and `just --list` over reading the full README. Pull README or
crate docs only for the surface you are changing.

## Layout

| Path | Role |
| --- | --- |
| `crates/tues-core` | Sans-IO: exec machine, sudo filter, `Command`, ssh_config, passwords. No I/O. |
| `crates/tues-async` | tokio + russh driver (connect, auth, exec, SFTP, ProxyJump). |
| `crates/tues-sync` | Blocking facade over a private tokio runtime. |
| `crates/tues` | Public facade: blocking at root, async in `tues::aio`. |
| `crates/tues-cli` | `tues` binary. |
| `crates/tues-python` | PyO3 module `tues._tues`. |
| `python/tues` | Python `subprocess`-shaped API on the extension. |
| `crates/tues-testsupport` | Docker `sshd` fixture for integration tests. |
| `docker/sshd` | Fixture image sources. |

Protocol and parsing belong in `tues-core`; networking stays in `tues-async`.
Mirror Rust API shapes in Python only when the change is user-facing.

## Commands

```sh
just setup                 # .venv, maturin develop, llvm-cov tools
just test                  # full Rust + Python suite with coverage summary
just test-rust             # cargo test --workspace (includes pytest via tues-python)
just test-py               # pytest only
just test-crate <crate>    # one Rust crate (e.g. tues-core)
just check                 # clippy --workspace --all-targets
just fmt                   # rustfmt --all
just coverage              # HTML coverage → target/llvm-cov/html
```

Narrow further while iterating:

```sh
cargo test -p tues-core --lib
cargo test -p tues-async --test sshd <filter>
pytest python/tests/test_sync.py -k <name>
```

Integration tests need Docker (build `tues-test-sshd`). Unit tests in
`tues-core` do not. After Python/extension changes, use `just setup` or
`maturin develop` so `.venv` loads the rebuilt cdylib (`PYO3_PYTHON`).

## Working style

- Change the smallest layer that owns the behavior; avoid drive-by refactors.
- Do not invent CLI flags or public API — check the crate/`python/tues` you touch.
- Prefer `just test-crate` / filtered pytest over a full `just test` while
  iterating; run `just check` before considering a change done.
- Releases: `just release` / `just rc` (see README only if changing release).
