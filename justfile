set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Create .venv, install build deps, and build the extension (expects uv, cargo, rustup).
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    for cmd in uv cargo rustup; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "$cmd is required on PATH" >&2
            exit 1
        fi
    done
    uv venv
    uv pip install --group dev
    .venv/bin/maturin develop --release
    rustup component add llvm-tools-preview rustfmt
    if ! cargo llvm-cov --version >/dev/null 2>&1; then
        cargo install cargo-llvm-cov --locked
    fi

# Format all Rust crates.
fmt:
    cd "{{justfile_directory()}}" && cargo fmt --all

# Clippy the workspace (all targets).
check:
    cd "{{justfile_directory()}}" && cargo clippy --workspace --all-targets

# Rust workspace tests (includes the pytest suite via tues-python).
test-rust:
    cd "{{justfile_directory()}}" && cargo test --workspace

# Python tests only (expects just setup).
test-py:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    if [[ ! -x .venv/bin/python ]]; then
        echo "create .venv first (just setup)" >&2
        exit 1
    fi
    .venv/bin/python -m pytest

# One Rust crate: just test-crate tues-core
test-crate crate *args:
    cd "{{justfile_directory()}}" && cargo test -p {{crate}} {{args}}

# HTML coverage report at target/llvm-cov/html.
coverage:
    cd "{{justfile_directory()}}" && cargo coverage

# Run the Rust and Python tests, then print per-file coverage.
test:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    if ! cargo llvm-cov --version >/dev/null 2>&1; then
        echo "cargo-llvm-cov is required: just setup" >&2
        exit 1
    fi
    if [[ ! -x .venv/bin/python ]]; then
        echo "create .venv and install pytest and coverage first (just setup)" >&2
        exit 1
    fi
    export TUES_COVERAGE=1
    # Same interpreter as pytest. See PYO3_PYTHON in .cargo/config.toml.
    export PYO3_PYTHON="${PWD}/.venv/bin/python"
    cargo llvm-cov --workspace --all-targets --no-report
    mkdir -p target/llvm-cov
    cargo llvm-cov report --json --summary-only --output-path target/llvm-cov/summary.json
    python3 - <<'PY'
    import json
    from pathlib import Path

    root = Path.cwd().resolve()
    data = json.loads(Path("target/llvm-cov/summary.json").read_text())
    rows = []
    for entry in data.get("data", []):
        for item in entry.get("files", []):
            path = Path(item["filename"])
            try:
                rel = path.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            if not rel.endswith(".rs") or rel.startswith("target/") or "/tests/" in rel:
                continue
            lines = item["summary"]["lines"]
            if lines["count"] == 0:
                continue
            rows.append((rel, lines["percent"], lines["covered"], lines["count"]))
    rows.sort()
    width = max([len("TOTAL"), *(len(rel) for rel, _, _, _ in rows)])
    print()
    print("Rust")
    print("file".ljust(width) + "  cover")
    for rel, pct, covered, count in rows:
        print("%s  %6.1f%%  (%d/%d)" % (rel.ljust(width), pct, covered, count))
    totals = data["data"][0]["totals"]["lines"]
    print("%s  %6.1f%%  (%d/%d)" % ("TOTAL".ljust(width), totals["percent"], totals["covered"], totals["count"]))
    PY
    echo
    echo "Python"
    .venv/bin/python -m coverage combine --quiet
    .venv/bin/python -m coverage report --include='*/python/tues/*'

# Run Rust (nightly) and Python tests in fail-fast mode.
test-fail-fast:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    if ! rustup toolchain list | rg -q '^nightly'; then
        echo "nightly toolchain is required: rustup toolchain install nightly" >&2
        exit 1
    fi
    if [[ ! -x .venv/bin/python ]]; then
        echo "create .venv first (just setup)" >&2
        exit 1
    fi
    # region agent log H1,H2
    python3 -c 'import json,time,pathlib; p=pathlib.Path(".cursor/debug-26b7ec.log"); p.parent.mkdir(parents=True, exist_ok=True); p.open("a", encoding="utf-8").write(json.dumps({"sessionId":"26b7ec","runId":"pre-fix","hypothesisId":"H1","location":"justfile:test-fail-fast","message":"starting fail-fast suite","data":{"rust_fail_fast":True,"rust_single_thread":True,"rust_single_job":True,"rust_per_package_loop":True,"pytest_fail_fast":True},"timestamp":int(time.time()*1000)})+"\n")'
    # endregion agent log H1,H2
    mapfile -t rust_packages < <(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; d=json.load(sys.stdin); m=set(d["workspace_members"]); p={x["id"]:x["name"] for x in d["packages"]}; [print(p[i]) for i in d["workspace_members"] if i in m]')
    for pkg in "${rust_packages[@]}"; do
        # region agent log H5
        python3 -c 'import json,time,pathlib,sys; p=pathlib.Path(".cursor/debug-26b7ec.log"); p.open("a", encoding="utf-8").write(json.dumps({"sessionId":"26b7ec","runId":"pre-fix","hypothesisId":"H5","location":"justfile:test-fail-fast","message":"starting rust package","data":{"package":sys.argv[1]},"timestamp":int(time.time()*1000)})+"\n")' "$pkg"
        # endregion agent log H5
        cargo +nightly test -j 1 -Z unstable-options -p "$pkg" -- -Z unstable-options --fail-fast --test-threads=1
    done
    # region agent log H3
    python3 -c 'import json,time,pathlib; p=pathlib.Path(".cursor/debug-26b7ec.log"); p.open("a", encoding="utf-8").write(json.dumps({"sessionId":"26b7ec","runId":"pre-fix","hypothesisId":"H3","location":"justfile:test-fail-fast","message":"rust phase passed","data":{"mode":"per-package sequential"},"timestamp":int(time.time()*1000)})+"\n")'
    # endregion agent log H3
    .venv/bin/python -m pytest -x
    # region agent log H4
    python3 -c 'import json,time,pathlib; p=pathlib.Path(".cursor/debug-26b7ec.log"); p.open("a", encoding="utf-8").write(json.dumps({"sessionId":"26b7ec","runId":"pre-fix","hypothesisId":"H4","location":"justfile:test-fail-fast","message":"python phase passed","data":{"command":"python -m pytest -x"},"timestamp":int(time.time()*1000)})+"\n")'
    # endregion agent log H4

# Tag and build the next release candidate (omit version to be prompted).
rc *args:
    "{{justfile_directory()}}/scripts/release" --rc {{args}}

# Tag and build a release (omit version to be prompted with recent commits).
release *args:
    "{{justfile_directory()}}/scripts/release" {{args}}
