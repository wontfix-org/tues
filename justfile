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
    rustup component add llvm-tools-preview
    if ! cargo llvm-cov --version >/dev/null 2>&1; then
        cargo install cargo-llvm-cov --locked
    fi

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

# Tag and build the next release candidate (omit version to be prompted).
rc *args:
    "{{justfile_directory()}}/scripts/release" --rc {{args}}

# Tag and build a release (omit version to be prompted with recent commits).
release *args:
    "{{justfile_directory()}}/scripts/release" {{args}}
