# Agent notes

## Tests

Run the full suite (Rust + Python, with coverage) with:

```sh
just test
```

Individual pieces:

```sh
cargo test --workspace   # Rust tests and the pytest suite
cargo test -p <crate>    # one Rust crate (e.g. tues-core, tues-async)
pytest                   # Python tests only (python/tests)
```
