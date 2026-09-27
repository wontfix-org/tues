//! The `tues` executable. The command line itself lives in the library so the
//! Python package can offer the same tool as a console script.

fn main() {
    std::process::exit(tues_cli::run(std::env::args_os()));
}
