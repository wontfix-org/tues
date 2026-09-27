"""The ``tues`` command: ``tues ...`` once installed, or ``python -m tues ...``.

The command line is the Rust CLI from the ``tues-cli`` crate, compiled into
the extension module. This file only hands over ``sys.argv`` and exits with
the code it returns.
"""

from __future__ import annotations

import signal
import sys

from ._tues import cli_main


def main() -> None:
    # Python turns SIGINT into a KeyboardInterrupt that is only raised once
    # control returns to Python code, which never happens while the CLI runs.
    # The default action ends the process, as it does for the native binary.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(cli_main(["tues", *sys.argv[1:]]))


if __name__ == "__main__":
    main()
