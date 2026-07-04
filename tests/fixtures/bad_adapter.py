from __future__ import annotations

import sys


def main() -> None:
    sys.stderr.write("boom: adapter failed on purpose\n")
    sys.stderr.flush()
    sys.exit(1)


if __name__ == "__main__":
    main()
