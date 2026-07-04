from __future__ import annotations

import sys


def main() -> None:
    sys.stdin.readline()
    sys.stdout.write("this is not valid json {{{\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
