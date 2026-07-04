from __future__ import annotations

import json
import sys


def main() -> None:
    line = sys.stdin.readline()
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        payload = {"last_user_message": ""}
    last_user = payload.get("last_user_message", "")
    if not isinstance(last_user, str):
        last_user = ""
    response = {
        "reply": f"echo: {last_user}",
        "raw": line,
        "error": None,
    }
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
