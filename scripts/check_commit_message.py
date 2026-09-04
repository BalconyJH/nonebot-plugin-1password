"""Validate the subject of a Conventional Commit message."""

import re
import sys
from pathlib import Path

CONVENTIONAL_SUBJECT = re.compile(
    r"^(?:feat|fix|docs|refactor|perf|test|build|ci|chore|revert|security)"
    r"(?:\([a-z0-9._/-]+\))?!?: .+"
)


def main() -> int:
    """Return success exactly when the first commit-message line is valid."""
    message_file = Path(sys.argv[1])
    subject = message_file.read_text(encoding="utf-8").splitlines()[0]
    if CONVENTIONAL_SUBJECT.fullmatch(subject):
        return 0
    sys.stderr.write("commit subject must follow Conventional Commits\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
