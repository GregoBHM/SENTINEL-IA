"""Print the SHA-256 of a local file in chunks."""
import argparse
import hashlib
from pathlib import Path


def main() -> None:
    """Display a test file's digest without modifying its contents."""
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    path = parser.parse_args().path
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    print(digest.hexdigest())


if __name__ == "__main__":
    main()
