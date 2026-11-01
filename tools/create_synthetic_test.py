"""Create an explicitly harmless rule-test fixture; never malware."""
from pathlib import Path


def main() -> None:
    """Write synthetic marker text to the working directory."""
    path = Path("synthetic_fixture.txt")
    path.write_text("ONEGUARD_SYNTHETIC_TEST_SIGNATURE\nNot malware.\n", encoding="utf-8")
    print(f"Fixture inocuo creado: {path.absolute()}")


if __name__ == "__main__":
    main()
