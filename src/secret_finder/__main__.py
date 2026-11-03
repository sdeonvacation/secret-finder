"""Allow `python -m secret_finder`."""

from secret_finder.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
