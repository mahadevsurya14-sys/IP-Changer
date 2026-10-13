"""Main entry point for IP Changer desktop application.

Author: Mahaduuu
"""

import sys
from src.app import IPChangerApp


def main() -> None:
    """Launch IP Changer application."""
    app = IPChangerApp(sys.argv)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
