#!/usr/bin/env python3
"""Entry-point script for running HexShield from the repo without install."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hexshield.cli.main import main

if __name__ == "__main__":
    sys.exit(main())