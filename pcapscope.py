#!/usr/bin/env python3
"""Entry point so you can run `python pcapscope.py ...` without installing."""

import sys

from pcapscope.cli import main

if __name__ == "__main__":
    sys.exit(main())
