# SPDX-License-Identifier: AGPL-3.0-or-later
"""python -m paddock_cli.guard"""
from __future__ import annotations

import sys

from paddock_cli.guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
