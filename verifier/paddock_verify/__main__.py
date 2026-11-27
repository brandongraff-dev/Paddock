# SPDX-License-Identifier: Apache-2.0
"""``python -m paddock_verify``."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
