"""Allow `python -m scamalyser email.eml`."""

import sys

from .cli import main

sys.exit(main())
