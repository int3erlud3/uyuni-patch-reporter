"""Allow ``python -m uyuni_patch_reporter``."""

import sys

from .cli import main

sys.exit(main())
