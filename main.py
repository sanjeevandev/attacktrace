#!/usr/bin/env python3
"""
ATTACKTRACE Main Entry Point Compatibility Shim.
Redirects to src.cli.main() for unified CLI interface.
"""
import sys
from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
