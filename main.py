#!/usr/bin/env python3
"""Clarity privacy firewall: entry point.

Usage: python main.py --input <input dir> --output <empty output dir>
The secret comes from the RAKSHA_SECRET environment variable.
"""
import sys

from rakshak.cli import main

if __name__ == "__main__":
    sys.exit(main())
