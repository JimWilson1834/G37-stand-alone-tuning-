#!/usr/bin/env python3
"""Additive launcher; leaves the historical combined application unchanged."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from g37offline.gui import launch
    launch()
