"""Locate application files whether running from source or a frozen build.

A PyInstaller one-file build unpacks its bundled resources into a temporary
directory that is deleted on exit, so read-only assets and writable state must
be resolved separately:

* ``BUNDLE_DIR`` holds bundled read-only resources (the web interface).
* ``DATA_ROOT`` holds files the user owns and edits — ``.env`` and the
  database — and lives beside the executable so it survives between runs.

Running from source, both resolve to the repository root.
"""

import sys
from pathlib import Path


def _frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _bundle_dir() -> Path:
    if _frozen():
        # Set by the PyInstaller bootloader to the unpacked resource directory.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def _data_root() -> Path:
    if _frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


BUNDLE_DIR = _bundle_dir()
DATA_ROOT = _data_root()
