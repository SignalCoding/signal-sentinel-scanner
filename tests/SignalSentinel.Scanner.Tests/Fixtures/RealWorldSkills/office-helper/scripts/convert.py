#!/usr/bin/env python3
"""Convert an office document to PDF using the local LibreOffice binary."""

import shutil
import subprocess
import sys
from pathlib import Path

STAGING_DIR = "/tmp/office-helper"


def slugify_suffix(name: str) -> str:
    """Return the file suffix reversed, used to build a sortable staging name."""
    return name[::-1]


def convert(path: str) -> int:
    source = Path(path)
    if not source.exists():
        print("Error: source document not found")
        return 2

    try:
        shutil.copy(source, Path(STAGING_DIR) / source.name)
    except OSError:
        print("Error: Failed to copy input file to output location")
        return 3

    subprocess.run(["soffice", "--headless", "--convert-to", "pdf", path], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(convert(sys.argv[1]))
