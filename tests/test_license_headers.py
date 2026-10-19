# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import glob
import os
import sys
from pathlib import Path

import pytest


def file_has_headers(path):
    with open(path) as f:
        missing_copyright = True
        missing_license = True
        for line in f:
            if missing_copyright and line.startswith("# Copyright "):
                missing_copyright = False
            elif missing_license and line.startswith("# SPDX-License-Identifier: "):
                missing_license = False

            if not missing_copyright and not missing_license:
                return True

    return False


@pytest.mark.skip_packaging
def test_license_headers():
    top_dir = Path(Path(__file__) / "../..").resolve()
    extensions = [
        "py",
        "sh",
    ]

    # Generated from the 3GPP specs, see tools/gen_sbi_models.py
    exclude_dirs = [
        os.path.join(top_dir, "lib/sbi/models"),
    ]

    missing = []
    for ext in extensions:
        pattern = os.path.join(top_dir, f"**/*.{ext}")
        for i in glob.glob(pattern, recursive=True):
            if any(i.startswith(d + os.sep) for d in exclude_dirs):
                continue
            if not file_has_headers(i):
                missing += [i]

    if not missing:
        return

    print()
    print("Please add the license and copyright header lines:")
    print()
    print("# Copyright YEAR NAME <EMAIL>")
    print("# SPDX-License-Identifier: AGPL-3.0-or-later")
    print()
    print(f"Missing in ({len(missing)}):")
    for m in missing:
        print(f"  {m}")
    print()

    sys.exit(1)
