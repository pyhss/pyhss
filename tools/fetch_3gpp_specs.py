#!/usr/bin/env python3
# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vendor the 3GPP 5GC OpenAPI files needed by the PyHSS SBI services.

The files are taken unmodified from the "standard" directory of the spec set
that Open5GS was generated from, so PyHSS and Open5GS use identical API
definitions. Starting at the root files, every file referenced through a
cross-file $ref is fetched as well (file-level closure), so the vendored set
is self-contained for code generators and validators.

Usage: tools/fetch_3gpp_specs.py [--out specs/3gpp/r19-20260402]
"""

import argparse
import hashlib
import os
import re
import sys
import urllib.request

import yaml

OPEN5GS_TAG = "v2.8.0"
OPEN5GS_COMMIT = "157f611a530e292e40ec50f9d23f0ef5d4fcd6a6"
SPEC_DIR = "lib/sbi/support/r19-20260402-openapitools-7.20.0/standard"
BASE_URL = f"https://raw.githubusercontent.com/open5gs/open5gs/{OPEN5GS_COMMIT}/{SPEC_DIR}"

ROOTS = [
    "TS29504_Nudr_DR.yaml",
    "TS29505_Subscription_Data.yaml",
    "TS29519_Policy_Data.yaml",
    "TS29503_Nudm_UEAU.yaml",
    "TS29503_Nudm_UECM.yaml",
    "TS29510_Nnrf_NFManagement.yaml",
    "TS29571_CommonData.yaml",
]

top_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
default_out = os.path.join(top_dir, "specs/3gpp/r19-20260402")


def find_refs(node, refs):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.add(value)
            else:
                find_refs(value, refs)
    elif isinstance(node, list):
        for value in node:
            find_refs(value, refs)


def referenced_files(text):
    refs = set()
    find_refs(yaml.safe_load(text), refs)
    files = set()
    for ref in refs:
        name = ref.split("#", 1)[0]
        if name:
            files.add(os.path.basename(name))
    return files


def fetch(name):
    with urllib.request.urlopen(f"{BASE_URL}/{name}") as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=default_out, help="output directory (default: %(default)s)")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    pending = list(ROOTS)
    done = {}
    while pending:
        name = pending.pop(0)
        if name in done:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.yaml", name):
            sys.exit(f"Refusing unexpected file name: {name}")
        print(f"Fetching {name}")
        data = fetch(name)
        done[name] = data
        pending += sorted(referenced_files(data.decode()) - done.keys())

    for name, data in done.items():
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)

    with open(os.path.join(args.out, "SHA256SUMS"), "w") as f:
        for name in sorted(done):
            f.write(f"{hashlib.sha256(done[name]).hexdigest()}  {name}\n")

    print(f"Wrote {len(done)} files to {args.out}")


if __name__ == "__main__":
    main()
