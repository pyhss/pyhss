# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# Copyright 2026 Lennart Rosam <hello@takuto.de>
# Copyright 2026 eta <eta@eta.st>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import re
import sys
import uuid
from pathlib import Path

import yaml
from gsup.protocol.gsup_msg import GMMCause

config = None


def load_config():
    global config

    if "PYHSS_CONFIG" in os.environ:
        paths = [os.environ["PYHSS_CONFIG"]]
        if not os.path.exists(paths[0]):
            print(f"ERROR: PYHSS_CONFIG is set, but file does not exist: {paths[0]}")
            sys.exit(1)
    else:
        paths = [
            "/etc/pyhss/config.yaml",
            "/usr/share/pyhss/config.yaml",
            Path(__file__).resolve().parent.parent / "config.yaml",
        ]

    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as stream:
                config = yaml.safe_load(stream)
            return

    print("ERROR: failed to find PyHSS config, tried these paths:")
    for path in paths:
        print(f" * {path}")
    sys.exit(1)


def validate_config():
    """Validate configuration values at startup.

    Refuses to start if config options have unexpected values,
    preventing silent misconfiguration. Add future validations here."""

    valid_reject_causes = {"IMSI_UNKNOWN", "ROAMING_NOT_ALLOWED"}
    reject_cause = (
        config.get("hss", {}).get("roaming", {}).get("inbound", {}).get("reject_unknown_imsis_with", "IMSI_UNKNOWN")
    )
    if reject_cause not in valid_reject_causes:
        print(
            f"ERROR: invalid value for hss.roaming.inbound.reject_unknown_imsis_with: '{reject_cause}'. "
            f"Valid options are: {', '.join(sorted(valid_reject_causes))}"
        )
        sys.exit(1)

    validate_udr_config(config.get("udr") or {})


def validate_udr_config(udr):
    def fail(message):
        print(f"ERROR: invalid udr config: {message}")
        sys.exit(1)

    snssai = udr.get("default_snssai") or {}
    if "sst" in snssai and not (isinstance(snssai["sst"], int) and 0 <= snssai["sst"] <= 255):
        fail(f"default_snssai.sst must be 0..255, not '{snssai['sst']}'")
    sd = snssai.get("sd")
    if sd is not None and not re.fullmatch(r"[0-9A-Fa-f]{6}", str(sd)):
        fail(f"default_snssai.sd must be 6 hex digits or null, not '{sd}'")
    if udr.get("sqn_patch_policy", "max") not in ("max", "set"):
        fail(f"sqn_patch_policy must be 'max' or 'set', not '{udr['sqn_patch_policy']}'")
    if udr.get("nf_instance_id"):
        try:
            uuid.UUID(str(udr["nf_instance_id"]))
        except ValueError:
            fail(f"nf_instance_id must be a UUID, not '{udr['nf_instance_id']}'")
    if not isinstance(udr.get("bind_port", 7777), int):
        fail(f"bind_port must be a number, not '{udr['bind_port']}'")
    for version in udr.get("api_versions", ["v1"]):
        if not re.fullmatch(r"v[0-9]+", str(version)):
            fail(f"api_versions must be like 'v1', not '{version}'")


load_config()
validate_config()


def get_unknown_subscriber_2g_reject_cause() -> GMMCause:
    if (
        config.get("hss", {}).get("roaming", {}).get("inbound", {}).get("reject_unknown_imsis_with", "IMSI_UNKNOWN")
        == "ROAMING_NOT_ALLOWED"
    ):
        return GMMCause.ROAMING_NOTALLOWED
    else:
        return GMMCause.IMSI_UNKNOWN
