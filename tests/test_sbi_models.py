# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import filecmp
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from sbi import models

top_dir = Path(__file__).resolve().parent.parent

# Bodies sent and accepted by Open5GS v2.8.0 NFs (taken from a capture of an Open5GS
# testbed), each one paired with the 3GPP schema it has to conform to.
REFERENCE_BODIES = [
    (
        models.AuthenticationSubscription,
        {
            "authenticationMethod": "5G_AKA",
            "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc",
            "sequenceNumber": {"sqn": "000000000000"},
            "authenticationManagementField": "8000",
            "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
        },
    ),
    (
        models.AccessAndMobilitySubscriptionData,
        {
            "subscribedUeAmbr": {"uplink": "1000000 Kbps", "downlink": "1000000 Kbps"},
            "nssai": {"defaultSingleNssais": [{"sst": 1}]},
        },
    ),
    (
        models.SmfSelectionSubscriptionData,
        {"subscribedSnssaiInfos": {"1": {"dnnInfos": [{"dnn": "internet", "defaultDnnIndicator": True}]}}},
    ),
    (
        models.SessionManagementSubscriptionData,
        {
            "singleNssai": {"sst": 1},
            "dnnConfigurations": {
                "internet": {
                    "pduSessionTypes": {"defaultSessionType": "IPV4V6", "allowedSessionTypes": ["IPV4", "IPV6"]},
                    "sscModes": {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]},
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE"},
                        "priorityLevel": 8,
                    },
                    "sessionAmbr": {"uplink": "1000000 Kbps", "downlink": "1000000 Kbps"},
                }
            },
        },
    ),
    (
        models.SmPolicyData,
        {"smPolicySnssaiData": {"1": {"snssai": {"sst": 1}, "smPolicyDnnData": {"internet": {"dnn": "internet"}}}}},
    ),
    (models.AmPolicyData, {}),
    (models.PatchItem, {"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000021"}),
    (
        models.AuthEvent,
        {
            "nfInstanceId": "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab",
            "success": True,
            "timeStamp": "2026-10-19T09:07:41.123456Z",
            "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
        },
    ),
    (
        models.Amf3GppAccessRegistration,
        {
            "amfInstanceId": "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab",
            "deregCallbackUri": "http://10.33.33.20:7777/namf-callback/v1/imsi-001010000000001/dereg-notify",
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
            "ratType": "NR",
            "pei": "imeisv-4370816125816151",
        },
    ),
    (
        models.NFProfile,
        {
            "nfInstanceId": "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab",
            "nfType": "UDR",
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "ipv4Addresses": ["10.33.33.18"],
            "nfServices": [
                {
                    "serviceInstanceId": "nudr-dr",
                    "serviceName": "nudr-dr",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address": "10.33.33.18", "transport": "TCP", "port": 7777}],
                }
            ],
        },
    ),
    (models.ProblemDetails, {"title": "Not Found", "status": 404, "cause": "USER_NOT_FOUND"}),
]


@pytest.mark.parametrize(("model", "body"), REFERENCE_BODIES, ids=lambda x: getattr(x, "__name__", ""))
def test_reference_bodies_round_trip(model, body):
    obj = model.model_validate(body)
    assert obj.model_dump(mode="json", by_alias=True, exclude_unset=True) == body


def test_spec_constraints_enforced():
    # TS 29.503 SscModes: allowedSscModes lists at most 2 modes besides the default
    with pytest.raises(ValueError):
        models.SscModes.model_validate(
            {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]}
        )
    with pytest.raises(ValueError):
        models.AuthenticationSubscription.model_validate(
            {"authenticationMethod": "5G_AKA", "authenticationManagementField": "80000"}
        )


def test_construct_by_field_name():
    # Fields that start with a digit get a python name; the 3GPP name is the alias
    profile = models.SubscribedDefaultQos(
        field_5qi=9, arp=models.Arp(priorityLevel=8, preemptCap="NOT_PREEMPT", preemptVuln="PREEMPTABLE")
    )
    assert profile.model_dump(mode="json", by_alias=True, exclude_unset=True)["5qi"] == 9


@pytest.mark.skip_packaging
@pytest.mark.skipif(
    importlib.util.find_spec("datamodel_code_generator") is None,
    reason="datamodel-code-generator not installed (requirements-dev.txt)",
)
def test_models_up_to_date(tmp_path):
    out = tmp_path / "models"
    subprocess.run([sys.executable, top_dir / "tools/gen_sbi_models.py", "--out", out], check=True)
    generated = out / "__init__.py"
    committed = top_dir / "lib/sbi/models/__init__.py"
    assert filecmp.cmp(generated, committed, shallow=False), (
        "lib/sbi/models/ is out of date, run tools/gen_sbi_models.py"
    )
