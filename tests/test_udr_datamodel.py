# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import copy

import pytest
from sbi import models
from udr import datamodel

DEFAULT_SNSSAI = {"sst": 1, "sd": None}


def apn(apn_id, name, **kwargs):
    data = {
        "apn_id": apn_id,
        "apn": name,
        "ip_version": 2,
        "apn_ambr_dl": 1000000000,
        "apn_ambr_ul": 1000000000,
        "qci": 9,
        "arp_priority": 8,
        "arp_preemption_capability": False,
        "arp_preemption_vulnerability": True,
        "sst": None,
        "sd": None,
    }
    data.update(kwargs)
    return data


# What Database.Get_5G_Subscription() returns for a subscriber like those in the Open5GS testbed
SUB = {
    "subscriber": {
        "subscriber_id": 1,
        "imsi": "001010000000001",
        "msisdn": None,
        "ue_ambr_dl": 1000000000,
        "ue_ambr_ul": 1000000000,
    },
    "auc": {
        "auc_id": 1,
        "ki": "465B5CE8B199B49FAA5F0A2EE238A6BC",
        "opc": "E8ED289DEBA952E4283B54E88E6183CA",
        "amf": "8000",
        "sqn": 33,
    },
    "apns": [apn(1, "internet")],
    "routing": {},
}

INTERNET_DNN_CONFIGURATION = {
    "pduSessionTypes": {"defaultSessionType": "IPV4V6", "allowedSessionTypes": ["IPV4", "IPV6", "IPV4V6"]},
    "sscModes": {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]},
    "5gQosProfile": {"5qi": 9, "arp": {"priorityLevel": 8, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE"}},
    "sessionAmbr": {"uplink": "1 Gbps", "downlink": "1 Gbps"},
}


def multi_slice_sub():
    sub = copy.deepcopy(SUB)
    sub["subscriber"]["msisdn"] = "+491701234567"
    sub["apns"] = [
        apn(1, "internet"),
        apn(
            2,
            "ims",
            qci=5,
            arp_priority=1,
            arp_preemption_capability=True,
            arp_preemption_vulnerability=False,
            apn_ambr_dl=256000,
            apn_ambr_ul=128000,
            ip_version=0,
            sst=1,
        ),
        apn(3, "iot", sst=2, sd="0000AB", ip_version=1, apn_ambr_dl=1500, apn_ambr_ul=1500),
        apn(4, "broken", apn_ambr_dl=0, apn_ambr_ul=0),
    ]
    sub["routing"] = {2: {"apn_id": 2, "ip_address": "10.46.0.5"}, 3: {"apn_id": 3, "ip_address": "2001:db8::5"}}
    return sub


@pytest.mark.parametrize(
    ("bps", "expected"),
    [
        (0, "0 bps"),
        (999999, "999999 bps"),
        (1500, "1500 bps"),
        (256000, "256 Kbps"),
        (5000000, "5 Mbps"),
        (1000000000, "1 Gbps"),
        (None, "0 bps"),
    ],
)
def test_bitrate(bps, expected):
    assert datamodel.bitrate(bps) == expected
    models.BitRate(expected)  # matches the 3GPP BitRate pattern


def test_authentication_subscription():
    assert datamodel.dump(datamodel.authentication_subscription(SUB)) == {
        "authenticationMethod": "5G_AKA",
        "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
        "authenticationManagementField": "8000",
        "sequenceNumber": {"sqn": "000000000021"},
    }


def test_am_data_open5gs_testbed():
    assert datamodel.dump(datamodel.am_data(SUB, DEFAULT_SNSSAI)) == {
        "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "1 Gbps"},
        "nssai": {"defaultSingleNssais": [{"sst": 1}]},
    }


def test_am_data_multi_slice_and_fields():
    sub = multi_slice_sub()
    assert datamodel.dump(datamodel.am_data(sub, DEFAULT_SNSSAI)) == {
        "gpsis": ["msisdn-491701234567"],
        "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "1 Gbps"},
        "nssai": {"defaultSingleNssais": [{"sst": 1}], "singleNssais": [{"sst": 2, "sd": "0000ab"}]},
    }
    assert datamodel.dump(datamodel.am_data(sub, DEFAULT_SNSSAI, fields=["nssai"])) == {
        "nssai": {"defaultSingleNssais": [{"sst": 1}], "singleNssais": [{"sst": 2, "sd": "0000ab"}]},
    }


def test_am_data_no_ue_ambr():
    sub = copy.deepcopy(SUB)
    sub["subscriber"]["ue_ambr_dl"] = 0
    sub["subscriber"]["ue_ambr_ul"] = 0
    assert datamodel.am_data(sub, DEFAULT_SNSSAI) is None


def test_default_snssai_with_sd():
    assert datamodel.dump(datamodel.am_data(SUB, {"sst": 3, "sd": "ABCDEF"}).nssai) == {
        "defaultSingleNssais": [{"sst": 3, "sd": "abcdef"}],
    }


def test_smf_selection_data():
    assert datamodel.dump(datamodel.smf_selection_data(SUB, DEFAULT_SNSSAI)) == {
        "subscribedSnssaiInfos": {"1": {"dnnInfos": [{"dnn": "internet", "defaultDnnIndicator": True}]}},
    }
    warnings = []
    assert datamodel.dump(datamodel.smf_selection_data(multi_slice_sub(), DEFAULT_SNSSAI, warnings.append)) == {
        "subscribedSnssaiInfos": {
            "1": {"dnnInfos": [{"dnn": "internet", "defaultDnnIndicator": True}, {"dnn": "ims"}]},
            "2-0000ab": {"dnnInfos": [{"dnn": "iot"}]},
        },
    }
    assert warnings == ["APN broken skipped for 5G, missing: apn_ambr"]


def test_smf_selection_data_no_usable_apn():
    sub = copy.deepcopy(SUB)
    sub["apns"] = [apn(1, "internet", qci=None)]
    assert datamodel.smf_selection_data(sub, DEFAULT_SNSSAI) is None


def test_sm_data_open5gs_testbed():
    assert datamodel.dump(datamodel.sm_data(SUB, DEFAULT_SNSSAI)) == [
        {"singleNssai": {"sst": 1}, "dnnConfigurations": {"internet": INTERNET_DNN_CONFIGURATION}},
    ]


def test_sm_data_multi_slice_and_filters():
    sub = multi_slice_sub()
    assert datamodel.dump(datamodel.sm_data(sub, DEFAULT_SNSSAI)) == [
        {
            "singleNssai": {"sst": 1},
            "dnnConfigurations": {
                "internet": INTERNET_DNN_CONFIGURATION,
                "ims": {
                    "pduSessionTypes": {"defaultSessionType": "IPV4", "allowedSessionTypes": ["IPV4"]},
                    "sscModes": {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]},
                    "5gQosProfile": {
                        "5qi": 5,
                        "arp": {"priorityLevel": 1, "preemptCap": "MAY_PREEMPT", "preemptVuln": "NOT_PREEMPTABLE"},
                    },
                    "sessionAmbr": {"uplink": "128 Kbps", "downlink": "256 Kbps"},
                    "staticIpAddress": [{"ipv4Addr": "10.46.0.5"}],
                },
            },
        },
        {
            "singleNssai": {"sst": 2, "sd": "0000ab"},
            "dnnConfigurations": {
                "iot": {
                    "pduSessionTypes": {"defaultSessionType": "IPV6", "allowedSessionTypes": ["IPV6"]},
                    "sscModes": {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]},
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE"},
                    },
                    "sessionAmbr": {"uplink": "1500 bps", "downlink": "1500 bps"},
                    "staticIpAddress": [{"ipv6Addr": "2001:db8::5"}],
                },
            },
        },
    ]
    sst2 = datamodel.parse_snssai('{"sst":2,"sd":"0000AB"}')
    assert [x.singleNssai.sst for x in datamodel.sm_data(sub, DEFAULT_SNSSAI, single_nssai=sst2)] == [2]
    result = datamodel.sm_data(sub, DEFAULT_SNSSAI, dnn="IMS")
    assert [list(x.dnnConfigurations) for x in result] == [["ims"]]
    assert datamodel.sm_data(sub, DEFAULT_SNSSAI, single_nssai=sst2, dnn="ims") == []


def test_provisioned_data_sets():
    result = datamodel.dump(datamodel.provisioned_data_sets(SUB, DEFAULT_SNSSAI, ["AM", "SMF_SEL", "SM"]))
    assert result == {
        "amData": datamodel.dump(datamodel.am_data(SUB, DEFAULT_SNSSAI)),
        "smfSelData": datamodel.dump(datamodel.smf_selection_data(SUB, DEFAULT_SNSSAI)),
        "smData": datamodel.dump(datamodel.sm_data(SUB, DEFAULT_SNSSAI)),
    }
    assert datamodel.dump(datamodel.provisioned_data_sets(SUB, DEFAULT_SNSSAI, ["SMF_SEL"])) == {
        "smfSelData": result["smfSelData"],
    }


def test_policy_data():
    assert datamodel.dump(datamodel.am_policy_data(SUB)) == {}
    sub = multi_slice_sub()
    sst2 = datamodel.parse_snssai('{"sst":2,"sd":"0000ab"}')
    assert datamodel.dump(datamodel.sm_policy_data(sub, DEFAULT_SNSSAI, sst2)) == {
        "smPolicySnssaiData": {
            "2-0000ab": {"snssai": {"sst": 2, "sd": "0000ab"}, "smPolicyDnnData": {"iot": {"dnn": "iot"}}}
        },
    }
    sst1 = datamodel.parse_snssai('{"sst":1}')
    assert datamodel.dump(datamodel.sm_policy_data(sub, DEFAULT_SNSSAI, sst1, dnn="internet")) == {
        "smPolicySnssaiData": {"1": {"snssai": {"sst": 1}, "smPolicyDnnData": {"internet": {"dnn": "internet"}}}},
    }
    assert datamodel.sm_policy_data(sub, DEFAULT_SNSSAI, datamodel.parse_snssai('{"sst":3}')) is None
