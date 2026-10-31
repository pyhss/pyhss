# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from pcf import datamodel


@pytest.mark.parametrize(
    "description,direction,expected",
    [
        ("permit out 17 from 1.1.1.1 100 to 2.2.2.2 200", "DOWNLINK", "permit out 17 from 1.1.1.1 100 to 2.2.2.2 200"),
        ("permit in 17 from 2.2.2.2 200 to 1.1.1.1 100", "UPLINK", "permit out 17 from 1.1.1.1 100 to 2.2.2.2 200"),
        ("permit in ip from any to any", "UPLINK", "permit out ip from any to any"),
        ("permit in 6 from 2.2.2.2 to 1.1.1.1", "UPLINK", "permit out 6 from 1.1.1.1 to 2.2.2.2"),
        (
            "permit out 17 from 1.1.1.1/32 100-200 to 2.2.2.2",
            "DOWNLINK",
            "permit out 17 from 1.1.1.1/32 100-200 to 2.2.2.2",
        ),
    ],
)
def test_flow_information_as_open5gs_rewrites_rx_flows(description, direction, expected):
    assert datamodel.flow_information(description) == {"flowDescription": expected, "flowDirection": direction}


def test_flow_information_rejects_other_actions():
    with pytest.raises(ValueError):
        datamodel.flow_information("deny out 17 from any to any")
    with pytest.raises(ValueError):
        datamodel.flow_information("permit in 17 from any")


@pytest.mark.parametrize(
    "text,bps",
    [
        ("41 Kbps", 41000),
        ("1.5 Mbps", 1500000),
        ("2 Gbps", 2000000000),
        ("100 bps", 100),
        ("1 Tbps", 10**12),
        (None, 0),
    ],
)
def test_bitrate_bps(text, bps):
    assert datamodel.bitrate_bps(text) == bps


def test_bare_dnn():
    assert datamodel.bare_dnn("ims.mnc001.mcc001.gprs") == "ims"
    assert datamodel.bare_dnn("IMS") == "ims"


def media(**values):
    return {
        "number": 1,
        "type": "AUDIO",
        "mar_dl": 0,
        "mar_ul": 0,
        "mir_dl": 0,
        "mir_ul": 0,
        "rr": 0,
        "rs": 0,
        "flows": ["permit out 17 from 1.1.1.1 1 to 2.2.2.2 2"],
        **values,
    }


def test_voice_defaults_when_the_af_requests_no_bandwidth():
    rules, qos = datamodel.media_decision([media()], "abc", {})
    assert list(rules) == ["af-abc-1"]
    assert rules["af-abc-1"]["precedence"] == 40
    assert qos["af-abc-1"]["5qi"] == 1
    assert qos["af-abc-1"]["maxbrDl"] == qos["af-abc-1"]["gbrDl"] == "128 Kbps"


def test_video_is_5qi_2():
    rules, qos = datamodel.media_decision([media(type="VIDEO", mar_dl=2000000, mar_ul=1000000)], "abc", {})
    assert qos["af-abc-1"]["5qi"] == 2
    assert qos["af-abc-1"]["maxbrDl"] == "2 Mbps"
    assert qos["af-abc-1"]["gbrUl"] == "1 Mbps"
    assert rules["af-abc-1"]["precedence"] == 30


def test_requested_minimum_is_the_gbr_and_rtcp_bandwidth_is_added_to_the_mbr():
    _, qos = datamodel.media_decision([media(mar_dl=64000, mir_dl=32000, rr=1000, rs=2000)], "abc", {})
    assert qos["af-abc-1"]["gbrDl"] == "32 Kbps"
    assert qos["af-abc-1"]["maxbrDl"] == "67 Kbps"


def test_qos_is_configurable():
    config = {"qos": {"audio": {"5qi": 65, "arp_priority": 7, "precedence": 11, "bandwidth": 64000}}}
    rules, qos = datamodel.media_decision([media()], "abc", config)
    assert qos["af-abc-1"]["5qi"] == 65
    assert qos["af-abc-1"]["arp"]["priorityLevel"] == 7
    assert qos["af-abc-1"]["maxbrUl"] == "64 Kbps"
    assert rules["af-abc-1"]["precedence"] == 11


def test_control_data_and_flowless_media_get_no_rule():
    components = [media(type="CONTROL"), media(number=2, type="DATA"), media(number=3, flows=[])]
    assert datamodel.media_decision(components, "abc", {}) == ({}, {})
