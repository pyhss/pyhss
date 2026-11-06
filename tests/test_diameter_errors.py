# Copyright 2026 phatlc <phatle.hsd@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression tests for nickvsnetworking/pyhss#308: a request with a missing or
# malformed AVP must be answered with an error Result-Code instead of being
# dropped, which makes the peer wait for the transaction to time out.
import pytest
from diameter import Diameter, DiameterInvalidAvpValue
from logtool import LogTool
from pyhss_config import config

IMSI = "505931111111116"
DOMAIN = "nickvsnetworking.com"
CX_VENDOR_SPECIFIC_APPLICATION_ID = "0000010a4000000c000028af000001024000000c01000000"


@pytest.fixture(autouse=True)
def autouse_fixtures(create_test_db):
    return


@pytest.fixture(scope="session")
def diameter():
    return Diameter(LogTool(config), "hss01", "epc.mnc001.mcc001.3gppnetwork.org", "PyHSS", "001", "01")


def build_request(diameter, command_code, application_id, avps):
    return diameter.generate_diameter_packet("01", "c0", command_code, application_id, "00000001", "00000002", avps)


def common_avps(diameter, session_id):
    avps = ""
    if session_id:
        avps += diameter.generate_avp(263, 40, diameter.string_to_hex("scscf01;abcde;1;app_cx"))
    avps += diameter.generate_avp(264, 40, diameter.string_to_hex("scscf01"))
    avps += diameter.generate_avp(296, 40, diameter.string_to_hex("ims.mnc001.mcc001.3gppnetwork.org"))
    avps += diameter.generate_avp(283, 40, diameter.string_to_hex("localdomain"))
    avps += diameter.generate_avp(260, 40, CX_VENDOR_SPECIFIC_APPLICATION_ID)
    avps += diameter.generate_avp(277, 40, "00000001")
    return avps


def mar_request(diameter, session_id=True, username=f"{IMSI}@{DOMAIN}", public_identity=True):
    avps = common_avps(diameter, session_id)
    if isinstance(username, bytes):
        avps += diameter.generate_avp(1, 40, username.hex())
    else:
        avps += diameter.generate_avp(1, 40, diameter.string_to_hex(username))
    if public_identity:
        avps += diameter.generate_vendor_avp(601, "c0", 10415, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(607, "c0", 10415, "00000001")
    sip_auth_data_item = diameter.generate_vendor_avp(608, "c0", 10415, diameter.string_to_hex("Digest-AKAv1-MD5"))
    avps += diameter.generate_vendor_avp(612, "c0", 10415, sip_auth_data_item)
    return build_request(diameter, 303, 16777216, avps)


def uar_request(diameter, session_id=True):
    avps = common_avps(diameter, session_id)
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(f"{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(601, "c0", 10415, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(600, "c0", 10415, diameter.string_to_hex(DOMAIN))
    return build_request(diameter, 300, 16777216, avps)


def answer(diameter, request):
    response = diameter.generateDiameterResponse(bytes.fromhex(request))
    assert response, "request was dropped instead of answered"
    packet_vars, avps = diameter.decode_diameter_packet(bytes.fromhex(response))
    assert packet_vars["hop-by-hop-identifier"] == "00000001"
    assert packet_vars["end-to-end-identifier"] == "00000002"
    assert packet_vars["flags"] == "40"
    return packet_vars, avps


def assert_common_error_avps(diameter, avps):
    assert diameter.get_avp_data(avps, 264) == [diameter.string_to_hex("hss01")]
    assert diameter.get_avp_data(avps, 296) == [diameter.string_to_hex("epc.mnc001.mcc001.3gppnetwork.org")]
    # Vendor-Specific-Application-Id is echoed from the request with its sub AVPs intact
    vendor_specific_application_id = diameter.get_avp_data(avps, 260)
    assert [(a["avp_code"], a["misc_data"]) for a in vendor_specific_application_id[0]] == [
        (266, "000028af"),
        (258, "01000000"),
    ]
    assert diameter.get_avp_data(avps, 277) == ["00000001"]


def top_level_avp_codes(avps):
    # get_avp_data() also searches inside grouped AVPs, so the Failed-AVP contents would show up there
    return [a["avp_code"] for a in avps]


def failed_avp(diameter, avps):
    failed_avps = diameter.get_avp_data(avps, 279)
    assert len(failed_avps) == 1
    assert len(failed_avps[0]) == 1
    return failed_avps[0][0]


def test_mar_without_session_id_is_answered_with_missing_avp(diameter):
    packet_vars, avps = answer(diameter, mar_request(diameter, session_id=False))
    assert packet_vars["command_code"] == 303
    assert packet_vars["ApplicationId"] == 16777216
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5005, 4)]
    assert diameter.get_avp_data(avps, 298) == []
    assert 263 not in top_level_avp_codes(avps)
    assert_common_error_avps(diameter, avps)
    assert failed_avp(diameter, avps)["avp_code"] == 263


def test_mar_user_name_without_domain_is_answered_with_invalid_avp_value(diameter):
    _, avps = answer(diameter, mar_request(diameter, username=IMSI))
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5004, 4)]
    assert diameter.get_avp_data(avps, 298) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]
    assert_common_error_avps(diameter, avps)
    user_name = failed_avp(diameter, avps)
    assert user_name["avp_code"] == 1
    assert user_name["misc_data"] == diameter.string_to_hex(IMSI)


def test_mar_without_public_identity_is_answered_with_missing_avp(diameter):
    _, avps = answer(diameter, mar_request(diameter, public_identity=False))
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5005, 4)]
    assert diameter.get_avp_data(avps, 298) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]
    assert_common_error_avps(diameter, avps)
    public_identity = failed_avp(diameter, avps)
    assert public_identity["avp_code"] == 601
    assert public_identity["vendor_id"] == 10415


def test_mar_user_name_that_is_not_utf8_is_answered_with_invalid_avp_value(diameter):
    _, avps = answer(diameter, mar_request(diameter, username=b"\xfe\xff"))
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5004, 4)]
    assert diameter.get_avp_data(avps, 298) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]
    assert_common_error_avps(diameter, avps)
    user_name = failed_avp(diameter, avps)
    assert (user_name["avp_code"], user_name["misc_data"]) == (1, "feff")


def test_uar_without_session_id_is_answered_with_missing_avp(diameter):
    packet_vars, avps = answer(diameter, uar_request(diameter, session_id=False))
    assert packet_vars["command_code"] == 300
    assert packet_vars["ApplicationId"] == 16777216
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5005, 4)]
    assert diameter.get_avp_data(avps, 298) == []
    assert 263 not in top_level_avp_codes(avps)
    assert_common_error_avps(diameter, avps)
    assert failed_avp(diameter, avps)["avp_code"] == 263


def test_valid_mar_is_still_answered_normally(diameter):
    # The IMSI is unknown to the test database, so a well-formed MAR is answered with
    # DIAMETER_ERROR_USER_UNKNOWN (5001) by the handler itself, exactly as before
    _, avps = answer(diameter, mar_request(diameter))
    assert diameter.get_avp_data(avps, 268) == []
    assert diameter.get_avp_data(avps, 298) == [diameter.int_to_hex(5001, 4)]
    assert diameter.get_avp_data(avps, 279) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]


S6A_VENDOR_SPECIFIC_APPLICATION_ID = "0000010a4000000c000028af000001024000000c01000023"


def pur_request(diameter, session_id=True):
    avps = common_avps(diameter, session_id).replace(
        CX_VENDOR_SPECIFIC_APPLICATION_ID, S6A_VENDOR_SPECIFIC_APPLICATION_ID
    )
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(IMSI))
    return build_request(diameter, 321, 16777251, avps)


def make_handler_raise(monkeypatch, diameter, command_code, application_id):
    for entry in diameter.diameterResponseList:
        if entry["commandCode"] == command_code and entry["applicationId"] == application_id:

            def raising_handler(packet_vars, avps):
                raise RuntimeError("simulated handler failure")

            monkeypatch.setitem(entry, "responseMethod", raising_handler)
            return entry
    raise AssertionError("no diameterResponseList entry found")


def test_empty_session_id_avp_is_answered_with_invalid_avp_value(diameter):
    # A Session-Id AVP that is present but carries no payload is an invalid value (5004), and the
    # received AVP is returned in Failed-AVP; it is not echoed as the answer's Session-Id
    avps = common_avps(diameter, session_id=False)
    avps += diameter.generate_avp(263, 40, "")
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(f"{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(601, "c0", 10415, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    _, answer_avps = answer(diameter, build_request(diameter, 303, 16777216, avps))
    assert diameter.get_avp_data(answer_avps, 268) == [diameter.int_to_hex(5004, 4)]
    assert diameter.get_avp_data(answer_avps, 298) == []
    assert 263 not in top_level_avp_codes(answer_avps)
    session_id = failed_avp(diameter, answer_avps)
    assert (session_id["avp_code"], session_id["avp_flags"], session_id["misc_data"]) == (263, "40", "")


def test_base_failure_code_is_sent_in_result_code_for_3gpp_application(diameter, monkeypatch):
    # PUR (S6a) falls back to DIAMETER_UNABLE_TO_COMPLY (5012), an RFC 6733 code: it must go in
    # Result-Code even though the application id is not 0, never in Experimental-Result
    make_handler_raise(monkeypatch, diameter, 321, 16777251)
    packet_vars, avps = answer(diameter, pur_request(diameter))
    assert packet_vars["command_code"] == 321
    assert packet_vars["ApplicationId"] == 16777251
    assert diameter.get_avp_data(avps, 268) == [diameter.int_to_hex(5012, 4)]
    assert diameter.get_avp_data(avps, 297) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]


def test_experimental_failure_code_is_sent_in_experimental_result(diameter, monkeypatch):
    # UAR (Cx) falls back to 4100, a 3GPP Experimental-Result-Code, so it keeps using Experimental-Result
    make_handler_raise(monkeypatch, diameter, 300, 16777216)
    _, avps = answer(diameter, uar_request(diameter))
    assert diameter.get_avp_data(avps, 268) == []
    experimental_result = diameter.get_avp_data(avps, 297)
    assert [(a["avp_code"], a["misc_data"]) for a in experimental_result[0]] == [
        (266, "000028af"),
        (298, diameter.int_to_hex(4100, 4)),
    ]


def test_failed_error_answer_is_not_counted_as_successful(diameter, monkeypatch):
    # If building the error answer itself fails, the request is dropped as before and counted as a
    # failed response, not a successful one
    metrics = []
    monkeypatch.setattr(diameter.redisMessaging, "sendMetric", lambda **kwargs: metrics.append(kwargs["metricName"]))
    make_handler_raise(monkeypatch, diameter, 321, 16777251)

    def broken_error_answer(*args, **kwargs):
        raise RuntimeError("cannot build the error answer")

    monkeypatch.setattr(diameter, "Respond_ResultCode", broken_error_answer)
    assert diameter.generateDiameterResponse(bytes.fromhex(pur_request(diameter))) == ""
    assert "prom_diam_response_count_application_id_successful" not in metrics
    assert "prom_diam_response_count_application_id_fail" in metrics


def test_vendor_specific_application_id_echo_keeps_vendor_zero_sub_avp(diameter, monkeypatch):
    # The decoder reports vendor_id as '' when the V bit is clear and as an int, possibly 0, when it
    # is set; a sub AVP with Vendor-Id 0 and the V bit set must be echoed with the V bit intact
    make_handler_raise(monkeypatch, diameter, 321, 16777251)
    avps = common_avps(diameter, session_id=True)
    avps = avps.replace(diameter.generate_avp(260, 40, CX_VENDOR_SPECIFIC_APPLICATION_ID), "")
    vendor_zero_sub_avp = diameter.generate_vendor_avp(258, "c0", 0, "01000001")
    avps += diameter.generate_avp(260, 40, diameter.generate_avp(266, 40, "000028af") + vendor_zero_sub_avp)
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(IMSI))
    _, answer_avps = answer(diameter, build_request(diameter, 321, 16777251, avps))
    echoed = diameter.get_avp_data(answer_avps, 260)[0]
    assert [(a["avp_code"], a["vendor_id"], a["avp_flags"], a["misc_data"]) for a in echoed] == [
        (266, "", "40", "000028af"),
        (258, 0, "c0", "01000001"),
    ]


def test_nested_session_id_does_not_satisfy_the_top_level_requirement(diameter):
    # A Session-Id inside a grouped AVP is not the request's Session-Id: the request is still missing it
    avps = common_avps(diameter, session_id=False)
    avps += diameter.generate_avp(279, 40, diameter.generate_avp(263, 40, diameter.string_to_hex("nested")))
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(f"{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(601, "c0", 10415, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    _, answer_avps = answer(diameter, build_request(diameter, 303, 16777216, avps))
    assert diameter.get_avp_data(answer_avps, 268) == [diameter.int_to_hex(5005, 4)]
    assert 263 not in top_level_avp_codes(answer_avps)
    assert failed_avp(diameter, answer_avps)["avp_code"] == 263


def test_public_identity_with_the_wrong_vendor_id_is_missing(diameter):
    # Public-Identity is a 3GPP AVP: a code 601 without the V bit does not satisfy the requirement
    avps = common_avps(diameter, session_id=True)
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(f"{IMSI}@{DOMAIN}"))
    avps += diameter.generate_avp(601, 40, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    _, answer_avps = answer(diameter, build_request(diameter, 303, 16777216, avps))
    assert diameter.get_avp_data(answer_avps, 268) == [diameter.int_to_hex(5005, 4)]
    public_identity = failed_avp(diameter, answer_avps)
    assert (public_identity["avp_code"], public_identity["vendor_id"]) == (601, 10415)


def test_answered_error_counts_one_failed_response_and_no_successful_one(diameter, monkeypatch):
    metrics = []
    monkeypatch.setattr(diameter.redisMessaging, "sendMetric", lambda **kwargs: metrics.append(kwargs["metricName"]))
    answer(diameter, mar_request(diameter, session_id=False))
    assert metrics.count("prom_diam_response_count_application_id_fail") == 1
    assert "prom_diam_response_count_application_id_successful" not in metrics


def test_unmatched_command_is_dropped_and_counted_as_failed(diameter, monkeypatch):
    metrics = []
    monkeypatch.setattr(diameter.redisMessaging, "sendMetric", lambda **kwargs: metrics.append(kwargs["metricName"]))
    assert (
        diameter.generateDiameterResponse(
            bytes.fromhex(build_request(diameter, 999, 16777216, common_avps(diameter, True)))
        )
        == ""
    )
    assert metrics.count("prom_diam_response_count_application_id_fail") == 1
    assert "prom_diam_response_count_application_id_successful" not in metrics


def test_error_answer_survives_a_header_only_sub_avp_in_vendor_specific_application_id(diameter):
    # The decoder yields [] for an empty payload; echoing 260 must not pass that to the encoder
    avps = common_avps(diameter, session_id=False).replace(
        diameter.generate_avp(260, 40, CX_VENDOR_SPECIFIC_APPLICATION_ID), ""
    )
    avps += diameter.generate_avp(
        260, 40, diameter.generate_avp(266, 40, "") + diameter.generate_avp(258, 40, "01000000")
    )
    avps += diameter.generate_avp(1, 40, diameter.string_to_hex(f"{IMSI}@{DOMAIN}"))
    avps += diameter.generate_vendor_avp(601, "c0", 10415, diameter.string_to_hex(f"sip:{IMSI}@{DOMAIN}"))
    _, answer_avps = answer(diameter, build_request(diameter, 303, 16777216, avps))
    assert diameter.get_avp_data(answer_avps, 268) == [diameter.int_to_hex(5005, 4)]
    echoed = diameter.get_avp_data(answer_avps, 260)[0]
    assert [(a["avp_code"], a["misc_data"]) for a in echoed] == [(266, ""), (258, "01000000")]


def test_failed_avp_keeps_vendor_id_zero(diameter, monkeypatch):
    for entry in diameter.diameterResponseList:
        if entry["commandCode"] == 321 and entry["applicationId"] == 16777251:

            def raising_handler(packet_vars, avps):
                raise DiameterInvalidAvpValue(258, avp_data="01000001", vendor_id=0)

            monkeypatch.setitem(entry, "responseMethod", raising_handler)
    _, answer_avps = answer(diameter, pur_request(diameter))
    assert diameter.get_avp_data(answer_avps, 268) == [diameter.int_to_hex(5004, 4)]
    bad = failed_avp(diameter, answer_avps)
    assert (bad["avp_code"], bad["vendor_id"], bad["avp_flags"], bad["misc_data"]) == (258, 0, "c0", "01000001")
