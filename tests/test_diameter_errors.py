# Copyright 2026 phatlc <phatle.hsd@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression tests for nickvsnetworking/pyhss#308: a request with a missing or
# malformed AVP must be answered with an error Result-Code instead of being
# dropped, which makes the peer wait for the transaction to time out.
import pytest
from diameter import Diameter
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


def test_handler_exception_is_answered_with_failure_result_code(diameter):
    # A User-Name that is not valid UTF-8 makes the handler raise UnicodeDecodeError,
    # which is answered with the command's failureResultCode (4100 for MAR) as Experimental-Result
    _, avps = answer(diameter, mar_request(diameter, username=b"\xfe\xff"))
    assert diameter.get_avp_data(avps, 268) == []
    experimental_result = diameter.get_avp_data(avps, 297)
    assert [(a["avp_code"], a["misc_data"]) for a in experimental_result[0]] == [
        (266, "000028af"),
        (298, diameter.int_to_hex(4100, 4)),
    ]
    assert diameter.get_avp_data(avps, 279) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]
    assert_common_error_avps(diameter, avps)


def test_uar_without_session_id_is_answered(diameter):
    packet_vars, avps = answer(diameter, uar_request(diameter, session_id=False))
    assert packet_vars["command_code"] == 300
    assert packet_vars["ApplicationId"] == 16777216
    assert diameter.get_avp_data(avps, 268) == []
    assert diameter.get_avp_data(avps, 298) == [diameter.int_to_hex(4100, 4)]
    assert 263 not in top_level_avp_codes(avps)
    assert_common_error_avps(diameter, avps)


def test_valid_mar_is_still_answered_normally(diameter):
    # The IMSI is unknown to the test database, so a well-formed MAR is answered with
    # DIAMETER_ERROR_USER_UNKNOWN (5001) by the handler itself, exactly as before
    _, avps = answer(diameter, mar_request(diameter))
    assert diameter.get_avp_data(avps, 268) == []
    assert diameter.get_avp_data(avps, 298) == [diameter.int_to_hex(5001, 4)]
    assert diameter.get_avp_data(avps, 279) == []
    assert diameter.get_avp_data(avps, 263) == [diameter.string_to_hex("scscf01;abcde;1;app_cx")]
