# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import json

import diameter as DiameterLib
from logtool import LogTool
from pcf import policy, rx
from pcf.store import PcfStore
from pyhss_config import config
from test_pcf_app import UE_IP, FakeNotifier, FakeRedis

SMF_URI = "http://10.70.0.14:7777/nsmf-callback/v1/sm-policy-notify/1"
RX_APP = 16777236
RX_SESSION = "pcscf.ims;1;2"


def diameter():
    return DiameterLib.Diameter(LogTool(config), "pcf", "realm", "test", "001", "01")


def vendor(d, code, data):
    return d.generate_vendor_avp(code, "c0", 10415, data)


def media_component(d, number, media_type, mar_dl, mar_ul, flows):
    sub = vendor(d, 509, d.int_to_hex(1, 4))  # Flow-Number
    for flow in flows:
        sub += vendor(d, 507, flow.encode().hex())
    data = vendor(d, 518, d.int_to_hex(number, 4))
    data += vendor(d, 520, d.int_to_hex(media_type, 4))
    data += vendor(d, 515, d.int_to_hex(mar_dl, 4))
    data += vendor(d, 516, d.int_to_hex(mar_ul, 4))
    data += vendor(d, 519, sub)
    return vendor(d, 517, data)


def aar_avps(d, components):
    avps = d.generate_avp(263, 40, RX_SESSION.encode().hex())
    avps += d.generate_avp(8, 40, "0a2e0002")  # Framed-IP-Address 10.46.0.2
    avps += "".join(components)
    return d.decodeAvpPacket(avps)


def session(store, id="sm1"):
    store.save_sm(
        {
            "id": id,
            "supi": "imsi-001010000000001",
            "dnn": "ims",
            "ipv4": UE_IP,
            "notification_uri": SMF_URI,
            "apps": [],
        }
    )


def test_media_components_from_nested_avps():
    d = diameter()
    avps = aar_avps(
        d,
        [
            media_component(d, 1, 0, 41000, 42000, ["permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000"]),
            media_component(d, 2, 1, 512000, 256000, ["permit in 17 from 10.46.0.2 40002 to 10.72.0.21 30002"]),
        ],
    )
    media = rx.media_components(avps)
    assert [m["number"] for m in media] == [1, 2]
    assert [m["type"] for m in media] == ["AUDIO", "VIDEO"]
    assert media[0]["mar_dl"] == 41000
    assert media[0]["mar_ul"] == 42000
    assert media[1]["flows"] == ["permit in 17 from 10.46.0.2 40002 to 10.72.0.21 30002"]


def test_aar_without_media_is_authorized_without_a_command():
    d = diameter()
    store = PcfStore(FakeRedis())
    session(store)
    assert rx.aar(store, "ims", RX_SESSION, UE_IP, aar_avps(d, [])) is True
    assert store.next_command(0) is None


def test_aar_for_a_ue_without_nr_session_is_not_ours():
    d = diameter()
    store = PcfStore(FakeRedis())
    assert rx.aar(store, "ims", RX_SESSION, UE_IP, aar_avps(d, [])) is False


def test_aar_and_str_install_and_remove_the_flow():
    d = diameter()
    store = PcfStore(FakeRedis())
    session(store)
    notifier = FakeNotifier()
    component = media_component(d, 1, 0, 41000, 41000, ["permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000"])
    assert rx.aar(store, "ims", RX_SESSION, UE_IP, aar_avps(d, [component])) is True

    manager = policy.PolicyManager(store, notifier, "http://127.0.1.18:7777", {})
    asyncio.run(manager.apply(store.next_command(0)))
    decision = notifier.sent[0][2]
    rule_id = next(iter(decision["pccRules"]))
    assert decision["qosDecs"][rule_id]["5qi"] == 1

    assert rx.session_termination(store, RX_SESSION) is True
    asyncio.run(manager.apply(store.next_command(0)))
    assert notifier.sent[1][2] == {"pccRules": {rule_id: None}}
    assert store.find_rx(RX_SESSION) is None
    assert rx.session_termination(store, RX_SESSION) is False


def test_commands_survive_as_json():
    store = PcfStore(FakeRedis())
    store.push_command({"op": "remove", "app_id": "a"})
    assert json.loads(json.dumps(store.next_command(0))) == {"op": "remove", "app_id": "a"}


def rx_request(d, command_code, components, framed_ip="0a2e0002"):
    avps = d.generate_avp(263, 40, RX_SESSION.encode().hex())
    avps += d.generate_avp(264, 40, b"pcscf".hex())
    avps += d.generate_avp(296, 40, b"realm".hex())
    avps += d.generate_avp(444, 40, b"sip:001010000000001@ims.example.org".hex())
    if framed_ip:
        avps += d.generate_avp(8, 40, framed_ip)
    avps += "".join(components)
    packet = d.generate_diameter_packet("01", "c0", command_code, RX_APP, d.generate_id(4), d.generate_id(4), avps)
    return d.decode_diameter_packet(packet)


def result_code(d, answer):
    _, avps = d.decode_diameter_packet(answer)
    return int(d.get_avp_data(avps, 268)[0], 16)


def test_diameter_answers_aar_and_str_of_an_nr_ue(create_test_db):
    d = diameter()
    d.pcfStore = PcfStore(FakeRedis())
    session(d.pcfStore)
    component = media_component(d, 1, 0, 41000, 41000, ["permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000"])

    packet_vars, avps = rx_request(d, 265, [component])
    assert result_code(d, d.Answer_16777236_265(packet_vars, avps)) == 2001
    command = d.pcfStore.next_command(0)
    assert command["op"] == "install"
    assert command["sm_id"] == "sm1"

    packet_vars, avps = rx_request(d, 275, [])
    assert result_code(d, d.Answer_16777236_275(packet_vars, avps)) == 2001
    assert d.pcfStore.next_command(0) == {"op": "remove", "app_id": command["app_id"]}


def test_diameter_leaves_other_ues_to_the_gx_path(create_test_db):
    d = diameter()
    d.pcfStore = PcfStore(FakeRedis())
    packet_vars, avps = rx_request(d, 265, [])
    # An unknown subscriber without a 5G session: rejected like before
    assert result_code(d, d.Answer_16777236_265(packet_vars, avps)) == 4001
    assert d.pcfStore.next_command(0) is None
