# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rx (TS 29.214) for UEs on NR: lets a P-CSCF without Npcf_PolicyAuthorization set up VoNR.

Runs in pyhss_hss, which answers the Diameter request right away. The SMF is notified by
pyhss_pcf, in the order of the requests, through the commands in the store.
"""

import uuid

AVP_MEDIA_COMPONENT_DESCRIPTION = 517
AVP_MEDIA_COMPONENT_NUMBER = 518
AVP_MEDIA_TYPE = 520
AVP_FLOW_DESCRIPTION = 507
AVP_FLOW_STATUS = 511
AVP_MAX_REQUESTED_BANDWIDTH_DL = 515
AVP_MAX_REQUESTED_BANDWIDTH_UL = 516
AVP_RR_BANDWIDTH = 521
AVP_RS_BANDWIDTH = 522
AVP_MIN_REQUESTED_BANDWIDTH_DL = 534
AVP_MIN_REQUESTED_BANDWIDTH_UL = 535

FLOW_STATUS_REMOVED = 4
MEDIA_TYPES = {0: "AUDIO", 1: "VIDEO", 2: "DATA", 3: "APPLICATION", 4: "CONTROL"}
BANDWIDTHS = {
    AVP_MAX_REQUESTED_BANDWIDTH_DL: "mar_dl",
    AVP_MAX_REQUESTED_BANDWIDTH_UL: "mar_ul",
    AVP_MIN_REQUESTED_BANDWIDTH_DL: "mir_dl",
    AVP_MIN_REQUESTED_BANDWIDTH_UL: "mir_ul",
    AVP_RR_BANDWIDTH: "rr",
    AVP_RS_BANDWIDTH: "rs",
}


def media_components(avps):
    """Normalized media components of an AAR, from the AVPs of Diameter.decodeAvpPacket().

    The decoder flattens the descendants of a grouped AVP into its sub_avps, so the flows of all
    Media-Sub-Components of a Media-Component-Description end up side by side. That is fine: the
    PCC rule of a media component holds all of them."""
    media = []
    for avp in avps:
        if avp["avp_code"] != AVP_MEDIA_COMPONENT_DESCRIPTION:
            continue
        component = {"number": 0, "type": None, "flows": []}
        component.update({name: 0 for name in BANDWIDTHS.values()})
        for sub_avp in avp.get("sub_avps", []):
            code = sub_avp["avp_code"]
            data = sub_avp.get("misc_data")
            if code == AVP_MEDIA_COMPONENT_NUMBER:
                component["number"] = int(data, 16)
            elif code == AVP_MEDIA_TYPE:
                component["type"] = MEDIA_TYPES.get(int(data, 16))
            elif code == AVP_FLOW_DESCRIPTION:
                component["flows"].append(bytes.fromhex(data).decode("ascii"))
            elif code == AVP_FLOW_STATUS and int(data, 16) == FLOW_STATUS_REMOVED:
                component["removed"] = True
            elif code in BANDWIDTHS:
                component[BANDWIDTHS[code]] = int(data, 16)
        media.append(component)
    return media


def aar(store, ims_dnn, rx_session_id, ue_ip, avps):
    """Handle an AAR. False if the UE has no NR session here, then it is not ours to answer."""
    session = store.find_sm(ue_ip, ims_dnn) if ue_ip else None
    if session is None:
        return False
    media = media_components(avps)
    if not media:
        # Registration: the signalling stays on the default QoS flow
        return True
    app_id = store.find_rx(rx_session_id)
    if app_id is None:
        app_id = uuid.uuid4().hex
        store.save_rx(rx_session_id, app_id)
    store.push_command({"op": "install", "app_id": app_id, "sm_id": session["id"], "media": media})
    return True


def session_termination(store, rx_session_id):
    """Handle an STR. False if the Rx session is not one of ours."""
    app_id = store.find_rx(rx_session_id)
    if app_id is None:
        return False
    store.delete_rx(rx_session_id)
    store.push_command({"op": "remove", "app_id": app_id})
    return True
