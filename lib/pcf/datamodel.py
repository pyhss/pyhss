# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build Npcf policy decisions (3GPP TS 29.507/29.512/29.514) from PyHSS data. All pure functions.

The results are plain dicts: removing a PCC rule needs a null map entry, which the models can't
express. Open5GS is stricter than the specs on some points, which is kept here on purpose:

 * The SMF asserts on the preemption values of a QosData, so "arp" is always complete.
 * A PCC rule that refers to a qosId missing from "qosDecs" is dropped by the SMF.
 * Its SessionRule values are only used if a trigger (SE_AMBR_CH, DEF_QOS_CH) says so.
"""

import re

from pcf.store import bare_dnn  # noqa: F401
from udr.datamodel import bitrate

# Bit of a feature in the SupportedFeatures hex string (bit 1 is the lowest)
AM_UE_AMBR_AUTHORIZATION = 1 << (3 - 1)
SM_DN_AUTHORIZATION = 1 << (27 - 1)

DEFAULT_QOS = {
    "audio": {"5qi": 1, "arp_priority": 2, "precedence": 40, "bandwidth": 128000},
    "video": {"5qi": 2, "arp_priority": 4, "precedence": 30, "bandwidth": 512000},
}

BITRATE_FACTORS = {"bps": 1, "Kbps": 10**3, "Mbps": 10**6, "Gbps": 10**9, "Tbps": 10**12}
FLOW = re.compile(r"^permit\s+(in|out)\s+(\S+)\s+from\s+(.+?)\s+to\s+(.+)$", re.IGNORECASE)
TFT_DIRECTIONS = {1: "DOWNLINK", 2: "UPLINK", 3: "BIDIRECTIONAL"}


def bitrate_bps(text):
    if not text:
        return 0
    value, unit = text.split()
    return int(float(value) * BITRATE_FACTORS[unit])


def features(requested, supported):
    return f"{int(requested or '0', 16) & supported:x}"


def feature_set(requested, feature):
    return bool(int(requested or "0", 16) & feature)


def flow_information(description, tft_direction=None):
    """FlowInformation from an IPFilterRule. The SMF expects "permit out" rules; as Open5GS'
    PCF does, a "permit in" rule becomes an uplink rule with its endpoints swapped."""
    match = FLOW.match(description.strip())
    if not match:
        raise ValueError(f"Unsupported flow description: {description}")
    direction, protocol, source, destination = match.groups()
    if direction.lower() == "in":
        source, destination = destination, source
        flow_direction = "UPLINK"
    else:
        flow_direction = "DOWNLINK"
    return {
        "flowDescription": f"permit out {protocol} from {source} to {destination}",
        "flowDirection": TFT_DIRECTIONS.get(tft_direction, flow_direction),
    }


def arp(priority, preempt_cap, preempt_vuln):
    return {
        "priorityLevel": int(priority),
        "preemptCap": "MAY_PREEMPT" if preempt_cap else "NOT_PREEMPT",
        "preemptVuln": "PREEMPTABLE" if preempt_vuln else "NOT_PREEMPTABLE",
    }


def qos_data(qos_id, five_qi, arp_value, mbr_dl=0, mbr_ul=0, gbr_dl=0, gbr_ul=0):
    data = {"qosId": qos_id, "5qi": int(five_qi), "priorityLevel": arp_value["priorityLevel"], "arp": arp_value}
    for name, value in (("maxbrDl", mbr_dl), ("maxbrUl", mbr_ul), ("gbrDl", gbr_dl), ("gbrUl", gbr_ul)):
        if value:
            data[name] = bitrate(value)
    return data


def pcc_rule(rule_id, precedence, flows):
    # Only one QosData per PCC rule, with the same ID, as in Open5GS
    rule = {"pccRuleId": rule_id, "refQosData": [rule_id], "flowInfos": flows}
    if precedence is not None:
        rule["precedence"] = int(precedence)
    return rule


def am_policy_association(request, sub):
    """PolicyAssociation for a PolicyAssociationRequest (as a dict)."""
    association = {
        "request": request,
        "suppFeat": features(request.get("suppFeat"), AM_UE_AMBR_AUTHORIZATION),
    }
    subscriber = sub["subscriber"]
    ul, dl = subscriber.get("ue_ambr_ul") or 0, subscriber.get("ue_ambr_dl") or 0
    requested = request.get("ueAmbr")
    if requested and (ul or dl) and feature_set(request.get("suppFeat"), AM_UE_AMBR_AUTHORIZATION):
        if bitrate_bps(requested.get("uplink")) // 1000 != ul // 1000 or (
            bitrate_bps(requested.get("downlink")) // 1000 != dl // 1000
        ):
            association["triggers"] = ["UE_AMBR_CH"]
            association["ueAmbr"] = {"uplink": bitrate(ul), "downlink": bitrate(dl)}
    return association


def charging_rule_decision(rule, warn):
    """(PccRule, QosData) of a Get_Charging_Rule() result, or None if it has no usable flow."""
    rule_id = str(rule.get("rule_name") or f"rule-{rule['charging_rule_id']}")
    flows = []
    for tft in rule.get("tft", []):
        try:
            flows.append(flow_information(tft["tft_string"], tft.get("direction")))
        except ValueError as e:
            warn(f"Charging rule {rule_id}: {e}")
    if not flows:
        return None
    arp_value = arp(
        rule["arp_priority"], rule.get("arp_preemption_capability"), rule.get("arp_preemption_vulnerability")
    )
    qos = qos_data(
        rule_id, rule["qci"], arp_value, rule.get("mbr_dl"), rule.get("mbr_ul"), rule.get("gbr_dl"), rule.get("gbr_ul")
    )
    return pcc_rule(rule_id, rule.get("precedence"), flows), qos


def sm_policy_decision(context, apn, charging_rules, warn):
    """SmPolicyDecision for a SmPolicyContextData (as a dict) from the APN and its charging rules."""
    requested_features = context.get("suppFeat")
    default_arp = arp(
        apn["arp_priority"], apn.get("arp_preemption_capability"), apn.get("arp_preemption_vulnerability")
    )
    rule = {
        "sessRuleId": "1",
        "authDefQos": {"5qi": int(apn["qci"]), "priorityLevel": default_arp["priorityLevel"], "arp": default_arp},
    }
    triggers = []

    subscribed_ambr = context.get("subsSessAmbr")
    if subscribed_ambr and feature_set(requested_features, SM_DN_AUTHORIZATION):
        ul, dl = apn.get("apn_ambr_ul") or 0, apn.get("apn_ambr_dl") or 0
        rule["authSessAmbr"] = {"uplink": bitrate(ul), "downlink": bitrate(dl)}
        if bitrate_bps(subscribed_ambr.get("uplink")) // 1000 != ul // 1000 or (
            bitrate_bps(subscribed_ambr.get("downlink")) // 1000 != dl // 1000
        ):
            triggers.append("SE_AMBR_CH")

    subscribed_qos = context.get("subsDefQos")
    if subscribed_qos and (
        subscribed_qos.get("5qi") != rule["authDefQos"]["5qi"]
        or (subscribed_qos.get("arp") or default_arp) != default_arp
    ):
        triggers.append("DEF_QOS_CH")

    decision = {"sessRules": {"1": rule}}
    pcc_rules = {}
    qos_decs = {}
    for charging_rule in charging_rules:
        result = charging_rule_decision(charging_rule, warn)
        if result:
            pcc_rules[result[0]["pccRuleId"]] = result[0]
            qos_decs[result[1]["qosId"]] = result[1]
    if pcc_rules:
        decision["pccRules"] = pcc_rules
        decision["qosDecs"] = qos_decs
    if triggers:
        decision["policyCtrlReqTriggers"] = triggers
    if requested_features:
        decision["suppFeat"] = features(requested_features, SM_DN_AUTHORIZATION)
    return decision


def media_from_af(components):
    """Normalized media components (see media_decision) of AscReqData.medComponents."""
    media = []
    for component in (components or {}).values():
        flows = []
        for sub_component in (component.get("medSubComps") or {}).values():
            flows.extend(sub_component.get("fDescs") or [])
        media.append(
            {
                "number": int(component["medCompN"]),
                "type": component.get("medType"),
                "mar_dl": bitrate_bps(component.get("marBwDl")),
                "mar_ul": bitrate_bps(component.get("marBwUl")),
                "mir_dl": bitrate_bps(component.get("mirBwDl")),
                "mir_ul": bitrate_bps(component.get("mirBwUl")),
                "rr": bitrate_bps(component.get("rrBw")),
                "rs": bitrate_bps(component.get("rsBw")),
                "flows": flows,
            }
        )
    return media


def merge_media(current, updates):
    """Apply updated media components. Values an update does not carry stay as they were, and a
    component with "removed" set is dropped."""
    merged = {component["number"]: component for component in current}
    for update in updates:
        number = update["number"]
        if update.get("removed"):
            merged.pop(number, None)
            continue
        changes = {key: value for key, value in update.items() if value}
        merged[number] = {**merged.get(number, {}), **changes, "number": number}
    return [merged[number] for number in sorted(merged)]


def rule_id(app_id, number):
    return f"af-{app_id}-{number}"


def media_decision(media, app_id, config):
    """(pccRules, qosDecs) for media components. A component is a dict with number, type (AUDIO,
    VIDEO, ...), bit rates in bps (mar_dl/ul, mir_dl/ul, rr, rs) and its IPFilterRules (flows).

    Only audio and video get a QoS flow: IMS signalling (CONTROL) stays on the default flow."""
    qos_config = config.get("qos") or {}
    pcc_rules = {}
    qos_decs = {}
    for component in media:
        media_type = (component.get("type") or "").lower()
        if media_type not in DEFAULT_QOS or not component.get("flows"):
            continue
        qos = {**DEFAULT_QOS[media_type], **(qos_config.get(media_type) or {})}
        rtcp = (component.get("rr") or 0) + (component.get("rs") or 0)
        mbr = {}
        gbr = {}
        for direction in ("dl", "ul"):
            requested = component.get(f"mar_{direction}") or 0
            # 5QI 1 and 2 are GBR, and P-CSCFs usually send only the maximum
            gbr[direction] = component.get(f"mir_{direction}") or requested or qos["bandwidth"]
            mbr[direction] = (requested or qos["bandwidth"]) + rtcp
        identifier = rule_id(app_id, component["number"])
        pcc_rules[identifier] = pcc_rule(
            identifier, qos["precedence"], [flow_information(flow) for flow in component["flows"]]
        )
        # Voice may preempt and is not preempted itself (TS 23.203 Annex J / GSMA IR.92)
        qos_decs[identifier] = qos_data(
            identifier,
            qos["5qi"],
            arp(qos["arp_priority"], True, False),
            mbr["dl"],
            mbr["ul"],
            gbr["dl"],
            gbr["ul"],
        )
    return pcc_rules, qos_decs
