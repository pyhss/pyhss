# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build Nudr_DataRepository resources (3GPP TS 29.505/29.519 data) from PyHSS subscriber data.

All functions are pure: they take the dict returned by Database.Get_5G_Subscription() and
return instances of the generated 3GPP models in sbi.models. 4G APN data is mapped to 5G:

 * APN name -> DNN, QCI -> 5QI, ARP -> ARP, APN-AMBR -> session AMBR
 * APN sst/sd -> S-NSSAI, falling back to the configured default S-NSSAI
 * Subscriber UE-AMBR -> subscribed UE-AMBR, MSISDN -> GPSI
 * SUBSCRIBER_ROUTING -> static UE IP addresses

An APN that is not usable in 5G (no QCI, no ARP or no APN-AMBR) is skipped with a warning,
as Open5GS's own UDR does.
"""

import json

from sbi import models

# APN.ip_version (3GPP TS 29.272 PDN-Type) -> (default, allowed) PDU session types
PDU_SESSION_TYPES = {
    0: ("IPV4", ["IPV4"]),
    1: ("IPV6", ["IPV6"]),
    2: ("IPV4V6", ["IPV4", "IPV6", "IPV4V6"]),
    3: ("IPV4V6", ["IPV4", "IPV6", "IPV4V6"]),
}


def dump(obj):
    """Serialize a model (or list of models) to the JSON form sent on the wire."""
    if isinstance(obj, list):
        return [dump(x) for x in obj]
    return obj.model_dump(mode="json", by_alias=True, exclude_unset=True)


def bitrate(bps):
    """PyHSS stores bit rates in bps, the SBI uses BitRate strings like "100 Mbps"."""
    bps = int(bps or 0)
    for unit, factor in (("Gbps", 10**9), ("Mbps", 10**6), ("Kbps", 10**3)):
        if bps and bps % factor == 0:
            return f"{bps // factor} {unit}"
    return f"{bps} bps"


def snssai(apn, default_snssai):
    sst = apn.get("sst")
    sd = apn.get("sd")
    if sst is None:
        sst = default_snssai["sst"]
        sd = default_snssai.get("sd") if sd is None else sd
    if sd:
        return models.Snssai(sst=int(sst), sd=str(sd).lower())
    return models.Snssai(sst=int(sst))


def snssai_key(value):
    """Key of an S-NSSAI in maps such as subscribedSnssaiInfos (VarSnssai: "sst" or "sst-sd")."""
    if value.sd:
        return f"{value.sst}-{value.sd}"
    return str(value.sst)


def parse_snssai(text):
    """Parse an S-NSSAI given as JSON in a query parameter, e.g. '{"sst":1,"sd":"0000ab"}'."""
    return models.Snssai.model_validate(json.loads(text))


def same_snssai(a, b):
    return a.sst == b.sst and (a.sd or "").lower() == (b.sd or "").lower()


def usable_apns(sub, warn=None):
    """APNs that have everything a 5G DNN configuration needs, default APN first."""
    result = []
    for apn in sub["apns"]:
        missing = [
            name
            for name, value in (
                ("qci", apn.get("qci")),
                ("arp_priority", apn.get("arp_priority")),
                ("apn_ambr", (apn.get("apn_ambr_dl") or 0) or (apn.get("apn_ambr_ul") or 0)),
            )
            if not value
        ]
        if missing:
            if warn:
                warn(f"APN {apn['apn']} skipped for 5G, missing: {', '.join(missing)}")
            continue
        result.append(apn)
    return result


def authentication_subscription(sub):
    auc = sub["auc"]
    return models.AuthenticationSubscription(
        authenticationMethod="5G_AKA",
        encPermanentKey=auc["ki"].lower(),
        encOpcKey=auc["opc"].lower(),
        authenticationManagementField=auc["amf"].lower(),
        sequenceNumber=models.SequenceNumber(sqn=f"{int(auc['sqn'] or 0):012x}"),
    )


def am_data(sub, default_snssai, fields=None):
    """AccessAndMobilitySubscriptionData, or None if the subscriber has no UE-AMBR."""
    subscriber = sub["subscriber"]
    ue_ambr_dl = subscriber.get("ue_ambr_dl") or 0
    ue_ambr_ul = subscriber.get("ue_ambr_ul") or 0
    if not ue_ambr_dl and not ue_ambr_ul:
        return None

    data = {}
    if subscriber.get("msisdn"):
        data["gpsis"] = ["msisdn-" + str(subscriber["msisdn"]).lstrip("+")]
    data["subscribedUeAmbr"] = models.Ambr(uplink=bitrate(ue_ambr_ul), downlink=bitrate(ue_ambr_dl))

    slices = []
    for apn in sub["apns"]:
        value = snssai(apn, default_snssai)
        if not any(same_snssai(value, x) for x in slices):
            slices.append(value)
    if not slices:
        slices.append(snssai({}, default_snssai))
    # The slice of the default APN (the first one) is the default slice
    nssai = {"defaultSingleNssais": slices[:1]}
    if slices[1:]:
        nssai["singleNssais"] = slices[1:]
    data["nssai"] = models.Nssai(**nssai)

    if fields:
        data = {k: v for k, v in data.items() if k in fields}
    return models.AccessAndMobilitySubscriptionData(**data)


def smf_selection_data(sub, default_snssai, warn=None):
    """SmfSelectionSubscriptionData, or None if the subscriber has no usable APN."""
    infos = {}
    for apn in usable_apns(sub, warn):
        key = snssai_key(snssai(apn, default_snssai))
        dnn_info = {"dnn": apn["apn"]}
        if not infos:
            # The default APN comes first
            dnn_info["defaultDnnIndicator"] = True
        infos.setdefault(key, []).append(models.DnnInfo(**dnn_info))
    if not infos:
        return None
    return models.SmfSelectionSubscriptionData(
        subscribedSnssaiInfos={key: models.SnssaiInfo(dnnInfos=dnn_infos) for key, dnn_infos in infos.items()}
    )


def dnn_configuration(sub, apn):
    default_type, allowed_types = PDU_SESSION_TYPES.get(apn.get("ip_version") or 0, PDU_SESSION_TYPES[0])
    config = {
        "pduSessionTypes": models.PduSessionTypes(defaultSessionType=default_type, allowedSessionTypes=allowed_types),
        # allowedSscModes are the modes allowed in addition to the default one (max. 2)
        "sscModes": models.SscModes(defaultSscMode="SSC_MODE_1", allowedSscModes=["SSC_MODE_2", "SSC_MODE_3"]),
        "field_5gQosProfile": models.SubscribedDefaultQos(
            field_5qi=int(apn["qci"]),
            arp=models.Arp(
                priorityLevel=int(apn["arp_priority"]),
                preemptCap="MAY_PREEMPT" if apn.get("arp_preemption_capability") else "NOT_PREEMPT",
                preemptVuln="PREEMPTABLE" if apn.get("arp_preemption_vulnerability") else "NOT_PREEMPTABLE",
            ),
        ),
        "sessionAmbr": models.Ambr(uplink=bitrate(apn.get("apn_ambr_ul")), downlink=bitrate(apn.get("apn_ambr_dl"))),
    }
    route = sub["routing"].get(apn["apn_id"])
    if route and route.get("ip_address"):
        key = "ipv6Addr" if ":" in route["ip_address"] else "ipv4Addr"
        config["staticIpAddress"] = [models.IpAddress(**{key: route["ip_address"]})]
    return models.DnnConfiguration(**config)


def sm_data(sub, default_snssai, single_nssai=None, dnn=None, warn=None):
    """List of SessionManagementSubscriptionData (one per S-NSSAI), optionally filtered."""
    slices = []
    for apn in usable_apns(sub, warn):
        value = snssai(apn, default_snssai)
        if single_nssai is not None and not same_snssai(value, single_nssai):
            continue
        if dnn is not None and apn["apn"].lower() != dnn.lower():
            continue
        for slice_value, configs in slices:
            if same_snssai(slice_value, value):
                break
        else:
            configs = {}
            slices.append((value, configs))
        configs[apn["apn"]] = dnn_configuration(sub, apn)
    return [
        models.SessionManagementSubscriptionData(singleNssai=value, dnnConfigurations=configs)
        for value, configs in slices
    ]


def provisioned_data_sets(sub, default_snssai, dataset_names, warn=None):
    data = {}
    if "AM" in dataset_names:
        value = am_data(sub, default_snssai)
        if value is not None:
            data["amData"] = value
    if "SMF_SEL" in dataset_names:
        value = smf_selection_data(sub, default_snssai, warn)
        if value is not None:
            data["smfSelData"] = value
    if "SM" in dataset_names:
        value = sm_data(sub, default_snssai, warn=warn)
        if value:
            data["smData"] = models.SmSubsData(value)
    return models.ProvisionedDataSets(**data)


def am_policy_data(sub):
    return models.AmPolicyData()


def sm_policy_data(sub, default_snssai, requested_snssai, dnn=None, warn=None):
    """SmPolicyData for the requested S-NSSAI, or None if the subscriber has no DNN in that slice."""
    dnn_data = {}
    for apn in usable_apns(sub, warn):
        if not same_snssai(snssai(apn, default_snssai), requested_snssai):
            continue
        if dnn is not None and apn["apn"].lower() != dnn.lower():
            continue
        dnn_data[apn["apn"]] = models.SmPolicyDnnData(dnn=apn["apn"])
    if not dnn_data:
        return None
    return models.SmPolicyData(
        smPolicySnssaiData={
            snssai_key(requested_snssai): models.SmPolicySnssaiData(snssai=requested_snssai, smPolicyDnnData=dnn_data)
        }
    )
