# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest
import yaml
from pcf.app import create_app
from pcf.policy import SmfNotifier
from pcf.store import PcfStore
from sbi import models

openapi_core = pytest.importorskip("openapi_core")
from openapi_core.testing import MockRequest, MockResponse

top_dir = Path(__file__).resolve().parent.parent
spec_dir = top_dir / "specs/3gpp/r19-20260402"
SPEC_SERVER = "https://example.com"

IMSI = "001010000000001"
SUPI = f"imsi-{IMSI}"
PCF_URI = "http://127.0.1.18:7777"
SMF_NOTIFY = "http://10.70.0.14:7777/nsmf-callback/v1/sm-policy-notify/1"
UE_IP = "10.46.0.2"

SUB = {
    "subscriber": {
        "subscriber_id": 1,
        "imsi": IMSI,
        "enabled": True,
        "msisdn": "491701234567",
        "ue_ambr_dl": 1000000000,
        "ue_ambr_ul": 500000000,
    },
    "auc": {"auc_id": 7, "ki": "00", "opc": "00", "amf": "8000", "sqn": 0},
    "apns": [
        {
            "apn_id": 1,
            "apn": "internet",
            "ip_version": 0,
            "apn_ambr_dl": 1000000000,
            "apn_ambr_ul": 1000000000,
            "qci": 9,
            "arp_priority": 8,
            "arp_preemption_capability": False,
            "arp_preemption_vulnerability": True,
            "sst": None,
            "sd": None,
            "charging_rule_list": "",
        },
        {
            "apn_id": 2,
            "apn": "ims",
            "ip_version": 0,
            "apn_ambr_dl": 128000,
            "apn_ambr_ul": 128000,
            "qci": 5,
            "arp_priority": 1,
            "arp_preemption_capability": True,
            "arp_preemption_vulnerability": False,
            "sst": None,
            "sd": None,
            "charging_rule_list": "9",
        },
    ],
    "routing": {},
}

CHARGING_RULE = {
    "charging_rule_id": 9,
    "rule_name": "sip",
    "qci": 5,
    "arp_priority": 1,
    "arp_preemption_capability": False,
    "arp_preemption_vulnerability": True,
    "mbr_dl": 128000,
    "mbr_ul": 128000,
    "gbr_dl": 0,
    "gbr_ul": 0,
    "precedence": 100,
    "tft": [
        {"tft_string": "permit out 17 from 10.72.0.1 5060 to any", "direction": 1},
        {"tft_string": "permit in 17 from any to 10.72.0.1 5060", "direction": 2},
    ],
}

# As built by amf_npcf_am_policy_control_build_create() of Open5GS
AM_REQUEST = {
    "notificationUri": f"http://10.70.0.22:7777/namf-callback/v1/{SUPI}/am-policy-notify",
    "supi": SUPI,
    "accessType": "3GPP_ACCESS",
    "pei": "imeisv-4370816125816151",
    "userLoc": {
        "nrLocation": {
            "tai": {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"},
            "ncgi": {"plmnId": {"mcc": "001", "mnc": "01"}, "nrCellId": "000000010"},
            "ueLocationTimestamp": "2026-10-31T19:00:00.000000+00:00",
        }
    },
    "timeZone": "+00:00",
    "servingPlmn": {"mcc": "001", "mnc": "01"},
    "ratType": "NR",
    "ueAmbr": {"uplink": "500000 Kbps", "downlink": "1000000 Kbps"},
    "allowedSnssais": [{"sst": 1}],
    "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
    "serviceName": "namf-callback",
    "suppFeat": "4",
}

# As built by smf_npcf_smpolicycontrol_build_create() of Open5GS
SM_CONTEXT = {
    "supi": SUPI,
    "pduSessionId": 1,
    "pduSessionType": "IPV4",
    "chargingcharacteristics": "00000800",
    "dnn": "ims",
    "notificationUri": SMF_NOTIFY,
    "ratType": "NR",
    "servingNetwork": {"mcc": "001", "mnc": "01"},
    "userLocationInfo": AM_REQUEST["userLoc"],
    "ueTimeZone": "+00:00",
    "ipv4Address": UE_IP,
    "subsSessAmbr": {"uplink": "128 Kbps", "downlink": "128 Kbps"},
    "subsDefQos": {
        "5qi": 5,
        "arp": {"priorityLevel": 1, "preemptCap": "MAY_PREEMPT", "preemptVuln": "NOT_PREEMPTABLE"},
        "priorityLevel": 1,
    },
    "suppFeat": "4000000",
    "sliceInfo": {"sst": 1},
}

APP_SESSION = {
    "ascReqData": {
        "suppFeat": "0",
        "notifUri": "http://10.72.0.1:7777/naf-callback/v1/1",
        "ueIpv4": UE_IP,
        "dnn": "ims",
        "medComponents": {
            "1": {
                "medCompN": 1,
                "medType": "AUDIO",
                "marBwDl": "41 Kbps",
                "marBwUl": "41 Kbps",
                "medSubComps": {
                    "1": {
                        "fNum": 1,
                        "fDescs": [
                            "permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000",
                            "permit in 17 from 10.46.0.2 40000 to 10.72.0.21 30000",
                        ],
                    }
                },
            }
        },
    }
}


class FakeDatabase:
    def __init__(self):
        self.subs = {IMSI: copy.deepcopy(SUB)}

    def Get_5G_Subscription(self, imsi):
        return copy.deepcopy(self.subs.get(imsi))

    def Get_Charging_Rule(self, charging_rule_id):
        assert charging_rule_id == 9
        return copy.deepcopy(CHARGING_RULE)


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.lists = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value.encode() if isinstance(value, str) else value

    def delete(self, key):
        self.values.pop(key, None)

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value.encode() if isinstance(value, str) else value)

    def blpop(self, key, timeout=0):
        if self.lists.get(key):
            return key, self.lists[key].pop(0)
        return None


class FakeNotifier:
    def __init__(self):
        self.sent = []
        self.ok = True

    async def update(self, notification_uri, resource_uri, decision):
        self.sent.append((notification_uri, resource_uri, json.loads(json.dumps(decision))))
        return self.ok


def load_spec(name):
    config = openapi_core.Config(
        spec_validator_cls=None,
        extra_media_type_deserializers={
            "application/problem+json": json.loads,
            "application/merge-patch+json": json.loads,
        },
    )
    return openapi_core.OpenAPI.from_file_path(str(spec_dir / name), config=config)


SPECS = {
    "npcf-am-policy-control": "TS29507_Npcf_AMPolicyControl.yaml",
    "npcf-smpolicycontrol": "TS29512_Npcf_SMPolicyControl.yaml",
    "npcf-policyauthorization": "TS29514_Npcf_PolicyAuthorization.yaml",
}


@pytest.fixture(scope="module")
def specs():
    return {name: load_spec(file) for name, file in SPECS.items()}


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def notifier():
    return FakeNotifier()


@pytest.fixture
def store():
    return PcfStore(FakeRedis())


@pytest.fixture
def pcf(db, store, notifier, specs):
    log = []
    config = {"advertise_ip": "127.0.1.18", "bind_port": 7777, "ims_dnn": "ims"}
    app = create_app(db, config, store, notifier, lambda level, message: log.append((level, message)))

    def call(method, service, path, body=None, content_type="application/json", validate=True):
        headers = {}
        content = None
        if body is not None:
            content = json.dumps(body).encode()
            headers["content-type"] = content_type

        async def request():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://pcf") as client:
                return await client.request(method, f"/{service}/v1{path}", content=content, headers=headers)

        response = asyncio.run(request())
        if validate:
            spec = specs[service]
            spec_request = MockRequest(
                SPEC_SERVER,
                method.lower(),
                f"/{service}/v1{path}",
                data=content,
                content_type=headers.get("content-type", "application/json"),
            )
            spec.validate_request(spec_request)
            spec.validate_response(
                spec_request,
                MockResponse(
                    response.content,
                    status_code=response.status_code,
                    headers={k.title(): v for k, v in response.headers.items()},
                    content_type=response.headers.get("content-type", "application/json"),
                ),
            )
        return response

    call.log = log
    return call


AM = "npcf-am-policy-control"
SM = "npcf-smpolicycontrol"
PA = "npcf-policyauthorization"


def create_sm(pcf, context=SM_CONTEXT):
    r = pcf("POST", SM, "/sm-policies", context)
    assert r.status_code == 201, r.text
    return r


def sm_id(response):
    return response.headers["location"].rsplit("/", 1)[1]


# Npcf_AMPolicyControl


def test_am_policy_create_as_the_amf_requires(pcf):
    r = pcf("POST", AM, "/policies", AM_REQUEST)
    # amf_npcf_am_policy_control_handle_create() rejects the UE without these
    assert r.status_code == 201
    location = r.headers["location"]
    assert location.startswith(f"{PCF_URI}/npcf-am-policy-control/v1/policies/")
    body = r.json()
    assert body["suppFeat"] == "4"
    assert body["request"]["supi"] == SUPI
    # The UE-AMBR the AMF has is the subscribed one
    assert "triggers" not in body


def test_am_policy_reports_a_changed_ue_ambr(pcf):
    request = {**AM_REQUEST, "ueAmbr": {"uplink": "1 Kbps", "downlink": "1 Kbps"}}
    body = pcf("POST", AM, "/policies", request).json()
    assert body["triggers"] == ["UE_AMBR_CH"]
    assert body["ueAmbr"] == {"uplink": "500 Mbps", "downlink": "1 Gbps"}


def test_am_policy_without_ue_ambr_feature(pcf):
    request = {k: v for k, v in AM_REQUEST.items() if k != "ueAmbr"} | {"suppFeat": "0"}
    body = pcf("POST", AM, "/policies", request).json()
    assert body["suppFeat"] == "0"
    assert "triggers" not in body


def test_am_policy_unknown_and_disabled_subscriber(pcf, db):
    request = {**AM_REQUEST, "supi": "imsi-001019999999999"}
    r = pcf("POST", AM, "/policies", request, validate=False)
    assert r.status_code == 404
    assert r.json()["cause"] == "USER_NOT_FOUND"
    db.subs[IMSI]["subscriber"]["enabled"] = False
    r = pcf("POST", AM, "/policies", AM_REQUEST)
    assert r.status_code == 403
    assert r.json()["cause"] == "POLICY_ASSOCIATION_DENIED" or r.json()["cause"] == "POLICY_CONTEXT_DENIED"


def test_am_policy_read_update_delete(pcf):
    r = pcf("POST", AM, "/policies", AM_REQUEST)
    path = "/policies/" + r.headers["location"].rsplit("/", 1)[1]
    assert pcf("GET", AM, path).json()["request"]["supi"] == SUPI
    r = pcf("POST", AM, f"{path}/update", {"triggers": ["LOC_CH"]})
    assert r.status_code == 200
    assert r.json()["resourceUri"].endswith(path)
    assert pcf("DELETE", AM, path).status_code == 204
    assert pcf("GET", AM, path, validate=False).status_code == 404


# Npcf_SMPolicyControl


def test_sm_policy_create_as_the_smf_requires(pcf):
    r = create_sm(pcf)
    assert r.headers["location"].startswith(f"{PCF_URI}/npcf-smpolicycontrol/v1/sm-policies/")
    body = r.json()
    rule = body["sessRules"]["1"]
    assert rule["sessRuleId"] == "1"
    assert rule["authSessAmbr"] == {"uplink": "128 Kbps", "downlink": "128 Kbps"}
    assert rule["authDefQos"]["5qi"] == 5
    assert rule["authDefQos"]["priorityLevel"] == 1
    assert rule["authDefQos"]["arp"] == {
        "priorityLevel": 1,
        "preemptCap": "MAY_PREEMPT",
        "preemptVuln": "NOT_PREEMPTABLE",
    }
    assert body["suppFeat"] == "4000000"
    # Nothing differs from what the SMF already has
    assert "policyCtrlReqTriggers" not in body


def test_sm_policy_triggers_when_subscription_changed(pcf):
    context = {**SM_CONTEXT, "subsSessAmbr": {"uplink": "1 Kbps", "downlink": "1 Kbps"}}
    context["subsDefQos"] = {**SM_CONTEXT["subsDefQos"], "5qi": 9}
    body = create_sm(pcf, context).json()
    assert sorted(body["policyCtrlReqTriggers"]) == ["DEF_QOS_CH", "SE_AMBR_CH"]


def test_sm_policy_installs_apn_charging_rules(pcf):
    body = create_sm(pcf).json()
    rule = body["pccRules"]["sip"]
    assert rule["pccRuleId"] == "sip"
    assert rule["precedence"] == 100
    assert rule["refQosData"] == ["sip"]
    assert rule["flowInfos"] == [
        {"flowDescription": "permit out 17 from 10.72.0.1 5060 to any", "flowDirection": "DOWNLINK"},
        {"flowDescription": "permit out 17 from 10.72.0.1 5060 to any", "flowDirection": "UPLINK"},
    ]
    qos = body["qosDecs"]["sip"]
    assert qos["qosId"] == "sip"
    assert qos["5qi"] == 5
    # update_authorized_pcc_rule_and_qos() asserts on both preemption values
    assert qos["arp"] == {"priorityLevel": 1, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE"}
    assert qos["maxbrDl"] == "128 Kbps"


def test_sm_policy_accepts_the_full_dnn(pcf):
    body = create_sm(pcf, {**SM_CONTEXT, "dnn": "ims.mnc001.mcc001.gprs"}).json()
    assert body["sessRules"]["1"]["authDefQos"]["5qi"] == 5


def test_sm_policy_unknown_dnn_and_subscriber(pcf):
    r = pcf("POST", SM, "/sm-policies", {**SM_CONTEXT, "dnn": "nope"})
    assert r.status_code == 403
    assert r.json()["cause"] == "POLICY_CONTEXT_DENIED"
    r = pcf("POST", SM, "/sm-policies", {**SM_CONTEXT, "supi": "imsi-001019999999999"})
    assert r.status_code == 400
    assert r.json()["cause"] == "USER_UNKNOWN"


def test_sm_policy_read_update_delete(pcf, store):
    r = create_sm(pcf)
    path = f"/sm-policies/{sm_id(r)}"
    body = pcf("GET", SM, path).json()
    assert body["context"]["supi"] == SUPI
    assert body["policy"]["sessRules"]["1"]["sessRuleId"] == "1"
    r = pcf("POST", SM, f"{path}/update", {"repPolicyCtrlReqTriggers": ["UE_IP_CH"], "ipv4Address": "10.46.0.3"})
    assert r.status_code == 200
    assert r.json()["sessRules"]["1"]["sessRuleId"] == "1"
    assert store.find_sm("10.46.0.3", "ims") is not None
    assert store.find_sm(UE_IP, "ims") is None
    assert pcf("POST", SM, f"{path}/delete", {}).status_code == 204
    assert pcf("GET", SM, path, validate=False).status_code == 404
    assert store.find_sm("10.46.0.3", "ims") is None


def test_new_session_replaces_a_stale_one_with_the_same_ip(pcf, store):
    old = sm_id(create_sm(pcf))
    new = sm_id(create_sm(pcf))
    assert store.get_sm(old) is None
    assert store.find_sm(UE_IP, "ims")["id"] == new


# Npcf_PolicyAuthorization


def test_app_session_installs_a_gbr_flow(pcf, notifier):
    sm = sm_id(create_sm(pcf))
    r = pcf("POST", PA, "/app-sessions", APP_SESSION)
    assert r.status_code == 201, r.text
    assert "/npcf-policyauthorization/v1/app-sessions/" in r.headers["location"]

    assert len(notifier.sent) == 1
    uri, resource, decision = notifier.sent[0]
    models.SmPolicyNotification.model_validate({"resourceUri": resource, "smPolicyDecision": decision})
    assert uri == SMF_NOTIFY
    assert resource == f"{PCF_URI}/npcf-smpolicycontrol/v1/sm-policies/{sm}/update"
    rule_id, rule = next(iter(decision["pccRules"].items()))
    assert rule["refQosData"] == [rule_id]
    assert rule["flowInfos"] == [
        {"flowDescription": "permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000", "flowDirection": "DOWNLINK"},
        {"flowDescription": "permit out 17 from 10.72.0.21 30000 to 10.46.0.2 40000", "flowDirection": "UPLINK"},
    ]
    qos = decision["qosDecs"][rule_id]
    assert qos["qosId"] == rule_id
    assert qos["5qi"] == 1
    assert qos["arp"]["preemptCap"] == "MAY_PREEMPT"
    assert qos["arp"]["preemptVuln"] == "NOT_PREEMPTABLE"
    assert qos["maxbrDl"] == qos["gbrDl"] == "41 Kbps"
    assert qos["maxbrUl"] == qos["gbrUl"] == "41 Kbps"


def test_app_session_delete_removes_the_flow(pcf, notifier):
    create_sm(pcf)
    r = pcf("POST", PA, "/app-sessions", APP_SESSION)
    path = "/app-sessions/" + r.headers["location"].rsplit("/", 1)[1]
    rule_id = next(iter(notifier.sent[0][2]["pccRules"]))
    assert pcf("POST", PA, f"{path}/delete", validate=False).status_code == 204
    assert notifier.sent[1][2] == {"pccRules": {rule_id: None}}
    assert pcf("GET", PA, path, validate=False).status_code == 404


def test_app_session_patch_changes_the_bandwidth(pcf, notifier):
    create_sm(pcf)
    r = pcf("POST", PA, "/app-sessions", APP_SESSION)
    path = "/app-sessions/" + r.headers["location"].rsplit("/", 1)[1]
    patch = {"ascReqData": {"medComponents": {"1": {"medCompN": 1, "medType": "AUDIO", "marBwDl": "64 Kbps"}}}}
    r = pcf("PATCH", PA, path, patch, content_type="application/merge-patch+json")
    assert r.status_code == 200, r.text
    decision = notifier.sent[1][2]
    rule_id = next(iter(decision["pccRules"]))
    assert decision["pccRules"][rule_id]["flowInfos"], "the flows of the session are kept"
    assert decision["qosDecs"][rule_id]["maxbrDl"] == "64 Kbps"


def test_app_session_without_pdu_session(pcf):
    r = pcf("POST", PA, "/app-sessions", APP_SESSION)
    assert r.status_code == 500
    assert r.json()["cause"] == "PDU_SESSION_NOT_AVAILABLE"


def test_control_media_needs_no_flow(pcf, notifier):
    create_sm(pcf)
    body = copy.deepcopy(APP_SESSION)
    body["ascReqData"]["medComponents"]["1"]["medType"] = "CONTROL"
    assert pcf("POST", PA, "/app-sessions", body).status_code == 201
    assert notifier.sent == []


def test_sm_delete_drops_its_app_sessions(pcf, store, notifier):
    r = create_sm(pcf)
    app = pcf("POST", PA, "/app-sessions", APP_SESSION).headers["location"].rsplit("/", 1)[1]
    assert pcf("POST", SM, f"/sm-policies/{sm_id(r)}/delete", {}).status_code == 204
    assert store.get_app(app) is None
    assert len(notifier.sent) == 1


def test_notifier_sends_what_the_smf_expects():
    received = []

    async def smf(request):
        received.append((request.url.path, json.loads(request.content)))
        return httpx.Response(204)

    async def scenario():
        notifier = SmfNotifier(transport=httpx.MockTransport(smf))
        decision = {"pccRules": {"af-1-1": None}}
        assert await notifier.update(
            f"{SMF_NOTIFY}/", f"{PCF_URI}/npcf-smpolicycontrol/v1/sm-policies/1/update", decision
        )

    asyncio.run(scenario())
    path, body = received[0]
    # smf_state_operational() routes on the third path component: update
    assert path == "/nsmf-callback/v1/sm-policy-notify/1/update"
    # A null map entry is how the SMF learns a rule is removed (TS 29.512 clause 4.2.6)
    assert body["smPolicyDecision"]["pccRules"] == {"af-1-1": None}


def test_notifier_reports_a_failure():
    async def scenario():
        notifier = SmfNotifier(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
        assert await notifier.update(SMF_NOTIFY, "http://pcf/1", {}) is False

    asyncio.run(scenario())


# Routes


@pytest.mark.parametrize("service,file", SPECS.items())
def test_routes_exist_in_the_specs(db, store, notifier, service, file):
    spec = yaml.safe_load((spec_dir / file).read_text())
    app = create_app(db, {}, store, notifier)
    routes = next(a for a in app.apps if a.base == f"/{service}").routes
    assert routes
    for route in routes:
        operation = spec["paths"][route.template][route.method.lower()]
        assert operation["operationId"] == route.operation_id
