# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import copy
import json
from pathlib import Path
from urllib.parse import parse_qsl, quote

import httpx
import pytest
import yaml
from udr.app import create_app

openapi_core = pytest.importorskip("openapi_core")
from openapi_core.testing import MockRequest, MockResponse

top_dir = Path(__file__).resolve().parent.parent
spec_dir = top_dir / "specs/3gpp/r19-20260402"
SPEC_SERVER = "https://example.com"

IMSI = "001010000000001"
UE_ID = f"imsi-{IMSI}"
AMF_ID = "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab"
SQN = "/sequenceNumber/sqn"

SUB = {
    "subscriber": {
        "subscriber_id": 1,
        "imsi": IMSI,
        "enabled": True,
        "msisdn": "491701234567",
        "ue_ambr_dl": 1000000000,
        "ue_ambr_ul": 500000000,
    },
    "auc": {
        "auc_id": 7,
        "ki": "465B5CE8B199B49FAA5F0A2EE238A6BC",
        "opc": "E8ED289DEBA952E4283B54E88E6183CA",
        "amf": "8000",
        "sqn": 0,
    },
    "apns": [
        {
            "apn_id": 1,
            "apn": "internet",
            "ip_version": 2,
            "apn_ambr_dl": 1000000000,
            "apn_ambr_ul": 1000000000,
            "qci": 9,
            "arp_priority": 8,
            "arp_preemption_capability": False,
            "arp_preemption_vulnerability": True,
            "sst": None,
            "sd": None,
        },
        {
            "apn_id": 2,
            "apn": "iot",
            "ip_version": 0,
            "apn_ambr_dl": 64000,
            "apn_ambr_ul": 64000,
            "qci": 9,
            "arp_priority": 10,
            "arp_preemption_capability": False,
            "arp_preemption_vulnerability": True,
            "sst": 2,
            "sd": "0000ab",
        },
    ],
    "routing": {1: {"apn_id": 1, "ip_address": "10.45.0.9"}},
}


class FakeDatabase:
    """The Database methods the UDR uses, on in-memory data."""

    def __init__(self):
        self.subs = {IMSI: copy.deepcopy(SUB)}
        self.serving_amf = {}
        self.sqn_increment = 32

    def Get_5G_Subscription(self, imsi):
        return copy.deepcopy(self.subs.get(imsi))

    def Update_AuC_SQN(self, auc_id, set_sqn=None, increment=0, policy="max", propagate=True):
        auc = next(s["auc"] for s in self.subs.values() if s["auc"]["auc_id"] == auc_id)
        sqn = auc["sqn"]
        if set_sqn is not None:
            sqn = set_sqn if policy == "set" else max(sqn, set_sqn)
        auc["sqn"] = (sqn + increment) & 0xFFFFFFFFFFFF
        return auc["sqn"]

    def Update_Serving_AMF(self, imsi, serving_amf):
        self.serving_amf[imsi] = serving_amf


@pytest.fixture(scope="module")
def spec():
    config = openapi_core.Config(
        spec_validator_cls=None,
        # JSON based media types used by 3GPP SBIs
        extra_media_type_deserializers={
            "application/problem+json": json.loads,
            "application/json-patch+json": json.loads,
            "application/merge-patch+json": json.loads,
        },
    )
    return openapi_core.OpenAPI.from_file_path(str(spec_dir / "TS29504_Nudr_DR.yaml"), config=config)


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def udr(db, spec):
    log = []
    app = create_app(db, {"default_snssai": {"sst": 1}}, lambda level, message: log.append((level, message)))

    def call(method, path, body=None, content_type="application/json", version="v2", validate=True):
        headers = {}
        content = None
        if body is not None:
            content = json.dumps(body).encode()
            headers["content-type"] = content_type

        async def request():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://udr") as client:
                return await client.request(method, f"/nudr-dr/{version}{path}", content=content, headers=headers)

        response = asyncio.run(request())
        if validate:
            path_only, _, query = path.partition("?")
            spec_request = MockRequest(
                SPEC_SERVER,
                method.lower(),
                f"/nudr-dr/v2{path_only}",
                args=dict(parse_qsl(query)) if query else None,
                data=content,
                content_type=headers.get("content-type", "application/json"),
            )
            spec.validate_request(spec_request)
            spec.validate_response(
                spec_request,
                MockResponse(
                    response.content,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type", "application/json"),
                ),
            )
        return response

    call.app = app
    call.log = log
    return call


def provisioned(path):
    return f"/subscription-data/{UE_ID}/00101/provisioned-data{path}"


def snssai_query(value):
    return quote(json.dumps(value, separators=(",", ":")))


# Authentication


def test_query_auth_subs_data(udr):
    r = udr("GET", f"/subscription-data/{UE_ID}/authentication-data/authentication-subscription")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert r.json() == {
        "authenticationMethod": "5G_AKA",
        "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
        "authenticationManagementField": "8000",
        "sequenceNumber": {"sqn": "000000000000"},
    }


def test_open5gs_uses_api_v1(udr):
    r = udr("GET", f"/subscription-data/{UE_ID}/authentication-data/authentication-subscription", version="v1")
    assert r.status_code == 200
    r = udr("GET", f"/policy-data/ues/{UE_ID}/am-data", version="v9", validate=False)
    assert r.status_code == 404


def test_unknown_and_disabled_subscriber(udr, db):
    r = udr("GET", "/subscription-data/imsi-001019999999999/authentication-data/authentication-subscription")
    assert r.status_code == 404
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["cause"] == "USER_NOT_FOUND"
    r = udr("GET", "/subscription-data/nai-user@example.com/authentication-data/authentication-subscription")
    assert r.status_code == 404

    db.subs[IMSI]["subscriber"]["enabled"] = False
    r = udr("GET", f"/subscription-data/{UE_ID}/authentication-data/authentication-subscription")
    assert r.status_code == 403
    assert r.json()["cause"] == "AUTHENTICATION_REJECTED"


def test_resync_patch(udr, db):
    path = f"/subscription-data/{UE_ID}/authentication-data/authentication-subscription"
    # As sent by the Open5GS UDM after verifying AUTS: SQN_MS + 33
    patch = [{"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000021"}]
    r = udr("PATCH", path, patch, content_type="application/json-patch+json")
    assert r.status_code == 204
    assert r.content == b""
    assert db.subs[IMSI]["auc"]["sqn"] == 0x21 + 32

    # A resync never moves the SQN backwards (shared with S6a)
    db.subs[IMSI]["auc"]["sqn"] = 5000
    r = udr("PATCH", path, patch, content_type="application/json-patch+json")
    assert r.status_code == 204
    assert db.subs[IMSI]["auc"]["sqn"] == 5032


def test_resync_patch_errors(udr):
    path = f"/subscription-data/{UE_ID}/authentication-data/authentication-subscription"
    patch = [{"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000021"}]
    # Wrong content type (the spec requires application/json-patch+json)
    r = udr("PATCH", path, patch, content_type="application/json", validate=False)
    assert r.status_code == 415
    r = udr("PATCH", path, [{"op": "replace", "path": "/encOpcKey", "value": "00"}], "application/json-patch+json")
    assert r.status_code == 400
    r = udr("PATCH", path, [{"op": "explode", "path": "/sequenceNumber/sqn"}], "application/json-patch+json")
    assert r.status_code == 400
    r = udr("PATCH", path, [{"op": "replace", "path": SQN, "value": "xyz"}], "application/json-patch+json")
    assert r.status_code == 400


def test_authentication_status(udr, db):
    path = f"/subscription-data/{UE_ID}/authentication-data/authentication-status"
    event = {
        "nfInstanceId": AMF_ID,
        "success": True,
        "timeStamp": "2026-10-19T09:07:41.123456Z",
        "authType": "5G_AKA",
        "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
    }
    r = udr("PUT", path, event)
    assert r.status_code == 204
    assert db.subs[IMSI]["auc"]["sqn"] == 32
    r = udr("DELETE", path)
    assert r.status_code == 204
    assert db.subs[IMSI]["auc"]["sqn"] == 64

    r = udr("PUT", path, {"success": True}, validate=False)
    assert r.status_code == 400
    assert r.json()["cause"] == "MANDATORY_IE_INCORRECT"
    r = udr("PUT", path, validate=False)
    assert r.status_code == 400
    assert db.subs[IMSI]["auc"]["sqn"] == 64


# Context data


def test_amf_3gpp_access(udr, db):
    path = f"/subscription-data/{UE_ID}/context-data/amf-3gpp-access"
    registration = {
        "amfInstanceId": AMF_ID,
        "deregCallbackUri": f"http://10.33.33.20:7777/namf-callback/v1/{UE_ID}/dereg-notify",
        "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
        "ratType": "NR",
        "pei": "imeisv-4370816125816151",
    }
    r = udr("PUT", path, registration)
    # Open5GS' UDM only accepts 204, which the spec allows also on creation
    assert r.status_code == 204
    assert db.serving_amf[IMSI] == AMF_ID

    r = udr("PATCH", path, [{"op": "replace", "path": "/purgeFlag", "value": True}], "application/json-patch+json")
    assert r.status_code == 204
    assert db.serving_amf[IMSI] is None


def test_smf_registrations(udr):
    path = f"/subscription-data/{UE_ID}/context-data/smf-registrations/1"
    registration = {
        "smfInstanceId": AMF_ID,
        "pduSessionId": 1,
        "singleNssai": {"sst": 1},
        "dnn": "internet",
        "plmnId": {"mcc": "001", "mnc": "01"},
    }
    assert udr("PUT", path, registration).status_code == 204
    assert udr("DELETE", path).status_code == 204


# Provisioned data


def test_am_data(udr):
    r = udr("GET", provisioned("/am-data"))
    assert r.status_code == 200
    assert r.json() == {
        "gpsis": ["msisdn-491701234567"],
        "subscribedUeAmbr": {"uplink": "500 Mbps", "downlink": "1 Gbps"},
        "nssai": {"defaultSingleNssais": [{"sst": 1}], "singleNssais": [{"sst": 2, "sd": "0000ab"}]},
    }
    r = udr("GET", provisioned("/am-data?fields=nssai"))
    assert list(r.json()) == ["nssai"]


def test_am_data_without_ue_ambr(udr, db):
    db.subs[IMSI]["subscriber"]["ue_ambr_dl"] = 0
    db.subs[IMSI]["subscriber"]["ue_ambr_ul"] = 0
    r = udr("GET", provisioned("/am-data"))
    assert r.status_code == 404
    assert r.json()["cause"] == "DATA_NOT_FOUND"


def test_smf_selection_subscription_data(udr):
    r = udr("GET", provisioned("/smf-selection-subscription-data"))
    assert r.status_code == 200
    assert r.json() == {
        "subscribedSnssaiInfos": {
            "1": {"dnnInfos": [{"dnn": "internet", "defaultDnnIndicator": True}]},
            "2-0000ab": {"dnnInfos": [{"dnn": "iot"}]},
        }
    }


def test_sm_data(udr):
    r = udr("GET", provisioned("/sm-data"))
    assert r.status_code == 200
    data = r.json()
    assert [x["singleNssai"] for x in data] == [{"sst": 1}, {"sst": 2, "sd": "0000ab"}]
    assert data[0]["dnnConfigurations"]["internet"]["staticIpAddress"] == [{"ipv4Addr": "10.45.0.9"}]

    # Query as sent by Open5GS' UDM
    r = udr("GET", provisioned(f"/sm-data?single-nssai={snssai_query({'sst': 1})}&dnn=internet"))
    assert r.status_code == 200
    assert [list(x["dnnConfigurations"]) for x in r.json()] == [["internet"]]

    r = udr("GET", provisioned(f"/sm-data?single-nssai={snssai_query({'sst': 3})}"))
    assert r.status_code == 404
    r = udr("GET", provisioned("/sm-data?single-nssai=garbage"), validate=False)
    assert r.status_code == 400


def test_provisioned_data_sets(udr):
    r = udr("GET", provisioned("?dataset-names=AM,SMF_SEL"))
    assert r.status_code == 200
    assert sorted(r.json()) == ["amData", "smfSelData"]
    r = udr("GET", provisioned("?dataset-names=AM,SMF_SEL,SM"))
    assert sorted(r.json()) == ["amData", "smData", "smfSelData"]


# Policy data


def test_policy_am_data(udr):
    r = udr("GET", f"/policy-data/ues/{UE_ID}/am-data")
    assert r.status_code == 200
    assert r.json() == {}


def test_policy_sm_data(udr):
    r = udr("GET", f"/policy-data/ues/{UE_ID}/sm-data?snssai={snssai_query({'sst': 2, 'sd': '0000ab'})}&dnn=iot")
    assert r.status_code == 200
    assert r.json() == {
        "smPolicySnssaiData": {
            "2-0000ab": {"snssai": {"sst": 2, "sd": "0000ab"}, "smPolicyDnnData": {"iot": {"dnn": "iot"}}}
        }
    }
    r = udr("GET", f"/policy-data/ues/{UE_ID}/sm-data")
    assert sorted(r.json()["smPolicySnssaiData"]) == ["1", "2-0000ab"]
    r = udr("GET", f"/policy-data/ues/{UE_ID}/sm-data?snssai={snssai_query({'sst': 3})}")
    assert r.status_code == 404


# Generic behaviour


def test_unknown_resource_and_method(udr):
    r = udr("GET", f"/subscription-data/{UE_ID}/no-such-resource", validate=False)
    assert r.status_code == 404
    assert r.json()["cause"] == "RESOURCE_URI_STRUCTURE_NOT_FOUND"
    r = udr("POST", f"/policy-data/ues/{UE_ID}/am-data", validate=False)
    assert r.status_code == 405


def test_internal_error(udr, db):
    def broken(imsi):
        raise RuntimeError("database down")

    db.Get_5G_Subscription = broken
    r = udr("GET", f"/policy-data/ues/{UE_ID}/am-data")
    assert r.status_code == 500
    assert r.json()["cause"] == "SYSTEM_FAILURE"
    assert any(level == "error" and "database down" in message for level, message in udr.log)


def load_spec_paths():
    """(method, path template) -> operationId of TS29504, with path $refs into other files resolved."""
    docs = {}

    def load(name):
        if name not in docs:
            with open(spec_dir / name) as f:
                docs[name] = yaml.safe_load(f)
        return docs[name]

    def resolve(name, node):
        while "$ref" in node:
            ref_file, _, pointer = node["$ref"].partition("#")
            name = ref_file or name
            node = load(name)
            for part in pointer.strip("/").split("/"):
                node = node[part.replace("~1", "/").replace("%7B", "{").replace("%7D", "}")]
        return node

    operations = {}
    for path, item in load("TS29504_Nudr_DR.yaml")["paths"].items():
        item = resolve("TS29504_Nudr_DR.yaml", item)
        for method, operation in item.items():
            if method in ("get", "put", "patch", "delete", "post"):
                operations[(method.upper(), path)] = operation["operationId"]
    return operations


def test_routes_conform_to_spec(udr):
    operations = load_spec_paths()
    assert udr.app.routes
    for route in udr.app.routes:
        key = (route.method, route.template)
        assert key in operations, f"{key} is not in TS 29.504"
        assert operations[key] == route.operation_id
