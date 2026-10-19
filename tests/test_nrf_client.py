# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import json
from pathlib import Path

import httpx
import pytest
from sbi.nrf_client import NrfClient, build_nf_profile

openapi_core = pytest.importorskip("openapi_core")
from openapi_core.testing import MockRequest

spec_path = Path(__file__).resolve().parent.parent / "specs/3gpp/r19-20260402/TS29510_Nnrf_NFManagement.yaml"
INSTANCE_ID = "6a1e2b7c-0d4f-4c3a-9a51-3c1f0d2e9b10"


class FakeNrf:
    """ASGI app recording the requests, answering like Open5GS' NRF."""

    def __init__(self, heartbeat_timer=1):
        self.requests = []
        self.heartbeat_timer = heartbeat_timer
        self.known = False
        self.fail_next = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        headers = {k.decode(): v.decode() for k, v in scope["headers"]}
        self.requests.append((scope["method"], scope["path"], headers, json.loads(body) if body else None))

        status, reply = 500, None
        if self.fail_next:
            self.fail_next -= 1
        elif scope["method"] == "PUT":
            status = 200 if self.known else 201
            reply = dict(json.loads(body), heartBeatTimer=self.heartbeat_timer)
            self.known = True
        elif scope["method"] == "PATCH":
            status = 204 if self.known else 404
        elif scope["method"] == "DELETE":
            status = 204
            self.known = False
        payload = json.dumps(reply).encode() if reply else b""
        await send(
            {"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]}
        )
        await send({"type": "http.response.body", "body": payload})

    def methods(self):
        return [r[0] for r in self.requests]


def profile():
    return build_nf_profile(
        INSTANCE_ID,
        "UDR",
        "nudr-dr",
        "10.33.33.18",
        7777,
        ["v1", "v2"],
        allowed_nf_types=["SCP", "PCF", "UDM"],
        service_allowed_nf_types=["PCF", "UDM"],
    )


def client(nrf, via_scp=False):
    return NrfClient(
        "http://scp:7777", profile(), via_scp=via_scp, retry_interval=0.1, transport=httpx.ASGITransport(app=nrf)
    )


def test_nf_profile_conforms_to_spec():
    spec = openapi_core.OpenAPI.from_file_path(str(spec_path), config=openapi_core.Config(spec_validator_cls=None))
    body = json.dumps(profile().model_dump(mode="json", by_alias=True, exclude_unset=True)).encode()
    request = MockRequest(
        "https://example.com",
        "put",
        f"/nnrf-nfm/v1/nf-instances/{INSTANCE_ID}",
        data=body,
        content_type="application/json",
    )
    spec.validate_request(request)
    assert json.loads(body) == {
        "nfInstanceId": INSTANCE_ID,
        "nfType": "UDR",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": ["10.33.33.18"],
        "allowedNfTypes": ["SCP", "PCF", "UDM"],
        "nfServiceList": {
            "nudr-dr": {
                "serviceInstanceId": "nudr-dr",
                "serviceName": "nudr-dr",
                "versions": [
                    {"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"},
                    {"apiVersionInUri": "v2", "apiFullVersion": "2.4.1"},
                ],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "10.33.33.18", "transport": "TCP", "port": 7777}],
                "allowedNfTypes": ["PCF", "UDM"],
            }
        },
    }


def test_register_heartbeat_deregister():
    nrf = FakeNrf(heartbeat_timer=10)
    c = client(nrf)

    async def scenario():
        assert await c.register() == 10
        assert await c.heartbeat() is True
        await c.deregister()
        await c.client.aclose()

    asyncio.run(scenario())
    assert nrf.methods() == ["PUT", "PATCH", "DELETE"]
    _method, path, headers, body = nrf.requests[1]
    assert path == f"/nnrf-nfm/v1/nf-instances/{INSTANCE_ID}"
    assert headers["content-type"] == "application/json-patch+json"
    assert body == [
        {"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
        {"op": "replace", "path": "/load", "value": 0},
    ]
    assert headers["user-agent"] == "UDR"
    assert "3gpp-sbi-discovery-target-nf-type" not in headers


def test_via_scp_headers():
    nrf = FakeNrf()
    c = client(nrf, via_scp=True)

    async def scenario():
        await c.register()
        await c.client.aclose()

    asyncio.run(scenario())
    headers = nrf.requests[0][2]
    assert headers["user-agent"] == "UDR"
    assert headers["3gpp-sbi-discovery-target-nf-type"] == "NRF"
    assert headers["3gpp-sbi-discovery-service-names"] == "nnrf-nfm"


def test_run_reregisters_retries_and_deregisters_on_cancel():
    nrf = FakeNrf(heartbeat_timer=1)
    nrf.fail_next = 1  # first registration fails
    c = client(nrf)

    async def scenario():
        task = asyncio.create_task(c.run())
        await asyncio.sleep(1.5)  # failed PUT, PUT, PATCH
        nrf.known = False  # NRF lost the registration (e.g. restarted)
        await asyncio.sleep(2.2)  # PATCH -> 404, PUT, PATCH
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert nrf.methods() == ["PUT", "PUT", "PATCH", "PATCH", "PUT", "PATCH", "DELETE"]
