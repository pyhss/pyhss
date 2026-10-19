# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio

import httpx
from database import AUC, Database
from logtool import LogTool
from pyhss_config import config

# Subscriber created by the create_test_db fixture
IMSI = "262423403000001"
BASE = f"http://127.0.0.1:{config['udr']['bind_port']}/nudr-dr/v1/subscription-data/imsi-{IMSI}"


def get_sqn():
    return Database(LogTool(config)).GetObj(AUC, 1)["sqn"]


def test_udr_service(run_redis, create_test_db, run_pyhss_udr):
    async def scenario():
        # HTTP/2 with prior knowledge (h2c), as Open5GS uses it
        async with httpx.AsyncClient(http1=False, http2=True) as client:
            r = await client.get(f"{BASE}/authentication-data/authentication-subscription")
            assert r.http_version == "HTTP/2"
            assert r.status_code == 200
            auth = r.json()
            assert auth["encPermanentKey"] == "3c6e0b8a9c15224a8228b9a98ca1531d"
            assert auth["sequenceNumber"]["sqn"] == f"{get_sqn():012x}"

            # SQN resync, as sent by the UDM after it verified the AUTS of the UE
            sqn = get_sqn() + 1000
            r = await client.patch(
                f"{BASE}/authentication-data/authentication-subscription",
                json=[{"op": "replace", "path": "/sequenceNumber/sqn", "value": f"{sqn:012x}"}],
                headers={"content-type": "application/json-patch+json"},
            )
            assert r.status_code == 204
            assert get_sqn() == sqn + 32

            r = await client.put(
                f"{BASE}/authentication-data/authentication-status",
                json={
                    "nfInstanceId": "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab",
                    "success": True,
                    "timeStamp": "2026-10-19T09:07:41Z",
                    "authType": "5G_AKA",
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
                },
            )
            assert r.status_code == 204
            assert get_sqn() == sqn + 64

            r = await client.get(f"{BASE}/00101/provisioned-data/am-data")
            assert r.status_code == 200
            assert r.json()["gpsis"] == ["msisdn-100"]

            # The fixture's APN has no APN-AMBR, so it can't be used in 5G
            r = await client.get(f"{BASE}/00101/provisioned-data/sm-data")
            assert r.status_code == 404
            assert r.headers["content-type"] == "application/problem+json"

    asyncio.run(scenario())
