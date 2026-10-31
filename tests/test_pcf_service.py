# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import copy

import httpx
from database import APN, Database
from logtool import LogTool
from pyhss_config import config
from test_pcf_app import AM_REQUEST, SM_CONTEXT

# Subscriber created by the create_test_db fixture
IMSI = "262423403000001"
BASE = f"http://127.0.0.1:{config['pcf']['bind_port']}"


def test_pcf_service(run_redis, create_test_db, run_pyhss_pcf):
    database = Database(LogTool(config))
    # The fixture's APN has no APN-AMBR, so it can't be used in 5G
    apn = database.GetObj(APN, 1)
    database.UpdateObj(APN, {**apn, "apn_ambr_dl": 1000000, "apn_ambr_ul": 1000000}, 1)

    async def scenario():
        async with httpx.AsyncClient(http1=False, http2=True) as client:
            body = {**copy.deepcopy(AM_REQUEST), "supi": f"imsi-{IMSI}"}
            r = await client.post(f"{BASE}/npcf-am-policy-control/v1/policies", json=body)
            assert r.http_version == "HTTP/2"
            assert r.status_code == 201, r.text
            assert r.headers["location"].startswith("http://127.0.0.1:")
            r = await client.delete(r.headers["location"])
            assert r.status_code == 204

            body = {**copy.deepcopy(SM_CONTEXT), "supi": f"imsi-{IMSI}", "dnn": apn["apn"]}
            r = await client.post(f"{BASE}/npcf-smpolicycontrol/v1/sm-policies", json=body)
            assert r.status_code == 201, r.text
            assert r.json()["sessRules"]["1"]["authDefQos"]["5qi"] == 9
            r = await client.post(f"{r.headers['location']}/delete", json={})
            assert r.status_code == 204

    try:
        asyncio.run(scenario())
    finally:
        # The test database is shared with the other tests
        database.UpdateObj(APN, apn, 1)
