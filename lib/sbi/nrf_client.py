# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Nnrf_NFManagement client (3GPP TS 29.510): register an NF instance at the NRF and keep it alive.

Requests go over HTTP/2 cleartext with prior knowledge (h2c), the default of Open5GS. With
via_scp, they are sent to an SCP with the 3GPP discovery headers that make it forward them to
the NRF (indirect communication, TS 29.500 clause 6.10).
"""

import asyncio
import uuid

import httpx
from sbi import models

NNRF_NFM = "/nnrf-nfm/v1"

# Full version of each API version in the URI, as advertised in NFService.versions
API_FULL_VERSIONS = {
    "nudr-dr": {"v1": "1.0.0", "v2": "2.4.1"},
}


def build_nf_profile(
    nf_instance_id,
    nf_type,
    service_name,
    ipv4_address,
    port,
    api_versions,
    allowed_nf_types=None,
    service_allowed_nf_types=None,
    plmn_list=None,
    heartbeat_timer=None,
):
    service_instance_id = service_name
    service = {
        "serviceInstanceId": service_instance_id,
        "serviceName": service_name,
        "versions": [
            {"apiVersionInUri": v, "apiFullVersion": API_FULL_VERSIONS.get(service_name, {}).get(v, "1.0.0")}
            for v in api_versions
        ],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "ipEndPoints": [{"ipv4Address": ipv4_address, "transport": "TCP", "port": int(port)}],
    }
    if service_allowed_nf_types:
        service["allowedNfTypes"] = service_allowed_nf_types
    profile = {
        "nfInstanceId": str(nf_instance_id),
        "nfType": nf_type,
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [ipv4_address],
        "nfServiceList": {service_instance_id: service},
    }
    if allowed_nf_types:
        profile["allowedNfTypes"] = allowed_nf_types
    if plmn_list:
        profile["plmnList"] = plmn_list
    if heartbeat_timer:
        profile["heartBeatTimer"] = int(heartbeat_timer)
    return models.NFProfile.model_validate(profile)


class NrfClient:
    def __init__(
        self,
        nrf_uri,
        profile,
        via_scp=False,
        heartbeat_interval=10,
        retry_interval=5,
        log=None,
        transport=None,
    ):
        self.nrf_uri = nrf_uri.rstrip("/")
        self.profile = profile
        self.nf_type = profile.nfType.root
        self.via_scp = via_scp
        self.heartbeat_interval = heartbeat_interval
        self.retry_interval = retry_interval
        self.log = log or (lambda level, message: None)
        self.registered = False
        if transport:
            # For tests, e.g. httpx.ASGITransport(app=fake_nrf)
            self.client = httpx.AsyncClient(transport=transport, timeout=5)
        else:
            self.client = httpx.AsyncClient(http1=False, http2=True, timeout=5)

    @property
    def instance_url(self):
        return f"{self.nrf_uri}{NNRF_NFM}/nf-instances/{self.profile.nfInstanceId.root}"

    def headers(self, content_type=None):
        headers = {"user-agent": str(self.nf_type)}
        if self.via_scp:
            headers["3gpp-sbi-discovery-target-nf-type"] = "NRF"
            headers["3gpp-sbi-discovery-service-names"] = "nnrf-nfm"
        if content_type:
            headers["content-type"] = content_type
        return headers

    async def register(self):
        """NFRegister. Returns the heartbeat interval the NRF wants (in seconds)."""
        body = self.profile.model_dump(mode="json", by_alias=True, exclude_unset=True)
        response = await self.client.put(self.instance_url, json=body, headers=self.headers("application/json"))
        if response.status_code not in (200, 201):
            raise RuntimeError(f"NRF registration failed: {response.status_code} {response.text}")
        timer = self.heartbeat_interval
        try:
            registered = models.NFProfile.model_validate(response.json())
            if registered.heartBeatTimer:
                timer = registered.heartBeatTimer
        except ValueError as e:
            self.log("warning", f"Could not parse the NFProfile returned by the NRF: {e}")
        self.registered = True
        self.log("info", f"Registered {self.nf_type} {self.profile.nfInstanceId.root} at NRF (heartbeat {timer}s)")
        return timer

    async def heartbeat(self):
        """NFUpdate with the load. Returns False if the NRF no longer knows this NF instance."""
        patch = [
            models.PatchItem(op="replace", path="/nfStatus", value="REGISTERED"),
            models.PatchItem(op="replace", path="/load", value=0),
        ]
        body = [x.model_dump(mode="json", by_alias=True, exclude_unset=True) for x in patch]
        response = await self.client.patch(
            self.instance_url, json=body, headers=self.headers("application/json-patch+json")
        )
        if response.status_code == 404:
            self.registered = False
            return False
        if response.status_code not in (200, 204):
            raise RuntimeError(f"NRF heartbeat failed: {response.status_code} {response.text}")
        return True

    async def deregister(self):
        """NFDeregister"""
        if not self.registered:
            return
        response = await self.client.delete(self.instance_url, headers=self.headers())
        self.registered = False
        self.log("info", f"Deregistered from NRF ({response.status_code})")

    async def run(self):
        """Register and send heartbeats until cancelled, then deregister."""
        try:
            while True:
                try:
                    timer = await self.register()
                    # Heartbeat a bit early, Open5GS' NRF only allows little slack
                    interval = max(1, timer - 2)
                    while True:
                        await asyncio.sleep(interval)
                        if not await self.heartbeat():
                            self.log("warning", "NRF does not know this NF instance (anymore), registering again")
                            break
                except (httpx.HTTPError, RuntimeError) as e:
                    self.log("error", f"NRF: {e}, retrying in {self.retry_interval}s")
                    await asyncio.sleep(self.retry_interval)
        except asyncio.CancelledError:
            try:
                await asyncio.wait_for(self.deregister(), timeout=2)
            except Exception as e:
                self.log("warning", f"NRF deregistration failed: {e}")
            raise
        finally:
            await self.client.aclose()


def new_instance_id():
    return str(uuid.uuid4())
