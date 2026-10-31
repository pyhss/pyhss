# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the PyHSS SBI services have in common: NRF registration and running the HTTP/2 server."""

import asyncio
import signal
import socket
import uuid

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from sbi.nrf_client import NrfClient, build_nf_profile


def nf_instance_id(service_config, name):
    # A stable ID by default, so a restarted service replaces its own NRF registration
    configured = service_config.get("nf_instance_id")
    if configured:
        return str(configured)
    port = service_config.get("bind_port", 7777)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"pyhss-{name}.{socket.gethostname()}:{port}"))


def create_nrf_client(service_config, name, nf_type, service_names, allowed_nf_types, hss_config, log):
    """service_config: the config.yaml section of the service. None if NRF registration is off."""
    nrf_config = service_config.get("nrf", {})
    if not nrf_config.get("enabled", False):
        return None
    plmn_list = None
    if nrf_config.get("send_plmn_list", False):
        plmn_list = [{"mcc": str(hss_config["MCC"]), "mnc": str(hss_config["MNC"])}]
    profile = build_nf_profile(
        nf_instance_id(service_config, name),
        nf_type,
        service_names,
        service_config.get("advertise_ip") or service_config.get("bind_ip", "127.0.0.1"),
        service_config.get("bind_port", 7777),
        service_config.get("api_versions", ["v1"]),
        allowed_nf_types=allowed_nf_types,
        # The SCP only forwards requests, the service itself is used by the other NF types
        service_allowed_nf_types=[t for t in allowed_nf_types if t != "SCP"],
        plmn_list=plmn_list,
        heartbeat_timer=nrf_config.get("heartbeat_interval", 10),
    )
    return NrfClient(
        nrf_config.get("uri", "http://127.0.0.1:7777"),
        profile,
        via_scp=nrf_config.get("via_scp", False),
        heartbeat_interval=nrf_config.get("heartbeat_interval", 10),
        retry_interval=nrf_config.get("retry_interval", 5),
        log=log,
    )


async def run_server(app, service_config, nrf_client, log, background=()):
    """Serve app (h2c) and run the NRF client and the background coroutines until a signal."""
    hypercorn_config = HypercornConfig()
    hypercorn_config.bind = [f"{service_config.get('bind_ip', '127.0.0.1')}:{service_config.get('bind_port', 7777)}"]
    # SCPs and NFs keep their HTTP/2 connections open, don't close them after 5s idle
    hypercorn_config.keep_alive_timeout = service_config.get("keep_alive_timeout", 3600)
    hypercorn_config.accesslog = None

    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)

    tasks = [asyncio.create_task(coroutine) for coroutine in background]
    if nrf_client:
        tasks.append(asyncio.create_task(nrf_client.run()))

    log("info", f"Serving SBI (h2c) on {hypercorn_config.bind[0]}")
    try:
        await serve(app, hypercorn_config, shutdown_trigger=shutdown.wait)
    finally:
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
