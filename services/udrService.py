#!/usr/bin/env python3
# PyHSS 5G UDR Service (Nudr_DataRepository over HTTP/2)
# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import os
import signal
import socket
import sys
import uuid

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from database import Database
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from logtool import LogTool
from messaging import RedisMessaging
from pyhss_config import config
from sbi.nrf_client import NrfClient, build_nf_profile
from udr.app import create_app


def nf_instance_id(udr_config):
    # A stable ID by default, so a restarted UDR replaces its own NRF registration
    configured = udr_config.get("nf_instance_id")
    if configured:
        return str(configured)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"pyhss-udr.{socket.gethostname()}:{udr_config.get('bind_port', 7777)}"))


def create_nrf_client(udr_config, log):
    nrf_config = udr_config.get("nrf", {})
    if not nrf_config.get("enabled", False):
        return None
    allowed_nf_types = udr_config.get("allowed_nf_types", ["SCP", "PCF", "UDM"])
    plmn_list = None
    if nrf_config.get("send_plmn_list", False):
        plmn_list = [{"mcc": str(config["hss"]["MCC"]), "mnc": str(config["hss"]["MNC"])}]
    profile = build_nf_profile(
        nf_instance_id(udr_config),
        "UDR",
        "nudr-dr",
        udr_config.get("advertise_ip") or udr_config.get("bind_ip", "127.0.0.1"),
        udr_config.get("bind_port", 7777),
        udr_config.get("api_versions", ["v1", "v2"]),
        allowed_nf_types=allowed_nf_types,
        # The SCP only forwards requests, the service itself is used by these NF types
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


async def run(app, udr_config, log):
    hypercorn_config = HypercornConfig()
    hypercorn_config.bind = [f"{udr_config.get('bind_ip', '127.0.0.1')}:{udr_config.get('bind_port', 7777)}"]
    # SCPs and UDMs keep their HTTP/2 connections open, don't close them after 5s idle
    hypercorn_config.keep_alive_timeout = udr_config.get("keep_alive_timeout", 3600)
    hypercorn_config.accesslog = None

    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)

    nrf_client = create_nrf_client(udr_config, log)
    nrf_task = asyncio.create_task(nrf_client.run()) if nrf_client else None

    log("info", f"UDR serving Nudr_DR (h2c) on {hypercorn_config.bind[0]}")
    try:
        await serve(app, hypercorn_config, shutdown_trigger=shutdown.wait)
    finally:
        if nrf_task:
            nrf_task.cancel()
            try:
                await nrf_task
            except asyncio.CancelledError:
                pass


def main():
    udr_config = config.get("udr", {})

    redis_host = config.get("redis", {}).get("host", "127.0.0.1")
    redis_port = int(config.get("redis", {}).get("port", 6379))
    redis_use_unix_socket = config.get("redis", {}).get("useUnixSocket", False)
    redis_unix_socket_path = config.get("redis", {}).get("unixSocketPath", "/var/run/redis/redis-server.sock")
    redis_messaging = RedisMessaging(
        host=redis_host, port=redis_port, useUnixSocket=redis_use_unix_socket, unixSocketPath=redis_unix_socket_path
    )

    log_tool = LogTool(config)

    def log(level, message):
        log_tool.log(service="UDR", level=level, message=f"[udrService.py] {message}", redisClient=redis_messaging)

    database = Database(log_tool, redisMessaging=redis_messaging)
    app = create_app(database, udr_config, log)
    asyncio.run(run(app, udr_config, log))


if __name__ == "__main__":
    main()
