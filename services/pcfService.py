#!/usr/bin/env python3
# PyHSS 5G PCF Service (Npcf_AMPolicyControl, Npcf_SMPolicyControl, Npcf_PolicyAuthorization)
# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import os
import sys
import traceback

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from database import Database
from logtool import LogTool
from messaging import RedisMessaging
from pcf.app import create_app
from pcf.policy import SmfNotifier
from pcf.store import PcfStore
from pyhss_config import config
from sbi.service import create_nrf_client, run_server

SERVICE_NAMES = ["npcf-am-policy-control", "npcf-smpolicycontrol", "npcf-policyauthorization"]


async def run_commands(store, manager, log):
    """Carry out what pyhss_hss queues for Rx sessions."""
    while True:
        command = await asyncio.to_thread(store.next_command)
        if command is None:
            continue
        try:
            await manager.apply(command)
        except Exception:
            log("error", f"PCF command {command} failed: {traceback.format_exc()}")


def main():
    pcf_config = config.get("pcf", {})

    redis_host = config.get("redis", {}).get("host", "127.0.0.1")
    redis_port = int(config.get("redis", {}).get("port", 6379))
    redis_use_unix_socket = config.get("redis", {}).get("useUnixSocket", False)
    redis_unix_socket_path = config.get("redis", {}).get("unixSocketPath", "/var/run/redis/redis-server.sock")
    redis_messaging = RedisMessaging(
        host=redis_host, port=redis_port, useUnixSocket=redis_use_unix_socket, unixSocketPath=redis_unix_socket_path
    )

    log_tool = LogTool(config)

    def log(level, message):
        log_tool.log(service="PCF", level=level, message=f"[pcfService.py] {message}", redisClient=redis_messaging)

    database = Database(log_tool, redisMessaging=redis_messaging)
    store = PcfStore(redis_messaging.redisClient)
    app = create_app(database, pcf_config, store, SmfNotifier(log), log)
    allowed_nf_types = pcf_config.get("allowed_nf_types", ["SCP", "AMF", "SMF", "AF", "NEF"])
    nrf_client = create_nrf_client(pcf_config, "pcf", "PCF", SERVICE_NAMES, allowed_nf_types, config["hss"], log)
    asyncio.run(run_server(app, pcf_config, nrf_client, log, [run_commands(store, app.manager, log)]))


if __name__ == "__main__":
    main()
