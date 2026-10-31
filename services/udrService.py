#!/usr/bin/env python3
# PyHSS 5G UDR Service (Nudr_DataRepository over HTTP/2)
# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import os
import sys

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from database import Database
from logtool import LogTool
from messaging import RedisMessaging
from pyhss_config import config
from sbi.service import create_nrf_client, run_server
from udr.app import create_app


def main():
    udr_config = {"api_versions": ["v1", "v2"], **config.get("udr", {})}

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
    allowed_nf_types = udr_config.get("allowed_nf_types", ["SCP", "PCF", "UDM"])
    nrf_client = create_nrf_client(udr_config, "udr", "UDR", "nudr-dr", allowed_nf_types, config["hss"], log)
    asyncio.run(run_server(app, udr_config, nrf_client, log))


if __name__ == "__main__":
    main()
