# PyHSS test fixtures
# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import subprocess
import time
import pytest
import socket
import logging
from pathlib import Path

from database import Database, APN, AUC, SUBSCRIBER
from logtool import LogTool
from pyhss_config import config

top_dir = Path(Path(__file__) / "../..").resolve()
pyhss_env = {
    "PATH": os.environ["PATH"],
    "PYHSS_CONFIG": os.environ["PYHSS_CONFIG"],
    "PYTHONPATH": os.path.join(top_dir, "lib"),
    "PYTHONUNBUFFERED": "1",
}


def pytest_collection_modifyitems(session, config, items):
    def by_slow(item):
        return 0 if item.get_closest_marker("slow") is None else 1

    # Run slow tests at the end
    items.sort(key=by_slow, reverse=False)


def wait_for_tcp_port(port, timeout=5):
    hostname = "127.0.0.1"
    start_time = time.time()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((hostname, port))
            if result == 0:
                return

            if time.time() - start_time >= timeout:
                raise RuntimeError(f"{hostname}:{port} did not become available within {timeout}s!")

            time.sleep(0.1)


@pytest.fixture(scope="session")
def create_test_db():
    test_db = os.path.join(top_dir, "tests/.pyhss.db")
    test_imsi = "262423403000001"

    print("--- create_test_db fixture start ---")

    if os.path.exists(test_db):
        print(f"Removing previous test DB: {test_db}")
        os.unlink(test_db)

    db = Database(LogTool(config), main_service=True)
    assert os.path.exists(test_db)

    db.CreateObj(APN, {
        "apn_id": 1,
        "apn": "internet",
        "ip_version": 0,
        "charging_characteristics": "0800",
        "apn_ambr_dl": 0,
        "apn_ambr_ul": 0,
        "qci": 9,
        "arp_priority": 4,
        "arp_preemption_capability": 0,
        "arp_preemption_vulnerability": 1,
    })

    db.CreateObj(AUC, {
        "auc_id": 1,
        "ki": "3c6e0b8a9c15224a8228b9a98ca1531d",
        "opc": "762a2206fe0b4151ace403c86a11e479",
        "amf": "8000",
        "sqn": "0",
        "imsi": test_imsi,
        "algo": "0",
    })

    db.CreateObj(SUBSCRIBER, {
        "auc_id": 1,
        "default_apn": "internet",
        "apn_list": "1,2",
        "imsi": test_imsi,
        "msisdn": "100",
    })

    print("--- create_test_db fixture end ---")


@pytest.fixture(scope="session")
def run_redis():
    cmd = ["redis-server", os.path.join(top_dir, "tests/redis.conf")]
    print(f"+ {cmd}")
    try:
        proc = subprocess.Popen(cmd, env=pyhss_env)
    except FileNotFoundError:
        logging.error("redis-server not found. Please install Redis to run the tests.")
        raise

    try:
        wait_for_tcp_port(6379)
        yield
    finally:
        proc.kill()


@pytest.fixture(scope="session")
def run_pyhss_api():
    cmd = ["python3", os.path.join(top_dir, "services/apiService.py")]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd, env=pyhss_env)

    try:
        wait_for_tcp_port(8080)
        yield
    finally:
        proc.kill()


@pytest.fixture(scope="session")
def run_pyhss_hss():
    cmd = ["python3", os.path.join(top_dir, "services/hssService.py")]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd, env=pyhss_env)

    try:
        yield
    finally:
        proc.kill()


@pytest.fixture(scope="session")
def run_pyhss_gsup():
    cmd = ["python3", os.path.join(top_dir, "services/gsupService.py")]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd, env=pyhss_env)

    try:
        wait_for_tcp_port(4222)
        yield
    finally:
        proc.kill()


@pytest.fixture(scope="session")
def run_pyhss_udr():
    cmd = ["python3", os.path.join(top_dir, "services/udrService.py")]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd, env=pyhss_env)

    try:
        wait_for_tcp_port(config["udr"]["bind_port"], timeout=10)
        yield
    finally:
        proc.kill()
