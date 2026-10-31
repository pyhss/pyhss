# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""PCF state in redis, shared by pyhss_pcf and pyhss_hss (which answers Rx).

The keys have no expiry: the SMF and AMF delete their policies, and a new session for the same
UE IP replaces a stale one.
"""

import json

PREFIX = "pcf"
COMMANDS = f"{PREFIX}:commands"


def bare_dnn(dnn):
    """The Network Identifier of a DNN, which Open5GS may send with its Operator Identifier."""
    return dnn.split(".mnc", 1)[0].lower()


class PcfStore:
    def __init__(self, redis_client):
        self.redis = redis_client

    def load(self, key):
        value = self.redis.get(key)
        return json.loads(value) if value else None

    def save(self, key, value):
        self.redis.set(key, json.dumps(value))

    # AM policy associations

    def save_am(self, association_id, association):
        self.save(f"{PREFIX}:am:{association_id}", association)

    def get_am(self, association_id):
        return self.load(f"{PREFIX}:am:{association_id}")

    def delete_am(self, association_id):
        self.redis.delete(f"{PREFIX}:am:{association_id}")

    # SM policy associations, found by UE IP and DNN

    def ue_key(self, ipv4, dnn):
        return f"{PREFIX}:ue:{ipv4}:{bare_dnn(dnn)}"

    def save_sm(self, session):
        previous = self.get_sm(session["id"])
        if previous and previous.get("ipv4") and previous.get("ipv4") != session.get("ipv4"):
            self.redis.delete(self.ue_key(previous["ipv4"], previous["dnn"]))
        self.save(f"{PREFIX}:sm:{session['id']}", session)
        if session.get("ipv4"):
            self.redis.set(self.ue_key(session["ipv4"], session["dnn"]), session["id"])

    def get_sm(self, session_id):
        return self.load(f"{PREFIX}:sm:{session_id}")

    def find_sm(self, ipv4, dnn):
        session_id = self.redis.get(self.ue_key(ipv4, dnn))
        if not session_id:
            return None
        return self.get_sm(session_id.decode() if isinstance(session_id, bytes) else session_id)

    def delete_sm(self, session):
        if session.get("ipv4"):
            self.redis.delete(self.ue_key(session["ipv4"], session["dnn"]))
        self.redis.delete(f"{PREFIX}:sm:{session['id']}")

    # AF sessions (Npcf_PolicyAuthorization app sessions, Rx sessions)

    def save_app(self, app):
        self.save(f"{PREFIX}:app:{app['id']}", app)

    def get_app(self, app_id):
        return self.load(f"{PREFIX}:app:{app_id}")

    def delete_app(self, app_id):
        self.redis.delete(f"{PREFIX}:app:{app_id}")

    def save_rx(self, rx_session_id, app_id):
        self.redis.set(f"{PREFIX}:rx:{rx_session_id}", app_id)

    def find_rx(self, rx_session_id):
        app_id = self.redis.get(f"{PREFIX}:rx:{rx_session_id}")
        return app_id.decode() if isinstance(app_id, bytes) else app_id

    def delete_rx(self, rx_session_id):
        self.redis.delete(f"{PREFIX}:rx:{rx_session_id}")

    # Commands from Rx to pyhss_pcf, in order

    def push_command(self, command):
        self.redis.rpush(COMMANDS, json.dumps(command))

    def next_command(self, timeout=1):
        item = self.redis.blpop(COMMANDS, timeout=timeout)
        return json.loads(item[1]) if item else None
