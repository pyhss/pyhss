# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dedicated QoS flows of AF sessions: installed and removed with SM policy update notifications."""

import httpx
from pcf import datamodel


class SmfNotifier:
    """Sends Npcf_SMPolicyControl UpdateNotify to the SMF (h2c, as Open5GS NFs do)."""

    def __init__(self, log=None, transport=None):
        self.log = log or (lambda level, message: None)
        if transport:
            self.client = httpx.AsyncClient(transport=transport, timeout=5)
        else:
            self.client = httpx.AsyncClient(http1=False, http2=True, timeout=5)

    async def update(self, notification_uri, resource_uri, decision):
        url = f"{notification_uri.rstrip('/')}/update"
        body = {"resourceUri": resource_uri, "smPolicyDecision": decision}
        try:
            response = await self.client.post(url, json=body)
        except httpx.HTTPError as e:
            self.log("error", f"SM policy update to {url} failed: {e}")
            return False
        if response.status_code not in (200, 204):
            self.log("error", f"SM policy update to {url} failed: {response.status_code} {response.text}")
            return False
        return True


class PolicyManager:
    def __init__(self, store, notifier, base_uri, config, log=None):
        self.store = store
        self.notifier = notifier
        self.base_uri = base_uri
        self.config = config
        self.log = log or (lambda level, message: None)

    def sm_resource_uri(self, session_id):
        return f"{self.base_uri}/npcf-smpolicycontrol/v1/sm-policies/{session_id}/update"

    async def notify(self, session, decision):
        return await self.notifier.update(session["notification_uri"], self.sm_resource_uri(session["id"]), decision)

    async def install(self, app_id, session_id, media):
        """Create or update an AF session. False if its PDU session is gone."""
        session = self.store.get_sm(session_id)
        if session is None:
            self.log("warning", f"AF session {app_id}: PDU session {session_id} is gone")
            return False
        app = self.store.get_app(app_id) or {"id": app_id, "sm_id": session_id, "media": [], "rules": []}
        app["media"] = datamodel.merge_media(app["media"], media)
        pcc_rules, qos_decs = datamodel.media_decision(app["media"], app_id, self.config)
        decision = {}
        if pcc_rules:
            decision = {"pccRules": dict(pcc_rules), "qosDecs": qos_decs}
        for rule_id in app["rules"]:
            if rule_id not in pcc_rules:
                decision.setdefault("pccRules", {})[rule_id] = None
        app["rules"] = list(pcc_rules)
        self.store.save_app(app)
        if app_id not in session["apps"]:
            session["apps"].append(app_id)
            self.store.save_sm(session)
        if decision:
            await self.notify(session, decision)
        return True

    async def remove(self, app_id):
        app = self.store.get_app(app_id)
        if app is None:
            return
        self.store.delete_app(app_id)
        session = self.store.get_sm(app["sm_id"])
        if session is None:
            return
        session["apps"] = [x for x in session["apps"] if x != app_id]
        self.store.save_sm(session)
        if app["rules"]:
            await self.notify(session, {"pccRules": {rule_id: None for rule_id in app["rules"]}})

    def drop_session(self, session):
        """The PDU session is gone, and with it its QoS flows: nothing to tell the SMF."""
        for app_id in session["apps"]:
            self.store.delete_app(app_id)
        self.store.delete_sm(session)

    async def apply(self, command):
        if command["op"] == "install":
            await self.install(command["app_id"], command["sm_id"], command["media"])
        elif command["op"] == "remove":
            await self.remove(command["app_id"])
        else:
            self.log("warning", f"Unknown PCF command: {command}")
