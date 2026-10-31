# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Npcf services (3GPP TS 29.507, 29.512, 29.514) as an ASGI application.

Serves Npcf_AMPolicyControl, Npcf_SMPolicyControl and Npcf_PolicyAuthorization from the PyHSS
subscriber data, without MongoDB. Policy is derived from the APN table, see docs/5g_pcf.md.
Path templates and operationIds are those of the 3GPP OpenAPI specs in specs/3gpp/.
"""

import asyncio
import re
import uuid

from pcf import datamodel
from pcf.policy import PolicyManager
from sbi import models
from sbi.server import JSON, MERGE_PATCH, Response, SbiApp, SbiError, SbiMultiApp
from udr.datamodel import usable_apns

IMSI_SUPI = re.compile(r"^imsi-([0-9]{5,15})$")

AM_BASE = "/npcf-am-policy-control"
SM_BASE = "/npcf-smpolicycontrol"
PA_BASE = "/npcf-policyauthorization"


def service_uri(pcf_config):
    host = pcf_config.get("advertise_ip") or pcf_config.get("bind_ip", "127.0.0.1")
    return f"http://{host}:{pcf_config.get('bind_port', 7777)}"


def no_content():
    return Response(204)


def create_app(database, pcf_config, store, notifier, log=None):
    """database: a database.Database, pcf_config: the "pcf" section of config.yaml."""
    log = log or (lambda level, message: None)
    versions = pcf_config.get("api_versions", ["v1"])
    base_uri = service_uri(pcf_config)
    ims_dnn = pcf_config.get("ims_dnn", "ims")
    manager = PolicyManager(store, notifier, base_uri, pcf_config, log)

    am = SbiApp(AM_BASE, versions, log)
    sm = SbiApp(SM_BASE, versions, log)
    pa = SbiApp(PA_BASE, versions, log)

    def warn(message):
        log("warning", message)

    def location(base, resource):
        return {"Location": f"{base_uri}{base}/{versions[0]}{resource}"}

    async def subscription(supi):
        match = IMSI_SUPI.match(supi)
        if not match:
            return None
        return await asyncio.to_thread(database.Get_5G_Subscription, match.group(1))

    async def charging_rules(apn):
        rules = []
        for rule_id in str(apn.get("charging_rule_list") or "").split(","):
            rule_id = rule_id.strip()
            if not rule_id.isdigit():
                continue
            try:
                rules.append(await asyncio.to_thread(database.Get_Charging_Rule, int(rule_id)))
            except Exception as e:
                warn(f"APN {apn['apn']}: can't load charging rule {rule_id}: {e}")
        return rules

    def find(item, what):
        if item is None:
            raise SbiError(404, "CONTEXT_NOT_FOUND", f"No such {what}")
        return item

    # Npcf_AMPolicyControl

    @am.route("POST", "/policies", "CreateIndividualAMPolicyAssociation")
    async def create_am_policy(request):
        request.model(models.PolicyAssociationRequest)
        body = request.json()
        sub = await subscription(body["supi"])
        if sub is None:
            raise SbiError(404, "USER_NOT_FOUND", f"No subscriber for {body['supi']}")
        if not sub["subscriber"].get("enabled", True):
            raise SbiError(403, "POLICY_ASSOCIATION_DENIED", "Subscriber is disabled")
        association = datamodel.am_policy_association(body, sub)
        association_id = uuid.uuid4().hex
        await asyncio.to_thread(store.save_am, association_id, association)
        log("info", f"{body['supi']}: AM policy association {association_id}")
        return Response(201, association, headers=location(AM_BASE, f"/policies/{association_id}"))

    @am.route("GET", "/policies/{polAssoId}", "ReadIndividualAMPolicyAssociation")
    async def read_am_policy(request, polAssoId):
        return Response(200, find(await asyncio.to_thread(store.get_am, polAssoId), "AM policy association"))

    @am.route("DELETE", "/policies/{polAssoId}", "DeleteIndividualAMPolicyAssociation")
    async def delete_am_policy(request, polAssoId):
        find(await asyncio.to_thread(store.get_am, polAssoId), "AM policy association")
        await asyncio.to_thread(store.delete_am, polAssoId)
        return no_content()

    @am.route("POST", "/policies/{polAssoId}/update", "ReportObservedEventTriggersForIndividualAMPolicyAssociation")
    async def update_am_policy(request, polAssoId):
        request.model(models.PolicyAssociationUpdateRequest)
        find(await asyncio.to_thread(store.get_am, polAssoId), "AM policy association")
        return Response(200, {"resourceUri": location(AM_BASE, f"/policies/{polAssoId}")["Location"]})

    # Npcf_SMPolicyControl

    @sm.route("POST", "/sm-policies", "CreateSMPolicy")
    async def create_sm_policy(request):
        request.model(models.SmPolicyContextData)
        context = request.json()
        supi = context["supi"]
        sub = await subscription(supi)
        if sub is None:
            raise SbiError(400, "USER_UNKNOWN", f"No subscriber for {supi}")
        dnn = datamodel.bare_dnn(context["dnn"])
        apn = next((x for x in usable_apns(sub, warn) if x["apn"].lower() == dnn), None)
        if apn is None or not sub["subscriber"].get("enabled", True):
            raise SbiError(403, "POLICY_CONTEXT_DENIED", f"{supi} can't use DNN {context['dnn']}")
        decision = datamodel.sm_policy_decision(context, apn, await charging_rules(apn), warn)

        ipv4 = context.get("ipv4Address")
        if ipv4:
            stale = await asyncio.to_thread(store.find_sm, ipv4, dnn)
            if stale:
                log("info", f"Dropping stale SM policy {stale['id']} of {ipv4}")
                await asyncio.to_thread(manager.drop_session, stale)
        session = {
            "id": uuid.uuid4().hex,
            "supi": supi,
            "dnn": dnn,
            "ipv4": ipv4,
            "notification_uri": context["notificationUri"],
            "context": context,
            "decision": decision,
            "apps": [],
        }
        await asyncio.to_thread(store.save_sm, session)
        log("info", f"{supi}: SM policy {session['id']} for {dnn}, UE IP {ipv4}")
        return Response(201, decision, headers=location(SM_BASE, f"/sm-policies/{session['id']}"))

    @sm.route("GET", "/sm-policies/{smPolicyId}", "GetSMPolicy")
    async def get_sm_policy(request, smPolicyId):
        session = find(await asyncio.to_thread(store.get_sm, smPolicyId), "SM policy")
        return Response(200, {"context": session["context"], "policy": session["decision"]})

    @sm.route("POST", "/sm-policies/{smPolicyId}/update", "UpdateSMPolicy")
    async def update_sm_policy(request, smPolicyId):
        request.model(models.SmPolicyUpdateContextData)
        update = request.json()
        session = find(await asyncio.to_thread(store.get_sm, smPolicyId), "SM policy")
        if update.get("ipv4Address"):
            session["ipv4"] = update["ipv4Address"]
            await asyncio.to_thread(store.save_sm, session)
        return Response(200, session["decision"])

    @sm.route("POST", "/sm-policies/{smPolicyId}/delete", "DeleteSMPolicy")
    async def delete_sm_policy(request, smPolicyId):
        session = find(await asyncio.to_thread(store.get_sm, smPolicyId), "SM policy")
        await asyncio.to_thread(manager.drop_session, session)
        log("info", f"{session['supi']}: SM policy {smPolicyId} deleted")
        return no_content()

    # Npcf_PolicyAuthorization

    @pa.route("POST", "/app-sessions", "PostAppSessions")
    async def post_app_sessions(request):
        request.model(models.AppSessionContext)
        context = request.json()
        data = context["ascReqData"]
        session = await asyncio.to_thread(store.find_sm, data.get("ueIpv4", ""), data.get("dnn") or ims_dnn)
        if session is None:
            raise SbiError(500, "PDU_SESSION_NOT_AVAILABLE", f"No PDU session for {data.get('ueIpv4')}")
        app_id = uuid.uuid4().hex
        context["ascRespData"] = {"suppFeat": "0"}
        await manager.install(app_id, session["id"], datamodel.media_from_af(data.get("medComponents")))
        app = store.get_app(app_id)
        app["context"] = context
        await asyncio.to_thread(store.save_app, app)
        return Response(201, context, headers=location(PA_BASE, f"/app-sessions/{app_id}"))

    @pa.route("GET", "/app-sessions/{appSessionId}", "GetAppSession")
    async def get_app_session(request, appSessionId):
        app = find(await asyncio.to_thread(store.get_app, appSessionId), "app session")
        return Response(200, app["context"])

    @pa.route("PATCH", "/app-sessions/{appSessionId}", "ModAppSession")
    async def mod_app_session(request, appSessionId):
        request.model(models.AppSessionContextUpdateDataPatch, (MERGE_PATCH, JSON))
        patch = request.json((MERGE_PATCH, JSON)).get("ascReqData") or {}
        app = find(await asyncio.to_thread(store.get_app, appSessionId), "app session")
        await manager.install(appSessionId, app["sm_id"], datamodel.media_from_af(patch.get("medComponents")))
        app = store.get_app(appSessionId)
        await asyncio.to_thread(store.save_app, app)
        return Response(200, app["context"])

    @pa.route("POST", "/app-sessions/{appSessionId}/delete", "DeleteAppSession")
    async def delete_app_session(request, appSessionId):
        find(await asyncio.to_thread(store.get_app, appSessionId), "app session")
        await manager.remove(appSessionId)
        return no_content()

    app = SbiMultiApp([am, sm, pa], log)
    app.manager = manager
    return app
