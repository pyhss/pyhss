# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Nudr_DataRepository (3GPP TS 29.504) ASGI application backed by the PyHSS database.

Implements the subset of resources a UDM and PCF use (as Open5GS 2.8.0 does): authentication
subscription and status, AMF/SMF registration context data, provisioned AM/SMF-selection/SM
subscription data and AM/SM policy data. Path templates and operationIds are those of the
3GPP OpenAPI specs in specs/3gpp/, which the tests validate requests and responses against.
"""

import asyncio
import re

from sbi import models
from sbi.server import JSON_PATCH, Response, SbiApp, SbiError
from udr import datamodel

SQN_PATH = "/sequenceNumber/sqn"
SQN_INCREMENT = 32  # added after an authentication event or a resync, as Open5GS' UDR does
IMSI_UE_ID = re.compile(r"^imsi-([0-9]{5,15})$")


def no_content():
    return Response(204)


def create_app(database, udr_config, log=None):
    """database: a database.Database instance, udr_config: the "udr" section of config.yaml."""
    log = log or (lambda level, message: None)
    default_snssai = udr_config.get("default_snssai") or {"sst": 1}
    sqn_patch_policy = udr_config.get("sqn_patch_policy", "max")
    app = SbiApp("/nudr-dr", udr_config.get("api_versions", ["v1", "v2"]), log)

    def warn(message):
        log("warning", message)

    async def load(ue_id):
        match = IMSI_UE_ID.match(ue_id)
        if not match:
            # Only IMSI based SUPIs are stored in PyHSS
            raise SbiError(404, "USER_NOT_FOUND", f"No subscriber for ueId {ue_id}")
        sub = await asyncio.to_thread(database.Get_5G_Subscription, match.group(1))
        if sub is None:
            raise SbiError(404, "USER_NOT_FOUND", f"No subscriber for ueId {ue_id}")
        return sub

    def found(value, what):
        if value is None or value == []:
            raise SbiError(404, "DATA_NOT_FOUND", f"No {what} for this subscriber")
        return Response(200, value)

    # Authentication data (TS 29.505 clause 5.2.2 / 5.2.3)

    @app.route("GET", "/subscription-data/{ueId}/authentication-data/authentication-subscription", "QueryAuthSubsData")
    async def query_auth_subs_data(request, ueId):
        sub = await load(ueId)
        if not sub["subscriber"].get("enabled", True):
            raise SbiError(403, "AUTHENTICATION_REJECTED", "Subscriber is disabled")
        return Response(200, datamodel.authentication_subscription(sub))

    @app.route(
        "PATCH",
        "/subscription-data/{ueId}/authentication-data/authentication-subscription",
        "ModifyAuthenticationSubscription",
    )
    async def modify_authentication_subscription(request, ueId):
        items = request.model(list[models.PatchItem], (JSON_PATCH,))
        sub = await load(ueId)
        sqn = None
        for item in items:
            if item.path == SQN_PATH and item.op.root in ("replace", "add"):
                try:
                    sqn = int(str(item.value), 16)
                except ValueError:
                    raise SbiError(400, "MANDATORY_IE_INCORRECT", f"Invalid SQN: {item.value}") from None
            else:
                warn(f"{ueId}: ignoring unsupported authentication-subscription patch {item.op.root} {item.path}")
        if sqn is None:
            raise SbiError(400, "MANDATORY_IE_MISSING", f"Only {SQN_PATH} can be modified")
        new_sqn = await asyncio.to_thread(
            database.Update_AuC_SQN,
            sub["auc"]["auc_id"],
            set_sqn=sqn,
            increment=SQN_INCREMENT,
            policy=sqn_patch_policy,
        )
        log("info", f"{ueId}: SQN resync to {sqn:012x}, stored SQN is now {new_sqn:012x}")
        return no_content()

    @app.route(
        "PUT", "/subscription-data/{ueId}/authentication-data/authentication-status", "CreateAuthenticationStatus"
    )
    async def create_authentication_status(request, ueId):
        event = request.model(models.AuthEvent)
        sub = await load(ueId)
        await asyncio.to_thread(database.Update_AuC_SQN, sub["auc"]["auc_id"], increment=SQN_INCREMENT)
        log("info", f"{ueId}: authentication {'succeeded' if event.success.root else 'failed'} ({event.authType.root})")
        return no_content()

    @app.route(
        "DELETE", "/subscription-data/{ueId}/authentication-data/authentication-status", "DeleteAuthenticationStatus"
    )
    async def delete_authentication_status(request, ueId):
        sub = await load(ueId)
        await asyncio.to_thread(database.Update_AuC_SQN, sub["auc"]["auc_id"], increment=SQN_INCREMENT)
        return no_content()

    # Context data (TS 29.505 clause 5.2.6). Open5GS' UDM accepts only 204, even on creation.

    @app.route("PUT", "/subscription-data/{ueId}/context-data/amf-3gpp-access", "CreateAmfContext3gpp")
    async def create_amf_context_3gpp(request, ueId):
        registration = request.model(models.Amf3GppAccessRegistration)
        sub = await load(ueId)
        amf = str(registration.amfInstanceId.root)
        await asyncio.to_thread(database.Update_Serving_AMF, sub["subscriber"]["imsi"], amf)
        log("info", f"{ueId}: registered at AMF {amf}")
        return no_content()

    @app.route("PATCH", "/subscription-data/{ueId}/context-data/amf-3gpp-access", "AmfContext3gpp")
    async def amf_context_3gpp(request, ueId):
        items = request.model(list[models.PatchItem], (JSON_PATCH,))
        sub = await load(ueId)
        for item in items:
            if item.path == "/purgeFlag" and item.op.root in ("replace", "add") and item.value is True:
                await asyncio.to_thread(database.Update_Serving_AMF, sub["subscriber"]["imsi"], None)
                log("info", f"{ueId}: purged from AMF")
        return no_content()

    @app.route(
        "PUT",
        "/subscription-data/{ueId}/context-data/smf-registrations/{pduSessionId}",
        "CreateOrUpdateSmfRegistration",
    )
    async def create_or_update_smf_registration(request, ueId, pduSessionId):
        registration = request.model(models.SmfRegistration)
        await load(ueId)
        log("info", f"{ueId}: PDU session {pduSessionId} registered at SMF {registration.smfInstanceId.root}")
        return no_content()

    @app.route(
        "DELETE", "/subscription-data/{ueId}/context-data/smf-registrations/{pduSessionId}", "DeleteSmfRegistration"
    )
    async def delete_smf_registration(request, ueId, pduSessionId):
        await load(ueId)
        log("info", f"{ueId}: PDU session {pduSessionId} deregistered at SMF")
        return no_content()

    # Provisioned data (TS 29.505 clause 5.2.4 / 5.2.5)

    def single_nssai(request, name):
        if name not in request.query:
            return None
        try:
            return datamodel.parse_snssai(request.query[name])
        except ValueError:
            raise SbiError(400, "INVALID_QUERY_PARAM", f"Invalid {name}: {request.query[name]}") from None

    @app.route("GET", "/subscription-data/{ueId}/{servingPlmnId}/provisioned-data", "QueryProvisionedData")
    async def query_provisioned_data(request, ueId, servingPlmnId):
        sub = await load(ueId)
        dataset_names = request.query_list("dataset-names") or ["AM", "SMF_SEL", "SM"]
        return Response(200, datamodel.provisioned_data_sets(sub, default_snssai, dataset_names, warn))

    @app.route("GET", "/subscription-data/{ueId}/{servingPlmnId}/provisioned-data/am-data", "QueryAmData")
    async def query_am_data(request, ueId, servingPlmnId):
        sub = await load(ueId)
        return found(datamodel.am_data(sub, default_snssai, request.query_list("fields")), "UE-AMBR")

    @app.route(
        "GET",
        "/subscription-data/{ueId}/{servingPlmnId}/provisioned-data/smf-selection-subscription-data",
        "QuerySmfSelectData",
    )
    async def query_smf_select_data(request, ueId, servingPlmnId):
        sub = await load(ueId)
        return found(datamodel.smf_selection_data(sub, default_snssai, warn), "usable APN")

    @app.route("GET", "/subscription-data/{ueId}/{servingPlmnId}/provisioned-data/sm-data", "QuerySmData")
    async def query_sm_data(request, ueId, servingPlmnId):
        snssai = single_nssai(request, "single-nssai")
        sub = await load(ueId)
        data = datamodel.sm_data(sub, default_snssai, snssai, request.query.get("dnn"), warn)
        return found(data, "session management data")

    # Policy data (TS 29.519 clause 5.2)

    @app.route("GET", "/policy-data/ues/{ueId}/am-data", "ReadAccessAndMobilityPolicyData")
    async def read_access_and_mobility_policy_data(request, ueId):
        sub = await load(ueId)
        return Response(200, datamodel.am_policy_data(sub))

    @app.route("GET", "/policy-data/ues/{ueId}/sm-data", "ReadSessionManagementPolicyData")
    async def read_session_management_policy_data(request, ueId):
        snssai = single_nssai(request, "snssai")
        sub = await load(ueId)
        dnn = request.query.get("dnn")
        if snssai is not None:
            return found(datamodel.sm_policy_data(sub, default_snssai, snssai, dnn, warn), "policy data for slice")
        # No S-NSSAI given: policy data of all slices
        result = None
        for item in datamodel.sm_data(sub, default_snssai, dnn=dnn, warn=warn):
            data = datamodel.sm_policy_data(sub, default_snssai, item.singleNssai, dnn, warn)
            if result is None:
                result = data
            else:
                result.smPolicySnssaiData.update(data.smPolicySnssaiData)
        return found(result, "policy data")

    return app
