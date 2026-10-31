# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from database import APN, AUC, SUBSCRIBER, SUBSCRIBER_ROUTING, Database
from logtool import LogTool
from pyhss_config import config

IMSI = "001019000000001"
SQN_MASK = 0xFFFFFFFFFFFF


@pytest.fixture(scope="module")
def db(create_test_db):
    db = Database(LogTool(config))
    apn_internet = db.CreateObj(
        APN,
        {"apn": "udr-internet", "ip_version": 2, "apn_ambr_dl": 1000000000, "apn_ambr_ul": 500000000, "sst": 1},
    )["apn_id"]
    apn_ims = db.CreateObj(APN, {"apn": "udr-ims", "apn_ambr_dl": 0, "apn_ambr_ul": 0, "qci": 5, "sd": "0000ab"})[
        "apn_id"
    ]
    auc_id = db.CreateObj(
        AUC,
        {
            "ki": "465B5CE8B199B49FAA5F0A2EE238A6BC",
            "opc": "E8ED289DEBA952E4283B54E88E6183CA",
            "amf": "8000",
            "sqn": 0,
            "imsi": IMSI,
        },
    )["auc_id"]
    subscriber_id = db.CreateObj(
        SUBSCRIBER,
        {"auc_id": auc_id, "default_apn": apn_internet, "apn_list": f"{apn_ims},{apn_internet}", "imsi": IMSI},
    )["subscriber_id"]
    db.CreateObj(
        SUBSCRIBER_ROUTING,
        {"subscriber_id": subscriber_id, "apn_id": apn_internet, "ip_version": 0, "ip_address": "10.45.0.9"},
    )
    db.test_ids = {"auc": auc_id, "subscriber": subscriber_id, "internet": apn_internet, "ims": apn_ims}
    return db


def get_sqn(db):
    return db.GetObj(AUC, db.test_ids["auc"])["sqn"]


def test_increment(db):
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=1000, policy="set")
    assert db.Update_AuC_SQN(db.test_ids["auc"], increment=32) == 1032
    assert get_sqn(db) == 1032


def test_set_policy_max_never_goes_backwards(db):
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=5000, policy="set")
    assert db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=33, increment=32, policy="max") == 5032
    assert db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=9000, increment=32, policy="max") == 9032


def test_set_policy_set_overwrites(db):
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=5000, policy="set")
    assert db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=33, increment=32, policy="set") == 65


def test_48bit_wrap(db):
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=SQN_MASK - 10, policy="set")
    assert db.Update_AuC_SQN(db.test_ids["auc"], increment=32) == 21


def test_s6a_and_5g_share_sqn(db):
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=0, policy="set")
    # S6a AIR: uses the stored SQN and adds the configured step (32)
    db.Get_Vectors_AuC(db.test_ids["auc"], "air", plmn="00f110")
    assert get_sqn(db) == 32
    # 5G: authentication-status PUT adds 32
    db.Update_AuC_SQN(db.test_ids["auc"], increment=32)
    assert get_sqn(db) == 64
    # 5G resync with an SQN behind the stored one must not move it backwards
    db.Update_AuC_SQN(db.test_ids["auc"], set_sqn=33, increment=32)
    assert get_sqn(db) == 96
    db.Get_Vectors_AuC(db.test_ids["auc"], "air", plmn="00f110")
    assert get_sqn(db) == 128


def test_update_unknown_auc(db):
    with pytest.raises(ValueError):
        db.Update_AuC_SQN(999999, increment=32)


def test_serving_amf(db):
    db.Update_Serving_AMF(IMSI, "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab")
    subscriber = db.Get_Subscriber(imsi=IMSI)
    assert subscriber["serving_amf"] == "2a8d4b0c-1d5e-41f0-b7e1-1234567890ab"
    assert subscriber["serving_amf_timestamp"]
    db.Update_Serving_AMF(IMSI, None)
    subscriber = db.Get_Subscriber(imsi=IMSI)
    assert subscriber["serving_amf"] is None
    assert subscriber["serving_amf_timestamp"] is None
    with pytest.raises(ValueError):
        db.Update_Serving_AMF("001019999999999", None)


def test_get_5g_subscription(db):
    sub = db.Get_5G_Subscription(IMSI)
    assert sub["subscriber"]["imsi"] == IMSI
    assert sub["auc"]["auc_id"] == db.test_ids["auc"]
    # default APN first, then the rest of apn_list
    assert [apn["apn"] for apn in sub["apns"]] == ["udr-internet", "udr-ims"]
    assert sub["apns"][0]["sst"] == 1
    assert sub["apns"][1]["sd"] == "0000ab"
    assert sub["routing"][db.test_ids["internet"]]["ip_address"] == "10.45.0.9"
    assert db.Get_5G_Subscription("001019999999999") is None
