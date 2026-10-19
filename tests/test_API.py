# Copyright 2022-2023 Nick <nick@nickvsnetworking.com>
# Copyright 2023 David Kneipp <david@davidkneipp.com>
# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
import requests
import json
import logging
import pytest

log = logging.getLogger("UnitTestLogger")
base_url = 'http://localhost:8080'

unittest.TestCase.maxDiff = None


@pytest.fixture(autouse=True)
def autouse_fixtures(create_test_db, run_pyhss_api):
    return


def payload_without_last_modified(payload):
    assert "last_modified" in payload
    del payload["last_modified"]
    return payload


class API_Tests(unittest.TestCase):
    def test_A_API_Response(self):
        r = requests.get(str(base_url) + '/swagger.json')
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

class APN_Tests(unittest.TestCase):
    apn_id = 0
    template_data = {
        "apn": "UnitTest1",
        "pgw_address": "10.98.0.20",
        "sgw_address": "10.98.0.10",
        "charging_characteristics": "0800",
        "apn_ambr_dl": 99999,
        "apn_ambr_ul": 99999,
        "qci": 7,
        "ip_version": 0,
        "nbiot": False,
        "nidd_mechanism": None,
        "nidd_preferred_data_mode": None,
        "nidd_rds": None,
        "nidd_scef_id": None,
        "nidd_scef_realm": None,
        "sst": None,
        "sd": None,
        "arp_priority": 1,
        "arp_preemption_capability": True,
        "arp_preemption_vulnerability": True,
        "charging_rule_list" : None,
        }

    def test_B_create_APN(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn/', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.apn_id = r.json()['apn_id']
        log.debug("Created APN ID " + str(self.__class__.apn_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_APN(self):
        r = requests.get(str(base_url) + '/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn_id'] = self.__class__.apn_id
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_D_Patch_APN(self):
        headers = {"Content-Type": "application/json"}
        patch_template_data = self.__class__.template_data
        patch_template_data['apn'] = 'PatchedValue'
        r = requests.patch(str(base_url) + '/apn/' + str(self.__class__.apn_id), data=json.dumps(patch_template_data), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(patch_template_data, payload, "JSON body should match input")

    def test_E_Get_Patched_APN(self):
        r = requests.get(str(base_url) + '/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn'] = 'PatchedValue'
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_F_Delete_Patched_APN(self):
        r = requests.delete(str(base_url) + '/apn/' + str(self.__class__.apn_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class AUC_Tests(unittest.TestCase):
    auc_id = 0
    algo = "3"
    template_data = {
    "ki": "fad51018f65affc04e6d56d699df3a76",
    "opc": '44d51018f65affc04e6d56d699df3a76',
    "amf": "8000",
    "sqn": 99,
    'batch_name': None,
    'esim': False,
    'iccid': None,
    'imsi': None,
    'lpa': None,
    'misc1': None,
    'misc2': None,
    'misc3': None,
    'misc4': None,
    'pin1': None,
    'pin2': None,
    'puk1': None,
    'puk2': None,
    'sim_vendor': None,    
    }

    def test_B_create_AUC(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/auc/', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.auc_id = r.json()['auc_id']
        log.debug("Created AUC ID " + str(self.__class__.auc_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_AUC(self):
        r = requests.get(str(base_url) + '/auc/' + str(self.__class__.auc_id))
        #Add AUC ID into Template for Validating
        self.__class__.template_data['auc_id'] = self.__class__.auc_id
        self.__class__.template_data['algo'] = self.__class__.algo
        self.__class__.template_data.pop('opc')
        self.__class__.template_data.pop('ki')
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_D_Patch_AUC(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['sim_vendor'] = "Nick1234"    
        r = requests.patch(str(base_url) + '/auc/' + str(self.__class__.auc_id), data=json.dumps(self.__class__.template_data), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_E_Get_Patched_AUC(self):
        r = requests.get(str(base_url) + '/auc/' + str(self.__class__.auc_id))
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_F_Delete_Patched_AUC(self):
        r = requests.delete(str(base_url) + '/auc/' + str(self.__class__.auc_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class Subscriber_Tests(unittest.TestCase):
    subscriber_id = 0
    apn_secondary = 0
    template_data = {
    "imsi": "001001000000019",
    "enabled": True,
    "msisdn": "123456789",
    "ue_ambr_dl": 999999,
    "ue_ambr_ul": 999999,
    "nam": 0,
    "subscribed_rau_tau_timer": 600,
    }


    def test_A_create_AUC_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/auc/', data=json.dumps({"ki": "23d51018f65affc04e6d56d699df3a76","opc": "fad51018f65affc04e6d56d699df3a76","amf": "8000","sqn": 99}), headers=headers)
        log.debug("Created AUC ID " + str(r.json()['auc_id']))
        self.__class__.template_data['auc_id'] = r.json()['auc_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn/', data=json.dumps({"apn": "UnitTestSub1", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.template_data['default_apn'] = r.json()['apn_id']
        self.__class__.template_data['apn_list'] = '1,2,' + str(r.json()['apn_id'])
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_another_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn/', data=json.dumps({"apn": "UnitTestSub2", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.apn_secondary = r.json()['apn_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_create_Subscriber(self):
        log.debug(self.__class__.template_data)
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/subscriber/', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.subscriber_id = r.json()['subscriber_id']
        log.debug("Created Subscriber ID " + str(self.__class__.subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.template_data['subscriber_id'] = self.__class__.subscriber_id
        self.__class__.template_data['last_location_update_timestamp'] = None
        self.__class__.template_data['last_seen_cell_id'] = None
        self.__class__.template_data['last_seen_eci'] = None
        self.__class__.template_data['last_seen_enodeb_id'] = None
        self.__class__.template_data['last_seen_mcc'] = None
        self.__class__.template_data['last_seen_mnc'] = None
        self.__class__.template_data['last_seen_tac'] = None
        self.__class__.template_data['roaming_enabled'] = True
        self.__class__.template_data['roaming_rule_list'] = None
        self.__class__.template_data['serving_amf'] = None
        self.__class__.template_data['serving_amf_timestamp'] = None
        self.__class__.template_data['serving_mme'] = None
        self.__class__.template_data['serving_mme_peer'] = None
        self.__class__.template_data['serving_mme_realm'] = None
        self.__class__.template_data['serving_mme_timestamp'] = None
        self.__class__.template_data['serving_msc'] = None
        self.__class__.template_data['serving_msc_timestamp'] = None
        self.__class__.template_data['serving_sgsn'] = None
        self.__class__.template_data['serving_sgsn_timestamp'] = None
        self.__class__.template_data['serving_vlr'] = None
        self.__class__.template_data['serving_vlr_timestamp'] = None

        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_D_Patch_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = '123414299213'
        self.__class__.template_data['apn_list'] = self.__class__.template_data['apn_list'] + "," + str(self.__class__.apn_secondary)
        r = requests.patch(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_E_Get_Patched_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_F_Get_Patched_Subscriber_by_MSISDN(self):
        r = requests.get(str(base_url) + '/subscriber/msisdn/' + str(self.__class__.template_data['msisdn']))
        self.__class__.template_data['attributes'] = []
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_Z_Delete_Patched_Subscriber(self):
        r = requests.delete(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        r2 = requests.delete(str(base_url) + '/auc/' + str(self.__class__.template_data['auc_id']))
        r3 = requests.delete(str(base_url) + '/apn/' + str(self.__class__.template_data['default_apn']))
        r3 = requests.delete(str(base_url) + '/apn/' + str(int(self.__class__.template_data['default_apn'])+1))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class IMS_Subscriber(unittest.TestCase):
    ims_subscriber_id = 0
    template_data = {
        "msisdn": "5231231",
        "msisdn_list": "5231231",
        "imsi": "5231231",
        "ifc_path": "fdasfd.xml",
        "sh_profile": "fdasfd.xml",
    }

    def test_B_create_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/ims_subscriber/', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.ims_subscriber_id = r.json()['ims_subscriber_id']
        log.debug("Created ims_subscriber_id " + str(self.__class__.ims_subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_IMS_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add IMS_Subscriber ID into Template for Validating
        self.__class__.template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.template_data['pcscf'] = None
        self.__class__.template_data['pcscf_active_session'] = None
        self.__class__.template_data['pcscf_peer'] = None
        self.__class__.template_data['pcscf_realm'] = None
        self.__class__.template_data['pcscf_timestamp'] = None
        self.__class__.template_data['scscf'] = None
        self.__class__.template_data['scscf_peer'] = None
        self.__class__.template_data['scscf_realm'] = None
        self.__class__.template_data['scscf_timestamp'] = None
        self.__class__.template_data['sh_template_path'] = None
        self.__class__.template_data['xcap_profile'] = None

        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_D_Patch_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = "5132312321"
        r = requests.patch(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_E_Get_Patched_IMS_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.template_data, payload, "JSON body should match input")

    def test_F_Delete_Patched_IMS_Subscriber(self):
        r = requests.delete(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class ChargingRule_Tests(unittest.TestCase):
    tft_id = 0
    charging_rule_id = 0
    #Define TFTs
    tft_template1 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 1
    }
    tft_template2 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 2
    }

    charging_rule_template = {
        'rule_name' : 'charging_rule_test2',
        'qci' : 4,
        'arp_priority' : 5,
        'arp_preemption_capability' : True,
        'arp_preemption_vulnerability' : False,
        'mbr_dl' : 128000,
        'mbr_ul' : 128000,
        'gbr_dl' : 128000,
        'gbr_ul' : 128000,
        'tft_group_id' : 1,
        'precedence' : 100,
        'rating_group' : 4000
        }


    def test_A_create_TFT_1(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/tft/', data=json.dumps(self.__class__.tft_template1), headers=headers)
        self.__class__.tft_template1 = payload_without_last_modified(r.json())
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_create_TFT_2(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/tft/', data=json.dumps(self.__class__.tft_template2), headers=headers)
        self.__class__.tft_id = r.json()['tft_id']
        self.__class__.tft_template2 = payload_without_last_modified(r.json())
        log.debug("Created TFT ID " + str(self.__class__.tft_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_TFT(self):
        r = requests.get(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.tft_template2, payload, "JSON body should match input")

    def test_D_Patch_TFT(self):
        headers = {"Content-Type": "application/json"}
        patch_tft_template2 = self.__class__.tft_template2
        patch_tft_template2['tft_string'] = 'permit out ip from 10.98.0.20 80 to any 1-65535'
        patch_tft_template2['tft_id'] = self.__class__.tft_id
        r = requests.patch(str(base_url) + '/tft/' + str(self.__class__.tft_id), data=json.dumps(patch_tft_template2), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(patch_tft_template2, payload, "JSON body should match input")

    def test_E_Get_Patched_TFT(self):
        r = requests.get(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        payload = payload_without_last_modified(r.json())
        #Add TFT ID into Template for Validating
        patch_tft_template2 = self.__class__.tft_template2
        patch_tft_template2['tft_string'] = 'permit out ip from 10.98.0.20 80 to any 1-65535'
        patch_tft_template2['tft_id'] = self.__class__.tft_id
        self.assertEqual(patch_tft_template2, payload, "JSON body should match input")

    def test_F_create_Charging_Rule(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/charging_rule/', data=json.dumps(self.__class__.charging_rule_template), headers=headers)
        self.__class__.charging_rule_id = r.json()['charging_rule_id']
        log.debug("Created charging_rule_id " + str(self.__class__.charging_rule_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_Get_Charging_Rule(self):
        r = requests.get(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        payload = payload_without_last_modified(r.json())
        #Add TFT ID into Template for Validating
        charging_rule_template = self.__class__.charging_rule_template
        charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        self.assertEqual(charging_rule_template, payload, "JSON body should match input")

    def test_H_Patch_Charging_Rule(self):
        headers = {"Content-Type": "application/json"}
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        r = requests.patch(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id), data=json.dumps(patch_charging_rule_template), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(patch_charging_rule_template, payload, "JSON body should match input")

    def test_I_Get_Patched_Charging_Rule(self):
        r = requests.get(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        payload = payload_without_last_modified(r.json())
        #Add charging_rule_id into Template for Validating
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        self.assertEqual(patch_charging_rule_template, payload, "JSON body should match input")

    def test_J_Get_Full_Charging_Rule(self):
        r = requests.get(str(base_url) + '/pcrf/' + str(self.__class__.charging_rule_id))
        payload = payload_without_last_modified(r.json())
        payload["tft"][0] = payload_without_last_modified(payload["tft"][0])
        payload["tft"][1] = payload_without_last_modified(payload["tft"][1])
        #Add charging_rule_id into Template for Validating
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        patch_charging_rule_template['tft'] = []
        patch_charging_rule_template['tft'].append(self.__class__.tft_template1)
        patch_charging_rule_template['tft'].append(self.__class__.tft_template2)
        self.assertEqual(patch_charging_rule_template, payload, "JSON body should match input")

    def test_X_Delete_TFT2(self):
        r = requests.delete(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_Y_Delete_TFT2(self):
        r = requests.delete(str(base_url) + '/tft/' + str(self.__class__.tft_id-1))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_Z_Delete_Charging_Rule(self):
        r = requests.delete(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class EIR_Tests(unittest.TestCase):
    eir_id = 0
    #Define EIR Template
    eir_template1 =  {
        "match_response_code": 1,
        "imei": "1234",
        "imsi": "567",
        "regex_mode": 0
    }

    eir_template2 =  {
        "match_response_code": 2,
        "imei": "^777.*",
        "imsi": "^1234123412341234$",
        "regex_mode": 1
    }

    def test_A_create_EIR_1(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/eir/', data=json.dumps(self.__class__.eir_template1), headers=headers)
        self.__class__.eir_template1 = payload_without_last_modified(r.json())
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_EIR_2(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/eir/', data=json.dumps(self.__class__.eir_template2), headers=headers)
        self.__class__.eir_template2 = payload_without_last_modified(r.json())
        self.__class__.eir_id = r.json()['eir_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_EIR(self):
        r = requests.get(str(base_url) + '/eir/' + str(self.__class__.eir_id))
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.eir_template2, payload, "JSON body should match input")

    def test_D_Patch_EIR(self):
        headers = {"Content-Type": "application/json"}
        patch_eir_template2 = self.__class__.eir_template2
        patch_eir_template2['match_response_code'] = 3
        patch_eir_template2['eir_id'] = self.__class__.eir_id
        r = requests.patch(str(base_url) + '/eir/' + str(self.__class__.eir_id), data=json.dumps(patch_eir_template2), headers=headers)
        payload = payload_without_last_modified(r.json())
        self.assertEqual(patch_eir_template2, payload, "JSON body should match input")

    def test_E_Get_Patched_EIR(self):
        r = requests.get(str(base_url) + '/eir/' + str(self.__class__.eir_id))
        #Add EIR into Template for Validating
        patch_eir_template2 = self.__class__.eir_template2
        patch_eir_template2['match_response_code'] = 3
        patch_eir_template2['eir_id'] = self.__class__.eir_id
        payload = payload_without_last_modified(r.json())
        self.assertEqual(patch_eir_template2, payload, "JSON body should match input")

    def test_I_Get_All_EIR_Rules(self):
        r = requests.get(str(base_url) + '/oam/eir_rules')
        self.assertIsNotNone(len(r.json()), "JSON body should return multiple objects")

    def test_X_Delete_EIR1(self):
        r = requests.delete(str(base_url) + '/eir/' + str(self.__class__.eir_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_X_Delete_EIR2(self):
        r = requests.delete(str(base_url) + '/eir/' + str(self.__class__.eir_id-1))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_Z_Get_All_EIR_Rules(self):
        r = requests.get(str(base_url) + '/eir/list')
        self.assertEqual(len(r.json()), 0, "JSON body should return 0")

class GeoRed_MME(unittest.TestCase):
    subscriber_id = 0
    apn_secondary = 0
    subscriber_template_data = {
    "imsi": "001001000000020",
    "enabled": True,
    "msisdn": "123456789",
    "ue_ambr_dl": 999999,
    "ue_ambr_ul": 999999,
    "nam": 0,
    "subscribed_rau_tau_timer": 600,
    }


    def test_A_GeoRed_MME_create_AUC_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/auc/', data=json.dumps({"ki": "1ad51018f65affc04e6d56d699df3a76","opc": "2ad51018f65affc04e6d56d699df3a76","amf": "8000","sqn": 99}), headers=headers)
        log.debug("Created AUC ID " + str(r.json()['auc_id']))
        self.__class__.subscriber_template_data['auc_id'] = r.json()['auc_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_GeoRed_MME_create_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn/', data=json.dumps({"apn": "GeoRedTest", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.apn_id = r.json()['apn_id']
        self.__class__.subscriber_template_data['default_apn'] = r.json()['apn_id']
        self.__class__.subscriber_template_data['apn_list'] = str(r.json()['apn_id'])
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_GeoRed_MME_create_Subscriber(self):
        log.debug(self.__class__.subscriber_template_data)
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/subscriber/', data=json.dumps(self.__class__.subscriber_template_data), headers=headers)
        self.__class__.subscriber_id = r.json()['subscriber_id']
        log.debug("Created Subscriber ID " + str(self.__class__.subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_D_GeoRed_MME_Get_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.subscriber_template_data['subscriber_id'] = self.__class__.subscriber_id
        self.__class__.subscriber_template_data['last_location_update_timestamp'] = None
        self.__class__.subscriber_template_data['last_seen_cell_id'] = None
        self.__class__.subscriber_template_data['last_seen_eci'] = None
        self.__class__.subscriber_template_data['last_seen_enodeb_id'] = None
        self.__class__.subscriber_template_data['last_seen_mcc'] = None
        self.__class__.subscriber_template_data['last_seen_mnc'] = None
        self.__class__.subscriber_template_data['last_seen_tac'] = None
        self.__class__.subscriber_template_data['roaming_enabled'] = True
        self.__class__.subscriber_template_data['roaming_rule_list'] = None
        self.__class__.subscriber_template_data['serving_mme'] = None
        self.__class__.subscriber_template_data['serving_amf'] = None
        self.__class__.subscriber_template_data['serving_amf_timestamp'] = None
        self.__class__.subscriber_template_data['serving_mme_peer'] = None
        self.__class__.subscriber_template_data['serving_mme_realm'] = None
        self.__class__.subscriber_template_data['serving_mme_timestamp'] = None
        self.__class__.subscriber_template_data['serving_msc'] = None
        self.__class__.subscriber_template_data['serving_msc_timestamp'] = None
        self.__class__.subscriber_template_data['serving_sgsn'] = None
        self.__class__.subscriber_template_data['serving_sgsn_timestamp'] = None
        self.__class__.subscriber_template_data['serving_vlr'] = None
        self.__class__.subscriber_template_data['serving_vlr_timestamp'] = None

        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.subscriber_template_data, payload, "JSON body should match input")

    def test_G_1_GeoRed_MME_Update_MME_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.subscriber_template_data['imsi']),
            "serving_mme": "test1234",
            "serving_mme_realm": "test_realm",
            "serving_mme_peer": "test_peer",
        }), headers=headers)
        log.debug("Updated Subscriber with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_2_GeoRed_MME_Get_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.subscriber_template_data['subscriber_id'] = self.__class__.subscriber_id
        self.__class__.subscriber_template_data['serving_mme'] = "test1234"
        self.__class__.subscriber_template_data['serving_mme_realm'] = "test_realm"
        self.__class__.subscriber_template_data['serving_mme_peer'] = "test_peer"
        payload = payload_without_last_modified(r.json())
        payload['serving_mme_timestamp'] = self.__class__.subscriber_template_data['serving_mme_timestamp']
        self.assertEqual(self.__class__.subscriber_template_data, payload, "JSON body should match input")

    def test_G_3_GeoRed_MME_Clear_MME_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.subscriber_template_data['imsi']),
            "serving_mme": None,
            "serving_mme_realm": None,
            "serving_mme_peer": None,
        }), headers=headers)
        log.debug("Updated Subscriber with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_4_GeoRed_MME_Get_Subscriber_Cleared_MME(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.subscriber_template_data['serving_mme'] = None
        self.__class__.subscriber_template_data['serving_mme_realm'] = None
        self.__class__.subscriber_template_data['serving_mme_peer'] = None
        self.__class__.subscriber_template_data['serving_mme_timestamp'] = None
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.subscriber_template_data, payload, "JSON body should match input")

    def test_Z_GeoRed_MME_Delete_Patched_Subscriber(self):
        r = requests.delete(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        r2 = requests.delete(str(base_url) + '/auc/' + str(self.__class__.subscriber_template_data['auc_id']))
        r3 = requests.delete(str(base_url) + '/apn/' + str(self.__class__.subscriber_template_data['default_apn']))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class GeoRed_PCRF(unittest.TestCase):
    subscriber_id = 0
    apn_secondary = 0
    subscriber_template_data = {
    "imsi": "001001000000020",
    "enabled": True,
    "msisdn": "123456789",
    "ue_ambr_dl": 999999,
    "ue_ambr_ul": 999999,
    "nam": 0,
    "subscribed_rau_tau_timer": 600,
    }

    def test_A_GeoRed_PCRF_create_AUC_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/auc/', data=json.dumps({"ki": "55d51018f65affc04e6d56d699df3a76","opc": "2ad51018f65affc04e6d56d699df3a76","amf": "8000","sqn": 99}), headers=headers)
        log.debug("Created AUC ID " + str(r.json()['auc_id']))
        self.__class__.subscriber_template_data['auc_id'] = r.json()['auc_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_GeoRed_PCRF_create_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn/', data=json.dumps({"apn": "GeoRedTestPCRF", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.apn_id = r.json()['apn_id']
        self.__class__.subscriber_template_data['default_apn'] = r.json()['apn_id']
        self.__class__.subscriber_template_data['apn_list'] = str(r.json()['apn_id'])
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_GeoRed_PCRF_create_Subscriber(self):
        log.debug(self.__class__.subscriber_template_data)
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/subscriber/', data=json.dumps(self.__class__.subscriber_template_data), headers=headers)
        self.__class__.subscriber_id = r.json()['subscriber_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_1_GeoRed_Update_PCRF_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.subscriber_template_data['imsi']),
            "serving_apn": "GeoRedTestPCRF",
            "pcrf_session_id": "sdfjkakjs",
            "ue_ip": "1.2.3.4",
            "serving_pgw": "pgwtestGeored",
            "subscriber_routing": "test-subscriber-routing",
        }), headers=headers)
        log.debug("Updated PCRF with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_4_GeoRed_Clear_PCRF_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.subscriber_template_data['imsi']),
            "serving_apn": "GeoRedTestPCRF",
            "pcrf_session_id": "sdfjkakjs",
            "ue_ip": "1.2.3.4",
            "serving_pgw": None,
            "subscriber_routing": None,
        }), headers=headers)
        log.debug("Cleared PCRF with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_Z_GeoRed_PCRF_Delete_Patched_Subscriber(self):
        r = requests.delete(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        r2 = requests.delete(str(base_url) + '/auc/' + str(self.__class__.subscriber_template_data['auc_id']))
        r3 = requests.delete(str(base_url) + '/apn/' + str(self.__class__.subscriber_template_data['default_apn']))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))


class GeoRed_IMS(unittest.TestCase):
    ims_subscriber_id = 0
    ims_template_data = {
        "msisdn": "5231231",
        "msisdn_list": "5231231",
        "imsi": "5231231",
        "ifc_path": "fdasfd.xml",
        "sh_profile": "fdasfd.xml",
    }

    def test_A_GeoRed_IMS_create_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/ims_subscriber/', data=json.dumps(self.__class__.ims_template_data), headers=headers)
        self.__class__.ims_subscriber_id = r.json()['ims_subscriber_id']
        log.debug("Created ims_subscriber_id " + str(self.__class__.ims_subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_GeoRed_IMS_Get_IMS_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add IMS_Subscriber ID into Template for Validating
        self.__class__.ims_template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.ims_template_data['pcscf'] = None
        self.__class__.ims_template_data['pcscf_active_session'] = None
        self.__class__.ims_template_data['pcscf_peer'] = None
        self.__class__.ims_template_data['pcscf_realm'] = None
        self.__class__.ims_template_data['pcscf_timestamp'] = None
        self.__class__.ims_template_data['scscf'] = None
        self.__class__.ims_template_data['scscf_peer'] = None
        self.__class__.ims_template_data['scscf_realm'] = None
        self.__class__.ims_template_data['scscf_timestamp'] = None
        self.__class__.ims_template_data['sh_template_path'] = None
        self.__class__.ims_template_data['xcap_profile'] = None

        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.ims_template_data, payload, "JSON body should match input")

    def test_C_GeoRed_IMS_Update_SCSCF_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.ims_template_data['imsi']),
            "scscf": "test1234"
        }), headers=headers)
        log.debug("Updated Subscriber with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_2_GeoRed_IMS_Get_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.ims_template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.ims_template_data['scscf'] = "test1234"

        # FIXME: Update_Serving_CSCF() has str(scscf_peer)
        self.__class__.ims_template_data['scscf_peer'] = "None"

        payload = payload_without_last_modified(r.json())
        payload['scscf_timestamp'] = self.__class__.ims_template_data['scscf_timestamp']
        self.assertEqual(self.__class__.ims_template_data, payload, "JSON body should match input")

    def test_G_3_GeoRed_IMS_Clear_SCCSF_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.patch(str(base_url) + '/geored/', data=json.dumps({
            "imsi": str(self.__class__.ims_template_data['imsi']),
            "scscf": None
        }), headers=headers)
        log.debug("Updated Subscriber with GeoRed")
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_4_GeoRed_IMS_Get_Subscriber_Cleared_SCSF(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.ims_template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.ims_template_data['scscf'] = None
        self.__class__.ims_template_data['scscf_timestamp'] = None
        self.__class__.ims_template_data['scscf_peer'] = None
        payload = payload_without_last_modified(r.json())
        self.assertEqual(self.__class__.ims_template_data, payload, "JSON body should match input")

    def test_W_GeoRed_IMS_Delete_IMS_Subscriber(self):
        r = requests.delete(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))
