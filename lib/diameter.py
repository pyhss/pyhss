# Diameter Packet Decoder / Encoder & Tools
# Copyright 2019-2025 Nick <nick@nickvsnetworking.com>
# Copyright 2023-2025 David Kneipp <david@davidkneipp.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
import socket
import binascii
import math
import uuid
import os
import random
import ipaddress
import jinja2
from database import Database, ROAMING_NETWORK, ROAMING_RULE, EMERGENCY_SUBSCRIBER, IMS_SUBSCRIBER
from messaging import RedisMessaging
from redis import Redis
import datetime
import json
import time
import socket
import requests
import traceback
import re
from baseModels import Peer, OutboundData
import pydantic_core
import xml.etree.ElementTree as ET
from pyhss_config import config
from rat import SubscriberRATRestriction, RAT


class DiameterAvpError(Exception):
    """
    Raised by a request handler when a received AVP is missing or invalid.
    generateDiameterResponse() turns it into an error answer carrying result_code and a Failed-AVP (RFC 6733 section 7.1.5).
    """
    result_code = 5012  # DIAMETER_UNABLE_TO_COMPLY

    def __init__(self, avp_code, avp_data='', vendor_id=None, avp_flags=None):
        self.avp_code = avp_code
        self.avp_data = avp_data
        self.vendor_id = vendor_id
        self.avp_flags = avp_flags if avp_flags is not None else ('c0' if vendor_id else 40)
        super().__init__(f"{self.__class__.__name__}: AVP {avp_code}" + (f" (Vendor-Id {vendor_id})" if vendor_id else ""))


class DiameterMissingAvp(DiameterAvpError):
    result_code = 5005  # DIAMETER_MISSING_AVP


class DiameterInvalidAvpValue(DiameterAvpError):
    result_code = 5004  # DIAMETER_INVALID_AVP_VALUE


class Diameter:

    def __init__(
        self,
        logTool,
        originHost: str = "hss01",
        originRealm: str = "epc.mnc999.mcc999.3gppnetwork.org",
        productName: str = "PyHSS",
        mcc: str = "999",
        mnc: str = "999",
        redisMessaging=None,
        main_service: bool = False,
    ):
        self.OriginHost = self.string_to_hex(originHost)
        self.OriginRealm = self.string_to_hex(originRealm)
        self.ProductName = self.string_to_hex(productName)
        self.MNC = str(mnc)
        self.MCC = str(mcc)
        self.logTool = logTool

        self.redisUseUnixSocket = config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = config.get('redis', {}).get('host', 'localhost')
        self.redisPort = config.get('redis', {}).get('port', 6379)
        self.redisAdditionalPeers = config.get('redis', {}).get('additionalPeers', [])
        if redisMessaging:
            self.redisMessaging = redisMessaging
        else:
            self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        
        self.hostname = socket.gethostname()

        self.database = Database(logTool=logTool, main_service=main_service)
        self.diameterRequestTimeout = int(config.get('hss', {}).get('diameter_request_timeout', 10))
        self.diameterPeerKey = config.get('hss', {}).get('diameter_peer_key', 'diameterPeers')
        self.useDraFallback = config.get('hss', {}).get('use_dra_fallback', False)
        self.emergency_subscriber_expiry = config.get('hss', {}).get('emergency_subscriber_expiry', 3600)
        self.sendDsrOnMmeChange = config.get('hss', {}).get('send_dsr_on_mme_change', False)
        self.dsrExternalIdentifier = config.get('hss', {}).get('dsr_external_identifier', "subscriber")
        self.ignorePurgeUeRequest = config.get('hss', {}).get('ignore_purge_ue_request', False)

        self.templateLoader = jinja2.FileSystemLoader(searchpath="../")
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

        self.logTool.log(service='HSS', level='info', message=f"Initialized Diameter Library", redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='info', message=f"Origin Host: {str(originHost)}", redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='info', message=f"Realm: {str(originRealm)}", redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='info', message=f"Product Name: {str(productName)}", redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='info', message=f"PLMN: {str(self.MCC)}/{str(self.MNC)}", redisClient=self.redisMessaging)

        self.diameterResponseList = [
                # Generic Diameter Messages RFC6733
                {"commandCode": 257, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_257, "failureResultCode": 5012 ,"requestAcronym": "CER", "responseAcronym": "CEA", "requestName": "Capabilites Exchange Request", "responseName": "Capabilites Exchange Answer"},
                {"commandCode": 280, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_280, "failureResultCode": 5012 ,"requestAcronym": "DWR", "responseAcronym": "DWA", "requestName": "Device Watchdog Request", "responseName": "Device Watchdog Answer"},
                {"commandCode": 282, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_282, "failureResultCode": 5012 ,"requestAcronym": "DPR", "responseAcronym": "DPA", "requestName": "Disconnect Peer Request", "responseName": "Disconnect Peer Answer"},

                # Gx PCEF/PCRF
                {"commandCode": 300, "applicationId": 16777216, "responseMethod": self.Answer_16777216_300, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "UAR", "responseAcronym": "UAA", "requestName": "User Authentication Request", "responseName": "User Authentication Answer"},
                {"commandCode": 301, "applicationId": 16777216, "responseMethod": self.Answer_16777216_301, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "SAR", "responseAcronym": "SAA", "requestName": "Server Assignment Request", "responseName": "Server Assignment Answer"},
                {"commandCode": 302, "applicationId": 16777216, "responseMethod": self.Answer_16777216_302, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "LIR", "responseAcronym": "LIA", "requestName": "Location Information Request", "responseName": "Location Information Answer"},
                {"commandCode": 303, "applicationId": 16777216, "responseMethod": self.Answer_16777216_303, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "MAR", "responseAcronym": "MAA", "requestName": "Multimedia Authentication Request", "responseName": "Multimedia Authentication Answer"},

                # Gy PCEF/OCS
                {"commandCode": 306, "applicationId": 16777217, "responseMethod": self.Answer_16777217_306, "failureResultCode": 5001 ,"failureResultCodeExperimental": True ,"requestAcronym": "UDR", "responseAcronym": "UDA", "requestName": "User Data Request", "responseName": "User Data Answer"},
                {"commandCode": 307, "applicationId": 16777217, "responseMethod": self.Answer_16777217_307, "failureResultCode": 5001 ,"failureResultCodeExperimental": True ,"requestAcronym": "PRUR", "responseAcronym": "PRUA", "requestName": "Profile Update Request", "responseName": "Profile Update Answer"},

                # Rx PCEF/P-CSCF
                {"commandCode": 265, "applicationId": 16777236, "responseMethod": self.Answer_16777236_265, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "AAR", "responseAcronym": "AAA", "requestName": "AA Request", "responseName": "AA Answer"},
                {"commandCode": 275, "applicationId": 16777236, "responseMethod": self.Answer_16777236_275, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "STR", "responseAcronym": "STA", "requestName": "Session Termination Request", "responseName": "Session Termination Answer"},
                {"commandCode": 274, "applicationId": 16777236, "responseMethod": self.Answer_16777236_274, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "ASR", "responseAcronym": "ASA", "requestName": "Abort Session Request", "responseName": "Abort Session Answer"},

                # Re OCS
                {"commandCode": 258, "applicationId": 16777238, "responseMethod": self.Answer_16777238_258, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "RAR", "responseAcronym": "RAA", "requestName": "Re Auth Request", "responseName": "Re Auth Answer"},
                {"commandCode": 272, "applicationId": 16777238, "responseMethod": self.Answer_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCA", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},

                # S6a MME
                {"commandCode": 318, "applicationId": 16777251, "flags": "c0", "responseMethod": self.Answer_16777251_318, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "AIR", "responseAcronym": "AIA", "requestName": "Authentication Information Request", "responseName": "Authentication Information Answer"},
                {"commandCode": 316, "applicationId": 16777251, "responseMethod": self.Answer_16777251_316, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "ULR", "responseAcronym": "ULA", "requestName": "Update Location Request", "responseName": "Update Location Answer"},
                {"commandCode": 321, "applicationId": 16777251, "responseMethod": self.Answer_16777251_321, "failureResultCode": 5012 ,"requestAcronym": "PUR", "responseAcronym": "PUA", "requestName": "Purge UE Request", "responseName": "Purge UE Answer"},
                {"commandCode": 323, "applicationId": 16777251, "responseMethod": self.Answer_16777251_323, "failureResultCode": 5012 ,"requestAcronym": "NOR", "responseAcronym": "NOA", "requestName": "Notify Request", "responseName": "Notify Answer"},

                # S13 EIR
                {"commandCode": 324, "applicationId": 16777252, "responseMethod": self.Answer_16777252_324, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "ECR", "responseAcronym": "ECA", "requestName": "ME Identity Check Request", "responseName": "ME Identity Check Answer"},

                # SLh LCS
                {"commandCode": 8388622, "applicationId": 16777291, "responseMethod": self.Answer_16777291_8388622, "failureResultCode": 4100 ,"failureResultCodeExperimental": True ,"requestAcronym": "LRR", "responseAcronym": "LRA", "requestName": "LCS Routing Info Request", "responseName": "LCS Routing Info Answer"},
            ]

        self.diameterRequestList = [
                # Gx PCEF/PCRF
                {"commandCode": 304, "applicationId": 16777216, "requestMethod": self.Request_16777216_304, "failureResultCode": 5012 ,"requestAcronym": "RTR", "responseAcronym": "RTA", "requestName": "Registration Termination Request", "responseName": "Registration Termination Answer"},

                # Re OCS
                {"commandCode": 258, "applicationId": 16777238, "requestMethod": self.Request_16777238_258, "failureResultCode": 5012 ,"requestAcronym": "RAR", "responseAcronym": "RAA", "requestName": "Re Auth Request", "responseName": "Re Auth Answer"},
                {"commandCode": 272, "applicationId": 16777238, "requestMethod": self.Request_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCA", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},

                # S6a MME
                {"commandCode": 317, "applicationId": 16777251, "requestMethod": self.Request_16777251_317, "failureResultCode": 5012 ,"requestAcronym": "CLR", "responseAcronym": "CLA", "requestName": "Cancel Location Request", "responseName": "Cancel Location Answer"},
                {"commandCode": 319, "applicationId": 16777251, "requestMethod": self.Request_16777251_319, "failureResultCode": 5012 ,"requestAcronym": "ISD", "responseAcronym": "ISA", "requestName": "Insert Subscriber Data Request", "responseName": "Insert Subscriber Data Answer"},
                {"commandCode": 320, "applicationId": 16777251, "requestMethod": self.Request_16777251_320, "failureResultCode": 5012 ,"requestAcronym": "DSR", "responseAcronym": "DSR", "requestName": "Delete Subscriber Data Request", "responseName": "Delete Subscriber Data Answer"}

        ]

    @staticmethod
    def get_unknown_imsi_reject_cause() -> int:
        if config.get('hss', {}).get('roaming', {}).get('inbound', {}).get('reject_unknown_imsis_with', 'IMSI_UNKNOWN') == 'ROAMING_NOT_ALLOWED':
            return 5004 # DIAMETER_ERROR_ROAMING_NOT_ALLOWED
        return 5001 # DIAMETER_ERROR_USER_UNKNOWN


    #Generates rounding for calculating padding
    def myround(self, n, base=4):
        if(n > 0):
            return math.ceil(n/4.0) * 4
        elif( n < 0):
            return math.floor(n/4.0) * 4
        else:
            return 4

    #Converts a dotted-decimal IPv4 address or IPV6 address to hex
    def ip_to_hex(self, ip):
        #Determine IPvX version:
        if "." in ip:
            ip = ip.split('.')
            ip_hex = "0001"         #IPv4
            ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
        else:
            ip_hex = "0002"         #IPv6
            ip_hex += format(ipaddress.IPv6Address(ip), 'X')
        return ip_hex
    
    def hex_to_int(self, hex):
        return int(str(hex), base=16)


    #Converts a hex formatted IPv4 address or IPV6 address to dotted-decimal 
    def hex_to_ip(self, hex_ip):
        if len(hex_ip) == 8:
            octet_1 = int(str(hex_ip[0:2]), base=16)
            octet_2 = int(str(hex_ip[2:4]), base=16)
            octet_3 = int(str(hex_ip[4:6]), base=16)
            octet_4 = int(str(hex_ip[6:8]), base=16)
            return str(octet_1) + "." + str(octet_2) + "." + str(octet_3) + "." + str(octet_4)
        elif len(hex_ip) == 32:
            n=4
            ipv6_split = [hex_ip[idx:idx + n] for idx in range(0, len(hex_ip), n)]
            ipv6_str = ''
            for octect in ipv6_split:
                ipv6_str += str(octect).lstrip('0') + ":"
            #Strip last Colon
            ipv6_str = ipv6_str[:-1]
            return ipv6_str

    #Converts string to hex
    def string_to_hex(self, string):
        string_bytes = string.encode('utf-8')
        return str(binascii.hexlify(string_bytes), 'ascii')

    #Converts int to hex padded to required number of bytes
    def int_to_hex(self, input_int, output_bytes):
        
        return format(input_int,"x").zfill(output_bytes*2)

    #Converts Hex byte to Binary
    def hex_to_bin(self, input_hex):
        return bin(int(str(input_hex), 16))[2:].zfill(8)

    #Generates a valid random ID to use
    def generate_id(self, length):
        length = length * 2
        return str(uuid.uuid4().hex[:length])

    def Reverse(self, str):
        stringlength=len(str)
        slicedString=str[stringlength::-1]
        return (slicedString)

    def DecodePLMN(self, plmn):
        if "f" in plmn:
            mcc = self.Reverse(plmn[0:2]) + self.Reverse(plmn[2:4]).replace('f', '')
            mnc = self.Reverse(plmn[4:6])
        else:
            mcc = self.Reverse(plmn[0:2]) + self.Reverse(plmn[2:4][1])
            mnc = self.Reverse(plmn[4:6]) + str(self.Reverse(plmn[2:4][0]))
        return mcc, mnc
        
    def EncodePLMN(self, mcc, mnc):
        plmn = list('XXXXXX')
        if len(mnc) == 2:
            plmn[0] = self.Reverse(mcc)[1]
            plmn[1] = self.Reverse(mcc)[2]
            plmn[2] = "f"
            plmn[3] = self.Reverse(mcc)[0]
            plmn[4] = self.Reverse(mnc)[0]
            plmn[5] = self.Reverse(mnc)[1]
            plmn_list = plmn
            plmn = ''
        else:
            plmn[0] = self.Reverse(mcc)[1]
            plmn[1] = self.Reverse(mcc)[2]
            plmn[2] = self.Reverse(mnc)[0]
            plmn[3] = self.Reverse(mcc)[0]
            plmn[4] = self.Reverse(mnc)[1]
            plmn[5] = self.Reverse(mnc)[2]
            plmn_list = plmn
            plmn = ''
        for bits in plmn_list:
            plmn = plmn + bits
        self.logTool.log(service='HSS', level='debug', message="Encoded PLMN: " + str(plmn), redisClient=self.redisMessaging)
        return plmn

    def TBCD_special_chars(self, input):
        self.logTool.log(service='HSS', level='debug', message="Special character possible in " + str(input), redisClient=self.redisMessaging)
        if input == "*":
            self.logTool.log(service='HSS', level='debug', message="Found * - Returning 1010", redisClient=self.redisMessaging)
            return "1010"
        elif input == "#":
            self.logTool.log(service='HSS', level='debug', message="Found # - Returning 1011", redisClient=self.redisMessaging)
            return "1011"
        elif input == "a":
            self.logTool.log(service='HSS', level='debug', message="Found a - Returning 1100", redisClient=self.redisMessaging)
            return "1100"
        elif input == "b":
            self.logTool.log(service='HSS', level='debug', message="Found b - Returning 1101", redisClient=self.redisMessaging)
            return "1101"
        elif input == "c":
            self.logTool.log(service='HSS', level='debug', message="Found c - Returning 1100", redisClient=self.redisMessaging)
            return "1100"      
        else:
            binform = "{:04b}".format(int(input))
            self.logTool.log(service='HSS', level='debug', message="input " + str(input) + " is not a special char, converted to bin: " + str(binform), redisClient=self.redisMessaging)
            return (binform)

    def TBCD_encode(self, input):
        self.logTool.log(service='HSS', level='debug', message="TBCD_encode input value is " + str(input), redisClient=self.redisMessaging)
        offset = 0
        output = ''
        matches = ['*', '#', 'a', 'b', 'c']
        if not all(digit.isdigit() or digit in matches for digit in str(input)):
            raise ValueError("TBCD_encode input contains non-TBCD characters: " + str(input))
        while offset < len(input):
            if len(input[offset:offset+2]) == 2:
                self.logTool.log(service='HSS', level='debug', message="processing bits " + str(input[offset:offset+2]) + " at position offset " + str(offset), redisClient=self.redisMessaging)
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                #Check if *, #, a, b or c
                if any(x in bit for x in matches):
                    self.logTool.log(service='HSS', level='debug', message="Special char in bit " + str(bit), redisClient=self.redisMessaging)
                    new_bit = ''
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[0]))
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[1]))
                    self.logTool.log(service='HSS', level='debug', message="Final bin output of new_bit is " + str(new_bit), redisClient=self.redisMessaging)
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    self.logTool.log(service='HSS', level='debug', message="Formatted as Hex this is " + str(bit), redisClient=self.redisMessaging)
                output = output + bit
                offset = offset + 2
            else:
                #If odd-length input
                last_digit = str(input[offset:offset+2])
                #Check if *, #, a, b or c
                if any(x in last_digit for x in matches):
                    self.logTool.log(service='HSS', level='debug', message="Special char in bit " + str(bit), redisClient=self.redisMessaging)
                    new_bit = ''
                    new_bit = new_bit + '1111'      #Add the F first
                    #Encode the symbol into binary and append it to the new_bit var
                    new_bit = new_bit + str(self.TBCD_special_chars(last_digit))
                    self.logTool.log(service='HSS', level='debug', message="Final bin output of new_bit is " + str(new_bit), redisClient=self.redisMessaging) 
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    self.logTool.log(service='HSS', level='debug', message="Formatted as Hex this is " + str(bit), redisClient=self.redisMessaging)
                else:
                    bit = "f" + last_digit
                offset = offset + 2
                output = output + bit
        self.logTool.log(service='HSS', level='debug', message="TBCD_encode final output value is " + str(output), redisClient=self.redisMessaging)
        return output

    def TBCD_decode(self, input):
        self.logTool.log(service='HSS', level='debug', message="TBCD_decode Input value is " + str(input), redisClient=self.redisMessaging)
        offset = 0
        output = ''
        while offset < len(input):
            if "f" not in input[offset:offset+2]:
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                output = output + bit
            else:   #If f in bit strip it
                bit = input[offset:offset+2]
                output = output + bit[1]
            offset = offset + 2
        self.logTool.log(service='HSS', level='debug', message="TBCD_decode output value is " + str(output), redisClient=self.redisMessaging)
        return output

    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_avp(self, avp_code, avp_flags, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that's overwritten later

        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)

        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)
        return avp

    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_vendor_avp(self, avp_code, avp_flags, avp_vendorid, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that gets overwritten later

        avp_vendorid = format(int(avp_vendorid),"x").zfill(8)
        
        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_vendorid) + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            self.logTool.log(service='HSS', level='debug', message="Rounded value is " + str(rounded_value), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Has " + str( int( rounded_value - avp_length)) + " bytes of padding", redisClient=self.redisMessaging)
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


        
        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_vendorid) + str(avp_content) + str(avp_padding)
        return avp

    def generate_diameter_packet(self, packet_version, packet_flags, packet_command_code, packet_application_id, packet_hop_by_hop_id, packet_end_to_end_id, avp):
        try:
            packet_length = 228
            packet_length = format(packet_length,"x").zfill(6)
        
            packet_command_code = format(packet_command_code,"x").zfill(6)
            
            packet_application_id = format(packet_application_id,"x").zfill(8)
            
            packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
            packet_length = int(round(len(packet_hex))/2)
            packet_length = format(packet_length,"x").zfill(6)
            
            packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
            return packet_hex
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [generate_diameter_packet] Exception: {e}", redisClient=self.redisMessaging)

    def get_sh_profile_call_barring_rules(self, serviceName, xmlRoot, xmlNamespace):
        service = xmlRoot.find(f'default:{serviceName}', xmlNamespace)
        if service is not None:
            active = service.get('active')
            allow = service.find('.//default:allow', xmlNamespace)
            allowValue = allow.text if allow is not None else None
            return active, allowValue
        return None, None

    def get_sh_profile_call_forwarding_rules(self, serviceName, xmlRoot, xmlNamespace):
        """
        Parse call forwarding rules from XCAP XML.
        Returns a tuple of (active_status, rules_dict) where rules_dict contains the forwarding rules
        for different conditions including unconditional forwarding.
        """
        service = xmlRoot.find(f'default:{serviceName}', xmlNamespace)
        if service is None:
            self.logTool.log(service='HSS', level='debug', message=f"Service {serviceName} not found", redisClient=self.redisMessaging)
            return None, None

        active = service.get('active') == 'true'
        
        forwarding_rules = {}
        
        ruleset = service.find('.//cp:ruleset', xmlNamespace)
        self.logTool.log(service='HSS', level='debug', message=f"Found ruleset: {ruleset is not None}", redisClient=self.redisMessaging)
        
        if ruleset is not None:
            rules = ruleset.findall('cp:rule', xmlNamespace)
            self.logTool.log(service='HSS', level='debug', message=f"Number of rules found: {len(rules)}", redisClient=self.redisMessaging)
            
            for rule in rules:
                rule_id = rule.get('id')
                if rule_id is None:
                    continue
                    
                self.logTool.log(service='HSS', level='debug', message=f"Processing rule ID: {rule_id}", redisClient=self.redisMessaging)
                
                conditions = rule.find('.//cp:conditions', xmlNamespace)
                condition = None
                
                if conditions is not None:
                    condition_children = list(conditions)
                    if len(condition_children) == 0:
                        condition = "unconditional"
                        self.logTool.log(service='HSS', level='debug', message="Found unconditional forwarding rule (empty conditions)", redisClient=self.redisMessaging)
                    elif len(condition_children) == 1:
                        first_condition = condition_children[0]
                        condition_tag = first_condition.tag.split('}')[-1]
                        if condition_tag == 'rule-deactivated':
                            condition = "unconditional"
                            self.logTool.log(service='HSS', level='debug', message="Found unconditional forwarding rule (rule-deactivated)", redisClient=self.redisMessaging)
                        else:
                            condition = condition_tag
                            self.logTool.log(service='HSS', level='debug', message=f"Found condition: {condition}", redisClient=self.redisMessaging)
                else:
                    condition = "unconditional"
                    self.logTool.log(service='HSS', level='debug', message="Found unconditional forwarding rule (no conditions element)", redisClient=self.redisMessaging)
                    
                actions = rule.find('.//cp:actions', xmlNamespace)
                if actions is not None:
                    forward_to = actions.find('.//default:forward-to', xmlNamespace)
                    if forward_to is not None:
                        target = forward_to.find('.//default:target', xmlNamespace)
                        if target is not None:
                            self.logTool.log(service='HSS', level='debug', message=f"Found target: {target.text}", redisClient=self.redisMessaging)
                            forwarding_rules[rule_id] = {
                                'condition': condition,
                                'target': target.text
                            }
                        else:
                            self.logTool.log(service='HSS', level='debug', message="No target element found", redisClient=self.redisMessaging)
                    else:
                        self.logTool.log(service='HSS', level='debug', message="No forward-to element found", redisClient=self.redisMessaging)
        
        no_reply_timer = service.find('.//default:NoReplyTimer', xmlNamespace)
        if no_reply_timer is not None:
            forwarding_rules['NoReplyTimer'] = no_reply_timer.text

        return active, forwarding_rules
    
    def roundUpToMultiple(self, n, multiple):
        return ((n + multiple - 1) // multiple) * multiple


    def validateSingleAvp(self, data) -> bool:
        """
        Attempts to validate a single hex string diameter AVP as being an AVP.
        """
        try:
            avpCode = int(data[0:8], 16)
            # The next byte contains the AVP Flags
            avpFlags = data[8:10]
            # The next 3 bytes contain the AVP Length
            avpLength = int(data[10:16], 16)
            if avpFlags not in ['80', '40', '20', '00', 'c0']:
                return False
            if int(len(data[16:]) / 2) < ((avpLength - 8)):
                return False
            return True
        except Exception as e:
            return False

    def split_diameter_message(self, data) -> list:
        """
        Returns a list of undecoded diameter messages, from a received binary message.
        This provides support for one or more diameter messages contained within a single packet.
        """
        packet_vars = {}
        diameter_messages = []
        message_processing_complete = False
        index = 0
        failsafe = 0

        if type(data) is bytes:
            data = data.hex()

        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Splitting: {data}", redisClient=self.redisMessaging)

        while message_processing_complete == False:
            try:
                if failsafe > 50:
                    message_processing_complete = True
                    break

                if len(data[index:]) < 40:
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Message splitting complete.", redisClient=self.redisMessaging)
                    message_processing_complete = True
                    break

                # One byte is 2 hex characters
                # First Byte is the Diameter Packet Version
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Index at start: {index}", redisClient=self.redisMessaging)
                
                diameter_message_header = data[index:index+40]
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Header: {diameter_message_header}", redisClient=self.redisMessaging)

                packet_version = diameter_message_header[0:2]
                packet_length = int(diameter_message_header[2:8], 16)
                hex_character_length = packet_length * 2
                packet_flags = diameter_message_header[8:10]
                packet_command_code = int(diameter_message_header[10:16], 16)
                packet_application_id = int(diameter_message_header[16:24], 16)
                packet_hop_by_hop_identifier = diameter_message_header[24:32]
                packet_end_to_end_identifier = diameter_message_header[32:40]

                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Packet Length: {packet_length}", redisClient=self.redisMessaging)
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Hex Char Length: {hex_character_length}", redisClient=self.redisMessaging)
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Appending: {data[index:index+hex_character_length]}", redisClient=self.redisMessaging)
                diameter_messages.append(data[index:index+hex_character_length])
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Current Index: {index}", redisClient=self.redisMessaging)
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Processed (HBH ID): {packet_hop_by_hop_identifier}", redisClient=self.redisMessaging)
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Processed (E2E ID): {packet_end_to_end_identifier}", redisClient=self.redisMessaging)
                index += hex_character_length
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] New Index: {index}", redisClient=self.redisMessaging)
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [split_diameter_message] Remaining Stack: {data[index:]}", redisClient=self.redisMessaging)

                failsafe += 1

            except Exception as e:
                self.logTool.log(service='HSS', level='warning', message=f"[diameter.py] [split_diameter_message] Error splitting diameter message: {traceback.format_exc()}", redisClient=self.redisMessaging)
                return diameter_messages

        return diameter_messages



    def decode_diameter_packet(self, data):
        """
        Handles decoding of a full diameter packet.
        """
        packet_vars = {}
        avps = []

        if type(data) is bytes:
            data = data.hex()
        # One byte is 2 hex characters
        # First Byte is the Diameter Packet Version
        packet_vars['packet_version'] = data[0:2]
        # Next 3 Bytes are the length of the entire Diameter packet
        packet_vars['length'] = int(data[2:8], 16)
        # Next Byte is the Diameter Flags
        packet_vars['flags'] = data[8:10]
        packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
        # Next 3 Bytes are the Diameter Command Code
        packet_vars['command_code'] = int(data[10:16], 16)
        # Next 4 Bytes are the Application Id
        packet_vars['ApplicationId'] = int(data[16:24], 16)
        # Next 4 Bytes are the Hop By Hop Identifier
        packet_vars['hop-by-hop-identifier'] = data[24:32]
        # Next 4 Bytes are the End to End Identifier
        packet_vars['end-to-end-identifier'] = data[32:40]

        lengthOfDiameterVars = int(len(data[:40]) / 2)

        #Length of all AVPs, in bytes
        avpLength = int(packet_vars['length'] - lengthOfDiameterVars)
        avpCharLength = int((avpLength * 2))
        remaining_avps = data[40:]

        avps = self.decodeAvpPacket(remaining_avps)

        return packet_vars, avps

    def decodeAvpPacket(self, data):
        """
        Returns a list of decoded AVP Packet dictionaries.
        This function is called at a high frequency, decoding methods should stick to iteration and not recursion, to avoid a memory leak.
        """
        # Note: After spending hours on this, I'm leaving the following technical debt:
        # Subavps and all their descendents are lifted up, flat, side by side into the parent's sub_avps list.
        # It's definitely possible to keep the nested tree structure, if anyone wants to improve this function. But I can't figure out a simple way to do so, without invoking recursion.


        # Our final list of AVP Dictionaries, which will be returned once processing is complete.
        processed_avps = []
        # Initialize a failsafe counter, to prevent packets that pass validation but aren't AVPs from causing an infinite loop
        failsafeCounter = 0

        # If the avp data is 8 bytes (16 chars) or less, it's invalid.
        if len(data) < 16:
            return []

        # Working stack to aid in iterative processing of sub-avps.
        subAvpUnprocessedStack = []

        # Keep processing AVPs until they're all dealt with
        while len(data) > 16:
            try:
                failsafeCounter += 1

                if failsafeCounter > 100:
                    self.logTool.log(service='HSS', level='warning', message=f"[diameter.py] [decodeAvpPacket] Diameter AVP Decoder Failsafe activated: {data}", redisClient=self.redisMessaging)
                    break
                avp_vars = {}
                # The first 4 bytes contains the AVP code
                avp_vars['avp_code'] = int(data[0:8], 16)
                # The next byte contains the AVP Flags
                avp_vars['avp_flags'] = data[8:10]
                # The next 3 bytes contains the AVP Length
                avp_vars['avp_length'] = int(data[10:16], 16)
                # The remaining bytes (until the end, defined by avp_length) is the AVP payload.
                # Padding is excluded from avp_length. It's calculated separately, and unknown by the AVP itself.
                # We calculate the avp payload length (in bytes) by subtracting 8, because the avp headers are always 8 bytes long. 
                # The result is then multiplied by 2 to give us chars.
                avpPayloadLength = int((avp_vars['avp_length'])*2)

                # Work out our vendor id and add the payload itself (misc_data)
                if avp_vars['avp_flags'] == 'c0' or avp_vars['avp_flags'] == '80':
                    avp_vars['vendor_id'] = int(data[16:24], 16)
                    avp_vars['misc_data'] = data[24:avpPayloadLength]
                else:
                    avp_vars['vendor_id'] = ''
                    avp_vars['misc_data'] = data[16:avpPayloadLength]

                payloadContainsSubAvps = self.validateSingleAvp(avp_vars['misc_data'])
                if payloadContainsSubAvps:
                    # If the payload contains sub or grouped AVPs, append misc_data to the subAvpUnprocessedStack to start working through one or more subavp
                    subAvpUnprocessedStack.append(avp_vars["misc_data"])
                    avp_vars["misc_data"] = ''

                # Rounds up the length to the nearest multiple of 4, which we can differential against the avp length to give us the padding length (if required)
                avp_padded_length = int((self.roundUpToMultiple(avp_vars['avp_length'], 4)))
                avpPaddingLength = ((avp_padded_length - avp_vars['avp_length']) * 2)

                # Initialize a blank sub_avps list, regardless of whether or not we have any sub avps.
                avp_vars['sub_avps'] = []

                while payloadContainsSubAvps:
                    # Increment our failsafe counter, which will fail after 100 tries. This prevents a rare validation error from causing the function to hang permanently.
                    failsafeCounter += 1

                    if failsafeCounter > 100:
                        self.logTool.log(service='HSS', level='warning', message=f"[diameter.py] [decodeAvpPacket] Diameter Sub-AVP Decoder Failsafe activated: {data}", redisClient=self.redisMessaging)
                        break
                    
                    # Pop the sub avp data from the list (remove from the end)
                    sub_avp_data = subAvpUnprocessedStack.pop()

                    # Initialize our sub avp dictionary, and grab the usual values
                    sub_avp = {}
                    sub_avp['avp_code'] = int(sub_avp_data[0:8], 16)
                    sub_avp['avp_flags'] = sub_avp_data[8:10]
                    sub_avp['avp_length'] = int(sub_avp_data[10:16], 16)
                    sub_avpPayloadLength = int((sub_avp['avp_length'])*2)

                    if sub_avp['avp_flags'] == 'c0' or sub_avp['avp_flags'] == '80':
                        sub_avp['vendor_id'] = int(sub_avp_data[16:24], 16)
                        sub_avp['misc_data'] = sub_avp_data[24:sub_avpPayloadLength]
                    else:
                        sub_avp['vendor_id'] = ''
                        sub_avp['misc_data'] = sub_avp_data[16:sub_avpPayloadLength]

                    containsSubAvps = self.validateSingleAvp(sub_avp["misc_data"])
                    if containsSubAvps:
                        subAvpUnprocessedStack.append(sub_avp["misc_data"])
                        sub_avp["misc_data"] = ''
                    
                    avp_vars['sub_avps'].append(sub_avp)

                    sub_avp_padded_length = int((self.roundUpToMultiple(sub_avp['avp_length'], 4)))
                    subAvpPaddingLength = ((sub_avp_padded_length - sub_avp['avp_length']) * 2)

                    sub_avp_data = sub_avp_data[sub_avpPayloadLength+subAvpPaddingLength:]
                    containsNestedSubAvps = self.validateSingleAvp(sub_avp_data)

                    # Check for nested sub avps and bring them to the top of the stack, for further processing.
                    if containsNestedSubAvps:
                        subAvpUnprocessedStack.append(sub_avp_data)
                    
                    if containsSubAvps or containsNestedSubAvps:
                        payloadContainsSubAvps = True
                    else:
                        if not subAvpUnprocessedStack:
                            payloadContainsSubAvps = False

                if avpPaddingLength > 0:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength+avpPaddingLength:]
                else:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength:]
            except Exception as e:
                print(e)
                continue

        return processed_avps

    def get_avp_data(self, avps, avp_code):               
        #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for avpObject in avps:
            if int(avpObject['avp_code']) == int(avp_code):
                if len(avpObject['misc_data']) == 0:
                    misc_data.append(avpObject['sub_avps'])
                else:
                    misc_data.append(avpObject['misc_data'])
            if 'sub_avps' in avpObject:
                for sub_avp in avpObject['sub_avps']:
                    if int(sub_avp['avp_code']) == int(avp_code):
                        misc_data.append(sub_avp['misc_data'])
        return misc_data

    def get_required_avp_data(self, avps, avp_code, vendor_id=None):
        #Returns the data of the first AVP with avp_code, or raises DiameterMissingAvp so the request is answered with DIAMETER_MISSING_AVP
        data = self.get_avp_data(avps, avp_code)
        if not data or not data[0]:                                                                 #Absent, or present with an empty payload
            raise DiameterMissingAvp(avp_code, vendor_id=vendor_id)
        return data[0]

    def decode_diameter_packet_length(self, data):
        packet_vars = {}
        data = data.hex()
        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        if packet_vars['packet_version'] == "01":
            return packet_vars['length']
        else:
            return False
        
    def getPeerType(self, originHost: str) -> str:
        try:
            peerTypes = ['mme', 'pgw', 'pcscf', 'icscf', 'scscf', 'hss', 'ocs', 'dra']

            for peer in peerTypes:
                if peer in originHost.lower():
                    return peer
            return 'Unknown'
        except Exception as e:
            return ''
    
    def decode_3gpp_user_location_info(self, hex_data):
        data = bytes.fromhex(hex_data)
        
        geo_type = data[0]
        
        geo_type_names = {
            0: "CGI", 1: "SAI", 2: "RAI", 128: "TAI", 129: "ECGI", 130: "TAI and ECGI",
            131: "eNodeB ID", 132: "TAI and eNodeB ID", 133: "extended eNodeB ID",
            134: "TAI and extended eNodeB ID", 135: "NCGI", 136: "5GS TAI",
            137: "5GS TAI and NCGI", 138: "NG-RAN Node ID", 139: "5GS TAI and NG-RAN Node ID"
        }
        
        result = {
            "Geographic_Location_Type": geo_type,
            "Geographic_Location_Type_Name": geo_type_names.get(geo_type, "Unknown")
        }
        
        if geo_type == 130:
            # TAI data is in bytes 1-5
            tai_data = data[1:6]
            
            # ECGI data is in bytes 6-12
            ecgi_data = data[6:]
            
            tai_plmn_hex = tai_data[0:3].hex()
            ecgi_plmn_hex = ecgi_data[0:3].hex()
            
            tai_mcc, tai_mnc = self.DecodePLMN(tai_plmn_hex)
            ecgi_mcc, ecgi_mnc = self.DecodePLMN(ecgi_plmn_hex)
            
            tai_tac = int.from_bytes(tai_data[3:5], byteorder='big')
            ecgi_eci = int.from_bytes(ecgi_data[3:7], byteorder='big')
            
            enodeb_id = (ecgi_eci >> 8) & 0xFFFFF
            cell_id = ecgi_eci & 0xFF

            result.update({
                "tai": {
                    "mcc": str(tai_mcc),
                    "mnc": str(tai_mnc),
                    "tac": str(tai_tac)
                },
                "ecgi": {
                    "mcc": str(ecgi_mcc),
                    "mnc": str(ecgi_mnc),
                    "eci": str(ecgi_eci),
                    "enodeb_id": str(enodeb_id),
                    "cell_id": str(cell_id)
                }
            })
        
        return result


    def getDraPeers(self) -> list:
        try:
            filteredConnectedPeers = []
            
            activePeers = self.redisMessaging.getAllHashData(name=self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
            if not activePeers:
                return filteredConnectedPeers
            
            for peerKey, peer in activePeers.items():
                diameterPeer = Peer.model_validate(pydantic_core.from_json(json.dumps(peer)))
                diameterPeerType = None
                if diameterPeer.Metadata:
                    metadataJson = json.loads(diameterPeer.Metadata)
                    diameterPeerType = metadataJson.get('DiameterPeerType', 'Unknown')
                    if diameterPeerType == 'Unknown':
                        try:
                            diameterPeerType = diameterPeer.PeerType
                        except:
                            diameterPeerType = "Unknown"
                    # If the peer matches the supplied type, and the peer is connected, add the matching peer type to filteredConnectedPeers.
                if diameterPeerType.lower() == 'dra' and diameterPeer.Connected:
                    filteredConnectedPeers.append(diameterPeer)
            
            return filteredConnectedPeers

        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [getDraPeers] Failed to find connected DRA peers: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return []

    def getConnectedPeersByType(self, peerType: str) -> list:
        try:
            requestedPeerType = peerType.lower()
            peerTypes = ['mme', 'pgw', 'pcscf', 'icscf', 'scscf', 'hss', 'ocs', 'dra']
            filteredConnectedPeers = []

            if requestedPeerType not in peerTypes:
                return filteredConnectedPeers
            
            activePeers = self.redisMessaging.getAllHashData(name=self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
            if not activePeers:
                return filteredConnectedPeers
            
            for peerKey, peer in activePeers.items():
                diameterPeer = Peer.model_validate(pydantic_core.from_json(json.dumps(peer)))
                diameterPeerType = None
                if diameterPeer.Metadata:
                    metadataJson = json.loads(diameterPeer.Metadata)
                    diameterPeerType = metadataJson.get('DiameterPeerType', 'Unknown')
                    if diameterPeerType == 'Unknown':
                        try:
                            diameterPeerType = diameterPeer.PeerType
                        except:
                            diameterPeerType = "Unknown"
                    # If the peer matches the supplied type, and the peer is connected, add the matching peer type to filteredConnectedPeers.
                if diameterPeerType == requestedPeerType and diameterPeer.Connected:
                    filteredConnectedPeers.append(diameterPeer)

            try:
                if len(filteredConnectedPeers) == 0:
                    if self.useDraFallback == True:
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [getConnectedPeersByType] No peers of type {peerType} found, attempting to use DRA fallback", redisClient=self.redisMessaging)
                        connectedDraPeers = self.getDraPeers()
                        if len(connectedDraPeers) > 0:
                            return [connectedDraPeers[0]]
                        else:
                            return filteredConnectedPeers
                    else:
                        return filteredConnectedPeers
            except Exception as e:
                pass

            return filteredConnectedPeers

        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [getConnectedPeersByType] Failed to find get connected peers by type {peerType}, {traceback.format_exc()}", redisClient=self.redisMessaging)
            return []

    def getPeerByHostname(self, hostname: str) -> Peer:
        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [getPeerByHostname] Looking for peer with hostname {hostname}", redisClient=self.redisMessaging)
        try:
            hostname = hostname.lower()
            activePeers = self.redisMessaging.getAllHashData(name=self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')

            if not activePeers:
                return {}

            for peerKey, peer in activePeers.items():
                diameterPeer = Peer.model_validate(pydantic_core.from_json(json.dumps(peer)))
                if diameterPeer.Hostname.lower() == hostname and diameterPeer.Connected:
                    return diameterPeer

            try:
                if self.useDraFallback == True:
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [getPeerByHostname] {hostname} not found, attempting to use DRA fallback", redisClient=self.redisMessaging)
                    connectedDraPeers = self.getDraPeers()
                    if len(connectedDraPeers) > 0:
                        return connectedDraPeers[0]
                    else:
                        return {}
                else:
                    return {}
            except Exception as e:
                return {}

        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [getPeerByHostname] Failed to find peer with hostname {hostname}, {traceback.format_exc()}", redisClient=self.redisMessaging)
            return {}

    def update_stored_peer(self, peerKey: str, peer: dict) -> bool:
        """
        Updates a peer in Redis storage using an upsert pattern.
        
        Args:
            peerKey (str): The IP address of the peer to update
            peer (dict): New peer data to merge with existing data
            
        Returns:
            bool: True if successful, False if there was an error
            
        Example peer data structure:
        {
            "Hostname": "host1.example.com",
            "PeerType": "MME",
            "Metadata": "{\"Host\":\"host1\",\"Realm\":\"example.com\"}"
        }
        """
        try:
            self.diameterPeerKey = config.get('hss', {}).get('diameter_peer_key', 'diameterPeers')
            
            existing_peer = self.redisMessaging.getHashValue(
                name=self.diameterPeerKey,
                key=peerKey,
                usePrefix=True,
                prefixHostname=self.hostname,
                prefixServiceName='diameter'
            )
            
            if existing_peer:
                try:
                    existing_data = json.loads(existing_peer)
                    for key, value in peer.items():
                        existing_data[key] = value
                    merged_peer = existing_data
                except json.JSONDecodeError:
                    self.logTool.log(
                        service='HSS',
                        level='warning',
                        message=f"Failed to parse existing peer data for {peerKey}, treating as new peer",
                        redisClient=self.redisMessaging
                    )
                    merged_peer = peer
            else:
                merged_peer = peer
                
            success = self.redisMessaging.setHashValue(
                name=self.diameterPeerKey,
                key=peerKey,
                value=json.dumps(merged_peer),
                usePrefix=True,
                prefixHostname=self.hostname,
                prefixServiceName='diameter'
            )
            
            if success:
                self.logTool.log(
                    service='HSS',
                    level='debug',
                    message=f"Successfully updated peer {peerKey}",
                    redisClient=self.redisMessaging
                )
                return True
            else:
                self.logTool.log(
                    service='HSS',
                    level='warning',
                    message=f"Failed to set peer data in Redis for {peerKey}",
                    redisClient=self.redisMessaging
                )
                return False
                
        except Exception as e:
            self.logTool.log(
                service='HSS',
                level='warning',
                message=f"Error updating stored peer: {traceback.format_exc()}",
                redisClient=self.redisMessaging
            )
            return False

    def getDiameterMessageType(self, binaryData: str) -> dict:
        """
        Determines whether a message is a request or a response, and the appropriate acronyms for each type.
        """
        packet_vars, avps = self.decode_diameter_packet(binaryData)
        response = {}
        
        for diameterApplication in self.diameterResponseList:
            try:
                assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                if packet_vars["flags_bin"][0:1] == "1":
                    response['inbound'] = diameterApplication["requestAcronym"]
                    response['outbound'] = diameterApplication["responseAcronym"]
                else:
                    response['inbound'] = diameterApplication["responseAcronym"]
                    response['outbound'] = diameterApplication["requestAcronym"]
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] Matched message types: {response}", redisClient=self.redisMessaging)
            except Exception as e:
                continue
        return response

    def sendDiameterRequest(self, requestType: str, hostname: str, **kwargs) -> str:
        """
        Sends a given diameter request of requestType to the provided peer hostname, if the peer is connected.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeer = self.getPeerByHostname(hostname=hostname)
                peerIp = None
                peerPort = None

                try:
                    peerIp = connectedPeer.IpAddress
                    peerPort = connectedPeer.Port
                except Exception as e:
                    pass

                try:
                    request = diameterApplication["requestMethod"](**kwargs)
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                except Exception as e:
                    self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Error generating request: {traceback.format_exc()}", redisClient=self.redisMessaging)
                    return ''
                outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                sendTime = time.time_ns()
                outboundMessage = OutboundData(DestinationIp=peerIp,
                                                DestinationPort=peerPort,
                                                InitialReceiveTimestamp=sendTime,
                                                OutboundHex=request)
                self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage.model_dump_json(), queueExpiry=self.diameterRequestTimeout, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Queueing for host: {hostname} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
            return request
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def broadcastDiameterRequest(self, requestType: str, peerType: str, **kwargs) -> bool:
        """
        Sends a diameter request of requestType to one or more connected peers, specified by peerType.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Broadcasting a diameter outbound request of type: {requestType} to peers of type: {peerType}", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeerList = self.getConnectedPeersByType(peerType=peerType)
                for connectedPeer in connectedPeerList:
                    try:
                        peerIp = connectedPeer.IpAddress
                        peerPort = connectedPeer.Port
                    except Exception as e:
                        return ''
                    try:
                        request = diameterApplication["requestMethod"](**kwargs)
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                    except Exception as e:
                        self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Error generating request: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        return ''
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                    outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                    sendTime = time.time_ns()

                    outboundMessage = OutboundData(DestinationIp=peerIp,
                                                DestinationPort=peerPort,
                                                InitialReceiveTimestamp=sendTime,
                                                OutboundHex=request)
                    
                    self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage.model_dump_json(), queueExpiry=self.diameterRequestTimeout, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Queueing for peer type: {peerType} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
            return connectedPeerList
        except Exception as e:
            return ''

    def awaitDiameterRequestAndResponse(self, requestType: str, hostname: str, timeout: float=0.12, **kwargs) -> str:
        """
        Sends a given diameter request of requestType to the provided peer hostname.
        Ensures the peer is connected, sends the request, then waits on and returns the response.
        If the timeout is reached, the function fails.

        Diameter lacks a unique identifier for all message types, the closest being Session-ID which exists for most.
        We attempt to get the associated response given the following logic:
          - If sessionId is none, attempt to return the first response that matches the expected response method (eg AAA, CEA, etc.) which has a timestamp greater than sendTime.
          - If sessionId is not none, perform the logic above, and also ensure that sessionId matches.

        Returns an empty string if fails.

        Until diameter.py is rewritten to be asynchronous, this method should be called only when strictly necessary. It potentially adds up to 120ms of delay per invocation.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeer = self.getPeerByHostname(hostname=hostname)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Sending request via connected peer {connectedPeer} from hostname {hostname}", redisClient=self.redisMessaging)
                try:
                    peerIp = connectedPeer.IpAddress
                    peerPort = connectedPeer.Port
                except Exception as e:
                    self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Could not get connection information for connectedPeer: {connectedPeer}", redisClient=self.redisMessaging)
                    return ''
                    
                try:
                    request = diameterApplication["requestMethod"](**kwargs)
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                except Exception as e:
                    self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Error generating request: {traceback.format_exc()}", redisClient=self.redisMessaging)
                    return ''
                responseType = diameterApplication["responseAcronym"]
                sessionId = kwargs.get('sessionId', None)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                sendTime = time.time_ns()
                outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                outboundMessage = OutboundData(DestinationIp=peerIp,
                                                DestinationPort=peerPort,
                                                InitialReceiveTimestamp=sendTime,
                                                OutboundHex=request)
                self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage.model_dump_json(), queueExpiry=self.diameterRequestTimeout, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Queueing for host: {hostname} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
                startTimer = time.time()
                while True:
                    try:
                        if not time.time() >= startTimer + timeout:
                            if sessionId is None:
                                queuedMessages = self.redisMessaging.getList(key=f"diameter-inbound", usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] queuedMessages(NoSessionId): {queuedMessages}", redisClient=self.redisMessaging)
                                for queuedMessage in queuedMessages:
                                    queuedMessage = json.loads(queuedMessage)
                                    clientAddress = queuedMessage.get('SenderIp', None)
                                    clientPort = queuedMessage.get('SenderPort', None)
                                    if clientAddress != peerIp or clientPort != peerPort:
                                        continue
                                    messageReceiveTime = queuedMessage.get('InitialReceiveTimestamp', None)
                                    if float(messageReceiveTime) > sendTime:
                                        messageHex = queuedMessage.get('InboundHex')
                                        messageType = self.getDiameterMessageType(messageHex)
                                        if messageType['inbound'].upper() == responseType.upper():
                                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Found inbound response: {messageHex}", redisClient=self.redisMessaging)
                                            return messageHex
                                time.sleep(0.02)
                            else:
                                queuedMessages = self.redisMessaging.getList(key=f"diameter-inbound", usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] queuedMessages({sessionId}): {queuedMessages} responseType: {responseType}", redisClient=self.redisMessaging)
                                for queuedMessage in queuedMessages:
                                    queuedMessage = json.loads(queuedMessage)
                                    clientAddress = queuedMessage.get('SenderIp', None)
                                    clientPort = queuedMessage.get('SenderPort', None)
                                    if clientAddress != peerIp or clientPort != peerPort:
                                        continue
                                    messageReceiveTime = queuedMessage.get('InitialReceiveTimestamp', None)
                                    if float(messageReceiveTime) > sendTime:
                                        messageHex = queuedMessage.get('InboundHex')
                                        messageType = self.getDiameterMessageType(messageHex)
                                        if messageType['inbound'].upper() == responseType.upper():
                                            packetVars, avps = self.decode_diameter_packet(messageHex)
                                            messageSessionId = bytes.fromhex(self.get_avp_data(avps, 263)[0]).decode('ascii')
                                            if messageSessionId == sessionId:
                                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Matched on Session Id: {sessionId}", redisClient=self.redisMessaging)
                                                return messageHex
                                time.sleep(0.02)
                        else:
                            return ''
                    except Exception as e:
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Traceback: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        return ''
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def generateDiameterResponse(self, binaryData: str) -> str:
            try:
                packet_vars, avps = self.decode_diameter_packet(binaryData)
                origin_host = self.get_avp_data(avps, 264)[0]
                origin_host = binascii.unhexlify(origin_host).decode("utf-8")
                response = ''

                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] Generating a diameter response", redisClient=self.redisMessaging)

                # Drop packet if it's a response packet:
                if packet_vars["flags_bin"][0:1] == "0":
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [generateDiameterResponse] Got a Response, not a request - dropping it.", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='debug', message=packet_vars, redisClient=self.redisMessaging)
                    return
                
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_request_count_application_id',
                    metricType='counter', metricAction='inc', 
                    metricLabels={
                        "diameter_application_id": packet_vars["ApplicationId"],
                        "diameter_cmd_code": packet_vars["command_code"],
                    },
                    metricValue=1.0, metricHelp='Number of Diameter Requests by Application Id',
                    metricExpiry=60,
                    usePrefix=True, 
                    prefixHostname=self.hostname, 
                    prefixServiceName='metric')
                
                matchedApplication = None
                handlerError = None
                for diameterApplication in self.diameterResponseList:
                    try:
                        assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                        assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                        if 'flags' in diameterApplication:
                            assert(str(packet_vars["flags"]) == str(diameterApplication["flags"]))
                    except Exception as e:
                        continue
                    matchedApplication = diameterApplication
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] Attempting to generate response", redisClient=self.redisMessaging)
                    try:
                        response = diameterApplication["responseMethod"](packet_vars, avps)
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] Successfully generated response: {response}", redisClient=self.redisMessaging)
                    except DiameterAvpError as e:
                        self.logTool.log(service='HSS', level='warning', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] {e}", redisClient=self.redisMessaging)
                        handlerError = e
                    except Exception as e:
                        self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] Error generating response: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        handlerError = e
                    break

                if matchedApplication is None:
                    raise ValueError(f"No response handler for command code {packet_vars['command_code']} application {packet_vars['ApplicationId']}")

                if handlerError is not None:
                    #The handler failed: answer with an error Result-Code instead of dropping the request.
                    #This runs outside the matching loop, so a failure while building the error answer is
                    #counted by the failure metric below and the request is dropped as before, not counted
                    #as a successful response.
                    if isinstance(handlerError, DiameterAvpError):
                        if handlerError.vendor_id:
                            failed_avp = self.generate_vendor_avp(handlerError.avp_code, handlerError.avp_flags, handlerError.vendor_id, handlerError.avp_data)
                        else:
                            failed_avp = self.generate_avp(handlerError.avp_code, handlerError.avp_flags, handlerError.avp_data)
                        response = self.Respond_ResultCode(packet_vars, avps, handlerError.result_code, failed_avp=failed_avp)
                    else:
                        #failureResultCodeExperimental marks the entries whose fallback code is a 3GPP
                        #(Vendor-Id 10415) Experimental-Result-Code; the RFC 6733 codes go in Result-Code.
                        response = self.Respond_ResultCode(packet_vars, avps, matchedApplication['failureResultCode'], experimental=matchedApplication.get('failureResultCodeExperimental', False))
                    self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_application_id_fail',
                                        metricType='counter', metricAction='inc',
                                        metricLabels={
                                            "diameter_application_id": packet_vars["ApplicationId"],
                                            "diameter_cmd_code": packet_vars["command_code"],
                                        },
                                        metricValue=1.0, metricHelp='Number of Failed Diameter Responses',
                                        metricExpiry=60,
                                        usePrefix=True,
                                        prefixHostname=self.hostname,
                                        prefixServiceName='metric')
                    return response

                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_application_id_successful',
                                    metricType='counter', metricAction='inc', 
                                    metricLabels={
                                        "diameter_application_id": packet_vars["ApplicationId"],
                                        "diameter_cmd_code": packet_vars["command_code"],
                                    },
                                    metricValue=1.0, metricHelp='Number of Successful Diameter Responses',
                                    metricExpiry=60,
                                    usePrefix=True, 
                                    prefixHostname=self.hostname, 
                                    prefixServiceName='metric')
                return response
            except Exception as e:
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_application_id_fail',
                                                metricType='counter', metricAction='inc',
                                                metricLabels={
                                                    "diameter_application_id": packet_vars["ApplicationId"],
                                                    "diameter_cmd_code": packet_vars["command_code"],
                                                },
                                                metricValue=1.0, metricHelp='Number of Failed Diameter Responses',
                                                metricExpiry=60,
                                                usePrefix=True, 
                                                prefixHostname=self.hostname, 
                                                prefixServiceName='metric')
                return ''

    def generateDiameterRequest(self, requestType: str, **kwargs) -> str:
        """
        Returns a given diameter request of requestType in a hex string.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue

                request = diameterApplication["requestMethod"](**kwargs)
                self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                return request
        except Exception as e:
            self.logTool.log(service='AS', level='error', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def validateImsSubscriber(self, imsi=None, msisdn=None) -> bool:
        """
        Ensures that a given IMSI or MSISDN (Or both, if specified) are associated with a subscriber that is enabled, and has an associated IMS Subscriber record.
        """
        self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [validateImsSubscriber] Checking subscriber with IMSI {imsi} / MSISDN {msisdn} is associated with a subscriber that is enabled and has an IMS Subscriber record", redisClient=self.redisMessaging)
        if imsi == None and msisdn == None:
            self.logTool.log(service='AS', level='info', message=f"[diameter.py] [validateImsSubscriber] Neither an IMSI or an MSISDN was passed", redisClient=self.redisMessaging)
            return False

        try:
            if imsi is not None:
                subscriberDetails = self.database.Get_Subscriber(imsi=imsi)
                if not subscriberDetails.get('enabled', False):
                    return False
                imsSubscriberDetails = self.database.Get_IMS_Subscriber(imsi=imsi)
                self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [validateImsSubscriber] IMS Subscriber validated based on IMSI OK", redisClient=self.redisMessaging)
        except Exception as e:
            return False
        try:
            if msisdn is not None:
                subscriberDetails = self.database.Get_Subscriber(msisdn=msisdn)
                if not subscriberDetails.get('enabled', False):
                    return False
                imsSubscriberDetails = self.database.Get_IMS_Subscriber(msisdn=msisdn)
                self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [validateImsSubscriber] IMS Subscriber validated based on MSISDN OK", redisClient=self.redisMessaging)
        except Exception as e:
            return False
        
        return True


    def deregisterApn(self, imsi: str=None, msisdn: str=None, apn: str=None) -> bool:
        """
        Revokes a given UE's session with the assigned PGW (If it exists), and sends a CLR to the MME.
        """
        try:
            if imsi is None and msisdn is None:
                return False

            if imsi is not None:
                subscriberDetails = self.database.Get_Subscriber(imsi=imsi)
            if msisdn is not None:
                subscriberDetails = self.database.Get_Subscriber(msisdn=msisdn)
                imsi = subscriberDetails.get('imsi', '')
        
            if subscriberDetails is None:
                return False
            
            subscriberId = subscriberDetails.get('subscriber_id', None)

            # If a subscriber has an active serving apn, grab the pcrf session id for that apn and send a CCR-T, then a Registration Termination Request to the serving pgw peer.
            if subscriberId is not None:
                servingApns = self.database.Get_Serving_APNs(subscriber_id=subscriberId)
                if len(servingApns.get('apns', {})) > 0:
                    for apnKey, apnDict in servingApns['apns'].items():
                        pcrfSessionId = None
                        servingPgwPeer = None
                        servingPgwRealm = None
                        servingPgw = None
                        for apnDataKey, apnDataValue in servingApns['apns'][apnKey].items():
                            if apnDataKey == 'pcrf_session_id':
                                pcrfSessionId = apnDataValue
                            if apnDataKey == 'serving_pgw_peer':
                                servingPgwPeer = apnDataValue
                            if apnDataKey == 'serving_pgw_realm':
                                servingPgwRealm = apnDataValue
                            if apnDataKey == 'serving_pgw':
                                servingPgwRealm = apnDataValue
                            
                        if pcrfSessionId is not None and servingPgwPeer is not None and servingPgwRealm is not None and servingPgw is not None:
                            if ';' in servingPgwPeer:
                                servingPgwPeer = servingPgwPeer.split(';')[0]
                            
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [deregisterData] Sending CCR-T with Session-ID:{pcrfSessionId} to peer: {servingPgwPeer} {apnKey}", redisClient=self.redisMessaging)

                            self.sendDiameterRequest(
                            requestType='CCR',
                            hostname=servingPgwPeer,
                            imsi=imsi,
                            destinationHost=servingPgw, 
                            destinationRealm=servingPgwRealm,
                            ccr_type=3,
                            sessionId=pcrfSessionId,
                            domain=servingPgwRealm
                            )

                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [deregisterData] Sending RTR to peer: {servingPgwPeer} {apnKey}", redisClient=self.redisMessaging)

                            self.sendDiameterRequest(
                            requestType='RTR',
                            hostname=servingPgwPeer,
                            imsi=imsi,
                            destinationHost=servingPgw, 
                            destinationRealm=servingPgwRealm, 
                            domain=servingPgwRealm
                            )

                        self.database.Update_Serving_APN(imsi=imsi, apn=apnKey, pcrf_session_id=None, serving_pgw=None, subscriber_routing='')
            
            return True
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [deregisterIms] Error deregistering subscriber from IMS: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return False

    def deregisterIms(self, imsi=None, msisdn=None) -> bool:
        """
        Revokes a given UE's IMS registration, and sends a RTR to the SCSCF (if defined).
        Does not revoke the pgw session, or notify the mme.
        """
        try:
            if imsi is None and msisdn is None:
                return False

            if imsi is not None:
                imsSubscriberDetails = self.database.Get_Subscriber(imsi=imsi)
            if msisdn is not None:
                imsSubscriberDetails = self.database.Get_Subscriber(msisdn=msisdn)
        
            if imsSubscriberDetails is None:
                return False
            
            servingScscf = imsSubscriberDetails.get('scscf', None)
            servingScscfPeer = imsSubscriberDetails.get('scscf_peer', None)
            servingScscfRealm = imsSubscriberDetails.get('scscf_realm', None)

            if servingScscfPeer is not None and servingScscfRealm is not None and servingScscf is not None:
                if ';' in servingScscfPeer:
                    servingScscfPeer = servingScscfPeer.split(';')[0]
                servingScscf = servingScscf.replace('sip:', '')
                if ';' in servingScscf:
                    servingScscf = servingScscf.split(';')[0]
                self.sendDiameterRequest(
                requestType='RTR',
                peerType=servingScscfPeer,
                imsi=imsi,
                destinationHost=servingScscf, 
                destinationRealm=servingScscfRealm, 
                domain=servingScscfRealm
                )

            if imsi is not None:
                self.database.Update_Serving_CSCF(imsi=imsi, serving_cscf=None)
            elif msisdn is not None:
                self.database.Update_Serving_CSCF(msisdn=msisdn, serving_cscf=None)
            
            return True
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [deregisterIms] Error deregistering subscriber from IMS: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return False

    def validateOutboundRoamingNetwork(self, assignedRoamingRules: str, mcc: str, mnc: str) -> bool:
        """
        Ensures that a given PLMN is allowed for outbound roaming.
        Checks if a subscriber has any assigned roaming rules for the given network, and validates the network accordingly.
        If the subscriber doesn't have any roaming rules applied, the network roaming rule is applied as a rule of last resort.
        """

        allowUndefinedNetworks = config.get('roaming', {}).get('outbound', {}).get('allow_undefined_networks', True)
        roamingRules = self.database.GetAll(ROAMING_RULE)
        subscriberRoamingRules = []
        if assignedRoamingRules:
            subscriberRoamingRules = assignedRoamingRules.split(',')
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Got Subscriber Roaming Rules: {subscriberRoamingRules}", redisClient=self.redisMessaging)

        """
        Iterate over every roaming rule, and it's reference roaming network.
        If the network that it refers to matches the supplied mcc and mnc to this function,
        then apply the rule action (allow/deny).
        """

        for subscriberRoamingRule in subscriberRoamingRules:
            for roamingRule in roamingRules:
                if str(roamingRule.get('roaming_rule_id')) != str(subscriberRoamingRule):
                    continue
                roamingNetworkId = roamingRule.get('roaming_network_id')
                roamingNetwork = self.database.GetObj(ROAMING_NETWORK, roamingNetworkId)
                allowNetwork = roamingRule.get('allow', True)
                if roamingNetwork:
                    if str(roamingNetwork.get('mcc')) == str(mcc) and str(roamingNetwork.get('mnc')) == str(mnc):
                        if allowNetwork:
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Subscriber Roaming Rule for PLMN: {mcc}{mnc} is Allowed", redisClient=self.redisMessaging)
                            return True
                        else:
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Subscriber Roaming Rule for PLMN: {mcc}{mnc} is Not Allowed", redisClient=self.redisMessaging)
                            return False

        """
        Iterate over every roaming rule, and it's reference roaming network.
        If the network that it refers to matches the supplied mcc and mnc to this function,
        then apply the rule action (allow/deny).
        This acts as a blanket roaming rule if we haven't matched on the subscriber-specific rule.
        """

        for roamingRule in roamingRules:
            roamingNetworkId = roamingRule.get('roaming_network_id')
            roamingNetwork = self.database.GetObj(ROAMING_NETWORK, roamingNetworkId)
            allowNetwork = roamingRule.get('allow', True)
            if roamingNetwork:
                if str(roamingNetwork.get('mcc')) == str(mcc) and str(roamingNetwork.get('mnc')) == str(mnc):
                    if allowNetwork:
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Fallback Roaming Rule for PLMN: {mcc}{mnc} is Allowed", redisClient=self.redisMessaging)
                        return True
                    else:
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Fallback Subscriber Roaming Rule for PLMN: {mcc}{mnc} is Not Allowed", redisClient=self.redisMessaging)
                        return False

        """
        By this point we haven't matched on any rules.
        If we're allowing undefined networks,
        return True, otherwise return False.
        """
        if allowUndefinedNetworks:
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Unknown Network Roaming Rule for PLMN: {mcc}{mnc} is Allowed", redisClient=self.redisMessaging)
            return True
        else:
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [validateOutboundRoamingNetwork] Unknown Network Roaming Rule for PLMN: {mcc}{mnc} is Not Allowed", redisClient=self.redisMessaging)
            return False

    def validateSubscriberRoaming(self, subscriber: dict, mcc: str, mnc: str) -> bool:
        """
        Ensures that a given subscriber is allowed to roam to the provided PLMN.
        Checks if a subscriber has roaming_enabled set in the subscriber object, and then evaluates the assigned roaming rules (if any).
        """

        roamingEnabled = subscriber.get('roaming_enabled', True)
        if roamingEnabled is not None:
            if not roamingEnabled:
                return False
        
        assignedRoamingRules = subscriber.get('roaming_rule_list', "")

        outboundNetworkAllowed = self.validateOutboundRoamingNetwork(assignedRoamingRules=assignedRoamingRules, mcc=mcc, mnc=mnc)
        if not outboundNetworkAllowed:
            return False
        
        return True

    def AVP_278_Origin_State_Incriment(self, avps):                                               #Capabilities Exchange Answer incriment AVP body
        for avp_dicts in avps:
            if avp_dicts['avp_code'] == 278:
                origin_state_incriment_int = int(avp_dicts['misc_data'], 16)
                origin_state_incriment_int = origin_state_incriment_int + 1
                origin_state_incriment_hex = format(origin_state_incriment_int,"x").zfill(8)
                return origin_state_incriment_hex

    def Match_SDP(self, regexPattern, sdpBody):
        """
        Matches a given regex in a given SDP body.
        Returns the result, or and empty string if not found.
        """

        try:
            sdpMatch = re.search(regexPattern, sdpBody, re.MULTILINE)
            if sdpMatch:
                sdpResult = sdpMatch.group(1)
                if sdpResult:
                    return str(sdpResult)
            return ''
        except Exception as e:
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Match_SDP] Error matching SDP: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def Charging_Rule_Generator(self, ChargingRules=None, ue_ip=None, chargingRuleName=None, action="install"):
        self.logTool.log(service='HSS', level='debug', message=f"Called Charging_Rule_Generator with action: {action}", redisClient=self.redisMessaging)
        if action not in ['install', 'remove']:
            self.logTool.log(service='HSS', level='debug', message="Invalid action supplied to Charging_Rule_Generator", redisClient=self.redisMessaging)
            return None
        
        if action == 'remove':
            if chargingRuleName is None:
                self.logTool.log(service='HSS', level='error', message="chargingRuleName must be defined when removing a charging rule", redisClient=self.redisMessaging)
                return None
            Charging_Rule_Name = self.generate_vendor_avp(1005, "c0", 10415, str(binascii.hexlify(str.encode(str(chargingRuleName))),'ascii'))
            ChargingRuleDef = Charging_Rule_Name
            return self.generate_vendor_avp(1002, "c0", 10415, ChargingRuleDef)
        
        else:
            if ChargingRules is None or ue_ip is None:
                self.logTool.log(service='HSS', level='error', message="ChargingRules and ue_ip must be defined when installing a charging rule", redisClient=self.redisMessaging)
                return None

            #Install Charging Rules
            self.logTool.log(service='HSS', level='debug', message="Naming Charging Rule", redisClient=self.redisMessaging)
            Charging_Rule_Name = self.generate_vendor_avp(1005, "c0", 10415, str(binascii.hexlify(str.encode(str(ChargingRules['rule_name']))),'ascii'))
            self.logTool.log(service='HSS', level='debug', message="Named Charging Rule", redisClient=self.redisMessaging)

            #Populate all Flow Information AVPs
            Flow_Information = ''
            for tft in ChargingRules['tft']:
                self.logTool.log(service='HSS', level='debug', message="Adding TFT: " + str(tft), redisClient=self.redisMessaging)
                #If {{ UE_IP }} in TFT splice in the real UE IP Value
                try:
                    tft['tft_string'] = tft['tft_string'].replace('{{ UE_IP }}', str(ue_ip))
                    tft['tft_string'] = tft['tft_string'].replace('{{UE_IP}}', str(ue_ip))
                    self.logTool.log(service='HSS', level='debug', message="Spliced in UE IP into TFT: " + str(tft['tft_string']), redisClient=self.redisMessaging)
                except Exception as E:
                    self.logTool.log(service='HSS', level='error', message="Failed to splice in UE IP into flow description", redisClient=self.redisMessaging)
                
                #Valid Values for Flow_Direction: 0- Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bidirectional
                Flow_Direction = self.generate_vendor_avp(1080, "80", 10415, self.int_to_hex(tft['direction'], 4))
                Flow_Description = self.generate_vendor_avp(507, "c0", 10415, str(binascii.hexlify(str.encode(tft['tft_string'])),'ascii'))
                Flow_Information += self.generate_vendor_avp(1058, "80", 10415, Flow_Direction + Flow_Description)

            Flow_Status = self.generate_vendor_avp(511, "c0", 10415, self.int_to_hex(2, 4))
            self.logTool.log(service='HSS', level='debug', message="Defined Flow_Status: " + str(Flow_Status), redisClient=self.redisMessaging)

            self.logTool.log(service='HSS', level='debug', message="Defining QoS information", redisClient=self.redisMessaging)
            #QCI 
            QCI = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(ChargingRules['qci'], 4))

            #ARP
            self.logTool.log(service='HSS', level='debug', message="Defining ARP information", redisClient=self.redisMessaging)
            AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(ChargingRules['arp_priority']), 4))
            AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not ChargingRules['arp_preemption_capability']), 4))
            AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not ChargingRules['arp_preemption_vulnerability']), 4))
            ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)

            self.logTool.log(service='HSS', level='debug', message="Defining MBR information", redisClient=self.redisMessaging)
            #Max Requested Bandwidth
            Bandwidth_info = ''
            Bandwidth_info += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_ul']), 4))
            Bandwidth_info += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_dl']), 4))

            self.logTool.log(service='HSS', level='debug', message="Defining GBR information", redisClient=self.redisMessaging)
            #GBR values are only valid for QCI 1 to 4
            if int(ChargingRules['qci']) <= 4:
                if int(ChargingRules['gbr_ul']) != 0:
                    Bandwidth_info += self.generate_vendor_avp(1026, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_ul']), 4))
                if int(ChargingRules['gbr_dl']) != 0:
                    Bandwidth_info += self.generate_vendor_avp(1025, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_dl']), 4))
            self.logTool.log(service='HSS', level='debug', message="Defined Bandwith Info: " + str(Bandwidth_info), redisClient=self.redisMessaging)

            #Populate QoS Information
            QoS_Information = self.generate_vendor_avp(1016, "c0", 10415, QCI + ARP + Bandwidth_info)
            self.logTool.log(service='HSS', level='debug', message="Defined QoS_Information: " + str(QoS_Information), redisClient=self.redisMessaging)
            
            #Precedence
            self.logTool.log(service='HSS', level='debug', message="Defining Precedence information", redisClient=self.redisMessaging)
            if ChargingRules['precedence'] != None:
                Precedence = self.generate_vendor_avp(1010, "c0", 10415, self.int_to_hex(ChargingRules['precedence'], 4))
            else:
                Precedence = self.generate_vendor_avp(1010, "c0", 10415, self.int_to_hex(0, 4))
            self.logTool.log(service='HSS', level='debug', message="Defined Precedence " + str(Precedence), redisClient=self.redisMessaging)

            #Rating Group
            self.logTool.log(service='HSS', level='debug', message="Defining Rating Group information", redisClient=self.redisMessaging)
            if ChargingRules['rating_group'] != None:
                RatingGroup = self.generate_avp(432, 40, format(int(ChargingRules['rating_group']),"x").zfill(8))                   #Rating-Group-ID
            else:
                RatingGroup = ''
            self.logTool.log(service='HSS', level='debug', message="Defined Rating Group " + str(ChargingRules['rating_group']), redisClient=self.redisMessaging)
            

            #Complete Charging Rule Defintion
            self.logTool.log(service='HSS', level='debug', message="Collating ChargingRuleDef", redisClient=self.redisMessaging)
            ChargingRuleDef = Charging_Rule_Name + Flow_Information + Flow_Status + QoS_Information + Precedence + RatingGroup
            ChargingRuleDef = self.generate_vendor_avp(1003, "c0", 10415, ChargingRuleDef)

            #Charging Rule Install
            self.logTool.log(service='HSS', level='debug', message="Collating ChargingRuleDef", redisClient=self.redisMessaging)
            return self.generate_vendor_avp(1001, "c0", 10415, ChargingRuleDef)

    def Get_IMS_Subscriber_Details_from_AVP(self, username):
        #Feed the Username AVP with Tel URI, SIP URI and either MSISDN or IMSI and this returns user data
        username = binascii.unhexlify(username).decode('utf-8')
        self.logTool.log(service='HSS', level='debug', message="Username AVP is present, value is " + str(username), redisClient=self.redisMessaging)
        #Strip scheme, URI parameters and domain, leaving the bare IMSI or MSISDN
        username = self.getPublicIdentityDigits(username)
        #Determine if dealing with IMSI or MSISDN
        if (len(username) == 15) or (len(username) == 16):
            self.logTool.log(service='HSS', level='debug', message="We have an IMSI: " + str(username), redisClient=self.redisMessaging)
            ims_subscriber_details = self.database.Get_IMS_Subscriber(imsi=username)
        else:
            self.logTool.log(service='HSS', level='debug', message="We have an msisdn: " + str(username), redisClient=self.redisMessaging)
            if username[0] == '+':
                username = username[1:]
            ims_subscriber_details = self.database.Get_IMS_Subscriber(msisdn=username)
        self.logTool.log(service='HSS', level='debug', message="Got subscriber details: " + str(ims_subscriber_details), redisClient=self.redisMessaging)
        return ims_subscriber_details

    def clear_expired_emergency_subscribers(self) -> bool:
        """
        Clears expired emergency subscribers from the database.
        """
        try:
            emergency_subscribers = self.database.GetAll(EMERGENCY_SUBSCRIBER)
            for emergency_subscriber in emergency_subscribers:
                try:
                    created_timestamp = emergency_subscriber.get('serving_pgw_timestamp', None)
                    emergency_subscriber_id = emergency_subscriber.get('emergency_subscriber_id', 0)
                    if created_timestamp == None:
                        created_timestamp = emergency_subscriber.get('serving_pcscf_timestamp', None)
                    if created_timestamp == None:
                        self.logTool.log(service='HSS', level='warning', message=f"serving_pgw_timestamp and serving_pcscf_timestamp missing from emergency subscriber, removing from database.", redisClient=self.redisMessaging)
                        emergency_subscribers = self.database.Delete_Emergency_Subscriber(emergencySubscriberId=emergency_subscriber_id)
                        continue
                    current_timestamp = int(time.time())
                    expiry_time_in_seconds = int(self.emergency_subscriber_expiry * 60)
                    if (current_timestamp - int(created_timestamp)) > expiry_time_in_seconds:
                        self.logTool.log(service='HSS', level='info', message=f"Emergency subscriber {emergency_subscriber.get('imsi', 'unknown_imsi')} has expired, removing from database.", redisClient=self.redisMessaging)
                        emergency_subscribers = self.database.Delete_Emergency_Subscriber(emergencySubscriberId=emergency_subscriber_id)
                except:
                    self.logTool.log(service='HSS', level='error', message=f"Error clearing expired emergency subscriber: {traceback.format_exc()}", redisClient=self.redisMessaging)
                    continue
            return True
        except:
            self.logTool.log(service='HSS', level='error', message=f"Error clearing expired emergency subscribers: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return False

    def Generate_Prom_Stats(self):
        self.logTool.log(service='HSS', level='debug', message="Called Generate_Prom_Stats", redisClient=self.redisMessaging)
        try:
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_ims_subs',
                                            metricType='gauge', metricAction='set', 
                                            metricValue=len(self.database.Get_Served_IMS_Subscribers(get_local_users_only=True)), metricHelp='Number of attached IMS Subscribers',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_mme_subs',
                                            metricType='gauge', metricAction='set', 
                                            metricValue=len(self.database.Get_Served_Subscribers(get_local_users_only=True)), metricHelp='Number of attached MME Subscribers',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_pcrf_subs',
                                            metricType='gauge', metricAction='set', 
                                            metricValue=len(self.database.Get_Served_PCRF_Subscribers(get_local_users_only=True)), metricHelp='Number of attached PCRF Subscribers',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
        except Exception as e:
            self.logTool.log(service='HSS', level='debug', message="Failed to generate Prometheus Stats for IMS Subscribers", redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=e, redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='debug', message="Generated Prometheus Stats for IMS Subscribers", redisClient=self.redisMessaging)

        return


    #### Diameter Answers ####

    #Capabilities Exchange Answer
    def Answer_257(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))        #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        for host in config['hss']['bind_ip']:                                                  #Loop through all IPs from Config and add to response
            avp += self.generate_avp(257, 40, self.ip_to_hex(host))                                 #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                               #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                       #Product-Name

        avp += self.generate_avp(267, "00", "000027d9")                                               #Firmware-Revision
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777252),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S13)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777291),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLh)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)       
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777236),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Rx)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777238),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))                            #Auth-Application-ID - Diameter Gx
        avp += self.generate_avp(258, 40, format(int(10),"x").zfill(8))                                  #Auth-Application-ID - Diameter CER
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                                #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)

        try:
            external_socket_service_enabled = config.get('hss', {}).get('use_external_socket_service', False)
            if external_socket_service_enabled == True:
                originHost = binascii.unhexlify(self.get_avp_data(avps, 264)[0]).decode()
                originRealm = binascii.unhexlify(self.get_avp_data(avps, 296)[0]).decode()
                hostIpAddressAvp = self.get_avp_data(avps, 257)[0]
                originHostIp = self.hex_to_ip(hostIpAddressAvp[4:])
                try:
                    productName = binascii.unhexlify(self.get_avp_data(avps, 269)[0]).decode()
                except:
                    productName = ""
                try:
                    vendorId = int(self.get_avp_data(avps, 266)[0], 16)
                except:
                    vendorId = ""
                try:
                    vsai = self.get_avp_data(avps, 260)[0]
                except:
                    vsai = ""

                metadata = {"Host": originHost,
                            "Realm": originRealm,
                            "ProductName": productName,
                            "VendorId": vendorId,
                            "CeaReceived": True,
                            "AuthorizedApplicationIds": vsai}

                peer = {"Hostname": originHost,
                        "PeerType": self.getPeerType(originHost),
                        "Metadata": json.dumps(metadata)
                        }
            
                self.update_stored_peer(peerKey=originHostIp, peer=peer)
        except Exception as e:
            self.logTool.log(service='HSS', level='warning', message=f"Error updating stored peer: {traceback.format_exc()}", redisClient=self.redisMessaging)

        response = self.generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet       
        self.logTool.log(service='HSS', level='debug', message="Successfully Generated CEA", redisClient=self.redisMessaging)
        return response

    #Device Watchdog Answer                                                 
    def Answer_280(self, packet_vars, avps): 
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:                                
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        response = self.generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet      
        self.logTool.log(service='HSS', level='debug', message="Successfully Generated DWA", redisClient=self.redisMessaging)
        return response

    #Disconnect Peer Answer    
    def Answer_282(self, packet_vars, avps):                                                      
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCCESS (2001))
        response = self.generate_diameter_packet("01", "00", 282, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
        self.logTool.log(service='HSS', level='debug', message="Successfully Generated DPA", redisClient=self.redisMessaging)
        return response

    #3GPP S6a/S6d Update Location Answer
    def Answer_16777251_316(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))   #Auth-Application-ID Relay
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)                                  #AVP: Auth-Application-Id(258) l=12 f=-M- val=3GPP S6a/S6d (16777251)  

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP

        #APNs from DB
        APN_Configuration = ''
        imsi = self.get_avp_data(avps, 1)[0]                                                            #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')                                                  #Convert IMSI
        try:
            subscriber_details = self.database.Get_Subscriber(imsi=imsi, get_attributes=True)
            self.logTool.log(service='HSS', level='debug', message="Got back subscriber_details: " + str(subscriber_details), redisClient=self.redisMessaging)

            if subscriber_details['enabled'] == 0:
                self.logTool.log(service='HSS', level='debug', message=f"Subscriber {imsi} is disabled", redisClient=self.redisMessaging)

                #Experimental Result AVP(Response Code for Failure)
                avp_experimental_result = ''
                avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
                avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5001, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001)
                avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
                
                avp += self.generate_avp(277, 40, "00000001")                                                   #Auth-Session-State
                self.logTool.log(service='HSS', level='debug', message=f"Successfully Generated ULA for disabled Subscriber: {imsi}", redisClient=self.redisMessaging)
                response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)
                return response

            rat_type_checker = SubscriberRATRestriction(logger=self.logTool, service="HSS")
            if not rat_type_checker.is_rat_allowed(subscriber_details["attributes"], RAT.EUTRAN):
                self.logTool.log(service='HSS', level='debug', message=f"Subscriber {imsi} is not allowed on EUTRAN RAT",
                                 redisClient=self.redisMessaging)

                # Experimental Result AVP(Response Code for Failure)
                avp_experimental_result = ''
                avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')  # AVP Vendor ID
                avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5421, 4))  # AVP Experimental-Result-Code: DIAMETER_ERROR_RAT_NOT_ALLOWED (5421)
                avp += self.generate_avp(297, 40, avp_experimental_result)  # AVP Experimental-Result(297)

                avp += self.generate_avp(277, 40, "00000001")  # Auth-Session-State
                self.logTool.log(service='HSS', level='debug',
                                 message=f"Successfully Generated ULA for disabled Subscriber: {imsi}",
                                 redisClient=self.redisMessaging)
                response = self.generate_diameter_packet("01", "40", 316, 16777251,
                                                         packet_vars['hop-by-hop-identifier'],
                                                         packet_vars['end-to-end-identifier'], avp)
                return response

        except ValueError as e:
            self.logTool.log(service='HSS', level='debug', message="failed to get data backfrom database for imsi " + str(imsi), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Error is " + str(e), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Responding with DIAMETER_ERROR_USER_UNKNOWN", redisClient=self.redisMessaging)
            avp += self.generate_avp(268, 40, self.int_to_hex(5030, 4))
            response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            self.logTool.log(service='HSS', level='debug', message="Diameter user unknown - Sending ULA with DIAMETER_ERROR_USER_UNKNOWN", redisClient=self.redisMessaging)
            return response
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            raise

        try:
            plmn = self.get_avp_data(avps, 1407)[0]                                                          #Visited-PLMN-ID
            decodedPlmn = self.DecodePLMN(plmn=plmn)
            mcc = decodedPlmn[0]
            mnc = decodedPlmn[1]
            subscriberIsRoaming = False
            subscriberRoamingAllowed = False 
            if str(mcc) != str(self.MCC) and str(mnc) != str(self.MNC):
                subscriberIsRoaming = True
            
            if subscriberIsRoaming:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777251_318] [ULA] Subscriber {imsi} is roaming", redisClient=self.redisMessaging)
                subscriberRoamingAllowed = self.validateSubscriberRoaming(subscriber=subscriber_details, mcc=mcc, mnc=mnc)

            if not subscriberRoamingAllowed and subscriberIsRoaming:
                avp = ''
                session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
                avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
                avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
                avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

                #Experimental Result AVP(Parent AVP for Roaming Failure)
                avp_experimental_result = ''
                avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
                avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5004, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004)
                avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
                
                avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
                avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
                response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                return response
            
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777251_318] [AIA] Subscriber {imsi} passed roaming validation for {decodedPlmn}", redisClient=self.redisMessaging)
            
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777251_318] [AIA] Error when validating subscriber roaming: {traceback.format_exc()}", redisClient=self.redisMessaging)

        #Store MME Location into Database
        OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
        OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it
        OriginRealm = self.get_avp_data(avps, 296)[0]                          #Get OriginRealm from AVP
        OriginRealm = binascii.unhexlify(OriginRealm).decode('utf-8')      #Format it
        self.logTool.log(service='HSS', level='debug', message="Subscriber is served by MME " + str(OriginHost) + " at realm " + str(OriginRealm), redisClient=self.redisMessaging)

        #Find Remote Peer we need to address CLRs through
        try:        #Check if we have a record-route set as that's where we'll need to send the response
            remote_peer = self.get_avp_data(avps, 282)[-1]                          #Get first record-route header
            remote_peer = binascii.unhexlify(remote_peer).decode('utf-8')           #Format it
        except:     #If we don't have a record-route set, we'll send the response to the OriginHost
            remote_peer = OriginHost
        remote_peer = remote_peer + ";" + str(config['hss']['OriginHost'])
        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777251_316] [ULA] Remote Peer is " + str(remote_peer), redisClient=self.redisMessaging)

        self.database.Update_Serving_MME(imsi=imsi, serving_mme=OriginHost, serving_mme_peer=remote_peer, serving_mme_realm=OriginRealm)

        #Boilerplate AVPs
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State    
        avp += self.generate_vendor_avp(1406, "c0", 10415, "00000001")                                   #ULA Flags

        #Subscription Data: 
        subscription_data = ''
        subscription_data += self.generate_vendor_avp(1426, "c0", 10415, "00000000")                     #Access Restriction Data
        subscription_data += self.generate_vendor_avp(1424, "c0", 10415, "00000000")                     #Subscriber-Status (SERVICE_GRANTED)
        subscription_data += self.generate_vendor_avp(1417, "c0", 10415, self.int_to_hex(int(subscriber_details['nam']), 4))                     #Network-Access-Mode (PACKET_AND_CIRCUIT)

        #AMBR is a sub-AVP of Subscription Data
        AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        ue_ambr_ul = int(subscriber_details['ue_ambr_ul'])
        ue_ambr_dl = int(subscriber_details['ue_ambr_dl'])
        AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
        AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
        subscription_data += self.generate_vendor_avp(1435, "c0", 10415, AMBR)                           #Add AMBR AVP in two sub-AVPs


        subscription_data += self.generate_vendor_avp(1619, "80", 10415, self.int_to_hex(int(subscriber_details['subscribed_rau_tau_timer']), 4))                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)


        #APN Configuration Profile is a sub AVP of Subscription Data
        APN_Configuration_Profile = ''
        APN_Configuration_Profile += self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))     #Context Identifier for default APN (First APN is default in our case)
        APN_Configuration_Profile += self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4))     #All-APN-Configurations-Included-Indicator

        #Split the APN list into a list
        apn_list = subscriber_details['apn_list'].split(',')
        self.logTool.log(service='HSS', level='debug', message="Current APN List: " + str(apn_list), redisClient=self.redisMessaging)
        #Remove the default APN from the list
        try:
            apn_list.remove(str(subscriber_details['default_apn']))
        except:
            self.logTool.log(service='HSS', level='debug', message="Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List", redisClient=self.redisMessaging)
            pass
        #Add default APN in first position
        apn_list.insert(0, str(subscriber_details['default_apn']))

        self.logTool.log(service='HSS', level='debug', message="APN list: " + str(apn_list), redisClient=self.redisMessaging)
        APN_context_identifer_count = 1
        for apn_id in apn_list:
            #Per APN Setup
            self.logTool.log(service='HSS', level='debug', message="Processing APN ID " + str(apn_id), redisClient=self.redisMessaging)
            try:
                apn_data = self.database.Get_APN(apn_id)
            except:
                self.logTool.log(service='HSS', level='error', message="Failed to get APN " + str(apn_id), redisClient=self.redisMessaging)
                continue
            APN_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex(str(apn_data['apn'])))

            self.logTool.log(service='HSS', level='debug', message="Setting APN Configuration Profile", redisClient=self.redisMessaging)
            #Sub AVPs of APN Configuration Profile
            APN_context_identifer = self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(APN_context_identifer_count, 4))
            APN_PDN_type = self.generate_vendor_avp(1456, "c0", 10415, self.int_to_hex(int(apn_data['ip_version']), 4))
            NIDD_Parameters = ''
            
            try:
                nbIotEnabled = apn_data.get('nbiot', False)
                #If int(apn_data['ip_version']) == 4 (Non-IP) then this is NB-IoT and we need to add the NB-IoT specific parameters
                if nbIotEnabled and int(apn_data['ip_version']) == 4:
    
                    #Add Non-IP-PDN-Type-Indicator
                    NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(1681, "c0", 10415, self.int_to_hex(1, 4))
    
                    #Add SCEF ID
                    try:
                        NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(3125, "c0", 10415, self.string_to_hex(str(apn_data['nidd_scef_id'])))
                    except: 
                        pass
    
                    #Add SCEF Realm
                    try:
                        #Check SCEF Realm is not empty
                        if apn_data['nidd_scef_realm'] != '':
                            NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(1684, "c0", 10415, self.string_to_hex(str(apn_data['nidd_scef_realm'])))
                    except:
                        pass
    
                    #Add Reliable Data Indicator
                    try:
                        NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(1697, "c0", 10415, self.int_to_hex(int(apn_data['nidd_rds']), 4))
                    except:
                        pass
    
                    #Add Preferred Data Mode
                    try:
                        NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(1686, "c0", 10415, self.int_to_hex(int(apn_data['nidd_preferred_data_mode']), 4))
                    except:
                        pass
    
                    #Add Non-IP-Data-Delivery-Mechanism
                    try:
                        NIDD_Parameters = NIDD_Parameters + self.generate_vendor_avp(1682, "c0", 10415, self.int_to_hex(int(apn_data['nidd_mechanism']), 4))
                    except:
                        pass
    
                else:
                    NIDD_Parameters = ''
                    
            except Exception as e:
                self.logTool.log(service='HSS', level='error', message=f"Error preparing NIDD parameters: {traceback.format_exc()}", redisClient=self.redisMessaging)

            self.logTool.log(service='HSS', level='debug', message="Setting APN AMBR", redisClient=self.redisMessaging)
            #AMBR
            AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
            apn_ambr_ul = int(apn_data['apn_ambr_ul'])
            apn_ambr_dl = int(apn_data['apn_ambr_dl'])
            AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
            AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
            APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

            self.logTool.log(service='HSS', level='debug', message="Setting APN Allocation-Retention-Priority", redisClient=self.redisMessaging)
            #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
            AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_data['arp_priority']), 4))
            AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_capability']), 4))
            AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_vulnerability']), 4))
            AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
            AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_data['qci']), 4))
            APN_EPS_Subscribed_QoS_Profile = self.generate_vendor_avp(1431, "c0", 10415, AVP_QoS + AVP_ARP)

            #Try static IP allocation
            try:
                subscriber_routing_dict = self.database.Get_SUBSCRIBER_ROUTING(subscriber_id=subscriber_details['subscriber_id'], apn_id=apn_id)                                               #Get subscriber details
                self.logTool.log(service='HSS', level='debug', message="Got static UE IP " + str(subscriber_routing_dict), redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="Found static IP for UE " + str(subscriber_routing_dict['ip_address']), redisClient=self.redisMessaging)
                Served_Party_Address = self.generate_vendor_avp(848, "c0", 10415, self.ip_to_hex(subscriber_routing_dict['ip_address']))
            except Exception as E:
                self.logTool.log(service='HSS', level='debug', message="No static UE IP found: " + str(E), redisClient=self.redisMessaging)
                Served_Party_Address = ""


            #if 'PDN_GW_Allocation_Type' in apn_profile:
            #     self.logTool.log(service='HSS', level='info', message="PDN_GW_Allocation_Type present, value " + str(apn_profile['PDN_GW_Allocation_Type']), redisClient=self.redisMessaging)
            #     PDN_GW_Allocation_Type = self.generate_vendor_avp(1438, 'c0', 10415, self.int_to_hex(int(apn_profile['PDN_GW_Allocation_Type']), 4))
            #     self.logTool.log(service='HSS', level='info', message="PDN_GW_Allocation_Type value is " + str(PDN_GW_Allocation_Type), redisClient=self.redisMessaging)
            # else:
            #     PDN_GW_Allocation_Type = ''
            # if 'VPLMN_Dynamic_Address_Allowed' in apn_profile:
            #     self.logTool.log(service='HSS', level='info', message="VPLMN_Dynamic_Address_Allowed present, value " + str(apn_profile['VPLMN_Dynamic_Address_Allowed']), redisClient=self.redisMessaging)
            #     VPLMN_Dynamic_Address_Allowed = self.generate_vendor_avp(1432, 'c0', 10415, self.int_to_hex(int(apn_profile['VPLMN_Dynamic_Address_Allowed']), 4))
            #     self.logTool.log(service='HSS', level='info', message="VPLMN_Dynamic_Address_Allowed value is " + str(VPLMN_Dynamic_Address_Allowed), redisClient=self.redisMessaging)
            # else:
            #     VPLMN_Dynamic_Address_Allowed = ''            
            PDN_GW_Allocation_Type = ''
            VPLMN_Dynamic_Address_Allowed = ''

            #If static SMF / PGW-C defined
            if apn_data['pgw_address'] is not None:
                self.logTool.log(service='HSS', level='debug', message="MIP6-Agent-Info present (Static SMF/PGW-C), value " + str(apn_data['pgw_address']), redisClient=self.redisMessaging)
                MIP_Home_Agent_Address = self.generate_avp(334, '40', self.ip_to_hex(apn_data['pgw_address']))
                MIP6_Agent_Info = self.generate_avp(486, '40', MIP_Home_Agent_Address)
            else:
                MIP6_Agent_Info = ''

            APN_Configuration_AVPS = APN_context_identifer + APN_PDN_type + APN_AMBR + APN_Service_Selection \
                + APN_EPS_Subscribed_QoS_Profile + Served_Party_Address + MIP6_Agent_Info + PDN_GW_Allocation_Type + VPLMN_Dynamic_Address_Allowed + NIDD_Parameters
            
            APN_Configuration += self.generate_vendor_avp(1430, "c0", 10415, APN_Configuration_AVPS)
            
            #Incriment Context Identifier Count to keep track of how many APN Profiles returned
            APN_context_identifer_count = APN_context_identifer_count + 1  
            self.logTool.log(service='HSS', level='debug', message="Completed processing APN ID " + str(apn_id), redisClient=self.redisMessaging)
        
        subscription_data += self.generate_vendor_avp(1429, "c0", 10415, APN_Configuration_Profile + APN_Configuration)

        try:
            if subscriber_details.get('msisdn'):
                self.logTool.log(service='HSS', level='debug', message="MSISDN is " + str(subscriber_details['msisdn']) + " - adding in ULA", redisClient=self.redisMessaging)
                msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(subscriber_details['msisdn'])))                     #MSISDN
                self.logTool.log(service='HSS', level='debug', message=msisdn_avp, redisClient=self.redisMessaging)
                subscription_data += msisdn_avp
            else:
                self.logTool.log(service='HSS', level='debug', message="Subscriber has no MSISDN, not adding MSISDN AVP in ULA", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='HSS', level='error', message="Failed to populate MSISDN in ULA due to error " + str(E), redisClient=self.redisMessaging)

        if 'RAT_freq_priorityID' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="RAT_freq_priorityID is " + str(subscriber_details['RAT_freq_priorityID']) + " - Adding in ULA", redisClient=self.redisMessaging)
            rat_freq_priorityID = self.generate_vendor_avp(1440, "C0", 10415, self.int_to_hex(int(subscriber_details['RAT_freq_priorityID']), 4))                              #RAT-Frequency-Selection-Priority ID
            self.logTool.log(service='HSS', level='debug', message="Adding rat_freq_priorityID: " + str(rat_freq_priorityID), redisClient=self.redisMessaging)
            subscription_data += rat_freq_priorityID

        if 'charging_characteristics' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="3gpp-charging-characteristics " + str(subscriber_details['charging_characteristics']) + " - Adding in ULA", redisClient=self.redisMessaging)
            _3gpp_charging_characteristics = self.generate_vendor_avp(13, "80", 10415, str(subscriber_details['charging_characteristics']))
            subscription_data += _3gpp_charging_characteristics
            self.logTool.log(service='HSS', level='debug', message="Adding _3gpp_charging_characteristics: " + str(_3gpp_charging_characteristics), redisClient=self.redisMessaging)

        #ToDo - Fix this  
        # if 'APN_OI_replacement' in subscriber_details:
        #     self.logTool.log(service='HSS', level='debug', message="APN_OI_replacement " + str(subscriber_details['APN_OI_replacement']) + " - Adding in ULA", redisClient=self.redisMessaging)
        #     subscription_data += self.generate_vendor_avp(1427, "C0", 10415, self.string_to_hex(str(subscriber_details['APN_OI_replacement'])))

        avp += self.generate_vendor_avp(1400, "c0", 10415, subscription_data)                            #Subscription-Data

        # Send DSR to Old MME if enabled
        if self.sendDsrOnMmeChange == True:
            try:
                maybeServingMmePeer = subscriber_details.get('serving_mme_peer')
                if maybeServingMmePeer != None:
                    servingMmePeer = maybeServingMmePeer.split(';')[0]
                    servingMme = subscriber_details.get('serving_mme')
                    servingMmeRealm = subscriber_details.get('serving_mme_realm')
                    new_serving_mme = OriginHost
                    if len(servingMmePeer) > 0 and new_serving_mme != servingMme:
                        self.logTool.log(service='HSS', level='debug', message=f"MME Serving UE has changed from: {servingMme} to {new_serving_mme}, Sending DSR.", redisClient=self.redisMessaging)
                        self.sendDiameterRequest(
                                            requestType='DSR',
                                            hostname=servingMmePeer,
                                            imsi=imsi,
                                            DestinationHost=servingMme, 
                                            DestinationRealm=servingMmeRealm,
                                            ExternalIdentifier=self.dsrExternalIdentifier
                                            )
            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message=f"Error sending DSR: {e}", redisClient=self.redisMessaging)

        response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet

        self.logTool.log(service='HSS', level='debug', message="Successfully Generated ULA", redisClient=self.redisMessaging)
        return response

    #3GPP S6a/S6d Authentication Information Answer
    def Answer_16777251_318(self, packet_vars, avps):
        self.logTool.log(service='HSS', level='debug', message=f"AIA AVPS: {avps}", redisClient=self.redisMessaging)
        imsi = self.get_required_avp_data(avps, 1)                                                       #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')                                                  #Convert IMSI
        plmn = self.get_avp_data(avps, 1407)[0]                                                          #Get PLMN from User-Name AVP in request

        try:
            subscriber_details = self.database.Get_Subscriber(imsi=imsi)                                               #Get subscriber details
            if subscriber_details['enabled'] == 0:
                self.logTool.log(service='HSS', level='debug', message=f"Subscriber {imsi} is disabled", redisClient=self.redisMessaging)
                avp = ''
                session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
                avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
                avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
                avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                metricType='counter', metricAction='inc', 
                                metricValue=1.0, 
                                metricLabels={
                                            "diameter_application_id": 16777251,
                                            "diameter_cmd_code": 318,
                                            "event": "Disabled User",
                                            "imsi_prefix": str(imsi[0:6])},
                                metricHelp='Diameter Authentication related Counters',
                                metricExpiry=60,
                                usePrefix=True, 
                                prefixHostname=self.hostname, 
                                prefixServiceName='metric')

                #Experimental Result AVP(Response Code for Failure)
                avp_experimental_result = ''
                avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
                avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5001, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001)
                avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
                
                avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
                avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
                response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                self.logTool.log(service='HSS', level='debug', message=f"Successfully Generated AIA for disabled Subscriber: {imsi}", redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message=f"{response}", redisClient=self.redisMessaging)
                return response
        except ValueError as e:
            self.logTool.log(service='HSS', level='debug', message="Error getting subscriber details for IMSI " + str(imsi), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=e, redisClient=self.redisMessaging)
            decodedPlmn = self.DecodePLMN(plmn=plmn)
            mcc = decodedPlmn[0]
            mnc = decodedPlmn[1]
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777251,
                                                        "diameter_cmd_code": 318,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(imsi[0:6])},
                                            metricInflux={
                                                            "measurement": "S6a_Authentication_Information_Request",
                                                            "fields": {"Result-Code": 5001},
                                                            "tags": {"IMSI": str(imsi), "MCC": str(mcc), "MNC": str(mnc)},
                                                            "time": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
                                                        },
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            #Handle if the subscriber is not present in HSS return the appropriate error
            self.logTool.log(service='HSS', level='debug', message="Subscriber " + str(imsi) + " is unknown in database", redisClient=self.redisMessaging)
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

            #Experimental Result AVP(Response Code for Failure)
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(self.get_unknown_imsi_reject_cause(), 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001) or DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004)
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            
            avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
            avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
            response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            raise

        try:
            decodedPlmn = self.DecodePLMN(plmn=plmn)
            mcc = decodedPlmn[0]
            mnc = decodedPlmn[1]
            subscriberIsRoaming = False
            subscriberRoamingAllowed = False
            if str(mcc) != str(self.MCC) and str(mnc) != str(self.MNC):
                subscriberIsRoaming = True
            
            if subscriberIsRoaming:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777251_318] [AIA] Subscriber {imsi} is roaming", redisClient=self.redisMessaging)
                subscriberRoamingAllowed = self.validateSubscriberRoaming(subscriber=subscriber_details, mcc=mcc, mnc=mnc)

            if not subscriberRoamingAllowed and subscriberIsRoaming:
                avp = ''
                session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
                avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
                avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
                avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

                #Experimental Result AVP(Parent AVP for Roaming Failure)
                avp_experimental_result = ''
                avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
                avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5004, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004)
                avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
                
                avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
                avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
                response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                return response
            
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777251_318] [AIA] Subscriber {imsi} passed roaming validation for {decodedPlmn}", redisClient=self.redisMessaging)
            
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777251_318] [AIA] Error when validating subscriber roaming: {traceback.format_exc()}", redisClient=self.redisMessaging)


        try:
            requested_vectors = 1
            EUTRAN_Authentication_Info = self.get_avp_data(avps, 1408)
            self.logTool.log(service='HSS', level='debug', message=f"authInfo: {EUTRAN_Authentication_Info}", redisClient=self.redisMessaging)
            if len(EUTRAN_Authentication_Info) > 0:
                EUTRAN_Authentication_Info = EUTRAN_Authentication_Info[0]
                self.logTool.log(service='HSS', level='debug', message="AVP: Requested-EUTRAN-Authentication-Info(1408) l=44 f=VM- vnd=TGPP", redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="EUTRAN_Authentication_Info is " + str(EUTRAN_Authentication_Info), redisClient=self.redisMessaging)
                for sub_avp in EUTRAN_Authentication_Info:
                    #If resync request
                    if sub_avp['avp_code'] == 1411:
                        self.logTool.log(service='HSS', level='debug', message="Re-Synchronization required - SQN is out of sync", redisClient=self.redisMessaging)
                        self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                                        metricType='counter', metricAction='inc', 
                                                        metricValue=1.0, 
                                                        metricLabels={
                                                                    "diameter_application_id": 16777251,
                                                                    "diameter_cmd_code": 318,
                                                                    "event": "Resync",
                                                                    "imsi_prefix": str(imsi[0:6])},
                                                        metricHelp='Diameter Authentication related Counters',
                                                        metricExpiry=60,
                                                        usePrefix=True, 
                                                        prefixHostname=self.hostname, 
                                                        prefixServiceName='metric')
                        auts = str(sub_avp['misc_data'])[32:]
                        rand = str(sub_avp['misc_data'])[:32]
                        rand = binascii.unhexlify(rand)
                        #Calculate correct SQN
                        self.database.Get_Vectors_AuC(subscriber_details['auc_id'], "sqn_resync", auts=auts, rand=rand)

                    #Get number of requested vectors
                    if sub_avp['avp_code'] == 1410:
                        self.logTool.log(service='HSS', level='debug', message="Raw value of requested vectors is " + str(sub_avp['misc_data']), redisClient=self.redisMessaging)
                        requested_vectors = int(sub_avp['misc_data'], 16)
                        if requested_vectors >= 32:
                            self.logTool.log(service='HSS', level='debug', message="Client has requested " + str(requested_vectors) + " vectors, limiting this to 32", redisClient=self.redisMessaging)
                            requested_vectors = 32

            self.logTool.log(service='HSS', level='debug', message="Generating " + str(requested_vectors) + " vectors as requested", redisClient=self.redisMessaging)
            eutranvector_complete = ''
            while requested_vectors != 0:
                self.logTool.log(service='HSS', level='debug', message="Generating vector number " + str(requested_vectors), redisClient=self.redisMessaging)
                plmn = self.get_avp_data(avps, 1407)[0]                                                     #Get PLMN from request
                vector_dict = self.database.Get_Vectors_AuC(subscriber_details['auc_id'], "air", plmn=plmn)
                eutranvector = ''                                                                           #This goes into the payload of AVP 10415 (Authentication info)
                eutranvector += self.generate_vendor_avp(1419, "c0", 10415, self.int_to_hex(requested_vectors, 4))
                eutranvector += self.generate_vendor_avp(1447, "c0", 10415, vector_dict['rand'])                                #And is made up of other AVPs joined together with RAND
                eutranvector += self.generate_vendor_avp(1448, "c0", 10415, vector_dict['xres'])                                #XRes
                eutranvector += self.generate_vendor_avp(1449, "c0", 10415, vector_dict['autn'])                                #AUTN
                eutranvector += self.generate_vendor_avp(1450, "c0", 10415, vector_dict['kasme'])                               #And KASME

                requested_vectors = requested_vectors - 1
                eutranvector_complete += self.generate_vendor_avp(1414, "c0", 10415, eutranvector)                         #Put EUTRAN vectors in E-UTRAN-Vector AVP

            avp = ''                                                                                    #Initiate empty var AVP
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
            avp += self.generate_vendor_avp(1413, "c0", 10415, eutranvector_complete)                                 #Authentication-Info (3GPP)                                      
            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
            avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
            avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")
            #avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
            
            response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            self.logTool.log(service='HSS', level='debug', message="Successfully Generated AIA", redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=response, redisClient=self.redisMessaging)
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=traceback.format_exc(), redisClient=self.redisMessaging)


    #Purge UE Answer (PUA)
    def Answer_16777251_321(self, packet_vars, avps):
        
        imsi = self.get_required_avp_data(avps, 1)                                                       #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')

        avp = ''
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #1442 - PUA-Flags
        avp += self.generate_vendor_avp(1442, "c0", 10415, self.int_to_hex(1, 4))

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP


        response = self.generate_diameter_packet("01", "40", 321, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        
        if self.ignorePurgeUeRequest == False:
            self.database.Update_Serving_MME(imsi, None)
        self.logTool.log(service='HSS', level='debug', message="Successfully Generated PUA", redisClient=self.redisMessaging)
        return response

    #Notify Answer (NOA)
    def Answer_16777251_323(self, packet_vars, avps):
        avp = ''
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))   #Auth-Application-ID Relay
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP
        response = self.generate_diameter_packet("01", "40", 323, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        self.logTool.log(service='HSS', level='debug', message="Successfully Generated NOA", redisClient=self.redisMessaging)
        return response

    #3GPP Gx Credit Control Answer
    def Answer_16777238_272(self, packet_vars, avps):
        try:
            CC_Request_Type = self.get_avp_data(avps, 416)[0]
            CC_Request_Number = self.get_avp_data(avps, 415)[0]
            #Called Station ID
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Attempting to find APN in CCR", redisClient=self.redisMessaging)
            apn = bytes.fromhex(self.get_avp_data(avps, 30)[0]).decode('utf-8')
            # Strip plmn based domain from apn, if present
            try:
                if '.' in apn:
                        assert('mcc' in apn)
                        assert('mnc' in apn)
                        apn = apn.split('.')[0]
            except Exception as e:
                apn = bytes.fromhex(self.get_avp_data(avps, 30)[0]).decode('utf-8')
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] CCR for APN " + str(apn), redisClient=self.redisMessaging)

            OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
            OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it

            OriginRealm = self.get_avp_data(avps, 296)[0]                          #Get OriginRealm from AVP
            OriginRealm = binascii.unhexlify(OriginRealm).decode('utf-8')      #Format it

            try:        #Check if we have a record-route set as that's where we'll need to send the response
                remote_peer = self.get_avp_data(avps, 282)[-1]                          #Get first record-route header
                remote_peer = binascii.unhexlify(remote_peer).decode('utf-8')           #Format it
            except:     #If we don't have a record-route set, we'll send the response to the OriginHost
                remote_peer = OriginHost
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Remote Peer is " + str(remote_peer), redisClient=self.redisMessaging)
            remote_peer = remote_peer + ";" + str(config['hss']['OriginHost'])

            avp = ''                                                                                    #Initiate empty var AVP
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Session Id is " + str(binascii.unhexlify(session_id).decode()), redisClient=self.redisMessaging)
            avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
            avp += self.generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
            avp += self.generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                     #CC-Request-Type
            avp += self.generate_avp(415, 40, format(int(CC_Request_Number),"x").zfill(8))                   #CC-Request-Number

            localImsi = None
            try:
                for SubscriptionIdentifier in self.get_avp_data(avps, 443):
                    for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                        if UniqueSubscriptionIdentifier['avp_code'] == 444:
                            localImsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Got local IMSI: {localImsi}", redisClient=self.redisMessaging)
                            subscriberDetails = self.database.Get_Subscriber(imsi=localImsi)
                            if not subscriberDetails:
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Local IMSI {localImsi} not found, treating as Emergency Subscriber", redisClient=self.redisMessaging)
                                localImsi = None
            except:
                localImsi = None

            """
            If Called-Station-ID contains 'sos', we're dealing with an emergency bearer request.
            Local authentication is bypassed if the subscriber doesn't exist and we'll return a basic QOS profile.
            """
            try:
                if apn.lower() == 'sos':
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Emergency Credit Control Request (SOS APN)", redisClient=self.redisMessaging)
                    if not localImsi:
                        if int(CC_Request_Type) == 1:
                            """
                            If we've recieved a CCR-Initial, create an emergency subscriber.
                            """
                            # Use our defined SOS APN AMBR, if defined.
                            # Otherwise, use a default value of 128/128kbps.
                            try:
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Handling Emergency CCR-I", redisClient=self.redisMessaging)
                                sosApn = (self.database.Get_APN_by_Name(apn="sos"))
                                AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
                                apn_ambr_ul = int(sosApn['apn_ambr_ul'])
                                apn_ambr_dl = int(sosApn['apn_ambr_dl'])
                                AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
                                AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
                                APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

                                AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(sosApn['arp_priority']), 4))
                                AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not sosApn['arp_preemption_capability']), 4))
                                AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not sosApn['arp_preemption_vulnerability']), 4))
                                AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
                                AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(sosApn['qci']), 4))
                                avp += self.generate_vendor_avp(1049, "80", 10415, AVP_QoS + AVP_ARP)

                            except Exception as e:
                                AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
                                apn_ambr_ul = 128000
                                apn_ambr_dl = 128000
                                AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
                                AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
                                APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)
                                
                                AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(1, 4))
                                AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(0, 4))          # Pre-Emption Capability Enabled
                                AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(1, 4))       # Pre-Emption Vulnerability Disabled
                                AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
                                AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(5, 4))                            # QCI 5
                                avp += self.generate_vendor_avp(1049, "80", 10415, AVP_QoS + AVP_ARP)
                        
                            QoS_Information = self.generate_vendor_avp(1041, "80", 10415, self.int_to_hex(apn_ambr_ul, 4))                                                                  
                            QoS_Information += self.generate_vendor_avp(1040, "80", 10415, self.int_to_hex(apn_ambr_dl, 4))
                            avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)                                         # QOS-Information

                            #Supported-Features(628) (Gx feature list)
                            avp += self.generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af0000000b")

                            """
                            Store the Emergency Subscriber
                            """
                            ueIp = self.get_avp_data(avps, 8)[0]
                            ueIp = str(self.hex_to_ip(ueIp))
                            try:
                                #Get the IMSI
                                for SubscriptionIdentifier in self.get_avp_data(avps, 443):
                                    for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                                        if UniqueSubscriptionIdentifier['avp_code'] == 444:
                                            imsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')
                            except Exception as e:
                                imsi="Unknown"
                            
                            try:
                                ratType = self.get_avp_data(avps, 1032)[0]
                                ratType = int(ratType, 16)
                            except Exception as e:
                                ratType = None

                            try:
                                accessNetworkGatewayAddress = self.get_avp_data(avps, 1050)[0]
                                accessNetworkGatewayAddress = str(self.hex_to_ip(accessNetworkGatewayAddress[4:]))
                            except Exception as e:
                                accessNetworkGatewayAddress = None

                            try:
                                accessNetworkChargingAddress = self.get_avp_data(avps, 501)[0]
                                accessNetworkChargingAddress = str(self.hex_to_ip(accessNetworkChargingAddress[4:]))
                            except Exception as e:
                                accessNetworkChargingAddress = None

                            emergencySubscriberData = {
                                "servingPgw": binascii.unhexlify(session_id).decode(),
                                "requestTime": int(time.time()),
                                "servingPcscf": None,
                                "aarRequestTime": None,
                                "gxOriginRealm": OriginRealm,
                                "gxOriginHost": OriginHost,
                                "imsi": imsi,
                                "ip": ueIp,
                                "ratType": ratType,
                                "accessNetworkGatewayAddress": accessNetworkGatewayAddress,
                                "accessNetworkChargingAddress": accessNetworkChargingAddress,
                            }

                            self.database.Update_Emergency_Subscriber(subscriberIp=ueIp, subscriberData=emergencySubscriberData, imsi=imsi, gxSessionId=emergencySubscriberData.get('servingPgw'))
                            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
                            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                            return response
                        
                        elif int(CC_Request_Type) == 3:
                            """
                            If we've recieved a CCR-Terminate, delete the emergency subscriber.
                            """
                            try:
                                ueIp = self.get_avp_data(avps, 8)[0]
                                ueIp = str(self.hex_to_ip(ueIp))
                            except Exception as e:
                                ueIp = None
                            try:
                                #Get the IMSI
                                for SubscriptionIdentifier in self.get_avp_data(avps, 443):
                                    for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                                        if UniqueSubscriptionIdentifier['avp_code'] == 444:
                                            imsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')
                            except Exception as e:
                                imsi="Unknown"

                            try:
                                ratType = self.get_avp_data(avps, 1032)[0]
                                ratType = int(ratType, 16)
                            except Exception as e:
                                ratType = None

                            try:
                                accessNetworkGatewayAddress = self.get_avp_data(avps, 1050)[0]
                                accessNetworkGatewayAddress = str(self.hex_to_ip(accessNetworkGatewayAddress))
                            except Exception as e:
                                accessNetworkGatewayAddress = None

                            try:
                                accessNetworkChargingAddress = self.get_avp_data(avps, 501)[0]
                                accessNetworkChargingAddress = str(self.hex_to_ip(accessNetworkChargingAddress))
                            except Exception as e:
                                accessNetworkChargingAddress = None
                            
                            emergencySubscriberData = {
                                "servingPgw": binascii.unhexlify(session_id).decode(),
                                "requestTime": int(time.time()),
                                "gxOriginRealm": OriginRealm,
                                "gxOriginHost": OriginHost,
                                "imsi": imsi,
                                "ip": ueIp,
                                "ratType": ratType,
                                "accessNetworkGatewayAddress": accessNetworkGatewayAddress,
                                "accessNetworkChargingAddress": accessNetworkChargingAddress,
                            }

                            self.database.Delete_Emergency_Subscriber(subscriberIp=ueIp, subscriberData=emergencySubscriberData, imsi=imsi, gxSessionId=binascii.unhexlify(session_id).decode())

                            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
                            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                            return response

            except Exception as e:
                self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777238_272] [CCA] Error generating SOS CCA: {traceback.format_exc()}", redisClient=self.redisMessaging)

            #Get Subscriber info from Subscription ID
            imsi = ""
            for SubscriptionIdentifier in self.get_avp_data(avps, 443):
                subscription_type = -1
                for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Evaluating UniqueSubscriptionIdentifier AVP " + str(UniqueSubscriptionIdentifier) + " to find IMSI", redisClient=self.redisMessaging)
                    if UniqueSubscriptionIdentifier['avp_code'] == 450:                    
                        subscription_type = int(UniqueSubscriptionIdentifier['misc_data'])
                        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Subscription-Type " + str(subscription_type), redisClient=self.redisMessaging)
                    if UniqueSubscriptionIdentifier['avp_code'] == 444:
                        if subscription_type == 1:
                            imsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')
                            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Found IMSI " + str(imsi), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] SubscriptionID: " + str(self.get_avp_data(avps, 443)), redisClient=self.redisMessaging)
            try:
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Getting Get_Charging_Rules for IMSI " + str(imsi) + " using APN " + str(apn) + " from database", redisClient=self.redisMessaging)                                            #Get subscriber details
                ChargingRules = self.database.Get_Charging_Rules(imsi=imsi, apn=apn)
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Got Charging Rules: " + str(ChargingRules), redisClient=self.redisMessaging)
            except Exception as E:
                #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
                self.logTool.log(service='HSS', level='debug', message=E, redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Subscriber " + str(imsi) + " unknown in HSS for CCR - Check Charging Rule assigned to APN is set and exists", redisClient=self.redisMessaging)


            # CCR - Initial Request
            if int(CC_Request_Type) == 1:
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Request type for CCA is 1 - Initial", redisClient=self.redisMessaging)

                #Get UE IP            
                try:
                    ue_ip = self.get_avp_data(avps, 8)[0]
                    ue_ip = str(self.hex_to_ip(ue_ip))
                    # Fire a notification to the webhook queue, for the OCS.
                    try:
                        ocsNotificationBody = {
                                'notification_type': 'ocs',
                                'timestamp': time.time_ns(),
                                'operation': 'POST',
                                'headers': {'Content-Type': 'application/json'},
                                'body': {
                                'event': 'initiate',
                                'subscriber': {
                                'imsi': imsi,
                                'ue_ip': ue_ip,
                                'apn': apn,
                                'pcrf_session_id': binascii.unhexlify(session_id).decode(),
                                }
                            }
                        }
                        self.redisMessaging.sendMessage(queue=f'webhook', message=json.dumps(ocsNotificationBody), queueExpiry=120, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='webhook')
                    except Exception as e:
                        self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed queueing OCS notification to redis: {traceback.format_exc()}", redisClient=self.redisMessaging)
                except Exception as E:
                    self.logTool.log(service='HSS', level='error', message="[diameter.py] [Answer_16777238_272] [CCA] Failed to get UE IP", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='error', message=E, redisClient=self.redisMessaging)
                    ue_ip = 'Failed to Decode / Get UE IP'

                #Store PGW location into Database
                remote_peer = remote_peer + ";" + str(config['hss']['OriginHost'])
                self.database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=binascii.unhexlify(session_id).decode(), serving_pgw=OriginHost, subscriber_routing=str(ue_ip), serving_pgw_realm=OriginRealm, serving_pgw_peer=remote_peer)

                # Update Subscriber location information
                try:
                    default_eps_bearer_qos = self.get_avp_data(avps, 1049)[0]
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] default_eps_bearer_qos: {default_eps_bearer_qos}", redisClient=self.redisMessaging)

                    default_eps_bearer_3gpp_user_location_info = self.decode_3gpp_user_location_info(self.get_avp_data(default_eps_bearer_qos, 22)[0])
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] default_eps_bearer_3gpp_user_location_info: {default_eps_bearer_3gpp_user_location_info}", redisClient=self.redisMessaging)

                    last_seen_eci = default_eps_bearer_3gpp_user_location_info.get('ecgi', {}).get('eci', None)
                    last_seen_enodeb_id = default_eps_bearer_3gpp_user_location_info.get('ecgi', {}).get('enodeb_id', None)
                    last_seen_cell_id = default_eps_bearer_3gpp_user_location_info.get('ecgi', {}).get('cell_id', None)
                    last_seen_tac = default_eps_bearer_3gpp_user_location_info.get('tai', {}).get('tac', None)
                    last_seen_mcc = default_eps_bearer_3gpp_user_location_info.get('tai', {}).get('mcc', None)
                    last_seen_mnc = default_eps_bearer_3gpp_user_location_info.get('tai', {}).get('mnc', None)
                    last_location_update_timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()

                    self.database.update_subscriber_location(imsi=imsi,
                                                            last_seen_eci=last_seen_eci,
                                                            last_seen_enodeb_id=last_seen_enodeb_id,
                                                            last_seen_cell_id=last_seen_cell_id,
                                                            last_seen_tac=last_seen_tac,
                                                            last_seen_mcc=last_seen_mcc,
                                                            last_seen_mnc=last_seen_mnc,
                                                            last_location_update_timestamp=last_location_update_timestamp,
                                                            propagate=True)

                except Exception as e:
                    pass

                #Supported-Features(628) (Gx feature list)
                avp += self.generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af0000000b")

                #Default EPS Bearer QoS (From database with fallback source CCR-I, then omission)
                try:
                    apn_data = ChargingRules['apn_data']
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Setting APN AMBR", redisClient=self.redisMessaging)
                    #AMBR
                    AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
                    apn_ambr_ul = int(apn_data['apn_ambr_ul'])
                    apn_ambr_dl = int(apn_data['apn_ambr_dl'])
                    AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
                    AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
                    APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Setting APN Allocation-Retention-Priority", redisClient=self.redisMessaging)
                    #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
                    # Per TS 29.212, we need to flip our stored values for capability and vulnerability:
                    # PRE-EMPTION_CAPABILITY_ENABLED (0)
                    # PRE-EMPTION_CAPABILITY_DISABLED (1)
                    # PRE-EMPTION_VULNERABILITY_ENABLED (0)
                    # PRE-EMPTION_VULNERABILITY_DISABLED (1)
                    AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_data['arp_priority']), 4))
                    AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_capability']), 4))
                    AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_vulnerability']), 4))
                    AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
                    AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_data['qci']), 4))
                    avp += self.generate_vendor_avp(1049, "80", 10415, AVP_QoS + AVP_ARP)
                except Exception as E:
                    self.logTool.log(service='HSS', level='error', message=E, redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='error', message="[diameter.py] [Answer_16777238_272] [CCA] Failed to populate default_EPS_QoS from DB for sub " + str(imsi), redisClient=self.redisMessaging)
                    default_EPS_QoS = self.get_avp_data(avps, 1049)[0][8:]
                    if len(default_EPS_QoS) > 0:
                        avp += self.generate_vendor_avp(1049, "80", 10415, default_EPS_QoS)

        
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Creating QoS Information", redisClient=self.redisMessaging)
                #QoS-Information
                try:
                    apn_data = ChargingRules['apn_data']
                    apn_ambr_ul = int(apn_data['apn_ambr_ul'])
                    apn_ambr_dl = int(apn_data['apn_ambr_dl'])
                    QoS_Information = self.generate_vendor_avp(1041, "80", 10415, self.int_to_hex(apn_ambr_ul, 4))                                                                  
                    QoS_Information += self.generate_vendor_avp(1040, "80", 10415, self.int_to_hex(apn_ambr_dl, 4))
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Created both QoS AVPs from data from Database", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Populated QoS_Information", redisClient=self.redisMessaging)
                    avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)
                except Exception as E:
                    self.logTool.log(service='HSS', level='error', message="[diameter.py] [Answer_16777238_272] [CCA] Failed to get QoS information dynamically for sub " + str(imsi), redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='error', message=E, redisClient=self.redisMessaging)

                    QoS_Information = ''
                    for AMBR_Part in self.get_avp_data(avps, 1016)[0]:
                        self.logTool.log(service='HSS', level='debug', message=AMBR_Part, redisClient=self.redisMessaging)
                        AMBR_AVP = self.generate_vendor_avp(AMBR_Part['avp_code'], "80", 10415, AMBR_Part['misc_data'][8:])
                        QoS_Information += AMBR_AVP
                        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] QoS_Information added " + str(AMBR_AVP), redisClient=self.redisMessaging)
                    avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] QoS information set statically", redisClient=self.redisMessaging)
                    
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Added to AVP List", redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] QoS Information: " + str(QoS_Information), redisClient=self.redisMessaging)                                                                                 
                
                # If database returned an existing ChargingRule defintion add ChargingRule to CCA-I
                # If a Charging Rule Install AVP is present, it may trigger the creation of a dedicated bearer.
                if ChargingRules and ChargingRules['charging_rules'] is not None:
                    try:
                        self.logTool.log(service='HSS', level='debug', message=ChargingRules, redisClient=self.redisMessaging)
                        for individual_charging_rule in ChargingRules['charging_rules']:
                            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Processing Charging Rule: " + str(individual_charging_rule), redisClient=self.redisMessaging)
                            chargingRule = self.Charging_Rule_Generator(ChargingRules=individual_charging_rule, ue_ip=ue_ip)
                            if len(chargingRule) > 0:
                                avp += chargingRule

                    except Exception as E:
                        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Error in populating dynamic charging rules: " + str(E), redisClient=self.redisMessaging)

            # CCR - Termination Request
            elif int(CC_Request_Type) == 3:
                self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Request type for CCA is 3 - Termination", redisClient=self.redisMessaging)
                session_id_string = str(binascii.unhexlify(session_id).decode())
                subscriber_details = self.database.Get_Subscriber(imsi=imsi)
                stored_apn = self.database.Get_APN_by_Name(apn=apn)
                if subscriber_details and stored_apn:
                    matching_subscriber_id = subscriber_details.get('subscriber_id', None)
                    matching_apn_id = stored_apn.get('apn_id', None)
                    serving_apn = self.database.Get_Serving_APN(subscriber_id=matching_subscriber_id, apn_id=matching_apn_id)
                    if serving_apn:
                        serving_apn_session_id = serving_apn.get('pcrf_session_id', "")
                        if serving_apn_session_id == session_id_string:
                            try:
                                ocsNotificationBody = {
                                        'notification_type': 'ocs',
                                        'timestamp': time.time_ns(),
                                        'operation': 'POST',
                                        'headers': {'Content-Type': 'application/json'},
                                        'body': {
                                        'event': 'terminate',
                                        'subscriber': {
                                        'imsi': imsi,
                                        'apn': apn,
                                        'pcrf_session_id': session_id_string
                                        }
                                    }
                                }
                                self.redisMessaging.sendMessage(queue=f'webhook', message=json.dumps(ocsNotificationBody), queueExpiry=120, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='webhook')
                            except Exception as e:
                                self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed queueing OCS notification to redis: {traceback.format_exc()}", redisClient=self.redisMessaging)
                            if 'ims' in apn:
                                    try:
                                        self.database.Update_Serving_CSCF(imsi=imsi, serving_cscf=None)
                                        self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=None)
                                        self.database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=session_id_string, serving_pgw=None, subscriber_routing='')
                                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Successfully cleared stored IMS state", redisClient=self.redisMessaging)
                                    except Exception as e:
                                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed to clear stored IMS state: {traceback.format_exc()}", redisClient=self.redisMessaging)
                            else:
                                    try:
                                        self.database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=session_id_string, serving_pgw=None, subscriber_routing='')
                                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Successfully cleared stored state for: {apn}", redisClient=self.redisMessaging)
                                    except Exception as e:
                                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed to clear apn state for {apn}: {traceback.format_exc()}", redisClient=self.redisMessaging)
                else:
                    pass

            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        except Exception as e:                                             #Get subscriber details
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Subscriber " + str(imsi) + " unknown in HSS for CCR", redisClient=self.redisMessaging)

            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777238,
                                                        "diameter_cmd_code": 272,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(imsi[0:6])},
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            avp += self.generate_avp(268, 40, self.int_to_hex(5030, 4))                                           #Result Code (DIAMETER ERROR - User Unknown)
            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #3GPP Cx User Authorization Answer
    def Answer_16777216_300(self, packet_vars, avps):
        
        avp = ''                                                                                         #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx


        OriginRealm = self.get_avp_data(avps, 296)[0]                          #Get OriginRealm from AVP
        OriginRealm = binascii.unhexlify(OriginRealm).decode('utf-8')      #Format it
        OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
        OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it

        try:        #Check if we have a record-route set as that's where we'll need to send the response
            remote_peer = self.get_avp_data(avps, 282)[-1]                          #Get first record-route header
            remote_peer = binascii.unhexlify(remote_peer).decode('utf-8')           #Format it
        except:     #If we don't have a record-route set, we'll send the response to the OriginHost
            remote_peer = OriginHost
        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777216_300] [UAR] Remote Peer is " + str(remote_peer), redisClient=self.redisMessaging)

        imsi = ""
        try:
            self.logTool.log(service='HSS', level='debug', message="Checking if username present", redisClient=self.redisMessaging)
            username = self.get_avp_data(avps, 1)[0]                                                     
            username = binascii.unhexlify(username).decode('utf-8')
            self.logTool.log(service='HSS', level='debug', message="Username AVP is present, value is " + str(username), redisClient=self.redisMessaging)
            imsi = username.split('@')[0]   #Strip Domain
            domain = username.split('@')[1] #Get Domain Part
            self.logTool.log(service='HSS', level='debug', message="Extracted imsi: " + str(imsi) + " now checking backend for this IMSI", redisClient=self.redisMessaging)
            ims_subscriber_details = self.database.Get_IMS_Subscriber(imsi=imsi)
        except Exception as E:
            self.logTool.log(service='HSS', level='debug', message="Threw Exception: " + str(E), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=f"No known MSISDN or IMSI in Answer_16777216_300()", redisClient=self.redisMessaging)
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777216,
                                                        "diameter_cmd_code": 300,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(imsi[0:6])},
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            result_code = 5001          #IMS User Unknown
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 300, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        #Determine SAR Type & Store
        user_authorization_type_avp_data = self.get_avp_data(avps, 623)
        if user_authorization_type_avp_data:
            try:
                User_Authorization_Type = int(user_authorization_type_avp_data[0])
                self.logTool.log(service='HSS', level='debug', message="User_Authorization_Type is: " + str(User_Authorization_Type), redisClient=self.redisMessaging)
                if (User_Authorization_Type == 1):
                    self.logTool.log(service='HSS', level='debug', message="This is Deregister", redisClient=self.redisMessaging)
                    self.database.Update_Serving_CSCF(imsi, serving_cscf=None)
                    #Populate S-CSCF Address
                    avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode(ims_subscriber_details['scscf'])),'ascii'))
                    avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))
                    response = self.generate_diameter_packet("01", "40", 300, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                    return response
                    
            except Exception as E:
                self.logTool.log(service='HSS', level='debug', message="Failed to get User_Authorization_Type AVP & Update_Serving_CSCF error: " + str(E), redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='debug', message="Got subscriber details: " + str(ims_subscriber_details), redisClient=self.redisMessaging)
        if ims_subscriber_details['scscf'] != None:
            self.logTool.log(service='HSS', level='debug', message="Already has SCSCF Assigned from DB: " + str(ims_subscriber_details['scscf']), redisClient=self.redisMessaging)
            avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode(ims_subscriber_details['scscf'])),'ascii'))
            experimental_avp = ''
            experimental_avp += experimental_avp + self.generate_avp(266, 40, format(int(10415),"x").zfill(8))          #3GPP Vendor ID            
            experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2002),"x").zfill(8))            #DIAMETER_SUBSEQUENT_REGISTRATION (2002)
            avp += self.generate_avp(297, 40, experimental_avp)                                                         #Expermental-Result
        else:
            self.logTool.log(service='HSS', level='debug', message="No SCSCF Assigned from DB", redisClient=self.redisMessaging)
            if 'scscf_pool' in config['hss']:
                try:
                    scscf = random.choice(config['hss']['scscf_pool'])
                    self.logTool.log(service='HSS', level='debug', message="Randomly picked SCSCF address " + str(scscf) + " from pool", redisClient=self.redisMessaging)
                    avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode(scscf)),'ascii'))
                except Exception as E:
                    avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org")),'ascii'))
                    self.logTool.log(service='HSS', level='debug', message="Using generated S-CSCF Address as failed to source from list due to " + str(E), redisClient=self.redisMessaging)
            else:                        
                avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org")),'ascii'))
                self.logTool.log(service='HSS', level='debug', message="Using generated S-CSCF Address as none set in scscf_pool in config", redisClient=self.redisMessaging)
            experimental_avp = ''
            experimental_avp += experimental_avp + self.generate_avp(266, 40, format(int(10415),"x").zfill(8))          #3GPP Vendor ID            
            experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2001),"x").zfill(8))            #DIAMETER_FIRST_REGISTRATION (2001) 
            avp += self.generate_avp(297, 40, experimental_avp)                                                         #Expermental-Result

        response = self.generate_diameter_packet("01", "40", 300, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #3GPP Cx Server Assignment Answer
    def Answer_16777216_301(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)

        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx

        OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
        OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it

        OriginRealm = self.get_avp_data(avps, 296)[0]                          #Get OriginRealm from AVP
        OriginRealm = binascii.unhexlify(OriginRealm).decode('utf-8')      #Format it

        #Find Remote Peer we need to address CLRs through
        try:        #Check if we have a record-route set as that's where we'll need to send the response
            remote_peer = self.get_avp_data(avps, 282)[-1]                          #Get first record-route header
            remote_peer = binascii.unhexlify(remote_peer).decode('utf-8')           #Format it
        except:     #If we don't have a record-route set, we'll send the response to the OriginHost
            remote_peer = OriginHost
        self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777216_301] [SAR] Remote Peer is " + str(remote_peer), redisClient=self.redisMessaging)

        try:
            self.logTool.log(service='HSS', level='debug', message="Checking if username present", redisClient=self.redisMessaging)
            username = self.get_avp_data(avps, 601)[0]                                                     
            ims_subscriber_details = self.Get_IMS_Subscriber_Details_from_AVP(username) 
            self.logTool.log(service='HSS', level='debug', message="Got subscriber details: " + str(ims_subscriber_details), redisClient=self.redisMessaging)
            imsi = ims_subscriber_details['imsi']
            domain = "ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org"
        except Exception as E:
            self.logTool.log(service='HSS', level='debug', message="Threw Exception: " + str(E), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=f"No known MSISDN or IMSI in Answer_16777216_301()", redisClient=self.redisMessaging)
            result_code = 5005
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 301, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(str(imsi) + '@' + str(domain))),'ascii'))
        #Cx-User-Data (XML)
        
        #This loads a Jinja XML template as the default iFC
        templateLoader = jinja2.FileSystemLoader(searchpath="../")
        templateEnv = jinja2.Environment(loader=templateLoader)
        self.logTool.log(service='HSS', level='debug', message="Loading iFC from path " + str(ims_subscriber_details['ifc_path']), redisClient=self.redisMessaging)
        template = templateEnv.get_template(ims_subscriber_details['ifc_path'])
        
        #These variables are passed to the template for use
        ims_subscriber_details['mnc'] = self.MNC.zfill(3)
        ims_subscriber_details['mcc'] = self.MCC.zfill(3)

        xmlbody = template.render(iFC_vars=ims_subscriber_details)  # this is where to put args to the template renderer
        avp += self.generate_vendor_avp(606, "c0", 10415, str(binascii.hexlify(str.encode(xmlbody)),'ascii'))
        
        #Charging Information
        #avp += self.generate_vendor_avp(618, "c0", 10415, "0000026dc000001b000028af7072695f6363665f6164647265737300")
        #avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS

        #Determine SAR Type & Store
        Server_Assignment_Type_Hex = self.get_avp_data(avps, 614)[0]
        Server_Assignment_Type = self.hex_to_int(Server_Assignment_Type_Hex)
        self.logTool.log(service='HSS', level='debug', message="Server-Assignment-Type is: " + str(Server_Assignment_Type), redisClient=self.redisMessaging)
        ServingCSCF = self.get_avp_data(avps, 602)[0]                          #Get OriginHost from AVP
        ServingCSCF = binascii.unhexlify(ServingCSCF).decode('utf-8')      #Format it
        self.logTool.log(service='HSS', level='debug', message="Subscriber is served by S-CSCF " + str(ServingCSCF), redisClient=self.redisMessaging)
        if (Server_Assignment_Type == 1) or (Server_Assignment_Type == 2):
            self.logTool.log(service='HSS', level='debug', message="SAR is Register / Re-Register", redisClient=self.redisMessaging)
            remote_peer = remote_peer + ";" + str(config['hss']['OriginHost'])
            self.database.Update_Serving_CSCF(imsi, serving_cscf=ServingCSCF, scscf_realm=OriginRealm, scscf_peer=remote_peer)
        else:
            self.logTool.log(service='HSS', level='debug', message="SAR is not Register", redisClient=self.redisMessaging)
            #Sometimes we may get a Server Assignment Request for a Deregister for a S-CSCF that no longer serves a subscriber, but that subscriber is now served by another S-CSCF
            #So we need to check the current S-CSCF from DB == the S-CSCF sending the SAR Deregister before clearing the S-CSCF from the DB
            username = self.get_avp_data(avps, 601)[0] 
            ims_subscriber_details = self.Get_IMS_Subscriber_Details_from_AVP(username)   
            scscf_on_record = ims_subscriber_details.get('scscf', None)
            if scscf_on_record == ServingCSCF:
                self.logTool.log(service='HSS', level='debug', message="Subscriber is served by S-CSCF " + str(ServingCSCF) + " and matches S-CSCF on record - Clearing Registration" + str(scscf_on_record), redisClient=self.redisMessaging)
                self.database.Update_Serving_CSCF(imsi, serving_cscf=None)
            else:
                self.logTool.log(service='HSS', level='debug', message="Subscriber is served by S-CSCF " + str(ServingCSCF) + " but does not match S-CSCF on record - Ignoring request to clear registration" + str(scscf_on_record), redisClient=self.redisMessaging)

        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))

        response = self.generate_diameter_packet("01", "40", 301, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response    

    #3GPP Cx Location Information Answer
    def Answer_16777216_302(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        
        try:
            self.logTool.log(service='HSS', level='debug', message="Checking if username present", redisClient=self.redisMessaging)
            username = self.get_avp_data(avps, 601)[0] 
            ims_subscriber_details = self.Get_IMS_Subscriber_Details_from_AVP(username)                                                    
            if ims_subscriber_details['scscf'] != None:
                self.logTool.log(service='HSS', level='debug', message="Got SCSCF on record for Sub", redisClient=self.redisMessaging)
                #Strip double sip prefix
                avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode(str(ims_subscriber_details['scscf']))),'ascii'))
            else:
                self.logTool.log(service='HSS', level='debug', message="No SCSF assigned - Using SCSCF Pool", redisClient=self.redisMessaging)
                if 'scscf_pool' in config['hss']:
                    try:
                        scscf = random.choice(config['hss']['scscf_pool'])
                        self.logTool.log(service='HSS', level='debug', message="Randomly picked SCSCF address " + str(scscf) + " from pool", redisClient=self.redisMessaging)
                        avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode(scscf)),'ascii'))
                    except Exception as E:
                        avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org")),'ascii'))
                        self.logTool.log(service='HSS', level='debug', message="Using generated iFC as failed to source from list due to " + str(E), redisClient=self.redisMessaging)
                else:                        
                    avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org")),'ascii'))
                    self.logTool.log(service='HSS', level='debug', message="Using generated iFC", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='HSS', level='debug', message="Threw Exception: " + str(E), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=f"No known MSISDN or IMSI in Answer_16777216_302()", redisClient=self.redisMessaging)
            result_code = 5001
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777216,
                                                        "diameter_cmd_code": 302,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(username[0:6])},
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 302, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        
        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS
        response = self.generate_diameter_packet("01", "40", 302, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        
        return response

    #3GPP Cx Multimedia Authentication Answer
    def Answer_16777216_303(self, packet_vars, avps):
        public_identity = self.get_required_avp_data(avps, 601, vendor_id=10415)
        public_identity = binascii.unhexlify(public_identity).decode('utf-8')
        self.logTool.log(service='HSS', level='debug', message="Got MAR for public_identity : " + str(public_identity), redisClient=self.redisMessaging)
        username_hex = self.get_required_avp_data(avps, 1)
        username = binascii.unhexlify(username_hex).decode('utf-8')
        if '@' not in username:
            raise DiameterInvalidAvpValue(1, avp_data=username_hex)                                 #User-Name must be imsi@domain
        imsi = username.split('@')[0]   #Strip Domain
        domain = username.split('@')[1] #Get Domain Part
        self.logTool.log(service='HSS', level='debug', message="Got MAR username: " + str(username), redisClient=self.redisMessaging)
        auth_scheme = ''

        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm        

        try:
            subscriber_details = self.database.Get_Subscriber(imsi=imsi)                                               #Get subscriber details
        except:
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            self.logTool.log(service='HSS', level='debug', message="Subscriber " + str(imsi) + " unknown in HSS for MAA", redisClient=self.redisMessaging)
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777216,
                                                        "diameter_cmd_code": 303,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(imsi[0:6])},
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric')
            experimental_result = self.generate_avp(298, 40, self.int_to_hex(5001, 4))                                           #Result Code (DIAMETER ERROR - User Unknown)
            experimental_result = experimental_result + self.generate_vendor_avp(266, 40, 10415, "")
            #Experimental Result (297)
            avp += self.generate_avp(297, 40, experimental_result)
            response = self.generate_diameter_packet("01", "40", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        
        self.logTool.log(service='HSS', level='debug', message="Got subscriber data for MAA OK", redisClient=self.redisMessaging)
        
        mcc, mnc = imsi[0:3], imsi[3:5]
        plmn = self.EncodePLMN(mcc, mnc)

        #Determine if SQN Resync is required & auth type to use
        for sub_avp_612 in self.get_avp_data(avps, 612)[0]:
            if sub_avp_612['avp_code'] == 610:
                self.logTool.log(service='HSS', level='debug', message="SQN in HSS is out of sync - Performing resync", redisClient=self.redisMessaging)
                auts = str(sub_avp_612['misc_data'])[32:]
                rand = str(sub_avp_612['misc_data'])[:32]
                rand = binascii.unhexlify(rand)
                self.database.Get_Vectors_AuC(subscriber_details['auc_id'], "sqn_resync", auts=auts, rand=rand)
                self.logTool.log(service='HSS', level='debug', message="Resynced SQN in DB", redisClient=self.redisMessaging)
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, 
                                                metricLabels={
                                                            "diameter_application_id": 16777216,
                                                            "diameter_cmd_code": 302,
                                                            "event": "ReAuth",
                                                            "imsi_prefix": str(imsi[0:6])},
                                                metricHelp='Diameter Authentication related Counters',
                                                metricExpiry=60,
                                                usePrefix=True, 
                                                prefixHostname=self.hostname, 
                                                prefixServiceName='metric')
            if sub_avp_612['avp_code'] == 608:
                self.logTool.log(service='HSS', level='debug', message="Auth mechansim requested: " + str(sub_avp_612['misc_data']), redisClient=self.redisMessaging)
                auth_scheme = binascii.unhexlify(sub_avp_612['misc_data']).decode('utf-8')
                self.logTool.log(service='HSS', level='debug', message="Auth mechansim requested: " + str(auth_scheme), redisClient=self.redisMessaging)

        self.logTool.log(service='HSS', level='debug', message="IMSI is " + str(imsi), redisClient=self.redisMessaging)        
        avp += self.generate_vendor_avp(601, "c0", 10415, str(binascii.hexlify(str.encode(public_identity)),'ascii'))               #Public Identity (IMSI)
        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(imsi + "@" + domain)),'ascii'))                                    #Username

    

        #Determine Vectors to Generate
        if auth_scheme == "Digest-MD5":
            self.logTool.log(service='HSS', level='debug', message="Generating MD5 Challenge", redisClient=self.redisMessaging)
            vector_dict = self.database.Get_Vectors_AuC(subscriber_details['auc_id'], "Digest-MD5", username=imsi, plmn=plmn)
            avp_SIP_Item_Number = self.generate_vendor_avp(613, "c0", 10415, format(int(0),"x").zfill(8))
            avp_SIP_Authentication_Scheme = self.generate_vendor_avp(608, "c0", 10415, str(binascii.hexlify(b'Digest-MD5'),'ascii'))
            #Nonce
            avp_SIP_Authenticate = self.generate_vendor_avp(609, "c0", 10415, str(vector_dict['nonce']))
            #Expected Response
            avp_SIP_Authorization = self.generate_vendor_avp(610, "c0", 10415,  str(binascii.hexlify(str.encode(vector_dict['SIP_Authenticate'])),'ascii'))
            auth_data_item = avp_SIP_Item_Number + avp_SIP_Authentication_Scheme + avp_SIP_Authenticate + avp_SIP_Authorization
        else:
            self.logTool.log(service='HSS', level='debug', message="Generating AKA-MD5 Auth Challenge", redisClient=self.redisMessaging)
            vector_dict = self.database.Get_Vectors_AuC(subscriber_details['auc_id'], "sip_auth", plmn=plmn)
        

            #diameter.3GPP-SIP-Auth-Data-Items:

            #AVP Code: 613 3GPP-SIP-Item-Number
            avp_SIP_Item_Number = self.generate_vendor_avp(613, "c0", 10415, format(int(0),"x").zfill(8))
            #AVP Code: 608 3GPP-SIP-Authentication-Scheme
            avp_SIP_Authentication_Scheme = self.generate_vendor_avp(608, "c0", 10415, str(binascii.hexlify(b'Digest-AKAv1-MD5'),'ascii'))
            #AVP Code: 609 3GPP-SIP-Authenticate
            avp_SIP_Authenticate = self.generate_vendor_avp(609, "c0", 10415, str(binascii.hexlify(vector_dict['SIP_Authenticate']),'ascii'))   #RAND + AUTN
            #AVP Code: 610 3GPP-SIP-Authorization
            avp_SIP_Authorization = self.generate_vendor_avp(610, "c0", 10415, str(binascii.hexlify(vector_dict['xres']),'ascii'))  #XRES
            #AVP Code: 625 Confidentiality-Key
            avp_Confidentialility_Key = self.generate_vendor_avp(625, "c0", 10415, str(binascii.hexlify(vector_dict['ck']),'ascii'))  #CK
            #AVP Code: 626 Integrity-Key
            avp_Integrity_Key = self.generate_vendor_avp(626, "c0", 10415, str(binascii.hexlify(vector_dict['ik']),'ascii'))          #IK

            auth_data_item = avp_SIP_Item_Number + avp_SIP_Authentication_Scheme + avp_SIP_Authenticate + avp_SIP_Authorization + avp_Confidentialility_Key + avp_Integrity_Key
        avp += self.generate_vendor_avp(612, "c0", 10415, auth_data_item)    #3GPP-SIP-Auth-Data-Item
            
        avp += self.generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items


        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS
        
        response = self.generate_diameter_packet("01", "40", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #Generate a Generic error handler with Result Code as input
    def Respond_ResultCode(self, packet_vars, avps, result_code, experimental=False, failed_avp=None):
        """
        Builds a generic error answer for the request in packet_vars / avps (RFC 6733 section 7.2).
        result_code is sent in Result-Code (268), or in Experimental-Result (297, Vendor-Id 10415) when experimental is True.
        failed_avp is an optional pre-encoded AVP to include inside Failed-AVP (279).
        """
        self.logTool.log(service='HSS', level='error', message="Responding with result code " + str(result_code) + " to request with command code " + str(packet_vars['command_code']), redisClient=self.redisMessaging)
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)                                                   #Get Session-ID
        if session_id and session_id[0]:                                                            #Echo it unless absent or empty (the decoder yields [] for an empty payload)
            avp += self.generate_avp(263, 40, session_id[0])                                        #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 260 (Vendor-Specific-Application-ID) if inital request included it
            if avps_to_check['avp_code'] == 260:
                concat_subavp = ''
                for sub_avp in avps_to_check['sub_avps']:
                    if sub_avp['vendor_id'] != '':                                                  #The decoder sets vendor_id to '' when the V bit is clear and to an int (possibly 0) when it is set
                        concat_subavp += self.generate_vendor_avp(sub_avp['avp_code'], sub_avp['avp_flags'], sub_avp['vendor_id'], sub_avp['misc_data'])
                    else:
                        concat_subavp += self.generate_avp(sub_avp['avp_code'], sub_avp['avp_flags'], sub_avp['misc_data'])
                avp += self.generate_avp(260, 40, concat_subavp)                                    #Vendor-Specific-Application-ID
        auth_session_state = self.get_avp_data(avps, 277)                                           #Only include AVP 277 (Auth-Session-State) if inital request included it
        if auth_session_state and auth_session_state[0]:
            avp += self.generate_avp(277, 40, auth_session_state[0])
        if experimental:
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                 #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))  #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                              #AVP Experimental-Result(297)
        else:
            avp += self.generate_avp(268, 40, self.int_to_hex(result_code, 4))                      #Result-Code
        if failed_avp:
            avp += self.generate_avp(279, 40, failed_avp)                                           #Failed-AVP
        flags = format(int(packet_vars['flags'], 16) & 0x40, '02x')                                 #Answer flags: only keep the Proxiable bit of the request
        response = self.generate_diameter_packet("01", flags, int(packet_vars['command_code']), int(packet_vars['ApplicationId']), packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #3GPP Cx Registration Termination Answer
    def Answer_16777216_304(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        vendor_id = self.generate_avp(266, 40, str(binascii.hexlify('10415'),'ascii'))
        self.logTool.log(service='HSS', level='debug', message="vendor_id avp: " + str(vendor_id), redisClient=self.redisMessaging)
        auth_application_id = self.generate_avp(248, 40, self.int_to_hex(16777252, 8))
        self.logTool.log(service='HSS', level='debug', message="auth_application_id: " + auth_application_id, redisClient=self.redisMessaging)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(268, 40, "000007d1")                                                   #Result Code - DIAMETER_SUCCESS
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm
                #* [ Proxy-Info ]
        proxy_host_avp = self.generate_avp(280, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        proxy_state_avp = self.generate_avp(33, "40", "0001")
        avp += self.generate_avp(284, "40", proxy_host_avp + proxy_state_avp)                 #Proxy-Info  AVP ( 284 )

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        
        response = self.generate_diameter_packet("01", "40", 304, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #Strips the URI scheme, parameters and domain from a Public-Identity, leaving the bare IMSI or MSISDN
    def getPublicIdentityDigits(self, public_identity: str) -> str:
        public_identity = str(public_identity).strip()
        for uriScheme in ['sips:', 'sip:', 'tel:']:
            if public_identity.lower().startswith(uriScheme):
                public_identity = public_identity[len(uriScheme):]
                break
        #Strip any URI parameters or headers, such as ;user=phone
        public_identity = public_identity.split(';')[0].split('?')[0]
        #Strip the domain part, if present
        public_identity = public_identity.split('@')[0]
        return public_identity

    #Returns the identities carried in the User-Identity AVP of an Sh request, as a list of
    #(identity_type, value) tuples in lookup order: MSISDN (701) first, then Public-Identity (601).
    #identity_type is 'imsi' or 'msisdn'. The list is empty if no usable identity is present.
    #Raises ValueError if User-Identity is present but not a grouped AVP.
    def getShUserIdentities(self, avps) -> list:
        identities = []

        try:
            user_identity_avp = self.get_avp_data(avps, 700)[0]
        except IndexError:
            self.logTool.log(service='HSS', level='debug', message="No User-Identity AVP present - This request is invalid", redisClient=self.redisMessaging)
            return identities
        if not isinstance(user_identity_avp, list):
            raise ValueError('User-Identity is not a grouped AVP')

        try:
            msisdn = self.get_avp_data(user_identity_avp, 701)[0]
            self.logTool.log(service='HSS', level='debug', message="Got raw MSISDN with value " + str(msisdn), redisClient=self.redisMessaging)
            msisdn = self.TBCD_decode(msisdn)
            self.logTool.log(service='HSS', level='debug', message="Got MSISDN with value " + str(msisdn), redisClient=self.redisMessaging)
            identities.append(('msisdn', msisdn))
        except Exception:
            self.logTool.log(service='HSS', level='debug', message="No MSISDN present in User-Identity", redisClient=self.redisMessaging)

        #TS 29.328 allows Public-Identity in place of, or alongside, MSISDN
        try:
            public_identity = self.get_avp_data(user_identity_avp, 601)[0]
            public_identity = binascii.unhexlify(public_identity).decode('utf-8')
            self.logTool.log(service='HSS', level='debug', message="Got public_identity : " + str(public_identity), redisClient=self.redisMessaging)
            public_identity = self.getPublicIdentityDigits(public_identity)

            #TS 23.003 section 2.2 allows IMSIs shorter than 15 digits. These are treated as an
            #MSISDN here and will not be found by IMSI. Known limitation, accepted for now.
            if len(public_identity) == 15 and public_identity.isdigit():
                self.logTool.log(service='HSS', level='debug', message="Got IMSI from Public-Identity: " + str(public_identity), redisClient=self.redisMessaging)
                identities.append(('imsi', public_identity))
            else:
                self.logTool.log(service='HSS', level='debug', message="Got MSISDN from Public-Identity: " + str(public_identity), redisClient=self.redisMessaging)
                identities.append(('msisdn', public_identity))
        except Exception:
            self.logTool.log(service='HSS', level='debug', message="No Public-Identity present in User-Identity", redisClient=self.redisMessaging)

        return identities

    #Looks up the subscriber for each identity in turn and returns (ims_subscriber, subscriber)
    #for the first one found, or (None, None) if none matches.
    def getShSubscriber(self, identities) -> tuple:
        for identity_type, identity in identities:
            try:
                subscriber_ims_details = self.database.Get_IMS_Subscriber(**{identity_type: identity})
                subscriber_details = self.database.Get_Subscriber(**{identity_type: identity})
                return subscriber_ims_details, subscriber_details
            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message=f"No subscriber found for {identity_type} {identity}: {e}", redisClient=self.redisMessaging)
        return None, None

    #3GPP Sh User-Data Answer
    def Answer_16777217_306(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID

        #Define values so we can check if they've been changed
        msisdn = None
        imsi = None
        scscf = None
        subscriberIsBarred = False
        username = None
        subscriber_ims_details = None
        subscriber_details = None
        invalid_user_identity = None

        try:
            identities = self.getShUserIdentities(avps)
            subscriber_ims_details, subscriber_details = self.getShSubscriber(identities)
            for identity_type, identity in identities:
                if identity_type == 'msisdn' and msisdn is None:
                    msisdn = identity
        except ValueError as e:
            self.logTool.log(service='HSS', level='debug', message=f"Rejecting Sh User-Data-Request: {e}", redisClient=self.redisMessaging)
            invalid_user_identity = next((avp_object for avp_object in avps if int(avp_object['avp_code']) == 700), None)

        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000001")            #Vendor-Specific-Application-ID for Cx

        if invalid_user_identity is not None:
            #DIAMETER_INVALID_AVP_VALUE (5004), with the User-Identity as received in Failed-AVP
            if invalid_user_identity['vendor_id'] != '':
                failed_avp = self.generate_vendor_avp(700, invalid_user_identity['avp_flags'], invalid_user_identity['vendor_id'], invalid_user_identity['misc_data'])
            else:
                failed_avp = self.generate_avp(700, invalid_user_identity['avp_flags'], invalid_user_identity['misc_data'])
            avp += self.generate_avp(268, 40, self.int_to_hex(5004, 4))                                  #Result-Code
            avp += self.generate_avp(279, 40, failed_avp)                                                #Failed-AVP
            response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        if subscriber_ims_details is not None:
                try:
                    self.logTool.log(service='HSS', level='debug', message="Got subscriber IMS details: " + str(subscriber_ims_details), redisClient=self.redisMessaging)
                    imsi = subscriber_details.get('imsi', None)
                    scscf = subscriber_ims_details.get('scscf', None)
                    if scscf is not None:
                        imsUserState = 1
                    else:
                        imsUserState = 0
                    self.logTool.log(service='HSS', level='debug', message="Got subscriber details: " + str(subscriber_details), redisClient=self.redisMessaging)
                    subscriber_details = {**subscriber_details, **subscriber_ims_details, 'imsUserState': imsUserState}
                    self.logTool.log(service='HSS', level='debug', message="Merged subscriber details: " + str(subscriber_details), redisClient=self.redisMessaging)
                except Exception as e:
                    self.logTool.log(service='HSS', level='debug', message=f"No subscriber found for MSISDN {msisdn}", redisClient=self.redisMessaging)
                    result_code = 5001
                    #Experimental Result AVP
                    avp_experimental_result = ''
                    avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
                    avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
                    avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
                    response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
                    return response
        else:
            self.logTool.log(service='HSS', level='error', message="No MSISDN or IMSI matched from Sh User-Data-Answer input", redisClient=self.redisMessaging)
            if username is not None:
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, 
                                                metricLabels={
                                                            "diameter_application_id": 16777216,
                                                            "diameter_cmd_code": 306,
                                                            "event": "Unknown User",
                                                            "imsi_prefix": str(username[0:6])},
                                                metricHelp='Diameter Authentication related Counters',
                                                metricExpiry=60,
                                                usePrefix=True, 
                                                prefixHostname=self.hostname, 
                                                prefixServiceName='metric')
            result_code = 5001
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        #Sh-User-Data (XML)
        #This loads a Jinja XML template containing the Sh-User-Data
        sh_userdata_template = config['hss']['Default_Sh_UserData']
        self.logTool.log(service='HSS', level='debug', message="Using template " + str(sh_userdata_template) + " for SH user data", redisClient=self.redisMessaging)
        template = self.templateEnv.get_template(sh_userdata_template)
        #These variables are passed to the template for use
        subscriber_details['mnc'] = self.MNC.zfill(3)
        subscriber_details['mcc'] = self.MCC.zfill(3)
        subscriberShProfile = subscriber_details.get('sh_profile', '')
        if not subscriberShProfile:
            subscriberShProfile = subscriber_details.get('xcap_profile', '')

        subscriber_details['inboundCommunicationBarred'] = False
        subscriber_details['outboundCommunicationBarred'] = False
        subscriber_details['callForwarding'] = {'enabled': True, 'unconditional': False, 'notRegistered': False, 'noAnswer': False, 'busy': False, 'notReachable': False, 'noReplyTimer': 20}

        try:
            subscriberShXml = ET.fromstring(subscriberShProfile)
            namespaces = {
                'default': 'http://uri.etsi.org/ngn/params/xml/simservs/xcap',
                'cp': 'urn:ietf:params:xml:ns:common-policy'
            }
            incomingCommunicationBarringRuleActive, incomingCommunicationBarringAllowed = self.get_sh_profile_call_barring_rules('incoming-communication-barring', subscriberShXml, namespaces)
            outgoingCommunicationBarringRuleActive, outgoingCommunicationBarringAllowed = self.get_sh_profile_call_barring_rules('outgoing-communication-barring', subscriberShXml, namespaces)

            call_forwarding_active, call_forwarding_rules = self.get_sh_profile_call_forwarding_rules('communication-diversion', subscriberShXml, namespaces)
            self.logTool.log(service='HSS', level='debug', message=f"Call forwarding rules enabled: {call_forwarding_active}", redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=f"Call forwarding rules: {call_forwarding_rules}", redisClient=self.redisMessaging)

            if incomingCommunicationBarringRuleActive:
                if not incomingCommunicationBarringAllowed:
                    subscriber_details['inboundCommunicationBarred'] = True

            if outgoingCommunicationBarringRuleActive:
                if not outgoingCommunicationBarringAllowed:
                    subscriber_details['outboundCommunicationBarred'] = True
            
            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['notRegistered'] = call_forwarding_rules['not-registered']['target']
            except:
                pass

            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['noAnswer'] = call_forwarding_rules['no-answer']['target']
            except:
                pass

            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['busy'] = call_forwarding_rules['busy']['target']
            except:
                pass

            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['notReachable'] = call_forwarding_rules['not-reachable']['target']
            except:
                pass

            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['unconditional'] = call_forwarding_rules['forward-unconditional']['target']
            except:
                pass

            try:
                if call_forwarding_active:
                    subscriber_details['callForwarding']['noReplyTimer'] = int(call_forwarding_rules['NoReplyTimer'])
            except:
                pass


        except Exception as e:
            self.logTool.log(service='HSS', level='debug', message="Unable to parse Sh Profile XML for subscriber: " + str(subscriber_details), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message=f"{traceback.format_exc()}", redisClient=self.redisMessaging)

        self.logTool.log(service='HSS', level='debug', message="Rendering template with values: " + str(subscriber_details), redisClient=self.redisMessaging)
        xmlbody = template.render(Sh_template_vars=subscriber_details)

        self.logTool.log(service='HSS', level='debug', message=f"Template: {template}", redisClient=self.redisMessaging)

        avp += self.generate_vendor_avp(702, "c0", 10415, str(binascii.hexlify(str.encode(xmlbody)),'ascii'))
        
        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS

        response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        
        return response

    #3GPP Sh Profile-Update Answer
    def Answer_16777217_307(self, packet_vars, avps):
        

        #Get IMSI
        imsi = self.get_avp_data(avps, 1)[0]                                                        #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')

        #Get Sh User Data
        sh_user_data = self.get_avp_data(avps, 702)[0]                                                        #Get IMSI from User-Name AVP in request
        sh_user_data = binascii.unhexlify(sh_user_data).decode('utf-8')

        self.logTool.log(service='HSS', level='debug', message="Got Sh User data: " + str(sh_user_data), redisClient=self.redisMessaging)

        #Push updated User Data into IMS Backend
        #Start with the Current User Data
        subscriber_ims_details = self.database.Get_IMS_Subscriber(imsi=imsi)
        self.database.UpdateObj(IMS_SUBSCRIBER, {'xcap_profile': sh_user_data}, subscriber_ims_details['ims_subscriber_id'])

        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_required_avp_data(avps, 263)                                               #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        avp += self.generate_avp(268, 40, "000007d1")                                                    #Result-Code (2001 SUCCESS)
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777217),"x").zfill(8))   #Auth-Application-ID Sh
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId) 
        response = self.generate_diameter_packet("01", "40", 307, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    ################################
    ####        3GPP RX         ####
    ################################ 

    #3GPP Rx - AA Answer (AAA)
    def Answer_16777236_265(self, packet_vars, avps):
        try:
            """
            Generates a response to a provided AAR.
            The response is determined by whether or not the subscriber is enabled, and has a matching ims_subscriber entry.
            """
            avp = ''
            sessionId = bytes.fromhex(self.get_avp_data(avps, 263)[0]).decode('ascii')                                          #Get Session-ID
            avp += self.generate_avp(263, 40, self.string_to_hex(sessionId))                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777236),"x").zfill(8))
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_vendor_avp(628, 80, 10415, "0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af00000001") #Supported Features

            subscriptionId = bytes.fromhex(self.get_avp_data(avps, 444)[0]).decode('ascii')
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Received subscription ID: {subscriptionId}", redisClient=self.redisMessaging)
            subscriptionId = subscriptionId.replace('sip:', '')
            imsi = None
            msisdn = None
            identifier = None
            apnId = None
            remoteServingApn = None
            servingApn = None
            ipServingApn = None
            try:
                serviceUrn = bytes.fromhex(self.get_avp_data(avps, 525)[0]).decode('ascii')
            except:
                serviceUrn = None
            emergencySubscriber = False
            registeredEmergencySubscriber = False

            try:
                ueIp = self.get_avp_data(avps, 8)[0]
                ueIp = str(self.hex_to_ip(ueIp))
            except Exception as e:
                ueIp = None

            """
            Determine if the AAR for the IP belongs to an inbound roaming emergency subscriber.
            """
            try:
                emergencySubscriberData = self.database.Get_Emergency_Subscriber(subscriberIp=ueIp)
                if emergencySubscriberData:
                    emergencySubscriber = True
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777236_265] [AAA] emergencySubscriber is True as data exists in Get_Emergency_Subscriber", redisClient=self.redisMessaging)
            except Exception as e:
                emergencySubscriberData = None
            
            """
            If we didn't get a service urn, check if the IP represents a bearer for a local subscriber.
            """
            try:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Service URN: {serviceUrn}", redisClient=self.redisMessaging)
                if not serviceUrn or serviceUrn == 'None' or serviceUrn == None:
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Checking Get_Serving_APN_By_IP for UE IP: {ueIp}", redisClient=self.redisMessaging)
                    try:
                        ipServingApn = self.database.Get_Serving_APN_By_IP(subscriberIp=ueIp)
                    except:
                        ipServingApn = None
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] IP Serving APN: {ipServingApn}", redisClient=self.redisMessaging)
                    ipApnName = ''
                    if ipServingApn:
                        ipApnName = self.database.Get_APN(apn_id=int(ipServingApn.get('apn', {})))
                        ipApnName = ipApnName.get('apn', None)
                    else:
                        #If we didn't find a serving APN for the IP, try the other local HSS'.
                        localGeoredEndpoints = config.get('geored', {}).get('local_endpoints', [])
                        for localGeoredEndpoint in localGeoredEndpoints:
                            endpointUrl = f"{localGeoredEndpoint}/pcrf/pcrf_serving_apn_ip/{ueIp}"
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Searching remote HSS for serving apn: {endpointUrl}", redisClient=self.redisMessaging)
                            response = requests.get(url=endpointUrl, timeout=1)
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Response: {response.text}", redisClient=self.redisMessaging)
                            responseJson = response.json()
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Response JSON: {responseJson}", redisClient=self.redisMessaging)
                            if not responseJson:
                                continue
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Recieved response from remote HSS: {responseJson}", redisClient=self.redisMessaging)
                            remoteServingApn = responseJson
                            ipApnName = self.database.Get_APN(apn_id=int(remoteServingApn.get('apn', {})))
                            ipApnName = ipApnName.get('apn', None)

            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Exception: {traceback.format_exc()}", redisClient=self.redisMessaging)
                ipApnName = ''

            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] IP APN Name: {ipApnName}", redisClient=self.redisMessaging)

            if '@' in subscriptionId:
                subscriberIdentifier = subscriptionId.split('@')[0]
                # Subscriber Identifier can be either an IMSI or an MSISDN
                try:
                    subscriberDetails = self.database.Get_Subscriber(imsi=subscriberIdentifier)
                    imsSubscriberDetails = self.database.Get_IMS_Subscriber(imsi=subscriberIdentifier)
                    identifier = 'imsi'
                    imsi = imsSubscriberDetails.get('imsi', None)
                except Exception as e:
                    pass
                try:
                    subscriberDetails = self.database.Get_Subscriber(msisdn=subscriberIdentifier)
                    imsSubscriberDetails = self.database.Get_IMS_Subscriber(msisdn=subscriberIdentifier)
                    identifier = 'msisdn'
                    msisdn = imsSubscriberDetails.get('msisdn', None)
                except Exception as e:
                    pass
                if identifier == None:
                    try:
                        ueIP = subscriptionId.split('@')[1].split(':')[0]
                        ue = self.database.Get_UE_by_IP(ueIP)
                        subscriberId = ue.get('subscriber_id', None)
                        subscriberDetails = self.database.Get_Subscriber(subscriber_id=subscriberId)
                        imsi = subscriberDetails.get('imsi', None)
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Found IMSI {imsi} by IP: {ueIP}", redisClient=self.redisMessaging)
                    except Exception as e:
                        pass
            else:
                imsi = None
                msisdn = None
                try:
                    ueIP = subscriptionId.split(':')[0]
                    ue = self.database.Get_UE_by_IP(ueIP)
                    subscriberId = ue.get('subscriber_id', None)
                    subscriberDetails = self.database.Get_Subscriber(subscriber_id=subscriberId)
                    imsi = subscriberDetails.get('imsi', None)
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Found IMSI {imsi} by IP: {ueIP}", redisClient=self.redisMessaging)
                except Exception as e:
                    pass

            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] IMSI: {imsi} / MSISDN: {msisdn}", redisClient=self.redisMessaging)
            imsEnabled = self.validateImsSubscriber(imsi=imsi, msisdn=msisdn)

            if imsEnabled or emergencySubscriber:
                """
                Add the PCSCF to the IMS_Subscriber object, and set the result code to 2001.
                """

                self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] Request authorized", redisClient=self.redisMessaging)

                aarOriginHost = self.get_avp_data(avps, 264)[0]
                aarOriginHost = bytes.fromhex(aarOriginHost).decode('ascii')
                aarOriginRealm = self.get_avp_data(avps, 296)[0]
                aarOriginRealm = bytes.fromhex(aarOriginRealm).decode('ascii')
                aarSessionID = self.get_avp_data(avps, 263)[0]
                aarSessionID = bytes.fromhex(aarSessionID).decode('ascii')

                if imsEnabled and not emergencySubscriber:
                    self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] imsEnabled on Subscriber and not emergencySubscriber", redisClient=self.redisMessaging)
                    if imsi is None:
                        imsi = subscriberDetails.get('imsi', None)
                    #Check if we have a record-route set as that's where we'll need to send the response
                    try:
                        #Get first record-route header, then parse it
                        remotePeer = self.get_avp_data(avps, 282)[-1]
                        remotePeer = binascii.unhexlify(remotePeer).decode('utf-8')
                    except Exception as e:
                        #If we don't have a record-route set, we'll send the response to the OriginHost
                        remotePeer = aarOriginHost
                    
                    remotePeer = f"{remotePeer};{config['hss']['OriginHost']}"

                    self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=aarOriginHost, pcscf_realm=aarOriginRealm, pcscf_peer=remotePeer, pcscf_active_session=None)
                    self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] Updated Serving P-CSCF in database OK", redisClient=self.redisMessaging)
                    """
                    Check for AVP's 504 (AF-Application-Identifier) and 520 (Media-Type), which indicates the UE is making a call.
                    Media-Type: 0 = Audio, 4 = Control
                    """
                else:
                    self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] not imsEnabled on Subscriber or is emergencySubscriber", redisClient=self.redisMessaging)



                try:
                    mediaType = self.get_avp_data(avps, 520)[0]
                    # In order to send a Gx RAR, we need to ensure that mediaType is AUDIO(0) or VIDEO(1)
                    valid_media_types = [0, 1]
                    if int(mediaType, 16) not in valid_media_types:
                        self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Media type with value {mediaType} is incorrect - Is not AUDIO or VIDEO or CONTROL", redisClient=self.redisMessaging)
                    assert(int(mediaType, 16) in valid_media_types)
                    # At this point, we know the AAR is indicating a call setup, so we'll get the serving pgw information, then send a 
                    # RAR to the PGW over Gx, asking it to setup the dedicated bearer.

                    try:
                        if emergencySubscriber and not imsEnabled:
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Call from an emergency subscriber without IMS enabled", redisClient=self.redisMessaging)
                            servingPgwPeer = emergencySubscriberData.get('serving_pgw', None).split(';')[0]
                            pcrfSessionId = emergencySubscriberData.get('serving_pgw', None)
                            servingPgwRealm = emergencySubscriberData.get('gx_origin_realm', None)
                            servingPgw = emergencySubscriberData.get('serving_pgw', None).split(';')[0]
                        else:
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Getting subscriber ID", redisClient=self.redisMessaging)
                            subscriberId = subscriberDetails.get('subscriber_id', None)
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got subscriber ID", redisClient=self.redisMessaging)
                            if serviceUrn:
                                if 'sos' in str(serviceUrn).lower():
                                    registeredEmergencySubscriber = True                                    
                                    apnId = (self.database.Get_APN_by_Name(apn="sos")).get('apn_id', None)
                                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777236_265] [AAA] registeredEmergencySubscriber is True as this is SOS APN", redisClient=self.redisMessaging)
                            elif ipApnName:
                                if 'sos' in ipApnName.lower():
                                    registeredEmergencySubscriber = True
                                    apnId = (self.database.Get_APN_by_Name(apn="sos")).get('apn_id', None)
                                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777236_265] [AAA] registeredEmergencySubscriber is True as this is SOS APN", redisClient=self.redisMessaging)
                            if apnId == None:
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Getting ID for ims apn", redisClient=self.redisMessaging)
                                apnId = (self.database.Get_APN_by_Name(apn="ims")).get('apn_id', None)
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] ApnID: {apnId}", redisClient=self.redisMessaging)
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Getting Serving APN for subscriberId: {subscriberId} and apnId: {apnId}", redisClient=self.redisMessaging)
                            if remoteServingApn:
                                servingApn = remoteServingApn
                            else:
                                servingApn = self.database.Get_Serving_APN(subscriber_id=subscriberId, apn_id=apnId)
                            servingPgwPeer = servingApn.get('serving_pgw_peer', None).split(';')[0]
                            servingPgw = servingApn.get('serving_pgw', None)
                            servingPgwRealm = servingApn.get('serving_pgw_realm', None)
                            pcrfSessionId = servingApn.get('pcrf_session_id', None)

                        if not ueIp:
                            ueIp = servingApn.get('subscriber_routing', None)

                        if (int(mediaType, 16) == 0):
                            #Audio
                            ulBandwidth = 128000
                            dlBandwidth = 128000
                            qci = 1
                            precedence = 40
                            arp_priority = 14
                            rule_name = "GBR-Voice_" + str(aarSessionID)
                            charging_rule_id = 1000
                        elif (int(mediaType, 16) == 4):
                            #Video
                            ulBandwidth = 512000
                            dlBandwidth = 512000
                            qci = 1
                            precedence = 30
                            arp_priority = 11
                            rule_name = "GBR-Video_" + str(aarSessionID)
                            charging_rule_id = 1001

                        try:
                            avpUlBandwidth = int((self.get_avp_data(avps, 516)[0]), 16)
                            avpDlBandwidth = int((self.get_avp_data(avps, 515)[0]), 16)

                            if avpUlBandwidth <= ulBandwidth:
                                ulBandwidth = avpUlBandwidth
                    
                            if avpDlBandwidth <= dlBandwidth:
                                dlBandwidth = avpDlBandwidth
                        except Exception as e:
                            pass

                        """
                        If the PCSCF supplies us TFT's ready to go, use those.
                        If not, compile our own.
                        """
                        suppliedTfts = None
                        completedTftList = []

                        try:
                            suppliedTfts = self.get_avp_data(avps, 507)
                            if suppliedTfts:
                                if isinstance(suppliedTfts, list):
                                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] P-CSCF provided TFTs", redisClient=self.redisMessaging)
                                    tftId = 1
                                    for suppliedTft in suppliedTfts:
                                        tftDirection = None
                                        decodedTft = bytes.fromhex(suppliedTft).decode('ascii')
                                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got TFT from PCSCF: {decodedTft}", redisClient=self.redisMessaging)
                                        if 'permit out' in decodedTft.lower():
                                            tftDirection = 1
                                        if 'permit in' in decodedTft.lower():
                                            #@@ Ugly hack, but open5gs has no support for 'permit in' currently.
                                            # Assuming standard syntax, we need to flip the src srcprt and dst dstport, then change permit in to permit out.
                                            # permit out 17 from 1.1.1.1 54939 to 2.2.2.2 50021
                                            # permit in 17 from 2.2.2.2 50021 to 2.2.2.2 54939
                                            decodedTftSplit = decodedTft.split(' ')
                                            decodedTft = f"permit out {decodedTftSplit[2]} from {decodedTftSplit[7]} {decodedTftSplit[8]} to {decodedTftSplit[4]} {decodedTftSplit[5]}"
                                            tftDirection = 2
                                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Recompiled 'permit in' TFT to: {decodedTft}", redisClient=self.redisMessaging)

                                        completedTftList.append({
                                        "tft_group_id": 1,
                                        "direction": tftDirection,
                                        "tft_id": tftId,
                                        "tft_string": decodedTft
                                        }
                                        )
                                        tftId += 1
                        except Exception as e:
                            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error using TFTs from PCSCF: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        if not suppliedTfts:
                            try:
                                sdpOffer = self.get_avp_data(avps, 524)[0]
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got SDP Offer raw: {sdpOffer}", redisClient=self.redisMessaging)
                                sdpOffer = binascii.unhexlify(sdpOffer).decode('utf-8')
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got SDP Offer decoded: {sdpOffer}", redisClient=self.redisMessaging)
                                sdpAnswer = self.get_avp_data(avps, 524)[1]
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got SDP Answer raw: {sdpAnswer}", redisClient=self.redisMessaging)
                                sdpAnswer = binascii.unhexlify(sdpAnswer).decode('utf-8')
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Got SDP Answer decoded: {sdpAnswer}", redisClient=self.redisMessaging)

                                regexIpv4 = r"IN IP4 (\d*\.\d*\.\d*\.\d*)"
                                regexIpv6 = r"IN IP6 ([0-9a-fA-F:]{3,39})"
                                regexRtp = r"m=audio (\d*)"
                                regexRtcp = r"a=rtcp:(\d+)"                            

                                sdpDownlink = None
                                sdpUplink = None
                                sdpDownlinkIpv4 = ''
                                sdpDownlinkRtpPort = ''
                                sdpUplinkRtpPort = ''

                                # First, work out which side the SDP Downlink is, then do the same for the SDP Uplink.
                                if 'downlink' in sdpOffer.lower():
                                    sdpDownlink  = sdpOffer
                                elif 'downlink' in sdpAnswer.lower():
                                    sdpDownlink = sdpAnswer
                                
                                if 'uplink' in sdpOffer.lower():
                                    sdpUplink  = sdpOffer
                                elif 'uplink' in sdpAnswer.lower():
                                    sdpUplink = sdpAnswer

                                # Grab the SDP Downlink IP
                                sdpDownlinkIpv4 = self.Match_SDP(regexPattern=regexIpv4, sdpBody=sdpDownlink)
                                sdpDownlinkIpv6 = self.Match_SDP(regexPattern=regexIpv6, sdpBody=sdpDownlink)

                                # Get the RTP ports
                                sdpDownlinkRtpPort = self.Match_SDP(regexPattern=regexRtp, sdpBody=sdpDownlink)
                                sdpUplinkRtpPort = self.Match_SDP(regexPattern=regexRtp, sdpBody=sdpUplink)

                                # The RTCP Port is always the RTP port + 1. Comma separated ports arent used due to lack of support in open source PGWs.
                                # We take a blind approach by setting a range of +1 on both sides.
                                sdpDownlinkRtpPorts = f"{sdpDownlinkRtpPort}-{int(sdpDownlinkRtpPort)+1}"
                                sdpUplinkRtpPorts = f"{sdpUplinkRtpPort}-{int(sdpUplinkRtpPort)+1}"

                                # If we've got a UE that's sending a malformed request, use a fallback rule.
                                # Else, if all necessary variables are defined, use the correct SDP rule.
                                # The fallback rule will fail on some cheap handsets.
                                if not sdpDownlinkIpv4 or not sdpDownlinkRtpPort or not sdpUplinkRtpPort:
                                    tftString = f"permit out 17 from {ueIp}/32 1-65535 to any 1-65535"
                                else:
                                    tftString = f"permit out 17 from {sdpDownlinkIpv4}/32 {sdpDownlinkRtpPorts} to {ueIp}/32 {sdpUplinkRtpPorts}"
                                
                                completedTftList.append({
                                        "tft_group_id": 1,
                                        "direction": 2,
                                        "tft_id": 2,
                                        "tft_string": tftString  
                                        })
                                completedTftList.append({
                                        "tft_group_id": 1,
                                        "direction": 1,
                                        "tft_id": 1,
                                        "tft_string": tftString
                                        })

                            except Exception as e:
                                self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Failed to extract SDP due to error: {traceback.format_exc()}", redisClient=self.redisMessaging)
                    
                        """
                        The below logic is applied:
                        1. Grab the Flow Rules and bitrates from the PCSCF in the AAR,
                        2. Compare it to a given backup rule
                        - If the flowrates are greater than the backup rule (UE is asking for more than allowed), use the backup rule
                        - If the flowrates are lesser than the backup rule, use the requested flowrates.
                        3. Send the winning rule.
                        """

                        if emergencySubscriber or registeredEmergencySubscriber:
                            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777236_265] [AAA] Setting ARP to PreEmpt as this is an emergency bearer", redisClient=self.redisMessaging)
                            arpPreemptionCapability = True
                            arpPreemptionVulnerability = False
                        else:
                            arpPreemptionCapability = False
                            arpPreemptionVulnerability = True
                        
                        chargingRule = {
                        "charging_rule_id": charging_rule_id,
                        "qci": qci,
                        "arp_preemption_capability": arpPreemptionCapability,
                        "mbr_dl": dlBandwidth,
                        "mbr_ul": ulBandwidth,
                        "gbr_ul": ulBandwidth,
                        "precedence": precedence,
                        "arp_priority": arp_priority,
                        "rule_name": rule_name,
                        "arp_preemption_vulnerability": arpPreemptionVulnerability,
                        "gbr_dl": dlBandwidth,
                        "tft_group_id": 1,
                        "rating_group": None,
                        "tft": completedTftList
                        }

                        if not emergencySubscriber:
                            self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=aarOriginHost, pcscf_realm=aarOriginRealm, pcscf_peer=remotePeer, pcscf_active_session=sessionId)
                        else:
                            updatedEmergencySubscriberData = {
                                "servingPgw": emergencySubscriberData.get('serving_pgw'),
                                "requestTime": emergencySubscriberData.get('serving_pgw_timestamp'),
                                "servingPcscf": sessionId,
                                "aarRequestTime": int(time.time()),
                                "gxOriginRealm": emergencySubscriberData.get('gx_origin_realm'),
                                "gxOriginHost": emergencySubscriberData.get('gx_origin_host'),
                                "imsi": emergencySubscriberData.get('imsi'),
                                "ip": emergencySubscriberData.get('ip'),
                                "ratType": emergencySubscriberData.get('rat_type'),
                                "accessNetworkGatewayAddress": emergencySubscriberData.get('access_network_gateway_address'),
                                "accessNetworkChargingAddress": emergencySubscriberData.get('access_network_charging_address'),
                            }
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Updating Emergency Subscriber: {updatedEmergencySubscriberData}", redisClient=self.redisMessaging)
                            self.database.Update_Emergency_Subscriber(subscriberIp=ueIp, subscriberData=updatedEmergencySubscriberData, imsi=imsi)

                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAR Generated to be sent to serving PGW: {servingPgw} via peer {servingPgwPeer}", redisClient=self.redisMessaging)
                        reAuthAnswer = self.awaitDiameterRequestAndResponse(
                                requestType='RAR',
                                hostname=servingPgwPeer,
                                sessionId=pcrfSessionId,
                                chargingRules=chargingRule,
                                ueIp=ueIp,
                                servingPgw=servingPgw,
                                servingRealm=servingPgwRealm
                        )

                        if not len(reAuthAnswer) > 0:
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA Timeout: {reAuthAnswer}", redisClient=self.redisMessaging)
                            assert()
                            
                        raaPacketVars, raaAvps = self.decode_diameter_packet(reAuthAnswer)
                        raaResultCode = int(self.get_avp_data(raaAvps, 268)[0], 16)

                        if raaResultCode == 2001:
                            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
                            self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA returned Successfully, authorizing request", redisClient=self.redisMessaging)
                        else:
                            avp += self.generate_avp(268, 40, self.int_to_hex(4001, 4))
                            self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA returned Unauthorized, declining request", redisClient=self.redisMessaging)

                    except Exception as e:
                        self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error processing RAR / RAA, Authorizing request: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
                except Exception as e:
                    self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error generating AAA Charging Rule: {traceback.format_exc()}", redisClient=self.redisMessaging)
                    avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
                    pass
            else:
                self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_265] [AAA] Request unauthorized", redisClient=self.redisMessaging)
                avp += self.generate_avp(268, 40, self.int_to_hex(4001, 4))

            response = self.generate_diameter_packet("01", "40", 265, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error generating AAA: {traceback.format_exc()}", redisClient=self.redisMessaging)
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777236),"x").zfill(8))
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(5012, 4))                                      #Result Code 5012 UNABLE_TO_COMPLY
            response = self.generate_diameter_packet("01", "40", 265, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

    #3GPP Rx - Re Auth Answer (RAA)
    def Answer_16777236_258(self, packet_vars, avps):
        try:
            """
            Generates a response to a provided RAR.
            The response is determined by whether or not the subscriber is enabled, and has a matching ims_subscriber entry.
            """
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777236),"x").zfill(8))
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            subscriptionId = bytes.fromhex(self.get_avp_data(avps, 444)[0]).decode('ascii')
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_258] [RAA] Received subscription ID: {subscriptionId}", redisClient=self.redisMessaging)
            subscriptionId = subscriptionId.replace('sip:', '')
            imsi = None
            msisdn = None
            identifier = None
            if '@' in subscriptionId:
                subscriberIdentifier = subscriptionId.split('@')[0]
                # Subscriber Identifier can be either an IMSI or an MSISDN
                try:
                    subscriberDetails = self.database.Get_Subscriber(imsi=subscriberIdentifier)
                    imsSubscriberDetails = self.database.Get_IMS_Subscriber(imsi=subscriberIdentifier)
                    identifier = 'imsi'
                    imsi = imsSubscriberDetails.get('imsi', None)
                except Exception as e:
                    pass
                try:
                    subscriberDetails = self.database.Get_Subscriber(msisdn=subscriberIdentifier)
                    imsSubscriberDetails = self.database.Get_IMS_Subscriber(msisdn=subscriberIdentifier)
                    identifier = 'msisdn'
                    msisdn = imsSubscriberDetails.get('msisdn', None)
                except Exception as e:
                    pass
            else:
                imsi = None
                msisdn = None
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_258] [RAA] IMSI: {imsi} / MSISDN: {msisdn}", redisClient=self.redisMessaging)
            imsEnabled = self.validateImsSubscriber(imsi=imsi, msisdn=msisdn)

            if imsEnabled:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_258] [RAA] Request authorized as imsEnabled", redisClient=self.redisMessaging)
                avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            else:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_258] [RAA] Request unauthorized", redisClient=self.redisMessaging)
                avp += self.generate_avp(268, 40, self.int_to_hex(4001, 4))

            response = self.generate_diameter_packet("01", "40", 258, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_258] [RAA] Error generating RAA: {traceback.format_exc()}", redisClient=self.redisMessaging)
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777236),"x").zfill(8))
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(5012, 4))                                      #Result Code 5012 UNABLE_TO_COMPLY
            response = self.generate_diameter_packet("01", "40", 258, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

    #3GPP Rx - Session Termination Answer (STA)
    def Answer_16777236_275(self, packet_vars, avps):
        try:
            """
            Triggers a Re-Auth-Request to the PGW, the returns a Session Termination Answer.
            """
            avp = ''
            sessionId = bytes.fromhex(self.get_avp_data(avps, 263)[0]).decode('ascii')                                          #Get Session-ID
            avp += self.generate_avp(263, 40, self.string_to_hex(sessionId))                                                    #Set session ID to received session ID
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            servingApn = None
            try:
                imsSubscriber = self.database.Get_IMS_Subscriber_By_Session_Id(sessionId=sessionId)
                imsi = imsSubscriber.get('imsi', None)
                pcscf = imsSubscriber.get('pcscf', None)
                pcscf_realm = imsSubscriber.get('pcscf_realm', None)
                pcscf_peer = imsSubscriber.get('pcscf_peer', None)
                subscriber = self.database.Get_Subscriber(imsi=imsi)
                subscriberId = subscriber.get('subscriber_id', None)
                apnId = (self.database.Get_APN_by_Name(apn="ims")).get('apn_id', None)
                servingApn = self.database.Get_Serving_APN(subscriber_id=subscriberId, apn_id=apnId)
                try:
                    if not servingApn or servingApn == None or servingApn == 'None':
                        #If we didn't find a serving APN for the Subscriber, try the other local HSS'.
                        localGeoredEndpoints = config.get('geored', {}).get('local_endpoints', [])
                        for localGeoredEndpoint in localGeoredEndpoints:
                            endpointUrl = f"{localGeoredEndpoint}/pcrf/pcrf_subscriber_imsi/{imsi}"
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Searching remote HSS for serving apn: {endpointUrl}", redisClient=self.redisMessaging)
                            response = requests.get(url=endpointUrl, timeout=1)
                            responseJson = response.json()
                            if not responseJson:
                                continue
                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Recieved response from remote HSS: {responseJson}", redisClient=self.redisMessaging)
                            remoteServingApn = responseJson
                            servingImsApn = remoteServingApn.get('apns', {}).get('ims', {})
                            if servingImsApn:
                                servingApn = servingImsApn
                except:
                    self.logTool.log(service='HSS', level='warning', message=f"[diameter.py] [Answer_16777236_275] [STA] Error Searching remote HSS for serving apn: {traceback.format_exc()}", redisClient=self.redisMessaging)
                if servingApn is not None:
                    servingPgw = servingApn.get('serving_pgw', '')
                    servingPgwRealm = servingApn.get('serving_pgw_realm', '')
                    servingPgwPeer = servingApn.get('serving_pgw_peer', '').split(';')[0]
                    pcrfSessionId = servingApn.get('pcrf_session_id', None)
                else:
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] No servingApn defined for IMS Subscriber", redisClient=self.redisMessaging)
                self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=pcscf, pcscf_realm=pcscf_realm, pcscf_peer=pcscf_peer, pcscf_active_session=None)
            except Exception as e:
                pass

            """
            Determine if the Session-ID for the STR belongs to an inbound roaming emergency subscriber.
            """
            try:
                emergencySubscriberData = self.database.Get_Emergency_Subscriber(rxSessionId=sessionId)
                if emergencySubscriberData:
                    emergencySubscriber = True
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Found emergency subscriber with Rx Session: {sessionId}", redisClient=self.redisMessaging)
            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Error getting Emergency Subscriber Data: {traceback.format_exc()}", redisClient=self.redisMessaging)
                emergencySubscriberData = None
            
            if emergencySubscriberData:
                servingPgwPeer = emergencySubscriberData.get('serving_pgw', None).split(';')[0]
                pcrfSessionId = emergencySubscriberData.get('serving_pgw', None)
                servingPgwRealm = emergencySubscriberData.get('gx_origin_realm', None)
                servingPgw = emergencySubscriberData.get('serving_pgw', None).split(';')[0]

            try:
                aarSessionID = self.get_avp_data(avps, 263)[0]
                aarSessionID = bytes.fromhex(aarSessionID).decode('ascii')
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Got Original SessionID: {aarSessionID}", redisClient=self.redisMessaging)
            except:
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Error getting Original SessionID: {traceback.format_exc()}", redisClient=self.redisMessaging)
                aarSessionID = ""
            if servingApn is not None or emergencySubscriberData:
                reAuthAnswer = self.awaitDiameterRequestAndResponse(
                        requestType='RAR',
                        hostname=servingPgwPeer,
                        sessionId=pcrfSessionId,
                        servingPgw=servingPgw,
                        servingRealm=servingPgwRealm,
                        chargingRuleName='GBR-Voice_' + str(aarSessionID),
                        chargingRuleAction='remove'
                )
            
                if not len(reAuthAnswer) > 0:
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] RAA Timeout: {reAuthAnswer}", redisClient=self.redisMessaging)
                    assert()
                
                raaPacketVars, raaAvps = self.decode_diameter_packet(reAuthAnswer)
                raaResultCode = int(self.get_avp_data(raaAvps, 268)[0], 16)

                if raaResultCode == 2001:
                    avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] RAA returned Successfully, authorizing request", redisClient=self.redisMessaging)
                else:
                    avp += self.generate_avp(268, 40, self.int_to_hex(5001, 4))
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] RAA returned Unauthorized, returning Result-Code 5001", redisClient=self.redisMessaging)

            else:
                self.logTool.log(service='HSS', level='info', message=f"[diameter.py] [Answer_16777236_275] [STA] Unable to find serving APN for RAR, returning Result-Code 2001", redisClient=self.redisMessaging)

            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            response = self.generate_diameter_packet("01", "40", 275, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_275] [STA] Error generating STA, returning 2001", redisClient=self.redisMessaging)
            avp = ''
            sessionId = self.get_avp_data(avps, 263)[0]                                                       #Get Session-ID
            avp += self.generate_avp(263, 40, sessionId)                                                    #Set session ID to received session ID
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            response = self.generate_diameter_packet("01", "40", 275, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

    #3GPP Rx - Abort Session Answer (ASA)
    def Answer_16777236_274(self, packet_vars, avps):
        try:
            """
            Generates a response to a provided ASR.
            Returns Result-Code 2001.
            """
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            response = self.generate_diameter_packet("01", "40", 274, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_274] [STA] Error generating STA: {traceback.format_exc()}", redisClient=self.redisMessaging)


    # Re Auth Answer
    def Answer_16777238_258(self, packet_vars, avps):
        try:
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            response = self.generate_diameter_packet("01", "40", 274, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_274] [RAA] Error generating RAA: {traceback.format_exc()}", redisClient=self.redisMessaging)

    #3GPP S13 - ME-Identity-Check Answer
    def Answer_16777252_324(self, packet_vars, avps):

        #Get IMSI
        try:
            imei = ''
            imsi = self.get_avp_data(avps, 1)[0]                                                            #Get IMSI from User-Name AVP in request
            imsi = binascii.unhexlify(imsi).decode('utf-8')                                                 #Convert IMSI
            #avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                      #Username (IMSI)
            self.logTool.log(service='HSS', level='debug', message="Got IMSI with value " + str(imsi), redisClient=self.redisMessaging)
        except Exception as e:
            self.logTool.log(service='HSS', level='debug', message="Failed to get IMSI from LCS-Routing-Info-Request", redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Error was: " + str(e), redisClient=self.redisMessaging)

        try:
            #Get IMEI
            for sub_avp in self.get_avp_data(avps, 1401)[0]:
                self.logTool.log(service='HSS', level='debug', message="Evaluating sub_avp AVP " + str(sub_avp) + " to find IMSI", redisClient=self.redisMessaging)
                if sub_avp['avp_code'] == 1402:
                    imei = binascii.unhexlify(sub_avp['misc_data']).decode('utf-8')
                    self.logTool.log(service='HSS', level='debug', message="Found IMEI " + str(imei), redisClient=self.redisMessaging)

            avp = ''                                                                                        #Initiate empty var AVP
            session_id = self.get_avp_data(avps, 263)[0]                                                    #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                   #Set session ID to received session ID
            avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID for S13
            avp += self.generate_avp(277, 40, "00000001")                                                   #Auth Session State        
            avp += self.generate_avp(264, 40, self.OriginHost)                                              #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm
            #Experimental Result AVP(Response Code for Failure)
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 'c0', 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 'c0', self.int_to_hex(2001, 4))                 #AVP Experimental-Result-Code: SUCESS (2001)
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))

            #Equipment-Status
            EquipmentStatus = self.database.Check_EIR(imsi=imsi, imei=imei)
            avp += self.generate_vendor_avp(1445, 'c0', 10415, self.int_to_hex(EquipmentStatus, 4))
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_eir_event_count',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, 
                                    metricLabels={
                                                "response": EquipmentStatus},
                                    metricHelp='Diameter EIR event related Counters',
                                    metricExpiry=60,
                                    usePrefix=True, 
                                    prefixHostname=self.hostname, 
                                    prefixServiceName='metric')
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=traceback.format_exc(), redisClient=self.redisMessaging)


        response = self.generate_diameter_packet("01", "40", 324, 16777252, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #3GPP SLh - LCS-Routing-Info-Answer
    def Answer_16777291_8388622(self, packet_vars, avps):
        avp = '' 
        session_id = self.get_required_avp_data(avps, 263)                                              #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                   #Set session    ID to received session ID
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777291),"x").zfill(8))   #Auth-Application-ID SLh
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                   #Auth Session State (NO_STATE_MAINTAINED)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                              #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm

        #Create list of valid AVPs
        present_avps = []
        for avp_id in avps:
            present_avps.append(avp_id['avp_code'])
        
        #Define values so we can check if they've been changed
        msisdn = None
        imsi = None

        #Try and get IMSI if present
        if 1 in present_avps:
            self.logTool.log(service='HSS', level='debug', message="IMSI AVP is present", redisClient=self.redisMessaging)
            try:
                imsi = self.get_avp_data(avps, 1)[0]                                                            #Get IMSI from User-Name AVP in request
                imsi = binascii.unhexlify(imsi).decode('utf-8')                                                 #Convert IMSI
                avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                       #Username (IMSI)
                self.logTool.log(service='HSS', level='debug', message="Got IMSI with value " + str(imsi), redisClient=self.redisMessaging)
            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message="Failed to get IMSI from LCS-Routing-Info-Request", redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="Error was: " + str(e), redisClient=self.redisMessaging)
        elif 701 in present_avps:
            #Try and get MSISDN if present
            try:
                msisdn = self.get_avp_data(avps, 701)[0]                                                          #Get MSISDN from AVP in request
                self.logTool.log(service='HSS', level='debug', message="Got MSISDN with value " + str(msisdn), redisClient=self.redisMessaging)
                avp += self.generate_vendor_avp(701, 'c0', 10415, self.get_avp_data(avps, 701)[0])                     #MSISDN
                self.logTool.log(service='HSS', level='debug', message="Got MSISDN with encoded value " + str(msisdn), redisClient=self.redisMessaging)
                msisdn = self.TBCD_decode(msisdn)
                self.logTool.log(service='HSS', level='debug', message="Got MSISDN with decoded value " + str(msisdn), redisClient=self.redisMessaging)
            except Exception as e:
                self.logTool.log(service='HSS', level='debug', message="Failed to get MSISDN from LCS-Routing-Info-Request", redisClient=self.redisMessaging)
                self.logTool.log(service='HSS', level='debug', message="Error was: " + str(e), redisClient=self.redisMessaging)
        else:
            self.logTool.log(service='HSS', level='error', message="No MSISDN or IMSI", redisClient=self.redisMessaging)

        try:
            if imsi is not None:
                    self.logTool.log(service='HSS', level='debug', message="Getting subscriber location based on IMSI", redisClient=self.redisMessaging)
                    subscriber_details = self.database.Get_Subscriber(imsi=imsi)
                    self.logTool.log(service='HSS', level='debug', message="Got subscriber_details from IMSI: " + str(subscriber_details), redisClient=self.redisMessaging)
            elif msisdn is not None:
                    self.logTool.log(service='HSS', level='debug', message="Getting subscriber location based on MSISDN", redisClient=self.redisMessaging)
                    subscriber_details = self.database.Get_Subscriber(msisdn=msisdn)
                    self.logTool.log(service='HSS', level='debug', message="Got subscriber_details from MSISDN: " + str(subscriber_details), redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='HSS', level='debug', message="No MSISDN or IMSI returned in Answer_16777291_8388622 input", redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Error is " + str(E), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="Responding with DIAMETER_ERROR_USER_UNKNOWN", redisClient=self.redisMessaging)
            avp += self.generate_avp(268, 40, self.int_to_hex(5030, 4))
            response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            self.logTool.log(service='HSS', level='debug', message="Diameter user unknown - Sending ULA with DIAMETER_ERROR_USER_UNKNOWN", redisClient=self.redisMessaging)
            return response


        
        self.logTool.log(service='HSS', level='debug', message="Got subscriber_details for subscriber: " + str(subscriber_details), redisClient=self.redisMessaging)

        
        if subscriber_details['serving_mme'] == None:
            #DB has no location on record for subscriber
            self.logTool.log(service='HSS', level='debug', message="No location on record for Subscriber", redisClient=self.redisMessaging)
            result_code = 4201
            #DIAMETER_ERROR_ABSENT_USER (4201)
            #This result code shall be sent by the HSS to indicate that the location of the targeted user is not known at this time to
            #satisfy the requested operation. 

            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            
            response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response



        #Serving Node AVP
        avp_serving_node = ''
        avp_serving_node += self.generate_vendor_avp(2402, "c0", 10415, self.string_to_hex(subscriber_details['serving_mme']))            #MME-Name
        avp_serving_node += self.generate_vendor_avp(2408, "c0", 10415, self.OriginRealm)                                   #MME-Realm
        avp_serving_node += self.generate_vendor_avp(2405, "c0", 10415, self.ip_to_hex(config['hss']['bind_ip'][0]))                        #GMLC-Address
        avp += self.generate_vendor_avp(2401, "c0", 10415, avp_serving_node)                                                #Serving-Node  AVP

        #Set Result-Code
        result_code = 2001                                                                                                  #Diameter Success
        avp += self.generate_avp(268, 40, self.int_to_hex(result_code, 4))                                                  #Result Code - DIAMETER_SUCCESS

        response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response
        
    #### Diameter Requests ####

    #Capabilities Exchange Request
    def Request_257(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(257, 40, self.ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                                    #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                                   #Product-Name
        avp += self.generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(260, 40, "000001024000000c01000027" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLg)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(258, 40, format(int(4294967295),"x").zfill(8))                          #Auth-Application-ID Relay
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                               #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)
        response = self.generate_diameter_packet("01", "80", 257, 0, self.generate_id(4), self.generate_id(4), avp)            #Generate Diameter packet
        return response

    #Device Watchdog Request
    def Request_280(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        response = self.generate_diameter_packet("01", "80", 280, 0, self.generate_id(4), self.generate_id(4), avp)#Generate Diameter packet
        return response

    #Disconnect Peer Request
    def Request_282(self):                                                                      
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(273, 40, "00000000")                                                    #Disconnect-Cause (REBOOTING (0))
        response = self.generate_diameter_packet("01", "80", 282, 0, self.generate_id(4), self.generate_id(4), avp)#Generate Diameter packet
        return response

    #3GPP S6a/S6d Authentication Information Request
    def Request_16777251_318(self, imsi, DestinationHost, DestinationRealm, requested_vectors=1):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                                                   #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                                   #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        number_of_requested_vectors = self.generate_vendor_avp(1410, "c0", 10415,  format(int(requested_vectors),"x").zfill(8))
        immediate_response_preferred = self.generate_vendor_avp(1412, "c0", 10415,  format(int(1),"x").zfill(8))
        avp += self.generate_vendor_avp(1408, "c0", 10415, str(number_of_requested_vectors) + str(immediate_response_preferred))

        mcc = str(imsi)[:3]
        mnc = str(imsi)[3:5]
        avp += self.generate_vendor_avp(1407, "c0", 10415, self.EncodePLMN(mcc, mnc))                    #Visited-PLMN-Id(1407) (Derrived from start of IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID       
        response = self.generate_diameter_packet("01", "c0", 318, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Update Location Request (ULR)
    def Request_16777251_316(self, imsi, DestinationRealm):
        mcc = imsi[0:3]
        mnc = imsi[3:5]
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, str(binascii.hexlify(str.encode("testclient." + config['hss']['OriginHost'])),'ascii'))          
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                                                   #Destination Realm
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_vendor_avp(1032, "80", 10415, self.int_to_hex(1004, 4))                    #RAT-Type val=EUTRAN (1004)
        avp += self.generate_vendor_avp(1405, "c0", 10415, "00000002")                                  #ULR-Flags val=2
        avp += self.generate_vendor_avp(1407, "c0", 10415, self.EncodePLMN(mcc, mnc))                    #Visited-PLMN-Id(1407) (Derrived from start of IMSI)
        avp += self.generate_vendor_avp(1615, "80", 10415, "00000000")                                  #E-SRVCC-Capability val=UE-SRVCC-NOT-SUPPORTED (0)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 316, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
    
    #3GPP S6a/S6d Purge UE Request PUR
    def Request_16777251_321(self, imsi, DestinationRealm, DestinationHost):
        avp = ''
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))               #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                         #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                               #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")                 #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 321, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d NOtify Request NOR
    def Request_16777251_323(self, imsi, DestinationRealm, DestinationHost):
        avp = ''
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))               #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                         #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                               #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")                 #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 323, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Cancel-Location-Request Request CLR
    def Request_16777251_317(self, imsi, DestinationRealm, DestinationHost=None, CancellationType=2, immediateReattach=True):
        avp = ''
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                      #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                         #Destination Realm
        if DestinationHost != None:
            avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                           #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                        #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
        avp += self.generate_vendor_avp(1420, "c0", 10415,  self.int_to_hex(CancellationType, 4))                       #Cancellation-Type (Subscription Withdrawl)
        if immediateReattach:
            avp += self.generate_vendor_avp(1638, "c0", 10415,  self.int_to_hex(2, 4))                       #CLR Flags
        response = self.generate_diameter_packet("01", "c0", 317, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Insert Subscriber Data Request (ISD)
    def Request_16777251_319(self, imsi, DestinationRealm, DestinationHost=None, PcscfRestoration=False, GetLocation=False, **kwargs):
        avp = ''                                                                                    #Initiate empty var AVP
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a'                 #Session ID generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))     #Session ID set AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a) 
        avp += self.generate_avp(277, 40, "00000001")                                               #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        avp += self.generate_vendor_avp(266, 40, 10415, '')                                         #AVP Vendor ID
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                 #AVP Vendor ID
        domain = "ims.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org"


        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        if GetLocation:
            self.logTool.log(service='HSS', level='debug', message="Requested Get Location ISD", redisClient=self.redisMessaging)
            #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
            SupportedFeatures = ''
            SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
            SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
            SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "18000007")             #Feature-List Flags
            avp += self.generate_vendor_avp(1490, "c0", 10415, "00000018")                        #IDR-Flags
            avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP
        if PcscfRestoration:
            avp += self.generate_vendor_avp(1490, "c0", 10415, "00000100")                        #IDR-Flags - 8th bit set
    
        avp += self.generate_avp(1, 40, self.string_to_hex(f"{imsi}"))                                   #Username (IMSI)
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP
        avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                                         #Destination-Host
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))

        APN_Configuration = ''

        try:
            subscriber_details = self.database.Get_Subscriber(imsi=imsi)                                               #Get subscriber details
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Request_16777251_319] [ISD] Got subscriber data: {subscriber_details}", redisClient=self.redisMessaging)

        except ValueError as e:
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Request_16777251_319] [ISD]failed to get data backfrom database for imsi " + str(imsi), redisClient=self.redisMessaging)
            self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Request_16777251_319] [ISD] Error is " + str(e), redisClient=self.redisMessaging)
            raise
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            raise

        #Subscription Data: 
        subscription_data = ''
        subscription_data += self.generate_vendor_avp(1426, "c0", 10415, "00000000")                     #Access Restriction Data
        subscription_data += self.generate_vendor_avp(1424, "c0", 10415, "00000000")                     #Subscriber-Status (SERVICE_GRANTED)
        subscription_data += self.generate_vendor_avp(1417, "c0", 10415, "00000002")                     #Network-Access-Mode (PACKET_AND_CIRCUIT)

        #AMBR is a sub-AVP of Subscription Data
        AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        if 'ue_ambr_ul' in subscriber_details:
            ue_ambr_ul = int(subscriber_details['ue_ambr_ul'])
        else:
            #use default AMBR of unlimited if no value in subscriber_details
            ue_ambr_ul = 1048576000

        if 'ue_ambr_dl' in subscriber_details:
            ue_ambr_dl = int(subscriber_details['ue_ambr_dl'])
        else:
            #use default AMBR of unlimited if no value in subscriber_details
            ue_ambr_dl = 1048576000

        AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
        AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
        subscription_data += self.generate_vendor_avp(1435, "c0", 10415, AMBR)                           #Add AMBR AVP in two sub-AVPs

        #APN Configuration Profile is a sub AVP of Subscription Data
        APN_Configuration_Profile = ''
        APN_Configuration_Profile += self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))     #Context Identifier
        APN_Configuration_Profile += self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4))     #All-APN-Configurations-Included-Indicator



        # apn_list = subscriber_details['pdn']
        # self.logTool.log(service='HSS', level='debug', message="APN list: " + str(apn_list), redisClient=self.redisMessaging)
        # APN_context_identifer_count = 1
        # for apn_profile in apn_list:
        #     self.logTool.log(service='HSS', level='debug', message="Processing APN profile " + str(apn_profile), redisClient=self.redisMessaging)
        #     APN_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex(str(apn_profile['apn'])))

        #     self.logTool.log(service='HSS', level='debug', message="Setting APN Configuration Profile", redisClient=self.redisMessaging)
        #     #Sub AVPs of APN Configuration Profile
        #     APN_context_identifer = self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(APN_context_identifer_count, 4))
        #     APN_PDN_type = self.generate_vendor_avp(1456, "c0", 10415, self.int_to_hex(0, 4))
            
        #     self.logTool.log(service='HSS', level='debug', message="Setting APN AMBR", redisClient=self.redisMessaging)
        #     #AMBR
        #     AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        #     if 'AMBR' in apn_profile:
        #         ue_ambr_ul = int(apn_profile['AMBR']['apn_ambr_ul'])
        #         ue_ambr_dl = int(apn_profile['AMBR']['apn_ambr_dl'])
        #     else:
        #         #use default AMBR of unlimited if no value in subscriber_details
        #         ue_ambr_ul = 50000000
        #         ue_ambr_dl = 100000000

        #     AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
        #     AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
        #     APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

        #     self.logTool.log(service='HSS', level='debug', message="Setting APN Allocation-Retention-Priority", redisClient=self.redisMessaging)
        #     #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
        #     AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['priority_level']), 4))
        #     AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['pre_emption_capability']), 4))
        #     AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "c0", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['pre_emption_vulnerability']), 4))
        #     AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
        #     AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_profile['qos']['qci']), 4))
        #     APN_EPS_Subscribed_QoS_Profile = self.generate_vendor_avp(1431, "c0", 10415, AVP_QoS + AVP_ARP)


        #     #If static UE IP is specified
        #     try:
        #         apn_ip = apn_profile['ue']['addr']
        #         self.logTool.log(service='HSS', level='debug', message="Found static IP for UE " + str(apn_ip), redisClient=self.redisMessaging)
        #         Served_Party_Address = self.generate_vendor_avp(848, "c0", 10415, self.ip_to_hex(apn_ip))
        #     except:
        #         Served_Party_Address = ""

        #     if 'MIP6-Agent-Info' in apn_profile:
        #         self.logTool.log(service='HSS', level='debug', message="MIP6-Agent-Info present, value " + str(apn_profile['MIP6-Agent-Info']), redisClient=self.redisMessaging)
        #         MIP6_Destination_Host = self.generate_avp(293, '40', self.string_to_hex(str(apn_profile['MIP6-Agent-Info']['MIP6_DESTINATION_HOST'])))
        #         MIP6_Destination_Realm = self.generate_avp(283, '40', self.string_to_hex(str(apn_profile['MIP6-Agent-Info']['MIP6_DESTINATION_REALM'])))
        #         MIP6_Home_Agent_Host = self.generate_avp(348, '40', MIP6_Destination_Host + MIP6_Destination_Realm)
        #         MIP6_Agent_Info = self.generate_avp(486, '40', MIP6_Home_Agent_Host)
        #         self.logTool.log(service='HSS', level='debug', message="MIP6 value is " + str(MIP6_Agent_Info), redisClient=self.redisMessaging)
        #     else:
        #         MIP6_Agent_Info = ''

        #     if 'PDN_GW_Allocation_Type' in apn_profile:
        #         self.logTool.log(service='HSS', level='debug', message="PDN_GW_Allocation_Type present, value " + str(apn_profile['PDN_GW_Allocation_Type']), redisClient=self.redisMessaging)
        #         PDN_GW_Allocation_Type = self.generate_vendor_avp(1438, 'c0', 10415, self.int_to_hex(int(apn_profile['PDN_GW_Allocation_Type']), 4))
        #         self.logTool.log(service='HSS', level='debug', message="PDN_GW_Allocation_Type value is " + str(PDN_GW_Allocation_Type), redisClient=self.redisMessaging)
        #     else:
        #         PDN_GW_Allocation_Type = ''

        #     if 'VPLMN_Dynamic_Address_Allowed' in apn_profile:
        #         self.logTool.log(service='HSS', level='debug', message="VPLMN_Dynamic_Address_Allowed present, value " + str(apn_profile['VPLMN_Dynamic_Address_Allowed']), redisClient=self.redisMessaging)
        #         VPLMN_Dynamic_Address_Allowed = self.generate_vendor_avp(1432, 'c0', 10415, self.int_to_hex(int(apn_profile['VPLMN_Dynamic_Address_Allowed']), 4))
        #         self.logTool.log(service='HSS', level='debug', message="VPLMN_Dynamic_Address_Allowed value is " + str(VPLMN_Dynamic_Address_Allowed), redisClient=self.redisMessaging)
        #     else:
        #         VPLMN_Dynamic_Address_Allowed = ''

        #     APN_Configuration_AVPS = APN_context_identifer + APN_PDN_type + APN_AMBR + APN_Service_Selection \
        #         + APN_EPS_Subscribed_QoS_Profile + Served_Party_Address + MIP6_Agent_Info + PDN_GW_Allocation_Type + VPLMN_Dynamic_Address_Allowed
            
        #     APN_Configuration += self.generate_vendor_avp(1430, "c0", 10415, APN_Configuration_AVPS)
            
        #     #Incriment Context Identifier Count to keep track of how many APN Profiles returned
        #     APN_context_identifer_count = APN_context_identifer_count + 1  
        #     self.logTool.log(service='HSS', level='debug', message="Processed APN profile " + str(apn_profile['apn']), redisClient=self.redisMessaging)
        
        # subscription_data += self.generate_vendor_avp(1619, "80", 10415, self.int_to_hex(720, 4))                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)
        # subscription_data += self.generate_vendor_avp(1429, "c0", 10415, APN_context_identifer + \
        #     self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4)) + APN_Configuration)

        #If MSISDN is present include it in Subscription Data
        if 'msisdn' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="MSISDN is " + str(subscriber_details['msisdn']) + " - adding in IDR", redisClient=self.redisMessaging)
            msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, self.string_to_hex(str(subscriber_details['msisdn'])))                     #MSISDN
            self.logTool.log(service='HSS', level='debug', message=msisdn_avp, redisClient=self.redisMessaging)
            subscription_data += msisdn_avp

        if 'RAT_freq_priorityID' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="RAT_freq_priorityID is " + str(subscriber_details['RAT_freq_priorityID']) + " - Adding in IDR", redisClient=self.redisMessaging)
            rat_freq_priorityID = self.generate_vendor_avp(1440, "C0", 10415, self.int_to_hex(int(subscriber_details['RAT_freq_priorityID']), 4))                              #RAT-Frequency-Selection-Priority ID
            self.logTool.log(service='HSS', level='debug', message=rat_freq_priorityID, redisClient=self.redisMessaging)
            subscription_data += rat_freq_priorityID

        if '3gpp-charging-characteristics' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="3gpp-charging-characteristics " + str(subscriber_details['3gpp-charging-characteristics']) + " - Adding in IDR", redisClient=self.redisMessaging)
            _3gpp_charging_characteristics = self.generate_vendor_avp(13, "80", 10415, self.string_to_hex(str(subscriber_details['3gpp-charging-characteristics'])))
            subscription_data += _3gpp_charging_characteristics
            self.logTool.log(service='HSS', level='debug', message=_3gpp_charging_characteristics, redisClient=self.redisMessaging)

            
        if 'APN_OI_replacement' in subscriber_details:
            self.logTool.log(service='HSS', level='debug', message="APN_OI_replacement " + str(subscriber_details['APN_OI_replacement']) + " - Adding in IDR", redisClient=self.redisMessaging)
            subscription_data += self.generate_vendor_avp(1427, "C0", 10415, self.string_to_hex(str(subscriber_details['APN_OI_replacement'])))

        avp += self.generate_vendor_avp(1400, "c0", 10415, subscription_data)                            #Subscription-Data

        response = self.generate_diameter_packet("01", "C0", 319, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
    
    #3GPP S6a/S6d Delete Subscriber Data Request (DSR)
    def Request_16777251_320(self, imsi, DestinationRealm, DestinationHost, ExternalIdentifier=None, **kwargs):
        avp = ''                                                                                    #Initiate empty var AVP
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_s6a' #Session ID generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))     #Session ID set AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af") #Vendor-Specific-Application-ID (S6a) 
        avp += self.generate_avp(277, 40, "00000001")                                               #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                      #Destination Host
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                     #Destination Realm
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                   #Username (IMSI)
        avp += self.generate_vendor_avp(1421, "c0", 10415, "00000000")                              #DSR-Flags val=0

        if ExternalIdentifier != None:
            avp += self.generate_vendor_avp(3111, "c0", 10415, self.string_to_hex(ExternalIdentifier))  #External-Identifier

        response = self.generate_diameter_packet("01", "C0", 320, 16777251, self.generate_id(4), self.generate_id(4), avp) #Generate Diameter packet
        return response

    #3GPP Cx Location Information Request (LIR)
    #ToDo - Check the command code here...
    def Request_16777216_302(self, sipaor):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        #Auth Session state
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex(sipaor))                      #Public-Identity / SIP-AOR
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'hss.localdomain'),'ascii'))                 #Destination Host

        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID


        response = self.generate_diameter_packet("01", "c0", 302, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx User Authorization Request (UAR)
    def Request_16777216_300(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi + "@" + domain))                   #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + imsi + "@" + domain))                 #Public-Identity
        avp += self.generate_vendor_avp(600, "c0", 10415, self.string_to_hex(domain))               #Visited Network Identifier
        response = self.generate_diameter_packet("01", "c0", 300, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Server Assignment Request (SAR)
    def Request_16777216_301(self, imsi, domain, server_assignment_type):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session Session ID
        avp += self.generate_avp(264, 40, str(binascii.hexlify(str.encode("testclient." + config['hss']['OriginHost'])),'ascii'))                                                              #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + imsi + "@" + domain))                 #Public-Identity
        avp += self.generate_vendor_avp(602, "c0", 10415, self.string_to_hex('sip:scscf.ims.mnc' + self.MNC + '.mcc' + self.MCC + '.3gppnetwork.org:5060'))                 #Public-Identity
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi + "@" + domain))                   #User-Name
        avp += self.generate_vendor_avp(614, "c0", 10415, format(int(server_assignment_type),"x").zfill(8))              #Server Assignment Type
        avp += self.generate_vendor_avp(624, "c0", 10415, "00000000")                               #User Data Already Available (Not Available)
        response = self.generate_diameter_packet("01", "c0", 301, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Multimedia Authentication Request (MAR)
    def Request_16777216_303(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_avp(1, 40, self.string_to_hex(str(imsi) + "@" + domain))                         #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + str(imsi) + "@" + domain))                      #Public-Identity
        avp += self.generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items
                                                                                                         #3GPP-SIP-Number-Auth-Data-Item
        
        avp += self.generate_vendor_avp(612, "c0", 10415, "00000260c0000013000028af756e6b6e6f776e0000000262c000002a000028af02e3fe1064bea4dd52602bef1c80a34ededbeb4ccabfa0430f4ffd5f1d8c0000")
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name
        response = self.generate_diameter_packet("01", "c0", 303, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Registration Termination Request (RTR)
    def Request_16777216_304(self, imsi, domain, destinationHost, destinationRealm):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session ID AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        
        #SIP-Deregistration-Reason
        reason_code_avp = self.generate_vendor_avp(616, "c0", 10415, "00000000")
        reason_info_avp = self.generate_vendor_avp(617, "c0", 10415, self.string_to_hex("Administrative Deregistration"))
        avp += self.generate_vendor_avp(615, "c0", 10415, reason_code_avp + reason_info_avp)
        
        avp += self.generate_avp(283, 40, self.string_to_hex(destinationRealm))                 #Destination Realm
        avp += self.generate_avp(293, 40, self.string_to_hex(destinationHost))                 #Destination Host
        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_avp(1, 40, self.string_to_hex(str(imsi) + "@" + domain))                         #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + str(imsi) + "@" + domain))                      #Public-Identity
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name
        
        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", self.OriginHost)
    
        response = self.generate_diameter_packet("01", "c0", 304, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet

        return response

    #3GPP Sh User-Data Request (UDR)
    def Request_16777217_306(self, **kwargs):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + ';' + self.generate_id(5) + ';1;app_sh'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session ID AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'hss.localdomain'),'ascii'))                 #Destination Host
        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        
        if kwargs.get("msisdn"):
            msisdn = str(kwargs['msisdn'])
            msisdn = msisdn.replace('+', '')
            msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(msisdn)))                                             #MSISDN
            avp += self.generate_vendor_avp(700, "c0", 10415, msisdn_avp)                         #User-Identity
            avp += self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(msisdn))) 
        elif "imsi" in kwargs:
            imsi = kwargs['imsi']
            public_identity_avp = self.generate_vendor_avp(601, 'c0', 10415, self.string_to_hex(imsi))                                             #MSISDN
            avp += self.generate_vendor_avp(700, "c0", 10415, public_identity_avp)                                          #Username (IMSI)

        response = self.generate_diameter_packet("01", "c0", 306, 16777217, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet

        return response

    #3GPP S13 - ME-Identity-Check Request
    def Request_16777252_324(self, imsi, imei, software_version):
        avp = ''
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID for S13
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'eir.localdomain'),'ascii'))                 #Destination Host
        imei = self.generate_vendor_avp(1402, "c0", 10415, str(binascii.hexlify(str.encode(imei)),'ascii'))
        software_version = self.generate_vendor_avp(1403, "c0", 10415, self.string_to_hex(software_version))
        avp += self.generate_vendor_avp(1401, "c0", 10415, imei + software_version)                                          #Terminal Information
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        response = self.generate_diameter_packet("01", "c0", 324, 16777252, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP SLg - Provide Subscriber Location Request
    def Request_16777255_8388620(self, imsi):
        avp = ''
        #ToDo - Update the Vendor Specific Application ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'mme-slg.localdomain'),'ascii'))                 #Destination Host        
        #SLg Location Type AVP
        avp += self.generate_vendor_avp(2500, "c0", 10415, "00000000")
        #Username (IMSI)
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        #LCS-EPS-Client-Name
        LCS_EPS_Client_Name = self.generate_vendor_avp(1238, "c0", 10415, str(binascii.hexlify(b'PyHSS GMLC'),'ascii'))    #LCS Name String
        LCS_EPS_Client_Name += self.generate_vendor_avp(1237, "c0", 10415, "00000002")     #LCS Format Indicator
        avp += self.generate_vendor_avp(2501, "c0", 10415, LCS_EPS_Client_Name)
        #LCS-Client-Type (Emergency Services)
        avp += self.generate_vendor_avp(1241, "c0", 10415, "00000000")
        response = self.generate_diameter_packet("01", "c0", 8388620, 16777255, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP SLh - Provide Subscriber Location Request
    def Request_16777291_8388622(self, **kwargs):
        avp = ''
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777252),"x").zfill(8))   #Auth-Application-ID S13
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm

        sessionid = str(bytes.fromhex(self.OriginHost).decode('ascii')) + self.generate_id(5) + ';1;app_slh'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        
        #Username (IMSI)
        if 'imsi' in kwargs:
            avp += self.generate_avp(1, 40, self.string_to_hex(str(kwargs.get('imsi'))))                                             #Username (IMSI)
        
        #MSISDN (Optional)
        if kwargs.get('msisdn'):
            avp += self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(kwargs.get('msisdn'))))                                             #MSISDN

        #GMLC Address
        avp += self.generate_vendor_avp(2405, 'c0', 10415, self.ip_to_hex('127.0.0.1'))                      #GMLC-Address

        response = self.generate_diameter_packet("01", "c0", 8388622, 16777291, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Gx - Credit Control Request
    def Request_16777238_272(self, imsi, apn, ccr_type, destinationHost, destinationRealm, sessionId=None):
        avp = ''
        if sessionId == None:
            sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_gx'                           #Session state generate
        else:
            sessionid = sessionId
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx

        #CCR Type
        avp += self.generate_avp(416, 40, format(int(ccr_type),"x").zfill(8))
        avp += self.generate_avp(415, 40, format(int(0),"x").zfill(8))

        #Subscription ID
        Subscription_ID_Data = self.generate_avp(444, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))
        Subscription_ID_Type = self.generate_avp(450, 40, format(int(1),"x").zfill(8))
        avp += self.generate_avp(443, 40, Subscription_ID_Type + Subscription_ID_Data)

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "0000000b")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP

        avp += self.generate_vendor_avp(1024, 80, 10415, self.int_to_hex(1, 4))                 #Network Requests Supported
        
        avp += self.generate_avp(8, 40, binascii.b2a_hex(os.urandom(4)).decode('utf-8'))        #Framed IP Address Randomly Generated

        avp += self.generate_vendor_avp(1027, 'c0', 10415, self.int_to_hex(5, 4))                 #IP CAN Type (EPS)
        avp += self.generate_vendor_avp(1032, 'c0', 10415, self.int_to_hex(1004, 4))              #RAT-Type (EUTRAN)
        #Default EPS Bearer QoS
        avp += self.generate_vendor_avp(1049, 80, 10415, 
            '0000041980000058000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001')
        #3GPP-User-Location-Information
        avp += self.generate_vendor_avp(22, 80, 10415, 
            '8205f539007b05f53900000001')
        avp += self.generate_vendor_avp(23, 80, 10415, '00000000')                              #MS Timezone

        #Called Station ID (APN)
        avp += self.generate_avp(30, 40, str(binascii.hexlify(str.encode(apn)),'ascii'))

        response = self.generate_diameter_packet("01", "c0", 272, 16777238, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Gx - Re Auth Request
    def Request_16777238_258(self, sessionId, servingPgw, servingRealm, chargingRules=None, ueIp=None, chargingRuleAction='install', chargingRuleName=None):
        avp = ''
        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Request_16777238_258] [RAR] Creating Re Auth Request", redisClient=self.redisMessaging)

        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionId)),'ascii'))          #Session-Id set AVP

        #Setup Charging Rule
        self.logTool.log(service='HSS', level='debug', message=chargingRules, redisClient=self.redisMessaging)
        if chargingRules is not None and ueIp is not None:
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Request_16777238_258] [RAR] Charging Rules: {chargingRules}", redisClient=self.redisMessaging)
            avp += self.Charging_Rule_Generator(ChargingRules=chargingRules, ue_ip=ueIp)
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Request_16777238_258] [RAR] Generated Charging Rules", redisClient=self.redisMessaging)
        elif chargingRuleName is not None and chargingRuleAction == 'remove':
            avp += self.Charging_Rule_Generator(action=chargingRuleAction, chargingRuleName=chargingRuleName)
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Request_16777238_258] [RAR] Removing Charging Rule: {chargingRuleName}", redisClient=self.redisMessaging)

        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(293, 40, self.string_to_hex(servingPgw))                                               #Destination Host
        avp += self.generate_avp(283, 40, self.string_to_hex(servingRealm))                                               #Destination Realm
       
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        
        avp += self.generate_avp(285, 40, format(int(0),"x").zfill(8))   #Re-Auth Request TYpe

        response = self.generate_diameter_packet("01", "c0", 258, 16777238, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Gy - Credit Control Request
    def Request_4_272(self, sessionid, imsi, CC_Request_Type, input_octets, output_octets):
        avp = ''
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session-Id set AVP

        avp += self.generate_avp(264, 40, self.OriginHost)                                                  #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                 #Origin Realm
        avp += self.generate_avp(283, 40, self.OriginRealm)                                                 #Destination Realm
       
        avp += self.generate_avp(258, 40, format(int(4),"x").zfill(8))                                      #Auth-Application-ID Gx
        avp += self.generate_avp(461, 40, self.string_to_hex("open5gs-smfd@open5gs.org"))                   #Service Context ID
        avp += self.generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                                      #CC Request Type
        avp += self.generate_avp(415, 40, format(int(0),"x").zfill(8))                                      #CC Request Number
        avp += self.generate_avp(55, 40, '00000000')                                                        #Event Timestamp

        #Subscription ID
        Subscription_ID_Data = self.generate_avp(444, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))
        Subscription_ID_Type = self.generate_avp(450, 40, format(int(1),"x").zfill(8))
        avp += self.generate_avp(443, 40, Subscription_ID_Type + Subscription_ID_Data)

        avp += self.generate_avp(436, 40, format(int(0),"x").zfill(8))                                      #Requested Action (Direct Debiting)

        avp += self.generate_vendor_avp(2055, 'c0', 10415, "00000001")                                        #AoC_FULL (1)

        avp += self.generate_avp(455, 40, format(int(0),"x").zfill(8))                                      #Multiple Services Indicator (Not Supported)
        if int(CC_Request_Type) == 1:
            mscc = ''                                                                                       #Multiple Services Credit Control
            mscc += self.generate_avp(437, 40, '')                                                          #Requested Service Unit
            used_service_unit = ''
            used_service_unit += self.generate_avp(420, 40, format(int(0),"x").zfill(8))                    #Time
            used_service_unit += self.generate_avp(412, 40, format(int(0),"x").zfill(16))                    #Input Octets
            used_service_unit += self.generate_avp(414, 40, format(int(0),"x").zfill(16))                    #Output Octets
            mscc += self.generate_avp(446, 40, used_service_unit)                                           #Used Service Unit
            mscc += self.generate_vendor_avp(1016, 'c0', 10415,                                             #QoS Information
                "00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000090000041780000010000028af000000000000041880000010000028af000000000000041180000010000028af061a80000000041080000010000028af061a8000")
            mscc += self.generate_vendor_avp(21, 'c0', 10415, '000028af')                                   #3GPP RAT Type (WB-EUTRAN)
            avp += self.generate_avp(456, 40, mscc)

        elif int(CC_Request_Type) == 2:
            mscc = ''                                                                                       #Multiple Services Credit Control
            mscc += self.generate_avp(437, 40, '')                                                          #Requested Service Unit
            used_service_unit = ''
            used_service_unit += self.generate_avp(420, 40, format(int(0),"x").zfill(8))                    #Time
            used_service_unit += self.generate_avp(412, 40, format(int(input_octets),"x").zfill(16))        #Input Octets
            used_service_unit += self.generate_avp(414, 40, format(int(output_octets),"x").zfill(16))       #Output Octets
            mscc += self.generate_avp(446, 40, used_service_unit)                                           #Used Service Unit
            mscc += self.generate_vendor_avp(872, 'c0', 10415, format(int(4),"x").zfill(8))                 #3GPP Reporting Reason (Validity Time (4))
            mscc += self.generate_vendor_avp(1016, 'c0', 10415,                                             #QoS Information
                "00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000090000041780000010000028af000000000000041880000010000028af000000000000041180000010000028af061a80000000041080000010000028af061a8000")
            mscc += self.generate_vendor_avp(21, 'c0', 10415, '000028af')                                   #3GPP RAT Type (WB-EUTRAN)
            avp += self.generate_avp(456, 40, mscc)
        elif int(CC_Request_Type) == 3:
            #Multiple Services Credit Control
            avp += self.generate_avp(456, 40,  
            "000001be40000034000001a44000000c000000000000019c4000001000000000000000000000019e40000010000000000000000000000368c0000010000028af00000002000003f8c0000078000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000020000041780000010000028af000000010000041880000010000028af000000000000041180000010000028af020000000000041080000010000028af0320000000000015c000000d000028af06000000")

                                                                                                            #Service Information
        avp += self.generate_vendor_avp(873, 'c0', 10415, 
        "0000036ac00000d8000028af00000002c0000010000028af0000010400000003c0000010000028af00000000000004cbc0000012000028af00010a2d01050000000004ccc0000012000028af0001ac1212ca00000000034fc0000012000028af0001ac12120400000000001e40000010696e7465726e65740000000cc000000d000028af300000000000000dc0000010000028af3030303000000012c0000011000028af30303130310000000000000ac000000d000028af0100000000000016c0000019000028af8200f110000100f11000000017000000")
        response = self.generate_diameter_packet("01", "c0", 272, 4, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Sh - Profile Update Request
    def Request_16777217_307(self, msisdn):
        avp = ''                                         
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_sh'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777217),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.string_to_hex('ExamplePGW.com'))                          #Origin Host
        avp += self.generate_avp(283, 40, self.OriginRealm)                                              #Destination Realm
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm

        self.logTool.log(service='HSS', level='debug', message="Getting subscriber IMS info based on MSISDN", redisClient=self.redisMessaging)
        subscriber_ims_details = self.database.Get_IMS_Subscriber(msisdn=msisdn)
        self.logTool.log(service='HSS', level='debug', message="Got subscriber IMS details: " + str(subscriber_ims_details), redisClient=self.redisMessaging)
        self.logTool.log(service='HSS', level='debug', message="Getting subscriber info based on MSISDN", redisClient=self.redisMessaging)
        subscriber_details = self.database.Get_Subscriber(msisdn=msisdn)
        self.logTool.log(service='HSS', level='debug', message="Got subscriber details: " + str(subscriber_details), redisClient=self.redisMessaging)
        subscriber_details = {**subscriber_details, **subscriber_ims_details}
        self.logTool.log(service='HSS', level='debug', message="Merged subscriber details: " + str(subscriber_details), redisClient=self.redisMessaging)

        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(subscriber_details['imsi'])),'ascii'))                 #Username AVP

        #Sh-User-Data (XML)
        #This loads a Jinja XML template containing the Sh-User-Data
        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader)
        sh_userdata_template = config['hss']['Default_Sh_UserData']
        self.logTool.log(service='HSS', level='debug', message="Using template " + str(sh_userdata_template) + " for SH user data", redisClient=self.redisMessaging)
        template = templateEnv.get_template(sh_userdata_template)
        #These variables are passed to the template for use
        subscriber_details['mnc'] = self.MNC.zfill(3)
        subscriber_details['mcc'] = self.MCC.zfill(3)

        self.logTool.log(service='HSS', level='debug', message="Rendering template with values: " + str(subscriber_details), redisClient=self.redisMessaging)
        xmlbody = template.render(Sh_template_vars=subscriber_details)  # this is where to put args to the template renderer
        avp += self.generate_vendor_avp(702, "c0", 10415, str(binascii.hexlify(str.encode(xmlbody)),'ascii'))
        
        response = self.generate_diameter_packet("01", "c0", 307, 16777217, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S13 - ME-Identity-Check Request
    def Request_16777252_324(self, imei, imsi):
        avp = ''                                         
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_s13'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.string_to_hex('ExamplePGW.com'))                          #Origin Host
        avp += self.generate_avp(283, 40, self.OriginRealm)                                              #Destination Realm
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        
        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))                 #Username AVP
        TerminalInformation = ''
        TerminalInformation += self.generate_vendor_avp(1402, 'c0', 10415, str(binascii.hexlify(str.encode(imei)),'ascii'))
        TerminalInformation += self.generate_vendor_avp(1403, 'c0', 10415, str(binascii.hexlify(str.encode('00')),'ascii'))
        avp += self.generate_vendor_avp(1401, 'c0', 10415, TerminalInformation)


        response = self.generate_diameter_packet("01", "c0", 324, 16777252, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
