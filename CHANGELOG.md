# Changelog

All notable changes to PyHSS are documented in this file, beginning from [Service Overhaul #168](https://github.com/nickvsnetworking/pyhss/pull/168).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Find a subscriber by MSISDN when the Cx Username AVP is a SIP or tel
  URI with parameters (e.g. `;phone-context=`, `;user=phone`): the
  identity is now parsed the same way as in Sh UDR, so the digits reach
  the lookup. Previously the parameters stayed attached, the lookup
  failed with `Experimental-Result-Code` 5001, and the LIA had no
  `Server-Name` for the I-CSCF to route to.

### Added

- 5G UDR: the new `pyhss_udr` service serves Nudr_DataRepository (3GPP TS 29.504) over HTTP/2
  cleartext and registers at the NRF, so PyHSS can be the subscriber database of e.g.
  Open5GS in 5G SA. 4G and 5G share the subscribers and the SQN. See
  [docs/5g_udr.md](docs/5g_udr.md).
- The SBI models (`lib/sbi/models/`) are generated from the 3GPP Release 19 OpenAPI specs,
  which are vendored in `specs/3gpp/`. The tests validate the UDR against these specs.
- Database schema version 2: `apn.sst`, `apn.sd` (S-NSSAI of an APN/DNN) and
  `subscriber.serving_amf`, `subscriber.serving_amf_timestamp`. Existing databases are
  upgraded automatically.

## [2.0.1] - 2026-10-14

### Fixed

- Fix `RuntimeError: dictionary changed size during iteration` in the diameter
  service when peers connect or disconnect while `activePeers` is being
  iterated ([#310](https://github.com/nickvsnetworking/pyhss/issues/310)).
- Fix Diameter requests that were lost when a message was split across TCP
  reads: the diameter service now queues only complete messages, framed by the
  Message Length in the Diameter header
  ([#341](https://github.com/nickvsnetworking/pyhss/pull/341)).
- Fix inbound Diameter requests being processed newest first: the HSS service
  now takes them from the queue in the order they arrived, so under load the
  oldest request no longer waits for the whole backlog
  ([#342](https://github.com/nickvsnetworking/pyhss/pull/342)).
- Find a subscriber by MSISDN whether it is stored with or without a leading
  `+`. The lookup is in `Get_Subscriber()` and `Get_IMS_Subscriber()`, so it
  applies to every MSISDN lookup: Cx, Rx AAR, Sh UDR and PUR, and the REST
  endpoints `/subscriber/msisdn/<msisdn>` and
  `/ims_subscriber/ims_subscriber_msisdn/<msisdn>`.
- Sh UDR: accept `tel:` URIs in Public-Identity, and fall back to
  Public-Identity when the MSISDN lookup fails.
- Sh UDR: reject a User-Identity that is not a grouped AVP with
  DIAMETER_INVALID_AVP_VALUE (5004) and Failed-AVP.
- Dependencies: pin bitstring to <5 as the recently released version 5 is
  incompatible with smspdudecoder 2.2.0

## [2.0.0] - 2026-08-17

### Added

- 2G / 3G support via Osmocom GSUP.
- Support for running PyHSS services in Docker containers and provide official
  Docker images.
- Database types postgresql and sqlite.
- Config loading from `/etc/pyhss/config.yaml`, `/usr/share/pyhss/config.yaml`,
  the `PYHSS_CONFIG` env var, or (old behavior) `config.yaml` at the top of the
  source tree, depending on which is available.
- Running services outside of the source tree.
- Building PyHSS with `python3 -m build` and as debian package.
- RAT restriction checking for subscribers.
- Automatic database upgrades (from 1.0.1 or higher).
- Allow users to configure `hss.roaming.inbound.reject_unknown_imsis_with` to
  either `IMSI_UNKNOWN` (default) or `ROAMING_NOT_ALLOWED`.

### Changed

- Set the default database backend to SQLite.
- Remove mysqlclient from requirements.txt. If you want to use PyHSS with
  MySQL, install mysqlclient or another MySQL/MariaDB library that SQLAlchemy
  supports manually (see [DBAPI
  Support](https://docs.sqlalchemy.org/en/latest/dialects/mysql.html#dialect-mysql)).
- Change the default bind IP from 0.0.0.0 to 127.0.0.1.
- Raise minimum Python version from 3.9 to 3.11.
- When logging to journalctl through systemd services, PyHSS doesn't add a
  redundant timestamp anymore.

### Removed

- Unused options from config.yaml.
- Debug prints in API service.

### Fixed

- Fix unit tests and run them with pytest in CI.
- Let services/apiService return HTTP status code 500 on errors instead of 200.

## [1.0.2] - 2024-07-03

### Added

- Configurable DWRs sendable to connected peers.
- Configurable outbound roaming rules on a per-network and per-subscriber basis.
- /pcrf/clr_subscriber for ease of use.
- Support for OCS webhook notifications on CCR-I and CCR-T.

### Fixed

- Removed '+' from MSISDNs when storing in the database.
- CCR-based logical bug when emergency attach procedure is performed.
- Repeated ECRs leaking open SQL sessions.
- Forced string evaluation for tacDatabasePath.

## [1.0.1] - 2024-01-23

### Removed

 - Assert on missing "IMS Services" for AAA/Audio Request

### Changed

- Reduced verbosity of failing subscriber lookups to debug
- Added CORS headers: [Zarya/171](https://github.com/nickvsnetworking/pyhss/pull/171)
- Gx RAR now dynamically creates TFT up to 512k based on UE request.
- SQN Resync now propogates via Geored when enabled 
- Renamed sh_profile to xcap_profile in ims_subscriber
- Rebuilt keys using unique namespace for redis-sentinel / stateless compatibility.
- The database schema was changed as follows. If you have a PyHSS database
  created with version 1.0.0 that you would like to use with 1.0.1 or newer,
  apply these changes manually. Newer versions of PyHSS have automatic database
  migrations.
<details>

```diff
--- a/release_1.0.0.sql
+++ b/release_1.0.1.sql
@@ -13,6 +13,12 @@ CREATE TABLE apn (
 	arp_preemption_capability BOOLEAN,
 	arp_preemption_vulnerability BOOLEAN,
 	charging_rule_list VARCHAR(18),
+	nbiot BOOLEAN,
+	nidd_scef_id VARCHAR(512),
+	nidd_scef_realm VARCHAR(512),
+	nidd_mechanism INTEGER,
+	nidd_rds INTEGER,
+	nidd_preferred_data_mode INTEGER,
 	last_modified VARCHAR(100),
 	PRIMARY KEY (apn_id)
 );
@@ -80,22 +86,40 @@ CREATE TABLE eir_history (
 	PRIMARY KEY (imsi_imei_history_id),
 	UNIQUE (imsi_imei)
 );
 CREATE TABLE ims_subscriber (
 	ims_subscriber_id INTEGER NOT NULL,
 	msisdn VARCHAR(18),
 	msisdn_list VARCHAR(1200),
 	imsi VARCHAR(18),
-	ifc_path VARCHAR(18),
+	ifc_path VARCHAR(512),
 	pcscf VARCHAR(512),
 	pcscf_realm VARCHAR(512),
 	pcscf_active_session VARCHAR(512),
 	pcscf_timestamp DATETIME,
 	pcscf_peer VARCHAR(512),
+	xcap_profile TEXT(12000),
 	sh_profile TEXT(12000),
 	scscf VARCHAR(512),
 	scscf_timestamp DATETIME,
 	scscf_realm VARCHAR(512),
 	scscf_peer VARCHAR(512),
+	sh_template_path VARCHAR(512),
 	last_modified VARCHAR(100),
 	PRIMARY KEY (ims_subscriber_id),
 	UNIQUE (msisdn)
@@ -115,6 +139,9 @@ CREATE TABLE operation_log (
 	auc_id INTEGER,
 	subscriber_id INTEGER,
 	ims_subscriber_id INTEGER,
+	roaming_rule_id INTEGER,
+	roaming_network_id INTEGER,
+	emergency_subscriber_id INTEGER,
 	charging_rule_id INTEGER,
 	tft_id INTEGER,
 	eir_id INTEGER,
@@ -127,12 +154,33 @@ CREATE TABLE operation_log (
 	FOREIGN KEY(auc_id) REFERENCES auc (auc_id),
 	FOREIGN KEY(subscriber_id) REFERENCES subscriber (subscriber_id),
 	FOREIGN KEY(ims_subscriber_id) REFERENCES ims_subscriber (ims_subscriber_id),
+	FOREIGN KEY(roaming_rule_id) REFERENCES roaming_rule (roaming_rule_id),
+	FOREIGN KEY(roaming_network_id) REFERENCES roaming_network (roaming_network_id),
+	FOREIGN KEY(emergency_subscriber_id) REFERENCES emergency_subscriber (emergency_subscriber_id),
 	FOREIGN KEY(charging_rule_id) REFERENCES charging_rule (charging_rule_id),
 	FOREIGN KEY(tft_id) REFERENCES tft (tft_id),
 	FOREIGN KEY(eir_id) REFERENCES eir (eir_id),
 	FOREIGN KEY(imsi_imei_history_id) REFERENCES eir_history (imsi_imei_history_id),
 	FOREIGN KEY(subscriber_attributes_id) REFERENCES subscriber_attributes (subscriber_attributes_id)
 );
 CREATE TABLE serving_apn (
 	serving_apn_id INTEGER NOT NULL,
 	subscriber_id INTEGER,
@@ -160,6 +208,8 @@ CREATE TABLE subscriber (
 	ue_ambr_dl INTEGER,
 	ue_ambr_ul INTEGER,
 	nam INTEGER,
+	roaming_enabled BOOLEAN,
+	roaming_rule_list VARCHAR(512),
 	subscribed_rau_tau_timer INTEGER,
 	serving_mme VARCHAR(512),
 	serving_mme_timestamp DATETIME,
```
</details>

### Fixed

- Geored failing when multiple peers defined and socket closes.
- Error in Update_Serving_MME when supplied with a NoneType timestamp.

### Added

- Support for CLR-based PCSCF restoration via `/pcrf/pcscf_restoration` and
  `/pcrf/pcscf_restoration_subscriber` in API.
- Optional immediateReattach parameter in Request_16777251_317, via CLR-Flags
- Sh-IMS-Data and IMSPrivateUserIdentity to default_sh_user_data.xml
- Optional config parameter `api.enable_insecure_auc` to allow retrieval of AuC
  keys through API
- sh_template_path in ims_subscriber
- generateUpgade.sh for generating alembic upgrade scripts
- Control of outbound roaming S6a AIR and ULA responses through roaming_rule
  and roaming_network objects.
- Roaming management on a per-subscriber basis, through
  subscriber.roaming_enabled and subscriber.roaming_rule_list.
- Support for Gx and Rx auth of unknown subscribers attaching via SOS.
- Preliminary support for SCTP.
- Additional prometheus metrics.

## [1.0.0] - 2023-09-27

### Added

 - Systemd service files for PyHSS services
 - /oam/diameter_peers endpoint
 - /oam/deregister/{imsi} endpoint
 - /geored/peers endpoint
 - /geored/webhooks endpoint
 - Dependency on Redis 7 for inter-service messaging
 - Significant performance improvements under load
 - Basic Rx support for RAA, AAA, ASA and STA
 - Rx MO call flow support (AAR -> RAR -> RAA -> AAA)
 - Dedicated bearer setup and teardown on Rx call
 - Asymmetric geored support
 - Configurable redis connection (Unix socket or TCP)
 - Basic database upgrade support in tools/databaseUpgrade
 - PCSCF state storage in ims_subscriber
 - (Experimental) Working horizontal scalability

### Changed

- Split logical functions of PyHSS into 6 service processes
- Logtool no longer handles metric processing
- Updated config.yaml
- Gx CCR-T now flushes PGW / IMS data, depending on Called-Station-Id
- Benchmarked capability of at least ~500 diameter requests per second with a
  response time of under 2 seconds on a local network.

### Fixed

 - Memory leaking in diameter.py
 - Gx CCA now supports apn inside a plmn based uri
 - AVP_Preemption_Capability and AVP_Preemption_Vulnerability now presents
   correctly in all diameter messages
 - Crash when webhook or geored endpoints enabled and no peers defined
 - CPU overutilization on all services

### Removed

- Multithreading in all services, except for metricService

[1.0.0]: https://github.com/nickvsnetworking/pyhss/releases/tag/1.0.0
[1.0.1]: https://github.com/nickvsnetworking/pyhss/releases/tag/1.0.1
[1.0.2]: https://github.com/nickvsnetworking/pyhss/releases/tag/1.0.2
[2.0.0]: https://github.com/nickvsnetworking/pyhss/releases/tag/2.0.0
[2.0.1]: https://github.com/nickvsnetworking/pyhss/releases/tag/2.0.1
