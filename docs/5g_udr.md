# 5G UDR (Nudr_DataRepository)

`pyhss_udr` (`services/udrService.py`) makes PyHSS a 5G **Unified Data Repository** (UDR). It
serves the Nudr_DataRepository API (3GPP TS 29.504) over HTTP/2 cleartext (h2c) and registers
at the NRF as an NF of type `UDR`. Use it, for example, as the subscriber database of
[Open5GS](https://open5gs.org) in 5G SA mode instead of `open5gs-udrd`.

4G and 5G use **the same subscribers**: the same `AUC` and `SUBSCRIBER` rows, including the
shared SQN. A subscriber provisioned for S6a works for 5G too, as long as one of its APNs has a
QCI, ARP and APN-AMBR.

```
   UE ── gNB ── AMF ── AUSF ── UDM ──┐ Nudr (HTTP/2, h2c)
                 │                   ├──────────────────── pyhss_udr ── PyHSS DB ── S6a (pyhss_hss)
                 SMF ─── PCF ────────┘                        │
                                                         NRF (via SCP)
```

## Scope

PyHSS is **only the UDR**. The UDM generates the 5G-AKA vectors, including the SQN handling,
and deconceals SUCIs. The home network keys for SUCI Profile A/B therefore stay configured in
the UDM (Open5GS `udm.yaml`, `hnet:`).

Resources served (prefix `/nudr-dr/{v1|v2}`):

| Resource | Methods | Data source |
|---|---|---|
| `/subscription-data/{ueId}/authentication-data/authentication-subscription` | GET, PATCH (SQN resync) | `AUC` |
| `/subscription-data/{ueId}/authentication-data/authentication-status` | PUT, DELETE | `AUC.sqn` |
| `/subscription-data/{ueId}/context-data/amf-3gpp-access` | PUT, PATCH (`purgeFlag`) | `SUBSCRIBER.serving_amf` |
| `/subscription-data/{ueId}/context-data/smf-registrations/{pduSessionId}` | PUT, DELETE | logged only |
| `/subscription-data/{ueId}/{servingPlmnId}/provisioned-data` | GET | the three below |
| `…/provisioned-data/am-data` | GET | UE-AMBR, MSISDN, S-NSSAIs of the APNs |
| `…/provisioned-data/smf-selection-subscription-data` | GET | DNNs per S-NSSAI |
| `…/provisioned-data/sm-data` | GET | DNN configurations |
| `/policy-data/ues/{ueId}/am-data` | GET | (empty) |
| `/policy-data/ues/{ueId}/sm-data` | GET | DNNs per S-NSSAI |

Only IMSI-based SUPIs (`imsi-<digits>`) are supported. Other identities get 404 `USER_NOT_FOUND`.

## Mapping PyHSS data to 5G

| 5G | PyHSS |
|---|---|
| K, OPc, AMF, SQN | `AUC.ki`, `AUC.opc`, `AUC.amf`, `AUC.sqn` (`encPermanentKey`/`encOpcKey` are sent unencrypted, as Open5GS expects) |
| GPSI | `msisdn-` + `SUBSCRIBER.msisdn` |
| Subscribed UE-AMBR | `SUBSCRIBER.ue_ambr_ul/dl` (bps). With both 0, `am-data` is 404, as in Open5GS |
| DNN | `APN.apn`, for the subscriber's `default_apn` (the default DNN) and `apn_list` |
| S-NSSAI of a DNN | `APN.sst`/`APN.sd`. Unset: `udr.default_snssai` |
| Default S-NSSAI | The S-NSSAI of the default APN |
| 5QI, ARP | `APN.qci`, `APN.arp_priority`, `arp_preemption_capability/vulnerability` |
| Session AMBR | `APN.apn_ambr_ul/dl` (bps) |
| PDU session types | `APN.ip_version`: 0 is IPv4, 1 is IPv6, 2/3 is IPv4v6 (default) with IPv4 and IPv6 also allowed |
| SSC modes | SSC mode 1 is the default, modes 2 and 3 are also allowed |
| Static UE IP | `SUBSCRIBER_ROUTING.ip_address` |

An APN without a QCI, ARP priority or APN-AMBR can't be used for 5G. It is skipped and a warning
is logged.

Example: an APN for slice SST 2 / SD `0000ab`:

```sh
curl -X PUT http://localhost:8080/apn/ -H 'Content-Type: application/json' -d '{
  "apn": "iot", "ip_version": 0, "sst": 2, "sd": "0000ab",
  "apn_ambr_dl": 10000000, "apn_ambr_ul": 10000000,
  "qci": 9, "arp_priority": 8, "arp_preemption_capability": false, "arp_preemption_vulnerability": true}'
```

## SQN handling

The SQN is shared between S6a (4G) and 5G:

- **S6a AIR:** the vector uses the stored SQN, then PyHSS stores SQN + 100 (unchanged).
- **5G authentication:**
  1. The UDM reads the SQN with a GET and generates the vector from it.
  2. After authentication, its PUT to `authentication-status` adds 32. Open5GS' UDR does the
     same, and its UDM relies on it.
- **5G resync:** the UDM verifies the AUTS and PATCHes `/sequenceNumber/sqn`. PyHSS stores the
  new value + 32.
  - With `udr.sqn_patch_policy: max` (the default), the SQN never moves backwards. A 5G resync
    therefore can't undo SQNs that S6a has handed out since.
  - With `set`, the value is overwritten, as Open5GS' UDR does.

SQN updates are atomic (row lock) and are propagated via geored, like `Update_AuC`.

## Configuration

See the `udr:` section in `config.yaml`. For Docker, set the `UDR_*` variables in
`docker/.env` and start the `5g` profile: `docker compose --profile 5g up`. The important settings:

| Setting | |
|---|---|
| `bind_ip`, `bind_port` | Where Nudr_DR is served (h2c) |
| `advertise_ip` | IP registered at the NRF, where the UDM/PCF/SCP reach the UDR |
| `nf_instance_id` | Fixed NF instance ID. If unset, it is derived from the hostname and port, so a restart replaces the old registration |
| `api_versions` | Open5GS 2.8.0 calls `v1`. TS 29.504 Release 19 defines `v2`. Both are served by default |
| `default_snssai` | S-NSSAI of APNs without `sst` |
| `nrf.enabled`, `nrf.uri` | Register at this NRF |
| `nrf.via_scp` | `nrf.uri` is an SCP (indirect communication, the Open5GS default). The 3gpp-Sbi-Discovery headers are added |
| `nrf.send_plmn_list` | Register `hss.MCC/MNC` as plmnList. Open5GS' NRF rejects PLMNs it doesn't serve |

## Using it with Open5GS 2.8.0

1. Stop `open5gs-udrd`. Otherwise UDM and PCF pick one of the two UDRs at random.
2. Configure `pyhss_udr`: set `advertise_ip`, then either point `nrf.uri` at the NRF, or at the
   SCP with `nrf.via_scp: True`. Then start it after `pyhss_hss`.
3. Provision subscribers through the PyHSS API: APN (with `sst`), AUC and SUBSCRIBER.
4. **Keep provisioning the subscribers in MongoDB as well.** The Open5GS 2.8.0 PCF asks the
   UDR for policy data, but then also reads the subscriber directly from MongoDB
   (`src/pcf/nudr-handler.c`). Without it, the AM policy association fails and with it the
   registration.

Verify:

```sh
curl --http2-prior-knowledge \
  http://<advertise_ip>:7777/nudr-dr/v1/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription
```

## Spec conformance

All bodies are built and validated with pydantic models generated from the 3GPP OpenAPI
specifications. These are the Release 19 set Open5GS 2.8.0 uses, vendored unmodified in
`specs/3gpp/r19-20260402/`.

- **Request bodies** with errors are answered with 400 and a `ProblemDetails` body.
- **Tests** (`tests/test_udr_app.py`, `tests/test_nrf_client.py`):
  - validate every request and response with `openapi-core` against the vendored specs
  - check that every route's path, method and operationId exist in TS 29.504

To update the specs or the generator:

```sh
tools/fetch_3gpp_specs.py                    # adjust OPEN5GS_TAG/COMMIT/SPEC_DIR first
pip install -r requirements-dev.txt          # pinned datamodel-code-generator
tools/gen_sbi_models.py                      # regenerates lib/sbi/models/
pytest tests/test_sbi_models.py              # checks that the committed models are up to date
```

`gen_sbi_models.py` documents how it bundles the needed schemas and the few 3GPP constructs it
simplifies for the generator.

Where Open5GS 2.8.0 and the specs differ:

- **API version:** Open5GS uses `/nudr-dr/v1`, while the R19 spec has `v2`. Both are served.
- **201 vs 204:** Open5GS accepts only 204 for the context-data PUTs. 204 is also allowed by the
  spec, so PyHSS always sends it.
- **Required fields:** Open5GS requires `encPermanentKey`, `encOpcKey`,
  `authenticationManagementField` and `sequenceNumber` in AuthenticationSubscription. They are
  optional in the spec, but PyHSS always sends them.
- **`allowedSscModes`:** Open5GS' own UDR sends three entries, which violates TS 29.503
  (`maxItems: 2`, the modes allowed besides the default). PyHSS sends the spec-compliant
  `["SSC_MODE_2", "SSC_MODE_3"]`, which the Open5GS SMF accepts.
- **SQN increment:** the SQN +32 on `authentication-status` follows Open5GS. The spec doesn't
  define this.
