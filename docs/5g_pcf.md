# 5G PCF (Npcf)

`pyhss_pcf` (`services/pcfService.py`) makes PyHSS a 5G **Policy Control Function** (PCF). It
serves three SBI services over HTTP/2 cleartext (h2c) and registers at the NRF as an NF of type
`PCF`. Use it together with [`pyhss_udr`](5g_udr.md) as a replacement for `open5gs-pcfd`. Open5GS'
PCF also reads subscribers from MongoDB, `pyhss_pcf` doesn't, so no MongoDB is needed.

| Service | Consumer | |
|---|---|---|
| `npcf-am-policy-control` | AMF | UE-AMBR check at registration |
| `npcf-smpolicycontrol` | SMF | Session AMBR, default QoS and PCC rules of a PDU session |
| `npcf-policyauthorization` | AF | Dedicated QoS flows for media |

No BSF is needed. Open5GS' PCF registers its sessions there so that an AF can discover the PCF,
but the AMF and SMF never query it. An AF talks directly to `pyhss_pcf`, or uses Rx.

## Policy

Everything comes from the PyHSS database:

| 5G | PyHSS |
|---|---|
| UE-AMBR | `SUBSCRIBER.ue_ambr_ul/dl` |
| Session AMBR | `APN.apn_ambr_ul/dl` |
| Default 5QI, ARP | `APN.qci`, `APN.arp_priority`, `arp_preemption_capability/vulnerability` |
| PCC rules of a session | `APN.charging_rule_list`: `CHARGING_RULE` with its `TFT`s |

A DNN needs a QCI, ARP priority and APN-AMBR, like for the [UDR](5g_udr.md). Otherwise the SM
policy is denied with 403 `POLICY_CONTEXT_DENIED`, as it is for a DNN the subscriber doesn't have
and for a disabled subscriber.

The AMF and SMF send what they got from the UDM. As that comes from the same APN, the PCF
normally changes nothing. If a value differs, it sets the `UE_AMBR_CH`, `SE_AMBR_CH` or
`DEF_QOS_CH` trigger, without which Open5GS ignores it.

## VoNR

```
 P-CSCF ── Rx AAR/STR ── pyhss_diameter ── pyhss_hss ─┐ redis: session lookup, commands
 AF ── Npcf_PolicyAuthorization ─────── pyhss_pcf <───┘
                                           └── SM policy UpdateNotify ── SMF ── QoS flow
```

Set `pcf.rx_enabled` for `pyhss_hss` to answer Rx. An AAR or STR is handled by the PCF if
`pcf.ims_dnn` has an SM policy for its Framed-IP-Address, so if the UE is on NR. Anything else
takes the existing Gx path. So a P-CSCF that sends all Rx to PyHSS keeps working for 4G only if
PyHSS is also its PCRF; if Open5GS' PCRF serves 4G, send only the Rx of NR sessions to PyHSS.

`pyhss_hss` answers the AAR right away with 2001 and queues the request for `pyhss_pcf`, which
sends the PCC rule to the SMF. The order of the requests is kept, so a failure to reach the SMF
is only logged, not returned to the P-CSCF.

| Media | 5QI | ARP | Default bandwidth |
|---|---|---|---|
| Audio | 1 | 2, may preempt | 128 Kbps |
| Video | 2 | 4, may preempt | 512 Kbps |

Change these under `pcf.qos`. Other media, including `CONTROL` for IMS signalling, gets no flow.
The GBR is the requested minimum, or else the requested maximum. The MBR is the requested
maximum plus the RS and RR bandwidths. Each media component becomes one PCC rule with all of its
flows, and a later AAR updates it. Flows are converted like Open5GS does: the SMF expects
`permit out`, so `permit in` becomes an uplink flow with source and destination swapped.

Not implemented:

- IPv6: UEs are only found by their IPv4 address.
- Rx event reporting and ASR: the P-CSCF isn't told if the PDU session goes away. Its QoS flows go
  with the session and a later STR is simply answered.
- Npcf_PolicyAuthorization events and PCSCF restoration.
- Emergency sessions in the PCF.

## State

Sessions are kept in redis under `pcf:`, without an expiry. A new session for a UE IP replaces a
stale one. `pyhss_pcf` is stateless otherwise and can be restarted at any time, but if redis loses
its data, the existing sessions get no more QoS flows until they are set up again.

## Configuration

See the `pcf:` section in `config.yaml`:

| Setting | |
|---|---|
| `bind_ip`, `bind_port` | Where the services are served (h2c) |
| `advertise_ip` | IP in the Location headers and at the NRF, where the AMF/SMF/SCP reach the PCF |
| `nf_instance_id` | Fixed NF instance ID. If unset, it is derived from the hostname and port |
| `api_versions` | Open5GS uses `v1` |
| `rx_enabled` | Handle Rx in `pyhss_hss`, restart it after changing this |
| `ims_dnn` | DNN where sessions without a DNN, so all of Rx, are looked up |
| `qos` | 5QI, ARP priority, precedence and default bandwidth per media type |
| `nrf.*` | As for the [UDR](5g_udr.md#configuration) |

## Using it with Open5GS

1. Stop `open5gs-pcfd` and `open5gs-udrd`. MongoDB, `open5gs-bsfd` and the WebUI are not needed.
2. Set up [`pyhss_udr`](5g_udr.md), and configure `pyhss_pcf` the same way, then start it.
3. Give the IMS APN QCI 5 and set `pcf.rx_enabled` for VoNR.

```sh
curl --http2-prior-knowledge http://<advertise_ip>:7777/npcf-smpolicycontrol/v1/sm-policies/<id>
redis-cli --scan --pattern 'pcf:*'
```

## Open5GS' requirements

These go beyond the specs (read in Open5GS 2.7.7 `src/amf/npcf-handler.c`,
`src/smf/npcf-handler.c`, `src/smf/smf-sm.c`):

- The AMF needs a 201, a `Location` with the association ID as last path component and `suppFeat`,
  even when it is 0.
- The SMF needs a 201 and the same `Location`. It uses that URI for `/delete`.
- `QosData.arp` needs both preemption values, the SMF asserts on them.
- A PCC rule's first `refQosData` entry must be in `qosDecs` of the same decision.
- To remove a rule, the decision has `{"pccRules": {"<id>": null}}`. The OpenAPI schema does not
  allow the null, the text of TS 29.512 clause 4.2.6 does, so it is built without the models.
- `SmPolicyNotification` goes to `<notificationUri>/update`.
