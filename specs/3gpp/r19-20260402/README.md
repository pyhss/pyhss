# 3GPP 5GC OpenAPI specifications (Release 19)

These are the 3GPP OpenAPI files the PyHSS SBI services (`pyhss_udr`) are built from.
`lib/sbi/models/` is generated from them with `tools/gen_sbi_models.sh`, and the tests
validate the PyHSS SBI requests and responses against them.

## Provenance

The files are **unmodified copies** of the "standard" spec set that Open5GS uses.
PyHSS and the Open5GS network functions therefore implement the same API definitions.

| | |
|---|---|
| Repository | https://github.com/open5gs/open5gs |
| Tag | `v2.8.0` (commit `157f611a530e292e40ec50f9d23f0ef5d4fcd6a6`) |
| Directory | `lib/sbi/support/r19-20260402-openapitools-7.20.0/standard/` |
| Upstream origin | 3GPP 5G APIs, https://forge.3gpp.org/rep/all/5G_APIs (Release 19) |

`SHA256SUMS` lists the checksum of every file.

Root files, with the transitive closure of their cross-file `$ref`s:

| File | Specification | API version |
|---|---|---|
| `TS29504_Nudr_DR.yaml` | TS 29.504 V19.6.0, Nudr_DataRepository | 2.4.1 |
| `TS29505_Subscription_Data.yaml` | TS 29.505 V19.5.0, Usage of the UDR service for subscription data | - |
| `TS29519_Policy_Data.yaml` | TS 29.519 V19.5.0, Usage of the UDR service for policy data | - |
| `TS29503_Nudm_UEAU.yaml` | TS 29.503, Nudm_UEAuthentication (`AuthEvent`) | 1.4.0 |
| `TS29503_Nudm_UECM.yaml` | TS 29.503, Nudm_UEContextManagement (`Amf3GppAccessRegistration`, `SmfRegistration`) | 1.4.1 |
| `TS29510_Nnrf_NFManagement.yaml` | TS 29.510 V19.6.0, Nnrf_NFManagement | 1.4.1 |
| `TS29571_CommonData.yaml` | TS 29.571, Common Data Types | 1.6.1 |

## Updating

```sh
tools/fetch_3gpp_specs.py          # edit OPEN5GS_TAG/OPEN5GS_COMMIT/SPEC_DIR first
tools/gen_sbi_models.sh            # regenerate lib/sbi/models/
```

## Copyright

The specification files are © 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI,
TSDSI, TTA, TTC); see the `info.description` field in each file. They are **not** covered
by the PyHSS AGPL licence. They are redistributed here unmodified for interoperability,
the same way Open5GS, free5GC and OAI redistribute them.
