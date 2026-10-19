# PyHSS

Python Home Subscriber Server implementing Diameter / 3GPP Interfaces.
![Shelly the PyHSS Snake](docs/images/shelly.png)

## Introduction
PyHSS is a Diameter Home Subscriber Server (HSS) and Subscriber Data Management solution, used for LTE (4G) Evolved Packet Core (EPC) networks, written in Python3.

This includes support for acting as:
 - Standard HSS
 - VoLTE HSS
 - Equipment Identity Register (EIR)
 - PCRF
 - Gateway Mobile Location Centre 
 - 5G Unified Data Repository (UDR), e.g. for Open5GS in 5G SA, see [5G UDR](docs/5g_udr.md)

Supported database backends are `MySQL`, `PostgreSQL` and `SQLite`, all provisioned through a Swagger based [RESTful API](docs/API.md) for easy, safe CRUD operations on the subscriber data.

The software supports full monitoring through `Prometheus`, and has been tested to over 1m subscribers.

To support redundancy, geographic redundancy clustering is supported to allow for multiple instances running together.

The underlying library - ``diameter.py`` can be easily worked with to add support other Diameter based interfaces / protocols.


## Implemented Responses 

* Diameter Base Protocol (Ie Device-Watchdog-Request, Capabilities-Exchange-Request)
* S6a - MME / HSS Authentication of Subscribers (Ie Authentication-Information-Request, Update-Location-Request)
* S13 - MME to EIR verification of devices (Ie ME-Identity-Check-Request)
* Cx - For P/S/I/E-CSCF Authentication and Routing (Ie User-Authentication-Request, Location-Information-Request)
* SLh - For Location of Subscriber MME from GMLC (Ie LCS-Routing-Info-Answer Request)
* Sh - For Application Servers to IMS & XCAP Data
* Gx Credit Control Answer / Re-Auth Request including installing Charging Rules on demand
* Nudr_DataRepository (5G SBI, HTTP/2) - Authentication, AM/SMF selection/SM subscription and policy data for the UDM and PCF


## Usage

Basic configuration is set in the `config.yaml` file, which gets loaded from:
* The path in the `PYHSS_CONFIG` environment variable (if set)
* `/etc/pyhss/config.yaml`
* `/usr/share/pyhss/config.yaml`
* The same directory as this `README.md`

You will need to set the IP address to bind to (IPv4 or IPv6), the Diameter hostname, realm, your PLMN and transport type to use (SCTP or TCP).

The diameter service runs in a trusting mode allowing Diameter connections from any other Diameter hosts.

To perform as a functioning HSS, the following services must be run as a minimum:
- diameterService.py
- hssService.py

If you're provisioning the HSS for the first time, you'll also want to run:
 - apiService.py

The rest of the services aren't strictly necessary, however your own configuration will dictate whether or not they are required.

### Using Docker (compose)

A docker-compose file is provided to make spinning up PyHSS quick and easy. For development purposes, you can simply run:

```shell
cd docker && docker compose up --build -d 
```

This will start the following services, bound to 127.0.0.1 to avoid exposing them to the network by default:

 - PyHSS Diameter Service (Port 3868/tcp)
 - PyHSS HSS Service
 - PyHSS API Service (Port 8080/tcp)
 - PyHSS GSUP Service (Port 4222/tcp)
 - Redis (Port 6379/tcp)

Subscriber data is stored in an SQLite database on the `pyhss_sqlite` volume.

For production, just pull the following image:

```shell
docker pull ghcr.io/pyhss/pyhss/pyhss:latest
```

The `latest` tag is automatically built from current master.  For configuration, please reference `docker/config.yaml`.
Every option in the configuration can be changed through environment variables, which are documented in the `docker/.env` file.

Each container needs a `CONTAINER_ROLE` variable as well with one of the following values:

 - diameter
 - hss
 - api
 - geored
 - logs
 - metrics
 - gsup
 - database

See the `docker/docker-compose.yaml` file for an example of how to set this up. This variable determines which service the container will run.

### For developers: Configuring your IDE to run / debug inside the docker container

Should you desire to run / debug PyHSS through your IDE like PyCharm to Run / Debug services through docker, you can.

1. Create a Python interpreter on docker (not docker compose) that uses the image `ghcr.io/pyhss/pyhss/pyhss:development`
2. Prepare the docker image by running `cd docker && docker compose build`. You'll need to rebuild only if requirements.txt changes.
3. Create a Run configuration for each script:
   * Select the docker interpreter as runtime
   * Be sure to configure the env vars to use the `docker/.env` file
   * Setup these additional env vars: `CONFIG_TEMPLATE=/opt/pyhss/docker/config.yaml;PYHSS_CONFIG=/tmp/config.yaml;PYTHONUNBUFFERED=1`
   * Be sure that the container run options look like this: `--entrypoint=/opt/pyhss/docker/launch-container.sh -v /home/YOUR_USER/git/pyhss:/opt/pyhss -p 127.0.0.1:4222:4222 --network docker_default --rm`
   * NOTE: The port example is for the GSUP daemon. Refer to the compose file for the relevant ports of your daemon
   * NOTE: the path `/home/YOUR_USER/git/pyhss` is meant to point to your local source tree
   * NOTE: The `--network docker_default` might need to be replaced with the network that is used by compose
4. Start the entire environment with `docker compose up -d`
5. Stop the service you'd like to manually run / debug. For instance: `docker compose stop pyhss_api`
6. Use your IDE run configuration to launch the desired service

## Structure

PyHSS uses a queued microservices model. Each service performs a specific set of tasks, and uses redis messages to communicate with other services.

The following services make up PyHSS:
 - diameterService.py: Handles receiving and sending of diameter messages, and diameter client connection state.
 - gsupService.py: Handles receiving and sending of GSUP messages to interact with 2G/3G Osmocom components.
 - hssService.py: Provides decoding and encoding of diameter requests and responses, as well as logic to perform as a HSS.
 - apiService.py: Provides the API, to allow management of PyHSS.
 - georedService.py: Sends georaphic redundancy messages to geored peers when defined. Also handles webhook messages.
 - logService.py: Handles logging for all services.
 - metricService.py: Exposes prometheus metrics from other services.
 - udrService.py: Optional 5G UDR, serves Nudr_DataRepository over HTTP/2 and registers at the NRF.
 
## Subscriber Information Storage

Subscriber data (IMSI, APN Profiles & Crypto values for each subscriber) are stored in a SQL backend, (See [databases](docs/databases.md) for more info) which can be interfaced with a number of different ways.

The [RESTful API](docs/API.md) allows for easy, safe CRUD operations on the subscriber data.

If REST isn't your jam and you instead want to interact directly with Python, `database.py` can be imported into your project and contains all the same hooks as the API.

## Installation

Create and activate a virtual environment:

```shell
python3 -m venv .venv
source .venv/bin/activate
```

Dependencies can be installed using Pip3:

```shell
pip3 install -r requirements.txt
```

PyHSS also requires [Redis 7.0.0](https://redis.io/docs/getting-started/installation/install-redis-on-linux/) or above.

Then after setting up the config, you can fire up the necessary PyHSS services by running:
```shell
python3 diameterService.py
python3 hssService.py
python3 apiService.py
```

By default these services bind to `127.0.0.1`; edit `bind_ip` in `config.yaml` if they need to be reachable from other hosts.

All going well you'll have a functioning HSS at this point. For production use, systemd scripts are located in `./systemd`
PyHSS API uses Flask, and can be configured with your favourite WSGI server.

To get everything more production ready checkout [Monit with PyHSS](docs/monit.md) for more info.

## Statistics

Historically stats were collected through Redis counters and exposed via an SNMP service, this feature has been left for backward compatibility, but now Prometheus is the recommended method for collecting metrics going forward.

More info about the legacy monitoring the system is available in [SNMP Readme](docs/monitoring.md).

## Running tests

Activate the virtual environment (see [installation](#installation), then
install test dependencies and execute the tests as follows:

```shell
pip3 install -r requirements-test.txt
pytest
```

## About

This software was written to address the limited options for lightweight HSS platforms out there, particularly those implementing IMS HSS functionality.

It is now deployed by several mid-tier operators, private LTE networks and lab networks worldwide.

Any contributions are welcome, just submit a PR or contact me.

You can contact me at nick (at) nickvsnetworking.com or via my blog at [nickvsnetworking.com](https://nickvsnetworking.com)

A matrix room for discussing PyHSS is available at:
[#pyhss:matrix.org](https://matrix.to/#/#pyhss:matrix.org)
