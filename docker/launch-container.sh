#!/bin/sh
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -e

# PyHSS Docker Launch Script
# This script processes the configuration template and starts the specified service

# Default values
TEMPLATE_FILE="${CONFIG_TEMPLATE:-/opt/pyhss/config.yaml.template}"
PYHSS_CONFIG="${PYHSS_CONFIG:-/opt/pyhss/config.yaml}"
CONTAINER_ROLE="${CONTAINER_ROLE:-undefined}"

echo "=== PyHSS Container Startup ==="
echo "Template file: $TEMPLATE_FILE"
echo "Config file: $PYHSS_CONFIG"

# Generate configuration file from template
if ! envsubst < "$TEMPLATE_FILE" > "$PYHSS_CONFIG"; then
    echo "ERROR: Failed to generate configuration file"
    exit 1
fi

echo "Configuration file generated successfully: $PYHSS_CONFIG"

# Print some environment info for debugging
echo ""
echo "=== Environment Information ==="
echo "Python version: $(python3 --version)"
echo "Working directory: $(pwd)"
echo "User: $(whoami)"

echo ""
echo "=== Starting Application ==="

# Execute the service specified in the CONTAINER_ROLE variable

case "${CONTAINER_ROLE}" in
    database)
        exec python3 databaseService.py
        ;;
    logs)
        exec python3 logService.py
        ;;
    metrics)
        exec python3 metricsService.py
        ;;
    api)
        exec python3 apiService.py
        ;;
    diameter)
        exec python3 diameterService.py
        ;;
    hss)
        exec python3 hssService.py
        ;;
    gsup)
        exec python3 gsupService.py
        ;;
    geored)
        exec python3 georedService.py
        ;;
    udr)
        exec python3 udrService.py
        ;;
    *)
        echo "WARN: Unknown env var value CONTAINER_ROLE '${CONTAINER_ROLE}'. Must be one of {hss,diameter,api,gsup,udr,metrics,logs,geored,database}. Defaulting to running container CMD."
        exec $@
        ;;
esac
