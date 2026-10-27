#!/bin/bash
# Start the eclipse-mosquitto MQTT broker via docker.
# Listens on localhost:1883 with anonymous access (sim use only).
set -euo pipefail

NAME="sentinel-mosquitto"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"; then
    echo "broker already running ($NAME on localhost:1883)"
    exit 0
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p 1883:1883 eclipse-mosquitto
echo "broker started ($NAME on localhost:1883)"
