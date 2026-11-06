#!/usr/bin/env bash

set -euo pipefail

# Run this inside a deployed proof-server Veritee VM. Unlike the local proxy
# test, this probe uses a routable Docker bridge and verifies that the kernel's
# DOCKER-USER policy, rather than an --internal network, blocks direct egress.

target_ip="${TEMENOS_EGRESS_TEST_IP:-1.1.1.1}"
target_port="${TEMENOS_EGRESS_TEST_PORT:-443}"
network="temenos-egress-kernel-test-$$"
container="temenos-egress-kernel-test-$$"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "this test must run as root to inspect firewall counters" >&2
  exit 1
fi

app_container="$(
  docker ps \
    --filter label=com.docker.compose.service=app \
    --format '{{.ID}}' \
    | head -n 1
)"
if [[ -z "$app_container" ]]; then
  echo "could not find the running proof-server app container" >&2
  exit 1
fi

app_image="$(docker inspect --format '{{.Config.Image}}' "$app_container")"

drop_packets() {
  iptables -w 5 -n -v -x -L TEMENOS-CONTAINER-EGRESS \
    | awk '$3 == "DROP" { total += $1 } END { print total + 0 }'
}

before="$(drop_packets)"
docker network create --driver bridge "$network" >/dev/null

set +e
docker run --rm \
  --name "$container" \
  --network "$network" \
  --entrypoint node \
  -e TEMENOS_TEST_IP="$target_ip" \
  -e TEMENOS_TEST_PORT="$target_port" \
  "$app_image" \
  -e '
    const net = require("node:net");
    const socket = net.connect({
      host: process.env.TEMENOS_TEST_IP,
      port: Number(process.env.TEMENOS_TEST_PORT),
      timeout: 5000,
    });
    socket.on("connect", () => process.exit(0));
    socket.on("timeout", () => { socket.destroy(); process.exit(2); });
    socket.on("error", () => process.exit(3));
  ' >/dev/null 2>&1
probe_status=$?
set -e

after="$(drop_packets)"
if [[ "$probe_status" -eq 0 ]]; then
  echo "direct container egress unexpectedly reached $target_ip:$target_port" >&2
  exit 1
fi
if (( after <= before )); then
  echo "direct connection failed, but the DOCKER-USER drop counter did not increase" >&2
  exit 1
fi

echo "routable bridge created: $network"
echo "direct container connection blocked: $target_ip:$target_port"
echo "TEMENOS-CONTAINER-EGRESS drops: $before -> $after"
