#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proxy_dir="$repo_root/server/egress_proxy"
proxy_bin="$proxy_dir/target/release/temenos-egress-proxy"
proof_image="docker.io/midnightntwrk/proof-server:8.1.0-amd64@sha256:829d02876b346fe773d3d17419a38aadb9fafc6653603afbb3f16672bc122bd4"
curl_image="docker.io/curlimages/curl@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6"
proxy_runtime_image="docker.io/library/debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
suffix="$$"
app_network="temenos-egress-app-$suffix"
proxy_network="temenos-egress-out-$suffix"
proxy_container="temenos-egress-proxy-$suffix"
proof_container="temenos-proof-server-$suffix"
policy_file="$(mktemp)"

cleanup() {
  docker rm -f "$proof_container" "$proxy_container" >/dev/null 2>&1 || true
  docker network rm "$app_network" "$proxy_network" >/dev/null 2>&1 || true
  rm -f "$policy_file"
}
trap cleanup EXIT

printf '%s\n' \
  '{"version":2,"profile":null,"outbound":[{"host":"srs.midnight.network","port":443}],"platform_outbound":[]}' \
  > "$policy_file"

cargo build --release --locked --manifest-path "$proxy_dir/Cargo.toml"
docker network create --internal "$app_network" >/dev/null
docker network create "$proxy_network" >/dev/null
app_cidr="$(docker network inspect "$app_network" --format '{{(index .IPAM.Config 0).Subnet}}')"

docker run --detach --rm \
  --name "$proxy_container" \
  --network "$proxy_network" \
  --mount "type=bind,src=$proxy_bin,dst=/usr/local/bin/temenos-egress-proxy,readonly" \
  --mount "type=bind,src=$policy_file,dst=/policy.json,readonly" \
  --entrypoint /usr/local/bin/temenos-egress-proxy \
  "$proxy_runtime_image" \
  --policy-file /policy.json \
  --scope app \
  --allow-client-cidr "$app_cidr" \
  --dns-server 1.1.1.1 >/dev/null

docker network connect --alias egress-proxy "$app_network" "$proxy_container"

docker run --detach --rm \
  --name "$proof_container" \
  --network "$app_network" \
  --network-alias proof-server \
  -e HTTP_PROXY=http://egress-proxy:18080 \
  -e HTTPS_PROXY=http://egress-proxy:18080 \
  -e http_proxy=http://egress-proxy:18080 \
  -e https_proxy=http://egress-proxy:18080 \
  "$proof_image" >/dev/null

for _ in $(seq 1 180); do
  if docker logs "$proof_container" 2>&1 | grep -q 'starting service:'; then
    break
  fi
  sleep 1
done

docker logs "$proof_container" 2>&1 | grep -q 'starting service:'
docker logs "$proxy_container" 2>&1 | grep -q 'allowed scope=app destination=srs.midnight.network:443'

docker run --rm --network "$app_network" \
  --env HTTPS_PROXY=http://egress-proxy:18080 \
  "$curl_image" --fail --silent --show-error --head \
  https://srs.midnight.network/midnight-powers-of-tau-2p25 >/dev/null

docker run --rm --network "$app_network" \
  "$curl_image" --fail --silent --show-error \
  http://proof-server:6300/health >/dev/null

if docker run --rm --network "$app_network" \
  --env HTTPS_PROXY=http://egress-proxy:18080 \
  "$curl_image" --fail --silent --show-error --head https://example.com/ >/dev/null 2>&1; then
  echo "undeclared destination unexpectedly succeeded" >&2
  exit 1
fi

if docker run --rm --network "$app_network" \
  "$curl_image" --fail --silent --show-error --head https://example.com/ >/dev/null 2>&1; then
  echo "direct container egress unexpectedly succeeded" >&2
  exit 1
fi

echo "proof server started through the measured SRS rule"
echo "proof server health endpoint responded on the internal network"
echo "undeclared proxy traffic and direct container egress were blocked"
