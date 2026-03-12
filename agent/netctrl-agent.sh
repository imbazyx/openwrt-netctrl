#!/bin/sh
# OpenWRT NetCtrl Agent v1.0
# Автозапуск: /etc/init.d/netctrl start

SERVER="${NETCTRL_SERVER:-http://10.10.0.1:3000}"
ID_FILE="/etc/netctrl-id"
INTERVAL="${NETCTRL_INTERVAL:-30}"

log() { logger -t netctrl "$1"; }

get_cpu() {
  local a1 a2 a3 a4 b1 b2 b3 b4
  read a1 a2 a3 a4 _ < /proc/stat
  sleep 1
  read b1 b2 b3 b4 _ < /proc/stat
  local idle_a=$((a4)) total_a=$((a1+a2+a3+a4))
  local idle_b=$((b4)) total_b=$((b1+b2+b3+b4))
  local dtotal=$((total_b-total_a)) didle=$((idle_b-idle_a))
  if [ "$dtotal" -eq 0 ]; then echo 0; return; fi
  echo $(( (dtotal-didle)*100/dtotal ))
}

get_ram() {
  local total free buffers cached
  total=$(awk '/MemTotal/{print $2}' /proc/meminfo)
  free=$(awk '/MemFree/{print $2}' /proc/meminfo)
  buffers=$(awk '/Buffers/{print $2}' /proc/meminfo)
  cached=$(awk '/^Cached/{print $2}' /proc/meminfo)
  local used=$(( total - free - buffers - cached ))
  [ "$total" -eq 0 ] && echo 0 && return
  echo $(( used*100/total ))
}

get_clients() {
  if command -v iw >/dev/null 2>&1; then
    iw dev 2>/dev/null | grep -c "station" 2>/dev/null || echo 0
  else
    cat /proc/net/arp 2>/dev/null | grep -c "0x2" || echo 0
  fi
}

get_uptime() { awk '{printf "%d", $1}' /proc/uptime; }

get_model() {
  local model=""
  model=$(cat /tmp/sysinfo/model 2>/dev/null)
  [ -z "$model" ] && model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
  [ -z "$model" ] && model="OpenWrt"
  echo "$model"
}

get_firmware() {
  grep -o 'DISTRIB_RELEASE=[^"]*"[^"]*"' /etc/openwrt_release 2>/dev/null | cut -d'"' -f2 \
  || grep DISTRIB_RELEASE /etc/openwrt_release 2>/dev/null | cut -d= -f2 | tr -d '"' \
  || echo ""
}

get_mac() { cat /sys/class/net/br-lan/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null || echo ""; }

get_ip() {
  ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}' \
  || ifconfig br-lan 2>/dev/null | awk '/inet addr/{print $2}' | cut -d: -f2 \
  || echo ""
}

get_load() { cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}'; }

register() {
  local name ip model firmware mac
  name=$(uci get system.@system[0].hostname 2>/dev/null || hostname)
  ip=$(get_ip)
  model=$(get_model)
  firmware=$(get_firmware)
  mac=$(get_mac)
  local payload="{\"name\":\"$name\",\"ip\":\"$ip\",\"model\":\"$model\",\"firmware\":\"$firmware\",\"mac\":\"$mac\"}"
  local response
  response=$(wget -q -O - --post-data="$payload" \
    --header="Content-Type: application/json" \
    "${SERVER}/api/routers/register" 2>/dev/null)
  local id
  id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
  if [ -n "$id" ] && [ "$id" != "null" ]; then
    echo "$id" > "$ID_FILE"
    log "Registered with ID=$id"
    echo "$id"
  else
    log "Registration failed. Response: $response"
    echo ""
  fi
}

heartbeat() {
  local id="$1"
  local cpu ram clients uptime_sec firmware load
  cpu=$(get_cpu)
  ram=$(get_ram)
  clients=$(get_clients)
  uptime_sec=$(get_uptime)
  firmware=$(get_firmware)
  load=$(get_load)
  local payload="{\"cpu\":$cpu,\"ram\":$ram,\"clients\":$clients,\"uptime_sec\":$uptime_sec,\"firmware\":\"$firmware\",\"load\":\"$load\"}"
  local result
  result=$(wget -q -O - --post-data="$payload" \
    --header="Content-Type: application/json" \
    "${SERVER}/api/routers/${id}/heartbeat" 2>/dev/null)
  if echo "$result" | grep -q '"ok":true'; then
    log "Heartbeat OK: CPU=${cpu}% RAM=${ram}% Clients=${clients}"
  else
    log "Heartbeat failed: $result"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
log "NetCtrl agent starting. Server: $SERVER"

# Get or register ID
if [ -f "$ID_FILE" ]; then
  ROUTER_ID=$(cat "$ID_FILE")
  log "Using existing ID=$ROUTER_ID"
else
  log "Registering with server..."
  ROUTER_ID=$(register)
  if [ -z "$ROUTER_ID" ]; then
    log "Registration failed, retrying in 30s..."
    sleep 30
    ROUTER_ID=$(register)
  fi
fi

if [ -z "$ROUTER_ID" ]; then
  log "Could not register. Exiting."
  exit 1
fi

# Main loop
while true; do
  heartbeat "$ROUTER_ID"
  sleep "$INTERVAL"
done
