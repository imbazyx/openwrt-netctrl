#!/bin/sh
# OpenWRT NetCtrl Agent v1.1
# Запуск: /etc/init.d/netctrl start   (создаётся установщиком /agent/install.sh)
# Ручной запуск: netctrl-agent.sh server=http://10.0.0.5:3000 key=<agent_key>

set -u

STATE_DIR=/etc/netctrl
ID_FILE="$STATE_DIR/id"
KEY_FILE="$STATE_DIR/key"
CPU_STATE="$STATE_DIR/cpu"

SERVER="${NETCTRL_SERVER:-}"
AGENT_KEY="${NETCTRL_AGENT_KEY:-}"
INTERVAL="${NETCTRL_INTERVAL:-30}"

# Установщик передаёт "server=... key=..." одной строкой (procd EXTRA_ARGS)
for arg in "$@"; do
  case "$arg" in
    server=*) SERVER="${arg#server=}" ;;
    key=*)   AGENT_KEY="${arg#key=}" ;;
    interval=*) INTERVAL="${arg#interval=}" ;;
  esac
done
SERVER="${SERVER%/}"
[ -n "$INTERVAL" ] || INTERVAL=30

log() { logger -t netctrl "$1"; }
die() { log "$1"; echo "$1" >&2; exit 1; }

[ -n "$SERVER" ] || die "SERVER not set: use server=http://host:port"

# ── HTTP-клиент: busybox wget / uclient-fetch / curl, что есть ───────────────
HTTP_POST=""
if command -v wget >/dev/null 2>&1 && wget --help 2>&1 | grep -q -- '--header'; then
  HTTP_POST="wget"
elif command -v curl >/dev/null 2>&1; then
  HTTP_POST="curl"
elif command -v uclient-fetch >/dev/null 2>&1; then
  HTTP_POST="uclient-fetch"
elif command -v wget >/dev/null 2>&1; then
  HTTP_POST="wget"
else
  die "no usable http client (need wget/curl/uclient-fetch)"
fi

# post <url> <json> <header:value>
post() {
  _url="$1"; _data="$2"; _hdr="${3:-}"
  if [ -n "$_hdr" ]; then
    case "$HTTP_POST" in
      curl)          curl -s -m 20 -H 'Content-Type: application/json' -H "$_hdr" --data-binary "$_data" "$_url" 2>/dev/null ;;
      uclient-fetch) uclient-fetch -q -m 20 -H 'Content-Type: application/json' -H "$_hdr" --post-data="$_data" -O - "$_url" 2>/dev/null ;;
      *)             wget -q -T 20 -O - --header='Content-Type: application/json' --header="$_hdr" --post-data="$_data" "$_url" 2>/dev/null ;;
    esac
  else
    case "$HTTP_POST" in
      curl)          curl -s -m 20 -H 'Content-Type: application/json' --data-binary "$_data" "$_url" 2>/dev/null ;;
      uclient-fetch) uclient-fetch -q -m 20 -H 'Content-Type: application/json' --post-data="$_data" -O - "$_url" 2>/dev/null ;;
      *)             wget -q -T 20 -O - --header='Content-Type: application/json' --post-data="$_data" "$_url" 2>/dev/null ;;
    esac
  fi
}

# ── Экранирование и разбор JSON (awk вместо sed: меньше кавычек) ─────────────
json_str() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'
}
field() {
  printf '%s' "$1" | awk -v k="\"$2\":" '
    { i = index($0, k); if (!i) next
      s = substr($0, i + length(k))
      if (substr(s,1,1) == "\"") { s = substr(s,2); j = index(s,"\""); if (j) print substr(s,1,j-1) } }'
}
num_field() {
  printf '%s' "$1" | awk -v k="\"$2\":" '
    { i = index($0, k); if (!i) next
      s = substr($0, i + length(k)); sub(/[^0-9.].*$/, "", s); print s }'
}

# ── Метрики ──────────────────────────────────────────────────────────────────
sample_cpu() {
  set -- $(head -1 /proc/stat 2>/dev/null)
  CPU_IDLE=$(( ${6:-0} + ${7:-0} ))
  CPU_TOTAL=$(( ${2:-0} + ${3:-0} + ${4:-0} + ${6:-0} + ${7:-0} + ${8:-0} + ${9:-0} ))
}

# Разница между двумя выборками /proc/stat: sleep 1 не нужен,
# интервал и так 30 секунд, а загрузка считается точнее.
get_cpu() {
  sample_cpu
  if [ ! -f "$CPU_STATE" ]; then
    echo "$CPU_TOTAL $CPU_IDLE" > "$CPU_STATE"
    echo 0
    return
  fi
  read -r ptotal pidle < "$CPU_STATE"
  echo "$CPU_TOTAL $CPU_IDLE" > "$CPU_STATE"
  dt=$(( CPU_TOTAL - ptotal ))
  di=$(( CPU_IDLE - pidle ))
  [ "$dt" -le 0 ] && { echo 0; return; }
  [ "$di" -lt 0 ] && di=0
  echo $(( (dt - di) * 100 / dt ))
}

get_ram() {
  total=$(awk '/^MemTotal/{print $2; exit}' /proc/meminfo)
  [ -n "$total" ] || { echo 0; return; }
  avail=$(awk '/^MemAvailable/{print $2; exit}' /proc/meminfo)
  if [ -n "$avail" ]; then echo $(( (total - avail) * 100 / total )); return; fi
  free=$(awk '/^MemFree/{print $2; exit}' /proc/meminfo)
  buf=$(awk '/^Buffers/{print $2; exit}' /proc/meminfo)
  cached=$(awk '/^Cached/{print $2; exit}' /proc/meminfo)
  echo $(( (total - free - buf - cached) * 100 / total ))
}

# 'Station' с большой буквы — grep -c "station" всегда давал 0
get_clients() {
  n=0
  if command -v iw >/dev/null 2>&1; then
    n=$(iw dev 2>/dev/null | grep -c 'Station ' || true)
  fi
  leases=0
  [ -f /tmp/dhcp.leases ] && leases=$(grep -c '^ ' /tmp/dhcp.leases 2>/dev/null || true)
  [ "$n" -lt "$leases" ] && n=$leases
  if [ "$n" -eq 0 ]; then
    n=$(awk '$NF=="0x2"' /proc/net/arp 2>/dev/null | wc -l | tr -d ' ')
  fi
  echo "${n:-0}"
}

get_uptime() { awk '{printf "%d", $1}' /proc/uptime; }
get_load()    { awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null; }

get_model() {
  m=$(cat /tmp/sysinfo/model 2>/dev/null)
  [ -z "$m" ] && m=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)
  [ -z "$m" ] && m="OpenWrt"
  echo "$m"
}

get_firmware() {
  grep -o 'DISTRIB_RELEASE="[^"]*"' /etc/openwrt_release 2>/dev/null | head -1 | cut -d'"' -f2
}

get_mac() {
  for i in br-lan eth0; do
    m=$(cat /sys/class/net/$i/address 2>/dev/null)
    [ -n "$m" ] && { echo "$m"; return; }
  done
  echo ""
}

# LAN-адрес, а не src из маршрута до 8.8.8.8 (это WAN за NAT)
get_ip() {
  ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 -o addr show dev br-lan 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  fi
  [ -z "$ip" ] && ip=$(ifconfig br-lan 2>/dev/null | awk '/inet addr/{print $2; exit}' | cut -d: -f2)
  [ -z "$ip" ] && ip=$(ifconfig br-lan 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1)
  [ -z "$ip" ] && ip=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')
  [ -z "$ip" ] && ip=$(uci -q get network.lan.ipaddr | sed 's#.*/##')
  echo "$ip"
}

# ── Регистрация и heartbeat ──────────────────────────────────────────────────
REGISTER_URL="$SERVER/api/routers/register"

register() {
  name=$(uci -q get system.@system[0].hostname || hostname)
  payload="{\"name\":\"$(json_str "$name")\",\"ip\":\"$(json_str "$(get_ip)")\",\"model\":\"$(json_str "$(get_model)")\",\"firmware\":\"$(json_str "$(get_firmware)")\",\"mac\":\"$(json_str "$(get_mac)")\"}"
  hdr=""
  [ -n "$AGENT_KEY" ] && hdr="X-Agent-Key: $AGENT_KEY"
  resp=$(post "$REGISTER_URL" "$payload" "$hdr")
  id=$(num_field "$resp" id)
  key=$(field "$resp" key)
  if [ -n "$id" ] && [ "$id" != "0" ]; then
    [ -n "$key" ] && echo "$key" > "$KEY_FILE"
    echo "$id" > "$ID_FILE"
    log "registered id=$id ip=$(get_ip)"
    echo "$id"
    return 0
  fi
  log "registration failed: ${resp:-<empty>}"
  echo ""
  return 1
}

heartbeat() {
  id="$1"
  key=""
  [ -f "$KEY_FILE" ] && key=$(cat "$KEY_FILE")
  payload="{\"cpu\":$(get_cpu),\"ram\":$(get_ram),\"clients\":$(get_clients),\"uptime_sec\":$(get_uptime),\"firmware\":\"$(json_str "$(get_firmware)")\",\"load\":\"$(json_str "$(get_load)")\"}"
  hdr=""
  [ -n "$key" ] && hdr="X-Router-Key: $key"
  post "$SERVER/api/routers/$id/heartbeat" "$payload" "$hdr"
}

# ── Main ─────────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
log "agent start server=$SERVER interval=$INTERVAL"

ROUTER_ID=""
[ -f "$ID_FILE" ] && ROUTER_ID=$(cat "$ID_FILE")

FAILS=0
while true; do
  if [ -z "$ROUTER_ID" ]; then
    ROUTER_ID=$(register)
    [ -z "$ROUTER_ID" ] && { log "no id, retry in 30s"; sleep 30; continue; }
    FAILS=0
  fi

  resp=$(heartbeat "$ROUTER_ID")
  # Сервер отдаёт ключ один раз для legacy-роутеров без ключа
  newkey=$(field "$resp" key)
  [ -n "$newkey" ] && echo "$newkey" > "$KEY_FILE"

  if printf '%s' "$resp" | grep -q '"ok":true'; then
    # Сервер может попросить другой интервал (настройка панели)
    want=$(num_field "$resp" interval)
    if [ -n "$want" ] && [ "$want" -ge 10 ] 2>/dev/null && [ "$want" -le 3600 ] 2>/dev/null && [ "$want" != "$INTERVAL" ]; then
      log "interval ${INTERVAL}s -> ${want}s (server setting)"
      INTERVAL="$want"
    fi
    [ "$FAILS" -gt 0 ] && log "heartbeat restored after $FAILS failures"
    FAILS=0
  else
    FAILS=$(( FAILS + 1 ))
    log "heartbeat failed (#$FAILS): ${resp:-<empty>}"
    # Роутер удалён на сервере или ключ сменился — перерегистрируемся
    if [ "$FAILS" -ge 3 ]; then
      log "re-registering after $FAILS failures"
      rm -f "$ID_FILE" "$KEY_FILE"
      ROUTER_ID=""
      FAILS=0
    fi
  fi

  sleep "$INTERVAL"
done