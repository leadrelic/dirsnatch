#!/usr/bin/env bash
#
# dirsnatch.sh — Clone one or more ports of an open directory over torsocks,
# proxychains, or an already-active VPN
#
# No command-line flags — just run it. Every choice (target, ports, VPN/proxy
# method, output directory, concurrency, hash verification, etc.) is asked
# interactively once the tool is running.
#
# First question asked at runtime: are you already running a VPN? If yes,
# the script skips the torsocks/proxychains requirement, pulls your current
# public IP/geolocation so you can visually confirm the VPN exit isn't your
# real IP/location, and connects directly (no wrapper needed).
#
# Supports multiple ports on the same host in one run, concurrent downloads,
# a pre-download size estimate, a JSON manifest (with sha256 hashes) per
# target, an opt-in sha256 re-verification pass for previously downloaded
# files, and graceful Ctrl+C handling that finalizes a partial manifest
# instead of leaving things in a half-written state.
#
# Usage:
#   ./dirsnatch.sh
#
# Requires: wget, curl, and EITHER (torsocks and/or proxychains) OR an
# active VPN
# macOS: brew install wget curl torsocks proxychains-ng
#
set -o pipefail
set -m
# Job control on: each per-target download batch is launched as its own
# background job, which under job control gets its own process group. That
# lets Ctrl+C kill that whole group (workers + their curl children) via a
# single negative-PID kill, without touching this script's own process.
# See on_interrupt() below.
#
# NOTE: deliberately not using 'set -u' (nounset) — macOS ships bash 3.2 by
# default, and bash <4.4 throws a spurious "unbound variable" error when
# expanding a legitimately empty array (e.g. "${TARGET_URLS[@]}") under
# nounset. This script is written to be safe without it.

# ---------- defaults (all of these are decided by prompts below, not flags) ----------
PROXY_TOOL=""
TARGET=""
PORTS_OPT=""
OUT_DIR=""
TIMEOUT=20      # whole-request cap for directory listings and hash re-verification only;
                # file downloads use a stall detector instead (see download_worker)
STALL_SECS=60   # abort a download only if it moves < 1 KB/s for this long
FILES_SUBDIR="files"  # cloned content lives here so a remote file can never collide
                      # with manifest.json / .dirsnatch.log / .counters
USING_VPN=""   # "" = ask, set to "yes"/"no" once asked
SKIP_CHECKS=0  # no longer settable — quick/skip-checks mode was removed; kept at 0 for any leftover references
CONCURRENCY=4
INTERRUPTED=0
VERIFY_HASHES=0  # opt-in hash re-verification of already-downloaded files, asked below
GEO_CURL_PREFIX=()  # curl prefix used by geolocation lookups — empty for a direct
                     # connection, or set to the active proxy wrapper (torsocks/
                     # proxychains) when verifying that wrapper is actually live

# ---------- helpers ----------
log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

# ---------- OS detection ----------
OS="$(uname -s)"
case "$OS" in
  Darwin) PLATFORM="mac" ;;
  Linux)  PLATFORM="linux" ;;
  *) die "Unsupported OS: $OS (this tool supports macOS and Linux only)" ;;
esac
log "Detected platform: $PLATFORM"

# Resolve curl/wget binaries — on mac, prefer homebrew curl if present
if [[ "$PLATFORM" == "mac" && -x /opt/homebrew/opt/curl/bin/curl ]]; then
  CURL_BIN="/opt/homebrew/opt/curl/bin/curl"
elif command -v curl >/dev/null 2>&1; then
  CURL_BIN="$(command -v curl)"
else
  die "curl not found. Install it and re-run."
fi

if command -v wget >/dev/null 2>&1; then
  WGET_BIN="$(command -v wget)"
else
  die "wget not found. Install it (mac: brew install wget) and re-run."
fi

# Some open directories block the default curl/wget UA string (or a UA-less
# request) outright. Present as an ordinary browser so listings that would
# otherwise silently come back empty actually load.
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Resolve a sha256 hasher — Linux typically has sha256sum, macOS has shasum
HASH_BIN=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_BIN="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_BIN="shasum -a 256"
fi
hash_file() {
  [[ -n "$HASH_BIN" && -f "$1" ]] || { echo ""; return; }
  $HASH_BIN "$1" 2>/dev/null | awk '{print $1}'
}

human_size() {
  local bytes="${1:-0}"
  awk -v b="$bytes" 'BEGIN{
    split("B KB MB GB TB", u, " ")
    i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    printf "%.1f %s", b, u[i]
  }'
}

json_escape() {
  # Escape backslash and quote, then drop control characters (a hostile
  # filename containing a newline/tab would otherwise produce invalid JSON).
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Listing entries come from a server we don't trust. Reject anything that
# could escape the output directory or confuse the terminal: a ".." path
# segment anywhere (not just at the start), or control characters.
unsafe_entry() {
  local e="$1"
  case "/$e/" in
    */../*) return 0 ;;
  esac
  [[ "$e" == *[[:cntrl:]]* ]] && return 0
  return 1
}

# ---------- Ctrl+C handling ----------
# Globals updated at the start of each clone_one_target call so the trap can
# finalize whatever's in flight for the target currently being cloned.
CURRENT_TARGET_DIR=""
CURRENT_MANIFEST_DIR=""
CURRENT_MANIFEST_OUT=""
CURRENT_COUNTER_FILE=""
CURRENT_TOTAL=0
CURRENT_SPAWN_PID=""   # PID of the current target's download-batch job (see clone_one_target)

on_interrupt() {
  INTERRUPTED=1
  echo
  warn "Ctrl+C received — stopping in-flight downloads..."
  # CURRENT_SPAWN_PID is the backgrounded job that fans out the per-file
  # workers for the target currently downloading. With job control on
  # (set -m, above), that job is its own process group leader, so its PGID
  # equals its PID — a kill on the *negative* PID hits that whole group
  # (the fan-out subshell, every worker it spawned, and their curl
  # children) in one shot, without touching this script's own process,
  # which is in a different group.
  if [[ -n "$CURRENT_SPAWN_PID" ]] && kill -0 "$CURRENT_SPAWN_PID" 2>/dev/null; then
    kill -9 -- "-$CURRENT_SPAWN_PID" 2>/dev/null
  fi
  sleep 1

  # A worker killed mid-update can leave its mkdir-based lock directory
  # behind; clear it so cleanup below (and any future run) isn't blocked.
  [[ -n "$CURRENT_COUNTER_FILE" ]] && rmdir "${CURRENT_COUNTER_FILE}.lock" 2>/dev/null

  if [[ -n "$CURRENT_COUNTER_FILE" && -f "$CURRENT_COUNTER_FILE" ]]; then
    local d s
    read -r d s < "$CURRENT_COUNTER_FILE" 2>/dev/null
    d=${d:-0}; s=${s:-0}
    warn "Partial progress on this target: $((d + s))/$CURRENT_TOTAL processed ($d downloaded, $s skipped)."
  fi

  finalize_manifest
  [[ -f "$CURRENT_MANIFEST_OUT" ]] && warn "Partial manifest written to: $CURRENT_MANIFEST_OUT"

  warn "Exiting."
  exit 130
}

# Runs on every exit path — Ctrl+C, kill/TERM, an unhandled error, or normal
# completion. Idempotent: by the time a target finishes normally,
# CURRENT_MANIFEST_DIR has already been merged and removed by
# clone_one_target, so this becomes a safe no-op for the common case. It
# exists specifically to catch the exit paths on_interrupt doesn't run for
# (e.g. SIGTERM, or the script dying to an unexpected error mid-download)
# so a manifest never gets left unfinalized no matter how the script stops.
finalize_manifest() {
  if [[ -n "$CURRENT_MANIFEST_DIR" && -d "$CURRENT_MANIFEST_DIR" ]]; then
    merge_manifest "$CURRENT_MANIFEST_DIR" "$CURRENT_MANIFEST_OUT"
    rm -rf "$CURRENT_MANIFEST_DIR"
  fi
}
trap on_interrupt INT TERM
trap finalize_manifest EXIT

# ---------- Are you already running a VPN? ----------
echo
read -rp "Are you currently running a VPN (e.g. ProtonVPN)? (yes/no): " vpn_ans
case "$vpn_ans" in
  y|Y|yes|YES) USING_VPN="yes" ;;
  *) USING_VPN="no" ;;
esac

# ---------- geolocation check ----------
GEO_LAST_ERROR=""
GEO_LAST_IP=""

# Pulls the current egress IP/geolocation. Routed through whatever is
# currently set in GEO_CURL_PREFIX (an array) — leave it empty for a direct
# lookup, or set it to a proxy wrapper (e.g. torsocks, proxychains) to check
# what a *wrapped* request looks like. Sets GEO_LAST_IP / GEO_LAST_ERROR as
# a side effect so callers can compare results across multiple invocations.
geolocate_current_ip() {
  local geo="" err="" rc=0
  local -a services=("https://ipinfo.io/json" "https://ifconfig.co/json" "https://api.ipify.org?format=json")
  local svc

  GEO_LAST_IP=""
  for svc in "${services[@]}"; do
    err="$("${GEO_CURL_PREFIX[@]}" "$CURL_BIN" -s -S --max-time 6 "$svc" -o /tmp/dirsnatch-geo.$$ 2>&1 1>/dev/null)"
    rc=$?
    geo="$(cat /tmp/dirsnatch-geo.$$ 2>/dev/null)"
    rm -f /tmp/dirsnatch-geo.$$
    if [[ $rc -eq 0 && -n "$geo" && "$geo" == *'"ip"'* ]]; then
      GEO_LAST_ERROR=""
      break
    else
      if [[ -n "$err" ]]; then
        GEO_LAST_ERROR="$svc -> $err"
      elif [[ $rc -ne 0 ]]; then
        GEO_LAST_ERROR="$svc -> curl exit code $rc"
      else
        GEO_LAST_ERROR="$svc -> empty/unexpected response"
      fi
      geo=""
    fi
  done

  [[ -n "$geo" && "$geo" == *'"ip"'* ]] || return 1

  local ip city region country org
  ip="$(printf '%s' "$geo" | grep -oE '"ip"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  city="$(printf '%s' "$geo" | grep -oE '"city"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  region="$(printf '%s' "$geo" | grep -oE '"region"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  country="$(printf '%s' "$geo" | grep -oE '"country"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  org="$(printf '%s' "$geo" | grep -oE '"org"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"

  GEO_LAST_IP="$ip"

  echo
  echo "==================== CURRENT EGRESS IP ===================="
  echo "  Public IP:  ${ip:-unknown}"
  echo "  Location:   ${city:-unknown}, ${region:-unknown}, ${country:-unknown}"
  echo "  Org/ASN:    ${org:-unknown}"
  echo "=============================================================="
  return 0
}

# Compares a direct (unwrapped) egress-IP lookup against the same lookup
# routed through the just-selected torsocks/proxychains wrapper. Unlike the
# VPN path (where the user is asserting a VPN is already live), a local
# wrapper can silently fail open — Tor not actually running, a proxychains
# config pointing at a dead proxy, etc — and depending on config that can
# mean traffic goes out unwrapped instead of erroring outright. If the two
# IPs match, the wrapper isn't doing anything and the user is warned
# explicitly before being allowed to continue.
verify_proxy_route() {
  log "Verifying $PROXY_TOOL is actually rerouting traffic (comparing direct vs. wrapped egress IP)..."

  GEO_CURL_PREFIX=()
  local direct_ip=""
  if geolocate_current_ip >/dev/null 2>&1; then
    direct_ip="$GEO_LAST_IP"
  fi

  GEO_CURL_PREFIX=("${PROXY_PREFIX[@]}")
  local wrapped_ok=1
  if ! geolocate_current_ip; then
    wrapped_ok=0
  fi
  local wrapped_ip="$GEO_LAST_IP"
  GEO_CURL_PREFIX=()

  if [[ $wrapped_ok -eq 0 ]]; then
    warn "Could not reach a geolocation service through $PROXY_TOOL."
    warn "Last error: ${GEO_LAST_ERROR:-unknown}"
    warn "This can mean $PROXY_TOOL itself can't get out at all (e.g. Tor isn't"
    warn "running, or the proxychains config points at a dead proxy) — which is"
    warn "actually the SAFE failure mode, since it means requests are being"
    warn "blocked rather than leaking. It can also just mean the lookup services"
    warn "themselves are unreachable through this route."
    read -rp "Continue anyway with $PROXY_TOOL? (yes/no): " proxy_confirm
    [[ "$proxy_confirm" == "yes" ]] || die "Aborted — could not verify $PROXY_TOOL is working."
    return
  fi

  if [[ -n "$direct_ip" && -n "$wrapped_ip" && "$direct_ip" == "$wrapped_ip" ]]; then
    warn "DANGER: egress IP through $PROXY_TOOL ($wrapped_ip) matches your direct,"
    warn "unwrapped IP ($direct_ip). $PROXY_TOOL is NOT actually rerouting traffic —"
    warn "requests would go out under your real IP."
    read -rp "Continue anyway, accepting your real IP will hit the target? (yes/no): " proxy_confirm
    [[ "$proxy_confirm" == "yes" ]] || die "Aborted — fix your $PROXY_TOOL setup before re-running."
    return
  fi

  if [[ -z "$direct_ip" ]]; then
    warn "Couldn't get a direct-IP baseline to compare against (geolocation"
    warn "services may be unreachable from this network at all), but $PROXY_TOOL"
    warn "did return a distinct-looking response above. Proceeding, but this"
    warn "wasn't a full confirmation."
    return
  fi

  ok "Confirmed: egress IP through $PROXY_TOOL ($wrapped_ip) differs from your direct IP ($direct_ip)."
}

if [[ "$USING_VPN" == "yes" ]]; then
  ok "VPN reported as active — will connect directly (no torsocks/proxychains wrap)."
  log "Pulling current public IP/geolocation so you can confirm it's your VPN exit, not your real location (times out in ~6s per lookup, 3 lookups max)..."
  GEO_CURL_PREFIX=()
  if geolocate_current_ip; then
    read -rp "Does the above look like your VPN exit (NOT your real ISP/location)? (yes/no): " geo_confirm
    [[ "$geo_confirm" == "yes" ]] || die "Aborted — verify your VPN is actually active/routing before re-running."
  else
    warn "Could not reach a geolocation service to verify your egress IP."
    warn "Last error: ${GEO_LAST_ERROR:-unknown}"
    warn "This usually means your VPN/network is blocking outbound HTTPS to these lookup"
    warn "services specifically, DNS is misbehaving, or a local firewall is interfering —"
    warn "it does not necessarily mean your VPN itself is down."
    log "You can manually check your IP in a browser (e.g. https://ipinfo.io) before continuing."
    read -rp "Continue anyway, assuming your VPN is active? (yes/no): " geo_confirm
    [[ "$geo_confirm" == "yes" ]] || die "Aborted. Re-run once you've confirmed your VPN is active."
  fi
  PROXY_TOOL="vpn"
  PROXY_PREFIX=()
fi

# ---------- proxy tool detection (only needed if not using a VPN) ----------
if [[ "$USING_VPN" != "yes" ]]; then
  HAVE_TORSOCKS=0
  HAVE_PROXYCHAINS=0
  command -v torsocks >/dev/null 2>&1 && HAVE_TORSOCKS=1
  if command -v proxychains4 >/dev/null 2>&1; then
    HAVE_PROXYCHAINS=1
    PROXYCHAINS_BIN="$(command -v proxychains4)"
  elif command -v proxychains >/dev/null 2>&1; then
    HAVE_PROXYCHAINS=1
    PROXYCHAINS_BIN="$(command -v proxychains)"
  fi

  if [[ $HAVE_TORSOCKS -eq 0 && $HAVE_PROXYCHAINS -eq 0 ]]; then
    die "Neither torsocks nor proxychains found on this system, and no VPN was reported. Install one:
    mac:   brew install torsocks   |  brew install proxychains-ng
    linux: apt install torsocks    |  apt install proxychains4
  ...or re-run and answer 'yes' to the VPN question if you're already tunneled."
  fi

  # ---------- pick proxy tool ----------
  echo
  echo "Available proxy wrappers:"
  [[ $HAVE_TORSOCKS -eq 1 ]] && echo "  1) torsocks    (found)"
  [[ $HAVE_PROXYCHAINS -eq 1 ]] && echo "  2) proxychains (found)"
  echo "  3) none        (direct connection — NOT recommended for adversary infra)"
  read -rp "Select proxy wrapper [1/2/3]: " choice
  case "$choice" in
    1) PROXY_TOOL="torsocks" ;;
    2) PROXY_TOOL="proxychains" ;;
    3) PROXY_TOOL="none" ;;
    *) die "Invalid selection" ;;
  esac

  case "$PROXY_TOOL" in
    torsocks)
      [[ $HAVE_TORSOCKS -eq 1 ]] || die "torsocks selected but not installed"
      PROXY_PREFIX=(torsocks)
      ;;
    proxychains)
      [[ $HAVE_PROXYCHAINS -eq 1 ]] || die "proxychains selected but not installed"
      PROXY_PREFIX=("$PROXYCHAINS_BIN")
      ;;
    none)
      warn "Proceeding WITHOUT proxy or VPN — your real IP will hit the target."
      read -rp "Are you sure? (yes/no): " confirm
      [[ "$confirm" == "yes" ]] || die "Aborted."
      PROXY_PREFIX=()
      ;;
    *) die "Unknown proxy tool: $PROXY_TOOL (expected torsocks, proxychains, or none)" ;;
  esac

  # Only torsocks/proxychains have anything to verify — "none" was already
  # an explicit, doubly-confirmed choice to go unwrapped.
  if [[ "$PROXY_TOOL" == "torsocks" || "$PROXY_TOOL" == "proxychains" ]]; then
    verify_proxy_route
  fi
fi
ok "Using proxy wrapper: $PROXY_TOOL"

# ---------- port list expansion ----------
# Accepts comma-separated ports and/or ranges, e.g. "8080,8081,9000-9005"
expand_ports() {
  local spec="$1"
  local part start end p
  local -a result=()
  IFS=',' read -ra parts <<< "$spec"
  for part in "${parts[@]}"; do
    part="$(echo "$part" | tr -d '[:space:]')"
    [[ -z "$part" ]] && continue
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      if [[ "$start" -gt "$end" ]]; then
        warn "Skipping invalid port range: $part"
        continue
      fi
      for ((p = start; p <= end; p++)); do
        result+=("$p")
      done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      result+=("$part")
    else
      warn "Skipping invalid port entry: $part"
    fi
  done
  printf '%s\n' "${result[@]}"
}

# ---------- target / host / ports ----------
declare -a TARGET_URLS=()
SINGLE_TARGET_MODE=0

echo
read -rp "Enter target host/IP, or a full URL (e.g. 203.0.113.5, or http://203.0.113.5:8080/some/path/): " TARGET
[[ -n "$TARGET" ]] || die "No target provided."

if [[ "$TARGET" =~ ^https?:// ]]; then
  # Full URL entered directly: treat as a single target, preserving any
  # path (e.g. a specific subdirectory) instead of asking for ports too.
  SINGLE_TARGET_MODE=1
  T="$TARGET"
  [[ "$T" == */ ]] || T="${T}/"
  TARGET_URLS+=("$T")
  HOST_PORT="$(echo "$T" | sed -E 's#^https?://##; s#/.*$##')"
  HOST_ONLY="${HOST_PORT%%:*}"
else
  # Host-plus-ports mode
  # Strip any scheme/port/path the user might have included anyway
  HOST_ONLY="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##')"
  [[ -n "$HOST_ONLY" ]] || die "Could not parse a host from: $TARGET"

  read -rp "Enter port(s) for $HOST_ONLY — single, comma list, and/or ranges (e.g. 8080 or 8080,8081,9000-9005): " PORTS_OPT
  [[ -n "$PORTS_OPT" ]] || die "No port(s) provided."

  PORT_LIST=()
  while IFS= read -r p_line; do
    [[ -n "$p_line" ]] && PORT_LIST+=("$p_line")
  done < <(expand_ports "$PORTS_OPT")
  [[ ${#PORT_LIST[@]} -gt 0 ]] || die "No valid ports parsed from: $PORTS_OPT"

  for prt in "${PORT_LIST[@]}"; do
    TARGET_URLS+=("http://${HOST_ONLY}:${prt}/")
  done
  HOST_PORT="$HOST_ONLY"
fi

ok "Host: $HOST_ONLY"
ok "Target(s) (${#TARGET_URLS[@]}): ${TARGET_URLS[*]}"

# ---------- extra reject patterns ----------
# Lets the user exclude specific filenames/patterns that hang or aren't real
# files (named pipes, slow dynamic endpoints, etc.) without editing the script.
REJECT_PATTERNS="index.html*,index.htm*"
read -rp "Any filenames/patterns to skip, e.g. a hanging endpoint (comma-separated, Enter for none): " extra_reject
[[ -n "$extra_reject" ]] && REJECT_PATTERNS="${REJECT_PATTERNS},${extra_reject}"

# ---------- concurrency ----------
read -rp "How many files to download in parallel? [default: $CONCURRENCY]: " conc_input
if [[ -n "$conc_input" && "$conc_input" =~ ^[0-9]+$ && "$conc_input" -gt 0 ]]; then
  CONCURRENCY="$conc_input"
fi
ok "Concurrency: $CONCURRENCY parallel download(s)"

# ---------- hash verification (opt-in) ----------
# Only ever matters for a target that already has files on disk from a prior
# run with matching filenames — see verify_cached_file(). Asking now, once,
# rather than as a flag, since the whole tool is interactive.
if [[ -z "$HASH_BIN" ]]; then
  warn "No sha256 hasher (sha256sum/shasum) found — hash verification isn't available this run."
else
  read -rp "If a target already has previously downloaded files, re-verify their content via sha256 (in addition to downloading anything new)? (yes/no) [default: no]: " hv_input
  case "$hv_input" in
    y|Y|yes|YES) VERIFY_HASHES=1 ;;
    *) VERIFY_HASHES=0 ;;
  esac
fi
[[ $VERIFY_HASHES -eq 1 ]] && ok "Hash verification of previously downloaded files: enabled"

# ---------- output parent dir ----------
TS="$(date +%Y%m%d_%H%M%S)"
SAFE_HOST="${HOST_ONLY//[:\/]/_}"
DEFAULT_OUT_DIR="./dirsnatch_${SAFE_HOST}_${TS}"

if [[ -z "$OUT_DIR" ]]; then
  read -rp "Directory to create for this clone [default: $DEFAULT_OUT_DIR]: " OUT_DIR_INPUT
  OUT_DIR="${OUT_DIR_INPUT:-$DEFAULT_OUT_DIR}"
fi
mkdir -p "$OUT_DIR" || die "Could not create output directory: $OUT_DIR"
ok "Output parent directory: $OUT_DIR"

read -rp "Proceed with cloning ${#TARGET_URLS[@]} target(s) into $OUT_DIR via $PROXY_TOOL? (yes/no): " go
[[ "$go" == "yes" ]] || die "Aborted."

# ---------- recursive discovery ----------
# Populates global FILE_QUEUE (array of full file URLs) by walking the open
# directory tree via HTML listing parsing. Skips entries matching REJECT_PATTERNS.
declare -a FILE_QUEUE=()
declare -a VISITED_DIRS=()
SIZE_KNOWN_TOTAL=0
SIZE_UNKNOWN_COUNT=0

matches_reject() {
  local name="$1" pat
  IFS=',' read -ra pats <<< "$REJECT_PATTERNS"
  for pat in "${pats[@]}"; do
    pat="$(echo "$pat" | sed -e 's/^ *//' -e 's/ *$//')"
    [[ -z "$pat" ]] && continue
    case "$name" in
      $pat) return 0 ;;
    esac
  done
  return 1
}

to_size_bytes() {
  # Converts a size token like "1.2K", "340M", "512" (bytes) into bytes.
  # Echoes empty string if it doesn't look like a size at all.
  local tok="$1"
  if [[ "$tok" =~ ^([0-9]+(\.[0-9]+)?)([KMGT]?)$ ]]; then
    local num="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[3]}"
    case "$unit" in
      K) awk -v n="$num" 'BEGIN{printf "%.0f", n*1024}' ;;
      M) awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024}' ;;
      G) awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024*1024}' ;;
      T) awk -v n="$num" 'BEGIN{printf "%.0f", n*1024*1024*1024*1024}' ;;
      "") awk -v n="$num" 'BEGIN{printf "%.0f", n}' ;;
    esac
  else
    echo ""
  fi
}

# Best-effort, zero-request size lookup: greps the already-fetched listing
# text for the line containing this entry's href and pulls a trailing size
# token off it (standard Apache/nginx autoindex format: name, date, size).
# Returns empty if the line can't be found or doesn't end in a size-shaped
# token — never issues a network request. Purely a nice-to-have estimate.
extract_size_from_listing() {
  local listing="$1" entry="$2" line tok
  line="$(printf '%s\n' "$listing" | grep -F "href=\"${entry}\"" | head -1)"
  [[ -n "$line" ]] || { echo ""; return; }
  tok="$(printf '%s' "$line" \
    | sed -E 's/<[^>]*>//g' \
    | grep -oE '[0-9]+(\.[0-9]+)?[[:space:]]*[KMGT]?[[:space:]]*$' \
    | tr -d '[:space:]')"
  to_size_bytes "$tok"
}

discover_dir() {
  local dir_url="$1"
  local d
  for d in "${VISITED_DIRS[@]}"; do
    [[ "$d" == "$dir_url" ]] && return
  done
  VISITED_DIRS+=("$dir_url")

  local listing
  listing="$("${PROXY_PREFIX[@]}" "$CURL_BIN" -s -L --max-time "$TIMEOUT" \
    -A "$USER_AGENT" "$dir_url" 2>/dev/null)"
  [[ -n "$listing" ]] || return

  local entries entry name full_url sz
  entries="$(printf '%s\n' "$listing" \
    | grep -oiE 'href="[^"]+"' \
    | sed -E 's/^href="//I; s/"$//' \
    | grep -vE '^(\.\./|/|\?|#)' \
    | grep -vE '^https?://' \
    | sort -u)"

  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    if unsafe_entry "$entry"; then
      warn "  ignoring unsafe listing entry from server (path traversal or control chars): $(printf '%s' "$entry" | LC_ALL=C tr -c '[:print:]' '?')"
      continue
    fi
    name="$(basename "${entry%/}")"
    if [[ "$entry" == */ ]]; then
      full_url="${dir_url%/}/${entry}"
      discover_dir "$full_url"
    else
      if matches_reject "$name"; then
        continue
      fi
      full_url="${dir_url%/}/${entry}"
      FILE_QUEUE+=("$full_url")
      sz="$(extract_size_from_listing "$listing" "$entry")"
      if [[ -n "$sz" ]]; then
        SIZE_KNOWN_TOTAL=$((SIZE_KNOWN_TOTAL + sz))
      else
        SIZE_UNKNOWN_COUNT=$((SIZE_UNKNOWN_COUNT + 1))
      fi
    fi
  done <<< "$entries"
}

# When discovery comes back with zero files, "found 0 file(s)" alone doesn't
# say whether the directory is genuinely empty, the server is blocking this
# request (UA filtering, geoblocking, WAF), or something else went wrong. A
# HEAD-style fetch of the status/headers gives a much better first read on
# which of those it is without requiring a manual curl -v.
diagnose_empty_listing() {
  local url="$1" info http_code content_type final_url
  info="$("${PROXY_PREFIX[@]}" "$CURL_BIN" -s -S -L --max-time "$TIMEOUT" \
    -A "$USER_AGENT" -o /dev/null \
    -w '%{http_code}|%{content_type}|%{url_effective}' "$url" 2>&1)"
  http_code="$(printf '%s' "$info" | cut -d'|' -f1)"
  content_type="$(printf '%s' "$info" | cut -d'|' -f2)"
  final_url="$(printf '%s' "$info" | cut -d'|' -f3-)"

  warn "  [$url] no entries parsed from the listing — diagnostic fetch:"
  warn "    HTTP status:   ${http_code:-no response / connection error}"
  warn "    Content-Type:  ${content_type:-unknown}"
  [[ -n "$final_url" && "$final_url" != "$url" ]] && warn "    Redirected to: $final_url"
  case "$http_code" in
    200)
      warn "    Server responded 200 but no <a href=\"...\"> entries matched — it's likely"
      warn "    not a standard Apache/nginx autoindex page (custom listing template, JSON"
      warn "    index, or a login/landing page instead of the real directory)."
      ;;
    301|302|303|307|308)
      warn "    Got redirected and the final page still had no parseable entries."
      ;;
    401|403)
      warn "    Access denied — could be UA filtering (already sending a browser UA),"
      warn "    IP/geo blocking, or the directory genuinely requires auth."
      ;;
    404)
      warn "    Path not found at this URL/port — double check the target."
      ;;
    ""|000)
      warn "    No response at all — connection refused/timed out, or blocked upstream"
      warn "    (proxy/VPN routing issue, firewall, or the host is down)."
      ;;
  esac
}

# When every single file in a target's batch ends up "skipped", that's not
# random flakiness — it's almost always one systemic cause (rate limiting,
# a WAF blocking the download path specifically even though the listing
# page loaded fine, a genuinely dead target, etc). download_worker now logs
# the real rc + HTTP status for every attempt, so pull an actual breakdown
# from that instead of guessing from a single extra fetch.
diagnose_all_failed() {
  local target="$1" log_file="$2"
  [[ -f "$log_file" ]] || return

  warn "  [$target] every file in this batch failed — breakdown of this run's attempts:"
  local breakdown
  breakdown="$(grep -E '^\[[0-9:]+\] attempt [0-9]+ failed' "$log_file" 2>/dev/null | grep -oE 'rc=[0-9]+ http=[A-Za-z0-9]+' | sort | uniq -c | sort -rn)"
  if [[ -z "$breakdown" ]]; then
    warn "    (no per-attempt detail captured — see $log_file)"
    return
  fi
  while IFS= read -r line; do
    warn "    $line"
  done <<< "$breakdown"

  local top_code
  top_code="$(printf '%s\n' "$breakdown" | head -1 | grep -oE 'http=[A-Za-z0-9]+' | cut -d= -f2)"
  case "$top_code" in
    403|401)
      warn "    Mostly HTTP $top_code — server allows browsing the listing but is actively"
      warn "    denying the actual file requests (UA/referer check, ban after N requests,"
      warn "    or download path requires auth the listing page doesn't)."
      ;;
    404|410)
      warn "    Mostly HTTP $top_code — the listed files don't actually exist at those URLs"
      warn "    anymore (moved/deleted), or the listing page's relative-path resolution"
      warn "    doesn't match how the server expects the download path to look."
      ;;
    429)
      warn "    Mostly HTTP 429 Too Many Requests — you're being rate limited. Try again"
      warn "    with concurrency=1 and see if that gets through."
      ;;
    none|"")
      warn "    Mostly no response at all (connection refused/reset/timed out) — this"
      warn "    points at the proxy/VPN dropping connections, a per-connection cap on"
      warn "    the target, or the download path being blocked at the network level"
      warn "    while the listing page (a single request) still got through."
      ;;
    *)
      warn "    Mostly HTTP $top_code — check what that status means for this server."
      ;;
  esac
  warn "    Full per-attempt log: $log_file"
}

# ---------- progress bar ----------
print_progress() {
  local done_count="$1" total="$2" skipped="$3" current="$4"
  local width=40
  local pct=0
  [[ "$total" -gt 0 ]] && pct=$(( done_count * 100 / total ))
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))
  local bar
  bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$empty" '')"
  printf '\r[%s] %d%% (%d/%d, %d skipped) %-30s' "$bar" "$pct" "$done_count" "$total" "$skipped" "${current:0:30}"
}

# ---------- manifest ----------
write_manifest_entry() {
  local manifest_dir="$1" url="$2" local_path="$3" status="$4" size="$5" sha="$6"
  local ts frag size_json
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
  if [[ -n "$size" ]]; then size_json="$size"; else size_json="null"; fi
  frag="$(mktemp "${manifest_dir}/entry.XXXXXX")"
  printf '{"url":"%s","local_path":"%s","status":"%s","size_bytes":%s,"sha256":"%s","timestamp":"%s"}\n' \
    "$(json_escape "$url")" "$(json_escape "$local_path")" "$status" "$size_json" "${sha:-}" "$ts" > "$frag"
}

merge_manifest() {
  local manifest_dir="$1" out_file="$2"
  # Carry forward records from the previous manifest.json for any URL this
  # run didn't touch. This run only queues new/failed files, so without this
  # the rewrite would silently drop the chain-of-custody record of every
  # file cloned earlier. Entries from this run win over older ones.
  if [[ -f "$out_file" ]]; then
    local seen line u n=0
    seen="$(mktemp)"
    cat "$manifest_dir"/entry.* 2>/dev/null | grep -oE '"url":"[^"]*"' | sort -u > "$seen"
    while IFS= read -r line; do
      u="$(printf '%s' "$line" | grep -oE '"url":"[^"]*"' | head -1)"
      [[ -n "$u" ]] || continue
      grep -qxF -- "$u" "$seen" && continue
      n=$((n + 1))
      printf '%s\n' "$line" > "$manifest_dir/entry.prev.$n"
    done < <(grep '^{"url"' "$out_file")
    rm -f "$seen"
  fi
  {
    echo "["
    local first=1 f
    for f in "$manifest_dir"/entry.*; do
      [[ -e "$f" ]] || continue
      if [[ $first -eq 1 ]]; then first=0; else echo ","; fi
      cat "$f"
    done
    echo
    echo "]"
  } > "$out_file.tmp" && mv -f "$out_file.tmp" "$out_file"
}

# ---------- compare against a previous run's manifest ----------
# If this target directory already has a manifest.json from an earlier run,
# diff the freshly-discovered file list against it and report what's new
# and what's no longer listed. The old manifest is preserved with a
# timestamped filename before being overwritten by this run's merge.
#
# If there's no manifest.json but the directory already has files in it
# (cloned by an older version of this script, before manifests existed),
# fall back to reconstructing an approximate previous file list by walking
# what's already on disk and re-deriving the URLs from the relative paths.
# This has no size/hash/timestamp history — it can only tell you new vs.
# removed by filename, not detect content changes to same-named files.
compare_with_previous_manifest() {
  local target_dir="$1" manifest_out="$2" base_url="$3"
  local old_urls_file new_urls_file
  old_urls_file="$(mktemp)"
  new_urls_file="$(mktemp)"
  local source_note="" old_count=0

  if [[ -f "$manifest_out" ]]; then
    # Entries that were skipped (failed) last time are deliberately left out
    # of the "already seen" set, so they show up as new and get retried.
    grep -v '"status":"skipped"' "$manifest_out" | grep -oE '"url":"[^"]*"' | sed -E 's/"url":"//; s/"$//' | sort -u > "$old_urls_file"
    old_count=$(grep -c . "$old_urls_file" 2>/dev/null)
    old_count=${old_count:-0}
    if [[ "$old_count" -gt 0 ]]; then
      source_note="manifest.json"
    else
      warn "  [$target_dir] manifest.json exists but had no usable entries — falling back to a disk scan."
    fi
  fi

  # Fall back to scanning what's actually on disk whenever the manifest
  # didn't give us anything usable — whether it's missing entirely (older
  # version of this script) or present but empty/corrupt (e.g. an
  # interrupted or failed prior run).
  if [[ "$old_count" -eq 0 ]]; then
    local existing_count scan_root
    # New layout keeps cloned content under $FILES_SUBDIR/ (nothing there but
    # remote files, so no name exclusions needed). Clones made by older
    # versions kept files directly in the target dir next to the tool's own
    # bookkeeping files, so that legacy layout still needs the exclusions.
    if [[ -d "${target_dir%/}/$FILES_SUBDIR" ]]; then
      scan_root="${target_dir%/}/$FILES_SUBDIR"
    else
      scan_root="$target_dir"
    fi
    existing_count=$(find "$scan_root" -type f ! -name '*.part' \
      ! -name '.dirsnatch.log' ! -name '.od-clone.log' ! -name '.counters*' ! -name 'manifest*.json' \
      ! -name 'changes_*.json' ! -path '*/.manifest_parts/*' 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$existing_count" -gt 0 ]]; then
      log "  [$target_dir] no usable manifest, but $existing_count existing file(s) on disk"
      log "  reconstructing prior file list from disk contents..."
      ( cd "$scan_root" && find . -type f ! -name '*.part' \
          ! -name '.dirsnatch.log' ! -name '.od-clone.log' ! -name '.counters*' ! -name 'manifest*.json' \
          ! -name 'changes_*.json' ! -path '*/.manifest_parts/*' \
        | sed 's|^\./||' ) 2>/dev/null | sed "s|^|${base_url%/}/|" | sort -u > "$old_urls_file"
      old_count=$(grep -c . "$old_urls_file" 2>/dev/null)
      old_count=${old_count:-0}
      source_note="on-disk scan (no usable prior manifest)"
    fi
  fi

  printf '%s\n' "${FILE_QUEUE[@]}" | sort -u > "$new_urls_file"

  if [[ "$old_count" -eq 0 ]]; then
    log "  [$target_dir] first time cloning this target — nothing to compare against yet."
    rm -f "$old_urls_file" "$new_urls_file"
    return
  fi

  if [[ "$old_count" -gt 0 ]]; then
    local backup
    backup="${manifest_out%.json}_previous_$(date +%Y%m%d_%H%M%S).json"
    [[ -f "$manifest_out" ]] && cp "$manifest_out" "$backup"

    local new_list removed_list new_n removed_n
    new_list="$(comm -13 "$old_urls_file" "$new_urls_file")"
    removed_list="$(comm -23 "$old_urls_file" "$new_urls_file")"
    new_n=$(printf '%s\n' "$new_list" | grep -c . )
    removed_n=$(printf '%s\n' "$removed_list" | grep -c . )

    COMPARE_HAD_HISTORY=1
    COMPARE_NEW_ONLY=()
    while IFS= read -r u; do
      [[ -n "$u" ]] && COMPARE_NEW_ONLY+=("$u")
    done <<< "$new_list"

    echo
    echo "==================== CHANGES SINCE LAST RUN ===================="
    echo "  Compared against:   $source_note"
    [[ -f "$backup" ]] && echo "  Previous manifest:  $backup"
    echo "  Previously seen:    $old_count file(s)"
    echo "  New files:          $new_n"
    echo "  No longer listed:   $removed_n"
    if [[ "$new_n" -gt 0 ]]; then
      echo "  --- New ---"
      printf '%s\n' "$new_list" | sed 's/^/    + /'
    fi
    if [[ "$removed_n" -gt 0 ]]; then
      echo "  --- No longer present on the server ---"
      printf '%s\n' "$removed_list" | sed 's/^/    - /'
    fi
    echo "==================================================================="

    local changes_file
    changes_file="${target_dir%/}/changes_$(date +%Y%m%d_%H%M%S).json"
    {
      echo "{"
      printf '  "compared_at": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      printf '  "previous_file_count": %s,\n' "$old_count"
      printf '  "new_file_count": %s,\n' "$new_n"
      printf '  "removed_file_count": %s,\n' "$removed_n"
      echo '  "new_files": ['
      printf '%s\n' "$new_list" | awk 'NF' | sed 's/\\/\\\\/g; s/"/\\"/g' | sed 's/.*/    "&"/' | sed '$!s/$/,/'
      echo '  ],'
      echo '  "removed_files": ['
      printf '%s\n' "$removed_list" | awk 'NF' | sed 's/\\/\\\\/g; s/"/\\"/g' | sed 's/.*/    "&"/' | sed '$!s/$/,/'
      echo '  ]'
      echo "}"
    } > "$changes_file"
    ok "  [$target_dir] changes report written: $changes_file"
  fi

  rm -f "$old_urls_file" "$new_urls_file"
}

bump_counter() {
  local counter_file="$1" field="$2"
  local lock="${counter_file}.lock"
  while ! mkdir "$lock" 2>/dev/null; do sleep 0.02; done
  local d s
  read -r d s < "$counter_file"
  d=${d:-0}; s=${s:-0}
  if [[ "$field" == "downloaded" ]]; then d=$((d + 1)); else s=$((s + 1)); fi
  echo "$d $s" > "$counter_file"
  rmdir "$lock" 2>/dev/null
}

# ---------- opt-in hash verification of already-downloaded files ----------
# Only ever called from download_worker's cached-file branch, i.e. only for
# a URL whose filename already exists locally from a prior run. Re-fetches
# to a temp file, sha256-compares against the existing local copy, and
# either leaves the local copy alone (identical) or replaces it (changed).
# Never touches files that don't already exist locally — genuinely new
# files always go through the normal download path below, untouched by -H.
verify_cached_file() {
  local url="$1" local_path="$2" manifest_dir="$3" log_file="$4" counter_file="$5"
  local tmp_path old_sha new_sha size rc

  tmp_path="$(mktemp "${local_path}.verify.XXXXXX")"
  "${PROXY_PREFIX[@]}" "$CURL_BIN" -s -S -L --connect-timeout 10 \
    --speed-limit 1024 --speed-time "$STALL_SECS" \
    -A "$USER_AGENT" \
    -o "$tmp_path" "$url" >> "$log_file" 2>&1
  rc=$?

  if [[ $rc -ne 0 || ! -s "$tmp_path" ]]; then
    # Couldn't re-fetch to verify (network hiccup, file pulled from the OD,
    # etc.) — keep the existing local copy rather than losing data, but be
    # honest in the manifest that this run didn't actually confirm it.
    rm -f "$tmp_path"
    old_sha="$(hash_file "$local_path")"
    size=$(wc -c < "$local_path" | tr -d ' ')
    write_manifest_entry "$manifest_dir" "$url" "$local_path" "cached-unverified" "$size" "$old_sha"
    bump_counter "$counter_file" downloaded
    echo "[$(date '+%H:%M:%S')] hash-verify: re-fetch failed (rc=$rc), kept existing local copy for $url" >> "$log_file"
    return
  fi

  old_sha="$(hash_file "$local_path")"
  new_sha="$(hash_file "$tmp_path")"

  if [[ "$old_sha" == "$new_sha" ]]; then
    rm -f "$tmp_path"
    size=$(wc -c < "$local_path" | tr -d ' ')
    write_manifest_entry "$manifest_dir" "$url" "$local_path" "cached-verified" "$size" "$old_sha"
  else
    mv -f "$tmp_path" "$local_path"
    size=$(wc -c < "$local_path" | tr -d ' ')
    write_manifest_entry "$manifest_dir" "$url" "$local_path" "updated" "$size" "$new_sha"
    echo "[$(date '+%H:%M:%S')] hash-verify: CONTENT CHANGED for $url (sha256 ${old_sha:-none} -> $new_sha)" >> "$log_file"
  fi
  bump_counter "$counter_file" downloaded
}

# ---------- per-file download worker ----------
# Sets globals: RESULT_STATUS, RESULT_REMOTE, RESULT_LOCAL_TOP, RESULT_LOCAL_TOTAL
FILE_MAX_TRIES=3   # 1 initial attempt + 2 retries before skipping a hung/failed file

download_worker() {
  local url="$1" base="$2" target_dir="$3" counter_file="$4" manifest_dir="$5" log_file="$6"
  local rel_path local_path part_path attempt rc success=0 sha size

  rel_path="${url#"$base"}"

  # Defense in depth: discover_dir already drops unsafe entries, but this is
  # the point where a path is actually built from server-supplied text.
  if [[ -z "$rel_path" || "$rel_path" == /* ]] || unsafe_entry "$rel_path"; then
    write_manifest_entry "$manifest_dir" "$url" "" "skipped" "" ""
    bump_counter "$counter_file" skipped
    echo "[$(date '+%H:%M:%S')] SKIPPED (unsafe path rejected): $url" >> "$log_file"
    return
  fi

  local_path="${target_dir%/}/${FILES_SUBDIR}/${rel_path}"
  part_path="${local_path}.part"
  mkdir -p "$(dirname "$local_path")"

  if [[ -s "$local_path" ]]; then
    if [[ $VERIFY_HASHES -eq 1 ]]; then
      verify_cached_file "$url" "$local_path" "$manifest_dir" "$log_file" "$counter_file"
    else
      sha="$(hash_file "$local_path")"
      size=$(wc -c < "$local_path" | tr -d ' ')
      write_manifest_entry "$manifest_dir" "$url" "$local_path" "cached" "$size" "$sha"
      bump_counter "$counter_file" downloaded
    fi
    return
  fi

  # A .part file left by an earlier interrupted run can't be trusted to
  # belong to the same version of the remote file, so never resume across
  # runs. (Resume is only used between retries within this one attempt loop.)
  rm -f "$part_path"

  local http_code http_code_file
  for ((attempt = 1; attempt <= FILE_MAX_TRIES; attempt++)); do
    [[ $INTERRUPTED -eq 1 ]] && return
    http_code_file="$(mktemp 2>/dev/null)"
    # No overall --max-time: big files over Tor legitimately take minutes.
    # Instead abort only if the transfer stalls (< 1 KB/s for STALL_SECS).
    # -C - resumes the .part file on retry. The file only gets its real name
    # (mv below) once the transfer has completed, so an interrupted run can
    # never leave a truncated file that later looks like a finished download.
    "${PROXY_PREFIX[@]}" "$CURL_BIN" -s -S -L --connect-timeout 10 \
      --speed-limit 1024 --speed-time "$STALL_SECS" -C - \
      -A "$USER_AGENT" \
      -o "$part_path" -w '%{http_code}' "$url" > "$http_code_file" 2>> "$log_file"
    rc=$?
    http_code="$(cat "$http_code_file" 2>/dev/null)"
    rm -f "$http_code_file"

    # curl only fails (nonzero rc) on connection-level problems, not on HTTP
    # error responses — a 403/404 page comes back as rc=0 with whatever body
    # the server sent, which is why the http_code check matters as much as rc.
    if [[ $rc -eq 0 && "$http_code" == 2* && -s "$part_path" ]]; then
      mv -f "$part_path" "$local_path" && success=1
      break
    fi

    echo "[$(date '+%H:%M:%S')] attempt $attempt failed (rc=$rc http=${http_code:-none}) for $url" >> "$log_file"

    # rc 33 / HTTP 416: server won't honour the resume range, so the partial
    # data is unusable. Start that file over on the next attempt.
    if [[ $rc -eq 33 || "$http_code" == "416" ]]; then
      rm -f "$part_path"
    fi

    # These HTTP statuses mean the server actively rejected this specific
    # file and a retry won't change that — stop burning attempts on it.
    case "$http_code" in
      401|403|404|410)
        rm -f "$part_path"
        echo "[$(date '+%H:%M:%S')] not retrying $url — server returned HTTP $http_code" >> "$log_file"
        break
        ;;
    esac
  done

  if [[ $success -eq 1 ]]; then
    sha="$(hash_file "$local_path")"
    size=$(wc -c < "$local_path" | tr -d ' ')
    write_manifest_entry "$manifest_dir" "$url" "$local_path" "downloaded" "$size" "$sha"
    bump_counter "$counter_file" downloaded
  else
    rm -f "$part_path"
    [[ $attempt -gt $FILE_MAX_TRIES ]] && attempt=$FILE_MAX_TRIES
    write_manifest_entry "$manifest_dir" "$url" "" "skipped" "" ""
    bump_counter "$counter_file" skipped
    echo "[$(date '+%H:%M:%S')] SKIPPED (last: rc=$rc http=${http_code:-none}) after $attempt attempt(s): $url" >> "$log_file"
  fi
}

# ---------- clone + verify a single target ----------
clone_one_target() {
  local target="$1"
  local target_dir="$2"
  mkdir -p "$target_dir"

  local log_file="${target_dir%/}/.dirsnatch.log"
  : > "$log_file"

  FILE_QUEUE=()
  VISITED_DIRS=()
  log "  [$target] scanning directory tree..."
  discover_dir "$target"
  local total_remote=${#FILE_QUEUE[@]}
  ok "  [$target] found $total_remote file(s) on the server."
  if [[ "$total_remote" -eq 0 ]]; then
    diagnose_empty_listing "$target"
  fi

  local manifest_dir="${target_dir%/}/.manifest_parts"
  local manifest_out="${target_dir%/}/manifest.json"
  mkdir -p "$manifest_dir"
  CURRENT_TARGET_DIR="$target_dir"
  CURRENT_MANIFEST_DIR="$manifest_dir"
  CURRENT_MANIFEST_OUT="$manifest_out"
  CURRENT_TOTAL="$total_remote"

  COMPARE_HAD_HISTORY=0
  COMPARE_NEW_ONLY=()
  compare_with_previous_manifest "$target_dir" "$manifest_out" "$target"

  # If we had a usable previous file list (manifest or disk-scan fallback),
  # only actually queue the files flagged as new by that comparison — no
  # need to loop over thousands of already-known files just to stat-check
  # and skip each one. If this is a genuine first run, the full remote list
  # is the queue, same as always.
  if [[ "$COMPARE_HAD_HISTORY" -eq 1 ]]; then
    if [[ $VERIFY_HASHES -eq 1 ]]; then
      ok "  [$target] previous run detected — hash verification is on, so all ${#FILE_QUEUE[@]} currently-listed file(s) will be checked (new files downloaded, previously-seen files re-verified against the server)."
    else
      FILE_QUEUE=("${COMPARE_NEW_ONLY[@]}")
      ok "  [$target] previous run detected — only downloading the ${#FILE_QUEUE[@]} new file(s) found above."
    fi
  fi
  local total=${#FILE_QUEUE[@]}

  if [[ $total -eq 0 ]]; then
    RESULT_STATUS="OK"; RESULT_REMOTE="$total_remote"; RESULT_LOCAL_TOP=0; RESULT_LOCAL_TOTAL=0; RESULT_UPDATED=0
    [[ "$COMPARE_HAD_HISTORY" -eq 1 ]] && ok "  [$target] nothing new since last run."
    merge_manifest "$manifest_dir" "$manifest_out"
    rm -rf "$manifest_dir"
    return
  fi

  # ---- size estimate (derived from the listing pages already fetched during
  # discovery — no extra requests to the target) ----
  if [[ "$SIZE_UNKNOWN_COUNT" -gt 0 ]]; then
    ok "  [$target] estimated size: at least $(human_size "$SIZE_KNOWN_TOTAL") ($SIZE_UNKNOWN_COUNT of $total file(s) didn't list a size in the directory page)"
  else
    ok "  [$target] estimated size: $(human_size "$SIZE_KNOWN_TOTAL")"
  fi
  read -rp "Proceed with downloading this target? (yes/no): " szc
  if [[ "$szc" != "yes" ]]; then
    warn "  [$target] skipped by user choice."
    RESULT_STATUS="SKIPPED"; RESULT_REMOTE="$total"; RESULT_LOCAL_TOP=0; RESULT_LOCAL_TOTAL=0; RESULT_UPDATED=0
    rm -rf "$manifest_dir"
    return
  fi

  # ---- concurrent download ----
  local counter_file="${target_dir%/}/.counters"
  rmdir "${counter_file}.lock" 2>/dev/null
  echo "0 0" > "$counter_file"
  CURRENT_COUNTER_FILE="$counter_file"

  local sem_fifo
  sem_fifo="$(mktemp -u "${target_dir%/}/sem_dl.XXXXXX")"
  mkfifo "$sem_fifo"
  exec 9<>"$sem_fifo"
  rm -f "$sem_fifo"
  local c
  for ((c = 0; c < CONCURRENCY; c++)); do echo >&9; done

  local interactive=0
  [[ -t 0 ]] && interactive=1
  [[ $interactive -eq 1 ]] && log "  (press Enter any time to refresh status)"

  (
    local idx
    for idx in "${!FILE_QUEUE[@]}"; do
      [[ $INTERRUPTED -eq 1 ]] && break
      read -u 9
      ( download_worker "${FILE_QUEUE[$idx]}" "$target" "$target_dir" "$counter_file" "$manifest_dir" "$log_file"; echo >&9 ) &
    done
    wait
  ) &
  local spawn_pid=$!
  CURRENT_SPAWN_PID="$spawn_pid"

  local d s
  while kill -0 "$spawn_pid" 2>/dev/null; do
    read -r d s < "$counter_file" 2>/dev/null
    d=${d:-0}; s=${s:-0}
    print_progress "$((d + s))" "$total" "$s" ""
    if [[ $interactive -eq 1 ]]; then
      read -t 1 -r _key 2>/dev/null
    else
      sleep 1
    fi
  done
  wait "$spawn_pid" 2>/dev/null
  CURRENT_SPAWN_PID=""
  { exec 9>&-; } 2>/dev/null

  read -r d s < "$counter_file" 2>/dev/null
  d=${d:-0}; s=${s:-0}
  print_progress "$((d + s))" "$total" "$s" ""
  echo

  merge_manifest "$manifest_dir" "$manifest_out"
  rm -rf "$manifest_dir"
  ok "  [$target] manifest written: $manifest_out"

  if [[ "$d" -eq 0 && "$s" -gt 0 ]]; then
    diagnose_all_failed "$target" "$log_file"
  fi

  RESULT_UPDATED=0
  if [[ $VERIFY_HASHES -eq 1 ]]; then
    RESULT_UPDATED=$(grep -c '"status":"updated"' "$manifest_out" 2>/dev/null)
    RESULT_UPDATED=${RESULT_UPDATED:-0}
    if [[ "$RESULT_UPDATED" -gt 0 ]]; then
      warn "  [$target] hash verification: $RESULT_UPDATED previously-downloaded file(s) had changed content on the server and were re-pulled."
    else
      ok "  [$target] hash verification: no content changes detected in previously-downloaded files."
    fi
  fi

  RESULT_REMOTE="$total"
  RESULT_LOCAL_TOP="$d"
  RESULT_LOCAL_TOTAL="$d"
  if [[ "$d" -eq "$total" ]]; then
    RESULT_STATUS="OK"
  elif [[ "$s" -gt 0 ]]; then
    RESULT_STATUS="PARTIAL($s skipped)"
  else
    RESULT_STATUS="MISMATCH"
  fi
}

# ---------- run over all targets ----------
declare -a SUMMARY_LINES=()
i=0
for T in "${TARGET_URLS[@]}"; do
  i=$((i + 1))
  PORT_FOR_DIR="$(echo "$T" | sed -E 's#^https?://[^:]+:##; s#/.*$##')"
  if [[ "$SINGLE_TARGET_MODE" -eq 1 ]]; then
    TARGET_DIR="$OUT_DIR"
  else
    TARGET_DIR="${OUT_DIR%/}/port_${PORT_FOR_DIR}"
  fi

  echo
  log "==== [$i/${#TARGET_URLS[@]}] Cloning $T -> $TARGET_DIR ===="
  clone_one_target "$T" "$TARGET_DIR"
  ok "  [$T] status=$RESULT_STATUS remote=$RESULT_REMOTE local_top=$RESULT_LOCAL_TOP local_total=$RESULT_LOCAL_TOTAL updated=$RESULT_UPDATED"
  SUMMARY_LINES+=("$T|$TARGET_DIR|$RESULT_STATUS|$RESULT_REMOTE|$RESULT_LOCAL_TOP|$RESULT_LOCAL_TOTAL|$RESULT_UPDATED")
done

# ---------- final summary ----------
echo
echo "======================================= SUMMARY ======================================="
printf '%-38s %-16s %-9s %-8s %-10s %-9s %-8s\n' "TARGET" "STATUS" "REMOTE" "LOC_TOP" "LOC_TOTAL" "UPDATED" "DIR"
while IFS='|' read -r t d s r lt ltot upd; do
  printf '%-38s %-16s %-9s %-8s %-10s %-9s %s\n' "$t" "$s" "$r" "$lt" "$ltot" "$upd" "$d"
done < <(printf '%s\n' "${SUMMARY_LINES[@]}")
echo "=========================================================================================="
[[ $VERIFY_HASHES -eq 0 ]] && echo "(UPDATED column is only populated when hash verification was enabled for this run)"

echo
ok "Done. Output parent directory: $OUT_DIR"
