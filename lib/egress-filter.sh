#!/usr/bin/env bash
# egress-filter.sh — Egress traffic filtering for claude-sandbox
# Sourced by sandbox.sh
#
# Requires: PYTHON3, COREUTILS, SANDBOX_TMPDIR — provided by sandbox.sh before sourcing.

# Default path inside sandbox where the egress proxy config lives
EGRESS_PROXY_SCRIPT="@EGRESS_PROXY@"

# setup_egress_filter WHITELIST_ARRAY BLACKLIST_ARRAY
#
# Generates the egress filter proxy configuration and starts the proxy.
# Sets EGRESS_PROXY_PORT to the port the proxy is listening on.
# Sets EGRESS_PROXY_PID to the proxy process PID.
#
# Whitelist/blacklist entries use glob syntax (fnmatch):
#   "*.anthropic.com"     — matches api.anthropic.com, docs.anthropic.com
#   "api.github.com"      — exact match
#   "*.example.*"         — matches foo.example.com, bar.example.org
#
# Rules:
#   - If whitelist is non-empty: ONLY whitelist entries are allowed
#   - If whitelist is empty: everything allowed EXCEPT blacklist entries
setup_egress_filter() {
  local -n _whitelist=$1
  local -n _blacklist=$2

  # Create egress config JSON
  local egress_config="${SANDBOX_TMPDIR}/egress-config.json"

  # Build JSON manually to avoid jq dependency in this function
  local wl_json="["
  local first=1
  for entry in "${_whitelist[@]}"; do
    [[ -z "$entry" ]] && continue
    [[ "$first" == "1" ]] && first=0 || wl_json+=","
    wl_json+="\"${entry}\""
  done
  wl_json+="]"

  local bl_json="["
  first=1
  for entry in "${_blacklist[@]}"; do
    [[ -z "$entry" ]] && continue
    [[ "$first" == "1" ]] && first=0 || bl_json+=","
    bl_json+="\"${entry}\""
  done
  bl_json+="]"

  cat > "$egress_config" << EOF
{"whitelist": ${wl_json}, "blacklist": ${bl_json}}
EOF

  local pidfile="${SANDBOX_TMPDIR}/egress-proxy.pid"
  local portfile="${SANDBOX_TMPDIR}/egress-proxy.port"

  # Start the proxy in the background
  # When network isolation is active (NET_NS_ACTIVE=1), the proxy must bind
  # to 0.0.0.0 so it's reachable from the sandbox via slirp4netns gateway.
  local bind_addr="127.0.0.1"
  if [[ "${NET_NS_ACTIVE:-0}" == "1" ]]; then
    bind_addr="0.0.0.0"
  fi

  "$PYTHON3" "$EGRESS_PROXY_SCRIPT" \
    --config "$egress_config" \
    --bind "$bind_addr" \
    --port 0 \
    --pidfile "$pidfile" \
    --portfile "$portfile" \
    &

  local proxy_bg_pid=$!

  # Wait for the proxy to signal readiness (up to 5 seconds)
  local waited=0
  while [[ ! -f "$portfile" ]] && [[ "$waited" -lt 50 ]]; do
    sleep 0.1
    waited=$((waited + 1))
    # Check if process is still alive
    if ! kill -0 "$proxy_bg_pid" 2>/dev/null; then
      echo "Error: egress filter proxy failed to start" >&2
      return 1
    fi
  done

  if [[ ! -f "$portfile" ]]; then
    echo "Error: egress filter proxy did not become ready within 5 seconds" >&2
    kill "$proxy_bg_pid" 2>/dev/null || true
    return 1
  fi

  EGRESS_PROXY_PORT="$(cat "$portfile")"
  EGRESS_PROXY_PID="$proxy_bg_pid"

  return 0
}

# stop_egress_filter
#
# Stops the egress filter proxy if it is running.
stop_egress_filter() {
  if [[ -n "${EGRESS_PROXY_PID:-}" ]]; then
    kill "$EGRESS_PROXY_PID" 2>/dev/null || true
    wait "$EGRESS_PROXY_PID" 2>/dev/null || true
    EGRESS_PROXY_PID=""
  fi
}
