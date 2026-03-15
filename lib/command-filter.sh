#!/usr/bin/env bash
# command-filter.sh — Generate command filter wrappers for blocked command patterns
# Sourced by sandbox.sh
#
# Requires: COREUTILS, SANDBOX_BASH — provided by sandbox.sh before sourcing.

# Path where the filter directory is mounted inside the sandbox (read-only)
SANDBOX_FILTER_DIR="/opt/command-filters"

# generate_command_filters FILTER_DIR PATTERNS...
#
# Creates wrapper scripts in FILTER_DIR that intercept and block commands
# matching the specified glob patterns.
#
# Patterns use shell glob syntax:
#   "az"                   — blocks all invocations of az
#   "az * delete"          — blocks "az group delete", "az vm delete", etc.
#   "kubectl delete ns *"  — blocks "kubectl delete ns production", etc.
#   "rm -rf /"             — blocks "rm -rf /"
#
# The filter directory should be bind-mounted read-only inside the sandbox
# at SANDBOX_FILTER_DIR and prepended to PATH.
generate_command_filters() {
  local filter_dir="$1"
  shift
  local patterns=("$@")

  "${COREUTILS}/bin/mkdir" -p "$filter_dir"

  # Write patterns to a config file (one per line)
  local patterns_file="${filter_dir}/_patterns.conf"
  : > "$patterns_file"
  for pattern in "${patterns[@]}"; do
    [[ -z "$pattern" ]] && continue
    printf '%s\n' "$pattern" >> "$patterns_file"
  done

  # Create the filter execution script
  # This script is invoked via symlink — the symlink name determines which
  # command is being filtered.
  local filter_exec="${filter_dir}/_filter_exec"
  cat > "$filter_exec" << 'FILTER_SCRIPT'
#!/usr/bin/env bash
# claude-sandbox command filter — do not modify (read-only mount)
set -uo pipefail

_CMD="$(basename "$0")"
_DIR="$(dirname "$0")"

# Check if the command matches any blocked pattern
while IFS= read -r _p || [[ -n "$_p" ]]; do
  [[ -z "$_p" || "$_p" == "#"* ]] && continue

  # Only check patterns that start with this command
  _base="${_p%% *}"
  [[ "$_base" != "$_CMD" ]] && continue

  # Bare command name: block all invocations
  if [[ "$_p" == "$_CMD" ]]; then
    echo "[claude-sandbox] BLOCKED: '$_CMD' is a blocked command" >&2
    exit 126
  fi

  # Pattern with arguments: glob match
  if [[ $# -gt 0 ]]; then
    _FULL="$_CMD $*"
    if [[ "$_FULL" == $_p ]]; then
      echo "[claude-sandbox] BLOCKED: '$_FULL' matches blocked pattern '$_p'" >&2
      exit 126
    fi
  fi
done < "${_DIR}/_patterns.conf"

# No pattern matched — execute the real command
# Remove the filter directory from PATH to find the real binary
_P=":${PATH}:"
_P="${_P/:${_DIR}:/:}"
_P="${_P#:}"
_P="${_P%:}"

_REAL="$(PATH="$_P" command -v "$_CMD" 2>/dev/null)"
if [[ -z "$_REAL" ]]; then
  echo "${_CMD}: command not found" >&2
  exit 127
fi

exec "$_REAL" "$@"
FILTER_SCRIPT

  "${COREUTILS}/bin/chmod" +x "$filter_exec"

  # Create symlinks for each unique base command
  declare -A seen_cmds
  for pattern in "${patterns[@]}"; do
    [[ -z "$pattern" ]] && continue
    local base_cmd="${pattern%% *}"
    [[ -z "$base_cmd" ]] && continue
    if [[ -z "${seen_cmds[$base_cmd]+x}" ]]; then
      seen_cmds[$base_cmd]=1
      ln -sf "_filter_exec" "${filter_dir}/${base_cmd}"
    fi
  done
}
