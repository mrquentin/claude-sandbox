#!/usr/bin/env bash
# detect.sh — Environment detection for claude-sandbox
# Sourced by sandbox.sh; sets global variables.
# Uses BWRAP/TRUE from caller if already set; falls back to Nix paths.

: "${BWRAP:=@BWRAP@}"
: "${TRUE:=@TRUE@}"
GNUGREP="@GNUGREP@"
COREUTILS="@COREUTILS@"

detect_environment() {
  # ── WSL2 detection ──────────────────────────────────────────────
  IS_WSL2="0"
  if [[ -f /proc/version ]] && "$GNUGREP" -qi "microsoft" /proc/version 2>/dev/null; then
    IS_WSL2="1"
  fi

  # ── User namespace support ─────────────────────────────────────
  HAS_USER_NS="0"
  if "$BWRAP" --unshare-user --uid 1000 --gid 1000 --ro-bind / / -- "$TRUE" 2>/dev/null; then
    HAS_USER_NS="1"
  fi

  # ── PID namespace support ──────────────────────────────────────
  HAS_PID_NS="0"
  if "$BWRAP" --unshare-pid --ro-bind / / --dev /dev --proc /proc -- "$TRUE" 2>/dev/null; then
    HAS_PID_NS="1"
  fi

  # ── FUSE support ───────────────────────────────────────────────
  HAS_FUSE="0"
  if [[ -e /dev/fuse ]]; then
    HAS_FUSE="1"
  fi

  export IS_WSL2 HAS_USER_NS HAS_PID_NS HAS_FUSE
}
