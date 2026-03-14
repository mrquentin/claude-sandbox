#!/usr/bin/env bash
# healthcheck.sh — Self-test for claude-sandbox
# Sourced by sandbox.sh when 'test' subcommand is used.

BWRAP="@BWRAP@"
TOOL_PATH="@TOOL_PATH@"
SSL_CERT_FILE="@SSL_CERT_FILE@"
SANDBOX_BASH="@BASH@"
GIT="@GIT@"
CURL="@CURL@"
TRUE="@TRUE@"

PASS=0
FAIL=0
WARN=0

check_pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
check_fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
check_warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }

run_healthcheck() {
  echo "claude-sandbox health check"
  echo "════════════════════════════════════════════"

  # 1. bwrap binary
  echo ""
  echo "Core dependencies:"
  if [[ -x "$BWRAP" ]]; then
    check_pass "bwrap found at $BWRAP"
  else
    check_fail "bwrap not found at $BWRAP"
  fi

  # 2. User namespace support
  if "$BWRAP" --unshare-user --uid 1000 --gid 1000 --ro-bind / / -- "$TRUE" 2>/dev/null; then
    check_pass "User namespaces work"
  else
    check_warn "User namespaces not available (sandbox will run without UID isolation)"
  fi

  # 3. PID namespace
  if "$BWRAP" --unshare-pid --ro-bind / / --dev /dev --proc /proc -- "$TRUE" 2>/dev/null; then
    check_pass "PID namespace works"
  else
    check_warn "PID namespace not available (sandbox will run without PID isolation)"
  fi

  # 4. Full sandbox test
  echo ""
  echo "Sandbox functionality:"
  if "$BWRAP" \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --unshare-pid \
    --unshare-ipc \
    --unshare-uts \
    --die-with-parent \
    -- "$TRUE" 2>/dev/null; then
    check_pass "Basic sandbox creation works"
  else
    check_fail "Basic sandbox creation failed"
  fi

  # 5. Read-only enforcement
  if ! "$BWRAP" \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --unshare-pid \
    -- "$SANDBOX_BASH" -c 'touch /etc/test-write 2>/dev/null' 2>/dev/null; then
    check_pass "Read-only filesystem enforced"
  else
    check_fail "Read-only filesystem NOT enforced (writes to /etc succeeded)"
  fi

  # 6. DNS + HTTPS check (use curl since getent may not be in tool PATH)
  echo ""
  echo "Network & DNS:"
  if "$BWRAP" \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    -- "$SANDBOX_BASH" -c "\"$CURL\" -sI --max-time 5 https://api.anthropic.com >/dev/null 2>&1" 2>/dev/null; then
    check_pass "DNS + HTTPS works inside sandbox"
  else
    check_warn "DNS/HTTPS check failed inside sandbox"
  fi

  # 7. SSL certificates
  if [[ -f "$SSL_CERT_FILE" ]]; then
    check_pass "SSL certificate bundle found"
  else
    check_fail "SSL certificate bundle missing: $SSL_CERT_FILE"
  fi

  # 8. Git
  echo ""
  echo "Tools:"
  if [[ -x "$GIT" ]]; then
    check_pass "git available"
  else
    check_fail "git not found"
  fi

  # 9. Claude binary
  if command -v claude >/dev/null 2>&1; then
    check_pass "claude binary found in PATH"
  else
    check_warn "claude binary not in current PATH (will need to be in TOOL_PATH)"
  fi

  # 10. WSL2 detection
  echo ""
  echo "Platform:"
  if grep -qi "microsoft" /proc/version 2>/dev/null; then
    check_warn "WSL2 detected — Windows interop will be blocked in sandbox"
    if [[ -e /proc/sys/fs/binfmt_misc/WSLInterop ]]; then
      check_pass "WSLInterop binfmt_misc entry found (will be masked)"
    fi
  else
    check_pass "Native Linux (not WSL2)"
  fi

  # 11. FUSE
  if [[ -e /dev/fuse ]]; then
    check_pass "FUSE available (overlay mode supported)"
  else
    check_warn "FUSE not available (overlay mode will not work, bwrap-only mode OK)"
  fi

  # Summary
  echo ""
  echo "════════════════════════════════════════════"
  echo "Results: $PASS passed, $FAIL failed, $WARN warnings"

  if [[ "$FAIL" -gt 0 ]]; then
    echo ""
    echo "Some checks failed. The sandbox may not work correctly."
    return 1
  elif [[ "$WARN" -gt 0 ]]; then
    echo ""
    echo "Some warnings. The sandbox will work with reduced isolation."
    return 0
  else
    echo ""
    echo "All checks passed. Sandbox is ready."
    return 0
  fi
}
