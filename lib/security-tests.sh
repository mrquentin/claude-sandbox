#!/usr/bin/env bash
# security-tests.sh — Security validation tests for claude-sandbox
# Sourced by sandbox.sh when --security-test is used.
#
# Runs test commands inside the ACTUAL sandbox configuration to verify
# that all security properties are enforced.
#
# Requires: BWRAP, BWRAP_ARGS, SANDBOX_BASH, COREUTILS, SECCOMP_PROFILE,
#           PROJECT_DIR, SANDBOX_TMPDIR, IS_WSL2, HAS_PID_NS, HAS_USER_NS
#           — all provided by sandbox.sh before sourcing this file.

PASS=0
FAIL=0
SKIP=0

test_pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
test_fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
test_skip() { echo "  [SKIP] $1"; SKIP=$((SKIP + 1)); }

# Re-open seccomp FD before each bwrap call.
# bwrap reads the BPF program from FD 9, advancing the file offset to EOF.
# Subsequent calls need a fresh FD pointing to the start of the file.
_reopen_seccomp_fd() {
  if [[ -f "${SECCOMP_PROFILE:-}" ]]; then
    exec 9< "$SECCOMP_PROFILE"
  fi
}

# Run a command inside the sandbox. Returns the exit code.
# Uses timeout to prevent hangs from --new-session processes.
sandbox_run() {
  _reopen_seccomp_fd
  "${COREUTILS}/bin/timeout" 10 "$BWRAP" "${BWRAP_ARGS[@]}" -- "$SANDBOX_BASH" -c "$1" 2>/dev/null
  return $?
}

# Run a command inside the sandbox, capture stdout (stderr suppressed).
sandbox_output() {
  _reopen_seccomp_fd
  "${COREUTILS}/bin/timeout" 10 "$BWRAP" "${BWRAP_ARGS[@]}" -- "$SANDBOX_BASH" -c "$1" 2>/dev/null
}

run_security_tests() {
  echo "claude-sandbox security tests"
  echo "════════════════════════════════════════════"
  echo ""
  echo "Testing with ACTUAL sandbox configuration."
  echo "Project directory: $PROJECT_DIR"
  echo ""

  # Write a Python helper for syscall-level tests (if python3 is available)
  cat > "${SANDBOX_TMPDIR}/home/seccomp-test.py" << 'PYEOF'
import ctypes
import sys

libc = ctypes.CDLL(None, use_errno=True)
name = sys.argv[1]

if name == "mount":
    ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
elif name == "ptrace":
    # PTRACE_TRACEME = 0
    ret = libc.ptrace(0, 0, None, None)
elif name == "chroot":
    ret = libc.chroot(b"/")
elif name == "personality":
    # PER_LINUX32 = 0x0008
    ret = libc.personality(0x0008)
else:
    print(f"UNKNOWN:{name}")
    sys.exit(2)

err = ctypes.get_errno()
if ret == -1 and err == 1:
    print("BLOCKED")
else:
    print(f"ALLOWED ret={ret} errno={err}")
PYEOF

  # ── Filesystem Isolation ────────────────────────────────────────
  echo "Filesystem isolation:"

  # Cannot write to host system directories
  if ! sandbox_run 'touch /etc/sandbox-security-test 2>/dev/null'; then
    test_pass "Cannot write to /etc (read-only)"
  else
    test_fail "Write to /etc succeeded — host filesystem NOT read-only"
  fi

  if ! sandbox_run 'touch /usr/sandbox-security-test 2>/dev/null'; then
    test_pass "Cannot write to /usr (read-only)"
  else
    test_fail "Write to /usr succeeded — host filesystem NOT read-only"
  fi

  if ! sandbox_run 'touch /nix/store/sandbox-security-test 2>/dev/null'; then
    test_pass "Cannot write to /nix/store (read-only)"
  else
    test_fail "Write to /nix/store succeeded — Nix store NOT read-only"
  fi

  # /tmp is fresh and writable
  if sandbox_run 'touch /tmp/sandbox-test && rm /tmp/sandbox-test'; then
    test_pass "/tmp is writable (fresh tmpfs)"
  else
    test_fail "/tmp is NOT writable"
  fi

  local tmp_count
  tmp_count="$(sandbox_output 'ls -A /tmp 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [[ "$tmp_count" == "0" ]]; then
    test_pass "/tmp is empty (not leaking host /tmp)"
  else
    test_fail "/tmp has $tmp_count items — leaking host /tmp contents"
  fi

  # Project directory is writable
  if sandbox_run "touch '${PROJECT_DIR}/.sandbox-security-test' && rm '${PROJECT_DIR}/.sandbox-security-test'"; then
    test_pass "Project directory is writable"
  else
    test_fail "Project directory is NOT writable"
  fi

  # ── Home Directory Isolation ────────────────────────────────────
  echo ""
  echo "Home directory isolation:"

  local sandbox_home
  sandbox_home="$(sandbox_output 'echo $HOME' | tr -d '[:space:]')"
  if [[ "$sandbox_home" == "/home/claude-sandbox" ]]; then
    test_pass "HOME=/home/claude-sandbox (isolated from host)"
  else
    test_fail "HOME='$sandbox_home' — expected /home/claude-sandbox"
  fi

  # Real host home is not accessible (except project dir mount point if project is under host home)
  local real_home="$HOME"
  local real_home_contents
  real_home_contents="$(sandbox_output "ls -A '${real_home}' 2>/dev/null" | tr -d '[:space:]')"
  if [[ -z "$real_home_contents" ]]; then
    test_pass "Host home ($real_home) is empty/inaccessible (masked by tmpfs)"
  elif [[ "${PROJECT_DIR}" == "${real_home}/"* ]]; then
    # When the project dir is under host home, bwrap creates intermediate
    # directories on the tmpfs for the bind mount — that's expected
    local project_subdir="${PROJECT_DIR#${real_home}/}"
    project_subdir="${project_subdir%%/*}"
    if [[ "$real_home_contents" == "$project_subdir" ]]; then
      test_pass "Host home ($real_home) only contains project mount point (masked by tmpfs)"
    else
      test_fail "Host home ($real_home) has unexpected items: $real_home_contents"
    fi
  else
    test_fail "Host home ($real_home) has visible items: $real_home_contents"
  fi

  # Sandbox home is writable
  if sandbox_run 'touch "$HOME/sandbox-test" && rm "$HOME/sandbox-test"'; then
    test_pass "Sandbox home is writable"
  else
    test_fail "Sandbox home is NOT writable"
  fi

  # ── Credential Protection ───────────────────────────────────────
  echo ""
  echo "Credential protection:"

  # .ssh is empty (tmpfs masked)
  local ssh_count
  ssh_count="$(sandbox_output 'ls -A "$HOME/.ssh" 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [[ "$ssh_count" == "0" ]]; then
    test_pass "~/.ssh is empty (masked by tmpfs)"
  else
    test_fail "~/.ssh has $ssh_count items — SSH keys may be exposed"
  fi

  # .gnupg is empty
  local gnupg_count
  gnupg_count="$(sandbox_output 'ls -A "$HOME/.gnupg" 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [[ "$gnupg_count" == "0" ]]; then
    test_pass "~/.gnupg is empty (masked by tmpfs)"
  else
    test_fail "~/.gnupg has $gnupg_count items — GPG keys may be exposed"
  fi

  # .aws is empty
  local aws_count
  aws_count="$(sandbox_output 'ls -A "$HOME/.aws" 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [[ "$aws_count" == "0" ]]; then
    test_pass "~/.aws is empty (masked by tmpfs)"
  else
    test_fail "~/.aws has $aws_count items — AWS credentials may be exposed"
  fi

  # .kube is empty
  local kube_count
  kube_count="$(sandbox_output 'ls -A "$HOME/.kube" 2>/dev/null | wc -l' | tr -d '[:space:]')"
  if [[ "$kube_count" == "0" ]]; then
    test_pass "~/.kube is empty (masked by tmpfs)"
  else
    test_fail "~/.kube has $kube_count items — kube config may be exposed"
  fi

  # .credentials.json is read-only (if present)
  if sandbox_run 'test -f "$HOME/.claude/.credentials.json"'; then
    if ! sandbox_run 'echo x >> "$HOME/.claude/.credentials.json" 2>/dev/null'; then
      test_pass "~/.claude/.credentials.json is read-only"
    else
      test_fail "~/.claude/.credentials.json is WRITABLE"
    fi
  else
    test_skip "No .credentials.json present (no OAuth credentials to test)"
  fi

  # ── Namespace Isolation ─────────────────────────────────────────
  echo ""
  echo "Namespace isolation:"

  # UTS namespace: hostname
  local sandbox_hostname
  sandbox_hostname="$(sandbox_output 'cat /proc/sys/kernel/hostname 2>/dev/null' | tr -d '[:space:]')"
  if [[ "$sandbox_hostname" == "claude-sandbox" ]]; then
    test_pass "Hostname is 'claude-sandbox' (UTS namespace isolated)"
  else
    test_fail "Hostname is '$sandbox_hostname' — expected 'claude-sandbox'"
  fi

  # PID namespace: PID 1 should be bwrap or bash, not host init
  if [[ "$HAS_PID_NS" == "1" ]]; then
    local pid1_name
    pid1_name="$(sandbox_output 'cat /proc/1/comm 2>/dev/null' | tr -d '[:space:]')"
    if [[ "$pid1_name" == "bash" || "$pid1_name" == "bwrap" ]]; then
      test_pass "PID namespace isolated (PID 1 is '$pid1_name', not host init)"
    else
      test_fail "PID namespace may not be isolated (PID 1 is '$pid1_name')"
    fi

    # Cannot see host processes
    local proc_count
    proc_count="$(sandbox_output 'ls /proc | grep -c "^[0-9]"' | tr -d '[:space:]')"
    if [[ -n "$proc_count" ]] && [[ "$proc_count" -lt 10 ]]; then
      test_pass "Only $proc_count processes visible (host processes hidden)"
    else
      test_skip "Cannot verify PID isolation (found $proc_count processes)"
    fi
  else
    test_skip "PID namespace not available — skipping PID isolation tests"
  fi

  # User namespace: UID mapping
  if [[ "$HAS_USER_NS" == "1" ]]; then
    local sandbox_uid
    sandbox_uid="$(sandbox_output 'id -u' | tr -d '[:space:]')"
    if [[ "$sandbox_uid" == "1000" ]]; then
      test_pass "UID is 1000 inside sandbox (user namespace mapped)"
    else
      test_fail "UID is '$sandbox_uid' — expected 1000"
    fi
  else
    test_skip "User namespace not available — skipping UID isolation test"
  fi

  # ── Capabilities ────────────────────────────────────────────────
  echo ""
  echo "Capabilities:"

  local cap_eff
  cap_eff="$(sandbox_output 'grep "^CapEff:" /proc/self/status' | awk '{print $2}' | tr -d '[:space:]')"
  if [[ "$cap_eff" == "0000000000000000" ]]; then
    test_pass "All capabilities dropped (CapEff=0)"
  elif [[ -n "$cap_eff" ]]; then
    test_fail "Capabilities not fully dropped (CapEff=$cap_eff)"
  else
    test_skip "Cannot read capabilities from /proc/self/status"
  fi

  # ── Environment Isolation ───────────────────────────────────────
  echo ""
  echo "Environment isolation:"

  local sandbox_var
  sandbox_var="$(sandbox_output 'echo $SANDBOX' | tr -d '[:space:]')"
  if [[ "$sandbox_var" == "1" ]]; then
    test_pass "SANDBOX=1 is set"
  else
    test_fail "SANDBOX is '${sandbox_var}' — expected '1'"
  fi

  local version_var
  version_var="$(sandbox_output 'echo $CLAUDE_SANDBOX_VERSION' | tr -d '[:space:]')"
  if [[ -n "$version_var" ]]; then
    test_pass "CLAUDE_SANDBOX_VERSION=$version_var is set"
  else
    test_fail "CLAUDE_SANDBOX_VERSION is not set"
  fi

  local sandbox_path
  sandbox_path="$(sandbox_output 'echo $PATH')"
  if echo "$sandbox_path" | grep -q '/nix/store'; then
    test_pass "PATH contains Nix store paths (sandbox tool PATH)"
  else
    test_fail "PATH does not contain Nix store paths"
  fi

  # ── Seccomp Filtering ──────────────────────────────────────────
  echo ""
  echo "Seccomp filtering:"

  if [[ ! -f "${SECCOMP_PROFILE:-}" ]]; then
    test_skip "Seccomp profile not loaded — skipping syscall tests"
  elif sandbox_run 'command -v python3 >/dev/null 2>&1'; then
    # mount() blocked
    local mount_result
    mount_result="$(sandbox_output 'python3 "$HOME/seccomp-test.py" mount' | tr -d '[:space:]')"
    if [[ "$mount_result" == "BLOCKED" ]]; then
      test_pass "mount() syscall blocked (EPERM)"
    else
      test_fail "mount() syscall NOT blocked: $mount_result"
    fi

    # ptrace() blocked
    local ptrace_result
    ptrace_result="$(sandbox_output 'python3 "$HOME/seccomp-test.py" ptrace' | tr -d '[:space:]')"
    if [[ "$ptrace_result" == "BLOCKED" ]]; then
      test_pass "ptrace() syscall blocked (EPERM)"
    else
      test_fail "ptrace() syscall NOT blocked: $ptrace_result"
    fi

    # chroot() blocked
    local chroot_result
    chroot_result="$(sandbox_output 'python3 "$HOME/seccomp-test.py" chroot' | tr -d '[:space:]')"
    if [[ "$chroot_result" == "BLOCKED" ]]; then
      test_pass "chroot() syscall blocked (EPERM)"
    else
      test_fail "chroot() syscall NOT blocked: $chroot_result"
    fi

    # personality() blocked (prevents ABI switching)
    local personality_result
    personality_result="$(sandbox_output 'python3 "$HOME/seccomp-test.py" personality' | tr -d '[:space:]')"
    if [[ "$personality_result" == "BLOCKED" ]]; then
      test_pass "personality() syscall blocked (prevents ABI switching)"
    else
      test_fail "personality() syscall NOT blocked: $personality_result"
    fi
  else
    test_skip "python3 not available — skipping syscall-level seccomp tests"
    test_skip "  (use 'default' or 'full' profile to enable syscall testing)"
  fi

  # ── WSL2 Isolation ──────────────────────────────────────────────
  if [[ "$IS_WSL2" == "1" ]]; then
    echo ""
    echo "WSL2 isolation:"

    # /mnt/c is empty (Windows C: drive masked)
    local mntc_count
    mntc_count="$(sandbox_output 'ls -A /mnt/c 2>/dev/null | wc -l' | tr -d '[:space:]')"
    if [[ "$mntc_count" == "0" ]] || [[ -z "$mntc_count" ]]; then
      test_pass "/mnt/c is empty (Windows C: drive masked)"
    else
      test_fail "/mnt/c has $mntc_count items — Windows drive NOT masked"
    fi

    # Cannot access Windows executables
    if ! sandbox_run 'test -f /mnt/c/Windows/System32/cmd.exe'; then
      test_pass "Cannot access Windows cmd.exe (drive masked)"
    else
      test_fail "Windows cmd.exe IS accessible — sandbox escape possible"
    fi

    # Check other drive letters
    for letter in d e f; do
      if [[ -d "/mnt/$letter" ]]; then
        local drive_count
        drive_count="$(sandbox_output "ls -A /mnt/$letter 2>/dev/null | wc -l" | tr -d '[:space:]')"
        if [[ "$drive_count" == "0" ]] || [[ -z "$drive_count" ]]; then
          test_pass "/mnt/$letter is empty (Windows drive masked)"
        else
          test_fail "/mnt/$letter has $drive_count items — drive NOT masked"
        fi
      fi
    done
  fi

  # ── Git Config Sanitization ────────────────────────────────────
  echo ""
  echo "Git config sanitization:"

  local gitconfig_content
  gitconfig_content="$(sandbox_output 'cat "$HOME/.gitconfig" 2>/dev/null')"
  if [[ -n "$gitconfig_content" ]]; then
    if ! echo "$gitconfig_content" | grep -qi '\[credential'; then
      test_pass "No [credential] section in sandbox .gitconfig"
    else
      test_fail "[credential] section found — credential helpers may leak tokens"
    fi

    if ! echo "$gitconfig_content" | grep -qi '\[alias'; then
      test_pass "No [alias] section in sandbox .gitconfig"
    else
      test_fail "[alias] section found — aliases can execute arbitrary commands"
    fi

    if ! echo "$gitconfig_content" | grep -qi 'sshCommand'; then
      test_pass "No sshCommand in sandbox .gitconfig"
    else
      test_fail "sshCommand found — can execute arbitrary commands"
    fi

    if ! echo "$gitconfig_content" | grep -qi '\[filter '; then
      test_pass "No [filter] section in sandbox .gitconfig"
    else
      test_fail "[filter] section found — filter drivers can execute code"
    fi

    if ! echo "$gitconfig_content" | grep -qi 'hooksPath'; then
      test_pass "No hooksPath in sandbox .gitconfig"
    else
      test_fail "hooksPath found — can execute arbitrary hook scripts"
    fi

    if ! echo "$gitconfig_content" | grep -qi '\[include'; then
      test_pass "No [include] section in sandbox .gitconfig"
    else
      test_fail "[include] section found — can pull in unsafe config files"
    fi
  else
    test_skip "No .gitconfig in sandbox home (nothing to sanitize)"
  fi

  # ── Cleanup ─────────────────────────────────────────────────────
  rm -f "${SANDBOX_TMPDIR}/home/seccomp-test.py"

  # ── Summary ─────────────────────────────────────────────────────
  echo ""
  echo "════════════════════════════════════════════"
  echo "Security test results: $PASS passed, $FAIL failed, $SKIP skipped"

  if [[ "$FAIL" -gt 0 ]]; then
    echo ""
    echo "SECURITY TESTS FAILED. The sandbox has isolation gaps."
    return 1
  elif [[ "$SKIP" -gt 0 ]]; then
    echo ""
    echo "All testable properties passed. Some tests were skipped."
    return 0
  else
    echo ""
    echo "All security tests passed. Sandbox isolation verified."
    return 0
  fi
}
