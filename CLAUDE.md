# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

claude-sandbox is an OS-level sandbox for Claude Code using bubblewrap (bwrap) on NixOS/Linux. It provides namespace isolation, read-only filesystem enforcement, seccomp filtering, and credential protection. Supports x86_64-linux and aarch64-linux.

## Build & Development Commands

```bash
nix develop                                    # Enter dev shell with all tools
nix build                                      # Build the sandbox package
./result/bin/claude-sandbox --test             # Run health check suite (13 checks)
./result/bin/claude-sandbox --security-test ~/project  # Run security validation inside sandbox
./result/bin/claude-sandbox --dry-run ~/project        # Print bwrap command without executing
./result/bin/claude-sandbox --verbose ~/project        # Show full config before launch
```

There is no separate lint or unit test command — the test suite is the `--test` (healthcheck) and `--security-test` (in-sandbox validation) flags on the built binary.

## Architecture

The sandbox works by constructing a bubblewrap command with layered isolation:

1. **`flake.nix`** — Defines three tool profiles (minimal/default/full), builds the seccomp BPF filter at build time via `lib/seccomp.nix`, patches all Nix store paths into `sandbox.sh`, and wraps the binary.

2. **`lib/sandbox.sh`** — Main entry point. Parses CLI args, loads user config (`~/.config/claude-sandbox/config.json`), calls `detect.sh` for platform detection, sets up a temporary sandbox home, runs `sanitize-git.sh`, constructs bwrap arguments (namespaces, bind mounts, seccomp FD, env vars), and executes.

3. **`lib/detect.sh`** — Exports `detect_environment()` which probes for WSL2, user/PID namespace support, and FUSE availability. Results drive conditional bwrap flags in `sandbox.sh`.

4. **`lib/sanitize-git.sh`** — Strips dangerous git config sections (credential helpers, aliases, includes, hooks) to prevent command execution or credential leaks inside the sandbox.

5. **`lib/seccomp.nix`** / **`lib/seccomp-gen.py`** — BPF filter generators. `seccomp.nix` runs at Nix build time to produce the default filter blocking 31 syscalls. `seccomp-gen.py` supports runtime generation with user-specified extra blocked syscalls.

6. **`lib/healthcheck.sh`** — Run via `--test`. Validates bwrap, namespaces, filesystem isolation, DNS, SSL, git, and Claude binary presence outside the sandbox.

7. **`lib/command-filter.sh`** — Generates PATH-based command filter wrappers. For each blocked command pattern (e.g., `"az * delete"`), creates a symlink to a shared `_filter_exec` script that uses bash glob matching to block or pass through. The filter directory is bind-mounted read-only at `/opt/command-filters` inside the sandbox.

8. **`lib/security-tests.sh`** — Run via `--security-test`. Executes inside the actual sandbox to verify all isolation guarantees (filesystem, credentials, namespaces, capabilities, seccomp, environment, git sanitization, command filtering).

9. **`modules/nixos.nix`** — Declarative NixOS module for system-level integration with options for profile, extra packages, bind mounts, and SSH agent forwarding.

## Key Design Details

- The build process uses `substituteInPlace` to hardcode Nix store paths into `sandbox.sh` — all tool references are absolute paths, not PATH lookups.
- User config can add extra nixpkgs at runtime via `nix build` (resolved dynamically in `sandbox.sh`).
- Sandbox home is a temp dir (`/tmp/claude-sandbox.XXXXXX`) that gets credential-scrubbed on exit (dd from urandom).
- `~/.claude` is mounted read-only with tmpfs overlays for directories that need writes.
- WSL2 gets special handling: Windows drive mounts (`/mnt/[a-z]`) are masked.
- All scripts are bash; seccomp generation uses Python3.
