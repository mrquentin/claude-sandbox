#!/usr/bin/env bash
# claude-sandbox — OS-level sandbox for Claude Code using bubblewrap
# https://github.com/mrquentin/claude-sandbox
set -euo pipefail

# ── Paths injected by Nix at build time ─────────────────────────────
BWRAP="@BWRAP@"
TOOL_PATH="@TOOL_PATH@"
SSL_CERT_FILE="@SSL_CERT_FILE@"
SANDBOX_BASH="@BASH@"
LIB_DIR="@LIB_DIR@"
COREUTILS="@COREUTILS@"
GIT_PKG="@GIT@"
GNUSED="@GNUSED@"
GNUGREP="@GNUGREP@"

# ── Defaults ────────────────────────────────────────────────────────
SANDBOX_NAME="claude-sandbox"
SANDBOX_HOSTNAME="claude-sandbox"
VERSION="0.1.0"

# ── Sourced helpers ─────────────────────────────────────────────────
source "${LIB_DIR}/detect.sh"

# ── Usage ───────────────────────────────────────────────────────────
usage() {
  cat <<EOF
claude-sandbox v${VERSION} — OS-level sandbox for Claude Code

USAGE:
    claude-sandbox [OPTIONS] [PROJECT_DIR] [-- COMMAND...]

ARGUMENTS:
    PROJECT_DIR       Directory to mount read-write (default: current dir)
    COMMAND...        Command to run inside sandbox (default: claude)

OPTIONS:
    --help, -h        Show this help
    --test            Run health checks
    --dry-run         Print bwrap command without executing
    --no-ssh-agent    Do not forward SSH_AUTH_SOCK
    --extra-bind DIR  Additional read-write bind mount (repeatable)
    --extra-ro DIR    Additional read-only bind mount (repeatable)
    --overlay         Enable fuse-overlayfs overlay (experimental)
    --verbose, -v     Print sandbox configuration before launch

EXAMPLES:
    claude-sandbox ~/projects/myapp
    claude-sandbox ~/projects/myapp -- claude --dangerously-skip-permissions
    claude-sandbox --extra-ro ~/.aws ~/projects/infra
    claude-sandbox test

ENVIRONMENT:
    CLAUDE_SANDBOX_SSH_AGENT=0   Disable SSH agent forwarding
    CLAUDE_SANDBOX_VERBOSE=1     Enable verbose output
EOF
  exit 0
}

# ── Argument parsing ────────────────────────────────────────────────
PROJECT_DIR=""
COMMAND=()
EXTRA_BINDS=()
EXTRA_RO_BINDS=()
FORWARD_SSH=1
DRY_RUN=0
VERBOSE="${CLAUDE_SANDBOX_VERBOSE:-0}"
OVERLAY_MODE=0
RUN_TEST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)     usage ;;
    --test|test)   RUN_TEST=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --no-ssh-agent) FORWARD_SSH=0; shift ;;
    --extra-bind)  EXTRA_BINDS+=("$2"); shift 2 ;;
    --extra-ro)    EXTRA_RO_BINDS+=("$2"); shift 2 ;;
    --overlay)     OVERLAY_MODE=1; shift ;;
    --verbose|-v)  VERBOSE=1; shift ;;
    --)            shift; COMMAND=("$@"); break ;;
    -*)            echo "Unknown option: $1" >&2; exit 1 ;;
    *)
      if [[ -z "$PROJECT_DIR" ]]; then
        PROJECT_DIR="$1"
      else
        COMMAND+=("$1")
      fi
      shift
      ;;
  esac
done

# Override SSH forwarding from env
if [[ "${CLAUDE_SANDBOX_SSH_AGENT:-}" == "0" ]]; then
  FORWARD_SSH=0
fi

# ── Health check mode ───────────────────────────────────────────────
if [[ "$RUN_TEST" == "1" ]]; then
  source "${LIB_DIR}/healthcheck.sh"
  run_healthcheck
  exit $?
fi

# ── Resolve project directory ───────────────────────────────────────
if [[ -z "$PROJECT_DIR" ]]; then
  PROJECT_DIR="$(pwd)"
fi
PROJECT_DIR="$("${COREUTILS}/bin/readlink" -f "$PROJECT_DIR")"

if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "Error: Project directory does not exist: $PROJECT_DIR" >&2
  exit 1
fi

# Default command: claude
if [[ ${#COMMAND[@]} -eq 0 ]]; then
  COMMAND=("claude")
fi

# ── Environment detection ───────────────────────────────────────────
detect_environment

# ── Sandbox home setup ──────────────────────────────────────────────
SANDBOX_TMPDIR="$("${COREUTILS}/bin/mktemp" -d "/tmp/${SANDBOX_NAME}.XXXXXX")"

cleanup() {
  if [[ -d "$SANDBOX_TMPDIR" ]]; then
    # Scrub credential copies if any leaked
    if [[ -f "${SANDBOX_TMPDIR}/home/.claude/.credentials.json" ]]; then
      dd if=/dev/urandom of="${SANDBOX_TMPDIR}/home/.claude/.credentials.json" bs=1 count=4096 2>/dev/null || true
    fi
    rm -rf "$SANDBOX_TMPDIR"
  fi
}
trap cleanup EXIT INT TERM HUP

"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/projects"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/debug"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/todos"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/statsig"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/shell-snapshots"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/file-history"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/cache"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/backups"
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude/plugins"

# Copy settings (writable — Claude Code needs to update permissions etc.)
if [[ -f "$HOME/.claude/settings.json" ]]; then
  cp "$HOME/.claude/settings.json" "${SANDBOX_TMPDIR}/home/.claude/settings.json"
fi
if [[ -f "$HOME/.claude/settings.local.json" ]]; then
  cp "$HOME/.claude/settings.local.json" "${SANDBOX_TMPDIR}/home/.claude/settings.local.json"
fi
if [[ -f "$HOME/.claude/keybindings.json" ]]; then
  cp "$HOME/.claude/keybindings.json" "${SANDBOX_TMPDIR}/home/.claude/keybindings.json"
fi
if [[ -f "$HOME/.claude.json" ]]; then
  cp "$HOME/.claude.json" "${SANDBOX_TMPDIR}/home/.claude.json"
fi

# Sanitize gitconfig
source "${LIB_DIR}/sanitize-git.sh"
sanitize_gitconfig "$HOME" "${SANDBOX_TMPDIR}/home"

# ── Build bwrap arguments ──────────────────────────────────────────
BWRAP_ARGS=()

# -- Namespaces --
if [[ "$HAS_PID_NS" == "1" ]]; then
  BWRAP_ARGS+=(--unshare-pid)
fi
BWRAP_ARGS+=(--unshare-ipc)
BWRAP_ARGS+=(--unshare-uts)
BWRAP_ARGS+=(--unshare-cgroup)

if [[ "$HAS_USER_NS" == "1" ]]; then
  BWRAP_ARGS+=(--unshare-user)
  BWRAP_ARGS+=(--uid 1000 --gid 1000)
fi

# Keep network (Claude needs API access)
# Network filtering is a Phase 2 feature

# -- Lifecycle --
BWRAP_ARGS+=(--die-with-parent)
BWRAP_ARGS+=(--new-session)
BWRAP_ARGS+=(--hostname "$SANDBOX_HOSTNAME")

# -- Capabilities --
BWRAP_ARGS+=(--cap-drop ALL)

# -- Filesystem: base layer (everything read-only) --
BWRAP_ARGS+=(--ro-bind / /)

# -- Filesystem: Nix store bypass (performance, already immutable) --
BWRAP_ARGS+=(--ro-bind /nix/store /nix/store)

# -- Filesystem: fresh special mounts --
BWRAP_ARGS+=(--dev /dev)
BWRAP_ARGS+=(--proc /proc)
BWRAP_ARGS+=(--tmpfs /tmp)
BWRAP_ARGS+=(--tmpfs /run)

# -- Filesystem: NixOS paths that must be re-bound after /run tmpfs --
if [[ -e /run/current-system ]]; then
  BWRAP_ARGS+=(--ro-bind /run/current-system /run/current-system)
fi
if [[ -e /run/wrappers ]]; then
  BWRAP_ARGS+=(--ro-bind /run/wrappers /run/wrappers)
fi
if [[ -e /run/opengl-driver ]]; then
  BWRAP_ARGS+=(--ro-bind /run/opengl-driver /run/opengl-driver)
fi
# nscd socket for name resolution on NixOS
if [[ -e /run/nscd ]]; then
  BWRAP_ARGS+=(--ro-bind /run/nscd /run/nscd)
fi

# -- Filesystem: DNS resolution --
# Only bind-mount resolv.conf if it's a regular file (not a symlink).
# On NixOS/WSL2, /etc/resolv.conf is a symlink to /mnt/wsl/resolv.conf,
# which already works through the base --ro-bind / / mount.
# bwrap cannot bind-mount over symlink destinations.
if [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]]; then
  BWRAP_ARGS+=(--ro-bind /etc/resolv.conf /etc/resolv.conf)
elif [[ -L /etc/resolv.conf ]]; then
  # Symlink — resolve and bind the target so DNS works even if
  # intermediate paths get masked
  RESOLV_TARGET="$("${COREUTILS}/bin/readlink" -f /etc/resolv.conf 2>/dev/null)"
  if [[ -n "$RESOLV_TARGET" && -f "$RESOLV_TARGET" ]]; then
    BWRAP_ARGS+=(--ro-bind "$RESOLV_TARGET" "$RESOLV_TARGET")
  fi
fi

# -- Filesystem: SSL certificates --
# Only bind real directories, not symlinks (NixOS /etc/static is a symlink
# into /nix/store which is already available via the base ro-bind)
if [[ -d /etc/ssl && ! -L /etc/ssl ]]; then
  BWRAP_ARGS+=(--ro-bind /etc/ssl /etc/ssl)
fi
if [[ -d /etc/pki && ! -L /etc/pki ]]; then
  BWRAP_ARGS+=(--ro-bind /etc/pki /etc/pki)
fi

# -- Filesystem: sandbox home (READ-WRITE) --
# /home is read-only from the base bind; we need a writable /home
# so bwrap can create the mount point for the sandbox user home
BWRAP_ARGS+=(--tmpfs /home)
BWRAP_ARGS+=(--bind "${SANDBOX_TMPDIR}/home" "/home/${SANDBOX_NAME}")

# -- Filesystem: project directory (READ-WRITE) --
# Must come AFTER --tmpfs /home so it overlays on top when project is under /home
BWRAP_ARGS+=(--bind "$PROJECT_DIR" "$PROJECT_DIR")

# -- Filesystem: credentials (READ-ONLY bind from host) --
if [[ -f "$HOME/.claude/.credentials.json" ]]; then
  BWRAP_ARGS+=(--ro-bind "$HOME/.claude/.credentials.json" "/home/${SANDBOX_NAME}/.claude/.credentials.json")
fi

# -- Filesystem: mask sensitive host directories --
BWRAP_ARGS+=(--tmpfs "/home/${SANDBOX_NAME}/.ssh")
BWRAP_ARGS+=(--tmpfs "/home/${SANDBOX_NAME}/.gnupg")
BWRAP_ARGS+=(--tmpfs "/home/${SANDBOX_NAME}/.aws")
BWRAP_ARGS+=(--tmpfs "/home/${SANDBOX_NAME}/.kube")

# -- WSL2: block Windows interop escape --
if [[ "$IS_WSL2" == "1" ]]; then
  # Mask individual Windows drive mounts (e.g. /mnt/c, /mnt/d, ...)
  # We keep /mnt/wsl and /mnt/wslg because NixOS on WSL2 symlinks
  # /etc/resolv.conf -> /mnt/wsl/resolv.conf for DNS resolution
  for wsl_mount in /mnt/[a-z]; do
    if [[ -d "$wsl_mount" && ! "$wsl_mount" =~ ^/mnt/wsl ]]; then
      BWRAP_ARGS+=(--tmpfs "$wsl_mount")
    fi
  done
  # Note: Windows binary execution via binfmt_misc is already blocked because
  # --proc /proc creates a fresh procfs without binfmt_misc mounts.
fi

# -- Extra bind mounts from CLI --
for dir in "${EXTRA_BINDS[@]}"; do
  resolved="$("${COREUTILS}/bin/readlink" -f "$dir")"
  BWRAP_ARGS+=(--bind "$resolved" "$resolved")
done
for dir in "${EXTRA_RO_BINDS[@]}"; do
  resolved="$("${COREUTILS}/bin/readlink" -f "$dir")"
  BWRAP_ARGS+=(--ro-bind "$resolved" "$resolved")
done

# -- SSH agent forwarding --
if [[ "$FORWARD_SSH" == "1" && -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK}" ]]; then
  BWRAP_ARGS+=(--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK")
fi

# -- Seccomp profile --
SECCOMP_PROFILE="${LIB_DIR}/seccomp.bpf"
# seccomp via --seccomp FD requires the file to exist and be a valid BPF
# We generate it at build time via lib/seccomp.nix
# For now, only apply if the profile exists
if [[ -f "$SECCOMP_PROFILE" ]]; then
  # bwrap --seccomp reads from an FD; we open the file on FD 9
  exec 9< "$SECCOMP_PROFILE"
  BWRAP_ARGS+=(--seccomp 9)
fi

# -- Detect Claude Code binary and add to PATH --
SANDBOX_PATH="$TOOL_PATH"
CLAUDE_BIN="$(command -v claude 2>/dev/null || true)"
if [[ -n "$CLAUDE_BIN" ]]; then
  CLAUDE_REAL="$("${COREUTILS}/bin/readlink" -f "$CLAUDE_BIN")"
  CLAUDE_DIR="$("${COREUTILS}/bin/dirname" "$CLAUDE_REAL")"
  SANDBOX_PATH="${SANDBOX_PATH}:${CLAUDE_DIR}"
fi

# -- Environment variables --
BWRAP_ARGS+=(--setenv HOME "/home/${SANDBOX_NAME}")
BWRAP_ARGS+=(--setenv PATH "$SANDBOX_PATH")
BWRAP_ARGS+=(--setenv SSL_CERT_FILE "$SSL_CERT_FILE")
BWRAP_ARGS+=(--setenv NODE_EXTRA_CA_CERTS "$SSL_CERT_FILE")
BWRAP_ARGS+=(--setenv TERM "${TERM:-xterm-256color}")
BWRAP_ARGS+=(--setenv LANG "${LANG:-en_US.UTF-8}")
BWRAP_ARGS+=(--setenv SANDBOX "1")
BWRAP_ARGS+=(--setenv CLAUDE_SANDBOX_VERSION "$VERSION")

# Forward SSH_AUTH_SOCK if allowed
if [[ "$FORWARD_SSH" == "1" && -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK}" ]]; then
  BWRAP_ARGS+=(--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK")
fi

# Forward ANTHROPIC_API_KEY if set (alternative to OAuth)
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  BWRAP_ARGS+=(--setenv ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY")
fi

# -- Working directory --
BWRAP_ARGS+=(--chdir "$PROJECT_DIR")

# ── Verbose output ──────────────────────────────────────────────────
if [[ "$VERBOSE" == "1" ]]; then
  echo "╭─── claude-sandbox v${VERSION} ───────────────────────────"
  echo "│ Project:     $PROJECT_DIR"
  echo "│ Sandbox home: ${SANDBOX_TMPDIR}/home"
  echo "│ WSL2:        $IS_WSL2"
  echo "│ User NS:     $HAS_USER_NS"
  echo "│ PID NS:      $HAS_PID_NS"
  echo "│ FUSE:        $HAS_FUSE"
  echo "│ SSH agent:   $FORWARD_SSH"
  echo "│ Command:     ${COMMAND[*]}"
  echo "╰──────────────────────────────────────────────────────────"
fi

# ── Dry run mode ────────────────────────────────────────────────────
if [[ "$DRY_RUN" == "1" ]]; then
  echo "Would execute:"
  echo "$BWRAP" "${BWRAP_ARGS[@]}" -- "${COMMAND[@]}"
  exit 0
fi

# ── Launch ──────────────────────────────────────────────────────────
exec "$BWRAP" "${BWRAP_ARGS[@]}" -- "${COMMAND[@]}"
