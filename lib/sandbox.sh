#!/usr/bin/env bash
# claude-sandbox — OS-level sandbox for Claude Code using bubblewrap
# https://github.com/mrquentin/claude-sandbox
set -euo pipefail

# ── Paths injected by Nix at build time ─────────────────────────────
BWRAP="@BWRAP@"
TOOL_PATH_MINIMAL="@TOOL_PATH_MINIMAL@"
TOOL_PATH_DEFAULT="@TOOL_PATH_DEFAULT@"
TOOL_PATH_FULL="@TOOL_PATH_FULL@"
SSL_CERT_FILE="@SSL_CERT_FILE@"
SANDBOX_BASH="@BASH@"
LIB_DIR="@LIB_DIR@"
COREUTILS="@COREUTILS@"
GIT_PKG="@GIT@"
GNUSED="@GNUSED@"
GNUGREP="@GNUGREP@"
PYTHON3="@PYTHON3@"
JQ="@JQ@"

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
    --profile NAME    Tool profile: minimal, default, full (default: default)
    --config FILE     Path to config file (default: ~/.config/claude-sandbox/config.json)
    --no-config       Ignore user config file
    --list-syscalls   List available syscall names for seccomp blocking
    --yolo            Run claude with --dangerously-skip-permissions
    --security-test   Run security validation tests inside the sandbox
    --verbose, -v     Print sandbox configuration before launch

EXAMPLES:
    claude-sandbox ~/projects/myapp
    claude-sandbox --yolo ~/projects/myapp
    claude-sandbox --extra-ro ~/.aws ~/projects/infra
    claude-sandbox test

ENVIRONMENT:
    CLAUDE_SANDBOX_SSH_AGENT=0     Disable SSH agent forwarding
    CLAUDE_SANDBOX_VERBOSE=1       Enable verbose output
    CLAUDE_SANDBOX_NO_SECCOMP=1    Allow running without seccomp (not recommended)
    CLAUDE_SANDBOX_EXTRA_PATH=...  Additional PATH entries inside sandbox
    CLAUDE_SANDBOX_PROFILE=NAME    Tool profile (minimal, default, full)
    CLAUDE_SANDBOX_CONFIG=FILE     Path to config file (overrides default)

CONFIG:
    Default config location: \${XDG_CONFIG_HOME:-~/.config}/claude-sandbox/config.json
    Example config: ${LIB_DIR}/config.example.json

    blocked_commands patterns use shell glob syntax:
      "az"                   Block all invocations of az
      "az * delete"          Block "az group delete", "az vm delete", etc.
      "kubectl delete ns *"  Block "kubectl delete ns production", etc.
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
YOLO_MODE=0
RUN_TEST=0
RUN_SECURITY_TEST=0
CONFIG_FILE="${CLAUDE_SANDBOX_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/claude-sandbox/config.json}"
USE_CONFIG=1
PROFILE="${CLAUDE_SANDBOX_PROFILE:-default}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)     usage ;;
    --test|test)   RUN_TEST=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --no-ssh-agent) FORWARD_SSH=0; shift ;;
    --extra-bind)
      if [[ $# -lt 2 ]]; then
        echo "Error: --extra-bind requires a directory argument" >&2
        exit 1
      fi
      EXTRA_BINDS+=("$2"); shift 2 ;;
    --extra-ro)
      if [[ $# -lt 2 ]]; then
        echo "Error: --extra-ro requires a directory argument" >&2
        exit 1
      fi
      EXTRA_RO_BINDS+=("$2"); shift 2 ;;
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "Error: --profile requires a name (minimal, default, full)" >&2
        exit 1
      fi
      PROFILE="$2"; shift 2 ;;
    --config)
      if [[ $# -lt 2 ]]; then
        echo "Error: --config requires a file path argument" >&2
        exit 1
      fi
      CONFIG_FILE="$2"; shift 2 ;;
    --no-config)   USE_CONFIG=0; shift ;;
    --list-syscalls)
      exec "$PYTHON3" "${LIB_DIR}/seccomp-gen.py" --list ;;
    --yolo)        YOLO_MODE=1; shift ;;
    --security-test) RUN_SECURITY_TEST=1; shift ;;
    --verbose|-v)  VERBOSE=1; shift ;;
    --)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Error: no command specified after --" >&2
        exit 1
      fi
      COMMAND=("$@"); break ;;
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

# Default command: claude (with --dangerously-skip-permissions in yolo mode)
if [[ ${#COMMAND[@]} -eq 0 ]]; then
  if [[ "$YOLO_MODE" == "1" ]]; then
    COMMAND=("claude" "--dangerously-skip-permissions")
  else
    COMMAND=("claude")
  fi
fi

# ── Environment detection ───────────────────────────────────────────
detect_environment

# ── Load user configuration ────────────────────────────────────────
CFG_EXTRA_PATHS=()
CFG_EXTRA_BLOCKED_SYSCALLS=()
CFG_BLOCKED_COMMANDS=()
CFG_ENV_VARS=()

if [[ "$USE_CONFIG" == "1" && -f "$CONFIG_FILE" ]]; then
  if [[ "$VERBOSE" == "1" ]]; then
    echo "Loading config: $CONFIG_FILE"
  fi

  # Profile override from config (CLI --profile takes precedence)
  if [[ "$PROFILE" == "default" && "${CLAUDE_SANDBOX_PROFILE:-}" == "" ]]; then
    cfg_profile="$("$JQ" -r '.profile // empty' "$CONFIG_FILE" 2>/dev/null)"
    if [[ -n "$cfg_profile" ]]; then
      PROFILE="$cfg_profile"
    fi
  fi

  # Nix packages — resolve to store paths and add to PATH
  while IFS= read -r pkg; do
    if [[ -n "$pkg" ]]; then
      store_path="$(nix build --no-link --print-out-paths "nixpkgs#${pkg}" 2>/dev/null)" || true
      if [[ -n "$store_path" && -d "${store_path}/bin" ]]; then
        CFG_EXTRA_PATHS+=("${store_path}/bin")
      elif [[ -n "$store_path" ]]; then
        # Some packages (e.g. go) put binaries in non-standard locations
        while IFS= read -r bin_dir; do
          CFG_EXTRA_PATHS+=("$bin_dir")
        done < <(find "$store_path" -name bin -type d 2>/dev/null)
      else
        echo "Warning: could not resolve nix package '${pkg}', skipping" >&2
      fi
    fi
  done < <("$JQ" -r --arg p "$PROFILE" '.packages[$p] // [] | .[]' "$CONFIG_FILE" 2>/dev/null)

  # Extra PATH entries (manual paths)
  while IFS= read -r p; do
    [[ -n "$p" ]] && CFG_EXTRA_PATHS+=("$p")
  done < <("$JQ" -r '.extra_path // [] | .[]' "$CONFIG_FILE" 2>/dev/null)

  # Extra blocked syscalls
  while IFS= read -r s; do
    [[ -n "$s" ]] && CFG_EXTRA_BLOCKED_SYSCALLS+=("$s")
  done < <("$JQ" -r '.blocked_syscalls // [] | .[]' "$CONFIG_FILE" 2>/dev/null)

  # Blocked command patterns
  while IFS= read -r cmd; do
    [[ -n "$cmd" ]] && CFG_BLOCKED_COMMANDS+=("$cmd")
  done < <("$JQ" -r '.blocked_commands // [] | .[]' "$CONFIG_FILE" 2>/dev/null)

  # Environment variables to forward into the sandbox
  while IFS= read -r v; do
    [[ -n "$v" ]] && CFG_ENV_VARS+=("$v")
  done < <("$JQ" -r '.env // [] | .[]' "$CONFIG_FILE" 2>/dev/null)
fi

# ── Sandbox home setup ──────────────────────────────────────────────
SANDBOX_TMPDIR="$("${COREUTILS}/bin/mktemp" -d "/tmp/${SANDBOX_NAME}.XXXXXX")"

cleanup() {
  # Prevent re-entry from nested signals
  trap '' INT TERM HUP
  if [[ -d "$SANDBOX_TMPDIR" ]]; then
    # Scrub any credential files that may have leaked into the tmpdir
    local cred_file="${SANDBOX_TMPDIR}/home/.claude/.credentials.json"
    if [[ -f "$cred_file" ]]; then
      local cred_size
      cred_size="$("${COREUTILS}/bin/stat" -c%s "$cred_file" 2>/dev/null || echo 4096)"
      dd if=/dev/urandom of="$cred_file" bs=1 count="$cred_size" conv=notrunc 2>/dev/null || true
      "${COREUTILS}/bin/sync" "$cred_file" 2>/dev/null || true
    fi
    rm -rf "$SANDBOX_TMPDIR"
  fi
}
trap cleanup EXIT INT TERM HUP

"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home"

# Copy files that Claude Code needs to write to at runtime
if [[ -f "$HOME/.claude.json" ]]; then
  cp "$HOME/.claude.json" "${SANDBOX_TMPDIR}/home/.claude.json"
fi
"${COREUTILS}/bin/mkdir" -p "${SANDBOX_TMPDIR}/home/.claude"
for settings_file in settings.json settings.local.json keybindings.json; do
  if [[ -f "$HOME/.claude/${settings_file}" ]]; then
    cp "$HOME/.claude/${settings_file}" "${SANDBOX_TMPDIR}/home/.claude/${settings_file}"
  fi
done

# Sanitize gitconfig
source "${LIB_DIR}/sanitize-git.sh"
sanitize_gitconfig "$HOME" "${SANDBOX_TMPDIR}/home"

# ── Generate command filters ──────────────────────────────────────
FILTER_HOST_DIR=""
if [[ ${#CFG_BLOCKED_COMMANDS[@]} -gt 0 ]]; then
  source "${LIB_DIR}/command-filter.sh"
  FILTER_HOST_DIR="${SANDBOX_TMPDIR}/filters"
  generate_command_filters "$FILTER_HOST_DIR" "${CFG_BLOCKED_COMMANDS[@]}"
  if [[ "$VERBOSE" == "1" ]]; then
    echo "Generated command filters for: $(printf '%s ' "${CFG_BLOCKED_COMMANDS[@]}")"
  fi
fi

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

# -- Filesystem: Claude config (READ-ONLY base from host) --
# Mount the entire ~/.claude so skills, agents, hooks, CLAUDE.md, MCP config etc. are available
if [[ -d "$HOME/.claude" ]]; then
  BWRAP_ARGS+=(--ro-bind "$HOME/.claude" "/home/${SANDBOX_NAME}/.claude")
fi

# -- Filesystem: writable Claude subdirs (overlay tmpfs on top of ro-bind) --
# Claude Code needs to write to these directories at runtime
for writable_dir in projects debug todos statsig shell-snapshots file-history cache backups plugins session-env; do
  BWRAP_ARGS+=(--tmpfs "/home/${SANDBOX_NAME}/.claude/${writable_dir}")
done

# Copy writable settings into the sandbox (Claude Code updates permissions etc.)
# These must come after the ro-bind so they overlay on top
for settings_file in settings.json settings.local.json keybindings.json; do
  if [[ -f "$HOME/.claude/${settings_file}" ]]; then
    BWRAP_ARGS+=(--bind "${SANDBOX_TMPDIR}/home/.claude/${settings_file}" "/home/${SANDBOX_NAME}/.claude/${settings_file}")
  fi
done

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
  # Note on binfmt_misc: masking Windows drive mounts removes access to
  # .exe files, which is the primary protection. The kernel's binfmt_misc
  # handler is system-wide and persists regardless of procfs mounts, so
  # --proc /proc alone does NOT disable it. However, without access to
  # the actual Windows binaries (drives masked), the handler cannot
  # execute them. The seccomp filter additionally blocks personality(2)
  # to prevent ABI switching.
fi

# -- Extra bind mounts from CLI --
for dir in "${EXTRA_BINDS[@]}"; do
  resolved="$("${COREUTILS}/bin/readlink" -f "$dir")"
  if [[ ! -d "$resolved" ]]; then
    echo "Error: --extra-bind directory does not exist: $dir" >&2
    exit 1
  fi
  BWRAP_ARGS+=(--bind "$resolved" "$resolved")
done
for dir in "${EXTRA_RO_BINDS[@]}"; do
  resolved="$("${COREUTILS}/bin/readlink" -f "$dir")"
  if [[ ! -d "$resolved" ]]; then
    echo "Error: --extra-ro directory does not exist: $dir" >&2
    exit 1
  fi
  BWRAP_ARGS+=(--ro-bind "$resolved" "$resolved")
done

# -- Command filter directory (READ-ONLY) --
if [[ -n "$FILTER_HOST_DIR" && -d "$FILTER_HOST_DIR" ]]; then
  BWRAP_ARGS+=(--ro-bind "$FILTER_HOST_DIR" "$SANDBOX_FILTER_DIR")
fi

# -- SSH agent forwarding --
# Note: the socket is bind-mounted read-only to prevent file-level writes,
# but the Unix socket itself remains fully functional for SSH agent operations.
# Use --no-ssh-agent if you want to block SSH agent access entirely.
if [[ "$FORWARD_SSH" == "1" && -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK}" ]]; then
  BWRAP_ARGS+=(--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK")
fi

# -- Seccomp profile --
if [[ ${#CFG_EXTRA_BLOCKED_SYSCALLS[@]} -gt 0 ]]; then
  # Generate custom BPF with extra blocked syscalls from user config
  SECCOMP_PROFILE="${SANDBOX_TMPDIR}/seccomp-custom.bpf"
  if [[ "$VERBOSE" == "1" ]]; then
    echo "Generating custom seccomp profile (extra blocks: ${CFG_EXTRA_BLOCKED_SYSCALLS[*]})"
  fi
  "$PYTHON3" "${LIB_DIR}/seccomp-gen.py" "${CFG_EXTRA_BLOCKED_SYSCALLS[@]}" > "$SECCOMP_PROFILE"
else
  SECCOMP_PROFILE="${LIB_DIR}/seccomp.bpf"
fi
if [[ -f "$SECCOMP_PROFILE" ]]; then
  # bwrap --seccomp reads from an FD; we open the file on FD 9
  exec 9< "$SECCOMP_PROFILE"
  BWRAP_ARGS+=(--seccomp 9)
else
  echo "Warning: Seccomp profile not found at ${SECCOMP_PROFILE}" >&2
  echo "  The sandbox will run WITHOUT syscall filtering." >&2
  if [[ "${CLAUDE_SANDBOX_NO_SECCOMP:-0}" != "1" ]]; then
    echo "  Set CLAUDE_SANDBOX_NO_SECCOMP=1 to run without seccomp (not recommended)." >&2
    exit 1
  fi
fi

# -- Detect Claude Code binary and add to PATH --
# Select tool profile
case "$PROFILE" in
  minimal) TOOL_PATH="$TOOL_PATH_MINIMAL" ;;
  default) TOOL_PATH="$TOOL_PATH_DEFAULT" ;;
  full)    TOOL_PATH="$TOOL_PATH_FULL" ;;
  *)
    echo "Error: unknown profile '$PROFILE' (use: minimal, default, full)" >&2
    exit 1
    ;;
esac
SANDBOX_PATH="$TOOL_PATH"

# Prepend command filter directory (must be first in PATH to intercept commands)
if [[ -n "$FILTER_HOST_DIR" && -d "$FILTER_HOST_DIR" ]]; then
  SANDBOX_PATH="${SANDBOX_FILTER_DIR}:${SANDBOX_PATH}"
fi

# Add extra packages from NixOS module or CLAUDE_SANDBOX_EXTRA_PATH env
if [[ -n "${CLAUDE_SANDBOX_EXTRA_PATH:-}" ]]; then
  SANDBOX_PATH="${SANDBOX_PATH}:${CLAUDE_SANDBOX_EXTRA_PATH}"
fi

# Add tool paths from user config
for p in "${CFG_EXTRA_PATHS[@]}"; do
  SANDBOX_PATH="${SANDBOX_PATH}:${p}"
done

CLAUDE_BIN="$(command -v claude 2>/dev/null || true)"
if [[ -n "$CLAUDE_BIN" ]]; then
  CLAUDE_REAL="$("${COREUTILS}/bin/readlink" -f "$CLAUDE_BIN")"
  CLAUDE_DIR="$("${COREUTILS}/bin/dirname" "$CLAUDE_REAL")"
  SANDBOX_PATH="${SANDBOX_PATH}:${CLAUDE_DIR}"
fi

# -- Environment variables --
# Clear host env to prevent leaking secrets, then set only what's needed
BWRAP_ARGS+=(--clearenv)
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

# Forward user-configured environment variables
for var_name in "${CFG_ENV_VARS[@]}"; do
  if [[ -n "${!var_name+x}" ]]; then
    BWRAP_ARGS+=(--setenv "$var_name" "${!var_name}")
  elif [[ "$VERBOSE" == "1" ]]; then
    echo "Warning: env var '$var_name' from config is not set, skipping" >&2
  fi
done

# -- Working directory --
BWRAP_ARGS+=(--chdir "$PROJECT_DIR")

# ── Verbose output ──────────────────────────────────────────────────
if [[ "$VERBOSE" == "1" ]]; then
  echo "╭─── claude-sandbox v${VERSION} ───────────────────────────"
  echo "│ Profile:     $PROFILE"
  echo "│ Project:     $PROJECT_DIR"
  echo "│ Sandbox home: ${SANDBOX_TMPDIR}/home"
  echo "│ WSL2:        $IS_WSL2"
  echo "│ User NS:     $HAS_USER_NS"
  echo "│ PID NS:      $HAS_PID_NS"
  echo "│ FUSE:        $HAS_FUSE"
  echo "│ SSH agent:   $FORWARD_SSH"
  if [[ "$USE_CONFIG" == "1" && -f "$CONFIG_FILE" ]]; then
    echo "│ Config:      $CONFIG_FILE"
    [[ ${#CFG_EXTRA_PATHS[@]} -gt 0 ]] && echo "│  paths:      ${CFG_EXTRA_PATHS[*]}"
    [[ ${#CFG_BLOCKED_COMMANDS[@]} -gt 0 ]] && echo "│  cmd-filter: ${CFG_BLOCKED_COMMANDS[*]}"
    [[ ${#CFG_EXTRA_BLOCKED_SYSCALLS[@]} -gt 0 ]] && echo "│  seccomp:    +${CFG_EXTRA_BLOCKED_SYSCALLS[*]}"
    [[ ${#CFG_ENV_VARS[@]} -gt 0 ]] && echo "│  env:        ${CFG_ENV_VARS[*]}"
  else
    echo "│ Config:      (none)"
  fi
  echo "│ Command:     ${COMMAND[*]}"
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "│ ⚠ API key:   ANTHROPIC_API_KEY is set (visible inside sandbox;"
    echo "│              network is unrestricted — key could be exfiltrated)"
  fi
  if [[ "$FORWARD_SSH" == "1" && -n "${SSH_AUTH_SOCK:-}" ]]; then
    echo "│ ⚠ SSH agent: socket is fully functional inside sandbox"
  fi
  echo "╰──────────────────────────────────────────────────────────"
fi

# ── Security test mode ──────────────────────────────────────────────
# Runs AFTER BWRAP_ARGS is fully built, so tests use the real config.
if [[ "$RUN_SECURITY_TEST" == "1" ]]; then
  source "${LIB_DIR}/security-tests.sh"
  run_security_tests
  exit $?
fi

# ── Dry run mode ────────────────────────────────────────────────────
if [[ "$DRY_RUN" == "1" ]]; then
  echo "Would execute:"
  echo "$BWRAP" "${BWRAP_ARGS[@]}" -- "${COMMAND[@]}"
  exit 0
fi

# ── Launch ──────────────────────────────────────────────────────────
exec "$BWRAP" "${BWRAP_ARGS[@]}" -- "${COMMAND[@]}"
