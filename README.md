# claude-sandbox

OS-level sandbox for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) using [bubblewrap](https://github.com/containers/bubblewrap) on NixOS/Linux.

Provides namespace isolation, read-only filesystem enforcement, seccomp filtering, and credential protection — while keeping full access to your dev tools and project directory.

## Features

- **Read-only filesystem** — Host filesystem mounted read-only by default; only your project directory and sandbox home are writable
- **Namespace isolation** — PID, IPC, UTS, cgroup, and (when available) user namespace isolation
- **Seccomp filtering** — Blocks ~30 dangerous syscalls (mount, ptrace, kexec, bpf, etc.) with user-configurable extensions
- **Credential protection** — OAuth credentials bind-mounted read-only; SSH keys, AWS/kube configs masked
- **Environment isolation** — Host environment cleared; only explicitly configured vars are forwarded
- **Claude config support** — `~/.claude` mounted read-only so skills, agents, hooks, and CLAUDE.md are available
- **Git config sanitization** — Strips credential helpers, aliases, and include directives from .gitconfig
- **WSL2 hardening** — Masks Windows drive mounts to block access to Windows binaries
- **Tool profiles** — Minimal, default, and full tool sets selectable at runtime
- **Command filtering** — Block specific command+argument patterns (e.g., `az * delete`) using glob syntax
- **User configuration** — Per-user config for extra Nix packages, seccomp rules, blocked commands, and environment variables
- **NixOS module** — Declarative system-level configuration
- **Self-test** — Built-in health check and security validation tests

## Quick Start

```bash
# Run directly from the flake
nix run github:mrquentin/claude-sandbox -- ~/my-project

# Or install to your profile
nix profile install github:mrquentin/claude-sandbox

# Run health checks
claude-sandbox --test
```

## Usage

```
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
```

### Examples

```bash
# Launch Claude in a sandbox with project dir writable
claude-sandbox ~/projects/myapp

# Run with dangerous permissions (still sandboxed at OS level)
claude-sandbox --yolo ~/projects/myapp

# Use the full tool profile (adds rust, go, clang, neovim, etc.)
claude-sandbox --profile full ~/projects/myapp

# Use the minimal tool profile (bash, coreutils, git, jq, curl)
claude-sandbox --profile minimal ~/projects/myapp

# Give read-only access to shared datasets
claude-sandbox --extra-ro /data/datasets ~/projects/ml-project

# Preview the bwrap command without running
claude-sandbox --dry-run ~/projects/myapp

# Verbose output showing sandbox configuration
claude-sandbox -v ~/projects/myapp

# List available syscall names for seccomp config
claude-sandbox --list-syscalls

# Run security validation tests
claude-sandbox --security-test ~/projects/myapp
```

## User Configuration

Each user can customize their sandbox without modifying the repository. Create a config file at `~/.config/claude-sandbox/config.json`:

```json
{
  "profile": "default",
  "packages": {
    "minimal": [],
    "default": ["go", "htop"],
    "full": ["docker"]
  },
  "extra_path": [],
  "blocked_commands": [
    "az * delete *",
    "kubectl delete namespace *"
  ],
  "blocked_syscalls": [],
  "env": ["GITHUB_TOKEN", "DATABASE_URL"]
}
```

| Field              | Description                                                       |
|--------------------|-------------------------------------------------------------------|
| `profile`          | Default tool profile (`minimal`, `default`, `full`)               |
| `packages`         | Nix packages to add per profile (resolved at startup)             |
| `extra_path`       | Additional directories to add to PATH                             |
| `blocked_commands` | Command patterns to block inside the sandbox (shell glob syntax)  |
| `blocked_syscalls` | Extra syscalls to block (see `--list-syscalls`)                   |
| `env`              | Host environment variable names to forward into the sandbox       |

The `--profile` flag and `CLAUDE_SANDBOX_PROFILE` env var override the config file profile.

### Adding tools

Install a package with Nix and add it to your config:

```bash
# No need to find store paths — just use the package name
nix profile install nixpkgs#go
```

```json
{
  "packages": {
    "default": ["go"]
  }
}
```

The sandbox resolves package names via `nix build` at startup and adds them to PATH.

### Blocking commands

You can prevent specific commands (or command+argument combinations) from being executed inside the sandbox using `blocked_commands`. Patterns use shell glob syntax:

```json
{
  "blocked_commands": [
    "az",
    "az * delete *",
    "kubectl delete namespace *",
    "rm -rf /",
    "curl * --upload-file *"
  ]
}
```

| Pattern                      | Effect                                                  |
|------------------------------|---------------------------------------------------------|
| `"az"`                       | Blocks all invocations of `az`                          |
| `"az * delete *"`            | Blocks `az group delete mygroup`, `az vm delete myvm`   |
| `"kubectl delete namespace *"` | Blocks `kubectl delete namespace production`          |
| `"rm -rf /"`                 | Blocks `rm -rf /`                                       |
| `"curl * --upload-file *"`   | Blocks curl with `--upload-file` anywhere in args       |

Blocked commands exit with code 126 and print a `[claude-sandbox] BLOCKED` message. The filter directory is mounted **read-only** inside the sandbox so filter rules cannot be tampered with.

## Tool Profiles

| Profile   | Tools                                                                 |
|-----------|-----------------------------------------------------------------------|
| `minimal` | bash, coreutils, git, ripgrep, fd, jq, curl, grep, sed, awk          |
| `default` | minimal + gcc, make, cmake, python3, nodejs, tree, less, diff, patch  |
| `full`    | default + clang, rust, go, ninja, neovim, tmux, htop, docker-client   |

Select at runtime:

```bash
claude-sandbox --profile full ~/project
```

Or set as default in your config:

```json
{ "profile": "full" }
```

### Security Tests

The `--security-test` flag builds the full sandbox configuration and runs validation tests inside it:

```bash
claude-sandbox --security-test ~/projects/myapp
```

Tests verify:
- **Filesystem isolation** — host filesystem is read-only, project dir is writable
- **Home isolation** — host home is masked, sandbox home is isolated
- **Credential masking** — `.ssh`, `.gnupg`, `.aws`, `.kube` directories are empty
- **Claude config isolation** — `~/.claude` read-only base, writable runtime dirs, settings writable, host config visible
- **Namespace isolation** — PID, UTS (hostname), user namespace separation
- **Capability dropping** — all capabilities are zeroed
- **Environment isolation** — host env vars do not leak into sandbox
- **Seccomp enforcement** — `mount()`, `ptrace()`, `chroot()`, `personality()` blocked
- **WSL2 drive masking** — Windows drives inaccessible (WSL2 only)
- **Git config sanitization** — dangerous sections stripped
- **Command filtering** — filter directory read-only, patterns enforced, wrappers tamper-proof

## NixOS Module

Add to your `flake.nix`:

```nix
{
  inputs.claude-sandbox.url = "github:mrquentin/claude-sandbox";

  outputs = { self, nixpkgs, claude-sandbox, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        claude-sandbox.nixosModules.default
        {
          programs.claude-sandbox = {
            enable = true;
            forwardSSHAgent = true;
            extraBindMounts = [ "/home/user/shared-libs" ];
            extraReadOnlyMounts = [ "/opt/datasets" ];
          };
        }
      ];
    };
  };
}
```

## Security Model

### What's protected

| Layer              | Protection                                                    |
|--------------------|---------------------------------------------------------------|
| Filesystem         | Host mounted read-only; project dir is the only writable path |
| Namespaces         | PID, IPC, UTS, cgroup isolation; user namespace when available|
| Capabilities       | All capabilities dropped (`--cap-drop ALL`)                   |
| Seccomp            | Blocks mount, ptrace, kexec, bpf, perf, keyctl, and more     |
| Environment        | Host env cleared (`--clearenv`); only explicit vars forwarded |
| Credentials        | `.credentials.json` read-only bind; SSH/AWS/kube dirs masked  |
| Claude config      | `~/.claude` read-only; skills/agents/hooks visible but not writable |
| Command filtering  | Configurable command+argument blocking via read-only wrappers |
| Git config         | Credential helpers, aliases, includes, filter drivers stripped|
| WSL2               | Windows drives masked; binary access blocked                  |
| SSH agent          | Forwarded by default (use `--no-ssh-agent` to disable)        |
| Process lifecycle  | `--die-with-parent` ensures cleanup; temp dirs scrubbed       |

### What's NOT restricted

- **Network access** — Claude Code needs the Anthropic API. Network egress filtering is planned for a future release.
- **Project directory** — Full read-write access to the specified directory (that's the point).
- **SSH agent** — When forwarded (default), the SSH agent socket is fully functional inside the sandbox. Use `--no-ssh-agent` to disable.

## Environment Variables

| Variable                       | Description                                    |
|--------------------------------|------------------------------------------------|
| `CLAUDE_SANDBOX_PROFILE`       | Tool profile (minimal, default, full)          |
| `CLAUDE_SANDBOX_CONFIG`        | Path to config file                            |
| `CLAUDE_SANDBOX_SSH_AGENT=0`   | Disable SSH agent forwarding                   |
| `CLAUDE_SANDBOX_VERBOSE=1`     | Enable verbose output                          |
| `CLAUDE_SANDBOX_NO_SECCOMP=1`  | Allow running without seccomp (not recommended)|
| `CLAUDE_SANDBOX_EXTRA_PATH`    | Additional PATH entries inside sandbox         |
| `ANTHROPIC_API_KEY`            | Forwarded into sandbox if set                  |
| `SANDBOX=1`                    | Set inside sandbox (for detection)             |
| `CLAUDE_SANDBOX_VERSION`       | Version string set inside sandbox              |

## Requirements

- Linux (x86_64 or aarch64)
- Nix with flakes enabled
- Works on NixOS, other distros with Nix, and WSL2

## Development

```bash
# Enter dev shell
nix develop

# Build and test locally
nix build
./result/bin/claude-sandbox --test

# Run security validation
./result/bin/claude-sandbox --security-test
```

## Architecture

```
claude-sandbox
├── flake.nix              # Nix flake: package, app, devShell, NixOS module
├── lib/
│   ├── sandbox.sh         # Main bwrap wrapper (entry point)
│   ├── detect.sh          # Environment detection (WSL2, namespaces, FUSE)
│   ├── sanitize-git.sh    # Git config sanitizer
│   ├── healthcheck.sh     # Health check suite
│   ├── security-tests.sh  # Security validation tests
│   ├── command-filter.sh  # Command filter wrapper generator
│   ├── seccomp.nix        # Seccomp BPF filter generator (build-time)
│   ├── seccomp-gen.py     # Seccomp BPF generator (runtime, for custom configs)
│   └── config.example.json # Example user configuration
└── modules/
    └── nixos.nix          # NixOS module
```

## License

MIT
