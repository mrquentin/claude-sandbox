# claude-sandbox

OS-level sandbox for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) using [bubblewrap](https://github.com/containers/bubblewrap) on NixOS/Linux.

Provides namespace isolation, read-only filesystem enforcement, seccomp filtering, and credential protection — while keeping full access to your dev tools and project directory.

## Features

- **Read-only filesystem** — Host filesystem mounted read-only by default; only your project directory and sandbox home are writable
- **Namespace isolation** — PID, IPC, UTS, cgroup, and (when available) user namespace isolation
- **Seccomp filtering** — Blocks ~30 dangerous syscalls (mount, ptrace, kexec, bpf, etc.)
- **Credential protection** — OAuth credentials bind-mounted read-only; SSH keys, AWS/kube configs masked
- **Git config sanitization** — Strips credential helpers, aliases, and include directives from .gitconfig
- **WSL2 hardening** — Masks Windows drive mounts to block access to Windows binaries
- **Tool profiles** — Minimal, default, and full tool sets
- **NixOS module** — Declarative system-level configuration
- **Self-test** — Built-in health check validates sandbox capabilities

## Quick Start

```bash
# Run directly from the flake
nix run github:mrquentin/claude-sandbox -- ~/my-project

# Or install in your flake
nix build github:mrquentin/claude-sandbox

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
    --yolo            Run claude with --dangerously-skip-permissions
    --verbose, -v     Print sandbox configuration before launch
```

### Examples

```bash
# Launch Claude in a sandbox with project dir writable
claude-sandbox ~/projects/myapp

# Run with dangerous permissions (still sandboxed at OS level)
claude-sandbox --yolo ~/projects/myapp

# Give read-only access to shared datasets
claude-sandbox --extra-ro /data/datasets ~/projects/ml-project

# Add a writable scratch directory
claude-sandbox --extra-bind /tmp/shared ~/projects/myapp

# Preview the bwrap command without running
claude-sandbox --dry-run ~/projects/myapp

# Verbose output showing sandbox configuration
claude-sandbox -v ~/projects/myapp
```

## Tool Profiles

| Profile   | Tools                                                                 |
|-----------|-----------------------------------------------------------------------|
| `minimal` | bash, coreutils, git, ripgrep, fd, jq, curl, grep, sed, awk          |
| `default` | minimal + gcc, make, cmake, python3, nodejs, tree, less, diff, patch  |
| `full`    | default + clang, rust, go, ninja, neovim, tmux, htop, docker-client   |

```bash
# Use a specific profile
nix run github:mrquentin/claude-sandbox#minimal -- ~/project
nix run github:mrquentin/claude-sandbox#full -- ~/project
```

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
            profile = "default";  # "minimal", "default", or "full"
            extraPackages = with pkgs; [ postgresql sqlite ];
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
| Credentials        | `.credentials.json` read-only bind; SSH/AWS/kube dirs masked  |
| Git config         | Credential helpers, aliases, includes, filter drivers stripped|
| WSL2               | Windows drives masked; binary access blocked                  |
| SSH agent          | Forwarded by default (use `--no-ssh-agent` to disable)        |
| Process lifecycle  | `--die-with-parent` ensures cleanup; temp dirs scrubbed       |

### What's NOT restricted

- **Network access** — Claude Code needs the Anthropic API. Network egress filtering is planned for a future release. If `ANTHROPIC_API_KEY` is set, it is forwarded into the sandbox and could be exfiltrated via the unrestricted network.
- **Project directory** — Full read-write access to the specified directory (that's the point).
- **SSH agent** — When forwarded (default), the SSH agent socket is fully functional inside the sandbox. Use `--no-ssh-agent` to disable.

## Environment Variables

| Variable                     | Description                           |
|------------------------------|---------------------------------------|
| `CLAUDE_SANDBOX_SSH_AGENT=0`   | Disable SSH agent forwarding                      |
| `CLAUDE_SANDBOX_VERBOSE=1`     | Enable verbose output                              |
| `CLAUDE_SANDBOX_NO_SECCOMP=1`  | Allow running without seccomp (not recommended)    |
| `CLAUDE_SANDBOX_EXTRA_PATH`    | Additional PATH entries inside sandbox             |
| `ANTHROPIC_API_KEY`            | Forwarded into sandbox if set                      |
| `SANDBOX=1`                    | Set inside sandbox (for detection)                 |
| `CLAUDE_SANDBOX_VERSION`       | Version string set inside sandbox                  |

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

# Build all profiles
nix build .#minimal
nix build .#default
nix build .#full
```

## Architecture

```
claude-sandbox
├── flake.nix              # Nix flake: packages, apps, devShell, NixOS module
├── lib/
│   ├── sandbox.sh         # Main bwrap wrapper (entry point)
│   ├── detect.sh          # Environment detection (WSL2, namespaces, FUSE)
│   ├── sanitize-git.sh    # Git config sanitizer
│   ├── healthcheck.sh     # Self-test suite
│   └── seccomp.nix        # Seccomp BPF filter generator
└── modules/
    └── nixos.nix          # NixOS module
```

## License

MIT
