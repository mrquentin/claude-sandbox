{ self }:

{ config, lib, pkgs, ... }:

let
  cfg = config.programs.claude-sandbox;
  inherit (lib) mkEnableOption mkOption types mkIf;
in
{
  options.programs.claude-sandbox = {
    enable = mkEnableOption "Claude Code sandbox";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.system}.default;
      description = "The claude-sandbox package to use.";
    };

    profile = mkOption {
      type = types.enum [ "minimal" "default" "full" ];
      default = "default";
      description = ''
        Tool profile to use:
        - minimal: git, ripgrep, coreutils, basic CLI tools
        - default: minimal + gcc, make, cmake, python3, nodejs
        - full: default + clang, rust, go, neovim, tmux, etc.
      '';
    };

    extraPackages = mkOption {
      type = types.listOf types.package;
      default = [];
      description = "Additional packages to make available inside the sandbox.";
    };

    forwardSSHAgent = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to forward SSH_AUTH_SOCK into the sandbox.";
    };

    extraBindMounts = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional directories to bind-mount read-write into the sandbox.";
      example = [ "/home/user/shared-libs" ];
    };

    extraReadOnlyMounts = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional directories to bind-mount read-only into the sandbox.";
      example = [ "/opt/datasets" ];
    };
  };

  config = mkIf cfg.enable {
    # Ensure bubblewrap is available system-wide
    environment.systemPackages = [
      cfg.package
      pkgs.bubblewrap
    ];

    # Ensure user namespaces are allowed (default on NixOS, but be explicit)
    security.allowUserNamespaces = true;

    # Ensure FUSE is available for optional overlay mode
    programs.fuse.userAllowOther = true;
  };
}
