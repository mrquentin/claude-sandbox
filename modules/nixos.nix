{ self }:

{ config, lib, pkgs, ... }:

let
  cfg = config.programs.claude-sandbox;
  inherit (lib) mkEnableOption mkOption types mkIf optionalString
                concatMapStringsSep makeBinPath literalExpression;

  profilePackages = {
    minimal = self.packages.${pkgs.system}.minimal;
    default = self.packages.${pkgs.system}.default;
    full = self.packages.${pkgs.system}.full;
  };

  profileBinNames = {
    minimal = "claude-sandbox-minimal";
    default = "claude-sandbox";
    full = "claude-sandbox-full";
  };

  basePackage = profilePackages.${cfg.profile};
  baseBinName = profileBinNames.${cfg.profile};

  extraPath = makeBinPath cfg.extraPackages;

  # Generate a wrapper script that applies NixOS module options as CLI flags
  # and environment variables, delegating to the real sandbox binary.
  wrappedBin = pkgs.writeShellScriptBin "claude-sandbox" ''
    args=()
    ${optionalString (!cfg.forwardSSHAgent) ''args+=(--no-ssh-agent)''}
    ${concatMapStringsSep "\n    " (dir: ''args+=(--extra-bind "${dir}")'') cfg.extraBindMounts}
    ${concatMapStringsSep "\n    " (dir: ''args+=(--extra-ro "${dir}")'') cfg.extraReadOnlyMounts}
    ${optionalString (cfg.extraPackages != []) ''export CLAUDE_SANDBOX_EXTRA_PATH="${extraPath}"''}
    exec "${basePackage}/bin/${baseBinName}" "''${args[@]}" "$@"
  '';
in
{
  options.programs.claude-sandbox = {
    enable = mkEnableOption "Claude Code sandbox";

    package = mkOption {
      type = types.package;
      default = wrappedBin;
      defaultText = literalExpression "auto-generated wrapper based on profile and options";
      description = ''
        The claude-sandbox package to install. Defaults to an auto-generated
        wrapper that applies profile selection and configured options.
        Override this only if you need a fully custom build.
      '';
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
      description = ''
        Additional packages to make available inside the sandbox.
        Their bin directories are added to the sandbox PATH via
        CLAUDE_SANDBOX_EXTRA_PATH.
      '';
      example = literalExpression "[ pkgs.postgresql pkgs.sqlite ]";
    };

    forwardSSHAgent = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to forward SSH_AUTH_SOCK into the sandbox.
        Note: the SSH agent socket is fully functional inside the sandbox
        (ro-bind only prevents file writes, not socket communication).
        Disable this if the sandbox should not have SSH agent access.
      '';
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
    # Install the wrapper (or user-overridden package) and bubblewrap
    environment.systemPackages = [
      cfg.package
      pkgs.bubblewrap
    ];

    # Ensure user namespaces are allowed (default on NixOS, but be explicit)
    security.allowUserNamespaces = true;

    # Ensure FUSE is available for optional future overlay mode
    programs.fuse.userAllowOther = true;
  };
}
