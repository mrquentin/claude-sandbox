#!/usr/bin/env bash
# sanitize-git.sh — Create a safe .gitconfig for the sandbox
# Strips credential helpers, include directives, SSH commands, aliases,
# filter drivers, and hook paths.

SED="@GNUSED@"
GREP="@GNUGREP@"

_sanitize_single_gitconfig() {
  local src="$1"
  local dst="$2"

  if [[ ! -f "$src" ]]; then
    return 1
  fi

  # Strip dangerous sections and directives.
  # Section headers are matched case-insensitively with optional leading whitespace
  # to prevent bypasses via indentation or case variation.
  # Sections removed entirely:
  #   credential.*  — credential helpers can leak tokens
  #   alias.*       — aliases can execute arbitrary shell commands
  #   url.*         — insteadOf can redirect to credential-leaking URLs
  #   include       — can pull in arbitrary unsafe config files
  #   includeIf     — conditional includes, same risk
  #   filter.*      — filter drivers (clean/smudge/process) execute arbitrary code
  # Individual keys removed (case-insensitive):
  #   sshCommand    — can execute arbitrary commands
  #   gitProxy      — can redirect traffic
  #   helper        — credential helper references
  #   hooksPath     — can execute arbitrary hook scripts
  #   askpass       — can execute arbitrary password prompts
  #   fsmonitor     — filesystem monitor can execute arbitrary commands
  #   pager         — can execute arbitrary commands
  #   diff.external — can execute arbitrary commands
  #   include/path  — stray include directives outside [include] sections
  "$SED" \
    -e '/^[[:space:]]*\[credential/I,/^[[:space:]]*\[/{ /^[[:space:]]*\[credential/Id; /^[[:space:]]*\[/!d; }' \
    -e '/^[[:space:]]*\[alias/I,/^[[:space:]]*\[/{ /^[[:space:]]*\[alias/Id; /^[[:space:]]*\[/!d; }' \
    -e '/^[[:space:]]*\[url /I,/^[[:space:]]*\[/{ /^[[:space:]]*\[url /Id; /^[[:space:]]*\[/!d; }' \
    -e '/^[[:space:]]*\[include\]/I,/^[[:space:]]*\[/{ /^[[:space:]]*\[include\]/Id; /^[[:space:]]*\[/!d; }' \
    -e '/^[[:space:]]*\[includeIf /I,/^[[:space:]]*\[/{ /^[[:space:]]*\[includeIf /Id; /^[[:space:]]*\[/!d; }' \
    -e '/^[[:space:]]*\[filter /I,/^[[:space:]]*\[/{ /^[[:space:]]*\[filter /Id; /^[[:space:]]*\[/!d; }' \
    -e '/sshCommand/Id' \
    -e '/gitProxy/Id' \
    -e '/helper\s*=/Id' \
    -e '/hooksPath/Id' \
    -e '/askpass/Id' \
    -e '/fsmonitor/Id' \
    -e '/^\s*include\b/Id' \
    -e '/^\s*path\s*=.*\//d' \
    "$src" > "$dst" 2>/dev/null || true
}

sanitize_gitconfig() {
  local src_home="$1"
  local dst_home="$2"
  local src_gitconfig="${src_home}/.gitconfig"
  local dst_gitconfig="${dst_home}/.gitconfig"

  if [[ ! -f "$src_gitconfig" ]]; then
    # No gitconfig to sanitize; create a minimal one
    cat > "$dst_gitconfig" <<'GITCFG'
[core]
	autocrlf = input
GITCFG
  else
    _sanitize_single_gitconfig "$src_gitconfig" "$dst_gitconfig"
    # If the result is empty or only whitespace, create a minimal config
    if [[ ! -s "$dst_gitconfig" ]] || ! "$GREP" -q '\S' "$dst_gitconfig" 2>/dev/null; then
      cat > "$dst_gitconfig" <<'GITCFG'
[core]
	autocrlf = input
GITCFG
    fi
  fi

  # Also sanitize XDG git config (~/.config/git/config) — git reads this
  # in addition to ~/.gitconfig and it can contain the same dangerous directives
  local xdg_config_home="${XDG_CONFIG_HOME:-${src_home}/.config}"
  local xdg_git_config="${xdg_config_home}/git/config"
  if [[ -f "$xdg_git_config" ]]; then
    local dst_xdg_dir="${dst_home}/.config/git"
    mkdir -p "$dst_xdg_dir"
    _sanitize_single_gitconfig "$xdg_git_config" "${dst_xdg_dir}/config"
  fi
}
