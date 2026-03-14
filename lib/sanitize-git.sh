#!/usr/bin/env bash
# sanitize-git.sh — Create a safe .gitconfig for the sandbox
# Strips credential helpers, include directives, SSH commands, and aliases.

SED="@GNUSED@"
GREP="@GNUGREP@"

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
    return 0
  fi

  # Copy and strip dangerous sections/directives
  # Remove: credential.*, core.sshCommand, core.gitProxy,
  #         alias.*, include, includeIf, url.*.insteadOf (can leak creds)
  "$SED" \
    -e '/^\[credential/,/^\[/{ /^\[credential/d; /^\[/!d; }' \
    -e '/^\[alias/,/^\[/{ /^\[alias/d; /^\[/!d; }' \
    -e '/^\[url /,/^\[/{ /^\[url /d; /^\[/!d; }' \
    -e '/^\[include\]/,/^\[/{ /^\[include\]/d; /^\[/!d; }' \
    -e '/^\[includeIf /,/^\[/{ /^\[includeIf /d; /^\[/!d; }' \
    -e '/sshCommand/d' \
    -e '/gitProxy/d' \
    -e '/helper\s*=/d' \
    -e '/^\s*include\b/Id' \
    -e '/^\s*path\s*=.*\//d' \
    "$src_gitconfig" > "$dst_gitconfig" 2>/dev/null || true

  # If the result is empty or only whitespace, create a minimal config
  if [[ ! -s "$dst_gitconfig" ]] || ! "$GREP" -q '\S' "$dst_gitconfig" 2>/dev/null; then
    cat > "$dst_gitconfig" <<'GITCFG'
[core]
	autocrlf = input
GITCFG
  fi
}
