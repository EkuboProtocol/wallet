_ekubo_wallet() {
  local current candidates
  COMPREPLY=()
  current="${COMP_WORDS[COMP_CWORD]}"

  # Everything already on the line, the command name included and the
  # half-typed word at the cursor excluded. The binary decides what belongs
  # here — subcommands, flags, configured networks, account ids, queued
  # requests — so this script never has to know which position means what.
  candidates="$("${COMP_WORDS[0]}" __complete plain "${COMP_WORDS[@]:0:COMP_CWORD}" 2>/dev/null)"

  if [[ "$candidates" == "__ekubo_wallet_complete_files__" ]]; then
    COMPREPLY=( $(compgen -f -- "$current") )
    return
  fi

  # Candidates are one per line and never contain spaces; without this, a
  # description-free list would still be split on every space in a value.
  local IFS=$'\n'
  COMPREPLY=( $(compgen -W "$candidates" -- "$current") )
}

complete -F _ekubo_wallet ekubo-wallet
