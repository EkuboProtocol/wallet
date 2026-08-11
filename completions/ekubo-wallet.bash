_ekubo_wallet() {
  local current candidates
  COMPREPLY=()
  current="${COMP_WORDS[COMP_CWORD]}"

  # Everything already on the line, the command name included and the
  # half-typed word at the cursor passed separately. The binary decides what belongs
  # here — subcommands, flags, configured networks, account ids, queued
  # requests — so this script never has to know which position means what.
  candidates="$("${COMP_WORDS[0]}" __complete plain --current "$current" "${COMP_WORDS[@]:0:COMP_CWORD}" 2>/dev/null)"

  # Both branches below read a command substitution into an array, which bash
  # splits on `$IFS` and then expands as a pathname pattern. Neither default is
  # wanted here.
  #
  # Splitting on spaces is why the candidate branch already narrowed `IFS`; the
  # file branch never did, so `compgen -f` offering `my policy.json` produced
  # two candidates and inserting either gave the wrong path. Globbing is the
  # other half, and applies to both: a file named `*` in the directory expands
  # to every name beside it, so what the shell inserts is chosen by whoever
  # could write a filename there rather than by the person typing. These are
  # the paths `policy set`, `token import`, and `reference` are completed with.
  #
  # `noglob` is the interactive shell's own setting, so it is restored rather
  # than cleared: an owner who set it did not ask this function to unset it.
  local restore_noglob=1
  [[ -o noglob ]] || restore_noglob=0
  set -o noglob
  local IFS=$'\n'

  if [[ "$candidates" == "__ekubo_wallet_complete_files__" ]]; then
    COMPREPLY=( $(compgen -f -- "$current") )
    # Told these are filenames, bash escapes what it inserts and appends the
    # trailing slash on a directory — the handling this branch exists to keep.
    compopt -o filenames 2>/dev/null
  else
    COMPREPLY=( $(compgen -W "$candidates" -- "$current") )
  fi

  ((restore_noglob)) || set +o noglob
}

complete -F _ekubo_wallet ekubo-wallet
