_ekubo_wallet() {
  local current first second choices
  COMPREPLY=()
  current="${COMP_WORDS[COMP_CWORD]}"
  first="${COMP_WORDS[1]}"
  second="${COMP_WORDS[2]}"

  if [[ "$first:$second" == "network:add" && "$COMP_CWORD" -ge 4 ]]; then
    choices="--rpc-url --display-name --alias --native-currency-name --native-currency-symbol --native-currency-decimals --max-gas-limit --block-explorer-url --documentation-url"
    COMPREPLY=( $(compgen -W "$choices" -- "$current") )
    return
  fi

  case "$COMP_CWORD" in
    1)
      choices="server version wallet network policy transaction tx approve reject completion --data-dir --help --version"
      ;;
    2)
      case "$first" in
        wallet) choices="list create import export remove" ;;
        network) choices="list presets reset add remove delete" ;;
        policy) choices="show set allow-all require-approval validate schema" ;;
        transaction|tx) choices="list show" ;;
        approve|reject) choices="$(ekubo-wallet __complete approvals 2>/dev/null)" ;;
        completion) choices="bash zsh fish elvish powershell" ;;
      esac
      ;;
    3)
      case "$first:$second" in
        policy:validate)
          COMPREPLY=( $(compgen -f -- "$current") )
          return
          ;;
        wallet:export|wallet:remove|policy:show|policy:set|policy:allow-all|policy:require-approval|transaction:list|tx:list)
          choices="$(ekubo-wallet __complete wallets 2>/dev/null)"
          ;;
        network:add)
          choices="$(ekubo-wallet __complete defaults 2>/dev/null)"
          ;;
        network:remove|network:delete)
          choices="$(ekubo-wallet __complete networks 2>/dev/null)"
          ;;
      esac
      ;;
    4)
      case "$first:$second" in
        policy:set)
          COMPREPLY=( $(compgen -f -- "$current") )
          return
          ;;
      esac
      ;;
  esac

  COMPREPLY=( $(compgen -W "$choices" -- "$current") )
}

complete -F _ekubo_wallet ekubo-wallet ew
