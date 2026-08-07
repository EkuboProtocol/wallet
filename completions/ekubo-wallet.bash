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
      choices="server version status account acct wallet network net policy transaction tx token address-book legal review completion --data-dir --json --help --version"
      ;;
    2)
      case "$first" in
        account|acct|wallet) choices="list create import export remove" ;;
        network|net) choices="list presets reset add edit remove delete review" ;;
        policy) choices="show set allow-all require-approval validate schema review" ;;
        transaction|tx) choices="list show cancel rebroadcast discard" ;;
        token) choices="list search review import" ;;
        address-book) choices="list add remove delete" ;;
        legal) choices="status show accept" ;;
        review) choices="$(ekubo-wallet __complete approvals 2>/dev/null)" ;;
        completion) choices="bash zsh fish elvish powershell" ;;
      esac
      ;;
    3)
      case "$first:$second" in
        policy:validate)
          COMPREPLY=( $(compgen -f -- "$current") )
          return
          ;;
        account:export|account:remove|acct:export|acct:remove|wallet:export|wallet:remove|policy:show|policy:set|policy:allow-all|policy:require-approval|policy:review|transaction:list|tx:list)
          choices="$(ekubo-wallet __complete wallets 2>/dev/null)"
          ;;
        network:add)
          choices="$(ekubo-wallet __complete defaults 2>/dev/null)"
          ;;
        network:edit|network:remove|network:delete)
          choices="$(ekubo-wallet __complete networks 2>/dev/null)"
          ;;
        address-book:list|address-book:add|address-book:remove|address-book:delete)
          choices="$(ekubo-wallet __complete networks 2>/dev/null)"
          ;;
        legal:show)
          choices="terms privacy licenses"
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
