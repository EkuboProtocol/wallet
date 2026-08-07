_ekubo_wallet() {
  local current first second choices
  COMPREPLY=()
  current="${COMP_WORDS[COMP_CWORD]}"
  first="${COMP_WORDS[1]}"
  second="${COMP_WORDS[2]}"

  if [[ "$first:$second" == "network:presets" && "$COMP_CWORD" -ge 3 ]]; then
    COMPREPLY=( $(compgen -W "--search --all" -- "$current") )
    return
  fi

  if [[ "$first:$second" == "network:add" && "$COMP_CWORD" -ge 4 ]]; then
    choices="--rpc-url --rpc-strategy --display-name --alias --native-currency-name --native-currency-symbol --native-currency-decimals --max-gas-limit --block-explorer-url --documentation-url"
    COMPREPLY=( $(compgen -W "$choices" -- "$current") )
    return
  fi

  case "$COMP_CWORD" in
    1)
      choices="server version status portfolio balance account network policy transaction tx token address-book agent legal review reference completion --data-dir --json --help --version"
      ;;
    2)
      case "$first" in
        account) choices="list create import export remove" ;;
        portfolio|balance) choices="$(ekubo-wallet __complete wallets 2>/dev/null)" ;;
        network) choices="list presets reset add edit remove delete review" ;;
        policy) choices="show set allow-all require-approval validate schema review" ;;
        transaction|tx) choices="list show cancel rebroadcast discard" ;;
        token) choices="list search review import remove delete" ;;
        address-book) choices="list add remove delete" ;;
        agent) choices="list add remove delete" ;;
        legal) choices="status show accept" ;;
        review) choices="$(ekubo-wallet __complete approvals 2>/dev/null)" ;;
        reference) choices="--type" ;;
        completion) choices="bash zsh fish elvish powershell" ;;
      esac
      ;;
    3)
      case "$first:$second" in
        policy:validate)
          COMPREPLY=( $(compgen -f -- "$current") )
          return
          ;;
        account:export|account:remove|policy:show|policy:set|policy:allow-all|policy:require-approval|policy:review|transaction:show|tx:show)
          choices="$(ekubo-wallet __complete wallets 2>/dev/null)"
          ;;
        network:add)
          choices="$(ekubo-wallet __complete defaults 2>/dev/null)"
          ;;
        network:edit|network:remove|network:delete)
          choices="$(ekubo-wallet __complete networks 2>/dev/null)"
          ;;
        address-book:add|address-book:remove|address-book:delete|token:remove|token:delete)
          choices="$(ekubo-wallet __complete networks 2>/dev/null)"
          ;;
        agent:add|agent:remove|agent:delete)
          choices="codex claude-code gemini-cli cursor"
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
