function __ekubo_wallet_needs_command
    set -l tokens (commandline -opc)
    test (count $tokens) -eq 1
end

function __ekubo_wallet_at_position
    set -l tokens (commandline -opc)
    test (count $tokens) -eq $argv[1]
end

complete -c ekubo-wallet -f
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a server -d 'Run the MCP server over stdio'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a version -d 'Print version information'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a status -d 'Show what is set up and what is waiting for you'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a portfolio -d 'Read native and token balances for an account'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a balance -d 'Alias for portfolio'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a bal -d 'Alias for portfolio'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a account -d 'Create, import, inspect, export, or remove accounts'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a acct -d 'Create, import, inspect, export, or remove accounts'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a network -d 'Inspect, add, edit, reset, or remove networks'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a net -d 'Alias for network'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a policy -d 'Set or inspect wallet policies'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a transaction -d 'Inspect signed and broadcast transactions'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a tx -d 'Inspect signed and broadcast transactions'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a token -d 'Inspect the local token database'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a address-book -d 'Manage per-chain address aliases'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a agent -d 'Register this server with the agents on this machine'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a legal -d 'Read and accept legal documents'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a review -d 'Review a pending request and approve or reject it'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a reference -d 'Print the artifact_reference envelope for a local JSON body'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -a completion -d 'Print shell completions'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -l data-dir -r -d 'Override the wallet data directory'
complete -c ekubo-wallet -l json -d 'Print machine-readable JSON instead of the human view'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -l help -d 'Show command help'
complete -c ekubo-wallet -n __ekubo_wallet_needs_command -l version -d 'Print version information'

complete -c ekubo-wallet -n '__fish_seen_subcommand_from account acct; and not __fish_seen_subcommand_from list create import export remove' -a 'list create import export remove'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and not __fish_seen_subcommand_from list presets reset add edit remove delete review' -a 'list presets reset add edit remove delete review'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from presets' -l search -r -d 'Search the compiled-in registry by chain ID or name'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from presets' -l all -d 'List every chain in the compiled-in registry'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from policy; and not __fish_seen_subcommand_from show set allow-all require-approval validate schema review' -a 'show set allow-all require-approval validate schema review'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from transaction tx; and not __fish_seen_subcommand_from list show cancel rebroadcast discard' -a 'list show cancel rebroadcast discard'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from token; and not __fish_seen_subcommand_from list search review import remove delete' -a 'list search review import remove delete'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from address-book; and not __fish_seen_subcommand_from list add remove delete' -a 'list add remove delete'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from legal; and not __fish_seen_subcommand_from status show accept' -a 'status show accept'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from legal' -a 'terms privacy licenses'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from add remove delete; and __fish_seen_subcommand_from address-book' -a '(ekubo-wallet __complete networks-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from address-book; and __fish_seen_subcommand_from add' -l note -r -d 'Attach a short note to the alias'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from reference' -l type -r -a 'execution_plan read_calls token_list' -d 'What the file holds'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from completion; and not __fish_seen_subcommand_from bash zsh fish elvish powershell' -a 'bash zsh fish elvish powershell'

complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from export remove; and __fish_seen_subcommand_from account acct' -a '(ekubo-wallet __complete wallets-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from add; and __fish_seen_subcommand_from network net' -a '(ekubo-wallet __complete defaults-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from edit remove delete; and __fish_seen_subcommand_from network net' -a '(ekubo-wallet __complete networks-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from show set allow-all require-approval review; and __fish_seen_subcommand_from policy' -a '(ekubo-wallet __complete wallets-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from transaction tx' -a '(ekubo-wallet __complete wallets-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 2; and __fish_seen_subcommand_from review' -a '(ekubo-wallet __complete approvals-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from review' -l decision -r -a 'reject approve' -d 'Decide without the interactive prompt'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 4; and __fish_seen_subcommand_from set; and __fish_seen_subcommand_from policy' -F
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from validate; and __fish_seen_subcommand_from policy' -F
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l rpc-url -r -d 'Use an RPC URL instead of a preset or hidden prompt'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l display-name -r -d 'Set the human-readable network name'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l alias -r -d 'Add a repeatable network alias'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l native-currency-name -r -d 'Set the native currency name'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l native-currency-symbol -r -d 'Set the native currency symbol'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l native-currency-decimals -r -d 'Set native currency decimals'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l max-gas-limit -r -d 'Cap submitted transaction gas'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l block-explorer-url -r -d 'Set the block explorer URL'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from network net; and __fish_seen_subcommand_from add' -l documentation-url -r -d 'Set the network documentation URL'

complete -c ekubo-wallet -n '__ekubo_wallet_at_position 2; and __fish_seen_subcommand_from portfolio balance bal' -a '(ekubo-wallet __complete wallets-fish 2>/dev/null)'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from portfolio balance bal' -l network -r -a '(ekubo-wallet __complete networks-fish 2>/dev/null)' -d 'Network name, alias, or chain ID'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from portfolio balance bal' -l tokens -r -d 'How many known tokens to check'

complete -c ekubo-wallet -n '__fish_seen_subcommand_from agent; and not __fish_seen_subcommand_from list add remove delete' -a 'list add remove delete'
complete -c ekubo-wallet -n '__ekubo_wallet_at_position 3; and __fish_seen_subcommand_from add remove delete; and __fish_seen_subcommand_from agent' -a 'codex claude-code gemini-cli cursor'

complete -c ekubo-wallet -n '__fish_seen_subcommand_from token' -l chain -r -a '(ekubo-wallet __complete networks-fish 2>/dev/null)' -d 'Network name, alias, or chain ID'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from address-book' -l network -r -a '(ekubo-wallet __complete networks-fish 2>/dev/null)' -d 'Network name, alias, or chain ID'
complete -c ekubo-wallet -n '__fish_seen_subcommand_from transaction tx' -l account -r -a '(ekubo-wallet __complete wallets-fish 2>/dev/null)' -d 'Only rows for this account'

complete -c ew -w ekubo-wallet
