function __ekubo_wallet_complete
    # Everything already on the line, the command name included and the
    # half-typed word at the cursor excluded. The binary decides what belongs
    # here — subcommands, flags, configured networks, account ids, queued
    # requests — so this script never has to know which position means what.
    set -l typed (commandline -opc)
    test (count $typed) -gt 0; or return

    set -l candidates ($typed[1] __complete fish $typed 2>/dev/null)
    if test (count $candidates) -eq 1; and test "$candidates[1]" = __ekubo_wallet_complete_files__
        __fish_complete_path (commandline -ct)
        return
    end

    # Each line is `value<tab>description`, which is what fish reads from -a.
    for candidate in $candidates
        echo $candidate
    end
end

complete -c ekubo-wallet -f -a '(__ekubo_wallet_complete)'
complete -c ew -w ekubo-wallet
