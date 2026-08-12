# WalletConnect

The Connections → WalletConnect route supports multiple concurrent sessions.
Users paste a `wc:` URI copied from the dapp's connect-wallet dialog. The app
validates pairing syntax and expiry before connecting.

Sessions do not persist or reconnect after restart. Account and chain methods,
personal signing, typed data, transactions, and EIP-5792 requests enter the
same `OwnerApi` review path as agent requests. Explicit Quit and updater restart
disconnect every live session.
