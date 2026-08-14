# Desktop storage

Desktop schema 1 lives in SQLCipher `wallet.db`, keyed by credential service
`org.ekubo.wallet.db`. It contains accounts and encrypted network settings,
wallet policies, signing queues and lifecycle history, owner-confirmed token
metadata, legal acceptance, application settings, and optional informational
harness-kind attribution for agent activity. It contains no local MCP client,
grant, access-token, refresh-token, or authorization-code tables.

Managed harness configuration files contain only the absolute installed bridge
command with its fixed `--client` argument and the hosted companion URL. They
are not sources of wallet authority and contain no wallet-managed credential.

Desktop private keys use `org.ekubo.wallet.private-key`.
