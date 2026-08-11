# Desktop storage

Desktop schema 1 lives in SQLCipher `wallet.db`, keyed by credential service
`org.ekubo.wallet.db`. It contains wallet policies, queues and lifecycle,
token and address-book state, legal acceptance, application settings, MCP
clients and raw recovery tokens, managed registration metadata, and requesting
client attribution.

Desktop private keys use `org.ekubo.wallet.private-key`.
