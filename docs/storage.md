# Desktop storage

Desktop schema 1 lives in SQLCipher `wallet.db`, keyed by credential service
`org.ekubo.wallet.db.v2`. It contains wallet policies, queues and lifecycle,
token and address-book state, legal acceptance, application settings, MCP
clients and raw recovery tokens, managed registration metadata, and requesting
client attribution. The schema also records literal lineage `desktop-v1` so a
retired schema with the same numeric version cannot be opened.

Desktop private keys use `org.ekubo.wallet.private-key.v2`. Legacy
`org.ekubo.wallet.private-key.v1` entries are never read, overwritten, or
deleted by migration.

Before the first desktop database opens, an existing pre-desktop directory is
atomically renamed to `legacy-pre-desktop-<timestamp>`. No accounts, policies,
settings, registrations, or history are imported. A marker makes the operation
idempotent.
