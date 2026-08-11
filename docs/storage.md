# Desktop storage

Desktop schema 1 lives in SQLCipher `wallet.db`, keyed by credential service
`org.ekubo.wallet.db.v2`. It contains accounts and encrypted network settings,
wallet policies, signing queues and lifecycle history, owner-confirmed token
metadata, legal acceptance, application settings, OAuth client and credential
hashes, managed registration metadata, and requesting-client attribution.

Desktop private keys use `org.ekubo.wallet.private-key`.
