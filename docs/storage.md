# Local storage

`EKUBO_WALLET_HOME`, when set, is the complete data directory. Otherwise the
platform defaults are below. They are deliberately distinct from the
TypeScript `wallet-mcp-server` directories and keychain entries: the storage
formats are incompatible, and the two servers must never read each other's
state.

| Platform | Data directory | Encrypted database |
| --- | --- | --- |
| macOS | `~/Library/Application Support/org.ekubo.wallet` | `policies.db` |
| Linux | `${XDG_STATE_HOME}/ekubo-wallet`, or `~/.local/state/ekubo-wallet` | `policies.db` |
| Windows | `%LOCALAPPDATA%\Ekubo\wallet` | `policies.db` |

The one SQLCipher file contains separate `wallet_policies`,
`pending_transactions`, `pending_typed_data`, `pending_messages`, `tokens`,
`address_book`, `legal_acceptance`, and `policy_proposals` tables. Token metadata, address
aliases, and legal acceptance deliberately live inside the authenticated
encrypted database rather than in plain files: they carry no signing
authority, but a file edit outside this process must not be able to forge
acceptance, retarget an alias, or misrepresent a token. A pre-existing plain
`tokens.db` is imported once (constraint-checked, never overwriting) and
removed; leftover `address_book.db` or `legal.json` files from unreleased
builds are deleted without being trusted. A pending row stores its normalized execution
plan and digest, policy revision, expiry and lifecycle status; once signed it
also stores the exact serialized transaction and hash before the first RPC
submission. An exceptional approval additionally records the digest of its
reviewed nonce, gas, fees, call, and delegation fields. Retries only rebroadcast
those persisted bytes. Inspect the ledger with `ekubo-wallet transaction list`
and `ekubo-wallet transaction show <request-id-or-hash>`: on a terminal these
open a human-readable view — `list` is an interactive browser with relative
ages, expandable details, block-explorer links, and receipt-decoded token
balance changes. It draws one page sized to the terminal and scrolls with the
arrow keys, so a long history never outgrows the screen; `Done` is the first
entry and `Esc` also leaves the browser. Every reporting command prints exact JSON instead when
`--json` is passed or when stdout is not a terminal, so scripts and agents
always receive machine-readable output.

The random 256-bit database key is stored separately under credential-service
name `org.ekubo.wallet.policy-database-key.v1`. Wallet private keys use
`org.ekubo.wallet.private-key.v1` and the wallet ID as their account. The
unencrypted `config.json` in the same data directory contains wallet metadata
and network configuration, including RPC URLs; it contains no private key.

## Cloud-synced private keys

`wallet create` and `wallet import` accept `--key-storage cloud-synced` to
place the private key in the iCloud-synchronized keychain instead of this
machine's local credential store. The choice is per wallet, recorded in its
metadata as `key_storage`, and fixed for the wallet's lifetime; every later
signing, export, and removal consults the store the key actually lives in.
Wallets without the field — every wallet created before the option existed —
are local.

A cloud-synced key is replicated by the OS to every device signed into the
same Apple account and survives the loss of this machine; that is the entire
trade. The key stops being held by one device, and any synced device (or an
iCloud account compromise) can reach it. Policies, the encrypted database, and
its key never sync — they are per-machine authority, so a second device that
receives the key still signs nothing until a wallet is attached there and a
policy deliberately installed. On a device that already holds the synced
credential, `wallet attach <id>` records the wallet locally without ever
displaying the key, and starts it under the require-approval policy exactly
like an import.

Two platform constraints bound the feature. It is macOS-only: the credential
stores this server uses on Linux (Secret Service) and Windows (Credential
Manager) do not replicate secrets across devices, so `--key-storage
cloud-synced` fails closed there with an error saying so. And synchronized
keychain items live in the protected-data keychain, which macOS only opens to
binaries signed with an application identifier and the iCloud keychain
entitlement — an ad hoc developer build or an unsigned release is refused by
the OS with `errSecMissingEntitlement (-34018)`, reported with that
explanation before any wallet metadata is written. Local key storage, the
default, is unaffected by either constraint.
