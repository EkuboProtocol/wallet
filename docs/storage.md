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
acceptance, retarget an alias, or misrepresent a token. Leftover `tokens.db`,
`address_book.db`, or `legal.json` files from unreleased builds are deleted
without being trusted: a plain file in the data directory has no curator
behind it, so importing one would be an unauthenticated write into the table
the review screen presents as confirmed. A pending row stores its normalized execution
plan and digest, policy revision, and lifecycle status; once signed it
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

Each queue records a decision in one `decided_at` column rather than a pair of
`approved_at` and `rejected_at` ones, because a request gets one decision and a
pair can claim it got both — a contradiction the schema previously had no
opinion about, alongside a rejected row carrying no rejection time. `status`
names which decision it was, since rejection is terminal and a decided row that
is not rejected was approved. A check states exactly which rows carry one: an
automatic transaction carries none because nobody decided anything, a queued
request has not been decided yet, and everything further along has been. The
`approved_at` and `rejected_at` fields the CLI and MCP surfaces report are
derived from the stored pair, so the two can never disagree.

Values are stored as what they are rather than as text that describes them.
Every hash, address, signature, signed envelope, and request ID is a `BLOB` of
its exact width, and every moment is an `INTEGER` count of milliseconds since
the Unix epoch. Both choices are about what the schema can enforce rather than
about size: a fixed-width blob column *is* the thing it holds — there is no
20-byte string that is not an address — where the hex-text column it replaced
could only check a length and a lowercase spelling, and admitted values no
address ever takes. Integer timestamps compare and sort as themselves, where
RFC 3339 text ordered correctly only while every writer spelled UTC the same
way. `crates/ekubo-wallet-core/src/sql.rs` holds every one of these encodings,
so no call site restates one. The hex and RFC 3339 spellings are still what the
CLI and MCP surfaces emit; they are rendered on the way out.

The random 256-bit database key is stored separately under credential-service
name `org.ekubo.wallet.db` — named for the database rather than for policies,
since the same file holds the pending signing queues, the address book, and
the token names a reviewer reads. Wallet private keys use
`org.ekubo.wallet.private-key.v1` and the wallet ID as their account. The
unencrypted `config.json` in the same data directory contains wallet metadata
and network configuration, including every network's list of RPC URLs; it
contains no private key. A configuration written by an earlier release names a
single `rpc_url` per network; it is read as a one-entry list and rewritten as
`rpc_urls` on the next change. Older builds cannot read the new spelling.
