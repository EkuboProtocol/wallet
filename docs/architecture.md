# Architecture

`ekubo-wallet` is one process. In server mode, the stdio MCP adapter, plan
validation, RPC simulation, policy evaluation, key access, signing, envelope
validation, durable lifecycle update, and broadcast pipeline all run in that
process. There is no privileged daemon, subprocess core, service mode, or
private IPC protocol.

Direct CLI commands use the same library but are separate invocations. They are
management, recovery, and human-approval surfaces—not clients of a signing
daemon. There is one signing implementation and no generic digest-signing API.

## Components

- `rmcp` provides MCP and stdio transport.
- `alloy` provides Ethereum primitives, RPC types, transaction construction,
  signing, and post-signature recovery.
- Alloy's typed `eth_simulateV1` client executes the exact direct call or
  Calibur batch against a pinned parent block. The process validates response
  parent linkage, simulated block number, call count, canonical Calibur runtime
  hash, balance probes, and returned transfer logs. There is no local EVM,
  `eth_getProof` reconstruction, or `eth_call` fallback for signing decisions.
- Recorded simulations (`src/simulation_store.rs`) are also in-process only.
  Simulating against real chain state returns a `simulation_id`, and a send may
  consume that recorded result instead of executing the identical
  `eth_simulateV1` request again seconds later. An entry supplies the plan as
  well as the result, is consumed on use, expires in two minutes, and is
  refused if the wallet, chain, or policy revision it was evaluated under has
  moved. The approval CLI is a different process and always re-simulates, so a
  human decides against the chain as it is when they decide.
- Temporary simulation forks (`src/fork.rs`) are held only in process memory as
  an ordered list of already-validated plans plus one pinned parent block.
  Every call replays that list as consecutive `eth_simulateV1` blocks, so the
  RPC still executes everything and no simulated state is stored locally. They
  are an agent workflow tool with no CLI surface and no signing authority.
- `rusqlite` with vendored SQLCipher stores current policies and pending
  transaction lifecycle rows in one encrypted `policies.db` file.
- `keyring` stores wallet keys and a distinct 256-bit SQLCipher key under
  separate service names.
- `HumanPresence` uses Local Authentication, Windows Hello, or polkit, and is
  reached only where key material is used or destroyed: signing, key export,
  and wallet removal. Local configuration changes confirm in the terminal.

The database deliberately contains no daily counters, rolling windows,
allowance reservations, spend history, or consumption ledger. Policy limits
are stateless and apply to one transaction or atomic batch.

## Signing pipeline

```text
structured plan
   │ validate sender/chain/shape and compute canonical plan digest
   ▼
eth_simulateV1 at pinned block
   │ exact call + optional EIP-7702 delegation override
   ▼
local policy evaluation
   ├─ denied/failed ─▶ encrypted awaiting_approval row ─▶ separate CLI
   │
   └─ allowed ──────▶ resolve nonce/gas/fees ─▶ load key ─▶ sign
                                                    │
                                                    ▼
                                       recover and validate envelope
                                                    │
                                                    ▼
                                  persist exact bytes/hash before RPC send
```

For an exceptional approval, nonce/gas/fees are prepared before the terminal
and OS review. The review digest commits to those fields and the exact call.
After OS authentication the CLI reloads mutable local authority and signs the
already-prepared object without another RPC lookup.

One plan step becomes a direct EIP-1559 transaction. Multiple steps are encoded
as a single atomic `execute` call to canonical Calibur. If the wallet does not
already delegate to that implementation, the signer emits EIP-7702 with one
authorization whose nonce is the sender transaction nonce plus one. Both the
authorization and outer envelope are recovered and validated after signing.

## Storage and lifecycle

Private keys are not in this directory at all. Each is an OS credential-store
entry under `org.ekubo.wallet.private-key.v1` keyed by wallet ID, and the
SQLCipher key is a separate entry under
`org.ekubo.wallet.policy-database-key.v1`. Keeping them apart is what lets the
data directory be copied — backed up, synced, attached to a bug report —
without carrying key material, and it means the frequently handled secret (the
database key, read by nearly every command) is not the same secret as the one
read only to sign.

Those entries carry no presence requirement: the wallet is built for unattended
agent operation, so a key the OS refuses to release without a live human would
defeat the automatic signing path. For that path the policy is the security
boundary rather than key custody. See
[the threat model](threat-model.md#key-custody-and-the-presence-check-that-is-deliberately-absent).

The platform data directory contains:

- `config.json`: private-permission wallet metadata and network profiles;
- `config.lock`: inter-process configuration update lock;
- `policies.lock`: inter-process database/key initialization lock; and
- `policies.db`: SQLCipher database containing separate `wallet_policies` and
  `pending_transactions` tables.

SQLCipher uses a credential-store key, authenticated pages, secure deletion,
full synchronization, and DELETE journal mode so there is no persistent WAL.
Startup runs cipher and logical integrity checks. A missing key for an existing
database, wrong key, corrupt page, unsupported schema, or configured wallet
without a policy fails closed.

Policy revisions provide optimistic concurrency. Pending rows bind the full
plan and digest, policy revision, approval status, optional review
digest, signed bytes/hash, broadcast hash, block number, and lifecycle state.
At most one signed/submitting/broadcast transaction exists for a wallet/chain.

Submission first claims a durable lease. A crash or ambiguous RPC response is
reconciled by exact transaction hash. If rebroadcast is needed, only the stored
serialized envelope is sent again. No fee bump, nonce replacement, or re-sign
occurs implicitly.

## Rollback boundary

There is no external database checkpoint. Restoring an older valid encrypted
database can restore an older policy or pending lifecycle state. Since there is
no consumed daily allowance, rollback cannot replenish a spending window. It
can nevertheless restore a more permissive policy or a still-valid signed
transaction; the latter may be rebroadcast after hash reconciliation. Protect
the data directory and backups accordingly.

See [the threat model](threat-model.md) for trust assumptions and
[exceptional approval flow](approval-ux.md) for the human boundary.
