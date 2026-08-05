# Security boundary

The MCP client, model output, configured RPC, and local files are treated as
untrusted. Before normal signing, the process validates the plan, simulates its
exact target/value/calldata, evaluates the active encrypted policy, resolves
nonce/fees, loads the key, signs locally, validates the recovered sender and
complete envelope, and durably stores the bytes and hash before broadcasting.

Exceptional signing has an additional boundary: the CLI re-simulates, prepares
the exact nonce/gas/fees/delegation without loading the key, shows those fields,
authenticates the owner against the OS, rechecks configuration and policy, and
signs the prepared object without another RPC lookup.

EIP-712 typed data never reaches the policy at all. Every payload, including a
recognized permit, queues in the encrypted database for CLI review, which
displays the complete payload, requires terminal approval plus OS owner
authentication, and only then signs. Recognized permits (ERC-2612, DAI, and
canonical Permit2, matched by their complete type encodings) are still decoded
into the token approvals signing would grant, but only so the reviewer can read
them.

A policy cannot bound a signature the way it bounds a transaction. A permit is
consumed once, so a rule that authorizes one permit under a limit authorizes an
unbounded series of them under that same limit, each individually within
policy, and the spender chooses when to redeem each one. There is no
per-transaction ceiling to apply, and the wallet holds no counters to apply one
with. That is why signing has no automatic path.

EIP-191 `personal_sign` messages queue the same way, for the additional reason
that no policy could even score what a message signature authorizes. The CLI prints the
exact bytes as hex beside their text, escapes control characters, terminal
escape sequences, and Unicode bidirectional overrides so the message cannot
repaint or reorder the screen reviewing it, and parses recognized ERC-4361
sign-in messages into labeled fields with warnings for an unconfigured or
disagreeing chain, an expired or post-dated login, a domain that disagrees with
its own URI, and any listed resources. A sign-in message naming an account other
than the signing wallet is refused outright, and legacy raw `eth_sign` over a
bare 32-byte digest is refused because no approval screen can describe it
honestly. A message signature binds no chain, so a `chain_id` sent with one is
displayed as the requester's claim.

## Why keys live in the credential store, and why nothing guards them

Private keys are the one secret that never enters the encrypted database. They
are stored as individual OS credential-store entries under
`org.ekubo.wallet.private-key.v1`, keyed by wallet ID, and the database's own
key is a separate entry. Two secrets rather than one buys something specific:
the data directory stops being key-bearing. It gets into backups, synced
folders, snapshots, and bug reports, and none of those copies can yield a key
no matter what else leaks — which matters because the database key is fetched
by nearly every command, while a private key is read only to sign. The
credential store also applies per-item access control the operating system
enforces, which a SQLCipher page cannot: once its key is in memory, the file's
protection is over.

What this does not do is stop an attacker already running code as you. Both
secrets sit in the same credential store behind the same login, so anything
that can read one can generally read the other. The protection is against
secrets at rest leaving the machine, not against a compromised session.

The obvious hardening — marking the key entry as requiring biometric or
passcode presence, so the OS refuses to release it without a live human — is
deliberately not applied, and will not be. This wallet exists so an agent can
pursue long-running goals unattended, including in loops; a key that cannot be
read without a fingerprint is a key that cannot sign at 3am. Presence
enforcement would make exactly the automatic path impossible. `wallet_send_execution_plan`
therefore performs no presence check at all on the automatic path.

So the boundary that actually contains an autonomous agent is the policy, not
key custody. What bounds a compromised or misled agent is what the policy
permits — the targets, the values, the call shapes — because once the policy
allows an action, nothing further stands between the request and a signature.
Owner authentication guards the exceptional path, where a human is present by
definition, along with key export and wallet removal. It is asked for nowhere
else: a policy, network, address book, or token change reads no key material,
so it is confirmed in the terminal rather than authenticated, and the one
prompt that does gate a signature stays worth reading. It is in any case an
application-level check in the CLI, not an operating-system gate on the key. Choose a wallet's policy on that
basis, and keep autonomous wallets funded accordingly.

SQLCipher protects confidentiality and page integrity, but there is no external
anti-rollback anchor. Restoring an older valid encrypted database can restore
an older policy or an already-signed pending record. See
[the threat model](threat-model.md) and
[architecture](architecture.md) for the precise guarantees and residual
risks, and [approval UX](approval-ux.md) for the actual approval flow.
