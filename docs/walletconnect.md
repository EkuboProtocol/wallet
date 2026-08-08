# Connecting to a dapp over WalletConnect

`ekubo-wallet connect` pairs this wallet with a website from a pasted
WalletConnect link, so a dapp can propose transactions and signatures the way
an MCP agent does.

```sh
ekubo-wallet connect 'wc:a1b2…@2?relay-protocol=irn&symKey=…'
```

Quote the link. It contains `&`, which every shell reads as "run this in the
background" long before the wallet sees it. Run the command with no argument
and it prompts for the link instead, which avoids the quoting question
entirely and keeps the link out of your shell history.

The command runs until the dapp disconnects or you press Ctrl-C. It needs an
interactive terminal, because every request it serves ends at a review there.


## What a dapp can and cannot do

A dapp reached this way is exactly as untrusted as an agent is. It can
*propose*, and nothing more:

- **`eth_sendTransaction`** becomes the same signer-neutral execution plan an
  agent would have produced. It is simulated, put to the same policy, and
  either signed automatically because your policy already allows it or queued
  and shown to you in the same full-screen review the `review` command uses —
  same document, same owner authentication.
- **`personal_sign`** and **`eth_signTypedData_v4`** always stop for your
  review. No policy authorizes a signature, because a per-transaction limit
  cannot bound something its holder redeems whenever it likes.
- **`eth_accounts`**, **`eth_chainId`**, and **`wallet_switchEthereumChain`**
  are answered from the session's own state and touch nothing.

Two methods are refused on purpose:

- **`eth_sign`** signs a bare 32-byte digest, so no review can show you what
  you would be authorizing.
- **`eth_signTransaction`** hands signed bytes back to the dapp instead of
  broadcasting them. This wallet's record of what it has signed is what makes
  nonce reconciliation and cancellation work, and a signed envelope loose in a
  dapp's memory breaks both.

Contract deployment is also refused: a transaction with no `to` cannot be
expressed as an execution plan, and it is refused by name rather than turned
into a call to the zero address.

The dapp's opinions about `nonce`, `gasPrice`, `maxFeePerGas`, and `chainId`
are not honored — the wallet determines those itself. It does not drop them
silently: whatever the dapp set is named in the "Plan source" line of the
approval document, so a review never shows you something the request disagreed
with.


## The connection review

Approving a connection settles a session with an explicit scope: one account,
a fixed set of chains, and a fixed set of methods. A request naming anything
outside that scope is refused before any wallet code runs, and the scope cannot
be changed afterwards — a dapp that asks to change it (`wc_sessionUpdate`) is
refused, because widening what a session exposes is a decision only you can
make, and there is no way to ask you for it mid-flight.

The review screen shows the dapp's name, URL, and description. **None of it is
verified.** A site impersonating another one will claim the other one's name
there, so the screen says so, and every one of those strings is sanitized
before it is drawn — a name carrying a right-to-left override would otherwise
rewrite the line it sits on. Approve only a connection you started yourself,
just now, from the site you meant.

Chains the dapp lists as *required* must already be configured in this wallet,
or the proposal is refused with a message naming them; add one with
`ekubo-wallet network add`. Chains it lists as *optional* are included only
when this wallet already has a configuration for them. Everything the session
will expose is listed on the review screen before you decide.


## The relay project id

The public WalletConnect relay refuses anonymous connections, so a project id
is required. Create one — it is free — at <https://dashboard.reown.com>, then
pass `--project-id` or set `EKUBO_WALLET_WALLETCONNECT_PROJECT_ID`.

It identifies the *application* to the relay operator, not you, and it is not a
secret. There is no built-in default on purpose: a wallet that silently
borrowed somebody else's id would be rate-limited on their quota.


## What the relay can see

Messages are end-to-end encrypted between this wallet and the dapp with a key
derived on the pairing, so the relay routes ciphertext it cannot read and
cannot forge a message that opens. It is still a third party: it sees which
topics talk to which and when, and it can drop messages. The honest summary is
that the relay is untrusted for confidentiality and integrity, and trusted for
liveness only.

`--relay-url` points at a self-hosted relay instead. It must be `wss:`; a
plaintext relay is refused rather than downgraded to, because the connection's
authentication token travels in the URL.

The pairing link itself is a secret while it is valid. The symmetric key is in
the link — that is what makes the QR code a key exchange — so anyone who reads
one can impersonate the dapp for the length of the pairing. Prefer the paste
prompt over an argument, and treat a link you did not just generate as spent.


## Limits

- One session per `connect` run. A second proposal on the same pairing is
  refused, because reviewing it would need a second terminal.
- One account per session, named with `--account` when the wallet holds more
  than one.
- The session ends if the relay connection drops; the dapp will show it as
  disconnected and you reconnect with a fresh link.
