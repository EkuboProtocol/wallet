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
- **`wallet_sendCalls`** ([EIP-5792](https://eips.ethereum.org/EIPS/eip-5792))
  is a batch, and becomes one execution plan whose steps are the calls in the
  order given. It takes the same path a single transaction takes — one
  simulation of the whole batch, the same policy, one review document listing
  every call — and executes atomically through EIP-7702, so either all of it
  happens or none does. See [batching](batching.md).
- **`personal_sign`** and **`eth_signTypedData_v4`** always stop for your
  review. No policy authorizes a signature, because a per-transaction limit
  cannot bound something its holder redeems whenever it likes.
- **`eth_accounts`**, **`eth_chainId`**, **`wallet_switchEthereumChain`**,
  **`wallet_getCapabilities`**, and **`wallet_getCallsStatus`** are answered
  from local state and touch nothing.

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
silently: whatever the dapp set is named on the session screen as the request
arrives, so nothing it asked for and did not get goes unsaid.

The approval document's "Plan source" says where a plan came from, and a dapp's
account of itself always appears there behind `WalletConnect: ` — as in
`WalletConnect: Ekubo (ekubo.org)`. A bare host in that line means TLS proved
it; the prefix means a dapp typed it, and a site is free to type anything.


## Batched calls

`wallet_getCapabilities` reports `atomic: supported` for every chain the
session covers, which is true: two or more calls become a single
`revertOnFailure` batch through the Calibur EIP-7702 delegation, so a batch
cannot half-execute. A dapp that reads this will send `wallet_sendCalls`
rather than a sequence of separate transactions.

What that changes for you is that one review covers several calls. The
approval document lists every one of them and the simulated effect of the
whole batch, and approving it approves all of it. At most 24 calls are
accepted in one batch — past that nobody is really reading the document they
are approving, and a dapp told the batch is too large can send smaller ones.

`wallet_sendCalls` returns the id of the record the batch became, which is the
same id `ekubo-wallet transaction show` takes, and `wallet_getCallsStatus`
reports on it: `100` while it is unsettled, `200` once mined without reverts,
`500` if it reverted as a whole, and `400` if it never reached the chain and
never will — because you declined it, because you cancelled it, or because its
nonce was taken by something else. The spec's `600`, partial revert, is never
returned: this wallet has no half-executed outcome to describe.

A batch is refused rather than partly honored if it asks for a capability this
wallet does not implement — a paymaster, say — unless the dapp marked it
optional.


## Choosing which account the dapp gets

A session exposes exactly one account, and you choose it on the review screen
rather than before it. Every account this wallet holds is listed there, with a
cursor on the one about to be connected:

```
 Connect as
   ▸ primary  0x1111111111111111111111111111111111111111
     cold     0x2222222222222222222222222222222222222222
     hot      0x3333333333333333333333333333333333333333
```

**Tab** moves through the list and **Shift-Tab** moves back. Each press swaps
in that account's own complete review, so the address that would be exposed and
the chains it would be exposed on are the ones on screen at the moment you
decide. **←** and **→** move between Reject and Approve, and the footer names
the account currently selected.

Switching resets the review: scroll position returns to the top and Approve
becomes unavailable until you have read to the end again. Having read one
account's consequences is not having read another's. That also makes Tab safe
on this screen — it can only ever move *away* from approving, so a Tab and an
Enter typed before the screen was drawn cannot approve anything.

On reviews with no account list — a transaction, a message, a typed-data
payload — Tab keeps its usual job of moving between Reject and Approve.

`--account` chooses where the list starts. It does not restrict it, because the
review names the selected account in its own document and changing it takes a
deliberate keystroke.


## The connection review

Approving a connection settles a session with an explicit scope: one account,
a fixed set of chains, and a fixed set of methods. A request naming anything
outside that scope is refused before any wallet code runs, and the scope cannot
be changed afterwards — a dapp that asks to change it (`wc_sessionUpdate`) is
refused, because widening what a session exposes is a decision only you can
make, and there is no way to ask you for it mid-flight.

### What the screen tells you about the dapp

A session proposal carries a name, a description, a URL, and some icon links,
all typed by whoever wrote the dapp and attested by nobody. The review
separates the part with a checkable shape from the part that is pure claim:

- **Site** leads: the host parsed out of the URL the dapp gave. This is the one
  field you can compare against the address bar of the page you opened, so it
  is the first line on the screen.
- **Name** and **About** are shown as claims. A site impersonating another one
  will put the other one's name here.
- **URL** and **Icons** appear further down, for when you want the whole thing
  rather than just the host.

The wallet also points out a few things worth weighing. None is a verdict — a
legitimate dapp can trip any of them:

- The dapp gave no URL, or one that does not parse.
- Its URL is not `https`.
- Its icons are served from a different host than its site.
- **Its name spells a domain it does not serve from** — calling itself
  `app.uniswap.org` while serving from `claim-rewards.example`. That is the
  exact shape of the attack this screen exists to catch.

There is no allowlist of known-good dapps and no reputation lookup. Both would
need a third party, and a wallet that prints "verified" on someone else's
authority has moved the decision somewhere you cannot see it. Nothing on this
screen reaches the network, and no icon is ever fetched — so connecting reveals
nothing to the dapp beyond what the relay already carries.

Every dapp-authored string is sanitized before it is drawn; a name carrying a
right-to-left override would otherwise rewrite the line it sits on. Approve
only a connection you started yourself, just now, from the page you meant.

Once connected, the dapp is named again on every request it sends: a
transaction's review says which site produced the plan, and a message or
typed-data review says who asked for the signature.

Chains the dapp lists as *required* must already be configured in this wallet,
or the proposal is refused with a message naming them; add one with
`ekubo-wallet network add`. Chains it lists as *optional* are included only
when this wallet already has a configuration for them. Everything the session
will expose is listed on the review screen before you decide.


## The relay project id

The public WalletConnect relay refuses anonymous connections, so every
connection sends a project id. This wallet's is compiled in; there is nothing
to create, configure, or pass.

It identifies the *application* to the relay operator, not you, and it is not a
secret — it travels in the relay URL's query string on every connection. It is
fixed rather than configurable because it names this wallet to the relay: a
copy connecting under some other id would spend that account's quota and
misreport who is pairing.


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


## The session screen

`connect` is full-screen from its first question to its last. Before pairing it
shows a paste surface for the link; once connected it shows a session screen
with the dapp's identity pinned at the top and a live log of every request
below it:

```
 Connected to app.example.com
 Site     app.example.com
 Account  primary
 Address  0x1111111111111111111111111111111111111111
 Chains   Ethereum, Optimism

 14:02:31  Connected. Waiting for requests…
 14:03:07  personal_sign on eip155:1
 14:03:19  personal_sign — answered.
 Connected · q or Ctrl-C disconnects
```

Who the session is with never scrolls away: a busy dapp fills the log, not the
identity block above it. Press `q` or Ctrl-C to disconnect.

The session screen hands the terminal over whenever a review opens and takes it
back afterwards, so exactly one surface is ever reading your keystrokes. That
handover is also what keeps owner authentication — Touch ID, or a polkit prompt
on Linux — on the ordinary screen where it belongs.


## Small terminals

The review is designed to be read in a split pane. The facts a connection turns
on — site, account, address, chains — are the first thing drawn, so they are
legible without scrolling on a short screen, and the warnings are last because
Approve stays unavailable until the end of the document has been on screen.

The key legend at the bottom shortens as the terminal narrows, dropping the
least important hints first so that `Esc` — the way out — survives at every
width. The Reject and Approve labels shorten rather than being cut, because
"Approve — scroll to the end of the document first" truncated to "Approve"
reads as an invitation to press it.


## Limits

- One session per `connect` run. A second proposal on the same pairing is
  refused, because reviewing it would need a second terminal.
- One account per session, chosen on the connection review. It is fixed once
  the session settles: the account is part of what the session advertised to
  the dapp, so changing it means disconnecting and reconnecting.
- The session ends if the relay connection drops; the dapp will show it as
  disconnected and you reconnect with a fresh link.
