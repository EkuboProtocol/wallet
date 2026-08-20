# Native approval flow

A review is a structured `ReviewDocument`: trusted facts, sections, exact
payloads, warnings, digest, request ID, and document identity. The initial
selection is Reject. The review renders every section and exact payload in one
scrollable document, and Approve remains unavailable until the user reaches its
end.

Closing a review records no decision. Refreshing always selects Reject again; a
changed document identity also returns scroll to the beginning and clears the
viewed-to-end bit. Generation numbers make events from a replaced view stale.

A dapp connection is the one review that asks the owner a question inside the
document — which account to expose — and it answers with a different document
per account. Answering it keeps the scroll position and the viewed-to-end bit,
provided the rows come out identical to the ones already on screen; the
documents differ only in the account they name, so nothing carried over was
read against text that changed. Rows that differ fall back to the general rule
above. The generation still advances on every answer, so clicks rendered from
the previous document remain stale. The choice starts unmade and the account
chooser is the first thing under the summary, because it gates approval.

Selecting Approve invokes platform owner authentication. After authentication,
the authority reloads the request and policy, verifies the review identity and
digest, and only then signs. Cancelling authentication leaves the request
pending. Notifications and tray menus never contain approval actions.

Approving a transaction also sends it: the signed envelope is submitted before
the review closes, which is why the button reads "Authenticate & send".
Submitting the exact bytes the owner just authenticated expands nothing the
approval did not already authorize, and it is the same exact-byte transition
the activity list's "Send now" performs. Nothing else has to come back and ask
for it — an agent whose approval wait timed out is usually gone by the time a
human reaches the window, and a signed transaction nobody submits is a decision
the wallet quietly failed to carry out. If every endpoint refuses the envelope,
the row stays `signed` and the reviewer is told, so "Send now" can try again.

A policy `review` effect, an unmatched call, and a sender that asked for review
of a transaction the policy would have signed all enter this same native flow.
The last is recorded on the request, because the document is authored fresh
when the review opens and the policy evaluation behind it says the transaction
is allowed; the summary names the ask rather than claiming a policy gap that
does not exist. In a batch, calls are checked independently and any review result makes
the whole prepared transaction reviewable; any deny result rejects the whole
transaction. A simulation ID is a short-lived plan handle, not approval or a
prepared transaction. Sending through one runs fresh real-chain simulation,
exact envelope preparation, and current-policy evaluation before signing or
queuing.

The configured RPC supplies simulation results and can lie. Expected balance
changes are advisory review evidence, never automatic-policy inputs or
authenticated state. The exact target, calldata/payload, native value, and
prepared transaction fields in the document are authoritative; refreshing a
review asks an endpoint again but does not create an independent trust anchor.

Private-key export uses the same owner-authentication boundary. The revealed
value is held for 30 seconds, copying requires a separate click, and clipboard
cleanup occurs only when the clipboard still contains that exact value.

A pairing link pasted anywhere in the window, or the WalletConnect page's
one-press handoff, starts a pairing from the clipboard. The clipboard is read
on that keystroke or that click and at no other time: the wallet never polls
it, and never advertises itself to a page. Text without the `wc:` scheme is
left alone and stays an ordinary paste; the keystroke is window-scoped, so a
focused text field keeps its own paste. The read is refused outright while the
legal gate is up, while a private-key export is open — that panel puts a key on
the clipboard on purpose — and while an unsaved network form would block the
move. Pairing is not connecting: the dapp still has to propose a session, and
that proposal still opens the review above, where the owner chooses an account
and authenticates. A pending security review is not dismissed by a paste; the
pairing starts behind it and its proposal queues.
