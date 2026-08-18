# Native approval flow

A review is a structured `ReviewDocument`: trusted facts, sections, exact
payloads, warnings, digest, request ID, and document identity. The initial
selection is Reject. The review renders every section and exact payload in one
scrollable document, and Approve remains unavailable until the user reaches its
end.

Closing a review records no decision. Refreshing always selects Reject again; a
changed document identity also returns scroll to the beginning and clears the
viewed-to-end bit. Generation numbers make events from a replaced view stale.

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

A policy `review` effect and an unmatched call both enter this same native
flow. In a batch, calls are checked independently and any review result makes
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
