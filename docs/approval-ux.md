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

Private-key export uses the same owner-authentication boundary. The revealed
value is held for 30 seconds, copying requires a separate click, and clipboard
cleanup occurs only when the clipboard still contains that exact value.
