# Security boundary

The [system-wide threat model](threat-model.md) defines the actors, trust
assumptions, persistence and rollback behavior, and accepted residual risks
that surround this code boundary.

Within the wallet process API, private keys and signing remain inside the core
authority. MCP never receives `OwnerApi`. Its constructed server has typed
storage capabilities and a narrow core execution authority that can only run
the guarded automatic-transaction and exact-cancellation paths. It never
receives a `KeyStore`, raw-key load, or arbitrary-signature method. It has no
methods for raw-key export, native-review decisions, policy installation,
legal acceptance, owner authorization, or owner-only settings mutation.

That compile-time boundary does not protect the generic OS credential entries
from a separate same-user process. Current Windows and common GNOME Linux
stores allow such a process to retrieve the SQLCipher key and raw account keys,
which recreates an arbitrary signer outside core. A prompt-injected agent
harness that can execute local programs as the desktop user can take this
route without calling MCP, so wallet policy, native review, and audit do not
interpose. Microsoft documents
[user-process access to generic credentials](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials),
and GNOME documents
[same-user access to unlocked keyrings](https://wiki.gnome.org/Projects%282f%29GnomeKeyring%282f%29SecurityFAQ.html).
This open critical gap is tracked in
[issue #112](https://github.com/EkuboProtocol/wallet/issues/112); the threat
model documents its platform consequences.

MCP may persist, replace, or disable scheduled automations. Automation
bytecode is an untrusted plan source, not a signing capability: the in-process
scheduler holds the same narrow `AgentExecutionAuthority`, and every emitted
batch is freshly simulated, prepared, and evaluated against the active policy.
Automations are bound to a wallet instance and policy revision; a revision
change stops the existing definition until the owner starts it again or an
agent replaces it while naming the current revision. A live agent can already
submit calls under the current policy; the binding prevents a dormant job from
silently inheriting a later policy, not a live agent from using authority that
policy grants. Policy matchers remain per call and per prepared envelope, not
cumulative budgets, so a permitted action may be repeated by either a live
agent or an automation.

Policies may allow, require native review, or deny. Each call resolves through
its first matching rule; deny dominates the whole transaction, then review or
an unmatched call, and only all-allow transactions proceed automatically. A
sender may additionally ask for native review of one submission it would
otherwise have sent automatically, which adds a human to a decision the policy
had already permitted; it cannot remove a review, widen a policy, or make a
denied transaction sendable, and it never applies to bytes already signed.
Typed data and personal messages always require native
review because reusable off-chain authority cannot be bounded by transaction
policy. Before every signature approved through native review, the authority
re-reads current request and policy state after OS authentication. An automatic
transaction instead reaches the signer only when the current core-owned policy
allows its exact call and prepared-envelope fields. Every send, including one
using a prior simulation ID, freshly simulates, prepares, and evaluates the
current policy; preview identifiers are not durable authorization.

Exact calldata, message bytes, complete typed data, digest, warnings, Unicode
controls, bidi controls, and confusable characters remain available in the
review. By default, transaction notifications name the account and network but
never show the request identifier or contain approval actions.

Public HTTPS and bounded `data:application/json` artifacts are supported.
Local-file artifacts are not.
