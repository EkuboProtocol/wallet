# Policy authoring for agents

Read the active policy and schema before proposing a complete replacement.
Bind the proposal to the returned revision and explain its purpose. A proposal
cannot install itself; the owner sees a minimized permission diff in the native
Policies screen and authenticates before installation.

Owners can manage chain entries in the Guided editor: add, rename, edit, or
remove a chain, set its batch ceiling, and allow no native value, any native
value, or an exact set of wei values. Existing allow/deny rules remain visible
and are preserved. Advanced JSON exposes the complete predicate language.
Both views feed the same canonical validation, revision recheck, permission
diff, and OS-authenticated installation path.

Prefer the narrowest rule that expresses the intended operation: exact chains,
targets, native-value ceilings, canonical ABI signatures, and typed argument
predicates. Deny rules always win. An uncovered call requires owner approval;
an explicit deny never queues.

In exact terms, a deny means nothing signs, nothing queues. Matching no rule
queues for explicit human approval. Native-value ceilings remain an independent
guard and no rule can widen it. An absent slot constrains nothing. A policy
accepts 1 to 4096 calls per batch, and each argument predicate is type-checked against the signature.
Never bare hex: selector rules name the complete canonical ABI signature.
The only variable there is the signing wallet's own address; labels and
simulation facts are not authorization variables.

Never rely on display labels, token symbols, or simulation output as
authorization. They are review context, not policy inputs.
