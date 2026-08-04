# Windows stack overflow in multi-statement `execute_batch`

On `x86_64-pc-windows-msvc`, passing one multi-statement SQL string to
rusqlite's `execute_batch` against the bundled SQLCipher (libsqlite3-sys
0.38.1, SQLCipher 4.14.0 community, vendored OpenSSL 3.5.0) crashes the
process with `STATUS_STACK_OVERFLOW`. The identical statements executed one
per `execute_batch` call succeed, keyed or unkeyed. Linux and macOS are
unaffected.

`PolicyStore::open` therefore runs its schema and migration statements
individually through `run_transaction` instead of as combined
`BEGIN IMMEDIATE; ...; COMMIT;` strings. Semantics are unchanged: the same
statements run in the same order inside one immediate transaction, with an
explicit rollback on failure.

## How this was isolated

Every step below ran in CI on `windows-2025` through the temporary
`windows-diagnose` workflow (removed after the fix; see git history):

1. A 24 MiB recursion probe passes under `RUST_MIN_STACK=64MiB`, so the
   raised stack floor is honored by test threads. The overflow reproduces
   even under a 256 MiB floor, so the consumption is effectively unbounded.
2. Construction of the test server was bisected step by step: the overflow
   is inside `PolicyStore::open`.
3. `PolicyStore::open` was replayed statement by statement: key derivation,
   `cipher_memory_security`, page reads/writes, and both
   `PRAGMA cipher_integrity_check` and `PRAGMA integrity_check` all pass.
   Instrumentation inside the real function showed the overflow begins at
   the schema `execute_batch`.
4. The same schema statements executed individually pass, keyed and
   unkeyed. Only the combined multi-statement string overflows.

The root cause inside the C amalgamation was not identified further once
the trigger was isolated to "multi-statement string on Windows MSVC" and a
semantics-preserving workaround existed. Revisit when updating
libsqlite3-sys: if a future bundled SQLCipher no longer reproduces the
overflow (re-add a multi-statement batch in a Windows test to check),
`run_transaction` can be simplified back to combined batches.
