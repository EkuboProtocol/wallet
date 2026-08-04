# Windows stack overflow: SQLCipher memory-security logging recursion

On `x86_64-pc-windows-msvc` with the bundled SQLCipher (libsqlite3-sys 0.38.1,
SQLCipher 4.14.0 community, vendored OpenSSL 3.5.0), opening the policy
database crashed with `STATUS_STACK_OVERFLOW`. Linux and macOS were
unaffected. The recursion, confirmed both empirically in CI and structurally
in the amalgamation source:

1. SQLCipher's default log configuration on Windows is level `WARN` to
   `stderr`.
2. `PRAGMA cipher_memory_security = ON` replaces SQLite's allocator with
   `sqlcipher_mem_malloc`, which `VirtualLock`s every allocation.
3. `VirtualLock` fails once the process working-set quota is exhausted —
   a documented, common condition that upstream treats as a warning
   (`sqlcipher_mlock: VirtualLock() returned 0 LastError=1453`).
4. The failure is logged at `WARN`. On Windows the log sink,
   `sqlcipher_fprintf`, converts to UTF-16 by allocating through
   `sqlite3_vmprintf` and `sqlite3_malloc` — the same locked allocator —
   so the log itself triggers another `VirtualLock` failure, which logs
   again, without bound.

Unix does not loop: its log path is plain `fprintf` with no SQLite
allocation, so an `mlock` failure logs once and returns.

Small statements never crashed because SQLCipher 4.7.0 pre-allocates a
locked private heap at startup; only allocations beyond that pool (for
example preparing this schema's larger `CREATE TABLE` statements) take
fresh `VirtualLock` calls. Pre-growing the working set with
`SetProcessWorkingSetSize` also eliminated the crash in CI, which is what
confirmed the quota mechanism.

## Mitigation in this wallet

`PolicyStore::open` sets `PRAGMA cipher_log_level = NONE` before keying the
database. `sqlcipher_log` checks the level before it formats or allocates,
so the cycle is broken while `cipher_memory_security` stays enabled.

Two consequences are accepted deliberately:

- SQLCipher's own diagnostics are silenced for this connection. SQLCipher
  errors still surface as SQLite result codes, which every call site
  already handles.
- When the quota is exhausted, memory locking silently degrades to
  best-effort, exactly as upstream already treats it on every platform.
  The database key lives in the OS credential store, and key material in
  process memory was never guaranteed unswappable on Windows.

`PolicyStore::open` also runs its schema and migration statements one per
`execute_batch` call inside an explicit transaction (`run_transaction`)
rather than as one multi-statement string. That was the first mitigation
landed while the root cause was being isolated; it remains because smaller
prepare units mean smaller transient allocations under the locked
allocator, and it costs nothing.

## How this was isolated

Every step ran in CI on `windows-2025` through a temporary
`windows-diagnose` workflow (removed after the fix; see git history):

1. A 24 MiB recursion probe passed under `RUST_MIN_STACK=64MiB`, proving
   the stack floor was honored; the crash reproduced under a 256 MiB
   floor, proving unbounded consumption.
2. Test-server construction was bisected to `PolicyStore::open`.
3. The open sequence was replayed statement by statement: key derivation,
   page I/O, and both integrity pragmas all passed; instrumentation showed
   the overflow began at the first allocation-heavy statement batch.
4. Variant probes eliminated `cipher_memory_security` alone, the
   `cipher_version` query, `busy_timeout`, and multi-statement strings as
   individual triggers, and finally isolated the combination of the locked
   allocator with large prepares — and showed a pre-grown working set
   eliminates the crash.

## Upstream status

The defect is upstream SQLCipher's: a reentrant logging path on Windows.
The minimal upstream fix is a reentrancy guard in `sqlcipher_log` (or a
non-allocating Windows log sink). Reported with an accompanying patch; see
the pull request referenced from the repository issue tracker. When a
bundled SQLCipher release containing a fix is picked up through
libsqlite3-sys, the `cipher_log_level` pragma can be relaxed if SQLCipher
diagnostics become desirable.
