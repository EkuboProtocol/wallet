# Offline function-signature directory

Pinned source: [ethereum-lists/4bytes](https://github.com/ethereum-lists/4bytes) at
`2b8a705fe27833b59aac2a2af5d14e0144e1e56e`, licensed under MIT. The upstream
license is retained here and included in the application's third-party notices.
Hashes, counts, and compression version are recorded in `snapshot.json`.

Reproduce from the repository root (Python 3.11+, zlib version recorded in the
snapshot; a different compressor version can produce different bytes):

```sh
curl -fL https://codeload.github.com/ethereum-lists/4bytes/tar.gz/2b8a705fe27833b59aac2a2af5d14e0144e1e56e -o /tmp/fourbytes.tar.gz
python3 contrib/vendor-fourbyte.py /tmp/fourbytes.tar.gz
```

The script verifies the source archive hash. It retains canonical-name entries
from `signatures/`, including selector collisions, without extracting the tar
archive to disk. Runtime parsing verifies each signature's selector independently.
Parameter names are not inferred: arguments are named `arg0`, `arg1`, etc.

`signatures.bin` starts with `EK4BYTE1`, then a little-endian u32 block count.
Each 12-byte block record contains the first selector (numeric big-endian EVM
selector, stored as little-endian u32), compressed-data offset, and length.
Offsets are relative to the end of this outer table. Each zlib block contains
up to 128 selectors: a little-endian row count, 12-byte records of selector,
string offset and length, then the ASCII strings. Inner offsets are relative
to the end of the inner table. Semicolons separate colliding signatures.

Lookup binary-searches the outer table and inflates one bounded block. A
64-block FIFO bounds cached decompressed data. The directory adds 19.23 MB to
the wallet core binary; it is not embedded in the standalone summary-model Wasm.

Hints appear only when neither a clear-signing descriptor nor standard decoder
provides a reading. Exact selector, canonical argument decoding, declared widths,
and complete byte-for-byte re-encoding are required. The review still says the
call is unrecognized; possible functions and typed raw arguments are supplemental
context. A candidate never establishes the target's implementation or token units.

Runtime budgets: 64 signatures examined, four matching candidates, 65,536 argument
bytes, 1,024 signature characters and 32 tuple/array markers. Each candidate shows
at most 16 arguments, with 256-character display limits. The signature display is
capped at 180 characters. Full raw calldata remains in the authoritative review.
