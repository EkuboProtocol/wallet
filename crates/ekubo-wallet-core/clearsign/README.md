# Clear-signing descriptor snapshot

Vendored [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730) calldata
descriptors, copied verbatim from the CC0-licensed
[clear-signing-erc7730-registry](https://github.com/ethereum/clear-signing-erc7730-registry)
at review time. The wallet embeds these files at compile time and never
fetches descriptors from the network: updating the snapshot is a reviewed
git commit, exactly like a code change, because descriptors shape what a
human sees while approving a transaction.

`registry/ekubo/` is the exception: those descriptors are written and
maintained here for Ekubo's own contracts, so a defect in them is fixed in
this tree. Everything else stays byte-identical to upstream, defects
included — a known upstream defect is named in the test that would
otherwise fail, never patched in place.

Descriptors are display metadata only. The approval digest binds the exact
calldata, matching is by exact chain ID, contract address, and function
selector, and a descriptor mismatch falls back to the generic selector
display — a wrong or missing descriptor can never alter what gets signed.

Every file here is parsed, selector-checked, and path-validated by the
test suite (`clear_signing` tests), so a malformed descriptor fails CI
rather than degrading the approval review silently.
