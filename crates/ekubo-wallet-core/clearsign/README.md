# Clear-signing descriptor snapshot

Vendored [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730) calldata
descriptors, copied verbatim from the CC0-licensed
[clear-signing-erc7730-registry](https://github.com/ethereum/clear-signing-erc7730-registry)
at review time. The wallet embeds these files at compile time and never
fetches descriptors from the network: updating the snapshot is a reviewed
git commit, exactly like a code change, because descriptors shape what a
human sees while approving a transaction.

`registry/ekubo/` covers Ekubo's own contracts and is authored on the
`fix-ekubo-signed-formats` branch of
[EkuboProtocol/clear-signing-erc7730-registry](https://github.com/EkuboProtocol/clear-signing-erc7730-registry),
where it is prepared for upstreaming, and copied here byte-for-byte from
there. A defect in one of them is fixed on that branch and re-vendored, not
patched here, so the two never say different things about what an Ekubo
transaction does.

Everything else stays byte-identical to upstream, defects included — a
known upstream defect is named in the test that would otherwise fail, never
patched in place.

Descriptors are display metadata only. The approval digest binds the exact
calldata, matching is by exact chain ID, contract address, and function
selector, and a descriptor mismatch falls back to the generic selector
display — a wrong or missing descriptor can never alter what gets signed.

Every file here is parsed, selector-checked, and path-validated by the
test suite (`clear_signing` tests), so a malformed descriptor fails CI
rather than degrading the approval review silently. One of those tests reads
every signed parameter in the corpus and refuses a formatter that would drop
its sign, which is how a swap amount displayed as a token amount — unsigned by
definition, on an `int128` where negative means exact-output — was caught
before it shipped.

The 2026-09-09 snapshot revisions and copied paths are recorded in
[snapshot.json](snapshot.json). Upstream test fixtures and signature attestations
are not runtime descriptors and are excluded. The Ekubo source branch preserves
the signed-amount fixes that have not landed on its older `ekubo` branch.
