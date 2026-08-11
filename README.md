# Ekubo Wallet

Ekubo Wallet is a native GPUI desktop wallet for EVM accounts used by people,
local AI agents, and WalletConnect dapps. One tray-first process owns encrypted
state and private keys. There is no command-line, terminal, stdio, or webview
mode.

The application exposes Streamable HTTP MCP only at
`http://127.0.0.1:61744/mcp`. Managed agent files contain that URL and OAuth
mode only. A harness must explicitly start OAuth login; the wallet then brings
its native window forward. A script-free local consent page lets the owner
choose a one-day, one-week, or one-month session before operating-system human
presence and issuance of a one-time PKCE-bound authorization code. The harness
owns storage of its 10-minute access token and rotated refresh token.

Every request must carry the exact loopback `Host`; `Origin`, every
`Access-Control-*` request header, and `OPTIONS` are rejected before a body is
read. OAuth credentials prevent accidental or unauthorized local clients;
plaintext loopback HTTP cannot protect against malicious software already
running as the same OS user.

## Desktop model

- `OwnerApi` exists only in the GUI and controls accounts, reviews, policies,
  networks, tokens, agent installation, legal acceptance,
  exports, and updates.
- `AgentApi` can inspect public wallet state, simulate, propose, enqueue signing
  requests, and observe results. It cannot approve, export keys, or weaken owner
  policy.
- Reviews start on Reject. Approve stays disabled until the complete document
  has been viewed, then requires OS authentication and immediate state
  revalidation.
- WalletConnect pairings are concurrent and memory-only. Screen-capture frames
  and decoded pairing URIs are never persisted.

The application initializes a fresh SQLCipher `wallet.db` on first launch.

## Development

```text
cargo check --workspace
cargo test --workspace
```

GPUI is pinned to Zed revision
`cc053a4a6fa2fd0e8793201ed9099466af1be0b1`; `gpui-component` is pinned to
`26cc9366abb27ccedce386ac99a615a8fa7018da`. The application consumes only the
Apache-2.0 GPUI infrastructure, not Zed's GPL workspace/UI crates.

See [architecture](docs/architecture.md), [installation](docs/installation.md),
[security boundary](docs/security-boundary.md), and
[release process](docs/releasing.md).

## Protocol integration note

Legacy limit orders are deprecated because they do not provide guaranteed
execution: a limit order can be un-executed. Integrators building current
signed swap flows should refer to the
[`SignedExclusiveSwap` extension source](https://github.com/EkuboProtocol/evm-contracts/blob/main/src/extensions/SignedExclusiveSwap.sol)
in `EkuboProtocol/evm-contracts`.

## License

See [LICENSE](LICENSE).
