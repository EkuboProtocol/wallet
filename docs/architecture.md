# Desktop architecture

`ApplicationAuthority` is the long-lived root for configuration, encrypted
storage, custody, policies, queues, events, MCP clients, notifications, and
WalletConnect. It issues two compile-time capabilities:

- `OwnerApi`, retained by GPUI, performs security-sensitive mutations.
- `AgentApi`, retained by the HTTP transport, constructs restricted MCP
  sessions only.

Background work runs on the Tokio executor bridged into GPUI. Domain events
carry proposal, review, transaction, configuration, connection, and service
changes back to focused GPUI entities. The desktop shell has routes for
Overview, Reviews, Activity, Accounts, Policies, Networks, Tokens,
WalletConnect, Settings, and Updates. Agent management and Legal/Version live
inside Settings.

One process lock and owner-only activation channel enforce a single authority.
Closing a window does not imply service shutdown; explicit Quit stops HTTP,
disconnects in-memory dapp sessions, flushes state, and exits.

GPUI and `gpui-component` revisions are recorded in `Cargo.toml`. No Zed
workspace or UI crate is linked.
