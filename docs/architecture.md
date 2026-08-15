# Desktop architecture

`ApplicationAuthority` is the long-lived root for configuration, encrypted
storage, custody, policies, queues, events, local MCP sessions, notifications,
and WalletConnect. It issues two compile-time capabilities:

- `OwnerApi`, retained by GPUI, performs security-sensitive mutations.
- `AgentApi`, supplied to the local IPC listener, constructs restricted MCP
  sessions for connected bridges only.

Restricted describes the operations a session can perform, not an absence of
storage or signing dependencies. A constructed MCP server owns typed
SQLCipher-backed stores and a narrow core `AgentExecutionAuthority` so it can
persist agent requests and ask core to execute only a fresh policy-authorized
transaction or exact cancellation. The MCP server never owns a `KeyStore` or
an arbitrary signing operation. It receives no owner-authorization capability, raw key export,
unrestricted database access, native-review decision, or owner-only settings
mutation.

Background work runs on the Tokio executor bridged into GPUI. Domain events
carry proposal, review, transaction, configuration, connection, and service
changes back to focused GPUI entities. The desktop shell has routes for
wallet setup, activity, permissions, connections, reference data, and settings.
Reviews open as focused overlays or activity-record details rather than as a
separate navigation destination.

One process lock and owner-only activation channel enforce a single authority.
Closing a window does not imply service shutdown; explicit Quit stops local MCP
IPC, disconnects in-memory dapp sessions, flushes state, and exits.

GPUI and `gpui-component` revisions are recorded in `Cargo.toml`. No Zed
workspace or UI crate is linked.

On Linux the tray is a direct StatusNotifierItem/DBusMenu service over zbus;
GTK and AppIndicator are not linked. macOS and Windows continue to use the
native `tray-icon` backend.
