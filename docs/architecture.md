# Desktop architecture

`ApplicationAuthority` is the long-lived root for configuration, encrypted
storage, custody, policies, queues, events, local MCP sessions, notifications,
and WalletConnect. The authority layer exposes three compile-time capabilities:

- `OwnerApi`, retained by GPUI, performs security-sensitive mutations.
- `AgentApi`, supplied to the local IPC listener, constructs restricted MCP
  sessions for connected bridges only.
- `DappApi`, derived by GPUI for a live WalletConnect session, exposes only
  session-state reads, review-only signature queues, and the guarded
  transaction path.

Restricted describes the operations a session can perform, not an absence of
storage or signing dependencies. A constructed MCP server owns typed
SQLCipher-backed stores and a narrow core `AgentExecutionAuthority` so it can
persist agent requests and ask core to execute only a fresh policy-authorized
transaction or exact cancellation. The MCP module receives no directly
callable `KeyStore` or arbitrary signing operation; core's authority privately
owns the key-store dependency behind those two guarded methods. It receives no
owner-authorization capability, raw key export, unrestricted database access,
native-review decision, or owner-only settings mutation.

This is an in-process capability architecture, not a complete OS custody
boundary. The current generic credential-store backends on Windows and common
GNOME Linux desktops allow a separate same-user process to retrieve the
database and account key bytes directly. [Issue #112](https://github.com/EkuboProtocol/wallet/issues/112)
tracks the app-isolated custody design needed to make the process boundary hold
on those platforms.

The automation scheduler is another consumer of the same narrow
`AgentExecutionAuthority`. Agent-installed bytecode supplies plans on a cron
schedule, but each output still enters the ordinary fresh simulation,
preparation, current-policy evaluation, signing-slot, and persistence path. A
policy revision change unlinks the existing job before it can run under the new
policy; the owner may start it again, and an agent may replace it while naming
the current revision.

WalletConnect transaction input is likewise kept outside custody. The dapp
adapter holds `DappApi`, which performs policy simulation and hands the exact
plan and result to core's guarded execution authority. The adapter never
receives `OwnerApi`, `OsKeyStore`, a raw store, or the automatic orchestrator.

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
