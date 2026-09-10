# Desktop storage

Desktop schema 1 lives in SQLCipher `wallet.db`, keyed by credential service
`org.ekubo.wallet.db`. It contains accounts and encrypted network settings,
wallet policies, signing queues and lifecycle history, owner-confirmed token
metadata, legal acceptance, application settings, and optional informational
harness-kind attribution for agent activity. It contains no local MCP client,
grant, access-token, refresh-token, or authorization-code tables.

Managed harness configuration files contain only the absolute installed bridge
command with its fixed `--client` argument and, where supported, the hosted
companion URL. Claude Desktop's hosted companion is an account-level custom
connector and is never written to its local stdio configuration. These files
are not sources of wallet authority and contain no wallet-managed credential.

Desktop private keys use `org.ekubo.wallet.private-key.instance`, keyed by the
wallet instance UUID rather than the reusable display ID.

Credentials use the macOS User keychain, Windows generic Credential Manager,
and the Secret Service default collection on Linux. On Linux, core opens a
fresh Secret Service session for each credential entry instead of using the
`keyring` v1 facade's process-wide cached session. A daemon restart or failed
first connection can therefore recover on the next operation without a wallet
restart. Keys are not cached, credential writes are not automatically retried,
and a missing database key still fails closed rather than replacing it.

The service and user strings above are lookup
identifiers, not access controls. Microsoft documents that
[Windows generic credentials are readable by user processes](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials),
the [Secret Service specification does not mandate access control](https://specifications.freedesktop.org/secret-service/latest/ch10.html),
and GNOME allows
[any same-user application to read an unlocked keyring](https://wiki.gnome.org/Projects%282f%29GnomeKeyring%282f%29SecurityFAQ.html).
On those platforms a sibling process can retrieve both the database unwrap key
and raw account keys. That includes a prompt-injected agent harness able to
execute local programs as the user. SQLCipher and core policy therefore do not
provide a same-user confidentiality boundary. This critical limitation is
tracked in [issue #112](https://github.com/EkuboProtocol/wallet/issues/112).
