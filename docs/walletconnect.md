# WalletConnect

The Connections → WalletConnect route supports multiple concurrent sessions.
Users can paste a `wc:` URI. On macOS, **Scan Screen** opens the native
screen/window selection UI for one ephemeral capture. The app validates pairing
syntax and expiry before connecting. Native picker adapters for Windows and
Linux are not yet exposed; those builds currently use URI paste.

QR decoding is pure Rust and in memory. Pixels, decoded URIs, and cropped
choices are not written, logged, cached, or added to history; buffers are
cleared when dropped. When several valid codes exist, only temporary choices
are shown.

Sessions do not persist or reconnect after restart. Account and chain methods,
personal signing, typed data, transactions, and EIP-5792 requests enter the
same `OwnerApi` review path as agent requests. Explicit Quit and updater restart
disconnect every live session.
