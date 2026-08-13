# Ekubo Wallet for Claude Desktop

This MCP Bundle is a local, dependency-free transport adapter. Claude Desktop
starts `server/index.js` over stdio; the adapter forwards MCP messages only to
the fixed Ekubo Wallet endpoint at `http://127.0.0.1:61744/mcp`.

The adapter implements OAuth dynamic client registration and PKCE. Access and
refresh tokens are held in process memory and are never written to the bundle,
an agent configuration file, or disk. Consequently, restarting Claude Desktop
can require authorizing it again in Ekubo Wallet.

Build and verify:

```sh
npm ci
npm test
npm run validate
npm run pack
```

The resulting `dist/ekubo-wallet.mcpb` can be installed from Claude Desktop's
Settings → Extensions → Advanced settings → Install Extension.
