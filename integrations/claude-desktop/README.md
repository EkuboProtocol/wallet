# Ekubo Wallet for Claude Desktop

This Claude plugin is a local, dependency-free transport adapter. Claude Desktop
starts `server/index.js` over stdio; the adapter forwards MCP messages only to
the fixed Ekubo Wallet endpoint at `http://127.0.0.1:61744/mcp`.

The plugin also installs the credential-free Ekubo companion at
`https://mcp.ekubo.org/mcp`.

The adapter implements OAuth dynamic client registration and PKCE. Access and
refresh tokens are held in process memory and are never written to the bundle,
an agent configuration file, or disk. Consequently, restarting Claude Desktop
can require authorizing it again in Ekubo Wallet.

Build and verify:

```sh
npm ci
npm test
npm run validate:plugin
npm run pack:plugin
```

The resulting `dist/ekubo-wallet-plugin.zip` can be imported by Claude
Desktop's plugin installer. The obsolete MCPB format is intentionally not
produced because current Claude Desktop versions do not import it.
