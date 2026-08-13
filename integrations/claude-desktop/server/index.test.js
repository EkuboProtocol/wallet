import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { base64Url, forwardLine, parseSse, WALLET_MCP_URL } from "./index.js";

test("the bridge endpoint is the exact fixed loopback resource", () => {
  assert.equal(WALLET_MCP_URL, "http://127.0.0.1:61744/mcp");
});

test("base64Url emits PKCE-safe text", () => {
  assert.equal(base64Url(Buffer.from([251, 255, 239])), "-__v");
});

test("SSE data frames become MCP messages", () => {
  assert.deepEqual(parseSse('event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":1,"result":{}}\n\n'), [
    { jsonrpc: "2.0", id: 1, result: {} }
  ]);
});

test("stdio messages are forwarded without changing their identity", async () => {
  const seen = [];
  const input = '{"jsonrpc":"2.0","id":7,"method":"tools/list"}';
  const output = await forwardLine(input, async message => {
    seen.push(message);
    return [{ jsonrpc: "2.0", id: message.id, result: { tools: [] } }];
  });
  assert.deepEqual(seen, [JSON.parse(input)]);
  assert.deepEqual(output, [{ jsonrpc: "2.0", id: 7, result: { tools: [] } }]);
});

// The bundle ships on the wallet's own release and Claude Desktop shows this
// number to the person installing it, so all four copies of it name the wallet
// or none of them mean anything. The lockfile is included because npm does not
// mind a stale root version, which leaves this the only thing that would ever
// notice one.
test("plugin versions match the native wallet", () => {
  const read = name => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url)));
  const pluginManifest = read(".claude-plugin/plugin.json");
  const npmPackage = read("package.json");
  const lockfile = read("package-lock.json");
  const cargo = readFileSync(new URL("../../../Cargo.toml", import.meta.url), "utf8");
  const walletVersion = cargo.match(/^version = "([^"]+)"$/m)?.[1];
  const fix = "run contrib/sync-claude-desktop-version.py";
  assert.equal(pluginManifest.version, walletVersion, `.claude-plugin/plugin.json: ${fix}`);
  assert.equal(npmPackage.version, walletVersion, `package.json: ${fix}`);
  assert.equal(lockfile.version, walletVersion, `package-lock.json: ${fix}`);
  assert.equal(lockfile.packages[""].version, walletVersion, `package-lock.json: ${fix}`);
});

test("the Claude plugin always installs the credential-free companion", () => {
  const pluginConfig = JSON.parse(
    readFileSync(new URL("../.mcp.json", import.meta.url), "utf8")
  );
  assert.deepEqual(pluginConfig.mcpServers.ekubo, {
    type: "http",
    url: "https://mcp.ekubo.org/mcp"
  });
});

test("runtime bridge contains no filesystem credential store", () => {
  const source = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:fs|writeFile|appendFile|createWriteStream|mcp-auth/);
});
