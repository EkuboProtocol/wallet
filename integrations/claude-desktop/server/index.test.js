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

test("bundle version matches the native wallet", () => {
  const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url)));
  const npmPackage = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  const cargo = readFileSync(new URL("../../../Cargo.toml", import.meta.url), "utf8");
  const walletVersion = cargo.match(/^version = "([^"]+)"$/m)?.[1];
  assert.equal(manifest.version, walletVersion);
  assert.equal(npmPackage.version, walletVersion);
});

test("runtime bridge contains no filesystem credential store", () => {
  const source = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:fs|writeFile|appendFile|createWriteStream|mcp-auth/);
});
