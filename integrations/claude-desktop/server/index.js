import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const WALLET_MCP_URL = "http://127.0.0.1:61744/mcp";
const WALLET_ORIGIN = "http://127.0.0.1:61744";
const RESOURCE_METADATA_URL = `${WALLET_ORIGIN}/.well-known/oauth-protected-resource`;
const PROTOCOL_VERSION = "2025-06-18";
const MAX_STDIO_LINE_BYTES = 24 * 1024 * 1024;
const AUTH_TIMEOUT_MS = 5 * 60 * 1000;

const oauth = {
  client: undefined,
  tokens: undefined,
  tokenEndpoint: undefined,
  resource: undefined,
};
let sessionId;

function log(message) {
  process.stderr.write(`[ekubo-wallet] ${message}\n`);
}

export function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function parseSse(body) {
  const messages = [];
  let data = [];
  for (const line of body.replaceAll("\r\n", "\n").split("\n")) {
    if (line === "") {
      if (data.length !== 0) messages.push(JSON.parse(data.join("\n")));
      data = [];
    } else if (line.startsWith("data:")) {
      data.push(line.slice(5).trimStart());
    }
  }
  if (data.length !== 0) messages.push(JSON.parse(data.join("\n")));
  return messages;
}

function openBrowser(url) {
  const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/d", "/s", "/c", "start", "", url] : [url];
  const child = spawn(command, args, { detached: true, stdio: "ignore", windowsHide: true });
  child.unref();
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  if (!response.ok) throw new Error(`${new URL(url).pathname} returned HTTP ${response.status}`);
  return text === "" ? {} : JSON.parse(text);
}

async function createAuthorizationCallback() {
  let settle;
  let fail;
  const result = new Promise((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/callback") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    response.end("Ekubo Wallet authorized Claude Desktop. You may close this tab.");
    settle({
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state"),
      error: url.searchParams.get("error")
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  server.on("error", fail);
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("could not allocate the OAuth callback port");
  }
  return {
    redirectUri: `http://127.0.0.1:${address.port}/callback`,
    result,
    close: () => server.close()
  };
}

async function authorize() {
  const metadata = await jsonRequest(RESOURCE_METADATA_URL);
  const issuer = new URL(metadata.authorization_servers?.[0] ?? WALLET_ORIGIN);
  if (issuer.origin !== WALLET_ORIGIN) throw new Error("wallet advertised an unexpected OAuth issuer");
  const authorizationServer = await jsonRequest(`${issuer.origin}/.well-known/oauth-authorization-server`);
  for (const endpoint of [authorizationServer.registration_endpoint, authorizationServer.authorization_endpoint, authorizationServer.token_endpoint]) {
    if (new URL(endpoint).origin !== WALLET_ORIGIN) throw new Error("wallet advertised an OAuth endpoint outside loopback");
  }
  oauth.tokenEndpoint = authorizationServer.token_endpoint;
  oauth.resource = metadata.resource ?? WALLET_MCP_URL;
  const callback = await createAuthorizationCallback();
  const redirectUri = callback.redirectUri;
  let timeoutId;

  try {
    oauth.client = await jsonRequest(authorizationServer.registration_endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Claude Desktop",
        redirect_uris: [redirectUri],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none"
      })
    });

    const verifier = base64Url(randomBytes(32));
    const challenge = base64Url(createHash("sha256").update(verifier).digest());
    const state = base64Url(randomBytes(24));
    const authorizationUrl = new URL(authorizationServer.authorization_endpoint);
    authorizationUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: oauth.client.client_id,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      scope: metadata.scopes_supported?.[0] ?? "mcp",
      resource: oauth.resource
    }).toString();
    openBrowser(authorizationUrl.toString());

    const timeout = new Promise((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error("wallet authorization timed out")), AUTH_TIMEOUT_MS);
    });
    const result = await Promise.race([callback.result, timeout]);
    if (result.error) throw new Error(`wallet authorization failed: ${result.error}`);
    if (!result.code || result.state !== state) throw new Error("wallet returned an invalid OAuth callback");
    oauth.tokens = await jsonRequest(authorizationServer.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: result.code,
        client_id: oauth.client.client_id,
        redirect_uri: redirectUri,
        code_verifier: verifier,
        resource: oauth.resource
      })
    });
  } finally {
    clearTimeout(timeoutId);
    callback.close();
  }
}

async function refreshTokens() {
  if (!oauth.tokens?.refresh_token || !oauth.client?.client_id || !oauth.tokenEndpoint || !oauth.resource) return false;
  try {
    const refreshed = await jsonRequest(oauth.tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: oauth.tokens.refresh_token,
        client_id: oauth.client.client_id,
        resource: oauth.resource
      })
    });
    oauth.tokens = { ...refreshed, refresh_token: refreshed.refresh_token ?? oauth.tokens.refresh_token };
    return true;
  } catch {
    oauth.tokens = undefined;
    return false;
  }
}

async function walletRequest(message, retried = false) {
  const headers = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
    "mcp-protocol-version": PROTOCOL_VERSION
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  if (oauth.tokens?.access_token) headers.authorization = `Bearer ${oauth.tokens.access_token}`;
  let response;
  try {
    response = await fetch(WALLET_MCP_URL, { method: "POST", headers, body: JSON.stringify(message) });
  } catch (error) {
    throw new Error(`Ekubo Wallet is not running at ${WALLET_MCP_URL}: ${error.message}`);
  }
  if (response.status === 401 && !retried) {
    await response.arrayBuffer();
    if (!(await refreshTokens())) await authorize();
    return walletRequest(message, true);
  }
  if (!response.ok) throw new Error(`wallet MCP returned HTTP ${response.status}`);
  sessionId = response.headers.get("mcp-session-id") ?? sessionId;
  if (response.status === 202) return [];
  const text = await response.text();
  return response.headers.get("content-type")?.includes("text/event-stream") ? parseSse(text) : [JSON.parse(text)];
}

function writeMessage(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function errorResponse(message, error) {
  if (!("id" in message)) return;
  writeMessage({
    jsonrpc: "2.0",
    id: message.id,
    error: { code: -32603, message: error instanceof Error ? error.message : "local wallet bridge failed" }
  });
}

export async function forwardLine(line, request = walletRequest) {
  if (Buffer.byteLength(line) > MAX_STDIO_LINE_BYTES) throw new Error("MCP message exceeds the wallet request limit");
  const message = JSON.parse(line);
  const responses = await request(message);
  return responses;
}

export async function main() {
  process.stdin.setEncoding("utf8");
  let buffer = "";
  let queue = Promise.resolve();
  process.stdin.on("data", chunk => {
    buffer += chunk;
    if (Buffer.byteLength(buffer) > MAX_STDIO_LINE_BYTES) {
      log("input exceeded the wallet request limit");
      process.exitCode = 1;
      process.stdin.pause();
      return;
    }
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const raw of lines) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (line.trim() === "") continue;
      queue = queue.then(async () => {
        let message;
        try {
          message = JSON.parse(line);
          for (const response of await forwardLine(line)) writeMessage(response);
        } catch (error) {
          log(error instanceof Error ? error.message : "local wallet bridge failed");
          if (message) errorResponse(message, error);
        }
      });
    }
  });
  process.stdin.on("end", () => queue.catch(error => log(error.message)));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
