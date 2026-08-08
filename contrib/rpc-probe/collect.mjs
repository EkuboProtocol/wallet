// Collect every public HTTPS JSON-RPC endpoint chainlist.org knows about.
//
// chainlist.org renders two sources: the ethereum-lists/chains registry
// (chainid.network/chains.json) and its own curated extras, which carry the
// tracking disclosure the site shows next to each endpoint. Both are merged
// here so the prober sees one candidate list per chain.
//
//   bun contrib/rpc-probe/collect.mjs <out-dir>
//
// Writes <out-dir>/candidates.json. Network access required.

import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const CHAINS_URL = "https://chainid.network/chains.json";

// chainlist's extras are a JavaScript module, and reading it means running it:
// the map is built by the module body, so there is no way to get the data out
// without executing whatever else is in the file, with this maintainer's own
// privileges. It used to be fetched from `main`, which is a branch — anyone
// who could push to it, or who compromised an account that could, chose what
// ran on the machine of whoever regenerated the registry, and that machine is
// the one that also holds the signing material.
//
// So the fetch is pinned to a commit, which cannot change under us, and the
// bytes are checked against the digest recorded beside it. Updating the pin is
// then a deliberate act with a reviewable diff: a new sha and a new digest,
// both visible, rather than a silent change in what runs.
//
// This does not make the file trusted. It makes it *fixed*, so that trusting
// it is a decision someone made once and can be pointed at, instead of one
// being retaken silently on every run.
const EXTRA_RPCS_COMMIT = "58e9056cc1548eae3f8f3738874d6db9cfbbf7a3";
const EXTRA_RPCS_SHA256 = "a02f43f61f68f577d72bb1dedb9e387617811fa5d2c302adc73db998d570f12e";
const EXTRA_RPCS_URL = `https://raw.githubusercontent.com/DefiLlama/chainlist/${EXTRA_RPCS_COMMIT}/constants/extraRpcs.js`;

const outDir = process.argv[2] ?? ".";
mkdirSync(outDir, { recursive: true });

// A path segment that is a long hex string, a UUID, or the word "demo" is
// somebody's credential. chainlist lists a number of these and they do answer
// requests, but shipping one as a default hands out a key we neither own nor
// can rotate, and the endpoint stops working for every user at once when the
// owner notices. Keyless endpoints only.
const KEY_SEGMENT = /^(?:[0-9a-f]{20,}|[0-9a-zA-Z_-]{24,}|demo|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

function carriesCredential(parsed) {
  for (const [name] of parsed.searchParams) {
    if (/key|token|secret|auth|pass/i.test(name)) return true;
  }
  return parsed.pathname
    .split("/")
    .filter(Boolean)
    .some((segment) => KEY_SEGMENT.test(segment));
}

// An endpoint that needs a key is not a fallback anyone can rely on, and a
// plaintext endpoint is one any network path can rewrite, so neither is a
// candidate no matter how healthy it would probe.
function usable(url) {
  if (typeof url !== "string") return false;
  if (!url.startsWith("https://")) return false;
  if (url.includes("${") || url.includes("API_KEY") || url.includes("_KEY}")) return false;
  try {
    const parsed = new URL(url);
    if (!parsed.hostname.includes(".")) return false;
    if (carriesCredential(parsed)) return false;
    return true;
  } catch {
    return false;
  }
}

// Trailing slashes and duplicate spellings of the same endpoint would each be
// probed separately and could both land in one chain's fallback list, which
// would make the list shorter than it looks.
function canonical(url) {
  const parsed = new URL(url);
  parsed.hash = "";
  if (parsed.pathname === "/") parsed.pathname = "";
  return parsed.toString();
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { "user-agent": "ekubo-wallet-rpc-probe" } });
  if (!response.ok) throw new Error(`${url} responded ${response.status}`);
  return response.json();
}

async function fetchExtraRpcs() {
  const response = await fetch(EXTRA_RPCS_URL, {
    headers: { "user-agent": "ekubo-wallet-rpc-probe" },
  });
  if (!response.ok) throw new Error(`${EXTRA_RPCS_URL} responded ${response.status}`);
  const source = await response.text();
  // Checked before the bytes touch the disk, let alone the module loader: a
  // mismatch here means the pin no longer describes what is being served, and
  // the only safe reading of that is to stop.
  const digest = createHash("sha256").update(source).digest("hex");
  if (digest !== EXTRA_RPCS_SHA256) {
    throw new Error(
      `${EXTRA_RPCS_URL} hashes to ${digest}, not the pinned ${EXTRA_RPCS_SHA256}; ` +
        "refusing to run it. If the pin is being updated deliberately, change " +
        "EXTRA_RPCS_COMMIT and EXTRA_RPCS_SHA256 together after reading the diff.",
    );
  }
  // The file is an ES module whose default export is the map. Importing the
  // real thing keeps the parse honest without vendoring a JS parser; it goes
  // through a scratch file because the module is far too large to import as a
  // data: URL. Importing it runs it — see the note on the pin above.
  const scratch = join(outDir, ".extra-rpcs.mjs");
  writeFileSync(scratch, source);
  const module = await import(pathToFileURL(scratch).href);
  rmSync(scratch, { force: true });
  return module.default ?? module.extraRpcs ?? {};
}

const [chains, extraRpcs] = await Promise.all([fetchJson(CHAINS_URL), fetchExtraRpcs()]);

const byChain = new Map();

function chainEntry(chainId) {
  let entry = byChain.get(chainId);
  if (!entry) {
    entry = { chainId, endpoints: new Map() };
    byChain.set(chainId, entry);
  }
  return entry;
}

function addEndpoint(chainId, url, tracking, source) {
  if (!usable(url)) return;
  const key = canonical(url);
  const entry = chainEntry(chainId);
  const existing = entry.endpoints.get(key);
  if (existing) {
    // chainlist's tracking disclosure is better evidence than the registry's
    // silence, so it wins when both list the same endpoint.
    if (tracking && (!existing.tracking || existing.tracking === "unknown")) {
      existing.tracking = tracking;
    }
    if (!existing.sources.includes(source)) existing.sources.push(source);
    return;
  }
  entry.endpoints.set(key, { url: key, tracking: tracking ?? "unknown", sources: [source] });
}

for (const chain of chains) {
  if (typeof chain.chainId !== "number") continue;
  // A chain that never reached mainnet, or was replaced by another, is not
  // something a wallet should offer to sign on.
  const deprecated = Boolean(chain.status && chain.status !== "active") || Boolean(chain.parent?.type === "shard");
  const entry = chainEntry(chain.chainId);
  entry.meta = {
    name: chain.name,
    shortName: chain.shortName,
    chain: chain.chain,
    networkId: chain.networkId,
    nativeCurrency: chain.nativeCurrency,
    explorers: (chain.explorers ?? [])
      .filter((explorer) => explorer?.url?.startsWith("https://"))
      .map((explorer) => ({ name: explorer.name, url: explorer.url, standard: explorer.standard })),
    infoURL: chain.infoURL,
    status: chain.status ?? "active",
    deprecated,
    // Named as a testnet, and nothing else. Having a faucet was the obvious
    // second signal and it is wrong: Gnosis runs one for xDAI on mainnet, and
    // reading that as "testnet" demoted a chain people hold real value on.
    testnet: /testnet|test net|devnet|sepolia|goerli|holesky|hoodi|ropsten|rinkeby|kovan|mumbai|amoy|fuji|chapel|bepolia|minato|curtis|saigon|\btestnet\b/i.test(
      `${chain.name} ${chain.shortName ?? ""} ${chain.network ?? ""} ${chain.title ?? ""}`,
    ),
    parent: chain.parent?.chain,
    slip44: chain.slip44,
  };
  for (const url of chain.rpc ?? []) addEndpoint(chain.chainId, url, undefined, "chainid.network");
}

for (const [rawChainId, extra] of Object.entries(extraRpcs)) {
  const chainId = Number(rawChainId);
  if (!Number.isFinite(chainId)) continue;
  for (const rpc of extra.rpcs ?? []) {
    if (typeof rpc === "string") addEndpoint(chainId, rpc, undefined, "chainlist");
    else addEndpoint(chainId, rpc.url, rpc.tracking, "chainlist");
  }
}

const candidates = [...byChain.values()]
  .filter((entry) => entry.endpoints.size > 0)
  .map((entry) => ({
    chainId: entry.chainId,
    meta: entry.meta ?? null,
    endpoints: [...entry.endpoints.values()],
  }))
  .sort((a, b) => a.chainId - b.chainId);

const endpointCount = candidates.reduce((total, entry) => total + entry.endpoints.length, 0);
const unique = new Set(candidates.flatMap((entry) => entry.endpoints.map((e) => e.url)));

writeFileSync(join(outDir, "candidates.json"), `${JSON.stringify(candidates, null, 1)}\n`);
console.log(
  `chains with candidates: ${candidates.length}\n` +
    `chain/endpoint pairs:   ${endpointCount}\n` +
    `unique endpoint URLs:   ${unique.size}\n` +
    `registry chains seen:   ${chains.length}`,
);
