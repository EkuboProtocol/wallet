// Turn probe results into the vendored network registry the wallet ships.
//
//   bun contrib/rpc-probe/select.mjs <probe-dir> [--out crates/ekubo-wallet-core/networks.json]
//
// Reads <probe-dir>/candidates.json and <probe-dir>/probe-results.jsonl and
// writes one entry per chain that has at least one endpoint this wallet can
// actually use, each carrying its endpoints in the order failover should try
// them.
//
// Ranking is not "fastest first". The endpoint list exists so that a chain
// keeps working when a provider does not, so the ordering optimises for the
// list surviving as a whole: capability first, then operator diversity, then
// speed. Two endpoints run by the same operator are one endpoint for the
// purpose of an outage.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2] ?? ".";
const flags = process.argv.slice(3);
const outIndex = flags.indexOf("--out");
const outPath =
  outIndex === -1
    ? join(dir, "networks.json")
    : flags[outIndex + 1];

const candidates = JSON.parse(readFileSync(join(dir, "candidates.json"), "utf8"));
const alchemy = JSON.parse(
  readFileSync(new URL("./alchemy-chains.json", import.meta.url), "utf8"),
);
const ALCHEMY_MAINNETS = new Set(Object.keys(alchemy.mainnets).map(Number));
const curated = JSON.parse(readFileSync(new URL("./curated.json", import.meta.url), "utf8")).chains;

const results = readFileSync(join(dir, "probe-results.jsonl"), "utf8")
  .split("\n")
  .filter((line) => line.trim())
  .map((line) => JSON.parse(line));

// The last probe of an endpoint wins, so a re-run refines rather than
// duplicates.
const probes = new Map();
for (const record of results) probes.set(`${record.chainId}|${record.url}`, record);

/// Endpoints one chain may ship with. `MAX_NETWORK_RPC_URLS` in config.rs is
/// the hard cap; this leaves room for an owner to add their own without
/// having to remove one of ours first.
const MAX_ENDPOINTS_PER_CHAIN = 6;

// An endpoint whose head is far behind its peers is serving stale state, and
// a wallet that reads a balance there sees a balance that is no longer true.
// Compared only against endpoints probed at a similar moment, because the
// survey itself takes minutes and chains produce blocks throughout.
const STALE_BLOCK_LAG = 256;
const COMPARABLE_WINDOW_MS = 120_000;

// Operator identity, approximated by the registrable domain. Four mevblocker
// paths are one operator having one bad day, and a list of them is a list of
// one endpoint.
function operator(url) {
  const { hostname } = new URL(url);
  const parts = hostname.split(".");
  return parts.slice(-2).join(".");
}

function usable(record) {
  if (!record.reachable || record.wrongChain) return false;
  if (record.observedChainId !== record.chainId) return false;
  const methods = record.methods;
  if (!methods) return false;
  // Every one of these is on the path to a signature: the head block and the
  // pinned code and balance reads set up a simulation, and eth_call backs
  // every token balance and allowance the approval screen shows.
  return Boolean(
    methods.getBalancePinned &&
      methods.getCodePinned &&
      methods.getTransactionCount &&
      methods.getBlockByNumber &&
      methods.call,
  );
}

function burstHealth(record) {
  if (!record.burst) return 0.5;
  const { succeeded, size } = record.burst;
  return size ? succeeded / size : 0.5;
}

function score(record) {
  let points = 0;
  // Simulation is the capability that decides whether this wallet can sign on
  // a chain at all, so it outweighs everything else combined.
  if (record.simulate?.supported) points += 1000;
  if (record.simulateFork?.supported) points += 120;
  // Broadcasting through an endpoint that only reads is a transaction that
  // never reaches a mempool.
  if (record.methods?.sendRawTransaction) points += 90;
  // Balance and allowance reads batch through Multicall3; without it they
  // fan out into one request per token against a rate-limited endpoint.
  if (record.multicall3) points += 60;
  if (record.methods?.feeHistory || record.methods?.maxPriorityFeePerGas) points += 40;
  if (record.methods?.estimateGas) points += 20;
  if (record.historicalState?.parentBlock) points += 25;
  if (record.historicalState?.deep4096) points += 10;
  if (record.batchRequests) points += 10;
  // A provider that says it does not log is preferable to one that says it
  // does, and both are preferable to one that says nothing.
  if (record.tracking === "none") points += 45;
  else if (record.tracking === "limited") points += 15;
  else if (record.tracking === "yes") points -= 25;
  points += Math.round(burstHealth(record) * 80);
  const latency = record.burst?.medianMs ?? record.chainIdLatencyMs ?? 5000;
  points += Math.max(0, Math.round((3000 - Math.min(latency, 3000)) / 60));
  return points;
}

function freshnessFiltered(records) {
  const withHeads = records.filter((record) => typeof record.blockNumber === "number");
  if (withHeads.length < 2) return records;
  const stale = new Set();
  for (const record of withHeads) {
    const at = Date.parse(record.probedAt);
    const peers = withHeads.filter(
      (other) => Math.abs(Date.parse(other.probedAt) - at) <= COMPARABLE_WINDOW_MS,
    );
    const best = Math.max(...peers.map((peer) => peer.blockNumber));
    if (best - record.blockNumber > STALE_BLOCK_LAG) stale.add(record.url);
  }
  const kept = records.filter((record) => !stale.has(record.url));
  // Never let the freshness check empty a chain: an entire chain reading as
  // stale means the measurement is wrong, not that the chain is gone.
  return kept.length ? kept : records;
}

// Interleave by operator so the first two entries are never the same provider,
// while keeping the strongest endpoint first.
function diversify(ranked) {
  const byOperator = new Map();
  for (const record of ranked) {
    const key = operator(record.url);
    if (!byOperator.has(key)) byOperator.set(key, []);
    byOperator.get(key).push(record);
  }
  const groups = [...byOperator.values()].sort((a, b) => score(b[0]) - score(a[0]));
  const ordered = [];
  for (let round = 0; ordered.length < ranked.length; round += 1) {
    let placed = false;
    for (const group of groups) {
      if (round < group.length) {
        ordered.push(group[round]);
        placed = true;
      }
    }
    if (!placed) break;
  }
  return ordered;
}

function identifier(text) {
  return text
    .toLowerCase()
    .replace(/\bmainnet\b/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
}

const chains = [];
for (const chain of candidates) {
  const meta = chain.meta;
  if (!meta) continue;
  const records = chain.endpoints
    .map((endpoint) => probes.get(`${chain.chainId}|${endpoint.url}`))
    .filter(Boolean)
    .filter(usable);
  if (!records.length) continue;

  const fresh = freshnessFiltered(records);
  const ranked = [...fresh].sort((a, b) => score(b) - score(a));
  // Rank first, then interleave operators, then cut. Cutting first would
  // throw away the diversity the interleave exists to create.
  let chosen = diversify(ranked).slice(0, MAX_ENDPOINTS_PER_CHAIN);
  if (!chosen.length) continue;

  const overlay = curated[String(chain.chainId)] ?? {};
  // The chain's own endpoint leads when it is healthy — but never at the cost
  // of simulation. Putting a node that has no eth_simulateV1 first would make
  // every signature on that chain pay a failed request before failover found
  // one that works.
  if (overlay.rpc_first) {
    const pinnedUrl = new URL(overlay.rpc_first).toString();
    const pin = ranked.find((record) => record.url === pinnedUrl);
    const chainSimulates = ranked.some((record) => record.simulate?.supported);
    if (pin && (pin.simulate?.supported || !chainSimulates)) {
      chosen = [pin, ...chosen.filter((record) => record.url !== pinnedUrl)].slice(
        0,
        MAX_ENDPOINTS_PER_CHAIN,
      );
    }
  }

  const simulate = chosen.filter((record) => record.simulate?.supported);
  chains.push({
    chain_id: chain.chainId,
    name:
      overlay.name ??
      identifier(meta.shortName || meta.name || `chain-${chain.chainId}`) ??
      `chain-${chain.chainId}`,
    display_name: overlay.display_name ?? meta.name,
    aliases: overlay.aliases ?? [],
    // A default is a network the wallet configures for an owner who never
    // asked for it, so the bar is higher than "it answered a probe": it is
    // the set Alchemy serves, which is the closest available proxy for the
    // chains people actually hold value on.
    default: ALCHEMY_MAINNETS.has(chain.chainId),
    testnet: Boolean(meta.testnet),
    native_currency: meta.nativeCurrency
      ? {
          name: meta.nativeCurrency.name,
          symbol: meta.nativeCurrency.symbol,
          decimals: meta.nativeCurrency.decimals,
        }
      : null,
    max_gas_limit: overlay.max_gas_limit ?? null,
    block_explorer_url: meta.explorers?.[0]?.url ?? null,
    documentation_url:
      overlay.documentation_url ??
      (meta.infoURL?.startsWith("https://") ? meta.infoURL : null),
    // What the survey observed, kept beside the endpoints so a reader can see
    // why a chain is or is not usable for signing without re-running the probe.
    simulate_endpoints: simulate.length,
    fork_endpoints: chosen.filter((record) => record.simulateFork?.supported).length,
    rpc_urls: chosen.map((record) => record.url),
  });
}

chains.sort((a, b) => a.chain_id - b.chain_id);

// Names and aliases are how an owner and an MCP caller address a network, so
// the whole registry has to agree on them. A derived name that collides with
// a curated one — or with another derived one — is disambiguated by chain ID
// rather than silently shadowing it, and defaults win the bare name because
// they are the ones anybody types.
const claimed = new Map();
for (const chain of chains.filter((entry) => entry.default)) {
  claimed.set(chain.name, chain.chain_id);
  for (const alias of chain.aliases) claimed.set(alias, chain.chain_id);
}
for (const chain of chains) {
  if (chain.default) continue;
  if (claimed.has(chain.name)) chain.name = `${chain.name}-${chain.chain_id}`;
  claimed.set(chain.name, chain.chain_id);
  chain.aliases = chain.aliases.filter((alias) => !claimed.has(alias));
  for (const alias of chain.aliases) claimed.set(alias, chain.chain_id);
}
const invalid = chains.filter((chain) => !/^[A-Za-z0-9_-]{1,64}$/.test(chain.name));
if (invalid.length) {
  throw new Error(
    `derived names are not valid network identifiers: ${invalid
      .map((chain) => `${chain.chain_id}=${JSON.stringify(chain.name)}`)
      .join(", ")}`,
  );
}

const stats = {
  chains: chains.length,
  defaults: chains.filter((chain) => chain.default).length,
  chainsWithSimulation: chains.filter((chain) => chain.simulate_endpoints > 0).length,
  endpoints: chains.reduce((total, chain) => total + chain.rpc_urls.length, 0),
  alchemyCovered: chains.filter((chain) => chain.default).length,
  alchemyTotal: ALCHEMY_MAINNETS.size,
};

writeFileSync(
  outPath,
  `${JSON.stringify({ generated_from: "chainlist.org (chainid.network + DefiLlama/chainlist), probed by contrib/rpc-probe", chains }, null, 1)}\n`,
);
console.log(JSON.stringify(stats, null, 2));
console.log(`wrote ${outPath}`);

const missing = [...ALCHEMY_MAINNETS].filter(
  (id) => !chains.some((chain) => chain.chain_id === id),
);
if (missing.length) console.log(`Alchemy mainnets with no usable endpoint: ${missing.join(", ")}`);
const noSimulation = chains.filter((chain) => chain.default && chain.simulate_endpoints === 0);
if (noSimulation.length) {
  console.log(
    `Alchemy mainnets with no eth_simulateV1 endpoint: ${noSimulation
      .map((chain) => `${chain.chain_id} (${chain.display_name})`)
      .join(", ")}`,
  );
}
