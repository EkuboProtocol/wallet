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
const DEFAULT_TESTNETS = new Set([
  10200, // Gnosis Chiado
  46630, // Robinhood Chain Testnet
  80069, // Berachain Bepolia
  84532, // Base Sepolia
  421614, // Arbitrum Sepolia
  763373, // Ink Sepolia
  11155420, // OP Sepolia
]);
const curated = JSON.parse(readFileSync(new URL("./curated.json", import.meta.url), "utf8")).chains;

const results = readFileSync(join(dir, "probe-results.jsonl"), "utf8")
  .split("\n")
  .filter((line) => line.trim())
  .map((line) => JSON.parse(line));

const probes = new Map();
for (const record of results) probes.set(`${record.chainId}|${record.url}`, record);

const MAX_ENDPOINTS_PER_CHAIN = 6;

const STALE_BLOCK_LAG = 256;
const COMPARABLE_WINDOW_MS = 120_000;

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
  if (record.simulate?.supported) points += 1000;
  if (record.simulateFork?.supported) points += 120;
  if (record.methods?.sendRawTransaction) points += 90;
  if (record.multicall3) points += 60;
  if (record.methods?.feeHistory || record.methods?.maxPriorityFeePerGas) points += 40;
  if (record.methods?.estimateGas) points += 20;
  if (record.historicalState?.parentBlock) points += 25;
  if (record.historicalState?.deep4096) points += 10;
  if (record.batchRequests) points += 10;
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
  // The collector works this out and says why: a chain that never reached
  // mainnet, or that another chain replaced, is not one a wallet should offer
  // to sign on. Nothing here read it, so the classification was computed,
  // written to the candidate file, and dropped — and the registry shipped
  // "Omni Testnet (Deprecated)" and the Harmony shards with the same
  // provenance as every live chain beside them. Abandoned infrastructure is
  // exactly what goes stale or changes hands.
  if (meta.deprecated) continue;
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
    default:
      ALCHEMY_MAINNETS.has(chain.chainId) || DEFAULT_TESTNETS.has(chain.chainId),
    testnet: Boolean(meta.testnet),
    native_currency: meta.nativeCurrency
      ? {
          name: meta.nativeCurrency.name,
          symbol: meta.nativeCurrency.symbol,
          decimals: meta.nativeCurrency.decimals,
        }
      : null,
    block_explorer_url: overlay.block_explorer_url ?? meta.explorers?.[0]?.url ?? null,
    documentation_url:
      overlay.documentation_url ??
      (meta.infoURL?.startsWith("https://") ? meta.infoURL : null),
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
  alchemyCovered: chains.filter(
    (chain) => chain.default && !chain.testnet,
  ).length,
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
