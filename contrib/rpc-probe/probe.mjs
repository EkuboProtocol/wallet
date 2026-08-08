// Probe every candidate endpoint for the requests this wallet actually makes.
//
//   bun contrib/rpc-probe/probe.mjs <dir> [--limit N] [--chain ID] [--resume]
//
// Reads <dir>/candidates.json, appends one JSON object per endpoint to
// <dir>/probe-results.jsonl. Re-running with --resume skips endpoints already
// in that file, so a survey of several thousand endpoints can be interrupted.
//
// The battery is deliberately the wallet's own request set rather than a
// generic health check. An endpoint that answers eth_chainId and nothing else
// is useless here: simulation-gated signing needs eth_simulateV1 pinned to a
// block, with state overrides, and the balance and code reads that set it up.

import { readFileSync, appendFileSync, existsSync, readFileSync as read } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2] ?? ".";
const flags = process.argv.slice(3);
const flagValue = (name) => {
  const index = flags.indexOf(name);
  return index === -1 ? undefined : flags[index + 1];
};
const limit = flagValue("--limit") ? Number(flagValue("--limit")) : Infinity;
const onlyChain = flagValue("--chain") ? Number(flagValue("--chain")) : undefined;
const resume = flags.includes("--resume");
const skipRateLimit = flags.includes("--no-rate-limit");

const OUT = join(dir, "probe-results.jsonl");

// One request may not exceed this; a public endpoint that needs longer than
// this for eth_chainId is not a fallback worth ranking.
const REQUEST_TIMEOUT_MS = 8000;
// eth_simulateV1 is the expensive one and some honest endpoints are slow at it.
const SIMULATE_TIMEOUT_MS = 20000;
const GLOBAL_CONCURRENCY = 96;
const PER_HOST_CONCURRENCY = 2;

const MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11";
// The Calibur delegation designator this wallet installs when it simulates an
// atomic batch. Its exact shape is what makes the override probe meaningful.
const CALIBUR = "0x000000005c84F8Fd50b21CAC312528A64437030e";
const PROBE_ADDRESS = "0x000000000000000000000000000000000000dEaD";
const USER_AGENT = "ekubo-wallet-rpc-probe/1.0 (+https://github.com/EkuboProtocol/wallet-mcp-server)";

const candidates = JSON.parse(readFileSync(join(dir, "candidates.json"), "utf8"));

const done = new Set();
if (resume && existsSync(OUT)) {
  for (const line of read(OUT, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const record = JSON.parse(line);
      done.add(`${record.chainId}|${record.url}`);
    } catch {
      // A truncated trailing line just means that endpoint gets probed again.
    }
  }
}

const jobs = [];
for (const chain of candidates) {
  if (onlyChain !== undefined && chain.chainId !== onlyChain) continue;
  for (const endpoint of chain.endpoints) {
    if (done.has(`${chain.chainId}|${endpoint.url}`)) continue;
    jobs.push({ chainId: chain.chainId, ...endpoint });
  }
}
jobs.length = Math.min(jobs.length, limit === Infinity ? jobs.length : limit);

let nextRequestId = 1;

async function rpc(url, method, params, timeoutMs = REQUEST_TIMEOUT_MS) {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({ jsonrpc: "2.0", id: nextRequestId++, method, params }),
      signal: controller.signal,
    });
    const elapsed = Math.round(performance.now() - started);
    const text = await response.text();
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        elapsed,
        error: `http ${response.status}`,
        retryAfter: response.headers.get("retry-after") ?? undefined,
        body: text.slice(0, 200),
      };
    }
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      return { ok: false, status: response.status, elapsed, error: "non-JSON response" };
    }
    if (payload.error) {
      return {
        ok: false,
        status: response.status,
        elapsed,
        rpcError: {
          code: payload.error.code,
          message: String(payload.error.message ?? "").slice(0, 200),
        },
      };
    }
    return { ok: true, status: response.status, elapsed, result: payload.result };
  } catch (error) {
    return {
      ok: false,
      elapsed: Math.round(performance.now() - started),
      error: String(error?.message ?? error).slice(0, 200),
    };
  } finally {
    clearTimeout(timer);
  }
}

function isRateLimited(response) {
  if (response.ok) return false;
  if (response.status === 429 || response.status === 503) return true;
  if (response.rpcError?.code === -32005) return true;
  return /rate limit|too many requests|quota|throttl/i.test(
    `${response.rpcError?.message ?? ""} ${response.body ?? ""}`,
  );
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A public endpoint refusing a burst says nothing about whether it implements
// a method. Backing off and asking once more is the difference between
// measuring capability and measuring how fast this survey ran.
async function rpcPatient(url, method, params, timeoutMs = REQUEST_TIMEOUT_MS) {
  let response = await rpc(url, method, params, timeoutMs);
  for (let attempt = 0; attempt < 2 && isRateLimited(response); attempt += 1) {
    await sleep(1500 * (attempt + 1));
    response = await rpc(url, method, params, timeoutMs);
  }
  return response;
}

// The wallet reads a handful of values at once, but firing all of them at a
// rate-limited endpoint measures the survey rather than the endpoint, so the
// battery runs in small groups.
async function inGroups(size, thunks) {
  const results = [];
  for (let index = 0; index < thunks.length; index += size) {
    results.push(...(await Promise.all(thunks.slice(index, index + size).map((run) => run()))));
  }
  return results;
}

async function rpcBatch(url, calls) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify(
        calls.map((call) => ({ jsonrpc: "2.0", id: nextRequestId++, ...call })),
      ),
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const payload = await response.json();
    return Array.isArray(payload) && payload.length === calls.length;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

const hex = (value) => `0x${value.toString(16)}`;

// The wallet's own eth_simulateV1 payload: one block per replayed plan, the
// 7702 designator installed by a state override, transfers traced, validation
// off. Anything that answers this answers what simulation-gated signing sends.
function simulatePayload({ withOverride, blocks, chainId }) {
  const call = {
    from: PROBE_ADDRESS,
    to: PROBE_ADDRESS,
    value: "0x0",
    gas: "0x186a0",
    input: "0x",
    chainId: hex(chainId),
  };
  const blockStateCalls = [];
  for (let index = 0; index < blocks; index += 1) {
    const block = { calls: [call] };
    if (withOverride && index === 0) {
      block.stateOverrides = {
        [PROBE_ADDRESS]: { code: `0xef0100${CALIBUR.slice(2).toLowerCase()}` },
      };
    }
    blockStateCalls.push(block);
  }
  return {
    blockStateCalls,
    traceTransfers: true,
    validation: false,
    returnFullTransactions: false,
  };
}

function simulateOutcome(response) {
  if (response.ok) {
    const blocks = Array.isArray(response.result) ? response.result.length : 0;
    return { supported: blocks > 0, blocks, elapsed: response.elapsed };
  }
  const message = (response.rpcError?.message ?? response.error ?? "").toLowerCase();
  const code = response.rpcError?.code;
  // -32601 is the standard "method not found"; several gateways instead answer
  // with a plain 4xx or a prose message, so the text is checked too.
  const unsupported =
    code === -32601 ||
    code === -32004 ||
    message.includes("method not found") ||
    message.includes("not supported") ||
    message.includes("unsupported method") ||
    message.includes("does not exist") ||
    message.includes("not available");
  return {
    supported: false,
    unsupported,
    elapsed: response.elapsed,
    reason: (response.rpcError?.message ?? response.error ?? "unknown").slice(0, 160),
    code,
  };
}

// A burst tells us what a wallet doing four or five reads at once will meet.
// Public endpoints commonly allow a low steady rate and reject bursts, and a
// fallback that fails the moment the wallet parallelises is not a fallback.
async function measureBurst(url) {
  const size = 10;
  const started = performance.now();
  const responses = await Promise.all(
    Array.from({ length: size }, () => rpc(url, "eth_chainId", [])),
  );
  const succeeded = responses.filter((response) => response.ok).length;
  const rateLimited = responses.filter(
    (response) =>
      response.status === 429 ||
      response.rpcError?.code === -32005 ||
      /rate|limit|quota|too many/i.test(response.rpcError?.message ?? ""),
  ).length;
  const latencies = responses.filter((r) => r.ok).map((r) => r.elapsed).sort((a, b) => a - b);
  return {
    size,
    succeeded,
    rateLimited,
    wallMs: Math.round(performance.now() - started),
    medianMs: latencies.length ? latencies[Math.floor(latencies.length / 2)] : null,
  };
}

async function probe(job) {
  const record = {
    chainId: job.chainId,
    url: job.url,
    tracking: job.tracking,
    sources: job.sources,
    probedAt: new Date().toISOString(),
  };

  const chainIdResponse = await rpcPatient(job.url, "eth_chainId", []);
  record.reachable = chainIdResponse.ok;
  record.chainIdLatencyMs = chainIdResponse.elapsed;
  if (!chainIdResponse.ok) {
    record.failure = chainIdResponse.rpcError?.message ?? chainIdResponse.error;
    record.httpStatus = chainIdResponse.status;
    return record;
  }
  const observed = Number(chainIdResponse.result);
  record.observedChainId = Number.isFinite(observed) ? observed : null;
  if (record.observedChainId !== job.chainId) {
    record.wrongChain = true;
    return record;
  }

  const blockNumberResponse = await rpcPatient(job.url, "eth_blockNumber", []);
  if (!blockNumberResponse.ok) {
    record.failure = blockNumberResponse.rpcError?.message ?? blockNumberResponse.error;
    return record;
  }
  const head = Number(blockNumberResponse.result);
  record.blockNumber = head;

  const pinned = hex(head);
  const [balance, code, nonce, block, multicallCode, receipt] = await inGroups(3, [
    () => rpcPatient(job.url, "eth_getBalance", [PROBE_ADDRESS, pinned]),
    () => rpcPatient(job.url, "eth_getCode", [PROBE_ADDRESS, pinned]),
    () => rpcPatient(job.url, "eth_getTransactionCount", [PROBE_ADDRESS, "latest"]),
    () => rpcPatient(job.url, "eth_getBlockByNumber", ["latest", false]),
    () => rpcPatient(job.url, "eth_getCode", [MULTICALL3, "latest"]),
    () =>
      rpcPatient(job.url, "eth_getTransactionReceipt", [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
      ]),
  ]);
  record.methods = {
    // Pinned reads at the head block are how simulation sets itself up; an
    // endpoint that only answers "latest" breaks that path.
    getBalancePinned: balance.ok,
    getCodePinned: code.ok,
    getTransactionCount: nonce.ok,
    getBlockByNumber: block.ok && block.result !== null,
    getTransactionReceipt: receipt.ok,
  };
  record.multicall3 =
    multicallCode.ok && typeof multicallCode.result === "string" && multicallCode.result.length > 4;

  const [feeHistory, gasPrice, priorityFee, estimateGas, sendRaw] = await inGroups(3, [
    () => rpcPatient(job.url, "eth_feeHistory", ["0x1", "latest", []]),
    () => rpcPatient(job.url, "eth_gasPrice", []),
    () => rpcPatient(job.url, "eth_maxPriorityFeePerGas", []),
    () =>
      rpcPatient(job.url, "eth_estimateGas", [
        { from: PROBE_ADDRESS, to: PROBE_ADDRESS, value: "0x0" },
      ]),
    // Deliberately malformed: a node that has the method answers "invalid
    // RLP", one that does not answers "method not found". Nothing is
    // broadcast either way.
    () => rpcPatient(job.url, "eth_sendRawTransaction", ["0x"]),
  ]);
  record.methods.feeHistory = feeHistory.ok;
  record.methods.gasPrice = gasPrice.ok;
  record.methods.maxPriorityFeePerGas = priorityFee.ok;
  record.methods.estimateGas = estimateGas.ok;
  // Support has to be something the node asserted, not something no one
  // denied. A JSON-RPC error object is the node answering: it read the
  // request, reached the method, and refused the payload — which is the
  // "invalid RLP" this deliberately malformed call is fishing for. A timeout,
  // a refused connection, an HTTP 500, and a body that is not JSON all arrive
  // with no `rpcError` at all, and reading those as support is how an
  // endpoint that cannot broadcast — or cannot be reached — collects the
  // largest bonus the selector awards, and leads the failover list a
  // cancellation depends on.
  const sendRawAnswered =
    sendRaw.rpcError !== undefined &&
    !(
      sendRaw.rpcError.code === -32601 ||
      /method not found/i.test(sendRaw.rpcError.message ?? "")
    );
  record.methods.sendRawTransaction = sendRaw.ok || sendRawAnswered;

  if (record.multicall3) {
    const call = await rpcPatient(job.url, "eth_call", [
      { to: MULTICALL3, input: "0x42cbb15c" },
      "latest",
    ]);
    record.methods.call = call.ok;
  } else {
    const call = await rpcPatient(job.url, "eth_call", [
      { to: PROBE_ADDRESS, input: "0x" },
      "latest",
    ]);
    record.methods.call = call.ok;
  }

  record.batchRequests = await rpcBatch(job.url, [
    { method: "eth_chainId", params: [] },
    { method: "eth_blockNumber", params: [] },
  ]);

  // Historical depth: the transaction view diffs the balance across a mined
  // block, which needs the parent block's state; deeper history is a bonus.
  if (head > 4096) {
    const [recent, deep] = await inGroups(2, [
      () => rpcPatient(job.url, "eth_getBalance", [PROBE_ADDRESS, hex(head - 1)]),
      () => rpcPatient(job.url, "eth_getBalance", [PROBE_ADDRESS, hex(head - 4096)]),
    ]);
    record.historicalState = { parentBlock: recent.ok, deep4096: deep.ok };
  }

  // The capability that decides whether this wallet can sign at all: one
  // block, pinned to the head, with the 7702 designator installed by a state
  // override. That is exactly what a one-shot simulation sends.
  const signing = await rpcPatient(
    job.url,
    "eth_simulateV1",
    [simulatePayload({ withOverride: true, blocks: 1, chainId: job.chainId }), pinned],
    SIMULATE_TIMEOUT_MS,
  );
  record.simulate = simulateOutcome(signing);

  if (record.simulate.supported) {
    // A second block is fork replay, and several chains answer the one-block
    // form while rejecting the two-block one ("unknown ancestor", "failed to
    // get parent header"). That costs forks, not signing, so it is recorded
    // separately instead of disqualifying the endpoint.
    const fork = await rpcPatient(
      job.url,
      "eth_simulateV1",
      [simulatePayload({ withOverride: true, blocks: 2, chainId: job.chainId }), pinned],
      SIMULATE_TIMEOUT_MS,
    );
    record.simulateFork = simulateOutcome(fork);
  } else {
    // Narrow down which part it refused, because "no eth_simulateV1 at all",
    // "no state overrides", and "no pinned block" are different defects and
    // only the first is hopeless.
    const plain = await rpcPatient(
      job.url,
      "eth_simulateV1",
      [simulatePayload({ withOverride: false, blocks: 1, chainId: job.chainId }), "latest"],
      SIMULATE_TIMEOUT_MS,
    );
    record.simulatePlain = simulateOutcome(plain);
    if (plain.ok) {
      const pinnedPlain = await rpcPatient(
        job.url,
        "eth_simulateV1",
        [simulatePayload({ withOverride: false, blocks: 1, chainId: job.chainId }), pinned],
        SIMULATE_TIMEOUT_MS,
      );
      record.simulatePinned = simulateOutcome(pinnedPlain);
      const overrideOnly = await rpcPatient(
        job.url,
        "eth_simulateV1",
        [simulatePayload({ withOverride: true, blocks: 1, chainId: job.chainId }), "latest"],
        SIMULATE_TIMEOUT_MS,
      );
      record.simulateOverride = simulateOutcome(overrideOnly);
    }
  }

  if (!skipRateLimit && (record.simulate.supported || record.simulatePlain?.supported)) {
    record.burst = await measureBurst(job.url);
  }

  return record;
}

// Endpoints are shuffled by host so the run does not hammer one provider's
// hundred chains back to back, and a per-host gate keeps concurrency polite
// even when it does.
const hostGates = new Map();
async function withHostGate(url, work) {
  const host = new URL(url).hostname;
  let gate = hostGates.get(host);
  if (!gate) {
    gate = { active: 0, queue: [] };
    hostGates.set(host, gate);
  }
  if (gate.active >= PER_HOST_CONCURRENCY) {
    await new Promise((resolve) => gate.queue.push(resolve));
  }
  gate.active += 1;
  try {
    return await work();
  } finally {
    gate.active -= 1;
    const next = gate.queue.shift();
    if (next) next();
  }
}

function interleaveByHost(list) {
  const byHost = new Map();
  for (const job of list) {
    const host = new URL(job.url).hostname;
    if (!byHost.has(host)) byHost.set(host, []);
    byHost.get(host).push(job);
  }
  const buckets = [...byHost.values()];
  const ordered = [];
  let index = 0;
  while (ordered.length < list.length) {
    let placed = false;
    for (const bucket of buckets) {
      if (index < bucket.length) {
        ordered.push(bucket[index]);
        placed = true;
      }
    }
    if (!placed) break;
    index += 1;
  }
  return ordered;
}

const ordered = interleaveByHost(jobs);
console.error(
  `probing ${ordered.length} endpoints across ${new Set(ordered.map((j) => j.chainId)).size} chains`,
);

let completed = 0;
let simulateCount = 0;
let cursor = 0;
const started = performance.now();

async function worker() {
  while (cursor < ordered.length) {
    const job = ordered[cursor++];
    let record;
    try {
      record = await withHostGate(job.url, () => probe(job));
    } catch (error) {
      record = {
        chainId: job.chainId,
        url: job.url,
        probedAt: new Date().toISOString(),
        reachable: false,
        failure: `probe crashed: ${String(error?.message ?? error).slice(0, 160)}`,
      };
    }
    appendFileSync(OUT, `${JSON.stringify(record)}\n`);
    completed += 1;
    if (record.simulate?.supported) simulateCount += 1;
    if (completed % 100 === 0) {
      const rate = completed / ((performance.now() - started) / 1000);
      const remaining = Math.round((ordered.length - completed) / rate);
      console.error(
        `${completed}/${ordered.length} probed · ${simulateCount} simulate-capable · ` +
          `${rate.toFixed(1)}/s · ~${Math.floor(remaining / 60)}m${remaining % 60}s left`,
      );
    }
  }
}

await Promise.all(Array.from({ length: GLOBAL_CONCURRENCY }, worker));
console.error(`done: ${completed} probed, ${simulateCount} simulate-capable`);
