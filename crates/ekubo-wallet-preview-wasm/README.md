# @ekubo/tx-preview

A 5.21 MB transaction-preview model that runs entirely in the browser. Give it
the decoded reading of a transaction — the same clear-signing interpretation a
wallet already shows — and it answers a category, a risk band, and a whole-plan summary of at most 100 characters.

No server, no API key, no network call. The weights ship inside the `.wasm`.

## Install

```sh
npm install @ekubo/tx-preview
```

## Use

```js
import init, { Previewer } from "@ekubo/tx-preview";

await init();

// CPU gives fast startup for the small card model. Run this in a Worker
// when integrating with a UI. WebGPU remains available explicitly.
const previewer = Previewer.initCpu();

const preview = await previewer.preview([
  {
    description: "approve spender 0x1111111254EEB25477B68fb85Ed929f73A960582 for 1000.5 USDC (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)",
    details: ["Spender: 0x1111111254EEB25477B68fb85Ed929f73A960582", "Amount: 1000.5 USDC"],
    warnings: [],
    target: "USDC (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)",
    nativeValue: "0 ETH",
  },
]);

// { class: "approval", risk: "caution",
//   summary: "Approve 1000.5 USDC to 0x111111…960582" }
```

For a queue of waiting requests, use `previewAll` and hand it every plan at
once. Card generation uses call encoding and a whole-plan salience model, with no autoregressive text loop and at most eight rows per dispatch. Long inputs use smaller batches; width-512 inputs run one at a time to bound attention memory.

```js
const previews = await previewer.previewAll([planA, planB, planC]);
```

## What it is for, and what it is not

It is for triage. Somebody with a queue of pending requests should be able to
tell a routine swap from an unlimited approval without opening each one.

It is **not** a security control and must not be used as one:

- Do not gate signing on it. The class and risk are advisory.
- Do not show it instead of the decoded fields. Show it *beside* them, marked
  as machine-written. The decoded reading is what a person is deciding on.
- Do not treat `risk: "critical"` as a block or `risk: "routine"` as an
  all-clear.

## Value provenance and limits

The preview summarizes ordered actions under a 100-character cap. A learned whole-plan ranker allocates detail to the main intent. Field roles, exact versus unlimited permissions, distinct recipients and call order constrain the wording. The model can still misclassify a request or omit useful detail; keep the full decoded review beside it.

An optional `evidence` object adds `{ chainId, from, to, calldata, abi }`; each ABI candidate is `{ signature, contractMatch, arguments }`, with `arguments` as name/value string pairs. Only supply directory candidates when there is no decoded reading, after validating the selector and an exact canonical ABI round trip. The wallet core bundles the offline directory; this standalone model Wasm does not. Distinguish a contract-bound ABI from a selector-only guess. Raw data is retained while compact typed evidence feeds the encoder. Unknown calls stay explicit even when a selector suggests a possible action.

`preview` and `previewAll` return Promises on both backends. GPU tensor readbacks are asynchronous; await them. Prefer running inference in a Worker so CPU computation does not block the page.

Each neural input is bounded to 512 tokens and 48 slots. A per-plan attention-work budget bounds classification cost; all calls still participate in ordered source-based rendering and warning checks. Oversized inputs retain their decoded action, with category abstention and conservative risk. Warnings and undecoded calls cannot be downgraded to routine by the model.

## Input

`preview` takes an array of calls, one per step of the plan:

| field         | type       | meaning                                          |
| ------------- | ---------- | ------------------------------------------------ |
| `description` | `string?`  | the one-line decoded reading; omit if undecoded   |
| `details`     | `string[]` | labeled field lines from the interpretation       |
| `warnings`    | `string[]` | warnings the interpretation attached              |
| `target`      | `string`   | the contract, already labeled                     |
| `nativeValue` | `string`   | native value, already rendered with its currency  |

The call-array form remains supported. To supply exact-plan simulation context, pass `{ calls, simulation: { sent: ["1 ETH"], received: ["2400 USDG"], from_logs: false } }`; each member of `previewAll` accepts either form. The caller must bind this display-only context to the actual wallet and plan, use trusted token identities/units, and distinguish measured balances from transfer-log estimates. `evidence.tokens` supplies trusted address/label pairs found in the call.

The model reads a compact projection of the decoded interpretation and optional execution evidence. Concrete displayed values remain bound to the supplied fields.

## Output

```ts
{
  class: string;
  risk: "routine" | "caution" | "critical";
  summary: string;
  basis: "interpretation" | "simulation" | "simulationTransfers" | "inferredIntent";
}
```

`class` is one of: `swap`, `approval`, `revocation`, `transfer`, `bridge`,
`supply`, `borrow`, `repay`, `withdraw`, `stake`, `unstake`, `claim`,
`liquidity_add`, `liquidity_remove`, `governance`, `nft`, `wrap_unwrap`,
`delegation`, `batch`, `unrecognized`.

`basis` belongs in secondary metadata, not as a headline prefix. An inferred intent is advisory; it does not establish a contract match or lower the unknown-call risk floor.

The class and risk are closed sets, so a forward pass cannot invent a category your UI has no
rendering for. `summary` is capped at 100 characters, including incomplete-plan fallbacks. Handle initialization or inference errors by retaining the decoded review.

## Size

| build                    | `.wasm` |
| ------------------------ | ------- |
| CPU only       | 6.61 MB |
| WebGPU                   | 9.95 MB |

About 5.21 MB of either is the weights. Build with `--no-default-features` for
CPU-only browser compatibility and a smaller download. The default Cargo build
includes WebGPU and the CPU fallback. Latency depends on the device,
input length, and batch size; see the repository review measurements.

## Licence

FSL-1.1-MIT, same as the wallet it came from.
