# @ekubo/tx-preview

A 5.20 MB transaction-preview model that runs entirely in the browser. Give it
the decoded reading of a transaction — the same clear-signing interpretation a
wallet already shows — and it answers a category, a risk band, and one sentence.

No server, no API key, no network call. The weights ship inside the `.wasm`.

## Install

```sh
npm install @ekubo/tx-preview
```

## Use

```js
import init, { Previewer } from "@ekubo/tx-preview";

await init();

// WebGPU when the browser has it, CPU when it does not. A missing adapter is
// an ordinary state, not an error.
const previewer = typeof Previewer.initWebGpu === "function" && navigator.gpu
  ? await Previewer.initWebGpu().catch(() => Previewer.initCpu())
  : Previewer.initCpu();

const preview = await previewer.preview([
  {
    description: "approve spender 0x1111…0582 for 1000.5 USDC (0xA0b8…eB48)",
    details: ["Spender: 0x1111…0582", "Amount: 1000.5 USDC"],
    warnings: [],
    target: "USDC (0xA0b8…eB48)",
    nativeValue: "0 ETH",
  },
]);

// { class: "approval", risk: "caution",
//   summary: "approve spender 0x1111…0582 for 1000.5 USDC (0xA0b8…eB48)" }
```

For a queue of waiting requests, use `previewAll` and hand it every plan at
once. Decoding is sequential in summary tokens but not in plans, with at most eight rows per dispatch. Long inputs use smaller batches; width-512 inputs run one at a time to bound attention memory.

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

The preview copies decoded actions and up to two model-selected labeled fields per call. Field labels keep a minimum output distinct from an amount being removed; contract addresses are not turned into recipients. The model can still misclassify a request or omit important fields. Show the authoritative decoded fields beside the machine-written summary.

`preview` and `previewAll` return Promises on both backends. GPU tensor readbacks are asynchronous; await them. Prefer running inference in a Worker so CPU computation does not block the page.

Inputs are bounded to 512 tokens and 48 slots per model invocation. A longer plan is processed call by call and the result identifies one call needing attention; review all calls. A single oversized call receives an explicit fallback. Warnings and undecoded calls cannot be downgraded to routine by the model.

## Input

`preview` takes an array of calls, one per step of the plan:

| field         | type       | meaning                                          |
| ------------- | ---------- | ------------------------------------------------ |
| `description` | `string?`  | the one-line decoded reading; omit if undecoded   |
| `details`     | `string[]` | labeled field lines from the interpretation       |
| `warnings`    | `string[]` | warnings the interpretation attached              |
| `target`      | `string`   | the contract, already labeled                     |
| `nativeValue` | `string`   | native value, already rendered with its currency  |

The model reads interpretations, never raw calldata. That is deliberate: it
bounds the values it can name to the ones your wallet already decided to show.

## Output

```ts
{ class: string; risk: "routine" | "caution" | "critical"; summary: string }
```

`class` is one of: `swap`, `approval`, `revocation`, `transfer`, `bridge`,
`supply`, `borrow`, `repay`, `withdraw`, `stake`, `unstake`, `claim`,
`liquidity_add`, `liquidity_remove`, `governance`, `nft`, `wrap_unwrap`,
`delegation`, `batch`, `unrecognized`.

Both are closed sets, so a forward pass cannot invent a category your UI has no
rendering for. `summary` is empty when nothing renderable came out; show the
class alone.

## Size

| build                    | `.wasm` |
| ------------------------ | ------- |
| CPU only       | 6.65 MB |
| WebGPU                   | 10.15 MB |

About 5.20 MB of either is the weights. Build with `--no-default-features` for
CPU-only browser compatibility and a smaller download. The default Cargo build
includes WebGPU and the CPU fallback. Latency depends on the device,
input length, and batch size; see the repository review measurements.

## Licence

FSL-1.1-MIT, same as the wallet it came from.
