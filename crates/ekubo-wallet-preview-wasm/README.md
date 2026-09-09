# @ekubo/tx-preview

A 2.4 MB transaction-preview model that runs entirely in the browser. Give it
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
const previewer = await Previewer.initWebGpu().catch(() => Previewer.initCpu());

const preview = previewer.preview([
  {
    description: "approve spender 0x1111…0582 for 1000.5 USDC (0xA0b8…eB48)",
    details: ["Spender: 0x1111…0582", "Amount: 1000.5 USDC"],
    warnings: [],
    target: "USDC (0xA0b8…eB48)",
    nativeValue: "0 ETH",
  },
]);

// { class: "approval", risk: "caution",
//   summary: "approve usdc: let 0x1111…0582 spend 1000.5 USDC (0xA0b8…eB48)" }
```

For a queue of waiting requests, use `previewAll` and hand it every plan at
once. Decoding is sequential in summary tokens but not in plans, so forty plans
cost about what one does.

```js
const previews = previewer.previewAll([planA, planB, planC]);
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

## Why a generated sentence is safe here

A language model writing prose next to a signing decision can commit one
failure that matters: a fluent sentence naming the wrong amount. This model is
never given the chance.

Every value in the input — amounts, addresses, token labels — is lifted out
into a numbered slot before tokenization. The model sees the value's *kind*,
never its digits. It emits words and slot *references*, and rendering
substitutes each reference with the original text verbatim. The decoder cannot
produce a slot reference from its vocabulary at all: it scores input positions,
and every position not holding a value is masked out.

So there is no path from the weights to a digit. The only thing a forward pass
chooses is which already-decoded value to name. A wrong choice is a visibly
wrong sentence next to the authoritative fields, not a plausible forgery. As a
last check, a rendered summary containing a number or address that is not in
the plan is dropped, and the category is returned alone.

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
| CPU only (default)       | ~4.2 MB |
| WebGPU                   | ~8.4 MB |

2.43 MB of either is the weights. The CPU build is the default because 1.2M
parameters over a forty-token sequence is a few milliseconds either way, and
half the download.

## Licence

FSL-1.1-MIT, same as the wallet it came from.
