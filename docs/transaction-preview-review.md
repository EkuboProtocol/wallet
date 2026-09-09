# Transaction preview review

The `tx-preview-llm` branch now generates short, ordered execution-plan summaries with a 100-character hard cap and an 80-character preferred budget. No open PR existed when the review began. This work prepares the feature branch and refreshed registry for a subsequent release; it does not publish a release.

## Current card path

The card uses a hybrid: the existing neural encoder classifies compact call evidence, a new learned focus ranker prioritizes the principal action, and a constrained renderer selects complete phrases and decoded values. The autoregressive decoder remains available for training diagnostics but is not run for cards. This removes token-by-token generation latency and prevents generated numbers or token names from entering the displayed summary.

Every call remains in the plan, in execution order. Raw calldata, chain and contract identity, clear-signing fields and warnings, and locally available ABI selector candidates accompany the input. The encoder sees compact typed evidence rather than all hexadecimal bytes. ABI candidates come from the vendored registry, not a complete public four-byte database; ambiguous selector matches do not establish contract identity. Nested executions still depend on what the decoder exposes: this is not a simulation of all downstream effects.

Exact displayed approval amounts can be compressed into “Approve and swap …” when the later target matches the spender and available chain/asset evidence does not contradict the relationship. Larger finite amounts, unlimited grants, unrelated spenders, and operator permissions stay explicit. This matching is based on decoded input amounts, not proof of eventual allowance consumption. Revocations remain in call order. Unknown calls cannot disappear behind a recognized action. Recipient roles and minimum-output labels remain distinct.

Neural work is capped per plan at a sum of squared padded sequence widths of 262,144, with at most 512 tokens per row. Identical token readings share classification work, including across queued requests, but cache reuse does not change the logical per-plan budget. Calls outside the budget still participate in source-based wording and warning checks, with category abstention and conservative risk. Thus large plans retain full source coverage without promising neural attention to every byte. Long summaries use complete overview phrases rather than cutting sentences at the character limit.

The focus ranker adds 1,344 float32 parameters (5,392 bytes) to the existing 5,202,927-byte weights. It was trained on 120 synthetic workflows labeled by local Qwen2.5-Coder-7B Q4_K_M, with 28 labels corrected during agent review. Training used 96 examples; 24 examples from held-out workflow families all matched the reviewed focus labels. This small synthetic result is not independent human validation. The committed script reproduces the weight and metadata files exactly.

A local eight-prompt generative pilot took roughly 0.7–1.6 seconds warm and also invented actions in some mixed/opaque workflows. That pilot motivated keeping generation out of the card's critical path; it does not establish that every larger model or decoding architecture would fail. No new cloud training instance was needed for this update.

See [architecture and reproduction](transaction-previews.md) for input contracts, budgets and commands.

## Retained base model and historical evaluation

The base model has approximately 2.6 million parameters: width 192, six attention heads, feed-forward width 384, four encoder layers and two decoder layers. Its weights occupy **5,202,927 bytes**. It trained for 14 epochs on an H100 with a seeded cosine learning-rate schedule. Retrieved weights and their fingerprint were verified; the training instance was deleted.

The refreshed corpus contains 30,714 examples: 30,691 encode successfully, with 27,129 training, 2,413 strict format-held-out and 1,149 mixed-partition examples excluded. It covers 1,402 of 1,435 interpretable formats. Architecture, corpus and weight hashes, seed and training configuration are recorded in [`training.json`](../crates/ekubo-wallet-preview/model/training.json).

The teacher is deterministic keyword/template code, **not an independent reasoning LLM**. The larger model also received new data and input markers; there is no matched small-model ablation proving capacity alone caused the improvement.

## Quality measurements

These measure agreement with the synthetic teacher, not independent semantic correctness. These are historical results from the legacy decoder path, not semantic accuracy measurements of the new card renderer.

| Same refreshed held-out documents (2,413) | Original model | Final model |
| --- | ---: | ---: |
| Category agreement | 81.52% | 93.95% |
| Advisory risk agreement | 72.86% | 96.60% |
| Critical examples underestimated | 0 / 72 | 0 / 72 |

Final rendered field-selection agreement is 2,319 / 2,413 (96.10%), with no empty summaries. This uses the new label-preserving renderer for both prediction and reference. Literal summary agreement is therefore not comparable with the original paraphrasing renderer. The critical result includes deterministic warning floors, not just model predictions.

**Regression:** on the original strict 1,920-example set, category agreement fell from 1,865 / 1,920 (97.14%) to 1,823 / 1,920 (94.95%). This is not a universal classifier improvement.

Remaining weak categories on the refreshed set include unstake (17/34), delegation (18/34), approval (132/161), governance (166/200), and unrecognized (137/161). Bridge, borrow and wrap/unwrap have no held-out support. Broader independently labeled evaluation is needed before treating these scores as general accuracy. The model remains advisory and does not authorize signing.

## Current performance

Optimized native CPU measurements used one pinned logical core of an AMD Ryzen AI 9 HX 470, 20 iterations. These measure summary-engine work after input assembly, not network requests or all clear-signing decoding. They constrain concurrency on a modern desktop; they are not measurements on an older phone or ARM device.

| Workload | Median | p95 |
| --- | ---: | ---: |
| Typical call | 1.514 ms | 1.904 ms |
| Eight requests with identical readings | 1.498 ms | 1.519 ms |
| 64-call plan with repeated readings | 1.558 ms | 1.599 ms |
| 4,096 calls with repeated readings | 6.965 ms | 7.033 ms |
| 4,096 distinct token readings | 191.213 ms | 199.386 ms |
| Call retaining 8 MiB calldata | 6.606 ms | 6.773 ms |
| One 512-token call | 48.792 ms | 49.183 ms |
| Eight identical 512-token requests | 49.030 ms | 49.424 ms |

Cold engine load plus first result took 9 ms. Peak process RSS was 62.07 MiB, including large input fixtures. The distinct-reading fixture varies context words across 4,096 calls; it is a performance stress test, not independently verified semantic coverage of 4,096 different operations. Repeated-request timings benefit from reuse; many unique long requests have cumulative costs. All measured per-plan cases meet the requested 300 ms target, but this is not a universal device guarantee.

Chromium CPU-only Wasm measured 10.5 ms median / 10.8 ms p95 warm and 56.9 ms for engine initialization plus first result after module initialization. Download time is excluded; browser checks overlapped compilation, so these are observed responsiveness figures rather than isolated device benchmarks. Uncompressed Wasm artifacts including weights are approximately 6.61 MB CPU-only and 9.95 MB with WebGPU and CPU fallback. CPU is the desktop default. Both Wasm configurations, WebGPU single/batch calls, and fallback after absent GPU, null adapter and rejected device were exercised.

## Clear-signing snapshot for the next release

The vendored registry now contains 399 descriptor/include JSON files: 67 added, 27 removed and 53 modified compared with the starting snapshot. Upstream is `ethereum/clear-signing-erc7730-registry` at `0a240f6e457d693cc953ed8204fe4bcf0b8a4faf`. Six Ekubo descriptors retain the signed-format fixes from `EkuboProtocol/clear-signing-erc7730-registry`, `fix-ekubo-signed-formats`, at `f25bc1a0cdd7d931271565463cea5228476795cd`. All vendored JSON bytes were verified against those sources.

The interpreter dependency already points at the patched `fix-raw-signed-integers-0.1.0` revision `c9471ee52dee0aab4ece1aec6f20292f05da1ba8`. Descriptor parsing, includes and signed-value formatting tests pass. Provenance is recorded in [`snapshot.json`](../crates/ekubo-wallet-core/clearsign/snapshot.json). No release tag was created.

## Validation and examples

The workspace gate passed: formatting, all-target/all-feature Clippy, 1,380 Rust tests passed with 6 ignored, Ruff, third-party notice freshness, and configured OSV vulnerability/license scans. Three Python teacher tests passed. Focus training reproduced the committed weights and metadata exactly. Both Wasm feature configurations compile. Native CPU, browser CPU, and WebGPU passed all 22 authored end-to-end summary examples; these are regressions, not a representative independent accuracy benchmark.

See [22 actual generated examples](transaction-preview-examples.md). Benchmark, evaluation and browser artifacts are retained locally in `/home/sendmoodz/Documents/wallet-plan-summary`; the preceding base-model review artifacts are in `/home/sendmoodz/Documents/wallet-preview-review`.
