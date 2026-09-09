# Transaction preview review

Reviewed the existing `tx-preview-llm` branch starting at `a05cb51`. No open GitHub PR existed for it when this review began. The implementation below is prepared on that feature branch; it does not create a release.

## Changes

The original encoder attended to padding, the decoder could emit copy slots through its ordinary word head, and the format-held-out evaluation admitted mixed training/held-out formats. These are fixed and covered by regression tests. Training now seeds the backend, evaluates without dropout, counts padded rows once, shuffles examples in width buckets, decays the learning rate, and rejects truncated examples. Vocabulary ordering and architecture are fingerprinted together.

Boolean polarity is now visible to the model. Zero native value is recognized correctly. Transfer-from summaries preserve sender and recipient; ownership of the sender does not imply ownership of the recipient. Standard operator grants and revocations retain their exact decoded reading and explicit classification. Decoded but uncategorized actions remain distinguishable from opaque calls.

Rendering preserves the decoded protocol/action sequence and up to two model-selected complete labeled fields per call. Generated connecting prose is not displayed. This prevents a minimum output from becoming a claimed withdrawal quantity or a contract target from becoming a recipient. Fields longer than 160 characters are omitted from the compact summary. Missing or reordered action predictions fall back to the decoded actions. Important fields can still be omitted; the summary supplements the full reading.

Long, overflowing, and mixed standard/opaque plans are processed call by call. Aggregation identifies a call needing attention and explicitly says to review all calls. Attention batches shrink as input width increases, bounding memory. Warning floors and opaque-call handling do not depend on a favorable model prediction.

Desktop inference defaults to CPU, runs after the decoded snapshot is published, caches by request ID and complete interpreted input, and discards stale generations. Failures disable previews. The desktop test fixture now joins its Tokio runtime before dropping its temporary database, and token reloads use a weak entity handle; this fixed a teardown crash found during the full test run.

Browser methods return Promises and use asynchronous GPU readbacks. Adapter/device initialization failures now reject normally so CPU fallback works. CPU-only builds remain available.

## Model and data

The new model has approximately 2.6 million parameters: width 192, six attention heads, feed-forward width 384, four encoder layers and two decoder layers. Its weights occupy **5,202,927 bytes**. It trained for 14 epochs on an H100 with a seeded cosine learning-rate schedule. Retrieved weights and their fingerprint were verified; the training instance was deleted.

The refreshed corpus contains 30,714 examples: 30,691 encode successfully, with 27,129 training, 2,413 strict format-held-out and 1,149 mixed-partition examples excluded. It covers 1,402 of 1,435 interpretable formats. Architecture, corpus and weight hashes, seed and training configuration are recorded in [`training.json`](../crates/ekubo-wallet-preview/model/training.json).

The teacher is deterministic keyword/template code, **not an independent reasoning LLM**. The larger model also received new data and input markers; there is no matched small-model ablation proving capacity alone caused the improvement.

## Quality measurements

These measure agreement with the synthetic teacher, not independent semantic correctness. The final deployment path produces the same aggregate results on native CPU and GPU.

| Same refreshed held-out documents (2,413) | Original model | Final model |
| --- | ---: | ---: |
| Category agreement | 81.52% | 93.95% |
| Advisory risk agreement | 72.86% | 96.60% |
| Critical examples underestimated | 0 / 72 | 0 / 72 |

Final rendered field-selection agreement is 2,319 / 2,413 (96.10%), with no empty summaries. This uses the new label-preserving renderer for both prediction and reference. Literal summary agreement is therefore not comparable with the original paraphrasing renderer. The critical result includes deterministic warning floors, not just model predictions.

**Regression:** on the original strict 1,920-example set, category agreement fell from 1,865 / 1,920 (97.14%) to 1,823 / 1,920 (94.95%). This is not a universal classifier improvement.

Remaining weak categories on the refreshed set include unstake (17/34), delegation (18/34), approval (132/161), governance (166/200), and unrecognized (137/161). Bridge, borrow and wrap/unwrap have no held-out support. Broader independently labeled evaluation is needed before treating these scores as general accuracy. The model remains advisory and does not authorize signing.

## Performance

Native CPU measurements used one pinned logical core of an AMD Ryzen AI 9 HX 470, 20 iterations, optimized `preview-train` builds. This constrains concurrency on a modern desktop; it is not a measurement on an actual low-end phone or ARM device.

| Workload | CPU median | CPU p95 |
| --- | ---: | ---: |
| One call | 4.43 ms | 5.38 ms |
| Eight requests | 26.87 ms | 27.09 ms |
| 64-call plan | 216.71 ms | 248.26 ms |
| One near-limit 512-token call | 71.06 ms | 71.45 ms |
| Eight near-limit requests | 571.29 ms | 574.45 ms |

CPU cold load plus first result took 14 ms; peak process RSS across the benchmark was 40.9 MiB. GPU cold load plus first result took 248 ms and a typical single call took 18.93 ms median / 19.90 ms p95. GPU was faster for long inputs and large batches, but CPU wins the usual one-request interaction and avoids GPU initialization overhead, so it is the desktop default.

Final uncompressed browser artifacts including weights are 6,654,010 bytes CPU-only and 10,153,532 bytes with WebGPU plus CPU fallback. Browser CPU, real WebGPU, single/batch APIs, and CPU-only builds were exercised in Chromium. Missing WebGPU, a null adapter and a rejected device request all returned errors and successfully fell back to CPU. Browser timings were not isolated from other validation work and are not presented as device benchmarks.

## Clear-signing snapshot for the next release

The vendored registry now contains 399 descriptor/include JSON files: 67 added, 27 removed and 53 modified compared with the starting snapshot. Upstream is `ethereum/clear-signing-erc7730-registry` at `0a240f6e457d693cc953ed8204fe4bcf0b8a4faf`. Six Ekubo descriptors retain the signed-format fixes from `EkuboProtocol/clear-signing-erc7730-registry`, `fix-ekubo-signed-formats`, at `f25bc1a0cdd7d931271565463cea5228476795cd`. All vendored JSON bytes were verified against those sources.

The interpreter dependency already points at the patched `fix-raw-signed-integers-0.1.0` revision `c9471ee52dee0aab4ece1aec6f20292f05da1ba8`. Descriptor parsing, includes and signed-value formatting tests pass. Provenance is recorded in [`snapshot.json`](../crates/ekubo-wallet-core/clearsign/snapshot.json). No release tag was created.

## Validation and examples

The full workspace gate passed: formatting, all-target/all-feature Clippy, **1,353 Rust tests passed with 6 ignored**, Ruff, third-party notice freshness, and OSV vulnerability/license policy scans using the repository configuration. Three Python teacher tests passed. The desktop CPU-default build and both Wasm feature configurations compile.

See [11 actual generated examples](transaction-preview-examples.md), including retained sender/recipient roles, operator grant/revocation polarity, an omitted cooldown amount, labeled minimum output, and a late opaque call. Raw predictions, benchmarks and browser results are retained locally in `/home/sendmoodz/Documents/wallet-preview-review`.
