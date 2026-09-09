# Transaction previews

The wallet produces a short summary of an entire waiting execution plan. The card targets 60–80 characters and never exceeds 100 Unicode scalar values. Shorter complete summaries stay short. Call order is preserved, while a learned plan-focus model decides which action gets more detail.

For example: `Approve and swap 250 USDC for ETH`, `Unlimited approve USDC and swap 250 USDC for ETH`, or `Swap 250 USDC for ETH, then revoke approval`.

## Evidence and context

`PlanDocument` retains every ordered call. Each `CallSummary` carries the clear-signing description, labeled fields, warnings, target and native value. Optional execution evidence adds the chain, sender, target, raw calldata and ABI candidates. The desktop supplies this evidence from the actual execution steps; browser callers can supply the same structure through `evidence`.

The offline four-byte index uses signatures from the vendored clear-signing registry. Candidates must decode canonically and re-encode to the original bytes. Exact chain/address matches are distinguished from selector-only guesses. This is a local, bounded index, not the full 4byte.directory database and not proof of a contract's implementation. The lookup considers at most eight signatures and declines ABI decoding for bodies larger than 65,536 bytes. Raw calldata remains available even when this supplementary decoder declines it. Named ABI parameters are retained where Alloy's parser supports the signature.

The neural input is a compact projection of this evidence: clear-signing text, selector, candidate signatures with their provenance, and bounded typed argument readings. The model does not spend thousands of language tokens regenerating hex. Raw canonical approval bytes are also inspected directly to preserve an unlimited grant independently of prose or optional warnings. The full evidence stays in the document and in cache identity.

Nested bytes and selector candidates do not establish an execution trace. A model-supported candidate can appear as `Unknown call (possible swap)`; it remains explicitly unknown and cannot lower the risk floor. Large or unfamiliar router payloads may still receive a general or incomplete summary. Simulation effects are not currently fed into this model.

## Fast, hierarchical inference

The card path uses the existing four-layer, width-192 encoder for call classification and advisory risk. It then runs a separate 16-unit contextual ranker over the complete sequence of call categories. Its features include the current, previous and next categories, the plan-wide category frequencies, relative position and whether a call is last. The ranker selects emphasis; it cannot reorder calls or invent facts.

There is no autoregressive text-generation loop in the card path. Constrained realization turns the interpreted actions, named field roles and learned salience into the final sentence. The encoder's old autoregressive decoder is retained in the weights and through `legacy_all_async` for reproducible evaluation of the earlier model. Public `preview`, `preview_all` and `preview_all_async`, desktop cards, and browser `preview`/`previewAll` use the new card path.

Each neural call reading has at most 512 tokens and 48 slots. Identical tokenized readings share a classification even if their copied amounts or addresses differ. Results are also reused across requests in the same invocation. Logical work selection remains per plan, so another queued request cannot change a plan's result. Attention dispatches remain grouped by padded width, with smaller batches for longer readings.

A per-plan budget limits the sum of squared padded widths to 262,144. Calls beyond this neural-work budget, or exceeding the model window, retain their decoded action in the card; they do not disappear. Their learned classification abstains and their advisory risk is at least caution, or critical for opaque calls. The renderer and warning checks still examine all calls. This bounds expensive model work while allowing the execution-plan limits of 4,096 steps and 8 MiB of calldata. It is not an assertion that the neural encoder fully read every byte or every field.

CPU is the desktop default. The decoded snapshot appears first; previews run in a separate background stage, and generation checks discard stale results. The in-memory cache keys on the request ID and complete document, including raw evidence. Settled requests leave the cache. Initialization or inference failures disable previews without delaying review controls. Browser APIs are asynchronous on both CPU and WebGPU; use a Worker for CPU inference to keep the page responsive.

## Card wording

The renderer allocates detail to the principal action before supporting actions and never slices a finished sentence. Exact approvals can become `Approve and swap` when the displayed amount matches a later call to the spender and available chain/asset evidence does not conflict. A larger finite allowance retains its amount. An unrelated spender stays explicit. Unlimited and operator grants are distinct from ordinary approvals; revocations preserve their position after an action.

Concrete amounts come from whole, recognized field labels. An input amount is not selected from a minimum-output field, conflicting amount labels are not arbitrarily resolved, and a cooldown is not rewritten as an immediate withdrawal. Distinct recipients stay visible. Full address annotations on token labels can be removed, and addresses can be abbreviated for display; the full decoded review retains their identity.

Consecutive repetitions can be grouped with a count. If their values differ, the grouped phrase does not repeat one value as though it applied to all calls. If even the essential action sequence cannot fit, the summary explicitly says to review the full plan. Unknown calls and unlimited/operator grants remain visible in that overview.

Unfamiliar actions keep their decoded wording rather than being freely paraphrased. Compound actions and changes to signers or other authority retain their specific wording. This favors faithful, compact summaries over an unrestricted language model's fluency.

## Models, training and limits

The existing approximately 2.6-million-parameter encoder/decoder weights occupy 5,202,927 bytes. The new plan-focus ranker adds 5,392 bytes, for about 5.21 MB total. Architecture and corpus provenance for the existing model remain in `model/training.json`; focus training and evaluation are recorded in `model/focus-training.json`.

The base model was trained on the deterministic teacher in `scripts/preview-labels.py`. Its earlier category limitations remain; this change does not establish a universal classifier improvement. The new ranker uses 120 synthetic workflows proposed to a local Qwen2.5-Coder-7B teacher and reviewed by the coding agent. Twenty-eight proposed focus labels were corrected. Ninety-six examples train the ranker; 24 examples from six entirely held-out workflow families evaluate it. These are small, agent-reviewed synthetic sets, not an independent human audit or a broad transaction-correctness benchmark.

The focus examples retain both the teacher's original index and the reviewed index in `model/focus-examples.jsonl`. Reproduce the exact focus weights and metadata with:

```sh
uv run scripts/preview-focus-train.py --out /tmp/focus-model
```

The base-model fingerprint includes the ordered vocabulary hash and architecture dimensions. Vocabulary or taxonomy changes require revisiting the fingerprint, training corpus and both models. Its corpus pipeline excludes plans mixing training and held-out formats, rejects truncation, seeds training, evaluates without dropout and deduplicates padded evaluation rows.

The summary is advisory. The policy engine and review identity do not depend on it, and it does not authorize signing. Incorrect descriptors, unsupported field roles, mistaken categories and omitted details remain possible. Always show the decoded review alongside it.

## Validation and measurement

Run the committed end-to-end card examples with the actual embedded weights:

```sh
cargo run --profile preview-train -p ekubo-wallet-preview --features train --bin preview-card-eval
```

`preview-bench cpu` measures the card path, including typical calls, repeated and distinct 4,096-call plans, 8 MiB calldata, and near-limit model inputs. Its optional second argument `legacy` measures the earlier autoregressive path. Run an optimized build on one pinned CPU core and report cold initialization, warm p50/p95 and process memory separately. The target is below 300 ms per summary; measurements on a constrained modern desktop do not guarantee that latency on every low-end device or for an arbitrarily large queue.

`preview-sample --count 0` deliberately retains the legacy decoder evaluation so its earlier synthetic-teacher measurements remain reproducible. Those scores are not the new card-summary quality metric. See [the review](transaction-preview-review.md) and [actual card examples](transaction-preview-examples.md).
