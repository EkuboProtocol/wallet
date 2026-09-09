# Transaction previews

The wallet embeds a small encoder-decoder model that reads deterministic clear-signing interpretations and proposes a transaction category, an advisory risk band, and a short summary. The review list displays it below the deterministic headline, labeled as machine-written. Inference is local; there is no model API or runtime download.

## Trust and limitations

The model is outside `ekubo-wallet-core`. Policy decisions and `ReviewDocument.identity` do not depend on it. The decoded fields remain authoritative. The model can misclassify a request or select incomplete/unhelpful supporting fields. The descriptor itself can also be wrong. A faithful extractive summary does **not** establish that the underlying transaction is correct.

Amounts, addresses, token labels, protocol names, and complete decoded action phrases are lifted into slots. The decoder copies action phrases instead of paraphrasing them; protocol and action copies must remain in call order. A missing or reordered action triggers a fallback showing the decoded actions directly. Supporting values retain their original field labels: the model selects up to two labeled fields per call, and the renderer copies each complete label/value line. Unlabeled or over-160-character fields are omitted; contract targets are never reinterpreted as recipients. Native value has its own explicit label. Free generated connecting words are not displayed. The word head is masked so it can emit only learned words or EOS; slot references must come from the copy head, whose scores are masked to input positions that contain slots. A final check rejects number/address fragments that are not complete value tokens in the input. This is a provenance check, not a check of the sentence's meaning.

An entirely undecoded call is always `Unrecognized / Needs care`. If it sends native value, its factual fallback names that value and target without asking the model to infer an action. Any decoded warning or undecoded component prevents the model from marking a plan routine. These display rules do not change signing authority.

## Bounded inference

The model has four encoder layers, two decoder layers, width 192, and six attention heads. Half-precision weights are stored in the binary; computation uses the backend's float type. See the review report for measured size and latency.

Each input has at most 512 tokens and 48 slots, including action phrases. Exceeding either limit is recorded explicitly. Plans with more than two calls, incomplete inputs, or a standard transfer/operator-approval or undecoded component are processed call by call; its aggregate uses the highest advisory risk and identifies one call needing attention, with an explicit instruction to review all calls. A single call that exceeds the limits receives an unavailable-summary message instead of a summary of its prefix. Long plans therefore do not silently discard their final calls. This is bounded per-call inference, not unlimited transformer context.

Inference groups requests by width and runs at most eight rows per dispatch. Width-256 inputs use at most two rows and width-512 inputs one, bounding quadratic attention memory. Encoder padding is masked in every attention layer as well as during pooling and decoder cross-attention. Thus adding a longer neighboring request cannot change the meaning of a short request's padding. Greedy decoding ends at EOS; a sequence that exhausts the output limit without terminating is withheld rather than displayed as a finished sentence.

The desktop publishes the decoded snapshot first and computes previews in a separate background stage. Generation checks discard stale results. Desktop inference uses CPU by default: measured single-request latency and cold startup beat GPU dispatch for this small workload. The preview crate and browser bindings retain explicit GPU support. An in-memory cache keys each result by request ID **and the complete interpreted input**, so changing metadata or warnings invalidates it. Settled requests leave the cache. No preview cache is written to disk. Initialization and inference failures disable previews; Rust panic guards cannot recover from process-level faults such as SIGSEGV or a driver killing the process.

The Rust engine provides synchronous native entry points and `preview_all_async`. Browser bindings return Promises from `preview` and `previewAll`: GPU readbacks must yield to the browser event loop. CPU-only browser builds use the same asynchronous API.

## Training

The teacher is `scripts/preview-labels.py`, a keyword classifier and per-class summary templates populated from decoded values and descriptor intents. The current weights are supervised by these rules. Boolean polarity is retained as input-only true/false markers. Decoded actions outside the category taxonomy keep their reading and receive caution, rather than being labeled like opaque calls. Action phrases and standard-call readings are copied from the interpreter; the model still learns which additional value slots to mention. The training decoder still learns the template token sequence, but display renders its selected fields through the label-preserving renderer. It has not been distilled from an independently reasoning larger LLM. Agreement with that teacher measures consistency with its labels; it does not demonstrate that the teacher assigned amounts or verbs correctly.

The corpus is generated through the actual wallet interpreter. Zero native value is determined from the amount, not from whether the rendered string still contains a currency suffix. Oversized input and summary targets are rejected, never silently shortened into incomplete training sentences. Standard `transferFrom` summaries retain both sender and recipient; an owned sender never makes an external recipient an owned account. Training uses a decaying learning rate and shuffles examples within width buckets each epoch, seeds the tensor backend as well as the data shuffle, and evaluates an inference-mode model with dropout disabled. Evaluation counts each example once even when a padded batch repeats it.

Formats are assigned deterministically to training or held-out partitions. A plan mixing formats from both sides is excluded from both populations. Otherwise a mixed example could put a training format in the held-out population. Format separation does not imply protocol separation: related formats from the same protocol can still be present on both sides.

The model fingerprint includes the ordered vocabulary's hash and the architecture revision and dimensions. Vocabulary length alone cannot detect reordered token meanings. Any tokenizer or taxonomy semantic change requires reviewing and bumping the revision, regenerating the corpus as needed, and retraining. The committed-weight test requires a matching, loadable model.

## Reproduction

Use a scratch directory outside the repository for generated corpora and evaluation output. Release-derived profiles require `EKUBO_UPDATER_PUBLIC_KEY`; use the repository's configured public verification key.

```sh
python3 scripts/preview-corpus-spec.py \
  --clearsign crates/ekubo-wallet-core/clearsign --out /tmp/corpus-spec.json
cargo run --profile preview-train -p ekubo-wallet-preview --features train --bin preview-corpus -- \
  --spec /tmp/corpus-spec.json --out /tmp/corpus.jsonl --samples 20
python3 scripts/preview-labels.py \
  --spec /tmp/corpus-spec.json --corpus /tmp/corpus.jsonl --out /tmp/labeled.jsonl
cargo run --profile preview-train -p ekubo-wallet-preview --features train --bin preview-train -- \
  --corpus /tmp/labeled.jsonl --out crates/ekubo-wallet-preview/model/preview.bin --epochs 14
cargo run --profile preview-train -p ekubo-wallet-preview --features train --bin preview-sample -- \
  --corpus /tmp/labeled.jsonl --count 0 --device gpu > /tmp/predictions.jsonl
```

`--count 0` evaluates every strictly held-out example, including examples rejected by training. A positive count selects a reproducibly shuffled sample. JSONL predictions include expected and actual class, risk, and summary. Standard error reports per-class support, critical-risk underestimates, agreement with the teacher's field selection rendered through the same label-preserving renderer, empty summaries, and slot-text-coverage agreement. Coverage uses substring matching on both rendered texts, includes values nested in action slots, and ignores ordering and roles; it is not a semantic or provenance metric. Timing includes initialization of dispatched shapes; it is not a warm per-plan latency claim.

When changing the vocabulary, first regenerate it with `scripts/build-preview-vocab.py` using the new corpus and registry, then rebuild the training binary. The fingerprint and weights must be retrieved together after training.

`scripts/train-preview-remote.sh /tmp/labeled.jsonl 14` can train on a temporary DigitalOcean GPU. It copies git-listed files, creates a temporary SSH key and droplet, and removes them on exit. Its `PREVIEW_DROPLET_SIZE` and `PREVIEW_DROPLET_REGION` overrides select a particular machine. The separate `preview-train` Cargo profile optimizes arithmetic without release LTO, reducing iteration time.

## Before treating quality numbers as a release criterion

Keep the synthetic held-out score separate from an independently reviewed challenge set. That set should cover swapped sender/recipient roles, multiple amounts with different meanings, approvals and revocations, mixed decoded/opaque calls, unknown protocols, and dangerous calls at the end of long plans. Class accuracy alone cannot validate generated signing prose. See [the review report](transaction-preview-review.md) for this branch's measurements and remaining limitations.

## Low-spec benchmark

`preview-bench cpu` isolates model loading and inference from corpus parsing. It reports cold startup and warm p50/p95 latency for one call, eight requests, a 64-call plan, and single/queued near-limit inputs. Run the optimized binary under `taskset -c <available-core>` and `/usr/bin/time -v` to measure one-core CPU performance and process peak RSS. This is a constrained desktop benchmark, not a measurement on an actual low-end phone.

Training provenance and content hashes are recorded in `crates/ekubo-wallet-preview/model/training.json`; registry source revisions are recorded in `crates/ekubo-wallet-core/clearsign/snapshot.json`. See [the review measurements](transaction-preview-review.md) and [actual examples](transaction-preview-examples.md).
