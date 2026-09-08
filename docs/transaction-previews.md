# Transaction previews

The wallet ships a small language model that reads the clear-signing
interpretation of a waiting transaction and answers three things: a category
from a closed set, a risk band, and one sentence saying what the plan does. The
review list shows all three, labeled as machine-written, beside the
deterministic headline it already showed.

It exists for triage. An owner with a queue of waiting requests should be able
to tell a routine swap from an unlimited approval without opening each one, and
the sentence should have been written for the plan in front of them rather than
picked from a table of stock phrases.

## What it is not

It is not part of the security kernel.

- The policy engine never consults it.
- `ReviewDocument.identity` — the digest a reviewer approves — does not cover
  it. Adding it there would make a model output part of what gets signed.
- The authoritative reading of a transaction remains the deterministic field
  list inside the review, which is decoded from calldata by
  `approval_summary::interpret_steps` and the vendored ERC-7730 registry.
- A preview that is absent, or wrong, changes nothing about what can be sent.

Absence is an ordinary state, not an error. A machine with no usable GPU
adapter, a build with no weights committed, or weights that do not match the
build all produce no previews and a wallet that behaves exactly as it did
before this existed.

## Why a generated sentence is safe on this surface

A language model writing prose next to a signing decision can commit one
failure that actually matters: a fluent, plausible sentence naming the wrong
amount or the wrong address. Training does not rule that out, and the review
list is precisely where it would be believed.

So the model is never given the opportunity.

Before tokenization, every concrete value in the decoded reading — amounts,
addresses, token labels, opaque data, bare integers — is lifted out into a
numbered slot (`crates/ekubo-wallet-preview/src/slots.rs`). What the model sees
is the value's *kind* and its slot reference, never its digits. What the model
emits is words and slot references. Rendering substitutes each reference with
the slot's verbatim text, taken from the same deterministic interpretation the
review displays.

There is therefore no path from the weights to a digit. The only thing a
forward pass chooses is *which* already-decoded value to name. A wrong choice
is a visibly wrong sentence sitting next to the authoritative field list — not
a forgery.

Three further constraints hold that shut:

- **The decoder cannot produce a slot reference from its vocabulary.** It
  scores input *positions* instead, and every position that does not hold a
  slot reference is masked to negative infinity. Pointing at a non-value is
  impossible rather than unlikely, and the set of things the model can name is
  exactly the set the deterministic interpretation lifted.
- **The vocabulary contains no digit-leading word.** The tokenizer lifts
  anything starting with a digit into a slot, so it could never *teach* one;
  `vocab_test.rs` asserts it over the committed file, which is what catches a
  regenerated vocabulary that harvested words from slot texts.
- **A rendered summary is checked against the plan's slots before display.** A
  number or address that is not in the plan drops the summary and leaves the
  category standing alone. This should be unreachable; it is there because
  "unreachable" is a claim about today's code.

The class and risk answers are indices into closed enums, so no forward pass
can produce a category the review surface was not written to display.

## Shape

Roughly 1.2M parameters at `d_model` 128: a four-layer encoder, two
classification heads pooled over it, and a two-layer decoder with cross
attention and a copy head. The decoder is deliberately shallow — a
one-sentence summary has no long-range structure worth the compute, and this
runs while somebody waits.

Inference runs on the GPU through `burn`'s `wgpu` backend, which is the same
interface GPUI already draws through, so one source tree covers Metal,
Direct3D and Vulkan. Previews for every waiting request are computed in one
batch off the UI thread, during `DesktopSnapshot::capture`.

## Rebuilding the model

Four steps. Only the first three need the `train` feature, which pulls in
`ekubo-wallet-core` and the autodiff backend and is never enabled by a release
build.

A release build of anything in this workspace needs
`EKUBO_UPDATER_PUBLIC_KEY` set to canonical base64 — `crates/ekubo-wallet-core/build.rs`
asserts it — so either export the real key or drop `--release`. Corpus
generation is fine in debug; training is roughly ten times slower without
optimizations, so it is worth the key.

```sh
export EKUBO_UPDATER_PUBLIC_KEY="$(gh variable get EKUBO_UPDATER_PUBLIC_KEY)"

# 1. Enumerate every call the vendored registry can interpret.
python3 scripts/preview-corpus-spec.py \
  --clearsign crates/ekubo-wallet-core/clearsign --out /tmp/corpus-spec.json

# 2. Synthesize plans and interpret them through the real engine.
cargo run --release -p ekubo-wallet-preview --features train --bin preview-corpus -- \
  --spec /tmp/corpus-spec.json --out /tmp/corpus.jsonl --samples 20

# 3. Attach a class, a risk band, and a summary to each.
python3 scripts/preview-labels.py \
  --spec /tmp/corpus-spec.json --corpus /tmp/corpus.jsonl --out /tmp/labeled.jsonl

# 4. Rebuild the vocabulary, then fit.
python3 scripts/build-preview-vocab.py \
  --registry crates/ekubo-wallet-core/clearsign/registry \
  --corpus /tmp/labeled.jsonl \
  --out crates/ekubo-wallet-preview/model/vocab.txt
cargo run --release -p ekubo-wallet-preview --features train --bin preview-train -- \
  --corpus /tmp/labeled.jsonl --out crates/ekubo-wallet-preview/model/preview.bin

# 5. Read what it actually says, on descriptors it was never fitted on.
cargo run --release -p ekubo-wallet-preview --features train --bin preview-sample -- \
  --corpus /tmp/labeled.jsonl --count 40
```

Step 5 loads the committed weights through `gpu::load`, exactly as the wallet
does, so it is also the check that inference runs on this machine's GPU at
all.

Step 2 reports coverage — how many registry formats produced a reading. That
number is the generator's own correctness check: signature canonicalization,
include resolution and deployment addresses all have to be right for a reading
to appear at all, so a mistake in any of them shows up as coverage rather than
as a corpus of examples the engine would never produce.

### The teacher is a rule table

`scripts/preview-labels.py` maps a descriptor's human-authored intent to a
class by keyword, derives the risk band from what the call *is* (an unlimited
allowance, blanket operator control, a delegation, or value sent somewhere
nothing decoded), and fills a per-class summary template from the call's slot
shapes.

Rules rather than a per-format label sheet, for two reasons. A rule reviewed
once applies to every format it matches, including ones vendored later, where
a thousand hand labels are a thousand chances to be inconsistent about what
"withdraw" means. And a rule can be read and argued with, where a label sheet
only records that somebody once decided.

The model is not the rules. It is fitted on what they produce and then runs on
calls they have nothing to say about — an unlisted protocol, a standard token
call, a phrasing the keyword table misses. Generalizing past the table is the
entire reason for having a model rather than shipping the table.

That claim is what the held-out set measures, which is why the split runs along
*descriptor formats* rather than examples: an entire format goes to one side or
the other, so the reported accuracy is reading a protocol the model was never
fitted on.

### Retraining obligations

The vocabulary's fixed prefix and the class and risk enums have indices that
the rendering code and the weights both depend on. Widening a taxonomy or
inserting a fixed vocabulary piece invalidates the committed weights:

- `vocab.rs` has a compile-time assertion on where slot references begin, so
  inserting a fixed piece fails the build rather than silently renumbering.
- The heads are sized from `CLASS_COUNT` and `RISK_COUNT`, so a widened enum is
  a shape mismatch at load rather than a misread label.
- `TransactionClass::Unrecognized` stays last, and both enums are append-only,
  so weights trained before a widening keep their meanings.

Weights are committed to git, so every retrain writes a new copy into history;
`weights_test.rs` fails if the file grows past 12 MB.

### Where training runs

`preview-train --device cpu` is the default and works anywhere. Fitting 1.2M
parameters over twenty thousand short sequences is roughly ten minutes an epoch
on a laptop CPU, which is slow but not prohibitive.

`--device gpu` uses the same `wgpu` backend inference does, and needs a machine
with real video memory. It will not work on a small integrated GPU: `cubecl`
sizes its memory pool from the adapter's reported memory, and on a 2 GB
carve-out that is a single ~3 GB allocation that fails outright — which is what
sent the first fitting of this model to the CPU.

`scripts/train-preview-remote.sh` does the GPU path on a DigitalOcean droplet:

```sh
scripts/train-preview-remote.sh /tmp/labeled.jsonl 12
```

It creates a throwaway SSH key and a GPU droplet, syncs this checkout and the
corpus, builds, fits, copies the weights back over
`crates/ekubo-wallet-preview/model/preview.bin`, and destroys both the droplet
and the key. The teardown is a shell trap on `EXIT INT TERM`, because the
droplet bills by the hour and leaving one running is the expensive mistake.
Size, region and image are overridable through `PREVIEW_DROPLET_SIZE`,
`PREVIEW_DROPLET_REGION` and `PREVIEW_DROPLET_IMAGE`.

The weights are backend-agnostic, so which device fitted them changes nothing
about what loads in the wallet — it is a flag rather than a fork, and the
numbers below were reproduced on both.
