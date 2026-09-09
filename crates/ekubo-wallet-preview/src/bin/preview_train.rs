//! Fit the transaction-preview model and write its weights.
//!
//! Trains on the GPU through `Wgpu` when one is available. The held-out set is
//! drawn along descriptor formats rather than examples, so what it reports is
//! how well the model reads a protocol it was never fitted on -- which is the
//! only claim worth making about it, since the rule table already handles
//! every format that *is* in the corpus.

use burn::{
    backend::{Autodiff, NdArray, Wgpu},
    module::{AutodiffModule as _, Module as _},
    optim::{AdamWConfig, GradientsParams, Optimizer},
    record::{BinFileRecorder, HalfPrecisionSettings},
    tensor::backend::{AutodiffBackend, Backend},
};
use ekubo_wallet_preview::{
    infer,
    model::PreviewModel,
    taxonomy::{CLASS_COUNT, TransactionClass},
    training::{self, Encoded, Labeled},
    vocab,
};
use rand::{SeedableRng as _, rngs::StdRng};
use std::path::PathBuf;

/// Where the fitting runs.
///
/// The CPU is the default because it works everywhere and a 1.2M-parameter
/// model over twenty thousand short sequences is minutes of work. It is also
/// the only thing that worked on the machine this was first fitted on:
/// `cubecl` sizes its `wgpu` memory pool from the adapter's reported memory,
/// and on an integrated GPU with a 2 GB carve-out that is one ~3 GB allocation
/// that simply fails.
///
/// A machine with real video memory has no such problem, and the same `wgpu`
/// backend inference uses will fit this in a fraction of the time. The weights
/// are backend-agnostic either way: what is fitted on one loads on the other
/// unchanged, which is what makes this a flag rather than a fork.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Device {
    Cpu,
    Gpu,
}

type Cpu = Autodiff<NdArray>;
type Gpu = Autodiff<Wgpu>;

struct Arguments {
    corpus: PathBuf,
    out: PathBuf,
    epochs: usize,
    learning_rate: f64,
    seed: u64,
    device: Device,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut corpus = None;
    let mut out = None;
    let mut epochs = 12_usize;
    let mut learning_rate = 3e-4_f64;
    let mut seed = 20_260_908_u64;
    let mut device = Device::Cpu;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--epochs" => epochs = value()?.parse().map_err(|_| "--epochs must be a number")?,
            "--lr" => learning_rate = value()?.parse().map_err(|_| "--lr must be a number")?,
            "--seed" => seed = value()?.parse().map_err(|_| "--seed must be a number")?,
            "--device" => {
                device = match value()?.as_str() {
                    "cpu" => Device::Cpu,
                    "gpu" => Device::Gpu,
                    other => return Err(format!("--device must be cpu or gpu, not {other}")),
                }
            }
            other => return Err(format!("unrecognized flag {other}")),
        }
    }
    Ok(Arguments {
        corpus: corpus.ok_or("--corpus is required")?,
        out: out.ok_or("--out is required")?,
        epochs,
        learning_rate,
        seed,
        device,
    })
}

fn main() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let vocabulary = vocab::size();
    let text = std::fs::read_to_string(&arguments.corpus)
        .map_err(|error| format!("reading {}: {error}", arguments.corpus.display()))?;

    let mut examples = Vec::new();
    let mut dropped = 0_usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let labeled: Labeled =
            serde_json::from_str(line).map_err(|error| format!("parsing an example: {error}"))?;
        match training::encode(&labeled, vocabulary) {
            Some(encoded) => examples.push(encoded),
            None => dropped += 1,
        }
    }
    eprintln!(
        "{} examples encoded, {dropped} dropped as unlearnable",
        examples.len()
    );

    // Held out along formats, so the reported numbers are generalization to
    // descriptors the model never saw rather than recall of ones it did.
    let (train, evaluate) = training::split(examples, 10);
    eprintln!(
        "{} training examples, {} held out across unseen formats",
        train.len(),
        evaluate.len()
    );
    let weights = training::class_weights(&train);
    // Fixed once: the held-out batches never change, so their shapes are
    // built once and reused every epoch rather than recompiled each time.
    let held_out_batches = training::plan_batches(&evaluate);

    match arguments.device {
        Device::Cpu => fit::<Cpu>(
            &burn::backend::ndarray::NdArrayDevice::default(),
            &arguments,
            &train,
            &evaluate,
            &held_out_batches,
            &weights,
        ),
        Device::Gpu => fit::<Gpu>(
            &burn::backend::wgpu::WgpuDevice::default(),
            &arguments,
            &train,
            &evaluate,
            &held_out_batches,
            &weights,
        ),
    }
}

/// Fit the model and write it, on whichever backend was asked for.
///
/// Generic rather than duplicated because the weights are backend-agnostic:
/// what is fitted here loads anywhere, and the only thing the choice changes
/// is how long it takes.
fn fit<B: AutodiffBackend>(
    device: &B::Device,
    arguments: &Arguments,
    train: &[Encoded],
    evaluate: &[Encoded],
    held_out_batches: &[(training::Shape, Vec<usize>)],
    weights: &[f32],
) -> Result<(), String> {
    let mut model = PreviewModel::<B>::new(device);
    let mut optimizer = AdamWConfig::new().init();
    let mut rng = StdRng::seed_from_u64(arguments.seed);
    // Planned once. Only the order changes between epochs.
    let mut planned = training::plan_batches(train);

    for epoch in 1..=arguments.epochs {
        let started = std::time::Instant::now();
        let mut total = 0.0_f64;
        let mut steps = 0_usize;
        training::shuffle_batches(&mut planned, &mut rng);
        for (shape, indices) in &planned {
            let members = training::gather(train, indices);
            let batch = training::batch::<B>(&members, *shape, device);
            let loss = training::loss(&model, &batch, weights, device);
            let value = loss
                .clone()
                .into_data()
                .to_vec::<f32>()
                .ok()
                .and_then(|values| values.first().copied())
                .unwrap_or_default();
            total += f64::from(value);
            steps += 1;
            let gradients = GradientsParams::from_grads(loss.backward(), &model);
            model = optimizer.step(arguments.learning_rate, model, gradients);
        }
        let mean = total / f64::from(u32::try_from(steps.max(1)).unwrap_or(u32::MAX));
        let accuracy = tally(&model, evaluate, held_out_batches, device);
        eprintln!(
            "epoch {epoch:>3}  loss {mean:.4}  held-out class {:.1}%  risk {:.1}%  ({:?})",
            100.0 * accuracy.class_accuracy(),
            100.0 * accuracy.risk_accuracy(),
            started.elapsed()
        );
    }

    tally(&model, evaluate, held_out_batches, device).report();

    // Saved from the inference view of the model, so the weights file carries
    // no autodiff state and loads under the plain backend the wallet runs.
    // Half precision, matching `weights::load`. See its doc comment: this is
    // about what goes into git, not about what the model computes in.
    let recorder = BinFileRecorder::<HalfPrecisionSettings>::new();
    model
        .valid()
        .save_file(arguments.out.clone(), &recorder)
        .map_err(|error| format!("writing {}: {error}", arguments.out.display()))?;
    // Beside the weights, and written by the same step that writes them, so
    // the two cannot get out of step. `weights::load` refuses a mismatch --
    // burn itself does not check, and a silently wrong embedding table is the
    // one failure this crate must never have.
    let fingerprint = arguments.out.with_extension("fingerprint");
    std::fs::write(
        &fingerprint,
        format!("{}\n", ekubo_wallet_preview::weights::fingerprint()),
    )
    .map_err(|error| format!("writing {}: {error}", fingerprint.display()))?;
    eprintln!(
        "wrote {} and {}",
        arguments.out.display(),
        fingerprint.display()
    );
    Ok(())
}

/// What the model got right on the held-out set, in total and per class.
///
/// One tally, formatted two ways. There used to be two functions walking the
/// same batches with the same comparison, and they disagreed: the headline
/// said 97.3% while the per-class table averaged about 44%. An independent
/// measurement through the inference path agreed with the headline, so the
/// table was wrong -- and a diagnostic that is wrong about which classes are
/// weak is worse than no diagnostic, because it is what you would act on.
///
/// Having one function makes that particular disagreement impossible rather
/// than merely unlikely.
struct Tally {
    class_right: usize,
    risk_right: usize,
    total: usize,
    right_by_class: [usize; CLASS_COUNT],
    seen_by_class: [usize; CLASS_COUNT],
}

impl Tally {
    fn class_accuracy(&self) -> f64 {
        ratio(self.class_right, self.total)
    }

    fn risk_accuracy(&self) -> f64 {
        ratio(self.risk_right, self.total)
    }

    /// Per class, for the classes the held-out set actually contains.
    fn report(&self) {
        eprintln!("held-out accuracy by class:");
        for index in 0..CLASS_COUNT {
            if self.seen_by_class[index] == 0 {
                continue;
            }
            eprintln!(
                "  {:18} {:>5.1}%  ({} held out)",
                TransactionClass::from_index(index).corpus_name(),
                100.0 * ratio(self.right_by_class[index], self.seen_by_class[index]),
                self.seen_by_class[index]
            );
        }
    }
}

fn ratio(part: usize, whole: usize) -> f64 {
    let whole = f64::from(u32::try_from(whole.max(1)).unwrap_or(u32::MAX));
    f64::from(u32::try_from(part).unwrap_or(u32::MAX)) / whole
}

fn tally<B: Backend>(
    model: &PreviewModel<B>,
    examples: &[Encoded],
    batches: &[(training::Shape, Vec<usize>)],
    device: &B::Device,
) -> Tally {
    let mut tally = Tally {
        class_right: 0,
        risk_right: 0,
        total: 0,
        right_by_class: [0; CLASS_COUNT],
        seen_by_class: [0; CLASS_COUNT],
    };
    for (shape, indices) in batches {
        let chunk = training::gather(examples, indices);
        let batch = training::batch::<B>(&chunk, *shape, device);
        let memory = model.encode(batch.input.clone(), &batch.pad);
        let prediction = model.classify(memory, &batch.pad);
        let classes = infer::indices(prediction.class.argmax(1));
        let risks = infer::indices(prediction.risk.argmax(1));
        for (index, example) in chunk.iter().enumerate() {
            let predicted_class = classes.get(index).copied();
            let correct = predicted_class == i64::try_from(example.class).ok();
            tally.total += 1;
            if let Some(seen) = tally.seen_by_class.get_mut(example.class) {
                *seen += 1;
            }
            if correct {
                tally.class_right += 1;
                if let Some(right) = tally.right_by_class.get_mut(example.class) {
                    *right += 1;
                }
            }
            if risks.get(index).copied() == i64::try_from(example.risk).ok() {
                tally.risk_right += 1;
            }
        }
    }
    tally
}
