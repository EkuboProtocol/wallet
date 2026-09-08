//! Fit the transaction-preview model and write its weights.
//!
//! Trains on the GPU through `Wgpu` when one is available. The held-out set is
//! drawn along descriptor formats rather than examples, so what it reports is
//! how well the model reads a protocol it was never fitted on -- which is the
//! only claim worth making about it, since the rule table already handles
//! every format that *is* in the corpus.

use burn::{
    backend::{Autodiff, NdArray},
    module::{AutodiffModule as _, Module as _},
    optim::{AdamWConfig, GradientsParams, Optimizer},
    record::{BinFileRecorder, FullPrecisionSettings},
    tensor::backend::{AutodiffBackend, Backend},
};
use ekubo_wallet_preview::{
    model::PreviewModel,
    taxonomy::{CLASS_COUNT, TransactionClass},
    training::{self, Encoded, Labeled},
    vocab,
};
use rand::{SeedableRng as _, rngs::StdRng};
use std::path::PathBuf;

/// Training runs on the CPU.
///
/// Not a limitation of the model, which is small enough either way, but of the
/// machine this was fitted on: `cubecl` sizes its `wgpu` memory pool from the
/// adapter's reported memory, and on an integrated GPU with a 2 GB carve-out
/// that is a single ~3 GB allocation which simply fails. A 1.2M-parameter
/// model over twenty thousand short sequences is minutes of CPU work, so
/// there was nothing to buy by fighting it.
///
/// Inference is a different question and does run on the GPU -- see
/// `ekubo_wallet_preview::gpu`. The weights are backend-agnostic, so what is
/// fitted here loads there unchanged.
type Train = Autodiff<NdArray>;

struct Arguments {
    corpus: PathBuf,
    out: PathBuf,
    epochs: usize,
    learning_rate: f64,
    seed: u64,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut corpus = None;
    let mut out = None;
    let mut epochs = 12_usize;
    let mut learning_rate = 3e-4_f64;
    let mut seed = 20_260_908_u64;
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
            other => return Err(format!("unrecognized flag {other}")),
        }
    }
    Ok(Arguments {
        corpus: corpus.ok_or("--corpus is required")?,
        out: out.ok_or("--out is required")?,
        epochs,
        learning_rate,
        seed,
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
    let held_out_batches = training::batches(&evaluate, &mut StdRng::seed_from_u64(0));

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let mut model = PreviewModel::<Train>::new(&device);
    let mut optimizer = AdamWConfig::new().init();
    let mut rng = StdRng::seed_from_u64(arguments.seed);

    for epoch in 1..=arguments.epochs {
        let mut total = 0.0_f64;
        let mut steps = 0_usize;
        for (shape, chunk) in training::batches(&train, &mut rng) {
            let batch = training::batch::<Train>(&chunk, shape, &device);
            let loss = training::loss(&model, &batch, &weights, &device);
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
        let accuracy = evaluate_accuracy(&model, &held_out_batches, &device);
        eprintln!(
            "epoch {epoch:>3}  loss {mean:.4}  held-out class {:.1}%  risk {:.1}%",
            100.0 * accuracy.class,
            100.0 * accuracy.risk
        );
    }

    report_per_class(&model, &held_out_batches, &device);

    // Saved from the inference view of the model, so the weights file carries
    // no autodiff state and loads under the plain backend the wallet runs.
    let recorder = BinFileRecorder::<FullPrecisionSettings>::new();
    model
        .valid()
        .save_file(arguments.out.clone(), &recorder)
        .map_err(|error| format!("writing {}: {error}", arguments.out.display()))?;
    eprintln!("wrote {}", arguments.out.display());
    Ok(())
}

/// Fractions of the held-out set the model gets right.
struct Accuracy {
    class: f64,
    risk: f64,
}

fn evaluate_accuracy<B: AutodiffBackend>(
    model: &PreviewModel<B>,
    batches: &[(training::Shape, Vec<Encoded>)],
    device: &B::Device,
) -> Accuracy {
    let (class, risk, total) = tally(model, batches, device);
    let total = f64::from(u32::try_from(total.max(1)).unwrap_or(u32::MAX));
    Accuracy {
        class: f64::from(u32::try_from(class).unwrap_or(u32::MAX)) / total,
        risk: f64::from(u32::try_from(risk).unwrap_or(u32::MAX)) / total,
    }
}

fn tally<B: Backend>(
    model: &PreviewModel<B>,
    batches: &[(training::Shape, Vec<Encoded>)],
    device: &B::Device,
) -> (usize, usize, usize) {
    let mut class_right = 0;
    let mut risk_right = 0;
    let mut total = 0;
    for (shape, chunk) in batches {
        let batch = training::batch::<B>(chunk, *shape, device);
        let memory = model.encode(batch.input.clone(), &batch.pad);
        let prediction = model.classify(memory, &batch.pad);
        let classes: Vec<i64> = prediction
            .class
            .argmax(1)
            .into_data()
            .to_vec()
            .unwrap_or_default();
        let risks: Vec<i64> = prediction
            .risk
            .argmax(1)
            .into_data()
            .to_vec()
            .unwrap_or_default();
        for (index, example) in chunk.iter().enumerate() {
            if classes.get(index).copied() == i64::try_from(example.class).ok() {
                class_right += 1;
            }
            if risks.get(index).copied() == i64::try_from(example.risk).ok() {
                risk_right += 1;
            }
            total += 1;
        }
    }
    (class_right, risk_right, total)
}

/// Per-class held-out accuracy, because one number over an imbalanced set
/// hides exactly the classes worth checking.
fn report_per_class<B: Backend>(
    model: &PreviewModel<B>,
    batches: &[(training::Shape, Vec<Encoded>)],
    device: &B::Device,
) {
    let mut right = [0_usize; CLASS_COUNT];
    let mut seen = [0_usize; CLASS_COUNT];
    for (shape, chunk) in batches {
        let batch = training::batch::<B>(chunk, *shape, device);
        let memory = model.encode(batch.input.clone(), &batch.pad);
        let classes: Vec<i64> = model
            .classify(memory, &batch.pad)
            .class
            .argmax(1)
            .into_data()
            .to_vec()
            .unwrap_or_default();
        for (index, example) in chunk.iter().enumerate() {
            seen[example.class] += 1;
            if classes.get(index).copied() == i64::try_from(example.class).ok() {
                right[example.class] += 1;
            }
        }
    }
    eprintln!("held-out accuracy by class:");
    for index in 0..CLASS_COUNT {
        if seen[index] == 0 {
            continue;
        }
        eprintln!(
            "  {:18} {:>5.1}%  ({} held out)",
            TransactionClass::from_index(index).corpus_name(),
            100.0 * f64::from(u32::try_from(right[index]).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(seen[index]).unwrap_or(u32::MAX)),
            seen[index]
        );
    }
}
