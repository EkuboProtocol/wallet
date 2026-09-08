//! Print what the committed model says about held-out examples.
//!
//! The numbers a training run reports are accuracies, and an accuracy cannot
//! show you a sentence. This loads the weights exactly as the wallet does and
//! prints the model's answer beside the label for a sample of the corpus, so
//! the thing a reviewer would actually read can be looked at.
//!
//! Held-out examples by default -- descriptors the model was never fitted on,
//! which is the only sample worth judging it by.

use ekubo_wallet_preview::{
    taxonomy::{RiskBand, TransactionClass},
    training::{self, Labeled},
    vocab,
};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let mut corpus = None;
    let mut count = 25_usize;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(value()?)),
            "--count" => count = value()?.parse().map_err(|_| "--count must be a number")?,
            other => return Err(format!("unrecognized flag {other}")),
        }
    }
    let corpus = corpus.ok_or("--corpus is required")?;

    let engine = ekubo_wallet_preview::gpu::load().map_err(|error| error.to_string())?;
    let text = std::fs::read_to_string(&corpus)
        .map_err(|error| format!("reading {}: {error}", corpus.display()))?;

    // Collected first, then run in one batch, because that is how the review
    // list uses this: every waiting request at once.
    let mut held_out = Vec::new();
    for line in text.lines() {
        if held_out.len() >= count || line.trim().is_empty() {
            continue;
        }
        let labeled: Labeled =
            serde_json::from_str(line).map_err(|error| format!("parsing an example: {error}"))?;
        // The same split the trainer used, so what is printed is a descriptor
        // the model never saw.
        let Some(encoded) = training::encode(&labeled, vocab::size()) else {
            continue;
        };
        if training::split(vec![encoded], 10).1.is_empty() {
            continue;
        }
        held_out.push(labeled);
    }

    // One plan first, so the timing below excludes kernel compilation: the
    // first dispatch of every shape pays for a compile, and reporting that as
    // the cost of a preview would be measuring the wrong thing.
    if let Some(first) = held_out.first() {
        let warm = std::time::Instant::now();
        let _ = engine.preview(&first.document);
        println!(
            "first plan (includes kernel compilation): {:?}\n",
            warm.elapsed()
        );
    }

    let documents: Vec<_> = held_out.iter().map(|l| l.document.clone()).collect();
    let started = std::time::Instant::now();
    let previews = engine.preview_all(&documents);
    let elapsed = started.elapsed();

    let mut shown = 0_usize;
    let mut right = 0_usize;
    for (labeled, preview) in held_out.iter().zip(&previews) {
        let expected = TransactionClass::from_corpus_name(&labeled.class)
            .unwrap_or(TransactionClass::Unrecognized);
        if preview.class == expected {
            right += 1;
        }
        println!(
            "{} expected {:<16} got {:<16} risk {:<10} | {}",
            if preview.class == expected {
                "  "
            } else {
                "!!"
            },
            expected.corpus_name(),
            preview.class.corpus_name(),
            risk_name(preview.risk),
            preview.summary
        );
        for call in &labeled.document.calls {
            if let Some(description) = &call.description {
                println!("     decoded: {description}");
            }
        }
        shown += 1;
    }
    println!("\n{right}/{shown} classes correct on held-out formats");
    println!(
        "{shown} plans previewed in {elapsed:?} ({:?} each, batched)",
        elapsed / u32::try_from(shown.max(1)).unwrap_or(1)
    );
    Ok(())
}

const fn risk_name(risk: RiskBand) -> &'static str {
    risk.corpus_name()
}
